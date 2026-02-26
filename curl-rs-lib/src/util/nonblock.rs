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
//!    `curl-rs-ffi` crate need a way to toggle blocking mode.
//! 2. **Legacy interop** — converting a raw file descriptor received from
//!    external code into a Tokio-managed async stream.
//!
//! For new internal Rust code, prefer using [`tokio::net::TcpStream`] directly
//! rather than manipulating raw file descriptors.
//!
//! # Platform Support
//!
//! - **Unix** (`cfg(unix)`): Uses `std::os::unix::io::{RawFd, BorrowedFd, FromRawFd}`.
//! - **Windows** (`cfg(windows)`): Uses `std::os::windows::io::{RawSocket, BorrowedSocket, FromRawSocket}`.
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
use std::os::unix::io::{BorrowedFd, FromRawFd, RawFd};

// ---------------------------------------------------------------------------
// Platform-specific imports — Windows
// ---------------------------------------------------------------------------
#[cfg(windows)]
use std::os::windows::io::{BorrowedSocket, FromRawSocket, RawSocket};

// ---------------------------------------------------------------------------
// set_nonblocking — Unix
// ---------------------------------------------------------------------------

/// Set or unset non-blocking mode on a raw file descriptor (Unix).
///
/// This is the Rust equivalent of C `curlx_nonblock(sockfd, nonblock)` which
/// uses `fcntl(fd, F_SETFL, O_NONBLOCK)` on Unix. The `socket2::SockRef` type
/// abstracts the platform-specific call so no manual `fcntl` is needed.
///
/// # Arguments
///
/// * `fd` — The raw file descriptor to modify. Must be a valid, open file
///   descriptor for the duration of this call.
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
/// use std::os::unix::io::AsRawFd;
///
/// let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
/// let fd = listener.as_raw_fd();
/// set_nonblocking(fd, true).unwrap();
/// ```
///
/// # Note
///
/// In the Tokio-based Rust rewrite, sockets created through
/// `tokio::net::TcpStream` are already non-blocking. This function is
/// primarily useful for the FFI layer where raw file descriptors from C
/// callers need mode adjustment.
#[cfg(unix)]
pub fn set_nonblocking(fd: RawFd, nonblock: bool) -> Result<(), CurlError> {
    // SAFETY: The caller guarantees that `fd` is a valid, open file descriptor
    // for the duration of this function call. `BorrowedFd::borrow_raw` creates
    // a borrowed handle that does NOT take ownership and will NOT close the fd
    // when dropped. This mirrors the C `curlx_nonblock` contract where the
    // caller retains ownership of the socket.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let sock = SockRef::from(&borrowed);
    sock.set_nonblocking(nonblock).map_err(io_to_connect_error)
}

/// Set or unset non-blocking mode on a raw socket (Windows).
///
/// Windows equivalent that uses `ioctlsocket(socket, FIONBIO, &flag)` under
/// the hood via `socket2::SockRef`.
///
/// # Arguments
///
/// * `socket` — The raw socket handle to modify. Must be a valid, open socket
///   for the duration of this call.
/// * `nonblock` — `true` to enable non-blocking mode, `false` for blocking.
///
/// # Errors
///
/// Returns [`CurlError::CouldntConnect`] if the underlying `ioctlsocket`
/// call fails.
#[cfg(windows)]
pub fn set_nonblocking(socket: RawSocket, nonblock: bool) -> Result<(), CurlError> {
    // SAFETY: The caller guarantees that `socket` is a valid, open socket
    // handle for the duration of this function call. `BorrowedSocket::borrow_raw`
    // creates a borrowed handle that does NOT take ownership and will NOT close
    // the socket when dropped.
    let borrowed = unsafe { BorrowedSocket::borrow_raw(socket) };
    let sock = SockRef::from(&borrowed);
    sock.set_nonblocking(nonblock).map_err(io_to_connect_error)
}

// ---------------------------------------------------------------------------
// make_tokio_socket — Unix
// ---------------------------------------------------------------------------

/// Convert a raw file descriptor into a Tokio async [`TcpStream`](tokio::net::TcpStream) (Unix).
///
/// This function **takes ownership** of the file descriptor. After a
/// successful call, the caller must NOT close `fd` — ownership is transferred
/// to the returned `tokio::net::TcpStream`, which will close the underlying fd
/// when dropped.
///
/// The fd is first wrapped in a `std::net::TcpStream`, set to non-blocking
/// mode (required by Tokio), and then converted to a `tokio::net::TcpStream`.
///
/// # Arguments
///
/// * `fd` — A raw file descriptor representing a connected TCP socket. The
///   caller transfers ownership to this function.
///
/// # Errors
///
/// * [`CurlError::CouldntConnect`] — if setting non-blocking mode fails.
/// * [`CurlError::FailedInit`] — if Tokio runtime registration fails (e.g.,
///   no active Tokio runtime, or the fd is not a valid socket).
///
/// # Note
///
/// This is the **preferred path** in the Rust rewrite for converting raw fds
/// from the FFI layer into async-capable streams. Tokio `TcpStream` is
/// inherently non-blocking, so no further mode toggling is needed after this
/// conversion.
#[cfg(unix)]
pub fn make_tokio_socket(
    fd: RawFd,
) -> Result<tokio::net::TcpStream, CurlError> {
    // SAFETY: The caller guarantees that `fd` is a valid, open file descriptor
    // representing a connected TCP socket. Ownership is transferred to the
    // std::net::TcpStream which will close the fd on drop. This is the same
    // ownership transfer semantics as the C code where the caller "gives" the
    // socket to the Tokio layer.
    let std_stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };

    // Tokio requires non-blocking mode on all registered sockets.
    std_stream
        .set_nonblocking(true)
        .map_err(io_to_connect_error)?;

    // Register with the Tokio reactor. This fails if there is no active Tokio
    // runtime or if the fd is not suitable for async I/O.
    tokio::net::TcpStream::from_std(std_stream).map_err(io_to_init_error)
}

/// Convert a raw socket handle into a Tokio async [`TcpStream`](tokio::net::TcpStream) (Windows).
///
/// Windows equivalent — see the Unix variant documentation for full details.
/// This function **takes ownership** of the socket handle.
#[cfg(windows)]
pub fn make_tokio_socket(
    socket: RawSocket,
) -> Result<tokio::net::TcpStream, CurlError> {
    // SAFETY: The caller guarantees that `socket` is a valid, open socket
    // handle representing a connected TCP socket. Ownership is transferred to
    // the std::net::TcpStream which will close the socket on drop.
    let std_stream = unsafe { std::net::TcpStream::from_raw_socket(socket) };

    // Tokio requires non-blocking mode on all registered sockets.
    std_stream
        .set_nonblocking(true)
        .map_err(io_to_connect_error)?;

    // Register with the Tokio reactor.
    tokio::net::TcpStream::from_std(std_stream).map_err(io_to_init_error)
}

// ---------------------------------------------------------------------------
// is_nonblocking — Unix
// ---------------------------------------------------------------------------

/// Check whether a raw file descriptor is currently in non-blocking mode (Unix).
///
/// This is primarily useful for assertions and debugging. Under the hood it
/// calls `fcntl(fd, F_GETFL)` and checks for the `O_NONBLOCK` flag, all
/// abstracted by `socket2::SockRef::nonblocking()`.
///
/// # Arguments
///
/// * `fd` — The raw file descriptor to query. Must be valid and open.
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
pub fn is_nonblocking(fd: RawFd) -> Result<bool, CurlError> {
    // SAFETY: The caller guarantees that `fd` is a valid, open file descriptor
    // for the duration of this function call. `BorrowedFd::borrow_raw` does
    // not take ownership.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let sock = SockRef::from(&borrowed);
    sock.nonblocking().map_err(io_to_connect_error)
}

/// Check whether a raw socket is currently in non-blocking mode (Windows).
///
/// # Important
///
/// On Windows, it is **not possible** to reliably query the non-blocking state
/// of a socket (there is no `ioctlsocket` query for `FIONBIO`). This function
/// always returns `Err(CurlError::CouldntConnect)` on Windows. Use this
/// function only for debugging on Unix, and avoid depending on its result in
/// Windows-targeted code paths.
#[cfg(windows)]
pub fn is_nonblocking(_socket: RawSocket) -> Result<bool, CurlError> {
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
    #[cfg(unix)]
    use std::os::unix::io::AsRawFd;

    /// Verify that a freshly-created TCP listener socket can be toggled
    /// between blocking and non-blocking mode using [`set_nonblocking`].
    #[cfg(unix)]
    #[test]
    fn test_set_and_query_nonblocking_unix() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fd = listener.as_raw_fd();

        // Set non-blocking
        set_nonblocking(fd, true).expect("set_nonblocking(true) should succeed");
        assert!(
            is_nonblocking(fd).expect("is_nonblocking should succeed"),
            "socket should be non-blocking after set_nonblocking(true)"
        );

        // Set blocking
        set_nonblocking(fd, false).expect("set_nonblocking(false) should succeed");
        assert!(
            !is_nonblocking(fd).expect("is_nonblocking should succeed"),
            "socket should be blocking after set_nonblocking(false)"
        );

        // Toggle back to non-blocking
        set_nonblocking(fd, true).expect("set_nonblocking(true) should succeed again");
        assert!(
            is_nonblocking(fd).expect("is_nonblocking should succeed"),
            "socket should be non-blocking again"
        );
    }

    /// Verify that setting non-blocking mode is idempotent — calling
    /// `set_nonblocking(fd, true)` twice does not error.
    #[cfg(unix)]
    #[test]
    fn test_set_nonblocking_idempotent() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fd = listener.as_raw_fd();

        set_nonblocking(fd, true).expect("first call should succeed");
        set_nonblocking(fd, true).expect("second call should also succeed");
        assert!(is_nonblocking(fd).unwrap());
    }

    /// Verify that a closed file descriptor produces an error, not a panic.
    ///
    /// We create a socket, extract its fd, close the original owner, and then
    /// attempt to toggle nonblocking mode on the now-closed fd.
    #[cfg(unix)]
    #[test]
    fn test_closed_fd_returns_error() {
        use std::os::unix::io::IntoRawFd;

        // Create and immediately close a socket to get a closed fd
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fd = listener.into_raw_fd();
        // Close the fd manually using libc-free approach: wrap in a TcpListener
        // which will close on drop
        let _ = unsafe { std::net::TcpListener::from_raw_fd(fd) };
        // fd is now closed

        let result = set_nonblocking(fd, true);
        assert!(
            result.is_err(),
            "closed fd should produce an error, got Ok"
        );
        assert_eq!(
            result.unwrap_err(),
            CurlError::CouldntConnect,
            "error variant should be CouldntConnect"
        );
    }

    /// Verify that querying a closed fd returns an error.
    #[cfg(unix)]
    #[test]
    fn test_is_nonblocking_closed_fd() {
        use std::os::unix::io::IntoRawFd;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fd = listener.into_raw_fd();
        let _ = unsafe { std::net::TcpListener::from_raw_fd(fd) };
        // fd is now closed

        let result = is_nonblocking(fd);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::CouldntConnect);
    }

    /// Verify that `make_tokio_socket` works inside a Tokio runtime context.
    /// We create a connected TCP pair and convert one end to a Tokio stream.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_make_tokio_socket() {
        use std::os::unix::io::IntoRawFd;

        // Create a TCP listener and connect to it to get a connected socket pair
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let client = std::net::TcpStream::connect(addr).unwrap();
        let _server_conn = listener.accept().unwrap();

        // Extract the raw fd (transfers ownership)
        let fd = client.into_raw_fd();

        // Convert to Tokio TcpStream
        let tokio_stream = make_tokio_socket(fd);
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
