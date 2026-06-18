//! Wait / readiness helpers — the Rust rewrite of libcurl's `lib/curlx/wait.c`
//! (and its `lib/curlx/wait.h` declaration).
//!
//! # Origin and mapping
//!
//! In C, [`curlx_wait_ms`] is curl's portable "sleep for N milliseconds"
//! primitive. It is implemented with a `select()`/`poll()` call over *empty*
//! file-descriptor sets (or `Sleep`/`delay` on Windows/MS-DOS) purely to delay
//! execution when no socket is available to wait on. See the behavioral oracle
//! `lib/curlx/wait.c` for the exact contract this module preserves.
//!
//! In the async core, socket *readiness* is provided by Tokio, so the C
//! `select`/`poll`-based waiting maps onto Tokio timers and readiness:
//!
//! * The blocking millisecond wait survives as [`curlx_wait_ms`], a thin parity
//!   shim for the few remaining synchronous call sites.
//! * The async millisecond wait is [`wait_ms`], backed by [`tokio::time::sleep`],
//!   which is what the multi/connection code actually uses.
//! * "Wait until this socket is readable/writable, or time out" is expressed by
//!   [`wait_readable`] / [`wait_writable`], thin wrappers over Tokio's readiness
//!   futures plus [`tokio::time::timeout`].
//!
//! # Scope boundary
//!
//! This module is intentionally limited to the wait/sleep + minimal readiness
//! shims. The heavyweight poll engine of `lib/select.c` and the
//! `curl_multi_socket_action` event-loop contract are **not** implemented here;
//! they belong to the connection layer (`conn/`) and the multi handle
//! (`multi.rs`). Keeping this module a leaf (no internal crate dependencies)
//! lets every layer reuse it without creating dependency cycles.
//!
//! # Memory safety
//!
//! This module contains zero `unsafe` code and is compiled under
//! `#![forbid(unsafe_code)]`. All waiting is performed via `tokio::time` (async)
//! or `std::thread::sleep` (the rare synchronous shim); there is no raw
//! `select`/`poll` FFI.

#![forbid(unsafe_code)]

use std::time::Duration;

use tokio::net::TcpStream;

/// Synchronous millisecond-wait parity shim — the Rust counterpart of C's
/// `int curlx_wait_ms(timediff_t timeout_ms)`.
///
/// The C `timediff_t` type is `curl_off_t` (a signed 64-bit integer), so the
/// argument is an [`i64`]. The return value mirrors the C contract exactly:
///
/// * `timeout_ms == 0` → returns `0` immediately (no sleep).
/// * `timeout_ms < 0`  → returns `-1`. In C this additionally sets the socket
///   errno to `SOCKEINVAL` (`EINVAL`); the safe core does not own a global
///   socket-errno, so it returns the integer contract only. The FFI boundary is
///   responsible for surfacing `EINVAL` to C callers that inspect errno.
/// * `timeout_ms > 0`  → blocks the current thread for (at least) that many
///   milliseconds and returns `0`.
///
/// # EINTR parity
///
/// The C implementation treats an `EINTR` interruption of its `select`/`poll`
/// as non-lethal and returns `0`. [`std::thread::sleep`] never returns early due
/// to signal delivery — it always sleeps for at least the requested duration —
/// so this shim likewise always returns `0` after a positive wait, matching the
/// "interrupted is not an error" semantics.
///
/// # Blocking warning
///
/// This is a **blocking** sleep and must never be called from within an async
/// task or the Tokio runtime, where it would stall the executor thread. Async
/// callers must use [`wait_ms`] instead. This shim exists only for parity with
/// the synchronous C call sites.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(curlx_wait_ms(0), 0);   // immediate
/// assert_eq!(curlx_wait_ms(-1), -1); // invalid (EINVAL parity)
/// assert_eq!(curlx_wait_ms(5), 0);   // sleeps ~5ms, then returns 0
/// ```
#[must_use]
pub fn curlx_wait_ms(timeout_ms: i64) -> i32 {
    // Zero timeout: return immediately, exactly as curl does.
    if timeout_ms == 0 {
        return 0;
    }
    // Negative timeout: invalid. C sets SOCKERRNO = SOCKEINVAL (EINVAL) and
    // returns -1; we return the -1 integer contract.
    if timeout_ms < 0 {
        return -1;
    }
    // Positive timeout: `timeout_ms` is guaranteed > 0 here, so the cast to the
    // unsigned `u64` expected by `Duration::from_millis` is lossless and cannot
    // overflow (i64::MAX fits within u64).
    std::thread::sleep(Duration::from_millis(timeout_ms as u64));
    0
}

/// Asynchronous millisecond wait — the async-core form of [`curlx_wait_ms`].
///
/// This is the variant the multi handle and connection code use to yield for a
/// fixed delay without blocking the Tokio runtime. It is driven by
/// [`tokio::time::sleep`]:
///
/// * `timeout_ms > 0`  → awaits a Tokio timer for that many milliseconds.
/// * `timeout_ms <= 0` → returns immediately (a zero or negative delay is, by
///   the same logic as the C shim, "no wait"). Unlike [`curlx_wait_ms`] there is
///   no error channel here; a non-positive delay is simply a no-op.
///
/// The positive cast to `u64` is lossless because the branch is only taken when
/// `timeout_ms > 0`.
pub async fn wait_ms(timeout_ms: i64) {
    if timeout_ms > 0 {
        tokio::time::sleep(Duration::from_millis(timeout_ms as u64)).await;
    }
    // timeout_ms <= 0: nothing to wait for; fall through and return immediately.
}

/// Await an arbitrary readiness future, optionally bounded by a timeout.
///
/// Shared implementation for [`wait_readable`] / [`wait_writable`]. The future
/// `fut` resolves to `Ok(())` when the underlying socket reaches the requested
/// readiness, or to `Err(_)` on an I/O error.
///
/// Returns:
/// * `Ok(true)`  — the socket reached readiness within the deadline (or no
///   deadline was set);
/// * `Ok(false)` — the optional `timeout` elapsed first;
/// * `Err(e)`    — an underlying I/O error occurred while waiting.
async fn wait_ready<F>(fut: F, timeout: Option<Duration>) -> std::io::Result<bool>
where
    F: std::future::Future<Output = std::io::Result<()>>,
{
    match timeout {
        Some(dur) => match tokio::time::timeout(dur, fut).await {
            // Readiness future completed before the deadline.
            Ok(Ok(())) => Ok(true),
            // Readiness future surfaced an I/O error.
            Ok(Err(err)) => Err(err),
            // The timeout fired first.
            Err(_elapsed) => Ok(false),
        },
        // No deadline: wait indefinitely for readiness (propagating I/O errors).
        None => {
            fut.await?;
            Ok(true)
        }
    }
}

/// Wait until `io` is readable, or until the optional `timeout` elapses.
///
/// This is the Tokio mapping of curl's "wait for `CURL_CSELECT_IN` on this
/// socket" used by `Curl_socket_check`/`Curl_poll`-style call sites. It wraps
/// [`tokio::net::TcpStream::readable`] in an optional [`tokio::time::timeout`].
///
/// Returns `Ok(true)` if the socket became readable, `Ok(false)` if the
/// `timeout` elapsed first, and `Err(_)` on an I/O error. A `None` timeout waits
/// indefinitely.
///
/// Note that, like the underlying Tokio readiness, a `true` result indicates the
/// kernel reported the socket *probably* readable; a subsequent read may still
/// return `WouldBlock` and should be retried. The full poll / socket-action
/// engine (the `curl_multi_socket_action` contract) lives in `conn/` and
/// `multi.rs`, not here.
pub async fn wait_readable(io: &TcpStream, timeout: Option<Duration>) -> std::io::Result<bool> {
    wait_ready(io.readable(), timeout).await
}

/// Wait until `io` is writable, or until the optional `timeout` elapses.
///
/// The write-side counterpart of [`wait_readable`] — the Tokio mapping of curl's
/// "wait for `CURL_CSELECT_OUT` on this socket". It wraps
/// [`tokio::net::TcpStream::writable`] in an optional [`tokio::time::timeout`].
///
/// Returns `Ok(true)` if the socket became writable, `Ok(false)` if the
/// `timeout` elapsed first, and `Err(_)` on an I/O error. A `None` timeout waits
/// indefinitely.
pub async fn wait_writable(io: &TcpStream, timeout: Option<Duration>) -> std::io::Result<bool> {
    wait_ready(io.writable(), timeout).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn curlx_wait_ms_negative_returns_minus_one() {
        // The EINVAL parity case: any negative timeout returns -1.
        assert_eq!(curlx_wait_ms(-1), -1);
        assert_eq!(curlx_wait_ms(-1000), -1);
        assert_eq!(curlx_wait_ms(i64::MIN), -1);
    }

    #[test]
    fn curlx_wait_ms_zero_returns_zero_immediately() {
        let start = Instant::now();
        assert_eq!(curlx_wait_ms(0), 0);
        // A zero timeout must not sleep.
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn curlx_wait_ms_positive_sleeps_and_returns_zero() {
        let start = Instant::now();
        let rc = curlx_wait_ms(30);
        assert_eq!(rc, 0);
        // `std::thread::sleep` guarantees *at least* the requested duration;
        // allow a little downward slack to stay robust against measurement.
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(25),
            "elapsed {elapsed:?} should be >= ~25ms for a 30ms wait"
        );
    }

    #[tokio::test]
    async fn wait_ms_positive_elapses() {
        let start = Instant::now();
        wait_ms(10).await;
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(8),
            "elapsed {elapsed:?} should be >= ~8ms for a 10ms async wait"
        );
    }

    #[tokio::test]
    async fn wait_ms_non_positive_is_immediate() {
        let start = Instant::now();
        wait_ms(0).await;
        wait_ms(-5).await;
        // Neither a zero nor a negative delay should sleep.
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn readiness_helpers_track_socket_state() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        // Establish a connected loopback TCP pair.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();

        // A freshly connected socket has send-buffer space, so it is writable.
        assert!(wait_writable(&client, Some(Duration::from_millis(500)))
            .await
            .unwrap());

        // With no data pending, the client is not readable within a short
        // window: the timeout fires and we get Ok(false).
        assert!(!wait_readable(&client, Some(Duration::from_millis(50)))
            .await
            .unwrap());

        // Once the peer writes, the client becomes readable.
        server.write_all(b"hello").await.unwrap();
        server.flush().await.unwrap();
        assert!(wait_readable(&client, Some(Duration::from_millis(1000)))
            .await
            .unwrap());
    }
}
