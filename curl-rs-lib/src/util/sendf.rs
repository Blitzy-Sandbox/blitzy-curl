//! Low-level byte send/recv primitives **and** the `infof`/`failf` diagnostic
//! helpers — the Rust rewrite of the *low-level* subset of libcurl's
//! `lib/sendf.c` / `lib/sendf.h`.
//!
//! # Scope boundary (MANDATORY — read before extending this module)
//!
//! `lib/sendf.c` historically bundles **two** distinct concerns. This module
//! owns exactly **one** of them:
//!
//! 1. **The high-level client-writer / client-reader chain** —
//!    `Curl_client_write`, the `Curl_cwriter_*` writer stack (`cw-out`,
//!    `cw-pause`, the download/raw writers, content-/transfer-decoding
//!    writers), and the `Curl_client_read` / `Curl_creader_*` reader stack.
//!    **This chain is OWNED by [`crate::transfer`]** (the parent
//!    `transfer.rs`). It is *not* implemented here, and must never be
//!    duplicated here. Doing so would fork the buffering/pausing state machine
//!    that the transfer engine is responsible for.
//!
//! 2. **Low-level raw byte movement + verbose/error diagnostics** — the
//!    primitive "send these bytes to the connection" / "read bytes from the
//!    connection" helpers shared by the transfer engine and every protocol
//!    handler, plus the `infof`/`failf` message helpers. **That is this
//!    module.**
//!
//! Keeping these apart mirrors the verified upstream layout: the client
//! writer/reader chain is curl's `cw-*`/`cr-*` machinery, whereas the raw
//! transport send/recv (`Curl_xfer_send`/`Curl_xfer_recv`) and the
//! diagnostic helpers (`Curl_infof`/`Curl_failf`, which actually live in
//! `lib/curl_trc.c`) are independent, lower-level primitives.
//!
//! # What this module provides
//!
//! * [`send_raw`], [`recv_raw`], [`send_all`] — generic async byte movers over
//!   any [`tokio::io::AsyncWrite`] / [`tokio::io::AsyncRead`] stream, so the
//!   same primitives serve plain TCP, TLS-wrapped, and proxy-wrapped
//!   connections. I/O errors are mapped to the ABI-correct [`CurlError`]
//!   variants ([`CurlError::SendError`] / [`CurlError::RecvError`] /
//!   [`CurlError::Again`]).
//! * [`infof`] / [`infof_fmt`] — emit a verbose (`CURLOPT_VERBOSE`)
//!   informational line. In the CLI these surface as the `* …` lines on
//!   stderr; the `* ` prefix is added by the binary's [`tracing`] subscriber,
//!   not here.
//! * [`failf`] / [`failf_fmt`] — format an error message, store it into the
//!   handle's error-buffer slot (mirroring `CURLOPT_ERRORBUFFER`), and emit it
//!   through [`tracing`]. The error-buffer write is **observable** (read by the
//!   CLI and by `tests/libtest` programs) and faithfully reproduces curl's
//!   first-write-wins semantics.
//! * The ergonomic [`infof!`](crate::infof) / [`failf!`](crate::failf) macros
//!   for `format!`-style call sites.
//!
//! These helpers REPLACE curl's `Curl_infof` / `Curl_failf` for diagnostics.
//! The verbose-gating (an `infof` does nothing unless verbose is on) and the
//! error-buffer storage (a `failf` records the *first* message into the slot)
//! must match curl exactly, and are covered by the unit tests below.
//!
//! # Memory safety (AAP §0.7.1)
//!
//! This module contains **zero** `unsafe` and is compiled under
//! `#![forbid(unsafe_code)]`. All byte movement goes through Tokio's safe
//! [`AsyncReadExt`]/[`AsyncWriteExt`] adapters; all logging goes through the
//! safe [`tracing`] macros. There is no raw `send`/`recv` syscall FFI here.

#![forbid(unsafe_code)]

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{CurlError, Result};
use crate::util::mprintf::{mprintf_string, FmtArg};

/// Size of curl's fixed error buffer, `CURL_ERROR_SIZE`
/// (`include/curl/curl.h`).
///
/// `CURLOPT_ERRORBUFFER` points at a caller-supplied `char[CURL_ERROR_SIZE]`.
/// curl's `Curl_failf` renders the error with `curl_mvsnprintf(error,
/// CURL_ERROR_SIZE, …)`, so the stored text is capped at `CURL_ERROR_SIZE - 1`
/// bytes plus a terminating NUL. [`failf`] reproduces that cap (see
/// [`truncate_error`]) so the message a C consumer reads back is byte-identical
/// to upstream curl.
pub const CURL_ERROR_SIZE: usize = 256;

/// The [`tracing`] target used for every curl diagnostic event emitted by
/// [`infof`] and [`failf`].
///
/// The CLI binary configures a `tracing` subscriber that listens on this target
/// to render curl's verbose `* …` lines (from [`infof`]) and error lines (from
/// [`failf`]) onto stderr. Exposing it as a constant lets the binary build its
/// subscriber filter without hard-coding the literal in two places.
///
/// NOTE: `tracing`'s `target:` argument must be a string *literal* at the macro
/// call site, so the emit sites below repeat the literal `"curl"`; the
/// [`diag_target_matches`](self) test pins the two together so they cannot
/// drift.
pub const DIAG_TARGET: &str = "curl";

// ---------------------------------------------------------------------------
// Internal text helpers (shared by the diagnostic helpers)
// ---------------------------------------------------------------------------

/// Strip trailing CR/LF from a diagnostic message.
///
/// curl's diagnostic messages never carry a trailing newline — `Curl_infof` /
/// `Curl_failf` `DEBUGASSERT(!strchr(fmt, '\n'))` and append the line
/// terminator themselves only for the verbose sink. The `tracing` sink supplies
/// its own line structure, so we drop any trailing newline a caller may have
/// included to keep emitted lines and the stored error buffer clean.
fn trim_message(message: &str) -> &str {
    message.trim_end_matches(['\r', '\n'])
}

/// Truncate `text` to at most `CURL_ERROR_SIZE - 1` bytes on a UTF-8 character
/// boundary, mirroring curl's fixed `char[CURL_ERROR_SIZE]` error buffer.
///
/// Truncation walks back to the nearest char boundary so the returned slice is
/// always valid UTF-8 (curl operates on raw bytes; we keep `String`s valid
/// while preserving the observable byte cap).
fn truncate_error(text: &str) -> &str {
    const MAX: usize = CURL_ERROR_SIZE - 1;
    if text.len() <= MAX {
        return text;
    }
    let mut end = MAX;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

// ---------------------------------------------------------------------------
// I/O error mapping (directional)
// ---------------------------------------------------------------------------

/// Map an outbound (send-side) [`io::Error`] to its ABI-correct [`CurlError`].
///
/// This intentionally does **not** use the general
/// [`From<io::Error>`](CurlError) conversion in [`crate::error`], which is
/// directionally ambiguous (it buckets unclassified errors as a *receive*
/// failure). At a send call site we have directional context, so — exactly as
/// that conversion's documentation recommends — we select the send variant
/// explicitly: a would-block maps to [`CurlError::Again`] (`CURLE_AGAIN`), and
/// every other failure maps to [`CurlError::SendError`] (`CURLE_SEND_ERROR`),
/// matching curl's `Curl_xfer_send` contract.
fn map_send_error(error: &io::Error) -> CurlError {
    match error.kind() {
        io::ErrorKind::WouldBlock => CurlError::Again,
        _ => CurlError::SendError,
    }
}

/// Map an inbound (receive-side) [`io::Error`] to its ABI-correct
/// [`CurlError`].
///
/// A would-block maps to [`CurlError::Again`] (`CURLE_AGAIN`); every other
/// failure maps to [`CurlError::RecvError`] (`CURLE_RECV_ERROR`), matching
/// curl's `Curl_xfer_recv` contract. Note that a *clean* end-of-stream is not
/// an error here: [`recv_raw`] reports it as `Ok(0)` (see its documentation).
fn map_recv_error(error: &io::Error) -> CurlError {
    match error.kind() {
        io::ErrorKind::WouldBlock => CurlError::Again,
        _ => CurlError::RecvError,
    }
}

// ===========================================================================
// Diagnostic helpers — infof / failf (curl's Curl_infof / Curl_failf)
// ===========================================================================

/// Emit a verbose informational diagnostic line — the Rust counterpart of
/// curl's `Curl_infof`.
///
/// When `verbose` is `false` this is a complete no-op (it neither formats nor
/// emits anything), exactly matching curl, where `Curl_infof` does nothing
/// unless `CURLOPT_VERBOSE` is set. When `verbose` is `true` the already-built
/// `message` is emitted as a [`tracing`] event at `debug` level on the
/// [`DIAG_TARGET`] target.
///
/// # CLI mapping
///
/// In the `curl` CLI these events become the `* …` lines printed to stderr
/// under `--verbose`. The leading `* ` marker is added by the binary's
/// `tracing` subscriber (which is configured to render [`DIAG_TARGET`] events),
/// **not** by this function — the core stays free of any presentation concern.
///
/// `message` should not contain a trailing newline (curl's contract); any
/// trailing CR/LF is trimmed defensively so emitted lines stay clean.
///
/// Most call sites should prefer the [`infof!`](crate::infof) macro, which
/// performs the `verbose` check *before* formatting so no allocation happens on
/// the common non-verbose path. Callers holding a curl-style printf format
/// string should use [`infof_fmt`].
///
/// # Examples
///
/// ```ignore
/// use curl_rs_lib::util::sendf::infof;
///
/// // Only emitted when the easy handle has CURLOPT_VERBOSE enabled.
/// infof(handle.verbose(), &format!("Connected to {host} port {port}"));
/// ```
pub fn infof(verbose: bool, message: &str) {
    if !verbose {
        return;
    }
    tracing::debug!(target: "curl", "{}", trim_message(message));
}

/// Emit a verbose informational diagnostic line from a curl-style printf format
/// string and its arguments.
///
/// This is the [`crate::util::mprintf`]-backed variant of [`infof`] for callers
/// that carry a C-style format string (`fmt`) plus a slice of typed
/// [`FmtArg`]s — for example protocol code translated closely from upstream
/// `Curl_infof(data, "…%s…", …)` sites. The message is rendered with curl's
/// exact printf semantics via [`mprintf_string`] and then routed through
/// [`infof`].
///
/// As with [`infof`], nothing is rendered or emitted when `verbose` is `false`,
/// so the (potentially non-trivial) formatting cost is skipped on the common
/// non-verbose path.
pub fn infof_fmt(verbose: bool, fmt: &[u8], args: &[FmtArg]) {
    if !verbose {
        return;
    }
    infof(true, &mprintf_string(fmt, args));
}

/// Format an error message, record it into the handle's error-buffer slot, and
/// emit it — the Rust counterpart of curl's `Curl_failf`.
///
/// # Error-buffer semantics (observable — must match curl)
///
/// `error_buffer` is the slot owned by the easy handle that backs
/// `CURLOPT_ERRORBUFFER` (the handle passes a `&mut` here; the FFI layer copies
/// the stored string into the caller's C `char[CURL_ERROR_SIZE]` on read). curl
/// records only the **first** failure of a transfer into that buffer
/// (`if(errorbuffer && !state.errorbuf)`), so this function writes the slot
/// **only when it is currently [`None`]** — the first `failf` wins and later
/// ones do not clobber it. The handle is responsible for resetting the slot to
/// [`None`] at the start of each transfer (mirroring curl clearing
/// `state.errorbuf`).
///
/// The stored text carries **no** trailing newline and is capped at
/// `CURL_ERROR_SIZE - 1` bytes (see [`truncate_error`]), reproducing exactly
/// what a C consumer reads back from `CURLOPT_ERRORBUFFER`.
///
/// # Emission
///
/// Regardless of whether the slot was written, the (cleaned, capped) message is
/// **always** emitted as a [`tracing`] event at `error` level on the
/// [`DIAG_TARGET`] target — matching curl, which writes every `failf` to the
/// verbose log even though only the first updates the error buffer. The
/// `tracing` subscriber decides whether/how to display it, so there is no
/// explicit `verbose` gate here (an error is meaningful independent of
/// `CURLOPT_VERBOSE`).
///
/// Most call sites should prefer the [`failf!`](crate::failf) macro; callers
/// holding a curl-style printf format string should use [`failf_fmt`].
///
/// # Examples
///
/// ```ignore
/// use curl_rs_lib::util::sendf::failf;
///
/// let mut errbuf: Option<String> = None;
/// failf(&mut errbuf, "Could not resolve host: example.invalid");
/// assert_eq!(errbuf.as_deref(), Some("Could not resolve host: example.invalid"));
/// ```
pub fn failf(error_buffer: &mut Option<String>, message: &str) {
    let cleaned = truncate_error(trim_message(message));

    // First-write-wins: only record into the slot if no error is stored yet.
    if error_buffer.is_none() {
        *error_buffer = Some(cleaned.to_owned());
    }

    // Always surface the failure on the diagnostic channel.
    tracing::error!(target: "curl", "{}", cleaned);
}

/// Format an error message from a curl-style printf format string and its
/// arguments, then record + emit it via [`failf`].
///
/// This is the [`crate::util::mprintf`]-backed variant of [`failf`] for callers
/// that carry a C-style format string (`fmt`) plus a slice of typed
/// [`FmtArg`]s, for example protocol code translated closely from upstream
/// `Curl_failf(data, "…%s…", …)` sites. The message is rendered with curl's
/// exact printf semantics via [`mprintf_string`]; the first-write-wins
/// error-buffer storage and the `tracing` emission are identical to [`failf`].
pub fn failf_fmt(error_buffer: &mut Option<String>, fmt: &[u8], args: &[FmtArg]) {
    failf(error_buffer, &mprintf_string(fmt, args));
}

/// Ergonomic verbose-diagnostic macro — the `format!`-style front end to
/// [`infof`](crate::util::sendf::infof).
///
/// Usage mirrors curl's `infof(data, fmt, …)` call sites:
///
/// ```ignore
/// infof!(handle.verbose(), "Connected to {host} port {port} (#{id})");
/// ```
///
/// The first argument is the `verbose` flag; the rest is a standard
/// [`std::format!`] argument list. The flag is evaluated exactly once and the
/// message is **only** built when it is `true`, so the common non-verbose path
/// performs no allocation — matching curl, which formats nothing unless
/// `CURLOPT_VERBOSE` is set.
#[macro_export]
macro_rules! infof {
    ($verbose:expr, $($arg:tt)*) => {{
        let __curl_verbose: bool = $verbose;
        if __curl_verbose {
            $crate::util::sendf::infof(true, &::std::format!($($arg)*));
        }
    }};
}

/// Ergonomic error-diagnostic macro — the `format!`-style front end to
/// [`failf`](crate::util::sendf::failf).
///
/// Usage mirrors curl's `failf(data, fmt, …)` call sites:
///
/// ```ignore
/// failf!(&mut handle.error_buffer, "HTTP/{maj}.{min} {code} {reason}");
/// ```
///
/// The first argument is the `&mut Option<String>` error-buffer slot; the rest
/// is a standard [`std::format!`] argument list. The message is always built
/// (an error must be recorded regardless of verbosity) and forwarded to
/// [`failf`](crate::util::sendf::failf), which applies the first-write-wins
/// storage and the `tracing` emission.
#[macro_export]
macro_rules! failf {
    ($error_buffer:expr, $($arg:tt)*) => {
        $crate::util::sendf::failf($error_buffer, &::std::format!($($arg)*))
    };
}

// ===========================================================================
// Low-level send / recv primitives
// ===========================================================================
//
// These are the raw byte movers shared by `crate::transfer` and the protocol
// handlers. They are deliberately generic over the async stream type so the
// *same* code path serves a plain `tokio::net::TcpStream`, a
// `tokio_rustls::client::TlsStream`, and any proxy-wrapped stream — the
// connection-filter chain hands whichever stream it has terminated at to these
// helpers. They sit *below* the client writer/reader chain (owned by
// `crate::transfer`); they move bytes, they do not interpret or buffer them.

/// Send a single chunk of bytes to the connection — the raw, one-shot send
/// primitive.
///
/// Writes from `buf` to `w` exactly once and returns the number of bytes the
/// underlying stream accepted, which may be **fewer** than `buf.len()` (a
/// partial write). Callers that must deliver an entire buffer (for example a
/// complete protocol request) should use [`send_all`], which loops internally.
///
/// # Errors
///
/// I/O failures are mapped to ABI-correct [`CurlError`] variants by
/// [`map_send_error`]: a would-block becomes [`CurlError::Again`]
/// (`CURLE_AGAIN`) and any other error becomes [`CurlError::SendError`]
/// (`CURLE_SEND_ERROR`). On a Tokio stream a would-block is normally handled by
/// the runtime (the future simply awaits writability), so `Again` is a
/// defensive mapping for non-Tokio or non-blocking adapters.
pub async fn send_raw<W>(w: &mut W, buf: &[u8]) -> Result<usize>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    match w.write(buf).await {
        Ok(n) => Ok(n),
        Err(error) => Err(map_send_error(&error)),
    }
}

/// Send an entire buffer to the connection, looping until every byte is
/// written — the `write_all`-style helper for complete protocol messages.
///
/// Internally drives [`tokio::io::AsyncWriteExt::write_all`], which repeats the
/// underlying write until all of `buf` has been accepted (transparently
/// handling partial writes). On success the return value is `buf.len()` (every
/// byte was sent); an empty `buf` is a no-op that returns `0`.
///
/// This does **not** flush: like curl's transport send, it hands the bytes to
/// the stream's send path; any buffering/flush policy is the stream's concern.
///
/// # Errors
///
/// I/O failures are mapped exactly as in [`send_raw`]
/// ([`CurlError::SendError`] / [`CurlError::Again`]). If the write terminates
/// early because the stream can accept no more data, Tokio surfaces a
/// `WriteZero` error, which maps to [`CurlError::SendError`].
pub async fn send_all<W>(w: &mut W, buf: &[u8]) -> Result<usize>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    match w.write_all(buf).await {
        Ok(()) => Ok(buf.len()),
        Err(error) => Err(map_send_error(&error)),
    }
}

/// Receive bytes from the connection into `buf` — the raw, one-shot recv
/// primitive.
///
/// Reads at most `buf.len()` bytes from `r` and returns the number actually
/// read. A return of **`Ok(0)`** means the peer performed an orderly shutdown:
/// the connection is **closed / end-of-stream**, not "try again". Callers
/// decide what a close means in context (for a sized transfer a premature close
/// is an error such as `CURLE_PARTIAL_FILE`; for an unsized one it is normal
/// completion) — this primitive does not impose that policy.
///
/// # Errors
///
/// I/O failures are mapped to ABI-correct [`CurlError`] variants by
/// [`map_recv_error`]: a would-block becomes [`CurlError::Again`]
/// (`CURLE_AGAIN`) and any other error becomes [`CurlError::RecvError`]
/// (`CURLE_RECV_ERROR`). As with [`send_raw`], a would-block is normally
/// handled by the Tokio runtime; the mapping is defensive.
pub async fn recv_raw<R>(r: &mut R, buf: &mut [u8]) -> Result<usize>
where
    R: AsyncRead + Unpin + ?Sized,
{
    match r.read(buf).await {
        // `n == 0` is a clean EOF / closed connection, surfaced to the caller
        // as `Ok(0)` rather than an error (curl's recv-of-zero contract).
        Ok(n) => Ok(n),
        Err(error) => Err(map_recv_error(&error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    // -----------------------------------------------------------------------
    // A minimal capturing `tracing` subscriber, built on the `tracing` crate
    // alone (NOT `tracing-subscriber`, which this crate does not depend on).
    // It records the level + target of every event so the verbose-gating and
    // diagnostic-channel contract can be asserted directly.
    // -----------------------------------------------------------------------
    #[derive(Clone, Default)]
    struct CaptureSubscriber {
        events: Arc<Mutex<Vec<(tracing::Level, String)>>>,
    }

    impl tracing::Subscriber for CaptureSubscriber {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let meta = event.metadata();
            self.events
                .lock()
                .expect("event lock poisoned")
                .push((*meta.level(), meta.target().to_owned()));
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    /// Run `f` under a fresh thread-local capturing subscriber and return the
    /// events it observed.
    ///
    /// [`tracing`] caches each callsite's *interest* globally. Other unit tests
    /// in this module call [`infof`]/[`failf`] **without** a subscriber
    /// installed; if such a call registers a diagnostic callsite first, its
    /// interest is cached against the no-op global subscriber and our events
    /// would be silently dropped. Invoking
    /// [`tracing::callsite::rebuild_interest_cache`] *after* installing the
    /// capturing subscriber forces every callsite's interest to be recomputed
    /// against it, making these assertions deterministic under the parallel
    /// test runner.
    fn capture_events<F: FnOnce()>(f: F) -> Vec<(tracing::Level, String)> {
        let sub = CaptureSubscriber::default();
        let events = sub.events.clone();
        tracing::subscriber::with_default(sub, || {
            tracing::callsite::rebuild_interest_cache();
            f();
        });
        let result = events.lock().expect("event lock poisoned").clone();
        result
    }

    // ----- text helpers ----------------------------------------------------

    #[test]
    fn trim_message_strips_only_trailing_newlines() {
        assert_eq!(trim_message("hello\n"), "hello");
        assert_eq!(trim_message("hello\r\n"), "hello");
        assert_eq!(trim_message("hello\n\n\r"), "hello");
        // Internal newlines are preserved (curl only ever adds a trailing one).
        assert_eq!(trim_message("a\nb\n"), "a\nb");
        assert_eq!(trim_message("plain"), "plain");
    }

    #[test]
    fn truncate_error_caps_ascii_at_error_size() {
        let long = "x".repeat(1000);
        let t = truncate_error(&long);
        assert_eq!(t.len(), CURL_ERROR_SIZE - 1);
        assert!(t.bytes().all(|c| c == b'x'));
    }

    #[test]
    fn truncate_error_respects_utf8_char_boundary() {
        // 254 ASCII bytes followed by a 2-byte 'é' (U+00E9 = bytes 254..256).
        // The 255-byte cap lands inside 'é', so truncation backs off to 254.
        let s = format!("{}\u{00e9}", "a".repeat(254));
        assert_eq!(s.len(), 256);
        let t = truncate_error(&s);
        assert_eq!(t.len(), 254);
        assert!(t.bytes().all(|c| c == b'a'));
    }

    #[test]
    fn truncate_error_leaves_short_text_unchanged() {
        assert_eq!(truncate_error("short"), "short");
    }

    #[test]
    fn diag_target_is_curl() {
        // Pins the public constant to the literal repeated at the emit sites.
        assert_eq!(DIAG_TARGET, "curl");
    }

    // ----- error mapping ---------------------------------------------------

    #[test]
    fn error_mapping_is_directional_and_abi_correct() {
        use std::io::{Error, ErrorKind};

        // Would-block maps to CURLE_AGAIN on both directions.
        assert_eq!(
            map_send_error(&Error::from(ErrorKind::WouldBlock)),
            CurlError::Again
        );
        assert_eq!(
            map_recv_error(&Error::from(ErrorKind::WouldBlock)),
            CurlError::Again
        );

        // Everything else is directional: send -> SEND_ERROR, recv -> RECV_ERROR.
        assert_eq!(
            map_send_error(&Error::from(ErrorKind::BrokenPipe)),
            CurlError::SendError
        );
        assert_eq!(
            map_send_error(&Error::from(ErrorKind::Other)),
            CurlError::SendError
        );
        assert_eq!(
            map_recv_error(&Error::from(ErrorKind::ConnectionReset)),
            CurlError::RecvError
        );
        assert_eq!(
            map_recv_error(&Error::from(ErrorKind::Other)),
            CurlError::RecvError
        );

        // Exact ABI integers (CURLE_SEND_ERROR=55, CURLE_RECV_ERROR=56, CURLE_AGAIN=81).
        assert_eq!(CurlError::SendError.code(), 55);
        assert_eq!(CurlError::RecvError.code(), 56);
        assert_eq!(CurlError::Again.code(), 81);
    }

    // ----- failf: error-buffer semantics -----------------------------------

    #[test]
    fn failf_records_first_message_only() {
        let mut buf: Option<String> = None;
        failf(&mut buf, "first error");
        assert_eq!(buf.as_deref(), Some("first error"));
        // First-write-wins: a later failf must NOT clobber the stored message.
        failf(&mut buf, "second error");
        assert_eq!(buf.as_deref(), Some("first error"));
    }

    #[test]
    fn failf_strips_trailing_newline_from_stored_text() {
        let mut buf: Option<String> = None;
        failf(&mut buf, "connection reset\r\n");
        assert_eq!(buf.as_deref(), Some("connection reset"));
    }

    #[test]
    fn failf_caps_stored_text_at_error_size() {
        let mut buf: Option<String> = None;
        failf(&mut buf, &"z".repeat(1000));
        let stored = buf.expect("error must be recorded");
        assert_eq!(stored.len(), CURL_ERROR_SIZE - 1);
    }

    #[test]
    fn failf_fmt_renders_with_printf_semantics() {
        let mut buf: Option<String> = None;
        failf_fmt(
            &mut buf,
            b"FTP error %d: %s",
            &[FmtArg::Int(530), FmtArg::string("Login incorrect")],
        );
        assert_eq!(buf.as_deref(), Some("FTP error 530: Login incorrect"));
    }

    // ----- infof / failf: tracing emission ---------------------------------

    #[test]
    fn infof_is_silent_when_not_verbose() {
        let ev = capture_events(|| {
            infof(false, "this must not be emitted");
        });
        assert!(ev.is_empty());
    }

    #[test]
    fn infof_emits_debug_on_curl_target_when_verbose() {
        let ev = capture_events(|| {
            infof(true, "Connected to example.com");
        });
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].0, tracing::Level::DEBUG);
        assert_eq!(ev[0].1, DIAG_TARGET);
    }

    #[test]
    fn infof_fmt_is_silent_when_not_verbose() {
        let ev = capture_events(|| {
            infof_fmt(false, b"value=%d", &[FmtArg::Int(7)]);
        });
        assert!(ev.is_empty());
    }

    #[test]
    fn failf_always_emits_error_event_even_when_not_recording() {
        let mut buf: Option<String> = None;
        let ev = capture_events(|| {
            failf(&mut buf, "one");
            // Second call does not update the buffer, but is still emitted.
            failf(&mut buf, "two");
        });
        assert_eq!(ev.len(), 2);
        assert!(ev
            .iter()
            .all(|(level, target)| *level == tracing::Level::ERROR && target == DIAG_TARGET));
        assert_eq!(buf.as_deref(), Some("one"));
    }

    // ----- ergonomic macros ------------------------------------------------

    #[test]
    fn infof_macro_gates_formatting_on_verbose() {
        let host = "example.com";
        let port = 443;
        let ev = capture_events(|| {
            // The non-verbose call must not emit; the verbose one must.
            crate::infof!(false, "Connecting to {host} port {port}");
            crate::infof!(true, "Connected to {host} port {port}");
        });
        assert_eq!(ev.len(), 1, "only the verbose=true macro call should emit");
        assert_eq!(ev[0].0, tracing::Level::DEBUG);
        assert_eq!(ev[0].1, DIAG_TARGET);
    }

    #[test]
    fn failf_macro_records_formatted_message() {
        let mut buf: Option<String> = None;
        let code = 404;
        let reason = "Not Found";
        crate::failf!(&mut buf, "HTTP error {code}: {reason}");
        assert_eq!(buf.as_deref(), Some("HTTP error 404: Not Found"));
    }

    // ----- low-level I/O ----------------------------------------------------

    #[tokio::test]
    async fn send_all_and_recv_raw_round_trip() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let payload = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";

        let sent = send_all(&mut client, payload).await.expect("send_all");
        assert_eq!(sent, payload.len());

        let mut buf = [0u8; 64];
        let n = recv_raw(&mut server, &mut buf).await.expect("recv_raw");
        assert_eq!(n, payload.len());
        assert_eq!(&buf[..n], payload);
    }

    #[tokio::test]
    async fn send_raw_returns_bytes_accepted() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let n = send_raw(&mut client, b"abc").await.expect("send_raw");
        assert_eq!(n, 3);

        let mut buf = [0u8; 8];
        let got = recv_raw(&mut server, &mut buf).await.expect("recv_raw");
        assert_eq!(&buf[..got], b"abc");
    }

    #[tokio::test]
    async fn recv_raw_reports_clean_eof_as_zero() {
        let (client, mut server) = tokio::io::duplex(64);
        // Closing the write half signals an orderly shutdown to the reader.
        drop(client);

        let mut buf = [0u8; 16];
        let n = recv_raw(&mut server, &mut buf).await.expect("recv_raw");
        assert_eq!(
            n, 0,
            "a closed peer must surface as Ok(0) (EOF), not an error"
        );
    }

    #[tokio::test]
    async fn send_all_loops_across_a_small_buffer() {
        // A duplex capacity smaller than the payload forces send_all to loop;
        // a concurrent reader drains so the writer can make progress.
        let (mut client, mut server) = tokio::io::duplex(8);
        let payload: Vec<u8> = (0u8..=255).collect();
        let expected = payload.clone();

        let reader = tokio::spawn(async move {
            let mut out = Vec::new();
            let mut buf = [0u8; 7];
            loop {
                let n = recv_raw(&mut server, &mut buf).await.expect("recv_raw");
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
            out
        });

        let sent = send_all(&mut client, &payload).await.expect("send_all");
        assert_eq!(sent, payload.len());
        drop(client); // signal EOF so the reader loop terminates

        let received = reader.await.expect("reader task");
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn send_all_empty_buffer_is_a_zero_length_noop() {
        let (mut client, _server) = tokio::io::duplex(8);
        let n = send_all(&mut client, b"").await.expect("send_all");
        assert_eq!(n, 0);
    }
}
