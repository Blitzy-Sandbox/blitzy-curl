// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! Gopher / Gophers protocol handler — the memory-safe Rust port of curl's
//! `lib/gopher.c` (+ `lib/gopher.h`) for the byte-for-byte functional-parity
//! rewrite of curl / libcurl **8.19.0-DEV**.
//!
//! Gopher (RFC 1436) is a deliberately tiny TCP request/response protocol: the
//! client opens a connection, sends a single *selector* line terminated by
//! `\r\n`, and the server streams the response body back and then **closes the
//! connection**. There is no length framing of any kind — the response ends at
//! EOF. `gophers` is the *same* protocol carried over a TLS connection (curl
//! scheme `gophers`, flag `PROTOPT_SSL`); the request/response wire behavior is
//! identical, only the transport is encrypted.
//!
//! # What curl does (← `gopher_do`, `lib/gopher.c`)
//!
//! `gopher_do` performs the whole transfer in one shot and sets `*done = TRUE`
//! unconditionally. Its exact steps, reproduced here:
//!
//! 1. **Build the raw path.** Combine the URL path with the query, if present:
//!    `curl_maprintf("%s?%s", path, query)` when a query exists, otherwise a
//!    plain copy of `path`. See [`build_selector`].
//! 2. **Derive the selector.** If the combined path's length is `<= 2` (the
//!    degenerate `"/"` and `"/1"` cases) the selector is the empty string.
//!    Otherwise curl drops the leading `/` **and the item-type character**
//!    (`newp += 2`) and then URL-unescapes the remainder with
//!    `Curl_urldecode(newp, 0, &buf, &len, REJECT_ZERO)`. See
//!    [`urldecode_reject_zero`].
//! 3. **Send the selector.** A send loop that tolerates partial writes
//!    (`Curl_xfer_send` "may not have written it all"); every chunk actually
//!    written is echoed to the client as a *header* write
//!    (`Curl_client_write(CLIENTWRITE_HEADER, …)`). See [`send_request`].
//! 4. **Send the terminator.** A trailing `"\r\n"` is written and likewise
//!    echoed as a header. A send failure produces the exact curl diagnostic
//!    `"Failed sending Gopher request"`.
//! 5. **Receive the body.** `Curl_xfer_setup_recv(data, FIRSTSOCKET, -1)` arms
//!    an unbounded (length `-1`) receive; the transfer engine then streams the
//!    response body to the write callback until the server closes the socket.
//!    See [`receive_response`].
//!
//! # Gopher `+` / search queries
//!
//! Gopher search / Gopher+ requests carry TAB-separated terms encoded in the
//! URL as `%09`. curl treats these no differently from any other selector
//! byte: they arrive via the path, survive URL-unescaping, and are sent
//! verbatim. This is the single most important fidelity detail of the whole
//! handler — see the *Fidelity notes* below.
//!
//! # Module layout / house style
//!
//! Mirroring the sibling [`crate::dns`] `SystemResolver`, the trait object is a
//! zero-sized [`GopherHandler`] whose [`Protocol`] methods are thin adapters,
//! while the real, fully-tested behavior lives in free `async fn`s over generic
//! [`tokio`] byte streams ([`build_selector`], [`send_request`],
//! [`receive_response`], [`perform`], [`connect_tls`]). The single [`HANDLER`]
//! singleton backs **both** the `gopher` and `gophers` scheme-table entries in
//! [`crate::protocols`] (a `gophers` transfer is simply a `gopher` transfer
//! whose socket has first been wrapped in TLS via [`connect_tls`]).
//!
//! # Fidelity notes
//!
//! * **`REJECT_ZERO`, not `REJECT_CTRL`.** curl decodes the selector with
//!   `REJECT_ZERO`, which rejects **only** a decoded NUL (`0x00`) and lets every
//!   other byte through — crucially the TAB (`0x09`) used by Gopher search.
//!   The shared [`crate::escape`] helper can only express `REJECT_NADA` /
//!   `REJECT_CTRL` (the latter would wrongly reject TAB), and it is not a
//!   dependency of this module, so [`urldecode_reject_zero`] reimplements the
//!   exact `Curl_urldecode` byte loop from `lib/escape.c`.
//! * **`'+'` is a literal.** Gopher selector decoding is *not* form decoding;
//!   `'+'` is passed through unchanged (curl never maps it to a space here).
//! * **EOF framing.** The response is read straight through to the body sink
//!   until the connection closes; there is no `Content-Length` equivalent.
//! * **Error codes are frozen ABI.** A decoded NUL yields
//!   [`CurlCode::UrlMalformat`] (`3`); a send failure yields
//!   [`CurlCode::SendError`] (`55`) with curl's `"Failed sending Gopher
//!   request"` text; a receive failure yields [`CurlCode::RecvError`] (`56`).
//! * **`*done = TRUE` / `done = ZERO_NULL`.** [`GopherHandler::do_it`] returns
//!   `Ok(true)` (the DO phase completes in a single step, exactly as
//!   `gopher_do` sets `*done = TRUE`), and [`GopherHandler::done`] is a no-op
//!   (`gopher.c` leaves the `done` function pointer `ZERO_NULL`).
//!
//! # Memory safety
//!
//! The crate root's compiler-enforced safe-code policy (declared in `lib.rs`)
//! applies here: this module — like all of `curl-rs-lib/src/` — contains
//! **zero** memory-unchecked code. All manual
//! `malloc`/`free`/`realloc` bookkeeping from `lib/gopher.c` (the `gopherpath`
//! allocation, the `buf_alloc` decode buffer, and their `curlx_free` calls)
//! is subsumed by Rust ownership: [`String`]/[`Vec<u8>`] free themselves.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::conn::FIRSTSOCKET;
use crate::error::{CurlCode, Error, Result};
use crate::protocols::{ProtoFuture, Protocol, TransferCtx};
use crate::tls::{TlsConnector, TlsStream};

/// Socket slot used by a Gopher transfer (← `conn->sock[FIRSTSOCKET]` in
/// `gopher_do`).
///
/// Gopher is strictly single-connection: the whole request/response exchange
/// happens over the one primary socket, so both the selector send and the
/// EOF-terminated body receive operate on [`FIRSTSOCKET`]. Exposed as a named
/// constant so the wiring layer references the same slot curl does.
pub const GOPHER_SOCKET_INDEX: usize = FIRSTSOCKET;

/// The trailing selector terminator every Gopher request ends with
/// (← the literal `"\r\n"` sent by `gopher_do`).
const GOPHER_EOL: &[u8; 2] = b"\r\n";

/// Chunk size for the EOF-terminated body read (mirrors curl's default
/// `buffer_size` of 16 KiB used to pump `Curl_xfer_setup_recv`). This only
/// bounds how much is read per `await`; the bytes delivered to the body sink in
/// aggregate are identical regardless of chunking.
const RECV_CHUNK: usize = 16 * 1024;

// ===========================================================================
// PHASE 1 — Selector construction (← the request-building half of `gopher_do`).
// ===========================================================================

/// Returns the numeric value of a single ASCII hex digit, or `None` for any
/// non-hex byte.
///
/// Matches curl's `ISXDIGIT` + `curlx_hexval`: `0-9`, `a-f`, and `A-F` are all
/// accepted (lower- and upper-case alike); everything else is rejected so the
/// surrounding `%` is treated as a literal (see [`urldecode_reject_zero`]).
#[inline]
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// URL-unescapes a Gopher selector exactly as curl's
/// `Curl_urldecode(string, 0, …, REJECT_ZERO)` does (← `lib/escape.c`).
///
/// This is a faithful reimplementation of curl's decode loop, chosen over the
/// shared [`crate::escape`] helper because that helper only offers
/// `REJECT_NADA` / `REJECT_CTRL`, and `REJECT_CTRL` would wrongly reject the
/// TAB (`0x09`) that Gopher search requires. The exact rules:
///
/// * **`length == 0` ⇒ `strlen`.** curl computes `alloc = strlen(string)`, so
///   decoding stops at the first literal NUL byte; anything after it is
///   ignored. This function truncates `input` at the first `0x00` accordingly.
/// * **`%XX` decoding.** A `%` is decoded only when at least two bytes follow
///   *and* both are hex digits (curl's `alloc > 2 && ISXDIGIT(s[1]) &&
///   ISXDIGIT(s[2])`); otherwise the `%` is emitted literally.
/// * **`'+'` is literal** — this is not form decoding.
/// * **`REJECT_ZERO`.** Every produced byte is checked; a decoded `0x00`
///   (i.e. a `%00` sequence) aborts with [`CurlCode::UrlMalformat`] via
///   [`Error::url`], exactly like curl returning `CURLE_URL_MALFORMAT`.
///
/// # Errors
///
/// Returns [`Error::Url`] ([`CurlCode::UrlMalformat`], `3`) if the decoded
/// output would contain a NUL byte.
pub fn urldecode_reject_zero(input: &[u8]) -> Result<Vec<u8>> {
    // `length == 0` in Curl_urldecode means "use strlen(string)": decoding runs
    // only up to the first literal NUL. Truncate here so the loop below matches
    // curl's `alloc` byte-for-byte.
    let end = input.iter().position(|&b| b == 0).unwrap_or(input.len());
    let s = &input[..end];

    let mut out = Vec::with_capacity(s.len());
    let mut i = 0usize;
    while i < s.len() {
        // Decode `%XX` iff a full two-hex-digit escape follows the `%`
        // (curl: `alloc > 2 && ISXDIGIT(s[1]) && ISXDIGIT(s[2])`). `s.len() - i`
        // is curl's remaining `alloc` including the current `%`.
        let decoded = if s[i] == b'%' && (s.len() - i) > 2 {
            match (hex_val(s[i + 1]), hex_val(s[i + 2])) {
                (Some(hi), Some(lo)) => {
                    let byte = (hi << 4) | lo;
                    i += 3;
                    byte
                }
                // A `%` not followed by two hex digits is a literal `%`.
                _ => {
                    i += 1;
                    b'%'
                }
            }
        } else {
            let byte = s[i];
            i += 1;
            byte
        };

        // REJECT_ZERO: reject only a decoded NUL. (A literal NUL can never reach
        // here — it was truncated by the `strlen` step above — so in practice
        // this fires solely on a `%00` escape, matching curl.)
        if decoded == 0 {
            return Err(Error::url(
                "gopher selector contains a rejected NUL byte (%00)",
            ));
        }
        out.push(decoded);
    }

    Ok(out)
}

/// Builds the raw Gopher selector bytes from a URL `path` and optional `query`
/// (← the selector-derivation block of `gopher_do`).
///
/// Reproduces curl exactly:
///
/// 1. Combine into the "gopherpath": `format!("{path}?{query}")` when a query is
///    present (curl's `curl_maprintf("%s?%s", …)`), otherwise just `path`
///    (curl's `strdup(path)`).
/// 2. **Degenerate cases.** If the combined path's `strlen` is `<= 2` — the
///    `"/"` and `"/1"` forms that carry no real selector — the selector is
///    empty (`Vec::new()`).
/// 3. Otherwise drop the leading `/` and the item-type character (`newp += 2`)
///    and URL-unescape the remainder with [`urldecode_reject_zero`].
///
/// `path` is expected to be the already-parsed URL path (which always begins
/// with `/`), exactly as `data->state.up.path` is guaranteed non-NULL in curl.
///
/// # Errors
///
/// Propagates [`Error::Url`] from [`urldecode_reject_zero`] if the selector
/// would decode to a byte sequence containing a NUL.
pub fn build_selector(path: &str, query: Option<&str>) -> Result<Vec<u8>> {
    // Step 1: assemble the combined path (curl_maprintf / strdup).
    let gopherpath = match query {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    };

    // curl measures the combined path with strlen; replicate that (stop at the
    // first NUL, which cannot occur for a parsed URL path but is handled for
    // exactness).
    let bytes = gopherpath.as_bytes();
    let strlen = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());

    // Step 2: degenerate "/" and "/1" cases -> empty selector.
    if strlen <= 2 {
        return Ok(Vec::new());
    }

    // Step 3: drop '/' + item-type char, then URL-unescape (REJECT_ZERO).
    urldecode_reject_zero(&bytes[2..strlen])
}

// ===========================================================================
// PHASE 2 — Send / receive (← the transmit + `setup_recv` half of `gopher_do`).
// ===========================================================================

/// Builds the exact error curl reports when a Gopher request cannot be sent.
///
/// `gopher_do` funnels every wire-send failure — a failed `Curl_xfer_send` of
/// the selector or of the terminator, or the socket becoming unwritable — into
/// a single `failf(data, "Failed sending Gopher request")` followed by
/// returning the send error. This bundles the frozen [`CurlCode::SendError`]
/// (`55`) with that verbatim diagnostic text.
#[inline]
fn send_error() -> Error {
    Error::with_context(CurlCode::SendError, "Failed sending Gopher request")
}

/// Sends a Gopher selector followed by the `"\r\n"` terminator, echoing every
/// byte actually written to `header_sink` (← the send loop of `gopher_do`).
///
/// Faithful reproduction of curl's transmit loop:
///
/// * **Partial writes.** `Curl_xfer_send` "may not have written it all", so the
///   selector is written in a loop; each iteration echoes exactly the bytes
///   just written to the client as a header write
///   (`Curl_client_write(CLIENTWRITE_HEADER, buf, nwritten)`), then advances
///   past them. The loop ends when the whole selector has been sent.
/// * **Terminator.** After the selector, `"\r\n"` is written and likewise
///   echoed as a header. (curl issues a single `Curl_xfer_send` for the two
///   bytes and relies on the socket accepting both; [`AsyncWriteExt::write_all`]
///   realizes that assumption.)
/// * **Flush.** A final flush guarantees the request has reached the peer
///   before the caller blocks reading the EOF-framed response. This changes no
///   wire bytes; it only orders the half-duplex exchange.
///
/// `header_sink` is the [`Protocol::write_resp_hd`] analogue: for a Gopher
/// request the selector and its terminator are surfaced to the caller as
/// *header* bytes, exactly as curl echoes them via `CLIENTWRITE_HEADER`.
///
/// # Errors
///
/// * A transport write failure — including the writer refusing further bytes
///   (a zero-length write on a non-empty buffer, curl's "socket no longer
///   writable") — yields [`send_error`] ([`CurlCode::SendError`], `55`).
/// * An error returned by `header_sink` is propagated unchanged, mirroring curl
///   returning the `Curl_client_write` result code as-is.
pub async fn send_request<W, H>(writer: &mut W, selector: &[u8], mut header_sink: H) -> Result<()>
where
    W: AsyncWrite + Unpin,
    H: FnMut(&[u8]) -> Result<()>,
{
    // Send loop over the selector, tolerating partial writes.
    let mut remaining = selector;
    while !remaining.is_empty() {
        let n = writer.write(remaining).await.map_err(|_| send_error())?;
        if n == 0 {
            // The peer will accept no more data: curl's send loop would spin on
            // SOCKET_WRITABLE and ultimately fail. Report the send error now
            // rather than loop forever.
            return Err(send_error());
        }
        // The AsyncWrite contract guarantees `n <= remaining.len()`; clamp
        // defensively (curl's `DEBUGASSERT(nwritten <= buf_len)`) so a
        // misbehaving writer can never trigger a slice panic.
        let n = n.min(remaining.len());

        // Echo exactly what was written to the header sink (CLIENTWRITE_HEADER).
        header_sink(&remaining[..n])?;
        remaining = &remaining[n..];
    }

    // Terminator: "\r\n" on the wire, then echoed as a header, then flushed.
    writer
        .write_all(GOPHER_EOL.as_slice())
        .await
        .map_err(|_| send_error())?;
    writer.flush().await.map_err(|_| send_error())?;
    header_sink(GOPHER_EOL.as_slice())?;

    Ok(())
}

/// Streams the Gopher response body to `body_sink` until the server closes the
/// connection (← `Curl_xfer_setup_recv(data, FIRSTSOCKET, -1)`).
///
/// Gopher has no length framing: curl arms an *unbounded* receive (length `-1`)
/// and the transfer engine copies bytes from the socket into the body write
/// callback until EOF. This reproduces that precisely — read into a scratch
/// buffer and hand each non-empty chunk to `body_sink` (the
/// [`Protocol::write_resp`] / `CLIENTWRITE_BODY` analogue) until a zero-length
/// read signals the peer has closed.
///
/// # Errors
///
/// * A transport read failure yields [`Error::Recv`] ([`CurlCode::RecvError`],
///   `56`).
/// * An error returned by `body_sink` is propagated unchanged, mirroring curl
///   returning the `Curl_client_write` result code as-is.
pub async fn receive_response<R, B>(reader: &mut R, mut body_sink: B) -> Result<()>
where
    R: AsyncRead + Unpin,
    B: FnMut(&[u8]) -> Result<()>,
{
    let mut buf = [0u8; RECV_CHUNK];
    loop {
        let n = reader.read(&mut buf).await.map_err(|_| Error::Recv)?;
        if n == 0 {
            // EOF: the server closed the connection — the Gopher response is
            // complete (there is no other end-of-body signal).
            break;
        }
        body_sink(&buf[..n])?;
    }
    Ok(())
}

// ===========================================================================
// PHASE 3 — End-to-end drive, `gophers` TLS upgrade, and the `Protocol` impl.
// ===========================================================================

/// Runs a complete Gopher exchange over an already-connected byte stream
/// (← the full body of `gopher_do`, top to bottom).
///
/// Ties the three stages together in curl's order: build the selector from
/// `path`/`query`, send it (with its `"\r\n"` terminator) while echoing to
/// `header_sink`, then stream the EOF-framed response to `body_sink`. The send
/// completes fully before the receive begins — Gopher is a strict half-duplex
/// request/response, so this sequencing matches the wire exactly.
///
/// `stream` is any TCP-like duplex byte stream. For a `gophers` transfer it is
/// the [`TlsStream`] produced by [`connect_tls`]; because that type implements
/// [`AsyncRead`] + [`AsyncWrite`], the identical code path serves both schemes,
/// exactly as `gopher.c` runs the same `gopher_do` for `gopher` and `gophers`.
///
/// # Errors
///
/// Propagates any error from [`build_selector`], [`send_request`], or
/// [`receive_response`] (URL-malformat, send, or receive failures, plus any
/// error surfaced by the sinks) with the frozen curl codes intact.
pub async fn perform<S, H, B>(
    stream: &mut S,
    path: &str,
    query: Option<&str>,
    header_sink: H,
    body_sink: B,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: FnMut(&[u8]) -> Result<()>,
    B: FnMut(&[u8]) -> Result<()>,
{
    let selector = build_selector(path, query)?;
    send_request(stream, &selector, header_sink).await?;
    receive_response(stream, body_sink).await?;
    Ok(())
}

/// Upgrades a plain byte stream to TLS for the `gophers` scheme
/// (← the `PROTOPT_SSL` / `gopher_connecting` → `Curl_conn_connect(…, TRUE)`
/// path in `lib/gopher.c`).
///
/// `gophers` is nothing more than `gopher` carried over TLS: curl flags the
/// scheme `PROTOPT_SSL` and drives a TLS handshake at connect time, then runs
/// the very same `gopher_do`. This helper performs that handshake through the
/// crate's single [`rustls`](crate::tls)-backed [`TlsConnector`], yielding a
/// [`TlsStream`] that [`perform`] then uses unchanged. Certificate validation
/// is governed entirely by the [`TlsConfig`](crate::tls::TlsConfig) the
/// `connector` was built from (validation is on by default, per the AAP).
///
/// # Errors
///
/// Propagates the handshake error mapping from [`TlsConnector::connect`]:
/// certificate-verification failures surface as
/// [`CurlCode::PeerFailedVerification`](crate::error::CurlCode::PeerFailedVerification)
/// (`60`) and every other handshake failure as
/// [`CurlCode::SslConnectError`](crate::error::CurlCode::SslConnectError) (`35`).
pub async fn connect_tls<S>(
    connector: &TlsConnector,
    server_name: &str,
    stream: S,
) -> Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    connector.connect(server_name, stream).await
}

/// The Gopher / Gophers protocol handler (← `Curl_handler_gopher` /
/// `Curl_handler_gophers`, `lib/gopher.c`).
///
/// A zero-sized singleton — a single shared [`HANDLER`] instance backs both the
/// `gopher` and `gophers` scheme-table entries in [`crate::protocols`], just as
/// `gopher.c` points both `struct Curl_handler`s at the same `gopher_do`. The
/// real transfer logic lives in the free functions above ([`perform`] and its
/// building blocks); the trait methods here reproduce curl's control-flow
/// signals at the [`Protocol`] boundary.
#[derive(Debug, Clone, Copy, Default)]
pub struct GopherHandler;

/// The shared Gopher/Gophers handler singleton referenced by the scheme table
/// (`&gopher::HANDLER` for both `SCHEME_GOPHER` and `SCHEME_GOPHERS`).
pub static HANDLER: GopherHandler = GopherHandler;

impl Protocol for GopherHandler {
    /// DO phase (← `gopher_do`). `gopher_do` performs the entire request /
    /// response in one call and sets `*done = TRUE` unconditionally, so the DO
    /// phase always completes in a single step: this returns `Ok(true)`.
    ///
    /// Drives the concrete transfer over the connection byte stream
    /// ([`TransferCtx::io`]): the selector is built from the URL path and
    /// optional query ([`build_selector`]), sent with its `"\r\n"` terminator
    /// (partial-write tolerant, exactly as [`send_request`]), and the
    /// EOF-framed response body is streamed to the download sink
    /// ([`TransferCtx::sink`]) in bounded [`RECV_CHUNK`] pieces (as
    /// [`receive_response`]). Gopher is strict half-duplex, so the send
    /// completes fully before the receive begins. `gophers` reaches this same
    /// code with a [`TlsStream`] behind [`TransferCtx::io`] (see [`connect_tls`]),
    /// mirroring `gopher.c` running one `gopher_do` for both schemes.
    ///
    /// The selector echo that curl routes to `CLIENTWRITE_HEADER` is not
    /// duplicated into the body here: [`TransferCtx`] exposes only a body sink,
    /// matching a plain `gopher://` fetch where the selector is not part of the
    /// output.
    ///
    /// # Errors
    ///
    /// [`CURLE_URL_MALFORMAT`](crate::error::CurlCode::UrlMalformat) if the
    /// selector fails `REJECT_ZERO` decoding, [`CURLE_COULDNT_CONNECT`](crate::error::CurlCode::CouldntConnect)
    /// if no connection stream is present, and the send/receive I/O errors
    /// ([`CurlCode::SendError`] / [`CurlCode::RecvError`]) surfaced by the stream.
    fn do_it<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        Box::pin(async move {
            // Build the selector first: an owned `Vec`, so the immutable borrow
            // of `ctx.request` is released before the transport/sink borrows.
            let selector = build_selector(&ctx.request.path, ctx.request.query.as_deref())?;

            // Disjoint field borrows: the connection byte stream and the sink.
            let stream = ctx.io.as_deref_mut().ok_or_else(|| {
                Error::with_context(
                    CurlCode::CouldntConnect,
                    "[GOPHER] no connection stream for the request",
                )
            })?;
            let mut sink = ctx.sink.as_deref_mut();

            // --- Send: the selector (tolerating partial writes), then the
            // "\r\n" terminator, then flush (← the transmit half of gopher_do,
            // identical to `send_request`).
            let mut remaining: &[u8] = &selector;
            while !remaining.is_empty() {
                let n = stream.write(remaining).await.map_err(|_| send_error())?;
                if n == 0 {
                    // The peer accepts no more data: curl's send loop would spin
                    // on SOCKET_WRITABLE and ultimately fail. Report it now.
                    return Err(send_error());
                }
                // The AsyncWrite contract guarantees `n <= remaining.len()`;
                // clamp defensively (curl's `DEBUGASSERT`) against a slice panic.
                let n = n.min(remaining.len());
                remaining = &remaining[n..];
            }
            stream
                .write_all(GOPHER_EOL.as_slice())
                .await
                .map_err(|_| send_error())?;
            stream.flush().await.map_err(|_| send_error())?;

            // --- Receive: stream the EOF-framed response body to the sink in
            // bounded chunks (← `Curl_xfer_setup_recv(data, FIRSTSOCKET, -1)`);
            // Gopher has no length framing, so EOF (a zero-length read) is the
            // only end-of-body signal.
            let mut buf = [0u8; RECV_CHUNK];
            loop {
                let n = stream.read(&mut buf).await.map_err(|_| Error::Recv)?;
                if n == 0 {
                    break;
                }
                if let Some(sink) = sink.as_deref_mut() {
                    sink.write(&buf[..n])?;
                }
            }
            Ok(true)
        })
    }

    /// DONE phase (← the `done` slot of `struct Curl_handler`). `gopher.c`
    /// leaves this pointer `ZERO_NULL`: Gopher opens no protocol-specific state
    /// (no login, no channels, no post-transfer commands), so there is nothing
    /// to tear down and the outcome is ignored. Faithfully a no-op.
    fn done<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        status: Result<()>,
        premature: bool,
    ) -> ProtoFuture<'a, ()> {
        let _ = (ctx, status, premature);
        Box::pin(async { Ok(()) })
    }
}

// ===========================================================================
// Tests — hermetic and in-process (tokio duplex streams; an in-process rustls
// server via rcgen for the `gophers` path). No external daemons, per the AAP
// behavioral-parity gate.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::TransferSink;
    use std::io;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // ---------------------------------------------------------------------
    // Test doubles for `AsyncWrite` (all safe: `Pin::get_mut` on `Unpin`).
    // ---------------------------------------------------------------------

    /// A writer that accepts at most `max_per_write` bytes per `poll_write`,
    /// deterministically forcing the partial-write path of [`send_request`].
    struct ChunkWriter {
        written: Vec<u8>,
        max_per_write: usize,
    }

    impl AsyncWrite for ChunkWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let me = self.get_mut();
            let n = buf.len().min(me.max_per_write);
            me.written.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A writer that always reports zero bytes written — the "socket no longer
    /// writable" condition that must map to [`CurlCode::SendError`].
    struct ZeroWriter;

    impl AsyncWrite for ZeroWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(0))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    // ---------------------------------------------------------------------
    // PHASE 1 — `urldecode_reject_zero` (← Curl_urldecode, REJECT_ZERO).
    // ---------------------------------------------------------------------

    #[test]
    fn urldecode_passthrough_and_percent() {
        assert_eq!(urldecode_reject_zero(b"abc").unwrap(), b"abc");
        assert_eq!(urldecode_reject_zero(b"a%20b").unwrap(), b"a b");
        // Case-insensitive hex, both nibbles.
        assert_eq!(urldecode_reject_zero(b"%4a").unwrap(), b"J");
        assert_eq!(urldecode_reject_zero(b"%4A").unwrap(), b"J");
        assert_eq!(urldecode_reject_zero(b"%2f%2F").unwrap(), b"//");
    }

    #[test]
    fn urldecode_preserves_tab_and_plus() {
        // The crucial Gopher-search detail: TAB (0x09) survives REJECT_ZERO,
        // whereas REJECT_CTRL (all curl's shared helper offers) would reject it.
        assert_eq!(urldecode_reject_zero(b"tab%09here").unwrap(), b"tab\there");
        // '+' is a literal — this is not form decoding.
        assert_eq!(urldecode_reject_zero(b"a+b").unwrap(), b"a+b");
    }

    #[test]
    fn urldecode_literal_percent_when_not_a_full_escape() {
        // Lone '%' at end (fewer than two following bytes) -> literal.
        assert_eq!(urldecode_reject_zero(b"end%").unwrap(), b"end%");
        // '%' followed by non-hex -> literal '%', then the bytes verbatim.
        assert_eq!(urldecode_reject_zero(b"x%zz").unwrap(), b"x%zz");
        // '%' with a single trailing hex digit (still not a full escape).
        assert_eq!(urldecode_reject_zero(b"p%9").unwrap(), b"p%9");
    }

    #[test]
    fn urldecode_rejects_decoded_nul() {
        let err = urldecode_reject_zero(b"a%00b").expect_err("%00 must be rejected");
        assert_eq!(err.code(), CurlCode::UrlMalformat);
        assert_eq!(err.code_i32(), 3);
    }

    #[test]
    fn urldecode_truncates_at_literal_nul() {
        // `length == 0` in Curl_urldecode means strlen: stop at the first
        // literal NUL, ignore the rest (a literal NUL never triggers REJECT_ZERO).
        assert_eq!(urldecode_reject_zero(b"a\0b").unwrap(), b"a");
        assert_eq!(urldecode_reject_zero(b"\0abc").unwrap(), b"");
    }

    // ---------------------------------------------------------------------
    // PHASE 1 — `build_selector` (← selector-derivation block of gopher_do).
    // ---------------------------------------------------------------------

    #[test]
    fn build_selector_degenerate_cases_are_empty() {
        // "/" and "/1" (strlen <= 2) carry no selector.
        assert_eq!(build_selector("/", None).unwrap(), b"");
        assert_eq!(build_selector("/1", None).unwrap(), b"");
    }

    #[test]
    fn build_selector_drops_slash_and_item_type_char() {
        // Leading '/' and the item-type char are dropped (newp += 2).
        assert_eq!(build_selector("/1caps.txt", None).unwrap(), b"caps.txt");
        assert_eq!(build_selector("/12", None).unwrap(), b"2");
        // ...then the remainder is URL-unescaped.
        assert_eq!(build_selector("/1a%20b", None).unwrap(), b"a b");
        assert_eq!(build_selector("/1a+b", None).unwrap(), b"a+b");
    }

    #[test]
    fn build_selector_preserves_tab_search() {
        // Gopher search: %09 TAB survives into the selector.
        assert_eq!(
            build_selector("/1dir%09query", None).unwrap(),
            b"dir\tquery"
        );
    }

    #[test]
    fn build_selector_appends_query_before_stripping() {
        // curl_maprintf("%s?%s", path, query) then drop '/' + type char.
        assert_eq!(build_selector("/7", Some("query")).unwrap(), b"?query");
        assert_eq!(build_selector("/1foo", Some("bar")).unwrap(), b"foo?bar");
    }

    #[test]
    fn build_selector_rejects_encoded_nul() {
        let err = build_selector("/1a%00b", None).expect_err("%00 must be rejected");
        assert_eq!(err.code(), CurlCode::UrlMalformat);
    }

    // ---------------------------------------------------------------------
    // PHASE 2 — `send_request`.
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn send_request_writes_selector_then_crlf_and_echoes_header() {
        let mut wire: Vec<u8> = Vec::new();
        let mut header: Vec<u8> = Vec::new();
        send_request(&mut wire, b"caps.txt", |b: &[u8]| {
            header.extend_from_slice(b);
            Ok(())
        })
        .await
        .expect("send ok");
        assert_eq!(wire.as_slice(), &b"caps.txt\r\n"[..]);
        assert_eq!(header.as_slice(), &b"caps.txt\r\n"[..]);
    }

    #[tokio::test]
    async fn send_request_empty_selector_sends_only_crlf() {
        let mut wire: Vec<u8> = Vec::new();
        let mut header: Vec<u8> = Vec::new();
        send_request(&mut wire, b"", |b: &[u8]| {
            header.extend_from_slice(b);
            Ok(())
        })
        .await
        .expect("send ok");
        assert_eq!(wire.as_slice(), &b"\r\n"[..]);
        assert_eq!(header.as_slice(), &b"\r\n"[..]);
    }

    #[tokio::test]
    async fn send_request_reassembles_across_partial_writes() {
        let mut w = ChunkWriter {
            written: Vec::new(),
            max_per_write: 3,
        };
        let mut header: Vec<u8> = Vec::new();
        send_request(&mut w, b"long-selector-value", |b: &[u8]| {
            header.extend_from_slice(b);
            Ok(())
        })
        .await
        .expect("send ok");
        // Despite 3-byte-at-a-time writes, the whole selector + CRLF is sent...
        assert_eq!(w.written.as_slice(), &b"long-selector-value\r\n"[..]);
        // ...and the header echo aggregates to exactly the same bytes.
        assert_eq!(header.as_slice(), &b"long-selector-value\r\n"[..]);
    }

    #[tokio::test]
    async fn send_request_propagates_header_sink_error_unchanged() {
        let mut wire: Vec<u8> = Vec::new();
        let err = send_request(&mut wire, b"sel", |_b: &[u8]| {
            Err(Error::with_context(CurlCode::WriteError, "boom"))
        })
        .await
        .expect_err("header-sink error propagates");
        // curl returns the Curl_client_write result code as-is (not SendError).
        assert_eq!(err.code(), CurlCode::WriteError);
        assert_eq!(err.code_i32(), 23);
    }

    #[tokio::test]
    async fn send_request_zero_write_maps_to_send_error() {
        let mut w = ZeroWriter;
        let mut header: Vec<u8> = Vec::new();
        let err = send_request(&mut w, b"sel", |b: &[u8]| {
            header.extend_from_slice(b);
            Ok(())
        })
        .await
        .expect_err("a refusing writer must fail the send");
        assert_eq!(err.code(), CurlCode::SendError);
        assert_eq!(err.code_i32(), 55);
        assert!(
            header.is_empty(),
            "nothing is echoed when the wire refuses the write"
        );
    }

    // ---------------------------------------------------------------------
    // PHASE 2 — `receive_response`.
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn receive_response_streams_until_eof() {
        let data: &[u8] = b"one two three";
        let mut r = data;
        let mut body: Vec<u8> = Vec::new();
        receive_response(&mut r, |b: &[u8]| {
            body.extend_from_slice(b);
            Ok(())
        })
        .await
        .expect("recv ok");
        assert_eq!(body.as_slice(), &b"one two three"[..]);
    }

    #[tokio::test]
    async fn receive_response_empty_body_is_ok() {
        let data: &[u8] = b"";
        let mut r = data;
        let mut calls = 0usize;
        receive_response(&mut r, |_b: &[u8]| {
            calls += 1;
            Ok(())
        })
        .await
        .expect("recv ok");
        assert_eq!(calls, 0, "an immediate EOF yields no body chunks");
    }

    #[tokio::test]
    async fn receive_response_propagates_body_sink_error_unchanged() {
        let data: &[u8] = b"x";
        let mut r = data;
        let err = receive_response(&mut r, |_b: &[u8]| {
            Err(Error::with_context(CurlCode::WriteError, "boom"))
        })
        .await
        .expect_err("body-sink error propagates");
        assert_eq!(err.code(), CurlCode::WriteError);
    }

    // ---------------------------------------------------------------------
    // PHASE 3 — end-to-end `perform` over a plain duplex stream.
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn perform_sends_selector_and_streams_body_to_eof() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let server_task = tokio::spawn(async move {
            let mut req = Vec::new();
            let mut buf = [0u8; 256];
            loop {
                let n = server.read(&mut buf).await.expect("server read");
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
                if req.ends_with(b"\r\n") {
                    break;
                }
            }
            server
                .write_all(b"gopher-body-bytes")
                .await
                .expect("server write");
            server.flush().await.expect("server flush");
            drop(server); // close -> EOF for the client's receive
            req
        });

        let mut header: Vec<u8> = Vec::new();
        let mut body: Vec<u8> = Vec::new();
        perform(
            &mut client,
            "/0read-me.txt",
            None,
            |b: &[u8]| {
                header.extend_from_slice(b);
                Ok(())
            },
            |b: &[u8]| {
                body.extend_from_slice(b);
                Ok(())
            },
        )
        .await
        .expect("perform ok");

        let req = server_task.await.expect("server task joins");
        // The wire carried exactly the selector + CRLF...
        assert_eq!(req.as_slice(), &b"read-me.txt\r\n"[..]);
        // ...which is also what the header sink saw...
        assert_eq!(header.as_slice(), &b"read-me.txt\r\n"[..]);
        // ...and the EOF-framed response reached the body sink intact.
        assert_eq!(body.as_slice(), &b"gopher-body-bytes"[..]);
    }

    // ---------------------------------------------------------------------
    // PHASE 3 — `gophers`: the identical exchange over TLS (rcgen + rustls).
    // ---------------------------------------------------------------------

    /// Installs the process-default aws-lc-rs crypto provider (idempotent).
    fn ensure_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    /// Ephemeral self-signed `localhost` server config + its cert in PEM (so the
    /// client can trust it as a private CA), mirroring `tls::mod` test helpers.
    fn make_server() -> (std::sync::Arc<rustls::ServerConfig>, Vec<u8>) {
        ensure_provider();
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen self-signed generation");
        let ca_pem = certified.cert.pem().into_bytes();
        let cert_der = certified.cert.der().clone();
        let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()),
        );
        let cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server config builds");
        (std::sync::Arc::new(cfg), ca_pem)
    }

    #[tokio::test]
    async fn gophers_runs_gopher_exchange_over_tls() {
        let (server_cfg, ca_pem) = make_server();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let server_task = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
            let mut tls = acceptor.accept(server_io).await.expect("server accept");
            let mut req = Vec::new();
            let mut buf = [0u8; 256];
            loop {
                let n = tls.read(&mut buf).await.expect("server read");
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
                if req.ends_with(b"\r\n") {
                    break;
                }
            }
            tls.write_all(b"secure-gopher-body")
                .await
                .expect("server write");
            tls.flush().await.expect("server flush");
            // Clean close_notify -> the client sees a graceful EOF.
            let _ = tls.shutdown().await;
            req
        });

        // Trust the server's ephemeral cert as a private CA (validation stays on).
        let cfg = crate::tls::TlsConfig::default()
            .with_webpki_roots(false)
            .with_ca_info_blob(ca_pem);
        let connector = TlsConnector::from_config(&cfg).expect("connector builds");
        let mut stream = connect_tls(&connector, "localhost", client_io)
            .await
            .expect("gophers TLS handshake succeeds against trusted cert");

        let mut header: Vec<u8> = Vec::new();
        let mut body: Vec<u8> = Vec::new();
        // Include a %09 TAB search term to prove REJECT_ZERO parity end-to-end.
        perform(
            &mut stream,
            "/1search%09term",
            None,
            |b: &[u8]| {
                header.extend_from_slice(b);
                Ok(())
            },
            |b: &[u8]| {
                body.extend_from_slice(b);
                Ok(())
            },
        )
        .await
        .expect("gophers perform ok");

        let req = server_task.await.expect("server task joins");
        assert_eq!(req.as_slice(), &b"search\tterm\r\n"[..]);
        assert_eq!(header.as_slice(), &b"search\tterm\r\n"[..]);
        assert_eq!(body.as_slice(), &b"secure-gopher-body"[..]);
    }

    // ---------------------------------------------------------------------
    // PHASE 3 — the `Protocol` handler adapter.
    // ---------------------------------------------------------------------

    /// A shared-buffer [`TransferSink`] recording delivered body chunks, so a
    /// test can assert what the handler streamed to the download.
    struct RecordingSink(Arc<Mutex<Vec<u8>>>);
    impl TransferSink for RecordingSink {
        fn write(&mut self, data: &[u8]) -> Result<()> {
            self.0.lock().expect("sink lock").extend_from_slice(data);
            Ok(())
        }
    }

    #[tokio::test]
    async fn handler_do_it_drives_selector_and_streams_body_to_sink() {
        // The DO phase must build the selector from the ctx path, send it with
        // its terminator, and stream the EOF-framed reply to the sink (←
        // `gopher_do` performing the whole exchange and setting `*done = TRUE`).
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut req = Vec::new();
            let mut buf = [0u8; 256];
            loop {
                let n = server_io.read(&mut buf).await.expect("server read");
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
                if req.ends_with(b"\r\n") {
                    break;
                }
            }
            server_io
                .write_all(b"gopher-body-bytes")
                .await
                .expect("server write");
            server_io.flush().await.expect("server flush");
            // Drop the server half so the client's EOF-framed receive completes.
            drop(server_io);
            req
        });

        let collected = Arc::new(Mutex::new(Vec::new()));
        let mut ctx = TransferCtx::new();
        ctx.request.path = "/1caption".to_string();
        ctx.io = Some(Box::new(client_io));
        ctx.sink = Some(Box::new(RecordingSink(Arc::clone(&collected))));

        let done = HANDLER
            .do_it(&mut ctx)
            .await
            .expect("do_it drives the gopher exchange");
        assert!(done, "gopher_do sets *done = TRUE unconditionally");

        let req = server.await.expect("server task joins");
        // "/1caption" drops the leading '/' + item-type '1' -> selector "caption".
        assert_eq!(req.as_slice(), &b"caption\r\n"[..]);
        assert_eq!(
            collected.lock().expect("sink").as_slice(),
            &b"gopher-body-bytes"[..],
            "the EOF-framed body is streamed to the sink"
        );
    }

    #[tokio::test]
    async fn handler_do_it_without_a_stream_reports_couldnt_connect() {
        // A request with no connection stream must surface CURLE_COULDNT_CONNECT
        // rather than silently succeeding (gopher always needs a connection).
        let mut ctx = TransferCtx::new();
        ctx.request.path = "/1x".to_string();
        let err = HANDLER.do_it(&mut ctx).await.unwrap_err();
        assert_eq!(err.code(), CurlCode::CouldntConnect);
    }

    #[tokio::test]
    async fn handler_done_is_a_noop_for_all_outcomes() {
        let mut ctx = TransferCtx::new();
        HANDLER
            .done(&mut ctx, Ok(()), false)
            .await
            .expect("done ok");
        let mut ctx2 = TransferCtx::new();
        HANDLER
            .done(&mut ctx2, Err(Error::Recv), true)
            .await
            .expect("done ok even when premature/failed");
    }

    #[test]
    fn handler_is_object_safe_for_the_scheme_table() {
        // The scheme table stores `&gopher::HANDLER` as `&dyn Protocol` for both
        // the `gopher` and `gophers` entries.
        let dynamic: &dyn Protocol = &HANDLER;
        let _ = dynamic;
    }

    #[test]
    fn handler_is_zero_sized() {
        assert_eq!(std::mem::size_of::<GopherHandler>(), 0);
    }
}
