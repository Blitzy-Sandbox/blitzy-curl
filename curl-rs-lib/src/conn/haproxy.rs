// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.
//! PROXY-protocol header-emission filter.
//!
//! This module is the Rust port of curl's `lib/cf-haproxy.c` (the
//! `Curl_cft_haproxy` connection filter). When `--haproxy-protocol` is set,
//! curl announces the real client address to the server it connects to by
//! prepending a single **PROXY protocol** header line to the byte stream,
//! immediately after the TCP connection is established and *before* any
//! application data. HAProxy (and other PROXY-protocol-aware servers) parse
//! that line to recover the originating client's address even though the
//! bytes arrive over curl's own socket.
//!
//! It is the simplest of curl's proxy filters: a *connect-then-passthrough*
//! layer. During [`connect`](ConnectionFilter::connect) it
//!
//! 1. drives the filter directly below it (the socket) to a connected state,
//! 2. builds the PROXY header from that socket's local/remote address, and
//! 3. writes the header out through the socket.
//!
//! Once the header has been sent the filter becomes a **transparent byte
//! relay**: `send`/`recv`/`data_pending`/`query` all inherit the
//! [`ConnectionFilter`] trait's default delegation to the next filter, exactly
//! as curl's descriptor wires every non-connect slot to `Curl_cf_def_*`.
//!
//! # Relationship to the C source-of-truth
//!
//! The implementation mirrors `cf-haproxy.c` so the emitted bytes are
//! byte-for-byte faithful to curl 8.x:
//!
//! * [`HaProxyState`] mirrors the C `haproxy_state` enum
//!   (`HAPROXY_INIT` / `HAPROXY_SEND` / `HAPROXY_DONE`).
//! * [`HaProxyFilter::build_header`] reproduces `cf_haproxy_date_out_set`: the
//!   fixed `"PROXY UNKNOWN\r\n"` line for a UNIX-domain socket, and the
//!   `"PROXY %s %s %s %i %i\r\n"` line (proto, client-ip, remote-ip,
//!   local-port, remote-port) otherwise.
//! * [`HaProxyFilter::connect`](ConnectionFilter::connect) reproduces
//!   `cf_haproxy_connect`, including the "drive the layer below first" gate and
//!   the `CURLE_AGAIN`/partial-write resume behaviour of `HAPROXY_SEND`.
//! * [`HaProxyFilter::close`](ConnectionFilter::close) reproduces
//!   `cf_haproxy_close`, and
//!   [`HaProxyFilter::adjust_pollset`](ConnectionFilter::adjust_pollset)
//!   reproduces `cf_haproxy_adjust_pollset` (wait for writability while the
//!   header is still outstanding).
//!
//! curl only ever emits the **PROXY protocol v1 (human-readable) text** form;
//! `cf-haproxy.c` contains no v2 (binary) code path, so — honouring the Minimal
//! Change Mandate — none is added here.
//!
//! # Design constraints
//!
//! * **Memory-safe.** Written entirely in safe Rust; the crate root's
//!   `#![forbid(unsafe_code)]` makes any `unsafe` token a hard compile error.
//! * **Tokio-only async.** All I/O flows through the sibling connection-filter
//!   contract ([`FilterCtx::send_next`] / [`FilterCtx::connect_next`]); there is
//!   no direct socket access here.
//! * **`Error::Proxy` (curl error 97).** A proxy-level failure surfaces as
//!   [`Error::proxy`]; a send failure propagates the underlying transport error
//!   verbatim, matching curl's `goto out` on a non-`CURLE_AGAIN` result.

use bytes::BytesMut;

use crate::conn::filters::{
    CfFuture, ConnectionFilter, FilterCtx, Pollset, QueryCtx, QueryOut, POLL_OUT,
};
use crate::conn::socket::CURL_SOCKET_BAD;
use crate::conn::{CfQuery, CfType, FilterChain, Transport};
use crate::error::{Error, Result};

// ===========================================================================
// Phase 1 — the connect state machine's states.
// ===========================================================================

/// The state of the PROXY-header handshake.
///
/// Exact parity with curl's `haproxy_state` enum (`lib/cf-haproxy.c`):
///
/// | Rust                    | C              | meaning                          |
/// |-------------------------|----------------|----------------------------------|
/// | [`HaProxyState::Init`]  | `HAPROXY_INIT` | initial / default, header unbuilt|
/// | [`HaProxyState::Send`]  | `HAPROXY_SEND` | the header is being written out  |
/// | [`HaProxyState::Done`]  | `HAPROXY_DONE` | header sent; filter transparent  |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HaProxyState {
    /// Init / default state: the PROXY header has not been built yet
    /// (`HAPROXY_INIT`).
    Init,
    /// The PROXY header has been built and is being sent to the peer
    /// (`HAPROXY_SEND`).
    Send,
    /// The PROXY header has been fully sent; the filter now relays bytes
    /// transparently (`HAPROXY_DONE`).
    Done,
}

// ===========================================================================
// The filter — the reimplementation of `struct cf_haproxy_ctx` + its vtable.
// ===========================================================================

/// The PROXY-protocol connection filter (curl's `Curl_cft_haproxy`).
///
/// A `HaProxyFilter` is installed directly above the socket filter (see
/// [`insert_after`]). During its connect it emits a single PROXY-protocol
/// header line; afterwards it is a transparent passthrough, so
/// `send`/`recv`/`data_pending`/`query` inherit the trait's default delegation
/// to the next filter (matching curl's `Curl_cf_def_*` vtable slots).
pub struct HaProxyFilter {
    /// The handshake state (curl's `ctx->state`).
    state: HaProxyState,
    /// The serialized PROXY header still awaiting transmission (curl's
    /// `ctx->data_out` dynbuf). Empty once fully sent.
    data_out: BytesMut,
    /// Whether the header has been sent and the filter is transparent (curl's
    /// `cf->connected`).
    connected: bool,
    /// The advertised client IP from `--haproxy-clientip`
    /// (`STRING_HAPROXY_CLIENT_IP`); when `None` the real local IP is used.
    client_ip: Option<String>,
}

impl HaProxyFilter {
    /// Creates a PROXY-protocol filter with no client-IP override, mirroring a
    /// default `cf_haproxy_create` (the header's client field defaults to the
    /// connection's real local IP).
    #[must_use]
    pub fn new() -> Self {
        Self::with_client_ip(None)
    }

    /// Creates a PROXY-protocol filter that advertises `client_ip` as the
    /// originating client address, reproducing curl's
    /// `data->set.str[STRING_HAPROXY_CLIENT_IP]` (the `--haproxy-clientip`
    /// option). Passing `None` falls back to the real local IP.
    #[must_use]
    pub fn with_client_ip(client_ip: Option<String>) -> Self {
        HaProxyFilter {
            state: HaProxyState::Init,
            data_out: BytesMut::new(),
            connected: false,
            client_ip,
        }
    }

    /// Builds the PROXY-protocol header into [`Self::data_out`], reproducing
    /// `cf_haproxy_date_out_set` exactly.
    ///
    /// The address information is read from the layer directly below this
    /// filter (the socket) through the connection-filter query mechanism —
    /// curl's `Curl_conn_cf_get_ip_info(cf->next, …)`:
    ///
    /// * A **UNIX-domain** connection (the socket below reports
    ///   [`Transport::Unix`]) has no IP peer, so the fixed line
    ///   `"PROXY UNKNOWN\r\n"` is emitted.
    /// * Otherwise the IPv6 flag and the local/remote address+port quadruple
    ///   are queried and formatted as `"PROXY %s %s %s %i %i\r\n"`
    ///   (`"TCP6"`/`"TCP4"`, client-ip, remote-ip, local-port, remote-port),
    ///   where the client-ip is the `--haproxy-clientip` override when set and
    ///   the real local IP otherwise.
    fn build_header(&mut self, cx: &FilterCtx<'_>) -> Result<()> {
        let mut buf = BytesMut::new();

        // Detect a UNIX-domain socket. curl checks `cf->conn->unix_domain_socket`
        // directly; in the filter model the transport carried by the socket
        // filter below conveys the same fact: TRNSPRT_UNIX <=> a UNIX socket.
        let mut transport_out = QueryOut::None;
        let is_unix = cx
            .query_next(CfQuery::Transport, &mut transport_out)
            .is_ok()
            && matches!(transport_out, QueryOut::Transport(Transport::Unix));

        if is_unix {
            // A UNIX-domain socket has no IP-level peer: emit curl's fixed line.
            buf.extend_from_slice(b"PROXY UNKNOWN\r\n");
        } else {
            // Read the connected address family + IP quadruple from the socket
            // below (curl's `Curl_conn_cf_get_ip_info(cf->next, …)`). A failure
            // here propagates exactly as curl returns the underlying result.
            let mut ip_out = QueryOut::None;
            cx.query_next(CfQuery::IpInfo, &mut ip_out)?;
            let (is_ipv6, quad) = match ip_out {
                QueryOut::IpInfo { is_ipv6, quad } => (is_ipv6, quad),
                _ => {
                    return Err(Error::proxy(
                        "HAProxy: connection IP information unavailable",
                    ))
                }
            };

            // "TCP6" for IPv6, "TCP4" for IPv4 (curl's exact prefixes).
            let proto = if is_ipv6 { "TCP6" } else { "TCP4" };
            // The advertised client IP: the `--haproxy-clientip` override when
            // set, otherwise the real local IP (curl's `ipquad.local_ip`).
            let client_ip = self.client_ip.as_deref().unwrap_or(quad.local_ip.as_str());

            // Exact curl format string: "PROXY %s %s %s %i %i\r\n"
            // (proto, client_ip, remote_ip, local_port, remote_port).
            let line = format!(
                "PROXY {proto} {client_ip} {} {} {}\r\n",
                quad.remote_ip, quad.local_port, quad.remote_port
            );
            buf.extend_from_slice(line.as_bytes());
        }

        self.data_out = buf;
        Ok(())
    }
}

impl Default for HaProxyFilter {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Phase 2 & 3 — the ConnectionFilter vtable (connect / close / pollset +
// transparent passthrough via the trait defaults).
// ===========================================================================

impl ConnectionFilter for HaProxyFilter {
    fn name(&self) -> &'static str {
        // curl's `Curl_cft_haproxy.name` — preserved verbatim for `--trace`.
        "HAPROXY"
    }

    fn cf_type(&self) -> CfType {
        // curl's `Curl_cft_haproxy.flags == CF_TYPE_PROXY` (1 << 3).
        CfType::PROXY
    }

    fn connect<'a>(
        &'a mut self,
        cx: &'a mut FilterCtx<'_>,
        blocking: bool,
    ) -> CfFuture<'a, Result<bool>> {
        Box::pin(async move {
            // Already done: the filter is a transparent passthrough from here on
            // (curl: `if(cf->connected) { *done = TRUE; return CURLE_OK; }`).
            if self.connected {
                return Ok(true);
            }

            // FIRST drive the layer below (the socket) to a connected state,
            // exactly like curl's `cf->next->cft->do_connect(cf->next, …)` gate:
            // `if(result || !*done) return result;`. If it is not connected yet
            // we propagate "not done" and will be re-driven later.
            if !cx.connect_next(blocking).await? {
                return Ok(false);
            }

            // --- HAPROXY_INIT: build the PROXY header once, then fall through
            //     into HAPROXY_SEND (curl's `FALLTHROUGH()`). ---
            if self.state == HaProxyState::Init {
                self.build_header(cx)?;
                self.state = HaProxyState::Send;
            }

            // --- HAPROXY_SEND: write the header out, resuming across partial
            //     writes / would-block (`CURLE_AGAIN`) exactly as curl does. ---
            if self.state == HaProxyState::Send {
                if !self.data_out.is_empty() {
                    let nwritten = match cx.send_next(&self.data_out[..], false).await {
                        Ok(n) => n,
                        // CURLE_AGAIN: the socket is not writable yet. curl sets
                        // `nwritten = 0`, keeps the whole buffer, and returns
                        // not-done so the transfer loop retries later.
                        Err(Error::Again) => 0,
                        // Any other send failure propagates verbatim
                        // (curl: `if(result != CURLE_AGAIN) goto out;`).
                        Err(e) => return Err(e),
                    };
                    if nwritten > 0 {
                        // Drop the bytes just handed off, keeping the unsent tail
                        // (curl: `curlx_dyn_tail(&ctx->data_out, len - nwritten)`).
                        let _ = self.data_out.split_to(nwritten);
                    }
                    if !self.data_out.is_empty() {
                        // Still bytes outstanding (partial write or would-block):
                        // stay in SEND and retry on the next connect() drive
                        // (curl: `result = CURLE_OK; goto out;`).
                        return Ok(false);
                    }
                }
                // The whole header has been sent — advance to DONE and fall
                // through to release the buffer (curl's `FALLTHROUGH()`).
                self.state = HaProxyState::Done;
            }

            // --- HAPROXY_DONE: free the buffer, mark connected, report done
            //     (curl: `curlx_dyn_free(&ctx->data_out)` + `cf->connected`). ---
            self.data_out = BytesMut::new();
            self.connected = true;
            tracing::trace!(
                target: "curl::cf",
                "HAPROXY: PROXY header sent; filter is now transparent"
            );
            Ok(true)
        })
    }

    fn close(&mut self, cx: &mut FilterCtx<'_>) {
        // Mirror `cf_haproxy_close`: mark not-connected, reset the context to
        // its initial state (curl's `cf_haproxy_ctx_reset`), and close the layer
        // below.
        tracing::trace!(target: "curl::cf", "HAPROXY: close");
        self.connected = false;
        self.state = HaProxyState::Init;
        self.data_out = BytesMut::new();
        cx.close_next();
    }

    fn adjust_pollset(&self, cx: &QueryCtx<'_>, ps: &mut Pollset) {
        // Once the header is sent the filter is transparent: the layers above
        // and below register their own interest (the chain driver visits every
        // filter). This is the `!cf->connected` guard of
        // `cf_haproxy_adjust_pollset`.
        if self.connected {
            return;
        }
        // While the PROXY header is still outstanding we are *sending*, so we
        // wait for the socket to become writable — curl's
        // `Curl_pollset_set_out_only(data, ps, Curl_conn_cf_get_socket(cf, …))`.
        let mut sock_out = QueryOut::None;
        if cx.query_next(CfQuery::Socket, &mut sock_out).is_ok() {
            if let QueryOut::Socket(fd) = sock_out {
                if fd != CURL_SOCKET_BAD {
                    ps.set(fd, POLL_OUT);
                }
            }
        }
    }
}

// ===========================================================================
// Phase 3 — factory functions (curl's `cf_haproxy_create` /
// `Curl_cf_haproxy_insert_after`).
// ===========================================================================

/// Creates a boxed PROXY-protocol filter with no client-IP override, the
/// direct analog of curl's `cf_haproxy_create` producing a `Curl_cft_haproxy`
/// instance.
#[must_use]
pub fn create() -> Box<dyn ConnectionFilter> {
    Box::new(HaProxyFilter::new())
}

/// Creates a boxed PROXY-protocol filter that advertises `client_ip`
/// (`--haproxy-clientip` / `STRING_HAPROXY_CLIENT_IP`) as the originating
/// client address. Passing `None` is equivalent to [`create`].
#[must_use]
pub fn create_with_client_ip(client_ip: Option<String>) -> Box<dyn ConnectionFilter> {
    Box::new(HaProxyFilter::with_client_ip(client_ip))
}

/// Inserts a freshly created [`HaProxyFilter`] into `chain` immediately after
/// the filter at `at_index`, mirroring `Curl_cf_haproxy_insert_after`.
///
/// The new filter therefore sits *above* the transport it prefixes (the filter
/// previously at `at_index`, i.e. the socket) and *below* whatever is added
/// later (TLS, HTTP). Returns
/// [`Error::bad_argument`](crate::error::Error::bad_argument) if `at_index` is
/// out of range, matching [`FilterChain::insert_after`].
pub fn insert_after(chain: &mut FilterChain, at_index: usize) -> Result<()> {
    chain.insert_after(at_index, create())
}

/// Like [`insert_after`], but the inserted filter advertises `client_ip`
/// (`--haproxy-clientip` / `STRING_HAPROXY_CLIENT_IP`) as the originating
/// client address.
pub fn insert_after_with_client_ip(
    chain: &mut FilterChain,
    at_index: usize,
    client_ip: Option<String>,
) -> Result<()> {
    chain.insert_after(at_index, create_with_client_ip(client_ip))
}

// ===========================================================================
// Phase 4 — unit & integration tests.
//
// These exercise the exact PROXY-protocol header bytes for every address
// family (IPv4 / IPv6 / UNIX) plus the `--haproxy-clientip` override, the
// "emit the header exactly once at connect, then relay transparently"
// contract, and the CURLE_AGAIN / partial-write resume path. A minimal
// in-process mock stands in for the socket filter directly below HAPROXY,
// recording every byte written so the emitted header can be asserted
// byte-for-byte.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::filters::IpQuadruple;
    use crate::conn::FIRSTSOCKET;
    use std::sync::{Arc, Mutex};

    // -----------------------------------------------------------------------
    // Mock socket filter (the layer *below* HAPROXY).
    // -----------------------------------------------------------------------

    /// A stand-in for the socket filter. It answers the transport / IP-info /
    /// socket-fd queries HAPROXY issues while building its header, records
    /// every byte it is asked to send, and can be configured to
    ///
    /// * accept at most `max_send` bytes per `send` (to force partial-write
    ///   resume), and
    /// * fail the first `again_rounds` sends with [`Error::Again`] (to force
    ///   the `CURLE_AGAIN` would-block resume path).
    ///
    /// The recorded write log is shared through an `Arc<Mutex<_>>` because a
    /// [`ConnectionFilter`] is `Send` and is moved into the owning
    /// [`FilterChain`]; a clone of the handle is taken before the move so the
    /// test can inspect what was written.
    struct MockSocket {
        transport: Transport,
        is_ipv6: bool,
        quad: IpQuadruple,
        fd: i32,
        max_send: Option<usize>,
        again_rounds: usize,
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl MockSocket {
        fn new(transport: Transport, is_ipv6: bool, quad: IpQuadruple) -> Self {
            MockSocket {
                transport,
                is_ipv6,
                quad,
                fd: 7,
                max_send: None,
                again_rounds: 0,
                written: Arc::new(Mutex::new(Vec::new())),
            }
        }

        /// Accept at most `n` bytes per `send`, forcing partial-write resume.
        fn with_max_send(mut self, n: usize) -> Self {
            self.max_send = Some(n);
            self
        }

        /// Fail the first `n` `send` calls with [`Error::Again`] (would-block).
        fn with_again_rounds(mut self, n: usize) -> Self {
            self.again_rounds = n;
            self
        }

        /// A shared handle to the recorded write log; clone this *before*
        /// moving the mock into the chain.
        fn written_handle(&self) -> Arc<Mutex<Vec<u8>>> {
            Arc::clone(&self.written)
        }
    }

    impl ConnectionFilter for MockSocket {
        fn name(&self) -> &'static str {
            "TCP"
        }

        fn cf_type(&self) -> CfType {
            CfType::IP_CONNECT
        }

        fn connect<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            _blocking: bool,
        ) -> CfFuture<'a, Result<bool>> {
            // The socket is treated as already connected for these tests.
            Box::pin(async { Ok(true) })
        }

        fn send<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            buf: &'a [u8],
            _eos: bool,
        ) -> CfFuture<'a, Result<usize>> {
            // Decide synchronously (before the `async move`) so the returned
            // future borrows neither `self` nor a mutex guard.
            if self.again_rounds > 0 {
                self.again_rounds -= 1;
                return Box::pin(async { Err(Error::Again) });
            }
            let cap = self.max_send.map_or(buf.len(), |m| m.min(buf.len()));
            let sink = Arc::clone(&self.written);
            Box::pin(async move {
                sink.lock()
                    .expect("mock write-log mutex poisoned")
                    .extend_from_slice(&buf[..cap]);
                Ok(cap)
            })
        }

        fn query(&self, _cx: &QueryCtx<'_>, query: CfQuery, out: &mut QueryOut) -> Result<()> {
            match query {
                CfQuery::Socket => {
                    *out = QueryOut::Socket(self.fd);
                    Ok(())
                }
                CfQuery::Transport => {
                    *out = QueryOut::Transport(self.transport);
                    Ok(())
                }
                CfQuery::IpInfo => {
                    *out = QueryOut::IpInfo {
                        is_ipv6: self.is_ipv6,
                        quad: self.quad.clone(),
                    };
                    Ok(())
                }
                _ => Err(Error::bad_argument("mock: unsupported query")),
            }
        }
    }

    // -----------------------------------------------------------------------
    // Fixtures / helpers.
    // -----------------------------------------------------------------------

    fn ipv4_quad() -> IpQuadruple {
        IpQuadruple {
            remote_ip: "93.184.216.34".to_string(),
            remote_port: 443,
            local_ip: "10.0.0.2".to_string(),
            local_port: 51000,
        }
    }

    fn ipv6_quad() -> IpQuadruple {
        IpQuadruple {
            remote_ip: "2001:db8::1".to_string(),
            remote_port: 443,
            local_ip: "2001:db8::2".to_string(),
            local_port: 51000,
        }
    }

    /// Assemble a chain `[HAPROXY, mock]` — HAPROXY on top, the socket at the
    /// bottom — the runtime ordering curl uses (`add` prepends at the head).
    fn chain_with(mock: MockSocket, client_ip: Option<String>) -> FilterChain {
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(mock)); // tail (the socket)
        chain.add(Box::new(HaProxyFilter::with_client_ip(client_ip))); // head (HAPROXY)
        chain
    }

    /// The recorded write log decoded as UTF-8 (the PROXY header is ASCII).
    fn written_str(written: &Arc<Mutex<Vec<u8>>>) -> String {
        String::from_utf8(written.lock().expect("write-log mutex poisoned").clone())
            .expect("recorded bytes are valid UTF-8")
    }

    // -----------------------------------------------------------------------
    // Metadata parity (`Curl_cft_haproxy.name` / `.flags`).
    // -----------------------------------------------------------------------

    #[test]
    fn name_and_cf_type_match_curl() {
        let f = HaProxyFilter::new();
        assert_eq!(f.name(), "HAPROXY");
        assert_eq!(f.cf_type(), CfType::PROXY);
        assert!(f.cf_type().contains(CfType::PROXY));
    }

    #[test]
    fn factories_build_haproxy_filters() {
        assert_eq!(create().name(), "HAPROXY");
        assert_eq!(create().cf_type(), CfType::PROXY);
        assert_eq!(
            create_with_client_ip(Some("203.0.113.7".to_string())).name(),
            "HAPROXY"
        );
    }

    // -----------------------------------------------------------------------
    // Exact header bytes (Phase 1 parity with `cf_haproxy_date_out_set`).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn header_ipv4_is_byte_exact() {
        let mock = MockSocket::new(Transport::Tcp, false, ipv4_quad());
        let written = mock.written_handle();
        let mut chain = chain_with(mock, None);

        assert!(chain.connect(false).await.expect("connect succeeds"));
        assert_eq!(
            written_str(&written),
            "PROXY TCP4 10.0.0.2 93.184.216.34 51000 443\r\n"
        );
    }

    #[tokio::test]
    async fn header_ipv6_uses_tcp6() {
        let mock = MockSocket::new(Transport::Tcp, true, ipv6_quad());
        let written = mock.written_handle();
        let mut chain = chain_with(mock, None);

        assert!(chain.connect(false).await.expect("connect succeeds"));
        assert_eq!(
            written_str(&written),
            "PROXY TCP6 2001:db8::2 2001:db8::1 51000 443\r\n"
        );
    }

    #[tokio::test]
    async fn header_unix_socket_is_unknown() {
        // A UNIX-domain socket has no IP-level peer, so curl emits the fixed
        // `PROXY UNKNOWN` line and never queries the address quadruple.
        let mock = MockSocket::new(Transport::Unix, false, IpQuadruple::default());
        let written = mock.written_handle();
        let mut chain = chain_with(mock, None);

        assert!(chain.connect(false).await.expect("connect succeeds"));
        assert_eq!(written_str(&written), "PROXY UNKNOWN\r\n");
    }

    #[tokio::test]
    async fn header_client_ip_override_replaces_client_field() {
        // `--haproxy-clientip 203.0.113.7` replaces only the client field; the
        // remote address and both ports remain as reported by the socket.
        let mock = MockSocket::new(Transport::Tcp, false, ipv4_quad());
        let written = mock.written_handle();
        let mut chain = chain_with(mock, Some("203.0.113.7".to_string()));

        assert!(chain.connect(false).await.expect("connect succeeds"));
        assert_eq!(
            written_str(&written),
            "PROXY TCP4 203.0.113.7 93.184.216.34 51000 443\r\n"
        );
    }

    // -----------------------------------------------------------------------
    // Emit-once-then-transparent-passthrough (Phase 3).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn header_emitted_once_then_transparent_passthrough() {
        let mock = MockSocket::new(Transport::Tcp, false, ipv4_quad());
        let written = mock.written_handle();
        let mut chain = chain_with(mock, None);
        let header = "PROXY TCP4 10.0.0.2 93.184.216.34 51000 443\r\n";

        // The connect emits the header exactly once.
        assert!(chain.connect(false).await.expect("connect succeeds"));
        assert_eq!(written_str(&written), header);

        // A second connect must NOT re-emit it (curl short-circuits on
        // `cf->connected`).
        assert!(chain.connect(false).await.expect("connect is idempotent"));
        assert_eq!(written_str(&written), header, "header emitted exactly once");

        // Now transparent: an application-level send flows straight through to
        // the socket, unchanged and un-prefixed.
        let n = chain.send(b"hello", false).await.expect("passthrough send");
        assert_eq!(n, 5);
        assert_eq!(written_str(&written), format!("{header}hello"));
    }

    // -----------------------------------------------------------------------
    // Resume paths (Phase 2: `HAPROXY_SEND` CURLE_AGAIN / partial write).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn eagain_defers_then_resumes() {
        // The first send attempt reports CURLE_AGAIN: nothing is written and the
        // handshake stays pending; the next drive flushes the whole header.
        let mock = MockSocket::new(Transport::Tcp, false, ipv4_quad()).with_again_rounds(1);
        let written = mock.written_handle();
        let mut chain = chain_with(mock, None);

        assert!(
            !chain.connect(false).await.expect("first drive ok"),
            "CURLE_AGAIN must leave the handshake pending"
        );
        let nothing_written = written.lock().expect("write-log mutex poisoned").is_empty();
        assert!(
            nothing_written,
            "nothing is written on the would-block round"
        );

        assert!(
            chain.connect(false).await.expect("second drive ok"),
            "the retry flushes the header and completes the handshake"
        );
        assert_eq!(
            written_str(&written),
            "PROXY TCP4 10.0.0.2 93.184.216.34 51000 443\r\n"
        );
    }

    #[tokio::test]
    async fn partial_writes_buffer_and_resume() {
        // A 7-byte-per-call cap forces the header out across several drives; the
        // unsent tail must be buffered and resumed until fully flushed.
        let mock = MockSocket::new(Transport::Tcp, false, ipv4_quad()).with_max_send(7);
        let written = mock.written_handle();
        let mut chain = chain_with(mock, None);
        let expected = "PROXY TCP4 10.0.0.2 93.184.216.34 51000 443\r\n";

        let mut drives = 0;
        loop {
            drives += 1;
            assert!(drives < 100, "connect failed to converge");
            if chain.connect(false).await.expect("connect drive ok") {
                break;
            }
        }
        assert!(
            drives > 1,
            "a 7-byte cap must require multiple connect drives"
        );
        assert_eq!(written_str(&written), expected);
    }

    // -----------------------------------------------------------------------
    // Pollset while the header is still outstanding (Phase 3 parity with
    // `cf_haproxy_adjust_pollset`).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn adjust_pollset_waits_for_writability_while_sending() {
        // The socket keeps reporting CURLE_AGAIN, so HAPROXY stays in SEND and
        // must ask the poll loop to watch the socket fd for writability.
        let mock =
            MockSocket::new(Transport::Tcp, false, ipv4_quad()).with_again_rounds(usize::MAX);
        let mut chain = chain_with(mock, None);

        assert!(
            !chain.connect(false).await.expect("connect stays pending"),
            "the header is not sent while the socket is not writable"
        );

        let mut ps = Pollset::new();
        chain.adjust_pollset(&mut ps);
        assert_eq!(
            ps.events(7),
            POLL_OUT,
            "HAPROXY must wait for socket writability while its header is outstanding"
        );
    }

    // -----------------------------------------------------------------------
    // Factory insertion (`Curl_cf_haproxy_insert_after`).
    // -----------------------------------------------------------------------

    #[test]
    fn insert_after_adds_a_haproxy_filter() {
        let mock = MockSocket::new(Transport::Tcp, false, ipv4_quad());
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(mock));

        insert_after(&mut chain, 0).expect("insert after index 0 succeeds");
        assert_eq!(chain.len(), 2);
        assert_eq!(
            chain.tail().expect("tail present").name(),
            "HAPROXY",
            "the HAPROXY filter is inserted after the socket"
        );
    }

    #[test]
    fn insert_after_with_client_ip_adds_a_haproxy_filter() {
        let mock = MockSocket::new(Transport::Tcp, false, ipv4_quad());
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(mock));

        insert_after_with_client_ip(&mut chain, 0, Some("203.0.113.7".to_string()))
            .expect("insert after index 0 succeeds");
        assert_eq!(chain.len(), 2);
        assert_eq!(chain.tail().expect("tail present").name(), "HAPROXY");
    }

    #[test]
    fn insert_after_out_of_range_is_rejected() {
        let mut chain = FilterChain::new(FIRSTSOCKET);
        // An empty chain has no filter to insert after.
        let err = insert_after(&mut chain, 0).expect_err("out-of-range insert must be rejected");
        assert!(matches!(err, Error::BadFunctionArgument(_)));
    }
}
