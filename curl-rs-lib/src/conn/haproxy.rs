//! HAProxy PROXY protocol (v1) header emitter — the Rust rewrite of curl's
//! `lib/cf-haproxy.c` / `lib/cf-haproxy.h`.
//!
//! This is the smallest of curl's proxy connection filters. When the user
//! enables the HAProxy PROXY protocol (`CURLOPT_HAPROXYPROTOCOL`, the CLI
//! `--haproxy-protocol` flag), this filter is spliced into the connection-filter
//! chain immediately **above the transport** (the raw socket / Happy-Eyeballs
//! filter) and **below TLS**. As soon as the transport below has connected, the
//! filter emits a single HAProxy PROXY protocol **version 1** header line
//! describing the original client/server endpoints, and then becomes a fully
//! transparent pass-through for the rest of the connection's lifetime.
//!
//! # The PROXY v1 header line
//!
//! The header is one CRLF-terminated ASCII line, reproduced byte-for-byte from
//! curl (`cf_haproxy_date_out_set`):
//!
//! * For a UNIX-domain-socket connection the address is not an IP, so the
//!   `UNKNOWN` form is emitted: `PROXY UNKNOWN\r\n`.
//! * Otherwise the filter queries the transport below for the connection's
//!   address family and its local/remote endpoint quadruple and emits
//!   `PROXY {TCP4|TCP6} {client_ip} {remote_ip} {local_port} {remote_port}\r\n`,
//!   where `client_ip` is the `CURLOPT_HAPROXY_CLIENT_IP` override when set, and
//!   otherwise the connection's own local IP. The exact C format string is
//!   `"PROXY %s %s %s %i %i\r\n"`.
//!
//! # Ordering invariant (enforced in `connect.rs`, restated here)
//!
//! The PROXY header is plaintext and **must be sent before any TLS handshake**,
//! so this filter is always inserted **below** the TLS filter. curl's SETUP
//! builder returns `CURLE_UNSUPPORTED_PROTOCOL` if an SSL filter is already in
//! place when the HAPROXY step runs; that guard lives in the SETUP state machine
//! (`crate::conn::connect`, when authored), not here. This module only
//! guarantees the *behavior* of the filter once it has been correctly placed:
//! it brings the transport below up first, then writes its header, then is
//! transparent.
//!
//! # Async mapping
//!
//! curl drives this filter re-entrantly: each `cf_haproxy_connect` call connects
//! the transport, builds the header once, then sends as much of it as the socket
//! will accept, trimming the sent prefix and returning early (`*done = FALSE`)
//! while bytes remain. That whole `CURLE_AGAIN` re-entry loop collapses here into
//! a single `connect(...).await`: the transport's `connect` is awaited to
//! completion, then the entire header is written with an awaited, `write_all`-
//! style send. curl's `cf_haproxy_adjust_pollset` (which arms the pollset for
//! writing while the header drains) has no analog — Tokio's reactor supplies the
//! write-readiness — and is intentionally omitted.
//!
//! # Memory safety (AAP §0.7.1)
//!
//! This module contains **zero** `unsafe` and opts into
//! `#![forbid(unsafe_code)]` so the rule is compiler-enforced. curl's
//! `struct dynbuf data_out` becomes a safe [`DynBuf`] sized at the same
//! [`DYN_HAXPROXY`] (2048-byte) cap; there is no raw pointer or manual `free`
//! (the buffer is released by [`DynBuf`]'s `Drop`, replacing
//! `cf_haproxy_ctx_free`).

#![forbid(unsafe_code)]

use crate::conn::filters::{
    BoxFuture, CfQuery, CfQueryResult, CfState, ConnectionFilter, FilterChain, FilterData,
    CF_TYPE_PROXY,
};
use crate::error::{CurlError, Result};
use crate::util::dynbuf::{DynBuf, DYN_HAXPROXY};
use crate::util::sendf;

/// The filter's progress through emitting its single header line — the Rust
/// equivalent of C's `haproxy_state` enum (`cf-haproxy.c`).
///
/// The states are visited strictly in order (`Init` → `Send` → `Done`) within a
/// single awaited [`ConnectionFilter::connect`]; [`ConnectionFilter::close`]
/// resets back to [`HaproxyState::Init`] so a reused connection re-emits the
/// header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HaproxyState {
    /// Header not yet built (C: `HAPROXY_INIT`).
    Init,
    /// Header built and (being) sent (C: `HAPROXY_SEND`).
    Send,
    /// Header fully sent; the filter is now transparent (C: `HAPROXY_DONE`).
    Done,
}

/// The HAProxy PROXY-protocol header-emitter filter — the Rust replacement for
/// C's `struct cf_haproxy_ctx` plus the per-filter state of its
/// `struct Curl_cfilter`.
///
/// It holds the chain-link/lifecycle [`CfState`] every filter embeds, the small
/// emit state machine, the staged header bytes ([`DynBuf`]), and the two pieces
/// of configuration the C code reads from `cf->conn` / `data->set` at connect
/// time (whether the connection is a UNIX-domain socket, and the optional
/// `CURLOPT_HAPROXY_CLIENT_IP` override). Because the Rust filter layer threads
/// only a minimal [`FilterData`] (verbosity + error buffer) — not the whole easy
/// handle — those two inputs are captured at construction by
/// [`create_haproxy_filter`] instead of being read mid-connect.
pub struct CfHaproxy {
    /// Chain link (`next`) + `connected`/`shutdown` bits (C: `Curl_cfilter`).
    state: CfState,
    /// Emit progress (C: `cf_haproxy_ctx.state`).
    hap_state: HaproxyState,
    /// Staged PROXY header bytes (C: `cf_haproxy_ctx.data_out`, a `dynbuf`).
    data_out: DynBuf,
    /// Whether the underlying connection is a UNIX-domain socket. When `true`
    /// the `PROXY UNKNOWN` form is emitted (C: `cf->conn->unix_domain_socket`).
    unix_domain_socket: bool,
    /// The `CURLOPT_HAPROXY_CLIENT_IP` override, if any (C:
    /// `data->set.str[STRING_HAPROXY_CLIENT_IP]`). When `Some`, it replaces the
    /// connection's local IP as the announced client address.
    client_ip: Option<String>,
}

impl CfHaproxy {
    /// Reset the emit state to its initial condition (C:
    /// `cf_haproxy_ctx_reset`): back to [`HaproxyState::Init`] with an emptied —
    /// but still allocated — header buffer, ready to rebuild on reconnect.
    fn ctx_reset(&mut self) {
        self.hap_state = HaproxyState::Init;
        self.data_out.curlx_dyn_reset();
    }

    /// Build the PROXY v1 header line into [`Self::data_out`] (C:
    /// `cf_haproxy_date_out_set`). Must be called exactly once per connect while
    /// in [`HaproxyState::Init`].
    ///
    /// For a UNIX-domain socket this appends the constant `PROXY UNKNOWN\r\n`.
    /// Otherwise it issues a [`CfQuery::IpInfo`] query to the filter below to
    /// obtain the address family and the local/remote [`crate::conn::filters::IpQuadruple`],
    /// then formats the header exactly as curl does — `"PROXY %s %s %s %i %i\r\n"`
    /// with `(proto, client_ip, remote_ip, local_port, remote_port)`.
    fn build_header(&mut self, data: &mut FilterData) -> Result<()> {
        // UNIX-domain socket: no IP endpoints to announce (C `USE_UNIX_SOCKETS`
        // branch). The buffer is more than large enough to hold this constant.
        if self.unix_domain_socket {
            return self.data_out.curlx_dyn_addn(b"PROXY UNKNOWN\r\n");
        }

        // Ask the transport below for the connection's address family and its
        // endpoint quadruple (C: `Curl_conn_cf_get_ip_info(cf->next, ...)`).
        let (is_ipv6, quad) = match self.state.next.as_ref() {
            Some(next) => match next.query(CfQuery::IpInfo)? {
                CfQueryResult::IpInfo { is_ipv6, quadruple } => (is_ipv6, quadruple),
                _ => {
                    sendf::failf(
                        &mut data.error_buffer,
                        "HAProxy: transport returned an unexpected IP-info query result",
                    );
                    return Err(CurlError::BadFunctionArgument);
                }
            },
            None => {
                sendf::failf(
                    &mut data.error_buffer,
                    "HAProxy: no transport filter below to query for IP info",
                );
                return Err(CurlError::FailedInit);
            }
        };

        // client_ip = CURLOPT_HAPROXY_CLIENT_IP override, else the local IP
        // (C: `data->set.str[STRING_HAPROXY_CLIENT_IP]` ? : `ipquad.local_ip`).
        let client_ip: &str = self
            .client_ip
            .as_deref()
            .unwrap_or(quad.local_ip.as_str());
        // "TCP6" for an IPv6 connection, else "TCP4".
        let proto = if is_ipv6 { "TCP6" } else { "TCP4" };

        // EXACT C format string and argument order:
        //   "PROXY %s %s %s %i %i\r\n"
        //   -> proto, client_ip, remote_ip, local_port, remote_port
        let line = format!(
            "PROXY {} {} {} {} {}\r\n",
            proto, client_ip, quad.remote_ip, quad.local_port, quad.remote_port
        );
        self.data_out.curlx_dyn_addn(line.as_bytes())
    }
}

/// Write the whole of `bytes` to the transport `next`, awaiting completion (the
/// async collapse of curl's `CURLE_AGAIN` re-entry loop).
///
/// Loops over [`ConnectionFilter::send`] advancing past each partial write until
/// every byte is accepted. A transient [`CurlError::Again`] yields back to the
/// runtime and retries (mirroring curl treating `CURLE_AGAIN` as "0 written, try
/// again"); a `0`-byte success means the peer closed the write side and is
/// surfaced as [`CurlError::SendError`]; any other error propagates unchanged.
async fn send_all(
    next: &mut (dyn ConnectionFilter + 'static),
    bytes: &[u8],
    data: &mut FilterData,
) -> Result<()> {
    let mut sent = 0usize;
    while sent < bytes.len() {
        // `eos = false`: this is a header prefixing the real stream, never the
        // end of it (C passes `FALSE` to `Curl_conn_cf_send`).
        match next.send(&bytes[sent..], false).await {
            Ok(0) => {
                sendf::failf(
                    &mut data.error_buffer,
                    "HAProxy: transport closed while sending the PROXY header",
                );
                return Err(CurlError::SendError);
            }
            Ok(n) => sent += n,
            Err(CurlError::Again) => tokio::task::yield_now().await,
            Err(other) => return Err(other),
        }
    }
    Ok(())
}

impl ConnectionFilter for CfHaproxy {
    fn name(&self) -> &'static str {
        // C: `Curl_cft_haproxy.name`.
        "HAPROXY"
    }

    fn cf_state(&self) -> &CfState {
        &self.state
    }

    fn cf_state_mut(&mut self) -> &mut CfState {
        &mut self.state
    }

    fn flags(&self) -> u32 {
        // C: `Curl_cft_haproxy.flags == CF_TYPE_PROXY`.
        CF_TYPE_PROXY
    }

    /// Establish the filter (C: `cf_haproxy_connect`).
    ///
    /// Brings the transport below up first, then — on first connect — builds and
    /// sends the PROXY header, and finally marks itself connected. Subsequent
    /// calls short-circuit on the `connected` bit.
    fn connect<'a>(&'a mut self, data: &'a mut FilterData) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // Fast path: already connected (C: `if(cf->connected) *done = TRUE`).
            if self.state.connected {
                return Ok(());
            }

            // 1. Bring the transport below up FIRST — the header can only be sent
            //    once the socket is connected (C:
            //    `cf->next->cft->do_connect(...)`; `if(result || !*done) return`).
            if let Some(next) = self.state.next.as_mut() {
                next.connect(data).await?;
            }

            // 2. HAPROXY_INIT: build the header once, advance to HAPROXY_SEND.
            if self.hap_state == HaproxyState::Init {
                self.build_header(data)?;
                self.hap_state = HaproxyState::Send;
                sendf::infof(data.verbose, "HAProxy: built PROXY protocol header, sending");
            }

            // 3. HAPROXY_SEND: write the whole header through the transport. Take
            //    ownership of the staged bytes (emptying the buffer) so the
            //    `&mut next` borrow below does not alias `self.data_out`.
            if self.hap_state == HaproxyState::Send {
                let bytes = self.data_out.curlx_dyn_take();
                if !bytes.is_empty() {
                    match self.state.next.as_mut() {
                        Some(next) => send_all(next.as_mut(), &bytes, data).await?,
                        None => {
                            sendf::failf(
                                &mut data.error_buffer,
                                "HAProxy: no transport filter below to send the PROXY header",
                            );
                            return Err(CurlError::SendError);
                        }
                    }
                }
                self.hap_state = HaproxyState::Done;
            }

            // 4. HAPROXY_DONE: release the buffer (C: `curlx_dyn_free`) and mark
            //    this filter connected (C: `cf->connected = *done`).
            self.data_out.curlx_dyn_free();
            self.state.connected = true;
            Ok(())
        })
    }

    /// Tear down the filter (C: `cf_haproxy_close`): clear the connected bit,
    /// reset the emit state so a reconnect re-sends the header, then close the
    /// transport below.
    fn close(&mut self) {
        self.state.connected = false;
        self.ctx_reset();
        if let Some(next) = self.state.next.as_mut() {
            next.close();
        }
    }

    // All other vtable slots — `shutdown`, `data_pending`, `send`, `recv`,
    // `cntrl`, `is_alive`, `keep_alive`, `query` — intentionally use the trait's
    // pass-through defaults (C: the `Curl_cf_def_*` entries in
    // `Curl_cft_haproxy`). Once the header is sent this filter is fully
    // transparent, forwarding every operation to the transport below.
    //
    // C's `cf_haproxy_adjust_pollset` slot has no analog and is omitted: Tokio's
    // reactor provides the write-readiness curl armed the pollset for.
}

// Note: C's `cf_haproxy_destroy` (which calls `cf_haproxy_ctx_free`) maps onto
// Rust's automatic `Drop`. `CfHaproxy`'s fields — the `DynBuf` and the owned
// `next` filter inside `CfState` — release themselves when the filter is
// dropped, so no explicit `Drop` impl (and no manual `free`) is required.

/// Create a HAProxy PROXY-protocol filter (C: `cf_haproxy_create`).
///
/// The returned filter stages its header into a [`DynBuf`] capped at
/// [`DYN_HAXPROXY`] and starts in [`HaproxyState::Init`]. The two configuration
/// inputs the C code reads from the easy handle at connect time are captured
/// here instead:
///
/// * `unix_domain_socket` — `true` when the underlying connection is a
///   UNIX-domain socket (`cf->conn->unix_domain_socket`), selecting the
///   `PROXY UNKNOWN` header form.
/// * `client_ip` — the `CURLOPT_HAPROXY_CLIENT_IP` override
///   (`data->set.str[STRING_HAPROXY_CLIENT_IP]`); when `Some`, it is announced
///   as the client address in place of the connection's local IP.
#[must_use]
pub fn create_haproxy_filter(
    unix_domain_socket: bool,
    client_ip: Option<String>,
) -> Box<dyn ConnectionFilter> {
    Box::new(CfHaproxy {
        state: CfState::new(),
        hap_state: HaproxyState::Init,
        data_out: DynBuf::curlx_dyn_init(DYN_HAXPROXY),
        unix_domain_socket,
        client_ip,
    })
}

/// Create a HAProxy filter and splice it into `chain` immediately after the
/// filter at `after_index` (C: `Curl_cf_haproxy_insert_after`).
///
/// `after_index` is the position of the filter the HAProxy filter must sit
/// directly above — in curl this is the transport (socket / Happy-Eyeballs)
/// filter, so the PROXY header is sent on the raw connection below TLS. Returns
/// [`CurlError::BadFunctionArgument`] if no filter exists at `after_index`
/// (propagated from [`FilterChain::insert_after_index`]).
pub fn haproxy_insert_after(
    chain: &mut FilterChain,
    after_index: usize,
    unix_domain_socket: bool,
    client_ip: Option<String>,
) -> Result<()> {
    let cf = create_haproxy_filter(unix_domain_socket, client_ip);
    chain.insert_after_index(after_index, cf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::filters::IpQuadruple;
    use std::sync::{Arc, Mutex};

    /// Drive a future to completion on a fresh current-thread runtime (mirrors
    /// the helper used by the `filters` tests).
    fn run<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("failed to build test runtime")
            .block_on(fut)
    }

    /// A leaf transport mock: answers [`CfQuery::IpInfo`] with a fixed
    /// `(is_ipv6, quadruple)` and records every byte sent through it (so a test
    /// can assert the exact PROXY header that reached the wire). Its `connect`
    /// uses the trait default, which marks it connected.
    struct MockTransport {
        state: CfState,
        is_ipv6: bool,
        quad: IpQuadruple,
        sent: Arc<Mutex<Vec<u8>>>,
    }

    impl MockTransport {
        fn new(is_ipv6: bool, quad: IpQuadruple, sent: Arc<Mutex<Vec<u8>>>) -> Self {
            Self {
                state: CfState::new(),
                is_ipv6,
                quad,
                sent,
            }
        }
    }

    impl ConnectionFilter for MockTransport {
        fn name(&self) -> &'static str {
            "MOCK-TRANSPORT"
        }
        fn cf_state(&self) -> &CfState {
            &self.state
        }
        fn cf_state_mut(&mut self) -> &mut CfState {
            &mut self.state
        }
        fn send<'a>(&'a mut self, buf: &'a [u8], _eos: bool) -> BoxFuture<'a, Result<usize>> {
            Box::pin(async move {
                self.sent.lock().expect("sent lock").extend_from_slice(buf);
                Ok(buf.len())
            })
        }
        fn query(&self, query: CfQuery) -> Result<CfQueryResult> {
            match query {
                CfQuery::IpInfo => Ok(CfQueryResult::IpInfo {
                    is_ipv6: self.is_ipv6,
                    quadruple: self.quad.clone(),
                }),
                _ => Err(CurlError::UnknownOption),
            }
        }
    }

    /// A representative IPv4 quadruple.
    fn quad_v4() -> IpQuadruple {
        IpQuadruple {
            remote_ip: "203.0.113.5".to_string(),
            local_ip: "192.0.2.10".to_string(),
            remote_port: 443,
            local_port: 50_000,
            transport: 0,
        }
    }

    /// A representative IPv6 quadruple.
    fn quad_v6() -> IpQuadruple {
        IpQuadruple {
            remote_ip: "2001:db8::2".to_string(),
            local_ip: "2001:db8::1".to_string(),
            remote_port: 8443,
            local_port: 51_000,
            transport: 0,
        }
    }

    /// Build a `CfHaproxy` for tests, optionally with a transport below.
    fn make_hap(
        next: Option<Box<dyn ConnectionFilter>>,
        unix_domain_socket: bool,
        client_ip: Option<String>,
    ) -> CfHaproxy {
        CfHaproxy {
            state: match next {
                Some(n) => CfState::with_next(n),
                None => CfState::new(),
            },
            hap_state: HaproxyState::Init,
            data_out: DynBuf::curlx_dyn_init(DYN_HAXPROXY),
            unix_domain_socket,
            client_ip,
        }
    }

    #[test]
    fn dyn_haxproxy_cap_is_2048() {
        // The header buffer must use curl's exact DYN_HAXPROXY allocation cap.
        assert_eq!(DYN_HAXPROXY, 2048);
    }

    #[test]
    fn name_and_flags_match_c_vtable() {
        let cf = create_haproxy_filter(false, None);
        assert_eq!(cf.name(), "HAPROXY");
        assert_eq!(cf.flags(), CF_TYPE_PROXY);
        assert!(cf.has_flag(CF_TYPE_PROXY));
        // A freshly created filter is not yet connected.
        assert!(!cf.is_connected());
    }

    #[test]
    fn build_header_ipv4_exact_bytes() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mock = MockTransport::new(false, quad_v4(), Arc::clone(&sent));
        let mut hap = make_hap(Some(Box::new(mock)), false, None);
        let mut data = FilterData::new();

        hap.build_header(&mut data).expect("build_header");

        // proto=TCP4, client_ip=local_ip, remote_ip, local_port, remote_port.
        let expected: &[u8] = b"PROXY TCP4 192.0.2.10 203.0.113.5 50000 443\r\n";
        assert_eq!(hap.data_out.curlx_dyn_ptr(), expected);
    }

    #[test]
    fn build_header_ipv6_exact_bytes() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mock = MockTransport::new(true, quad_v6(), Arc::clone(&sent));
        let mut hap = make_hap(Some(Box::new(mock)), false, None);
        let mut data = FilterData::new();

        hap.build_header(&mut data).expect("build_header");

        let expected: &[u8] = b"PROXY TCP6 2001:db8::1 2001:db8::2 51000 8443\r\n";
        assert_eq!(hap.data_out.curlx_dyn_ptr(), expected);
    }

    #[test]
    fn build_header_unix_socket_is_unknown() {
        // A UNIX-domain socket needs no IP info and emits the UNKNOWN form.
        let mut hap = make_hap(None, true, None);
        let mut data = FilterData::new();

        hap.build_header(&mut data).expect("build_header");

        let expected: &[u8] = b"PROXY UNKNOWN\r\n";
        assert_eq!(hap.data_out.curlx_dyn_ptr(), expected);
    }

    #[test]
    fn build_header_honors_client_ip_override() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mock = MockTransport::new(false, quad_v4(), Arc::clone(&sent));
        // CURLOPT_HAPROXY_CLIENT_IP override replaces the local IP.
        let mut hap = make_hap(Some(Box::new(mock)), false, Some("198.51.100.7".to_string()));
        let mut data = FilterData::new();

        hap.build_header(&mut data).expect("build_header");

        let expected: &[u8] = b"PROXY TCP4 198.51.100.7 203.0.113.5 50000 443\r\n";
        assert_eq!(hap.data_out.curlx_dyn_ptr(), expected);
    }

    #[test]
    fn build_header_without_transport_fails() {
        // Non-UNIX path with no filter below cannot obtain IP info.
        let mut hap = make_hap(None, false, None);
        let mut data = FilterData::new();
        assert_eq!(hap.build_header(&mut data), Err(CurlError::FailedInit));
    }

    #[test]
    fn connect_sends_header_then_is_transparent() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mock = MockTransport::new(false, quad_v4(), Arc::clone(&sent));
        let mut hap = make_hap(Some(Box::new(mock)), false, None);
        let mut data = FilterData::new();

        run(hap.connect(&mut data)).expect("connect");

        // The filter is connected and finished emitting.
        assert!(hap.is_connected());
        assert_eq!(hap.hap_state, HaproxyState::Done);
        // The exact PROXY header reached the transport below.
        let expected: &[u8] = b"PROXY TCP4 192.0.2.10 203.0.113.5 50000 443\r\n";
        assert_eq!(sent.lock().expect("sent lock").as_slice(), expected);
        // The staged buffer was released once sent.
        assert_eq!(hap.data_out.curlx_dyn_len(), 0);

        // Transparency: a query now delegates straight to the transport below.
        match hap.query(CfQuery::IpInfo).expect("query delegates") {
            CfQueryResult::IpInfo { is_ipv6, quadruple } => {
                assert!(!is_ipv6);
                assert_eq!(quadruple, quad_v4());
            }
            other => panic!("unexpected query result: {other:?}"),
        }
    }

    #[test]
    fn connect_ipv6_emits_tcp6_header() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mock = MockTransport::new(true, quad_v6(), Arc::clone(&sent));
        let mut hap = make_hap(Some(Box::new(mock)), false, None);
        let mut data = FilterData::new();

        run(hap.connect(&mut data)).expect("connect");

        assert!(hap.is_connected());
        let expected: &[u8] = b"PROXY TCP6 2001:db8::1 2001:db8::2 51000 8443\r\n";
        assert_eq!(sent.lock().expect("sent lock").as_slice(), expected);
    }

    #[test]
    fn connect_is_idempotent_once_connected() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mock = MockTransport::new(false, quad_v4(), Arc::clone(&sent));
        let mut hap = make_hap(Some(Box::new(mock)), false, None);
        let mut data = FilterData::new();

        run(hap.connect(&mut data)).expect("first connect");
        let after_first = sent.lock().expect("sent lock").clone();
        // A second connect must be a no-op (the header is not re-sent).
        run(hap.connect(&mut data)).expect("second connect");
        assert_eq!(sent.lock().expect("sent lock").as_slice(), after_first.as_slice());
    }

    #[test]
    fn close_resets_emit_state() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mock = MockTransport::new(false, quad_v4(), Arc::clone(&sent));
        let mut hap = make_hap(Some(Box::new(mock)), false, None);
        let mut data = FilterData::new();

        run(hap.connect(&mut data)).expect("connect");
        assert!(hap.is_connected());

        // close clears the connected bit and rewinds the emit state so a reused
        // connection rebuilds and re-sends the header.
        hap.close();
        assert!(!hap.is_connected());
        assert_eq!(hap.hap_state, HaproxyState::Init);
    }
}

