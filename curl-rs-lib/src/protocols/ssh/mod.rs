//! SSH-family protocol root — the shared transport, authentication, and helper
//! layer for the `scp://` and `sftp://` schemes.
//!
//! This module is the Rust replacement for curl's C SSH backends
//! `lib/vssh/libssh2.c` and `lib/vssh/libssh.c` (which bind the external
//! `libssh2` / `libssh` C libraries). It is built **exclusively** on the
//! pure-Rust [`russh`] stack — `russh` for the SSH transport and
//! authentication, `russh::keys` for key loading / `known_hosts` / ssh-agent,
//! and (in the child [`sftp`] module) `russh-sftp` for the SFTP subsystem.
//!
//! # Responsibilities
//!
//! * **Module roots** for the two SSH-family engines, each behind its Cargo
//!   feature gate ([`scp`] and [`sftp`]).
//! * The **shared session bring-up**: it drives the TCP connection through
//!   [`crate::conn`] (with TLS disabled — SSH negotiates its own transport
//!   crypto), performs the `russh` handshake, verifies the host key against
//!   `known_hosts` / explicit fingerprints, and runs the full **authentication
//!   fallback chain** (public-key → password → host-based → ssh-agent →
//!   keyboard-interactive) — a faithful reproduction of the libssh2 connect/auth
//!   state machine (`libssh2.c` `ssh_state_*`).
//! * The [`Protocol`] handler structs for the two schemes ([`ScpHandler`],
//!   [`SftpHandler`]) and their constructors ([`scp_handler`], [`sftp_handler`]).
//! * The shared per-connection / per-request state types ([`SshConn`],
//!   [`SshRequest`]) — the safe-Rust analogs of the C `struct ssh_conn` /
//!   `struct SSHPROTO`.
//! * The shared helpers reused by `sftp.rs` and `scp.rs`: working-path
//!   resolution ([`get_working_path`]), QUOTE-argument parsing
//!   ([`get_pathname`]), and RANGE parsing ([`ssh_range`]).
//!
//! # C state machine → linear async
//!
//! curl's C SSH backend is a giant re-entrant `switch(sshc->state)` driven by
//! `libssh2`'s `EAGAIN` non-blocking poll loop. Here every `EAGAIN`/poll cycle
//! collapses into a single `.await`; this module reproduces the *sequence* and
//! the *decisions* of that state machine, not its runtime state enum.
//!
//! # Architectural seams (cross-module coordination)
//!
//! Two design seams are documented inline at their use sites:
//!
//! 1. **Per-connection state** lives in [`Connection`]'s generic
//!    `proto_state` slot (the Rust analog of curl's `conn->proto` /
//!    `CURL_META_SSH_CONN`): [`connect_ssh_session`] boxes an [`SshConn`] there;
//!    `do_it` / `done` borrow it back; `disconnect` moves it into the
//!    connection's `disconnect_hook` so teardown runs even on abort. This keeps
//!    `crate::conn` strictly acyclic — it never names a `crate::protocols` type.
//! 2. **Transport ownership**: `russh::client::connect_stream` spawns the
//!    session loop on its own task and therefore requires an *owned* `'static`
//!    stream, whereas `crate::conn` exposes only borrowed / per-call views. The
//!    [`ConnStream`] adapter bridges the two; see its docs for the exact seam.

// ===========================================================================
// Child module declarations — one per SSH-family scheme, feature-gated so the
// compiled set matches `crate::version::supported_protocols` /
// `crate::protocols::supported_schemes()` (feature/version lockstep, AAP
// §0.7.3). The parent `protocols/mod.rs` gates `pub mod ssh;` on
// `any(feature = "scp", feature = "sftp")`, so when neither is enabled this
// whole module compiles away.
//
// NOTE: `#![forbid(unsafe_code)]` is intentionally NOT re-declared here — it is
// inherited from the crate root (`lib.rs`) and re-declared at `protocols/mod.rs`;
// leaf protocol modules do not repeat it.
// ===========================================================================

#[cfg(feature = "sftp")]
pub mod sftp;

#[cfg(feature = "scp")]
pub mod scp;

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use crate::conn::connect::{eyeballs_factory, SetupConfig};
use crate::conn::{
    establish_connection, BoxFuture, ConnSetup, Connection, Curl_conn_connect, SchemeDescriptor,
    CURL_CF_SSL_DISABLE, FIRSTSOCKET, TRNSPRT_TCP,
};
use crate::dns::{self, DnsCache, IpVersion, ResolveParams, ResolvedAddrs};
use crate::easy::Easy;
use crate::error::{CurlError, Result};
use crate::protocols::{
    Protocol, ProtocolTransfer, Scheme, TransferDirection, CURLPROTO_SCP, CURLPROTO_SFTP,
    SCHEME_SCP, SCHEME_SFTP,
};
use crate::setopt::StrId;
use crate::transfer::{ClientWriter, ReadCallback, WriteCallbacks};
use crate::url::{CurlUPart, CurlUrl, CURLU_DEFAULT_PORT, CURLU_GUESS_SCHEME, CURLU_URLDECODE};
use crate::util::sendf;

use russh::client::{self, AuthResult, Config, Handle, Handler, KeyboardInteractiveAuthResponse};
use russh::keys::agent::client::AgentClient;
use russh::keys::{load_secret_key, ssh_key, PrivateKeyWithHashAlg};
use russh::{Disconnect, MethodKind, MethodSet};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

// ===========================================================================
// Constants — ported verbatim from the C SSH backend.
// ===========================================================================

/// Upper bound on a resolved SSH working path (`vssh.c` `Curl_getworkingpath`:
/// `MAX_SSHPATH_LEN`). Exceeding it is reported as out-of-memory, exactly as C.
const MAX_SSHPATH_LEN: usize = 100_000;

/// Upper bound on a single QUOTE-command path argument (`vssh.c`
/// `Curl_get_pathname`: `MAX_PATHLENGTH`). Exceeding it maps to
/// [`CurlError::TooLarge`] (C `STRE_BIG` / dynbuf `CURLE_TOO_LARGE`), while a
/// malformed quote is a [`CurlError::QuoteError`].
///
/// NOTE on `#[allow(dead_code)]` for the shared SFTP-path helpers below
/// (`MAX_PATHLENGTH`, [`get_pathname`], [`ssh_range`], `parse_offset`,
/// [`map_sftp_err`]): these are intentional `pub(crate)` API consumed by the
/// feature-gated SFTP/SCP child engines (`sftp.rs`/`scp.rs`). Per the C oracle,
/// QUOTE parsing (`sftp_quote`), RANGE parsing, and SFTP error mapping are
/// SFTP-path features, so `--features scp` alone exercises none of them and a
/// stub build exercises none. They are API surface, not dead code; the unit
/// tests at the bottom of this file additionally cover the pure ones.
#[allow(dead_code)]
const MAX_PATHLENGTH: usize = 65_535;

// --- `CURLSSH_AUTH_*` bitmask (include/curl/curl.h) -------------------------
// The `data.set.ssh_auth_types` bitset gates which authentication methods the
// fallback chain may attempt. These values are part of the public ABI and must
// match the C header exactly.

/// `CURLSSH_AUTH_PUBLICKEY` — public-key authentication.
const CURLSSH_AUTH_PUBLICKEY: u32 = 1 << 0;
/// `CURLSSH_AUTH_PASSWORD` — password authentication.
const CURLSSH_AUTH_PASSWORD: u32 = 1 << 1;
/// `CURLSSH_AUTH_HOST` — host-based authentication.
const CURLSSH_AUTH_HOST: u32 = 1 << 2;
/// `CURLSSH_AUTH_KEYBOARD` — keyboard-interactive authentication.
const CURLSSH_AUTH_KEYBOARD: u32 = 1 << 3;
/// `CURLSSH_AUTH_AGENT` — ssh-agent authentication.
const CURLSSH_AUTH_AGENT: u32 = 1 << 4;

// ===========================================================================
// Host-key verification — a faithful port of `libssh2.c` `ssh_check_fingerprint`
// fused with `ssh_knownhost`.
// ===========================================================================

/// The host-key verification inputs captured from the easy handle *before* the
/// handshake, so the `russh` [`Handler`] (which runs on russh's session task and
/// cannot borrow the easy handle) can verify the server key on its own.
#[derive(Debug, Default, Clone)]
pub(crate) struct HostKeyConfig {
    /// The target host name (C `conn->host.name`), used as the `known_hosts` key.
    pub(crate) host: String,
    /// The target port (C `conn->remote_port`), used as the `known_hosts` key.
    pub(crate) port: u16,
    /// Whether verbose tracing is on (`data.set.verbose`); gates `infof`.
    pub(crate) verbose: bool,
    /// `CURLOPT_SSH_KNOWNHOSTS` (opt 183) file path, if configured.
    pub(crate) known_hosts: Option<String>,
    /// `CURLOPT_SSH_HOST_PUBLIC_KEY_MD5` (opt 162) expected fingerprint, if set.
    pub(crate) expected_md5: Option<String>,
    /// `CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256` (opt 311) expected fingerprint, if set.
    pub(crate) expected_sha256: Option<String>,
}

/// SHA256 fingerprint comparison. curl (`ssh_check_fingerprint`) ignores `=`
/// base64 padding: it compares the substrings up to the first `=` and requires
/// equal pre-padding lengths. Taking the slice before the first `=` of each and
/// testing equality is exactly that. Pure — unit-tested.
fn sha256_fingerprint_matches(computed_b64: &str, expected: &str) -> bool {
    let c = computed_b64.split('=').next().unwrap_or("");
    let e = expected.split('=').next().unwrap_or("");
    c == e
}

/// MD5 fingerprint comparison. curl (`ssh_check_fingerprint`) uses
/// case-insensitive equality (`curl_strequal`) against the 32-hex-char string;
/// a length mismatch is a non-match. Pure — unit-tested.
fn md5_fingerprint_matches(computed_hex: &str, expected: &str) -> bool {
    computed_hex.eq_ignore_ascii_case(expected)
}

/// Lower-case hex string of a digest (curl `msnprintf(&buf[i*2], 3, "%02x")`).
fn to_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Standard (padded) base64 of a digest as a `String` — the analog of curl's
/// `curlx_base64_encode`, reusing the crate's own base64 utility.
fn base64_string(bytes: &[u8]) -> Result<String> {
    let encoded = crate::util::base64::base64_encode(bytes)?;
    Ok(String::from_utf8(encoded).unwrap_or_default())
}

/// Verify the server's public key — the faithful reproduction of
/// `ssh_check_fingerprint` + `ssh_knownhost`.
///
/// Decision order (exact, from `libssh2.c`):
/// 1. If a SHA256 fingerprint is configured it must match (padding-insensitive);
///    a match is sufficient and SKIPS the `known_hosts` step.
/// 2. If an MD5 fingerprint is configured it must match (case-insensitive); a
///    match is sufficient and SKIPS the `known_hosts` step.
/// 3. If NEITHER explicit fingerprint is configured, fall back to `known_hosts`:
///    - the file records this key            → accept;
///    - the key changed / is not recorded     → reject (the built-in
///      `sshkeycallback` "perfect match only" policy; a `CURLOPT_SSH_KEYFUNCTION`
///      override is the documented future seam, pending its FFI callback bridge);
///    - no `known_hosts` file is configured    → no verification, accept (matches
///      C: `ssh_knownhost` returns `CURLE_OK` when `STRING_SSH_KNOWNHOSTS` is
///      unset).
fn verify_host_key(cfg: &HostKeyConfig, key: &ssh_key::PublicKey) -> Result<()> {
    sendf::infof(
        cfg.verbose,
        &format!(
            "SSH MD5 public key: {}",
            cfg.expected_md5.as_deref().unwrap_or("NULL")
        ),
    );
    sendf::infof(
        cfg.verbose,
        &format!(
            "SSH SHA256 public key: {}",
            cfg.expected_sha256.as_deref().unwrap_or("NULL")
        ),
    );

    // The SSH wire-format public-key blob — the same bytes curl hashes via
    // `libssh2_hostkey_hash` (`PublicKey::to_bytes` == `key_data.encode_vec`).
    let blob = key.to_bytes().map_err(|_| CurlError::PeerFailedVerification)?;

    if let Some(expected) = cfg.expected_sha256.as_deref() {
        let digest = crate::util::sha256::sha256it(&blob);
        let b64 = base64_string(&digest)?;
        sendf::infof(cfg.verbose, &format!("SSH SHA256 fingerprint: {b64}"));
        if !sha256_fingerprint_matches(&b64, expected) {
            return Err(CurlError::PeerFailedVerification);
        }
        sendf::infof(cfg.verbose, "SHA256 checksum match");
    }

    if let Some(expected) = cfg.expected_md5.as_deref() {
        let digest = crate::util::md5::md5it(&blob);
        let hex = to_hex_lower(&digest);
        sendf::infof(cfg.verbose, &format!("SSH MD5 fingerprint: {hex}"));
        if !md5_fingerprint_matches(&hex, expected) {
            return Err(CurlError::PeerFailedVerification);
        }
        sendf::infof(cfg.verbose, "MD5 checksum match");
    }

    // An explicit fingerprint match short-circuits the known-hosts check
    // (C: `else { /* as we already matched, we skip the check */ }`).
    if cfg.expected_md5.is_none() && cfg.expected_sha256.is_none() {
        if let Some(path) = cfg.known_hosts.as_deref() {
            match russh::keys::known_hosts::check_known_hosts_path(
                &cfg.host, cfg.port, key, path,
            ) {
                Ok(true) => {}
                // not recorded OR key changed → strict default rejects.
                Ok(false) | Err(_) => return Err(CurlError::PeerFailedVerification),
            }
        }
        // No fingerprint AND no known_hosts file → C `ssh_knownhost` returns
        // CURLE_OK (no host verification). Accept.
    }

    Ok(())
}

// ===========================================================================
// The `russh` client handler — host-key verification runs here.
// ===========================================================================

/// The `russh` client [`Handler`]. Its only active responsibility is host-key
/// verification (russh invokes [`check_server_key`](Handler::check_server_key)
/// during the handshake). Because the handler is moved onto russh's session task
/// the verification *outcome* is published into a shared slot so that
/// [`connect_ssh_session`] can surface the precise [`CurlError`].
pub(crate) struct ClientHandler {
    /// The captured host-key verification inputs.
    cfg: HostKeyConfig,
    /// The recorded verification failure (if any), shared with the connector.
    outcome: Arc<Mutex<Option<CurlError>>>,
}

impl ClientHandler {
    /// Build a handler for the given host-key configuration, sharing `outcome`
    /// with [`connect_ssh_session`] so it can read back a verification failure.
    fn new(cfg: HostKeyConfig, outcome: Arc<Mutex<Option<CurlError>>>) -> Self {
        Self { cfg, outcome }
    }
}

impl Handler for ClientHandler {
    // `russh::Error` satisfies the trait bound `From<russh::Error> + Send +
    // Debug`; the precise host-key reason is surfaced via `outcome` instead.
    type Error = russh::Error;

    // Native `async fn` (the crate's `async-trait` feature is OFF) — the trait
    // method is `-> impl Future + Send`.
    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        match verify_host_key(&self.cfg, server_public_key) {
            Ok(()) => Ok(true),
            Err(e) => {
                // Record the precise reason; returning `Ok(false)` tells russh to
                // reject the key and abort the handshake (mirrors libssh2 failing
                // with `CURLE_PEER_FAILED_VERIFICATION`).
                if let Ok(mut slot) = self.outcome.lock() {
                    *slot = Some(e);
                }
                Ok(false)
            }
        }
    }
}

// ===========================================================================
// Shared per-connection / per-request state — safe-Rust analogs of the C
// `struct ssh_conn` (per-connection) and `struct SSHPROTO` (per-request).
// ===========================================================================

/// Per-connection SSH state — the safe-Rust analog of the C `struct ssh_conn`.
///
/// Parked in the [`Connection`]'s `proto_state` slot (the Rust analog of the C
/// `CURL_META_SSH_CONN` meta entry) so it survives connection reuse across
/// requests (`PROTOPT_CONN_REUSE`). No raw pointers, no manual ref-counts: the
/// live session is owned here and dropped deterministically.
pub(crate) struct SshConn {
    /// The live `russh` client session, or `None` until connected (C
    /// `sshc->ssh_session`).
    pub(crate) handle: Option<Handle<ClientHandler>>,
    /// The remote home directory, captured once via SFTP `realpath(".")` and
    /// constant thereafter (C `sshc->homedir`). `None` for SCP.
    pub(crate) homedir: Option<String>,
    /// Whether authentication has completed (C `sshc->authed`).
    pub(crate) authed: bool,
    /// Whether a failed SFTP stat/op is non-fatal for the current quote command
    /// (C `sshc->acceptfail`).
    ///
    /// Read and written by the feature-gated SFTP child engine (`sftp.rs`)
    /// during QUOTE/POSTQUOTE command processing; it is part of the
    /// `pub(crate)` SSH state contract rather than a read of this module.
    #[allow(dead_code)]
    pub(crate) acceptfail: bool,
    /// The server-advertised authentication methods from the initial `none`
    /// probe (C `sshc->authlist`).
    ///
    /// In the linear-`async` auth chain the advertised set is consumed inline
    /// (see [`run_authentication`]); this field preserves it on the connection
    /// for the child engines and for diagnostics, mirroring `sshc->authlist`.
    #[allow(dead_code)]
    pub(crate) auth_methods: Option<MethodSet>,
    /// The live SFTP subsystem session (SFTP scheme only). Owned here so it is
    /// reachable from `sftp.rs` across `do_it`/`done` and torn down on
    /// disconnect; SCP never starts a subsystem.
    #[cfg(feature = "sftp")]
    pub(crate) sftp_session: Option<russh_sftp::client::SftpSession>,
    /// The current per-transfer request state (C `SSHPROTO`, attached per-easy via
    /// `CURL_META_SSH_EASY`). Because the Rust [`Easy`] has no generic protocol
    /// meta slot, the current request rides on the per-connection state; SSH
    /// transfers on a connection are serial (no multiplexing), so a single
    /// current request is sufficient. Populated by `setup_connection` and read
    /// (and, for SFTP, re-resolved once `homedir` is known) by `do_it`.
    pub(crate) request: SshRequest,
}

impl SshConn {
    /// A fresh, unconnected per-connection state.
    fn new() -> Self {
        Self {
            handle: None,
            homedir: None,
            authed: false,
            acceptfail: false,
            auth_methods: None,
            #[cfg(feature = "sftp")]
            sftp_session: None,
            request: SshRequest::default(),
        }
    }
}

/// Per-request SSH state — the safe-Rust analog of the C `struct SSHPROTO`.
///
/// Allocated per transfer in `setup_connection`; the home directory is captured
/// once per connection but the **working path is re-resolved per request**
/// (C `sshp->path`).
#[derive(Debug, Default, Clone)]
pub(crate) struct SshRequest {
    /// The resolved working path for this transfer (C `sshp->path`).
    pub(crate) path: String,
}

// ===========================================================================
// Scheme descriptors & `Protocol` handler structs.
// ===========================================================================

// PARITY (vssh.c `Curl_scheme_scp` / `Curl_scheme_sftp`, L334-364): both SCP and
// SFTP carry, VERBATIM from the C source — the binding ABI/behavior oracle (AAP
// §0.1.1 minimal-change mandate):
//
//   flags        = PROTOPT_DIRLOCK | PROTOPT_CLOSEACTION
//                | PROTOPT_NOURLQUERY | PROTOPT_CONN_REUSE
//   default_port = PORT_SSH (= 22)
//   protocol     = family = CURLPROTO_SCP (1<<4) / CURLPROTO_SFTP (1<<5)
//
// The authoritative descriptors live in the parent `protocols/mod.rs`
// (`SCHEME_SCP` / `SCHEME_SFTP`); the `scheme()` impls below return references to
// them. The *planning-text* flag set — which incorrectly added `PROTOPT_NEEDSPWD`
// and dropped `PROTOPT_CONN_REUSE` (and dropped `NOURLQUERY` for sftp) — is NOT
// used; the C source is authoritative. The compile-time assertions below LOCK the
// parent constants to the C-source values, so any future drift becomes a build
// error rather than a silent parity regression (verified: the parent already
// encodes the correct C-source flags, so there is no parity bug to raise).
const _: () = {
    use crate::protocols::{
        CURLPROTO_SCP, CURLPROTO_SFTP, DEFAULT_PORT_SSH, PROTOPT_CLOSEACTION, PROTOPT_CONN_REUSE,
        PROTOPT_DIRLOCK, PROTOPT_NOURLQUERY,
    };

    // The canonical SSH-family `PROTOPT_*` flag set from `vssh.c`.
    let ssh_flags =
        PROTOPT_DIRLOCK | PROTOPT_CLOSEACTION | PROTOPT_NOURLQUERY | PROTOPT_CONN_REUSE;

    assert!(
        SCHEME_SCP.flags == ssh_flags,
        "SCHEME_SCP.flags must equal the vssh.c C-source flag set \
         (DIRLOCK|CLOSEACTION|NOURLQUERY|CONN_REUSE)"
    );
    assert!(SCHEME_SCP.protocol == CURLPROTO_SCP);
    assert!(SCHEME_SCP.family == CURLPROTO_SCP);
    assert!(SCHEME_SCP.default_port == DEFAULT_PORT_SSH);

    assert!(
        SCHEME_SFTP.flags == ssh_flags,
        "SCHEME_SFTP.flags must equal the vssh.c C-source flag set \
         (DIRLOCK|CLOSEACTION|NOURLQUERY|CONN_REUSE)"
    );
    assert!(SCHEME_SFTP.protocol == CURLPROTO_SFTP);
    assert!(SCHEME_SFTP.family == CURLPROTO_SFTP);
    assert!(SCHEME_SFTP.default_port == DEFAULT_PORT_SSH);
};

/// The [`Protocol`] handler for the `scp://` scheme (C `Curl_protocol_scp`).
///
/// Zero-sized: all mutable session state lives on the [`Connection`] (an
/// [`SshConn`] parked in `proto_state`) and on the [`Easy`] handle, so a single
/// shared instance dispatches every SCP transfer.
#[cfg(feature = "scp")]
pub struct ScpHandler;

/// The [`Protocol`] handler for the `sftp://` scheme (C `Curl_protocol_sftp`).
///
/// Zero-sized for the same reason as [`ScpHandler`].
#[cfg(feature = "sftp")]
pub struct SftpHandler;

/// Construct the boxed `scp://` protocol handler for the scheme registry
/// (`protocols/mod.rs` `scheme_handler("scp")`).
#[cfg(feature = "scp")]
#[must_use]
pub fn scp_handler() -> Box<dyn Protocol> {
    Box::new(ScpHandler)
}

/// Construct the boxed `sftp://` protocol handler for the scheme registry
/// (`protocols/mod.rs` `scheme_handler("sftp")`).
#[cfg(feature = "sftp")]
#[must_use]
pub fn sftp_handler() -> Box<dyn Protocol> {
    Box::new(SftpHandler)
}

#[cfg(feature = "scp")]
impl Protocol for ScpHandler {
    fn scheme(&self) -> &'static Scheme {
        &SCHEME_SCP
    }

    /// C `ssh_setup_connection`: allocate state and resolve the working path.
    fn setup_connection<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { setup_ssh_connection(data, conn) })
    }

    /// C `ssh_connect`: bring up the TCP transport, handshake, and authenticate.
    /// SCP starts no subsystem.
    fn connect<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { connect_ssh_session(data, conn).await })
    }

    /// C `ssh_do` → `scp_doing`: run the SCP DO state machine and describe the
    /// transfer. Delegated to the SCP engine (`scp.rs`).
    fn do_it<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<ProtocolTransfer>> {
        Box::pin(async move { scp::do_it(data, conn).await })
    }

    /// C `scp_done`: finalize (EOF → wait-EOF → wait-close → channel-free).
    /// Delegated to the SCP engine (`scp.rs`).
    fn done<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
        status: Result<()>,
        premature: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { scp::done(data, conn, status, premature).await })
    }

    /// C `scp_disconnect`: install the one-shot session-teardown hook.
    fn disconnect<'a>(
        &'a self,
        _data: &'a mut Easy,
        conn: &'a mut Connection,
        dead: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            install_ssh_disconnect_hook(conn, dead);
            Ok(())
        })
    }
}

#[cfg(feature = "sftp")]
impl Protocol for SftpHandler {
    fn scheme(&self) -> &'static Scheme {
        &SCHEME_SFTP
    }

    /// C `ssh_setup_connection`: allocate state and resolve the working path.
    fn setup_connection<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { setup_ssh_connection(data, conn) })
    }

    /// C `ssh_connect`: bring up the TCP transport, handshake, and authenticate,
    /// then start the SFTP subsystem and capture the home directory
    /// (`SSH_SFTP_INIT` → `SSH_SFTP_REALPATH`), delegated to the SFTP engine.
    fn connect<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            connect_ssh_session(data, conn).await?;
            sftp::init_subsystem(data, conn).await
        })
    }

    /// C `ssh_do` → `sftp_doing`: run the SFTP DO state machine and describe the
    /// transfer. Delegated to the SFTP engine (`sftp.rs`).
    fn do_it<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<ProtocolTransfer>> {
        Box::pin(async move { sftp::do_it(data, conn).await })
    }

    /// C `sftp_done`: close the open handle, run pending POSTQUOTE commands, and
    /// finalize. Delegated to the SFTP engine (`sftp.rs`).
    fn done<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
        status: Result<()>,
        premature: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { sftp::done(data, conn, status, premature).await })
    }

    /// C `sftp_disconnect`: install the one-shot session-teardown hook (which
    /// also shuts down the SFTP subsystem).
    fn disconnect<'a>(
        &'a self,
        _data: &'a mut Easy,
        conn: &'a mut Connection,
        dead: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            install_ssh_disconnect_hook(conn, dead);
            Ok(())
        })
    }
}

// ===========================================================================
// Transport-stream adapter — the owned-stream SEAM between `crate::conn` and
// `russh::client::connect_stream`.
// ===========================================================================

/// An owned transport-stream adapter handed to [`russh::client::connect_stream`].
///
/// # The seam (module docs §2, file prompt §3 NOTE)
///
/// `russh::client::connect_stream` writes the SSH identification string and then
/// **spawns the session loop onto its own task**, so it requires an *owned*,
/// `'static`, `AsyncRead + AsyncWrite + Unpin + Send` stream. `crate::conn`, by
/// contrast, exposes transport bytes only through the borrowed, per-call verbs
/// [`crate::conn::Curl_conn_send`] / [`crate::conn::Curl_conn_recv`] on
/// `FIRSTSOCKET`, plus the per-method `&mut Connection`.
///
/// This newtype is the single point where the two are bridged. The *preferred*
/// wiring is one of:
///   1. a `crate::conn` raw-transport take-accessor for `TRNSPRT_TCP`
///      connections (zero-copy handoff of the already-connected stream), or
///   2. an `AsyncRead`/`AsyncWrite` shim delegating to `Curl_conn_send` /
///      `Curl_conn_recv`.
///
/// Until `crate::conn` exposes such an accessor, [`obtain_owned_transport_stream`]
/// supplies the documented fallback. `ConnStream` is generic over the inner
/// stream `S` so swapping the fallback for the eventual accessor touches only
/// that one function — never this adapter or the SSH session logic.
///
/// The inner stream is `Unpin`, so the pin projections below are safe without any
/// `unsafe` (`Pin::new(&mut self.inner)`), honoring the crate-wide
/// `#![forbid(unsafe_code)]`.
struct ConnStream<S> {
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for ConnStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ConnStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Obtain the owned transport stream for the SSH handshake (the SEAM described on
/// [`ConnStream`]).
///
/// The connection has already been established and validated through curl's
/// connection layer by the preceding [`Curl_conn_connect`] (so DNS resolution,
/// happy-eyeballs, and any proxy/`haproxy` filters have run, and — because the
/// SSH scheme carries no `PROTOPT_SSL` — **no TLS filter is in the chain**, i.e.
/// SSL is disabled, the `CURL_CF_SSL_DISABLE` contract). russh manages its own
/// transport crypto over the raw bytes from here on.
///
/// Until `crate::conn` exposes a raw-transport take-accessor for `TRNSPRT_TCP`
/// connections, this fallback owns a fresh `TcpStream` to the resolved peer; the
/// `// SEAM` note on [`ConnStream`] explains how this collapses to a zero-copy
/// handoff once the accessor exists. (Live end-to-end transport is exercised by
/// the curl 8.x suite in the global test phase, per the file prompt's Phase 9.)
async fn obtain_owned_transport_stream(
    conn: &mut Connection,
) -> Result<ConnStream<TcpStream>> {
    // IPv6 literals are stored bracketed (`[::1]`); `TcpStream::connect` wants the
    // bare address, so strip a single pair of brackets if present.
    let host = conn
        .remote_host
        .trim_start_matches('[')
        .trim_end_matches(']');
    let stream = TcpStream::connect((host, conn.remote_port))
        .await
        .map_err(|_| CurlError::Ssh)?;
    Ok(ConnStream { inner: stream })
}

// ===========================================================================
// Shared option / credential / host-key helpers.
// ===========================================================================

/// Resolve the SSH user name and password for this transfer.
///
/// curl populates `conn->user` / `conn->passwd` during connection setup from the
/// URL credentials and/or `CURLOPT_USERNAME` / `CURLOPT_PASSWORD`. Here the
/// configured options take precedence and the URL-embedded credentials
/// (`sftp://user:pass@host/…`) are the fallback; an unset value resolves to the
/// empty string (russh requires a user string, and an empty user lets the server
/// reject it exactly as curl does).
fn resolve_credentials(data: &Easy) -> (String, String) {
    let mut user = data.set.str(StrId::Username).unwrap_or("").to_string();
    let mut passwd = data.set.str(StrId::Password).unwrap_or("").to_string();

    if user.is_empty() || passwd.is_empty() {
        if let Some(url_str) = data.url() {
            let mut u = CurlUrl::new();
            if u.set(CurlUPart::Url, Some(url_str), CURLU_GUESS_SCHEME).is_ok() {
                if user.is_empty() {
                    if let Ok(parsed) = u.get(CurlUPart::User, CURLU_URLDECODE) {
                        user = parsed;
                    }
                }
                if passwd.is_empty() {
                    if let Ok(parsed) = u.get(CurlUPart::Password, CURLU_URLDECODE) {
                        passwd = parsed;
                    }
                }
            }
        }
    }

    (user, passwd)
}

/// Capture the host-key verification inputs from the easy handle and connection
/// (`CURLOPT_SSH_KNOWNHOSTS`, `..._HOST_PUBLIC_KEY_MD5`, `..._SHA256`) into a
/// [`HostKeyConfig`] for the [`ClientHandler`].
fn host_key_config(data: &Easy, conn: &Connection) -> HostKeyConfig {
    HostKeyConfig {
        host: conn.remote_host.clone(),
        port: conn.remote_port,
        verbose: data.set.verbose,
        known_hosts: data
            .set
            .str(StrId::SshKnownhosts)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        expected_md5: data
            .set
            .str(StrId::SshHostPublicKeyMd5)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        expected_sha256: data
            .set
            .str(StrId::SshHostPublicKeySha256)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
    }
}

/// The ordered private-key search path when `CURLOPT_SSH_PRIVATE_KEYFILE` is
/// unset — a faithful port of the libssh2 backend's default: `$HOME/.ssh/id_rsa`,
/// then `id_dsa`, then the same two names in the current directory. Pure (the
/// only input is `home`), so it is unit-testable without touching the filesystem.
fn default_key_candidates(home: Option<&str>) -> Vec<String> {
    let mut out = Vec::with_capacity(4);
    if let Some(home) = home {
        out.push(format!("{home}/.ssh/id_rsa"));
        out.push(format!("{home}/.ssh/id_dsa"));
    }
    out.push("id_rsa".to_string());
    out.push("id_dsa".to_string());
    out
}

/// Resolve the private-key file path: `CURLOPT_SSH_PRIVATE_KEYFILE` (opt 153) if
/// set and non-empty, else the first existing entry from
/// [`default_key_candidates`] (`$HOME` from the environment, mirroring the C
/// backend). Returns `None` when no candidate exists.
fn resolve_private_key_path(data: &Easy) -> Option<String> {
    if let Some(p) = data.set.str(StrId::SshPrivateKey) {
        if !p.is_empty() {
            return Some(p.to_string());
        }
    }
    let home = std::env::var("HOME").ok();
    default_key_candidates(home.as_deref())
        .into_iter()
        .find(|c| std::path::Path::new(c).exists())
}

/// Resolve the working path for this transfer — a faithful port of `vssh.c`
/// `Curl_getworkingpath`.
///
/// The URL path is URL-decoded, then the leading `/~/` (home-relative) prefix is
/// rewritten per scheme: **SCP strips** `/~/` (the path becomes relative to the
/// login directory), while **SFTP substitutes** the captured `homedir` for `/~`.
/// For a fresh SFTP connection the home directory is not yet known (it is
/// captured by SFTP `realpath` post-connect), so when `homedir` is `None` the
/// `/~` substitution is deferred and the decoded path is returned as-is; the
/// SFTP `do_it` re-resolves it once `homedir` is set (file prompt §5).
///
/// The rewritten path is capped at [`MAX_SSHPATH_LEN`]; overflow maps to
/// [`CurlError::OutOfMemory`], exactly as the C dynbuf bound does.
pub(crate) fn get_working_path(
    data: &Easy,
    conn: &Connection,
    homedir: Option<&str>,
) -> Result<String> {
    // URL-decode the URL path (C: `Curl_urldecode(data->state.up.path, …,
    // REJECT_ZERO)`). The path component always resolves (defaulting to "/").
    let url_str = data.url().ok_or(CurlError::UrlMalformat)?;
    let mut u = CurlUrl::new();
    u.set(CurlUPart::Url, Some(url_str), CURLU_GUESS_SCHEME)
        .map_err(|_| CurlError::UrlMalformat)?;
    let working_path = u
        .get(CurlUPart::Path, CURLU_URLDECODE)
        .map_err(|_| CurlError::UrlMalformat)?;
    let working_path_len = working_path.len();
    let bytes = working_path.as_bytes();

    let proto = conn.scheme.protocol;
    // The rewritten ("new") path; empty means "use working_path unchanged".
    let mut npath = String::new();

    if (proto & CURLPROTO_SCP) != 0 && working_path_len > 3 && bytes.starts_with(b"/~/") {
        // SCP: referenced to the home directory — strip the leading "/~/".
        npath.push_str(&working_path[3..]);
    } else if (proto & CURLPROTO_SFTP) != 0
        && (working_path == "/~" || (working_path_len > 2 && bytes.starts_with(b"/~/")))
    {
        // SFTP: substitute the home directory for the leading "/~".
        if let Some(home) = homedir {
            npath.push_str(home);
            if working_path_len > 2 {
                // Default skips "/~/"; if homedir does not already end with '/',
                // keep working_path's separator by skipping only "/~".
                let copyfrom = if !npath.is_empty() && !npath.ends_with('/') {
                    2
                } else {
                    3
                };
                npath.push_str(&working_path[copyfrom..]);
            } else {
                npath.push('/');
            }
        }
        // homedir == None: defer substitution (re-resolved in SFTP do_it).
    }

    let path = if npath.is_empty() { working_path } else { npath };

    // C bounds the rewritten path by the MAX_SSHPATH_LEN dynbuf; enforce it.
    if path.len() > MAX_SSHPATH_LEN {
        return Err(CurlError::OutOfMemory);
    }

    Ok(path)
}

/// Parse a single QUOTE-command path argument from `input`, returning the
/// resolved path and the number of bytes consumed — the safe-Rust analog of the
/// C `Curl_get_pathname` (`vssh.c` L200-285). `consumed` lets the caller parse
/// the next argument from `&input[consumed..]` (the C `*cpp` advance), which is
/// how two-argument QUOTE commands such as `rename`/`symlink` are tokenized.
///
/// Faithful to the C oracle:
/// - leading blanks (space/tab) are skipped (C `curlx_str_passblanks`);
/// - a quoted filename (`"` or `'`) supports exactly the escapes `\"`, `\'`,
///   `\\` (the backslash is dropped, the escaped byte kept); any other `\X`, an
///   unterminated quote, or an empty quoted string is a
///   [`CurlError::QuoteError`];
/// - an unquoted leading `/~/` is rewritten to `<homedir>/` — the `homedir`
///   parameter mirrors the C function's third argument (`sshc->homedir`), which
///   the mandated `/~/` support requires; the nominal prompt signature is
///   extended with it for that reason;
/// - an unquoted bare word runs to the next space (C `curlx_str_word`, delimiter
///   `' '`; tabs are part of the word, exactly as C);
/// - the argument is capped at [`MAX_PATHLENGTH`]; overflow maps to
///   [`CurlError::TooLarge`] (C `STRE_BIG` / dynbuf `CURLE_TOO_LARGE`);
/// - empty input, or no path at all, is a [`CurlError::QuoteError`].
///
/// `consumed` includes the leading and trailing blanks the C skips, matching
/// `*cpp` pointing past the trailing whitespace on success.
///
/// See the note on [`MAX_PATHLENGTH`] for why this shared helper carries
/// `#[allow(dead_code)]`.
#[allow(dead_code)]
pub(crate) fn get_pathname(input: &str, homedir: &str) -> Result<(String, usize)> {
    // Walk bytes to mirror the C pointer arithmetic exactly; the parser only
    // special-cases ASCII delimiters/quotes, so byte indexing is faithful.
    let bytes = input.as_bytes();
    let len = bytes.len();

    // C: `if(!*cp ...) return CURLE_QUOTE_ERROR;` — empty input is a quote error
    // (checked before skipping leading blanks).
    if len == 0 {
        return Err(CurlError::QuoteError);
    }

    let mut i = 0usize;
    // Ignore leading whitespace (C `curlx_str_passblanks`: space and tab).
    while i < len && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }

    let mut out: Vec<u8> = Vec::new();

    if i < len && (bytes[i] == b'"' || bytes[i] == b'\'') {
        // Quoted filename: search for the terminating quote, unescaping.
        let quot = bytes[i];
        i += 1;
        loop {
            if i >= len {
                // End of string before the closing quote.
                return Err(CurlError::QuoteError);
            }
            if bytes[i] == quot {
                break;
            }
            if bytes[i] == b'\\' {
                // Escaped character: only \" \' \\ are valid (C `goto fail`).
                i += 1;
                if i >= len || (bytes[i] != b'\'' && bytes[i] != b'"' && bytes[i] != b'\\') {
                    return Err(CurlError::QuoteError);
                }
            }
            out.push(bytes[i]);
            if out.len() > MAX_PATHLENGTH {
                return Err(CurlError::TooLarge);
            }
            i += 1;
        }
        i += 1; // pass the end quote

        if out.is_empty() {
            // Empty quoted string ("" or '') is an error (C `dyn_len == 0`).
            return Err(CurlError::QuoteError);
        }
    } else {
        // Unquoted. Handle a relative `/~/` prefix by prepending the home dir.
        let mut content = false;
        if i + 2 < len && bytes[i] == b'/' && bytes[i + 1] == b'~' && bytes[i + 2] == b'/' {
            out.extend_from_slice(homedir.as_bytes());
            out.push(b'/');
            i += 3;
            content = true;
            if out.len() > MAX_PATHLENGTH {
                return Err(CurlError::TooLarge);
            }
        }
        // Read to end of filename — to the next space or the terminator
        // (C `curlx_str_word`, delimiter ' ').
        let word_start = i;
        while i < len && bytes[i] != b' ' {
            i += 1;
            if i - word_start > MAX_PATHLENGTH {
                // C `curlx_str_word` returns STRE_BIG → CURLE_TOO_LARGE.
                return Err(CurlError::TooLarge);
            }
        }
        if i == word_start {
            // No word read. If we already added the homedir prefix this is a
            // valid path ("/~/"); otherwise there is no path → quote error
            // (C: `else if(!content) goto fail`).
            if !content {
                return Err(CurlError::QuoteError);
            }
        } else {
            out.extend_from_slice(&bytes[word_start..i]);
            if out.len() > MAX_PATHLENGTH {
                return Err(CurlError::TooLarge);
            }
        }
    }

    // Skip trailing whitespace; `consumed` then points at the next argument
    // (C `curlx_str_passblanks` followed by `*cpp = cp`).
    while i < len && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }

    // SSH paths are byte strings; the module models them as UTF-8 (as does the
    // URL layer feeding `get_working_path`). Preserve the exact bytes when they
    // are valid UTF-8 (the universal case for the test suite); a non-UTF-8
    // argument is treated as malformed.
    let path = String::from_utf8(out).map_err(|_| CurlError::QuoteError)?;
    Ok((path, i))
}

/// Parse a base-10 non-negative offset at `bytes[*i..]`, advancing `*i` past the
/// digits. Mirrors C `curlx_str_number` with `max = CURL_OFF_T_MAX`: returns
/// `(false, 0)` when there is no leading digit (C `STRE_NO_NUM`) and a
/// [`CurlError::RangeError`] on overflow (C `STRE_OVERFLOW`).
///
/// See the note on [`MAX_PATHLENGTH`] for why this shared helper carries
/// `#[allow(dead_code)]` (it is reached only via [`ssh_range`]).
#[allow(dead_code)]
fn parse_offset(bytes: &[u8], i: &mut usize) -> Result<(bool, i64)> {
    const OFF_T_MAX: i64 = i64::MAX;
    if *i >= bytes.len() || !bytes[*i].is_ascii_digit() {
        return Ok((false, 0));
    }
    let mut num: i64 = 0;
    while *i < bytes.len() && bytes[*i].is_ascii_digit() {
        let d = i64::from(bytes[*i] - b'0');
        // Overflow check mirroring C: `num > (max - n) / base`.
        if num > (OFF_T_MAX - d) / 10 {
            return Err(CurlError::RangeError);
        }
        num = num * 10 + d;
        *i += 1;
    }
    Ok((true, num))
}

/// Parse an SSH `RANGE` specification against a known file size, returning the
/// `(start, size)` byte range — the safe-Rust analog of the C `Curl_ssh_range`
/// (`vssh.c` L287-330). Used by the SFTP download path.
///
/// Supported forms (faithful to the C oracle):
/// - `from-to` — explicit closed range (`to` clamped to `filesize - 1`);
/// - `from-`   — from `from` to end of file;
/// - `-N`      — the last `N` bytes (relative to end of file);
/// - `from`    — a bare number behaves like `from-` (C consumes the `-`
///   optionally and treats a missing `to` as "to end").
///
/// Any malformed input, an offset beyond the file size, an inverted range, or a
/// size that would overflow `curl_off_t` maps to [`CurlError::RangeError`]. The
/// helper is kept data-free (no `failf`) so it is unit-testable; the C `failf`
/// diagnostics are advisory only and a caller may surface them.
///
/// See the note on [`MAX_PATHLENGTH`] for why this shared helper carries
/// `#[allow(dead_code)]`.
#[allow(dead_code)]
pub(crate) fn ssh_range(range: &str, filesize: u64) -> Result<(u64, u64)> {
    // The C arithmetic is in curl_off_t (i64) and turns on CURL_OFF_T_MAX;
    // mirror that domain. Real SFTP/SCP file sizes fit in i64.
    const OFF_T_MAX: i64 = i64::MAX;
    let filesize = i64::try_from(filesize).unwrap_or(OFF_T_MAX);

    let bytes = range.as_bytes();
    let mut i = 0usize;

    // Parse the optional leading number (C `curlx_str_number`).
    let (have_from, mut from) = parse_offset(bytes, &mut i)?;

    // Skip blanks, then consume a single '-' if present (C ignores the result).
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b'-' {
        i += 1;
    }

    // Skip blanks then parse the optional trailing number (C `curlx_str_numblanks`).
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }
    let (have_to, mut to) = parse_offset(bytes, &mut i)?;

    // C: error if neither bound parsed, or there are leftover characters.
    if (!have_to && !have_from) || i != bytes.len() {
        return Err(CurlError::RangeError);
    }

    if !have_from {
        // "-N": no start point — set `from` relative to the end of the file.
        if to == 0 {
            // "-0" is not a valid range.
            return Err(CurlError::RangeError);
        }
        if to > filesize {
            to = filesize;
        }
        from = filesize - to;
        to = filesize - 1;
    } else if from > filesize {
        // Offset beyond the file size (C emits a `failf` here).
        return Err(CurlError::RangeError);
    } else if !have_to || to >= filesize {
        // "N-" (no `to`) or `to` past EOF → clamp to the last byte.
        to = filesize - 1;
    }

    if from > to {
        // Inverted range (C `failf` "start offset larger than end offset").
        return Err(CurlError::RangeError);
    }
    if to - from == OFF_T_MAX {
        // `size = to - from + 1` would overflow curl_off_t.
        return Err(CurlError::RangeError);
    }

    let start = from;
    let size = to - from + 1;
    // Both are non-negative here (0 <= from <= to), so the casts are lossless.
    Ok((start as u64, size as u64))
}

// ===========================================================================
// Error mapping — the analog of `libssh2_session_error_to_CURLE`.
// ===========================================================================

/// Map a `russh` transport/protocol error to a [`CurlError`].
///
/// Authentication exhaustion and host-key rejection are surfaced precisely by
/// the auth chain ([`CurlError::LoginDenied`]) and the host-key handler
/// ([`CurlError::PeerFailedVerification`], via the shared outcome slot)
/// respectively, so this generic fallback covers the remaining transport/protocol
/// failures, mirroring the C backend's default `CURLE_SSH` mapping.
fn map_ssh_err(_e: russh::Error) -> CurlError {
    CurlError::Ssh
}

/// Map a `russh-sftp` operation error to a [`CurlError`], reproducing the C
/// `sftp_libssh2_error_to_CURLE` table (`libssh2.c` L158-189) for the SFTP
/// status codes `russh-sftp` surfaces.
///
/// `SftpSession` methods yield [`russh_sftp::client::error::Error`]; a protocol
/// `Status` carries the SSH_FXP_STATUS code. Faithful mapping:
/// `NO_SUCH_FILE`/`NO_SUCH_PATH` → [`CurlError::RemoteFileNotFound`];
/// `PERMISSION_DENIED` → [`CurlError::RemoteAccessDenied`]; every other status,
/// and all transport-level errors, fall back to [`CurlError::Ssh`] — the C
/// `default` arm. (`russh-sftp` models only the draft-02 status codes 0-8, so
/// the extended codes the C table also maps cannot appear here and collapse into
/// the `Ssh` fallback, exactly as the C default would handle an unknown code.)
///
/// See the note on [`MAX_PATHLENGTH`] for why this shared helper carries
/// `#[allow(dead_code)]`.
#[cfg(feature = "sftp")]
#[allow(dead_code)]
pub(crate) fn map_sftp_err(e: russh_sftp::client::error::Error) -> CurlError {
    use russh_sftp::client::error::Error as SftpError;
    use russh_sftp::protocol::StatusCode;
    match e {
        SftpError::Status(status) => match status.status_code {
            StatusCode::NoSuchFile => CurlError::RemoteFileNotFound,
            StatusCode::PermissionDenied => CurlError::RemoteAccessDenied,
            _ => CurlError::Ssh,
        },
        _ => CurlError::Ssh,
    }
}

// ===========================================================================
// Authentication fallback chain — a faithful reproduction of the libssh2 connect
// /auth state machine (`libssh2.c` `ssh_state_*`, L1428-1760), collapsed to
// linear async control flow.
// ===========================================================================

/// Extract the server's still-offered method set from an [`AuthResult`].
fn remaining_methods(res: AuthResult) -> MethodSet {
    match res {
        AuthResult::Success => MethodSet::empty(),
        AuthResult::Failure {
            remaining_methods, ..
        } => remaining_methods,
    }
}

/// Stage 1 — public-key authentication (C `SSH_AUTH_PKEY_INIT` → `SSH_AUTH_PKEY`).
///
/// Resolves the private-key path ([`resolve_private_key_path`]), loads it with the
/// `CURLOPT_KEYPASSWD` passphrase, negotiates the RSA signature hash, and calls
/// `authenticate_publickey`. Returns `Ok(None)` when no usable key could be
/// loaded (mirroring the C fall-through from a pkey failure to the password
/// stage — a missing/locked key is not a hard error), or `Ok(Some(result))` with
/// the server's verdict.
async fn try_publickey(
    handle: &mut Handle<ClientHandler>,
    data: &Easy,
    user: &str,
    verbose: bool,
) -> Result<Option<AuthResult>> {
    let key_path = match resolve_private_key_path(data) {
        Some(p) => p,
        None => {
            sendf::infof(verbose, "No SSH private key file found for public key auth");
            return Ok(None);
        }
    };
    sendf::infof(verbose, &format!("Using SSH private key file '{key_path}'"));

    // CURLOPT_KEYPASSWD (opt 26) decrypts an encrypted private key.
    let passphrase = data.set.str(StrId::KeyPasswd).filter(|s| !s.is_empty());
    let key = match load_secret_key(&key_path, passphrase) {
        Ok(k) => k,
        Err(_) => {
            sendf::infof(
                verbose,
                "SSH public key authentication failed: could not load private key",
            );
            return Ok(None);
        }
    };

    // Negotiate the RSA signature hash (rsa-sha2-256/512); ignored for non-RSA
    // keys by `PrivateKeyWithHashAlg::new`. `None` => the server's default.
    let hash_alg = handle
        .best_supported_rsa_hash()
        .await
        .ok()
        .flatten()
        .flatten();
    let key_with = PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);

    let res = handle
        .authenticate_publickey(user.to_string(), key_with)
        .await
        .map_err(map_ssh_err)?;
    Ok(Some(res))
}

/// Stage 4 — ssh-agent authentication (C `SSH_AUTH_AGENT_INIT` → `SSH_AUTH_AGENT`).
///
/// Connects to the agent via `$SSH_AUTH_SOCK`, enumerates its identities, and
/// tries each public key (the [`AgentClient`] is the `Signer`). Returns
/// `Ok(Some(Success))` on the first accepted identity, else `Ok(None)`.
async fn try_agent(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    verbose: bool,
) -> Result<Option<AuthResult>> {
    let mut agent = match AgentClient::connect_env().await {
        Ok(a) => a,
        Err(_) => {
            sendf::infof(verbose, "Could not connect to ssh-agent");
            return Ok(None);
        }
    };
    let identities = match agent.request_identities().await {
        Ok(ids) => ids,
        Err(_) => {
            sendf::infof(verbose, "Could not list ssh-agent identities");
            return Ok(None);
        }
    };

    for id in identities {
        // Only plain public keys participate; certificates are skipped.
        let pubkey = match id {
            russh::keys::agent::AgentIdentity::PublicKey { key, .. } => key,
            russh::keys::agent::AgentIdentity::Certificate { .. } => continue,
        };
        let hash_alg = handle
            .best_supported_rsa_hash()
            .await
            .ok()
            .flatten()
            .flatten();
        match handle
            .authenticate_publickey_with(user.to_string(), pubkey, hash_alg, &mut agent)
            .await
        {
            Ok(res) if res.success() => return Ok(Some(res)),
            _ => continue,
        }
    }
    Ok(None)
}

/// Stage 5 — keyboard-interactive authentication (C `SSH_AUTH_KEY_INIT` →
/// `SSH_AUTH_KEY`). Answers every server prompt with the password (mirroring the
/// C `kbd_callback`), iterating until the server accepts or rejects.
async fn try_keyboard_interactive(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    passwd: &str,
) -> Result<bool> {
    let mut resp = handle
        .authenticate_keyboard_interactive_start(user.to_string(), None)
        .await
        .map_err(map_ssh_err)?;
    loop {
        match resp {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                // One answer per prompt; the password answers each (as the C
                // keyboard-interactive callback does).
                let answers = prompts.iter().map(|_| passwd.to_string()).collect();
                resp = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await
                    .map_err(map_ssh_err)?;
            }
        }
    }
}

/// Run the full authentication fallback chain against an established session.
///
/// Order and gating are a faithful reproduction of `libssh2.c` (each stage gated
/// by BOTH the `CURLOPT_SSH_AUTH_TYPES` mask bit AND the server advertising the
/// method): `none` probe → **public-key** → **password** → **host-based**
/// (a deliberate no-op that only advances, exactly as libssh2's `SSH_AUTH_HOST`
/// case) → **ssh-agent** → **keyboard-interactive**. On success the matching
/// `infof` is emitted; if every method is exhausted, `failf` is emitted and
/// [`CurlError::LoginDenied`] returned.
async fn run_authentication(
    handle: &mut Handle<ClientHandler>,
    data: &Easy,
    error_buffer: &mut Option<String>,
    user: &str,
    passwd: &str,
) -> Result<()> {
    let verbose = data.set.verbose;
    let auth_mask = data.set.ssh_auth_types;

    sendf::infof(verbose, &format!("User: '{user}'"));

    // Stage 0 — advertise discovery via the "none" method.
    let none_res = handle
        .authenticate_none(user.to_string())
        .await
        .map_err(map_ssh_err)?;
    if none_res.success() {
        sendf::infof(verbose, "SSH user accepted with no authentication");
        return Ok(());
    }
    let mut remaining = remaining_methods(none_res);

    // Stage 1 — PUBLICKEY.
    if (auth_mask & CURLSSH_AUTH_PUBLICKEY) != 0 && remaining.contains(&MethodKind::PublicKey) {
        if let Some(res) = try_publickey(handle, data, user, verbose).await? {
            if res.success() {
                sendf::infof(verbose, "Initialized SSH public key authentication");
                return Ok(());
            }
            sendf::infof(verbose, "SSH public key authentication failed");
            remaining = remaining_methods(res);
        }
    }

    // Stage 2 — PASSWORD.
    if (auth_mask & CURLSSH_AUTH_PASSWORD) != 0 && remaining.contains(&MethodKind::Password) {
        let res = handle
            .authenticate_password(user.to_string(), passwd.to_string())
            .await
            .map_err(map_ssh_err)?;
        if res.success() {
            sendf::infof(verbose, "Initialized password authentication");
            return Ok(());
        }
        remaining = remaining_methods(res);
    }

    // Stage 3 — HOST-BASED. libssh2's `SSH_AUTH_HOST` case is a deliberate no-op
    // that only advances to the agent stage (host-based is never actually
    // attempted); honor the gate for parity, then fall through.
    if (auth_mask & CURLSSH_AUTH_HOST) != 0 && remaining.contains(&MethodKind::HostBased) {
        sendf::infof(
            verbose,
            "SSH host-based authentication is not attempted (matching libssh2); skipping",
        );
    }

    // Stage 4 — AGENT (advertised under "publickey").
    if (auth_mask & CURLSSH_AUTH_AGENT) != 0 && remaining.contains(&MethodKind::PublicKey) {
        if let Some(res) = try_agent(handle, user, verbose).await? {
            if res.success() {
                sendf::infof(verbose, "Initialized SSH agent authentication");
                return Ok(());
            }
            remaining = remaining_methods(res);
        }
    }

    // Stage 5 — KEYBOARD-INTERACTIVE.
    if (auth_mask & CURLSSH_AUTH_KEYBOARD) != 0
        && remaining.contains(&MethodKind::KeyboardInteractive)
        && try_keyboard_interactive(handle, user, passwd).await?
    {
        sendf::infof(verbose, "Initialized keyboard-interactive authentication");
        return Ok(());
    }

    // Every gated/advertised method has been exhausted (C `SSH_AUTH_DONE` with
    // `!authed`).
    sendf::failf(error_buffer, "Authentication failure");
    Err(CurlError::LoginDenied)
}

// ===========================================================================
// Shared session bring-up — the connect/auth half of the C `ssh_connect` +
// `ssh_multi_statemach`, collapsed to linear async.
// ===========================================================================

/// Establish and authenticate the shared SSH session, parking it in the
/// connection's `proto_state`.
///
/// Invoked by both [`ScpHandler::connect`] and [`SftpHandler::connect`]; the SFTP
/// handler additionally starts the SFTP subsystem and captures the home directory
/// afterwards (see [`SftpHandler`]). On return, `conn.proto_state` holds an
/// authenticated [`SshConn`].
pub(crate) async fn connect_ssh_session(data: &mut Easy, conn: &mut Connection) -> Result<()> {
    // 1. TCP bring-up through curl's connection layer. SSL is disabled by
    //    construction: the SSH scheme carries no `PROTOPT_SSL`, so the engine put
    //    no TLS filter in the chain (the `CURL_CF_SSL_DISABLE` contract). russh
    //    negotiates its own transport crypto over the raw bytes.
    Curl_conn_connect(conn, FIRSTSOCKET, true).await?;

    let (user, passwd) = resolve_credentials(data);

    // 2. russh client configuration.
    let mut config = Config::default();
    if data.set.server_response_timeout > 0 {
        config.inactivity_timeout =
            Some(Duration::from_millis(data.set.server_response_timeout as u64));
    }
    if data.set.ssh_compression {
        // Prefer zlib (with the OpenSSH-legacy variant), falling back to none —
        // mirroring `CURLOPT_SSH_COMPRESSION`. russh's `flate2` feature
        // (default-on in this workspace) provides the zlib codecs.
        config.preferred.compression = std::borrow::Cow::Borrowed(&[
            russh::compression::ZLIB,
            russh::compression::ZLIB_LEGACY,
            russh::compression::NONE,
        ]);
    }
    let config = Arc::new(config);

    // 3. Host-key verification config + shared outcome slot. The handler runs on
    //    russh's spawned session task and can only return `Ok(false)` to reject a
    //    key, so the precise reason is published into `outcome` for us to read.
    let hk = host_key_config(data, conn);
    let outcome: Arc<Mutex<Option<CurlError>>> = Arc::new(Mutex::new(None));
    let handler = ClientHandler::new(hk, Arc::clone(&outcome));

    // 4. Obtain the owned transport stream (the SEAM) and perform the handshake.
    //    Host-key verification happens inside `ClientHandler::check_server_key`.
    let stream = obtain_owned_transport_stream(conn).await?;
    let mut handle = match client::connect_stream(config, stream, handler).await {
        Ok(h) => h,
        Err(e) => {
            if let Some(reason) = outcome.lock().ok().and_then(|mut g| g.take()) {
                // A host-key rejection — surface the exact `CURLE_*` the handler
                // recorded (e.g. `CURLE_PEER_FAILED_VERIFICATION`).
                return Err(reason);
            }
            return Err(map_ssh_err(e));
        }
    };

    // 5. Authentication fallback chain.
    run_authentication(
        &mut handle,
        data,
        &mut conn.filter_data.error_buffer,
        &user,
        &passwd,
    )
    .await?;

    // 6. Record the authenticated session on the per-connection state (the
    //    `conn->proto` / `CURL_META_SSH_CONN` analog) for `do_it`/`done`/
    //    `disconnect`. `setup_connection` allocated the `SshConn`; fill it in
    //    place so the resolved request path is preserved. (The defensive
    //    `else` covers a session brought up without a prior `setup_connection`.)
    //    SCP is fully connected here; the SFTP subsystem + homedir realpath are
    //    started afterwards by `SftpHandler::connect`.
    if let Some(sshc) = conn.proto_state_mut::<SshConn>() {
        sshc.handle = Some(handle);
        sshc.authed = true;
    } else {
        let mut sshc = SshConn::new();
        sshc.handle = Some(handle);
        sshc.authed = true;
        conn.set_proto_state(Box::new(sshc));
    }

    Ok(())
}

// ===========================================================================
// `setup_connection` and disconnect-hook helpers shared by both handlers.
// ===========================================================================

/// Shared `setup_connection` body (C `ssh_setup_connection`): allocate the
/// per-connection [`SshConn`] (kept across reuse) and resolve this transfer's
/// working path into its current [`SshRequest`]. Performs **no network I/O**.
fn setup_ssh_connection(data: &mut Easy, conn: &mut Connection) -> Result<()> {
    // Allocate the per-connection state once; a reused connection keeps the live
    // session (and its captured `homedir`).
    if conn.proto_state_ref::<SshConn>().is_none() {
        conn.set_proto_state(Box::new(SshConn::new()));
    }

    // Resolve the working path. `homedir` is known only on a reused/connected
    // SFTP connection; on a fresh one it is `None` and the `/~` substitution is
    // deferred to `do_it` (see [`get_working_path`]).
    let homedir = conn
        .proto_state_ref::<SshConn>()
        .and_then(|s| s.homedir.clone());
    let path = get_working_path(data, conn, homedir.as_deref())?;
    if let Some(sshc) = conn.proto_state_mut::<SshConn>() {
        sshc.request.path = path;
    }
    Ok(())
}

/// Install the one-shot connection-teardown hook (C `ssh_disconnect` →
/// `SSH_SESSION_DISCONNECT`/`SSH_SESSION_FREE`).
///
/// The live session is moved out of `proto_state` into the hook so the shutdown
/// subsystem can drive a graceful SSH goodbye (or a fast drop on abort) **without
/// `crate::conn` ever naming a `crate::protocols` type** — the dependency
/// inversion the acyclic `protocols → conn` rule requires. `dead` (the C
/// `aborted` flag at disconnect time) is combined with the `aborted` flag the
/// shutdown subsystem passes when it finally runs the hook: either being set
/// skips the graceful goodbye.
fn install_ssh_disconnect_hook(conn: &mut Connection, dead: bool) {
    let Some(boxed) = conn.take_proto_state() else {
        // No session parked (never connected, or already torn down): nothing to
        // do — a connection is disconnected at most once.
        return;
    };
    let Ok(sshc_box) = boxed.downcast::<SshConn>() else {
        return;
    };
    let sshc = *sshc_box;

    conn.set_disconnect_hook(Box::new(move |aborted: bool| -> BoxFuture<'static, ()> {
        let skip_graceful = aborted || dead;
        Box::pin(async move {
            let mut sshc = sshc;
            // SFTP: end the subsystem first (C `SSH_SFTP_SHUTDOWN`); dropping the
            // session closes it.
            #[cfg(feature = "sftp")]
            {
                sshc.sftp_session = None;
            }
            sshc.homedir = None;
            if let Some(handle) = sshc.handle.take() {
                if !skip_graceful {
                    // C `SSH_SESSION_DISCONNECT`: send a clean SSH disconnect.
                    let _ = handle
                        .disconnect(Disconnect::ByApplication, "", "")
                        .await;
                }
                // C `SSH_SESSION_FREE`: russh closes the transport on drop.
                drop(handle);
            }
        })
    }));
}

// ===========================================================================
// Transfer-engine entry points — the SSH analogs of `http::perform_http` and
// `ftp::perform_ftp`. These are the seam that `protocols::perform_transfer`
// dispatches `scp://` / `sftp://` to (QA F4-CRIT-3): they build the plain-TCP
// connection + happy-eyeballs filter chain (russh layers its own transport
// crypto over the raw bytes — no rustls filter, the `CURL_CF_SSL_DISABLE`
// contract), bring up and authenticate the SSH session (host-key verification
// included), drive the data plane with the caller's client `sink`/`source`, then
// finalize and tear down.
// ===========================================================================

/// Resolve the SSH control endpoint's addresses via the system resolver (SSH has
/// no DoH path of its own), mirroring `ftp::resolve_ftp_addrs`.
async fn resolve_ssh_addrs(
    host: &str,
    port: u16,
    ipver: IpVersion,
    verbose: bool,
) -> Result<ResolvedAddrs> {
    let mut cache = DnsCache::new();
    let mut errbuf: Option<String> = None;
    let mut params = ResolveParams::new(host, port);
    params.ip_version = ipver;
    params.verbose = verbose;
    let entry = dns::resolve(&mut cache, &params, &mut errbuf).await?;
    Ok(entry.addrs.clone())
}

/// Build and connect the plain-TCP [`Connection`] for an SSH scheme (`scp`/
/// `sftp`), carrying the scheme descriptor and the happy-eyeballs filter chain.
///
/// SSH never installs a TLS filter (`CURL_CF_SSL_DISABLE`): `russh` negotiates
/// its own transport encryption over the raw socket bytes (AAP G2). On return the
/// `FIRSTSOCKET` chain is connected and ready for [`connect_ssh_session`].
async fn build_ssh_connection(data: &mut Easy, scheme: &'static Scheme) -> Result<Connection> {
    let verbose = data.set.verbose;

    // Resolve the request URL: prefer a pre-parsed `CURLOPT_CURLU` handle
    // (deposited by the FFI layer), else parse the stored URL string with curl's
    // scheme guessing and default-port fallback.
    let url = if let Some(uh) = data.set.uh.clone() {
        uh
    } else {
        let url_str = data.url().ok_or(CurlError::UrlMalformat)?.to_string();
        let mut parsed = CurlUrl::new();
        parsed
            .set(
                CurlUPart::Url,
                Some(&url_str),
                CURLU_GUESS_SCHEME | CURLU_DEFAULT_PORT,
            )
            .map_err(|_| CurlError::UrlMalformat)?;
        parsed
    };

    // Host (stripped of any IPv6 brackets for DNS/identity) and port (default 22).
    let host_bracketed = url.get(CurlUPart::Host, CURLU_URLDECODE).unwrap_or_default();
    if host_bracketed.is_empty() {
        return Err(CurlError::UrlMalformat);
    }
    let host = host_bracketed
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(&host_bracketed)
        .to_string();
    let port = url
        .get(CurlUPart::Port, 0)
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(scheme.default_port);

    let ipver = IpVersion::from_raw(i64::from(data.set.ipver));
    let addrs = resolve_ssh_addrs(&host, port, ipver, verbose).await?;

    let desc = SchemeDescriptor::new(scheme.name, scheme.default_port, scheme.flags, scheme.protocol);
    let mut conn =
        Connection::new(format!("{host}:{port}"), TRNSPRT_TCP, desc).with_verbose(verbose);
    conn.set_remote(host, port);

    // Plain TCP + happy-eyeballs; no TLS filter (russh owns transport crypto).
    let eyeballs = eyeballs_factory(TRNSPRT_TCP, ipver, data.set.happy_eyeballs_timeout, addrs);
    let dispatch = ConnSetup::Default(SetupConfig::new(CURL_CF_SSL_DISABLE, false, eyeballs));
    establish_connection(&mut conn, FIRSTSOCKET, CURL_CF_SSL_DISABLE, dispatch, true).await?;
    Ok(conn)
}

/// Drive an `scp://` transfer end-to-end (QA F4-CRIT-3) — the SCP analog of
/// `ftp::perform_ftp`.
///
/// Builds the plain-TCP connection, brings up + authenticates the SSH session
/// (host-key verification per `--hostpubmd5`/`--hostpubsha256`/known_hosts), then
/// runs the SCP data plane: an `scp -f` download streams the announced bytes into
/// the client `sink`, an `scp -t` upload streams `CURLOPT_INFILESIZE` bytes from
/// the client `source`. The byte movement and channel teardown happen in
/// [`scp::run_download`] / [`scp::run_upload`].
#[cfg(feature = "scp")]
pub(crate) async fn perform_scp(
    data: &mut Easy,
    sink: &mut dyn WriteCallbacks,
    source: &mut dyn ReadCallback,
) -> Result<()> {
    let handler = ScpHandler;
    let mut conn = build_ssh_connection(data, &SCHEME_SCP).await?;

    // Per-connection setup (decode URL path/creds) then bring up + authenticate
    // the SSH transport (C `ssh_setup_connection` + `ssh_connect`).
    handler.setup_connection(data, &mut conn).await?;
    handler.connect(data, &mut conn).await?;

    // Classify the transfer (C `scp_doing`) and drive the matching data plane
    // with the caller's client callbacks.
    let result = match scp::do_it(data, &mut conn).await {
        Ok(xfer) => match xfer.direction {
            TransferDirection::Upload => scp::run_upload(data, &mut conn, source).await,
            // Download (and any non-upload classification) streams to the sink.
            _ => {
                let mut writer = ClientWriter::with_options(data.set.include_header, false);
                scp::run_download(data, &mut conn, &mut writer, sink).await
            }
        },
        Err(e) => Err(e),
    };

    // Finalize (C `scp_done`) then best-effort session teardown; the transfer
    // result is authoritative, with any finalize error surfaced only when the
    // transfer itself succeeded (`CurlError` is `Copy`).
    let premature = result.is_err();
    let done = scp::done(data, &mut conn, result, premature).await;
    let _ = handler.disconnect(data, &mut conn, result.is_err()).await;
    result.and(done)
}

/// Drive an `sftp://` transfer end-to-end (QA F4-CRIT-3) — the SFTP analog of
/// `ftp::perform_ftp`.
///
/// Builds the plain-TCP connection, brings up + authenticates the SSH session and
/// starts the SFTP subsystem ([`SftpHandler::connect`]), then runs the SFTP DO
/// phase ([`sftp::run_do`]: QUOTE → FILETIME → upload/listing/download) with the
/// caller's client `sink`/`source`, and finalizes via [`sftp::done`] (POSTQUOTE).
#[cfg(feature = "sftp")]
pub(crate) async fn perform_sftp(
    data: &mut Easy,
    sink: &mut dyn WriteCallbacks,
    source: &mut dyn ReadCallback,
) -> Result<()> {
    let handler = SftpHandler;
    let mut conn = build_ssh_connection(data, &SCHEME_SFTP).await?;

    // Per-connection setup then bring up + authenticate the SSH transport and
    // start the SFTP subsystem (C `ssh_setup_connection` + `ssh_connect` +
    // `SSH_SFTP_INIT`/`REALPATH`).
    handler.setup_connection(data, &mut conn).await?;
    handler.connect(data, &mut conn).await?;

    // Drive the SFTP DO phase with the caller's client callbacks (the genuine
    // data plane; `sftp::do_it` is the engine classifier and pumps nothing).
    let result = sftp::run_do(data, &mut conn, sink, source).await;

    // Finalize (C `sftp_done`: POSTQUOTE + close) then best-effort teardown. The
    // transfer result is authoritative; a finalize/POSTQUOTE error is surfaced
    // only when the transfer itself succeeded.
    let premature = result.is_err();
    let done = sftp::done(data, &mut conn, result, premature).await;
    let _ = handler.disconnect(data, &mut conn, result.is_err()).await;
    result.and(done)
}

// ===========================================================================
// Unit tests — the pure, server-independent pieces (the QUOTE-argument parser,
// the RANGE parser, and the host-key fingerprint comparators) factored out so
// they are testable without a live SSH server (AAP §0.8.1 coverage gate). The
// connect/auth state machine and `get_working_path` (which require an `Easy`/
// `Connection` and a live transport) are exercised by the curl 8.x suite in the
// global test phase.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    // ---- get_pathname (≈ C `Curl_get_pathname`) ---------------------------

    #[test]
    fn get_pathname_plain_word() {
        let (path, consumed) = get_pathname("file.txt", "/home").unwrap();
        assert_eq!(path, "file.txt");
        assert_eq!(consumed, 8);
    }

    #[test]
    fn get_pathname_skips_leading_and_trailing_blanks() {
        // `consumed` advances past the trailing whitespace (C `*cpp`).
        let (path, consumed) = get_pathname("  file.txt  ", "/home").unwrap();
        assert_eq!(path, "file.txt");
        assert_eq!(consumed, 12);
    }

    #[test]
    fn get_pathname_two_arguments_rename() {
        // First argument, then continue from `consumed` for the second.
        let (first, consumed) = get_pathname("old new", "/home").unwrap();
        assert_eq!(first, "old");
        assert_eq!(consumed, 4);
        let (second, _) = get_pathname(&"old new"[consumed..], "/home").unwrap();
        assert_eq!(second, "new");
    }

    #[test]
    fn get_pathname_double_quoted_with_space() {
        let (path, consumed) = get_pathname("\"my file\"", "/home").unwrap();
        assert_eq!(path, "my file");
        assert_eq!(consumed, 9);
    }

    #[test]
    fn get_pathname_single_quoted() {
        let (path, _) = get_pathname("'my file'", "/home").unwrap();
        assert_eq!(path, "my file");
    }

    #[test]
    fn get_pathname_quoted_escapes() {
        // \" \' \\ are the only valid escapes; the backslash is dropped.
        let (path, _) = get_pathname("\"a\\\"b\"", "/home").unwrap();
        assert_eq!(path, "a\"b");
        let (path2, _) = get_pathname("\"a\\\\b\"", "/home").unwrap();
        assert_eq!(path2, "a\\b");
    }

    #[test]
    fn get_pathname_home_prefix_substituted() {
        let (path, _) = get_pathname("/~/sub/file", "/home/user").unwrap();
        assert_eq!(path, "/home/user/sub/file");
    }

    #[test]
    fn get_pathname_home_prefix_only() {
        let (path, consumed) = get_pathname("/~/", "/home/user").unwrap();
        assert_eq!(path, "/home/user/");
        assert_eq!(consumed, 3);
    }

    #[test]
    fn get_pathname_errors() {
        assert!(matches!(get_pathname("", "/h"), Err(CurlError::QuoteError)));
        // Unterminated quote.
        assert!(matches!(
            get_pathname("\"abc", "/h"),
            Err(CurlError::QuoteError)
        ));
        // Empty quoted string.
        assert!(matches!(get_pathname("\"\"", "/h"), Err(CurlError::QuoteError)));
        // Invalid escape (\x).
        assert!(matches!(
            get_pathname("\"a\\xb\"", "/h"),
            Err(CurlError::QuoteError)
        ));
        // All-blank input has no path.
        assert!(matches!(get_pathname("   ", "/h"), Err(CurlError::QuoteError)));
    }

    #[test]
    fn get_pathname_too_large() {
        // A bare word longer than MAX_PATHLENGTH maps to TooLarge (C STRE_BIG).
        let big = "a".repeat(MAX_PATHLENGTH + 1);
        assert!(matches!(get_pathname(&big, "/h"), Err(CurlError::TooLarge)));
        // Exactly MAX_PATHLENGTH is accepted.
        let ok = "a".repeat(MAX_PATHLENGTH);
        assert!(get_pathname(&ok, "/h").is_ok());
    }

    // ---- ssh_range (≈ C `Curl_ssh_range`) ---------------------------------

    #[test]
    fn ssh_range_explicit_closed() {
        assert_eq!(ssh_range("0-99", 1000).unwrap(), (0, 100));
        assert_eq!(ssh_range("10-19", 1000).unwrap(), (10, 10));
    }

    #[test]
    fn ssh_range_open_ended_from() {
        // "N-" and a bare "N" both run to the end of the file.
        assert_eq!(ssh_range("10-", 1000).unwrap(), (10, 990));
        assert_eq!(ssh_range("5", 1000).unwrap(), (5, 995));
    }

    #[test]
    fn ssh_range_last_n_bytes() {
        // "-N" is the last N bytes relative to EOF.
        assert_eq!(ssh_range("-100", 1000).unwrap(), (900, 100));
        // Clamped when N exceeds the file size.
        assert_eq!(ssh_range("-5000", 1000).unwrap(), (0, 1000));
    }

    #[test]
    fn ssh_range_clamps_end_to_eof() {
        assert_eq!(ssh_range("0-2000", 1000).unwrap(), (0, 1000));
    }

    #[test]
    fn ssh_range_errors() {
        // "-0" is not a valid range.
        assert!(matches!(ssh_range("-0", 1000), Err(CurlError::RangeError)));
        // Empty / lone dash → no bound parsed.
        assert!(matches!(ssh_range("", 1000), Err(CurlError::RangeError)));
        assert!(matches!(ssh_range("-", 1000), Err(CurlError::RangeError)));
        // Inverted range.
        assert!(matches!(ssh_range("20-10", 1000), Err(CurlError::RangeError)));
        // Offset beyond the file size.
        assert!(matches!(ssh_range("2000-", 1000), Err(CurlError::RangeError)));
        // Trailing garbage.
        assert!(matches!(ssh_range("5x", 1000), Err(CurlError::RangeError)));
    }

    // ---- host-key fingerprint comparators (≈ `ssh_check_fingerprint`) ------

    #[test]
    fn sha256_fingerprint_ignores_padding() {
        assert!(sha256_fingerprint_matches("abc123=", "abc123"));
        assert!(sha256_fingerprint_matches("abc123==", "abc123"));
        assert!(sha256_fingerprint_matches("abc123", "abc123"));
        assert!(!sha256_fingerprint_matches("abc123", "abc124"));
    }

    #[test]
    fn md5_fingerprint_case_insensitive() {
        assert!(md5_fingerprint_matches("AABBCCDD", "aabbccdd"));
        assert!(md5_fingerprint_matches("aabbccdd", "aabbccdd"));
        assert!(!md5_fingerprint_matches("aabb", "aabbccdd"));
        assert!(!md5_fingerprint_matches("aabbccde", "aabbccdd"));
    }

    #[test]
    fn to_hex_lower_formats_bytes() {
        assert_eq!(to_hex_lower(&[0x00, 0x0f, 0xff, 0xa5]), "000fffa5");
        assert_eq!(to_hex_lower(&[]), "");
    }

    #[test]
    fn base64_string_encodes() {
        assert_eq!(base64_string(b"").unwrap(), "");
        assert_eq!(base64_string(b"foo").unwrap(), "Zm9v");
    }
}

