// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.
//
//! In-process `russh`-server integration tests for the SSH stack — the
//! behavioural proof for the three SSH review findings:
//!
//! * **`ssh/mod.rs` #1 (transport):** SFTP/SCP must run over the established
//!   [`crate::conn::Connection`] `FIRSTSOCKET` filter chain, never a raw dial.
//!   Every test here drives the real [`SftpHandler`](super::SftpHandler) /
//!   [`ScpHandler`](super::ScpHandler) `do_it` hook, whose only transport is the
//!   filter chain installed on the [`TransferCtx`]. A [`DuplexFilter`] sits in
//!   that chain counting every byte in each direction, so a passing test proves
//!   the transfer bytes actually traversed the filter layer (the analogue of
//!   traversing a proxy / Happy-Eyeballs / TLS filter).
//! * **`ssh/sftp.rs` (SFTP wiring):** download, listing, upload and filetime
//!   propagation are exercised end-to-end against a real
//!   [`russh_sftp::server`] running over the same channel the client opened.
//! * **`ssh/scp.rs` (SCP byte protocol):** the `scp -t` / `scp -f` exec channel,
//!   the `C<mode> <size> <name>` header, the single-byte acknowledgements and
//!   the body pump are exercised against a hand-written server-side SCP peer.
//!
//! The topology mirrors production exactly. `run_over_chain` bridges the filter
//! chain into an in-memory [`tokio::io::duplex`] whose far half feeds a real
//! `russh` **client**; here the *server* side of a **second** duplex is handed
//! to [`russh::server::run_stream`], and the [`DuplexFilter`] shuttles bytes
//! between the two. Nothing dials a socket, and no external daemon is required
//! (per the AAP's in-process-mock-server test strategy, §0.6.4).
//!
//! The module only compiles when at least one SSH transfer feature is on (it is
//! otherwise dead code under a bare `ssh` build).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{SshAuthTypes, SshScheme, SshSession, SshSetup};
use crate::conn::filters::{CfFuture, FilterCtx, QueryCtx, QueryOut};
use crate::conn::{
    CfQuery, CfType, Connection, ConnectionFilter, FilterChain, Scheme, Transport, FIRSTSOCKET,
};
use crate::error::{CurlCode, Error, Result};
use crate::protocols::{Protocol, TransferCtx, TransferSink};

// ===========================================================================
// Test server key — a throwaway ed25519 OpenSSH key with no passphrase. Fixed
// so the tests are deterministic and need no RNG/keygen at run time.
// ===========================================================================

const SERVER_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB3YnhnX/9X+YbX9Q9kePPSiwBjUF0pavoQJdLKilcy5AAAAJjfnW5F351u
RQAAAAtzc2gtZWQyNTUxOQAAACB3YnhnX/9X+YbX9Q9kePPSiwBjUF0pavoQJdLKilcy5A
AAAEDU0MWSr9LS2dSP2wW4RtL7u5w+rWLgYs6EJZ2N8yH8GHdieGdf/1f5htf1D2R489KL
AGNQXSlq+hAl0sqKVzLkAAAAEGJsaXR6eS1pdC1zZXJ2ZXIBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
";

// ===========================================================================
// Shared, inspectable server state.
// ===========================================================================

/// The bytes the SFTP/SCP test server serves and captures, plus the mtime it
/// reports. Shared (behind an [`Arc`]) between the test, the `russh` handler and
/// the spawned per-channel protocol tasks. Critical sections never span an
/// `.await`, so a plain [`std::sync::Mutex`] keeps every handler future `Send`.
#[derive(Default)]
struct ServerState {
    /// The file body the server streams on a download (SFTP read / SCP `-f`).
    download: Vec<u8>,
    /// The file body the server captured from an upload (SFTP write / SCP `-t`).
    uploaded: Vec<u8>,
    /// The mtime the server reports from `stat`/`fstat` (for `CURLOPT_FILETIME`).
    mtime: u32,
    /// The directory entries the server returns from `readdir`.
    entries: Vec<String>,
}

type SharedState = Arc<Mutex<ServerState>>;

// ===========================================================================
// DuplexFilter — a leaf connection filter that IS the transport under test.
//
// It bridges the connection's filter chain (`chain.send`/`chain.recv`, driven
// by `run_over_chain`'s pump) to one half of an in-memory duplex whose other
// half feeds the in-process `russh` server. Every byte in each direction is
// counted, so a test can assert the SSH transfer really traversed the filter
// chain rather than a raw socket (review finding `ssh/mod.rs` #1).
// ===========================================================================

struct DuplexFilter {
    /// The filter's half of the transport duplex; the `russh` server owns the
    /// other half.
    stream: tokio::io::DuplexStream,
    /// A synthetic file descriptor reported to `CfQuery::Socket`, mirroring the
    /// mock filters in the mail modules.
    fd: i32,
    /// Bytes written toward the server (client → server), proving `send`
    /// traversal.
    sent: Arc<AtomicUsize>,
    /// Bytes read from the server (server → client), proving `recv` traversal.
    recvd: Arc<AtomicUsize>,
}

impl ConnectionFilter for DuplexFilter {
    fn name(&self) -> &'static str {
        "DUPLEX-TEST"
    }

    fn cf_type(&self) -> CfType {
        CfType::IP_CONNECT
    }

    fn connect<'a>(
        &'a mut self,
        _cx: &'a mut FilterCtx<'_>,
        _blocking: bool,
    ) -> CfFuture<'a, Result<bool>> {
        // The in-memory duplex is always "connected"; there is no handshake.
        Box::pin(async { Ok(true) })
    }

    fn send<'a>(
        &'a mut self,
        _cx: &'a mut FilterCtx<'_>,
        buf: &'a [u8],
        _eos: bool,
    ) -> CfFuture<'a, Result<usize>> {
        Box::pin(async move {
            // A single `write` call keeps this cancel-safe: the chain pump may
            // drop a pending branch, and a partial write is completed by the
            // pump's own retry loop.
            let n = self.stream.write(buf).await.map_err(|_| Error::Send)?;
            self.sent.fetch_add(n, Ordering::SeqCst);
            Ok(n)
        })
    }

    fn recv<'a>(
        &'a mut self,
        _cx: &'a mut FilterCtx<'_>,
        buf: &'a mut [u8],
    ) -> CfFuture<'a, Result<usize>> {
        Box::pin(async move {
            // A single cancel-safe `read`; `0` means the server closed its half.
            let n = self.stream.read(buf).await.map_err(|_| Error::Recv)?;
            self.recvd.fetch_add(n, Ordering::SeqCst);
            Ok(n)
        })
    }

    fn data_pending(&self, _cx: &QueryCtx<'_>) -> bool {
        false
    }

    fn query(&self, _cx: &QueryCtx<'_>, query: CfQuery, out: &mut QueryOut) -> Result<()> {
        match query {
            CfQuery::Socket => {
                *out = QueryOut::Socket(self.fd);
                Ok(())
            }
            CfQuery::Transport => {
                *out = QueryOut::Transport(Transport::Tcp);
                Ok(())
            }
            _ => Err(Error::Code(CurlCode::UnknownOption)),
        }
    }
}

/// Byte counters shared with the [`DuplexFilter`] installed in a chain, so a
/// test can assert traversal in each direction.
#[derive(Clone)]
struct Counters {
    sent: Arc<AtomicUsize>,
    recvd: Arc<AtomicUsize>,
}

impl Counters {
    fn new() -> Self {
        Counters {
            sent: Arc::new(AtomicUsize::new(0)),
            recvd: Arc::new(AtomicUsize::new(0)),
        }
    }
}

/// Build a [`Connection`] whose `FIRSTSOCKET` chain is a single
/// [`DuplexFilter`] bridged to `filter_half`, wired with the shared traversal
/// counters.
fn conn_over_filter(
    scheme: &str,
    filter_half: tokio::io::DuplexStream,
    counters: &Counters,
) -> Connection {
    let mut conn = Connection::new(
        Scheme::new(scheme, super::PORT_SSH),
        "127.0.0.1",
        super::PORT_SSH,
    );
    let mut chain = FilterChain::new(FIRSTSOCKET);
    chain.add(Box::new(DuplexFilter {
        stream: filter_half,
        fd: 11,
        sent: Arc::clone(&counters.sent),
        recvd: Arc::clone(&counters.recvd),
    }));
    conn.cfilter[FIRSTSOCKET] = Some(chain);
    conn
}

/// A password-only SSH setup pointing at the in-process test server. Public-key
/// / agent / GSSAPI / keyboard-interactive are disabled so the deterministic
/// password path (which the test server accepts) is exercised.
fn password_setup(scheme: SshScheme) -> SshSetup {
    SshSetup {
        scheme: Some(scheme),
        host: "127.0.0.1".to_string(),
        port: super::PORT_SSH,
        user: Some("tester".to_string()),
        password: Some("s3cr3t".to_string()),
        insecure: true,
        auth_types: SshAuthTypes {
            publickey: false,
            password: true,
            gssapi: false,
            keyboard: false,
            agent: false,
        },
        ..SshSetup::default()
    }
}

// ===========================================================================
// A capturing client write sink (← the `CLIENTWRITE_BODY` callback).
// ===========================================================================

struct VecSink(Arc<Mutex<Vec<u8>>>);

impl TransferSink for VecSink {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        self.0.lock().unwrap().extend_from_slice(data);
        Ok(())
    }
}

// ===========================================================================
// The in-process `russh` server.
//
// It accepts password auth, opens session channels, and — on a `sftp`
// subsystem request or a `scp -t`/`scp -f` exec request — hands the channel's
// byte stream to a spawned protocol task. The spawn is essential: `russh`
// dispatches these handler calls inline on the same task that reads the socket,
// so a handler that awaited the whole sub-protocol would starve the reader and
// deadlock. Returning immediately (after `channel_success`) lets the session
// loop keep pumping channel data to the spawned task.
// ===========================================================================

struct TestSshServer {
    clients: Arc<
        tokio::sync::Mutex<
            std::collections::HashMap<russh::ChannelId, russh::Channel<russh::server::Msg>>,
        >,
    >,
    state: SharedState,
}

impl TestSshServer {
    fn new(state: SharedState) -> Self {
        TestSshServer {
            clients: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            state,
        }
    }

    /// Remove and return the channel stashed by `channel_open_session`.
    async fn take_channel(
        &mut self,
        id: russh::ChannelId,
    ) -> Option<russh::Channel<russh::server::Msg>> {
        self.clients.lock().await.remove(&id)
    }
}

impl russh::server::Handler for TestSshServer {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        _user: &str,
        _password: &str,
    ) -> std::result::Result<russh::server::Auth, Self::Error> {
        Ok(russh::server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        _session: &mut russh::server::Session,
    ) -> std::result::Result<bool, Self::Error> {
        self.clients.lock().await.insert(channel.id(), channel);
        Ok(true)
    }

    async fn subsystem_request(
        &mut self,
        channel_id: russh::ChannelId,
        name: &str,
        session: &mut russh::server::Session,
    ) -> std::result::Result<(), Self::Error> {
        #[cfg(feature = "sftp")]
        if name == "sftp" {
            let channel = self.take_channel(channel_id).await;
            session.channel_success(channel_id)?;
            if let Some(channel) = channel {
                let state = Arc::clone(&self.state);
                tokio::spawn(async move {
                    russh_sftp::server::run(channel.into_stream(), SftpTestServer::new(state))
                        .await;
                });
            }
            return Ok(());
        }
        let _ = name;
        session.channel_failure(channel_id)?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel_id: russh::ChannelId,
        data: &[u8],
        session: &mut russh::server::Session,
    ) -> std::result::Result<(), Self::Error> {
        #[cfg(feature = "scp")]
        {
            let cmd = String::from_utf8_lossy(data);
            if cmd.starts_with("scp ") {
                // `scp -t` = the client uploads (server is the sink); `scp -f` =
                // the client downloads (server is the source).
                let upload = cmd.contains(" -t");
                let channel = self.take_channel(channel_id).await;
                session.channel_success(channel_id)?;
                if let Some(channel) = channel {
                    let state = Arc::clone(&self.state);
                    tokio::spawn(async move {
                        let _ = scp_server_side(channel.into_stream(), upload, state).await;
                    });
                }
                return Ok(());
            }
        }
        let _ = data;
        session.channel_failure(channel_id)?;
        Ok(())
    }
}

/// Spawn the in-process `russh` server on `server_half` (the far end of the
/// transport duplex bridged by the [`DuplexFilter`]).
fn spawn_server(server_half: tokio::io::DuplexStream, state: SharedState) {
    let key = russh::keys::decode_secret_key(SERVER_KEY, None).expect("decode test server key");
    let mut config = russh::server::Config {
        keys: vec![key],
        ..russh::server::Config::default()
    };
    // Keep the rejected initial "none" probe from stalling the test.
    config.auth_rejection_time = std::time::Duration::from_millis(1);
    config.auth_rejection_time_initial = Some(std::time::Duration::from_millis(0));
    let config = Arc::new(config);
    let handler = TestSshServer::new(state);
    tokio::spawn(async move {
        if let Ok(running) = russh::server::run_stream(config, server_half, handler).await {
            let _ = running.await;
        }
    });
}

// ===========================================================================
// The server-side SFTP handler (← the `russh_sftp::server` example template).
// ===========================================================================

#[cfg(feature = "sftp")]
struct SftpTestServer {
    state: SharedState,
    /// Whether the single directory listing has already been returned (so the
    /// second `readdir` reports EOF, as the protocol requires).
    readdir_done: bool,
}

#[cfg(feature = "sftp")]
impl SftpTestServer {
    fn new(state: SharedState) -> Self {
        SftpTestServer {
            state,
            readdir_done: false,
        }
    }

    /// The size + mtime the server reports for the download file.
    fn file_attrs(&self) -> russh_sftp::protocol::FileAttributes {
        let g = self.state.lock().unwrap();
        russh_sftp::protocol::FileAttributes {
            size: Some(g.download.len() as u64),
            mtime: Some(g.mtime),
            permissions: Some(0o100_644),
            ..russh_sftp::protocol::FileAttributes::default()
        }
    }
}

#[cfg(feature = "sftp")]
impl russh_sftp::server::Handler for SftpTestServer {
    type Error = russh_sftp::protocol::StatusCode;

    fn unimplemented(&self) -> Self::Error {
        russh_sftp::protocol::StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: std::collections::HashMap<String, String>,
    ) -> std::result::Result<russh_sftp::protocol::Version, Self::Error> {
        Ok(russh_sftp::protocol::Version::new())
    }

    async fn realpath(
        &mut self,
        id: u32,
        _path: String,
    ) -> std::result::Result<russh_sftp::protocol::Name, Self::Error> {
        // canonicalize(".") resolves the home directory; any absolute answer is
        // fine because the tests use absolute remote paths.
        Ok(russh_sftp::protocol::Name {
            id,
            files: vec![russh_sftp::protocol::File::dummy("/home/tester")],
        })
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        _pflags: russh_sftp::protocol::OpenFlags,
        _attrs: russh_sftp::protocol::FileAttributes,
    ) -> std::result::Result<russh_sftp::protocol::Handle, Self::Error> {
        // Use the path as the opaque handle; the client echoes it back.
        Ok(russh_sftp::protocol::Handle {
            id,
            handle: filename,
        })
    }

    async fn close(
        &mut self,
        id: u32,
        _handle: String,
    ) -> std::result::Result<russh_sftp::protocol::Status, Self::Error> {
        Ok(russh_sftp::protocol::Status {
            id,
            status_code: russh_sftp::protocol::StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    async fn fstat(
        &mut self,
        id: u32,
        _handle: String,
    ) -> std::result::Result<russh_sftp::protocol::Attrs, Self::Error> {
        Ok(russh_sftp::protocol::Attrs {
            id,
            attrs: self.file_attrs(),
        })
    }

    async fn stat(
        &mut self,
        id: u32,
        _path: String,
    ) -> std::result::Result<russh_sftp::protocol::Attrs, Self::Error> {
        Ok(russh_sftp::protocol::Attrs {
            id,
            attrs: self.file_attrs(),
        })
    }

    async fn read(
        &mut self,
        id: u32,
        _handle: String,
        offset: u64,
        len: u32,
    ) -> std::result::Result<russh_sftp::protocol::Data, Self::Error> {
        let g = self.state.lock().unwrap();
        let off = offset as usize;
        if off >= g.download.len() {
            return Err(russh_sftp::protocol::StatusCode::Eof);
        }
        let end = (off + len as usize).min(g.download.len());
        Ok(russh_sftp::protocol::Data {
            id,
            data: g.download[off..end].to_vec(),
        })
    }

    async fn write(
        &mut self,
        id: u32,
        _handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> std::result::Result<russh_sftp::protocol::Status, Self::Error> {
        {
            let mut g = self.state.lock().unwrap();
            let start = offset as usize;
            let end = start + data.len();
            if g.uploaded.len() < end {
                g.uploaded.resize(end, 0);
            }
            g.uploaded[start..end].copy_from_slice(&data);
        }
        Ok(russh_sftp::protocol::Status {
            id,
            status_code: russh_sftp::protocol::StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    async fn opendir(
        &mut self,
        id: u32,
        path: String,
    ) -> std::result::Result<russh_sftp::protocol::Handle, Self::Error> {
        self.readdir_done = false;
        Ok(russh_sftp::protocol::Handle { id, handle: path })
    }

    async fn readdir(
        &mut self,
        id: u32,
        _handle: String,
    ) -> std::result::Result<russh_sftp::protocol::Name, Self::Error> {
        if self.readdir_done {
            return Err(russh_sftp::protocol::StatusCode::Eof);
        }
        self.readdir_done = true;
        let names = self.state.lock().unwrap().entries.clone();
        let files = names
            .into_iter()
            .map(|n| {
                russh_sftp::protocol::File::new(n, russh_sftp::protocol::FileAttributes::default())
            })
            .collect();
        Ok(russh_sftp::protocol::Name { id, files })
    }
}

// ===========================================================================
// The server side of the SCP byte protocol (there is no library for this, so
// it is hand-written to mirror the client in `scp.rs`, exactly as OpenSSH's own
// remote `scp -t`/`scp -f` behaves).
// ===========================================================================

/// Serve one SCP exchange over `stream`. `upload == true` means the client is
/// running `scp -t` (the server is the sink); `false` means `scp -f` (the
/// server is the source).
#[cfg(feature = "scp")]
async fn scp_server_side<S>(mut stream: S, upload: bool, state: SharedState) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if upload {
        // Sink: ready-ack, read header, ack, read body + trailing NUL, final ack.
        stream.write_all(b"\0").await?;
        stream.flush().await?;
        let header = scp_read_line(&mut stream).await?;
        let size = scp_header_size(&header);
        stream.write_all(b"\0").await?;
        stream.flush().await?;
        let mut body = vec![0u8; size];
        stream.read_exact(&mut body).await?;
        let mut nul = [0u8; 1];
        let _ = stream.read_exact(&mut nul).await; // the client's EOF NUL
        stream.write_all(b"\0").await?;
        stream.flush().await?;
        state.lock().unwrap().uploaded = body;
    } else {
        // Source: read the client's start-ack, send header, read header-ack,
        // send body, send trailing NUL.
        let mut ack = [0u8; 1];
        stream.read_exact(&mut ack).await?;
        let content = state.lock().unwrap().download.clone();
        let header = format!("C0644 {} scpfile\n", content.len());
        stream.write_all(header.as_bytes()).await?;
        stream.flush().await?;
        let mut hack = [0u8; 1];
        stream.read_exact(&mut hack).await?;
        stream.write_all(&content).await?;
        stream.write_all(b"\0").await?;
        stream.flush().await?;
        // The client acknowledges the trailing NUL with one more byte.
        let mut fin = [0u8; 1];
        let _ = stream.read(&mut fin).await;
    }
    Ok(())
}

/// Read a `\n`-terminated SCP header line from a server-side stream.
#[cfg(feature = "scp")]
async fn scp_read_line<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<String> {
    let mut out = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 || byte[0] == b'\n' {
            break;
        }
        out.push(byte[0]);
        if out.len() > 4096 {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// Extract the size field from a `C<mode> <size> <name>` header.
#[cfg(feature = "scp")]
fn scp_header_size(header: &str) -> usize {
    header
        .trim_start_matches('C')
        .split(' ')
        .nth(1)
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(0)
}

// ===========================================================================
// SFTP tests (review findings `ssh/sftp.rs` + `ssh/mod.rs` #1).
// ===========================================================================

#[cfg(feature = "sftp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sftp_download_streams_body_over_filter_chain() {
    const BODY: &[u8] = b"the quick brown fox jumps over the lazy dog\n";

    let state: SharedState = Arc::new(Mutex::new(ServerState {
        download: BODY.to_vec(),
        mtime: 1_700_000_000,
        ..ServerState::default()
    }));

    let (filter_half, server_half) = tokio::io::duplex(1 << 20);
    spawn_server(server_half, Arc::clone(&state));

    let counters = Counters::new();
    let conn = conn_over_filter("sftp", filter_half, &counters);

    let mut engine = SshSession::new(password_setup(SshScheme::Sftp));
    engine.proto.path = "/download.txt".to_string();

    let captured = Arc::new(Mutex::new(Vec::new()));
    let mut ctx = TransferCtx::new();
    ctx.conn = Some(Box::new(conn));
    ctx.proto_state = Some(Box::new(engine));
    ctx.sink = Some(Box::new(VecSink(Arc::clone(&captured))));

    let done = super::SFTP_HANDLER
        .do_it(&mut ctx)
        .await
        .expect("SFTP download DO phase");
    assert!(done, "SFTP DO phase should reach SSH_STOP");

    assert_eq!(captured.lock().unwrap().as_slice(), BODY);
    // The transfer must have crossed the filter chain in BOTH directions.
    assert!(
        counters.sent.load(Ordering::SeqCst) > 0,
        "no bytes sent through the filter chain"
    );
    assert!(
        counters.recvd.load(Ordering::SeqCst) > 0,
        "no bytes received through the filter chain"
    );
}

#[cfg(feature = "sftp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sftp_directory_listing_flushes_entries_to_sink() {
    let state: SharedState = Arc::new(Mutex::new(ServerState {
        entries: vec!["alpha.txt".to_string(), "beta.txt".to_string()],
        ..ServerState::default()
    }));

    let (filter_half, server_half) = tokio::io::duplex(1 << 20);
    spawn_server(server_half, Arc::clone(&state));

    let counters = Counters::new();
    let conn = conn_over_filter("sftp", filter_half, &counters);

    let mut engine = SshSession::new(password_setup(SshScheme::Sftp));
    // A trailing '/' selects a directory listing (← SSH_SFTP_TRANS_INIT).
    engine.proto.path = "/dir/".to_string();

    let captured = Arc::new(Mutex::new(Vec::new()));
    let mut ctx = TransferCtx::new();
    ctx.conn = Some(Box::new(conn));
    ctx.proto_state = Some(Box::new(engine));
    ctx.sink = Some(Box::new(VecSink(Arc::clone(&captured))));

    let done = super::SFTP_HANDLER
        .do_it(&mut ctx)
        .await
        .expect("SFTP listing DO phase");
    assert!(done);

    let listing = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    assert!(
        listing.contains("alpha.txt"),
        "listing missing alpha.txt: {listing:?}"
    );
    assert!(
        listing.contains("beta.txt"),
        "listing missing beta.txt: {listing:?}"
    );
    assert!(counters.recvd.load(Ordering::SeqCst) > 0);
}

#[cfg(feature = "sftp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sftp_upload_streams_payload_to_server() {
    const PAYLOAD: &[u8] = b"upload payload bytes 0123456789\n";

    let state: SharedState = Arc::new(Mutex::new(ServerState::default()));

    let (filter_half, server_half) = tokio::io::duplex(1 << 20);
    spawn_server(server_half, Arc::clone(&state));

    let counters = Counters::new();
    let conn = conn_over_filter("sftp", filter_half, &counters);

    let mut engine = SshSession::new(password_setup(SshScheme::Sftp));
    engine.proto.path = "/upload.txt".to_string();

    let mut ctx = TransferCtx::new();
    ctx.conn = Some(Box::new(conn));
    ctx.proto_state = Some(Box::new(engine));
    ctx.request.upload = true;
    ctx.request.body = Some(PAYLOAD.to_vec());

    let done = super::SFTP_HANDLER
        .do_it(&mut ctx)
        .await
        .expect("SFTP upload DO phase");
    assert!(done);

    assert_eq!(state.lock().unwrap().uploaded.as_slice(), PAYLOAD);
    assert!(counters.sent.load(Ordering::SeqCst) > 0);
}

#[cfg(feature = "sftp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sftp_filetime_is_propagated_from_stat() {
    // `CURLOPT_FILETIME` is a set-only option the shared `TransferRequest` does
    // not carry, so it is set directly on the engine (exactly where the setopt
    // layer drives it), then the whole session is run over the filter chain.
    const MTIME: u32 = 1_699_999_123;
    const BODY: &[u8] = b"filetime body\n";

    let state: SharedState = Arc::new(Mutex::new(ServerState {
        download: BODY.to_vec(),
        mtime: MTIME,
        ..ServerState::default()
    }));

    let (filter_half, server_half) = tokio::io::duplex(1 << 20);
    spawn_server(server_half, Arc::clone(&state));

    let counters = Counters::new();
    let mut conn = conn_over_filter("sftp", filter_half, &counters);

    let mut engine = SshSession::new(password_setup(SshScheme::Sftp));
    engine.proto.path = "/timed.txt".to_string();
    engine.req.get_filetime = true;
    let captured = Arc::new(Mutex::new(Vec::new()));
    engine.sink = Some(Box::new(VecSink(Arc::clone(&captured))));

    let chain = conn.cfilter[FIRSTSOCKET].as_mut().unwrap();
    engine
        .run_over_chain(chain)
        .await
        .expect("SFTP filetime run over chain");

    assert_eq!(engine.filetime, Some(i64::from(MTIME)));
    assert_eq!(captured.lock().unwrap().as_slice(), BODY);
}

// ===========================================================================
// SCP tests (review findings `ssh/scp.rs` + `ssh/mod.rs` #1).
// ===========================================================================

#[cfg(feature = "scp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scp_download_streams_body_over_filter_chain() {
    const BODY: &[u8] = b"scp download payload \x00\x01\x02 with binary\n";

    let state: SharedState = Arc::new(Mutex::new(ServerState {
        download: BODY.to_vec(),
        ..ServerState::default()
    }));

    let (filter_half, server_half) = tokio::io::duplex(1 << 20);
    spawn_server(server_half, Arc::clone(&state));

    let counters = Counters::new();
    let conn = conn_over_filter("scp", filter_half, &counters);

    let mut engine = SshSession::new(password_setup(SshScheme::Scp));
    engine.proto.path = "/scp-download.bin".to_string();

    let captured = Arc::new(Mutex::new(Vec::new()));
    let mut ctx = TransferCtx::new();
    ctx.conn = Some(Box::new(conn));
    ctx.proto_state = Some(Box::new(engine));
    ctx.sink = Some(Box::new(VecSink(Arc::clone(&captured))));

    let done = super::SCP_HANDLER
        .do_it(&mut ctx)
        .await
        .expect("SCP download DO phase");
    assert!(done);

    assert_eq!(captured.lock().unwrap().as_slice(), BODY);
    assert!(counters.sent.load(Ordering::SeqCst) > 0);
    assert!(counters.recvd.load(Ordering::SeqCst) > 0);
}

#[cfg(feature = "scp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scp_upload_streams_payload_to_server() {
    const PAYLOAD: &[u8] = b"scp upload body \x00 with a NUL and more\n";

    let state: SharedState = Arc::new(Mutex::new(ServerState::default()));

    let (filter_half, server_half) = tokio::io::duplex(1 << 20);
    spawn_server(server_half, Arc::clone(&state));

    let counters = Counters::new();
    let conn = conn_over_filter("scp", filter_half, &counters);

    let mut engine = SshSession::new(password_setup(SshScheme::Scp));
    engine.proto.path = "/scp-upload.bin".to_string();

    let mut ctx = TransferCtx::new();
    ctx.conn = Some(Box::new(conn));
    ctx.proto_state = Some(Box::new(engine));
    ctx.request.upload = true;
    ctx.request.body = Some(PAYLOAD.to_vec());

    let done = super::SCP_HANDLER
        .do_it(&mut ctx)
        .await
        .expect("SCP upload DO phase");
    assert!(done);

    assert_eq!(state.lock().unwrap().uploaded.as_slice(), PAYLOAD);
    assert!(counters.sent.load(Ordering::SeqCst) > 0);
}
