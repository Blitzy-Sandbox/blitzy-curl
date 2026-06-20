//! SCP protocol engine — single-file transfer over an `russh` **exec** channel.
//!
//! This is the Rust analog of the SCP code paths in the C oracle
//! `lib/vssh/libssh2.c` (`ssh_state_scp_download_init` L2231,
//! `ssh_state_scp_upload_init` L2376, the `SSH_SCP_DONE` → `SEND_EOF` →
//! `WAIT_EOF` → `WAIT_CLOSE` → `CHANNEL_FREE` teardown, and the `scp_send` /
//! `scp_recv` data plane L3539). The C build delegates the wire protocol to
//! libssh2 (`libssh2_scp_recv2` / `libssh2_scp_send64`); `russh` ships **no**
//! SCP helper, so this module opens an SSH **session channel**, `exec`s the
//! remote `scp` command (`scp -f <path>` to download, `scp -t <path>` to
//! upload), and drives the classic **rcp / SCP source–sink protocol** by hand.
//!
//! # Wire protocol (rcp source ↔ sink)
//!
//! The side **receiving** data is the *sink*; the side **sending** data is the
//! *source*. The sink emits acknowledgement bytes; the source emits a control
//! line, the file payload, and a trailing status byte:
//!
//! * **Acknowledgement** — a single `0x00` (OK), or `0x01 <msg>\n` (warning) /
//!   `0x02 <msg>\n` (fatal error).
//! * **Control line** (terminated by `\n`): `C<mode> <size> <name>` (a file),
//!   `T<mtime> 0 <atime> 0` (timestamps, acked and skipped), `D<mode> 0 <name>`
//!   / `E` (directory start/end — recursive mode only, unsupported here), or an
//!   `0x01`/`0x02` message.
//!
//! When we **download** (`scp -f`) we are the *sink*: send `0x00`, read the
//! control line, ack it, read exactly `size` payload bytes, read the source's
//! trailing status, then send a final `0x00`. When we **upload** (`scp -t`) we
//! are the *source*: wait for the sink's `0x00`, send the `C…` control line,
//! wait for the ack, send exactly `infilesize` payload bytes, send a trailing
//! `0x00`, then wait for the final ack.
//!
//! # Architecture notes
//!
//! * **Data plane is the exec channel, never the connection socket.** SCP file
//!   bytes flow over the `russh` exec channel; the connection filter chain
//!   (`FIRSTSOCKET`) carries the *encrypted SSH transport* owned by `russh`.
//!   This mirrors the C handler overriding `conn->recv[FIRSTSOCKET]` /
//!   `conn->send[FIRSTSOCKET]` with `scp_recv` / `scp_send` (libssh2.c L3539).
//! * **The channel cannot persist between [`do_it`] and the data plane.** The
//!   connection has a single `proto_state` slot (already holding the
//!   [`SshConn`]), [`ScpHandler`](super::ScpHandler) is zero-sized, and
//!   [`ProtocolTransfer`] is a descriptor with no stream field, so the entire
//!   SCP exchange (open → exec → negotiate → transfer → teardown) runs inside
//!   [`run_download`] / [`run_upload`] with the channel owned as a local. This
//!   mirrors `mqtt.rs`'s deferred `run_subscription` receive loop. [`do_it`]
//!   only decides direction, validates the upload size, and returns the
//!   [`ProtocolTransfer`] descriptor.
//! * **No `unsafe`.** All raw-pointer handling lives in `curl-rs-ffi`; the
//!   `#![forbid(unsafe_code)]` attribute is inherited from the crate root and
//!   `protocols/mod.rs` and is deliberately not repeated here.

use bytes::Bytes;

use super::{get_working_path, map_ssh_err, SshConn};
use crate::conn::Connection;
use crate::easy::Easy;
use crate::error::{CurlError, Result};
use crate::protocols::{ProtocolTransfer, TransferDirection};
use crate::setopt::HttpReq;
use crate::transfer::{
    ClientWriteType, ClientWriter, ReadCallback, ReadStep, UploadReader, WriteCallbacks,
};
use crate::util::sendf::{failf, infof};

// ===========================================================================
// Protocol constants
// ===========================================================================

/// rcp acknowledgement / status byte: success.
const SCP_OK: u8 = 0x00;
/// rcp control byte: a *warning* message (text follows up to `\n`); non-fatal.
const SCP_WARN: u8 = 0x01;
/// rcp control byte: a *fatal* error message (text follows up to `\n`).
const SCP_FATAL: u8 = 0x02;

/// Default file mode for an upload control line when `CURLOPT_NEW_FILE_PERMS`
/// is unset (curl's `data->set.new_file_perms` default, `0644`).
const DEFAULT_FILE_PERMS: u32 = 0o644;

/// Scratch-buffer size for streaming payload bytes to/from the channel. Matches
/// the order of magnitude of curl's transfer buffer; bytes are delivered in
/// whatever chunk sizes the channel and this buffer produce.
const SCP_XFER_CHUNK: usize = 16 * 1024;

// ===========================================================================
// Pure helpers (no I/O — the unit-test core)
// ===========================================================================

/// POSIX single-quote the remote path so it can be interpolated safely into the
/// remote shell command (`scp -f -- '<path>'`).
///
/// Every character except `'` is preserved verbatim inside the surrounding
/// single quotes; an embedded `'` is rendered as the classic `'\''` sequence
/// (close-quote, escaped quote, reopen-quote). This makes injection of shell
/// metacharacters impossible regardless of the path contents.
fn shell_quote(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 2);
    out.push('\'');
    for ch in path.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Build the remote `scp` command to `exec` over the SSH session.
///
/// * **download** (`upload == false`) → `scp -f -- '<path>'` (remote is the
///   *source*; it sends the file to us, the sink).
/// * **upload** (`upload == true`) → `scp -t -- '<path>'` (remote is the
///   *sink*; it receives the file from us, the source).
///
/// The `--` terminates option parsing so a path beginning with `-` is never
/// mistaken for a flag, and the path is [`shell_quote`]d.
fn build_scp_command(upload: bool, path: &str) -> String {
    let mode = if upload { "-t" } else { "-f" };
    format!("scp {mode} -- {}", shell_quote(path))
}

/// The final path component (everything after the last `/`), used as the
/// `<name>` field of an upload control line. Returns the whole string when there
/// is no `/`, and an empty string when the path ends in `/` (the caller treats
/// that as a missing destination file name).
fn basename(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some((_, name)) => name,
        None => path,
    }
}

/// Format a file mode as the 4-digit octal string used in an SCP `C` control
/// line (e.g. `0o644` → `"0644"`), masking to the permission/sticky bits.
fn format_mode(mode: u32) -> String {
    format!("{:04o}", mode & 0o7777)
}

/// Build an upload control line: `C<mode> <size> <name>\n` (e.g.
/// `b"C0644 1234 file.txt\n"`). Mirrors the line `libssh2_scp_send64` emits.
fn build_upload_control_line(mode: u32, size: u64, name: &str) -> Vec<u8> {
    let mut line = Vec::with_capacity(name.len() + 16);
    line.push(b'C');
    line.extend_from_slice(format_mode(mode).as_bytes());
    line.push(b' ');
    line.extend_from_slice(size.to_string().as_bytes());
    line.push(b' ');
    line.extend_from_slice(name.as_bytes());
    line.push(b'\n');
    line
}

// ===========================================================================
// Control-line classification
// ===========================================================================

/// A parsed SCP control line (the source → sink protocol messages).
#[derive(Debug, Clone, PartialEq, Eq)]
enum ScpControl {
    /// `C<mode> <size> <name>` — a regular file to transfer.
    File { mode: u32, size: u64, name: String },
    /// `T<mtime> 0 <atime> 0` — file timestamps preceding a `C`/`D` line; the
    /// sink must ack it and read the next line.
    Time,
    /// `D<mode> 0 <name>` — start of a directory (recursive transfers only).
    StartDir,
    /// `E` — end of a directory (recursive transfers only).
    EndDir,
    /// `0x01 <msg>` — a non-fatal warning from the peer.
    Warning(String),
    /// `0x02 <msg>` — a fatal error from the peer.
    Fatal(String),
}

/// Parse one control line (the bytes **before** the terminating `\n`) into an
/// [`ScpControl`]. A malformed or empty line is a generic SSH protocol error
/// ([`CurlError::Ssh`]); the caller decides whether to remap it (e.g. a fatal
/// `0x02` on download becomes [`CurlError::RemoteFileNotFound`], matching the C
/// `LIBSSH2_ERROR_SCP_PROTOCOL` → `CURLE_REMOTE_FILE_NOT_FOUND` mapping).
fn parse_control_line(line: &[u8]) -> Result<ScpControl> {
    let Some((&first, rest)) = line.split_first() else {
        // An empty control line is never valid.
        return Err(CurlError::Ssh);
    };
    match first {
        b'C' => {
            let text = std::str::from_utf8(rest).map_err(|_| CurlError::Ssh)?;
            // `splitn(3, ' ')` keeps the (possibly space-containing) file name
            // as the final field, exactly as the rcp protocol allows.
            let mut it = text.splitn(3, ' ');
            let mode_s = it.next().unwrap_or("");
            let size_s = it.next().ok_or(CurlError::Ssh)?;
            let name = it.next().ok_or(CurlError::Ssh)?;
            if mode_s.is_empty() || name.is_empty() {
                return Err(CurlError::Ssh);
            }
            let mode = u32::from_str_radix(mode_s, 8).map_err(|_| CurlError::Ssh)?;
            let size = size_s.parse::<u64>().map_err(|_| CurlError::Ssh)?;
            Ok(ScpControl::File {
                mode,
                size,
                name: name.to_string(),
            })
        }
        b'D' => Ok(ScpControl::StartDir),
        b'E' => Ok(ScpControl::EndDir),
        b'T' => Ok(ScpControl::Time),
        SCP_WARN => Ok(ScpControl::Warning(
            String::from_utf8_lossy(rest).into_owned(),
        )),
        SCP_FATAL => Ok(ScpControl::Fatal(
            String::from_utf8_lossy(rest).into_owned(),
        )),
        _ => Err(CurlError::Ssh),
    }
}

/// The outcome of reading an acknowledgement byte from the peer.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Ack {
    /// `0x00` — success.
    Ok,
    /// `0x01 <msg>` — a non-fatal warning (the message is logged; we proceed).
    Warning(String),
    /// `0x02 <msg>` — a fatal error (the message is recorded; we abort).
    Fatal(String),
}

// ===========================================================================
// Diagnostics sink (decouples the framing logic from `Easy`/`Connection`)
// ===========================================================================

/// Diagnostic sink used by the framing logic, so [`ScpSession`] stays decoupled
/// from the concrete `Easy`/`Connection` types and is unit-testable with a mock.
///
/// * [`info`](ScpReporter::info) mirrors curl's `infof` (verbose-only log).
/// * [`fail`](ScpReporter::fail) mirrors curl's `failf` (records the first
///   failure into the error buffer and always logs).
// `Send` is required so the SCP data-plane futures (`run_download`/`run_upload`),
// which hold a `&mut dyn ScpReporter` across `.await`s, stay `Send` — the
// transfer engine drives them from `perform_transfer`, whose future is spawned
// on the multi-thread Multi runtime (`Handle::spawn` requires `Send`). The only
// implementor, `ConnReporter`, is `Send` (it holds `&mut Option<String>` + a
// `bool`).
trait ScpReporter: Send {
    /// Emit a verbose informational diagnostic.
    fn info(&mut self, msg: &str);
    /// Record and emit a failure diagnostic.
    fn fail(&mut self, msg: &str);
}

/// The production [`ScpReporter`]: routes to [`crate::util::sendf`] using the
/// handle's verbose flag and the connection's error-buffer slot.
struct ConnReporter<'a> {
    /// `CURLOPT_VERBOSE` — gates [`info`](ScpReporter::info).
    verbose: bool,
    /// The `CURLOPT_ERRORBUFFER`-backed slot (`conn.filter_data.error_buffer`).
    error_buffer: &'a mut Option<String>,
}

impl ScpReporter for ConnReporter<'_> {
    fn info(&mut self, msg: &str) {
        infof(self.verbose, msg);
    }

    fn fail(&mut self, msg: &str) {
        failf(self.error_buffer, msg);
    }
}

// ===========================================================================
// Channel abstraction (mockable byte transport over the russh exec channel)
// ===========================================================================

/// The bidirectional byte channel the SCP framing runs over — the `russh` exec
/// channel in production ([`RusshChannelAdapter`]), an in-memory script in
/// tests. Modeled on the libssh2 channel read/write/EOF/close primitives the C
/// SCP code uses (`libssh2_channel_read`/`_write`/`_send_eof`/`_free`).
///
/// `async fn` in a private, never-`dyn` trait: the lint that warns the returned
/// future carries no `Send` bound is irrelevant here (these are only ever
/// awaited from the non-`Send` `run_*` data-plane functions, exactly as
/// `mqtt.rs`'s `run_subscription` is non-`Send`), so it is silenced locally.
#[allow(async_fn_in_trait)]
trait ScpChannel {
    /// Read the next chunk of channel data, or `None` at end of stream
    /// (channel EOF/close). Stderr (`ExtendedData`) is skipped.
    async fn read_chunk(&mut self) -> Result<Option<Vec<u8>>>;
    /// Write all of `data` to the channel (data-plane send).
    async fn write_all(&mut self, data: &[u8]) -> Result<()>;
    /// Send channel EOF (C `libssh2_channel_send_eof`).
    async fn send_eof(&mut self) -> Result<()>;
    /// Drain inbound messages until EOF/close is observed (C
    /// `libssh2_channel_wait_eof` + `_wait_closed`).
    async fn drain(&mut self) -> Result<()>;
    /// Close the channel (C `libssh2_channel_free`).
    async fn close(&mut self) -> Result<()>;
}

/// Concrete [`ScpChannel`] backed by a live `russh` client exec channel.
struct RusshChannelAdapter {
    /// The opened-and-`exec`ed session channel carrying the SCP stream.
    channel: russh::Channel<russh::client::Msg>,
    /// Set once [`close`](ScpChannel::close) has run, so teardown is idempotent.
    closed: bool,
}

impl RusshChannelAdapter {
    /// Wrap a freshly opened (and `exec`ed) russh channel.
    fn new(channel: russh::Channel<russh::client::Msg>) -> Self {
        Self {
            channel,
            closed: false,
        }
    }
}

impl ScpChannel for RusshChannelAdapter {
    async fn read_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        // Pull messages until we get payload data or reach end of stream.
        loop {
            match self.channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => return Ok(Some(data.to_vec())),
                // Remote stderr — not part of the SCP byte stream; skip it. SCP
                // surfaces errors in-band via the `0x01`/`0x02` framing instead.
                Some(russh::ChannelMsg::ExtendedData { .. }) => continue,
                // End of the data stream.
                Some(russh::ChannelMsg::Eof | russh::ChannelMsg::Close) | None => return Ok(None),
                // The remote command's exit status / window updates / other
                // control messages: ignore and keep waiting for payload or EOF.
                Some(_) => continue,
            }
        }
    }

    async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        // `russh` `data_bytes` queues the whole buffer; honor the channel's
        // flow control internally. An empty write is a no-op.
        if data.is_empty() {
            return Ok(());
        }
        self.channel
            .data_bytes(Bytes::copy_from_slice(data))
            .await
            .map_err(map_ssh_err)
    }

    async fn send_eof(&mut self) -> Result<()> {
        self.channel.eof().await.map_err(map_ssh_err)
    }

    async fn drain(&mut self) -> Result<()> {
        loop {
            match self.channel.wait().await {
                Some(russh::ChannelMsg::Eof | russh::ChannelMsg::Close) | None => return Ok(()),
                Some(_) => continue,
            }
        }
    }

    async fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.channel.close().await.map_err(map_ssh_err)
    }
}

// ===========================================================================
// SCP session — the rcp source/sink framing engine over an `ScpChannel`
// ===========================================================================

/// The metadata of the file announced by a download `C` control line.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ScpFileMeta {
    /// The file mode (permission bits) parsed from the control line.
    mode: u32,
    /// The exact payload length in bytes (the engine reads exactly this many).
    size: u64,
    /// The file name from the control line.
    name: String,
}

/// Drives the rcp/SCP source–sink protocol over an [`ScpChannel`], with an
/// internal read buffer so byte-exact framing is possible without ever reading
/// past a file's payload (the trailing status byte must not be consumed as
/// payload). Generic over the channel so the framing is unit-tested against a
/// mock with no SSH server.
struct ScpSession<C: ScpChannel> {
    /// The underlying byte channel (russh exec channel or mock).
    chan: C,
    /// Bytes read from the channel but not yet consumed by the framing logic.
    rbuf: Vec<u8>,
    /// Read cursor into [`rbuf`](Self::rbuf).
    rpos: usize,
}

impl<C: ScpChannel> ScpSession<C> {
    /// Wrap a channel in a fresh session with an empty read buffer.
    fn new(chan: C) -> Self {
        Self {
            chan,
            rbuf: Vec::new(),
            rpos: 0,
        }
    }

    /// The bytes currently buffered and not yet consumed.
    fn available(&self) -> &[u8] {
        &self.rbuf[self.rpos..]
    }

    /// Mark `n` buffered bytes consumed, resetting the buffer when drained.
    fn consume(&mut self, n: usize) {
        self.rpos += n;
        if self.rpos >= self.rbuf.len() {
            self.rbuf.clear();
            self.rpos = 0;
        }
    }

    /// Ensure at least one byte is buffered, fetching the next non-empty channel
    /// chunk if the buffer is empty. Returns `false` at end of stream.
    async fn fill(&mut self) -> Result<bool> {
        if self.rpos < self.rbuf.len() {
            return Ok(true);
        }
        self.rbuf.clear();
        self.rpos = 0;
        loop {
            match self.chan.read_chunk().await? {
                Some(chunk) => {
                    if chunk.is_empty() {
                        continue;
                    }
                    self.rbuf = chunk;
                    return Ok(true);
                }
                None => return Ok(false),
            }
        }
    }

    /// Read exactly one protocol byte; an EOF here is an unexpected truncation.
    async fn next_byte(&mut self) -> Result<u8> {
        if !self.fill().await? {
            return Err(CurlError::RecvError);
        }
        let b = self.available()[0];
        self.consume(1);
        Ok(b)
    }

    /// Read up to and including the next `\n`, returning the bytes **before** it.
    /// An EOF before the terminator is a protocol truncation.
    async fn read_until_lf(&mut self) -> Result<Vec<u8>> {
        let mut line = Vec::new();
        loop {
            if !self.fill().await? {
                return Err(CurlError::RecvError);
            }
            let avail = self.available();
            if let Some(idx) = avail.iter().position(|&b| b == b'\n') {
                line.extend_from_slice(&avail[..idx]);
                self.consume(idx + 1); // also drop the '\n'
                return Ok(line);
            }
            let n = avail.len();
            line.extend_from_slice(avail);
            self.consume(n);
        }
    }

    /// Read and parse one control line.
    async fn read_control(&mut self) -> Result<ScpControl> {
        let line = self.read_until_lf().await?;
        parse_control_line(&line)
    }

    /// Read an acknowledgement byte (and any trailing warning/fatal message).
    async fn read_ack(&mut self) -> Result<Ack> {
        let b = self.next_byte().await?;
        match b {
            SCP_OK => Ok(Ack::Ok),
            SCP_WARN => {
                let msg = self.read_until_lf().await?;
                Ok(Ack::Warning(String::from_utf8_lossy(&msg).into_owned()))
            }
            SCP_FATAL => {
                let msg = self.read_until_lf().await?;
                Ok(Ack::Fatal(String::from_utf8_lossy(&msg).into_owned()))
            }
            // Any other byte is an out-of-protocol acknowledgement.
            _ => Err(CurlError::Ssh),
        }
    }

    /// Send a single acknowledgement/status byte.
    async fn send_byte(&mut self, b: u8) -> Result<()> {
        self.chan.write_all(&[b]).await
    }

    /// Map an [`Ack`] to a `Result`, logging warnings and recording fatals.
    fn classify_ack(ack: Ack, reporter: &mut dyn ScpReporter) -> Result<()> {
        match ack {
            Ack::Ok => Ok(()),
            Ack::Warning(msg) => {
                reporter.info(&format!("scp: {msg}"));
                Ok(())
            }
            Ack::Fatal(msg) => {
                reporter.fail(&msg);
                Err(CurlError::Ssh)
            }
        }
    }

    /// Read an ack and require success (warnings are logged and tolerated).
    async fn expect_ack(&mut self, reporter: &mut dyn ScpReporter) -> Result<()> {
        let ack = self.read_ack().await?;
        Self::classify_ack(ack, reporter)
    }

    /// DOWNLOAD negotiation (`scp -f`; we are the sink). Sends the initial
    /// ready byte, reads control lines (acking `T` timestamp lines and skipping
    /// warnings) until the file `C` line arrives, acks it, and returns the
    /// announced file metadata. A fatal message maps to
    /// [`CurlError::RemoteFileNotFound`]; a directory line is unsupported.
    async fn negotiate_download(&mut self, reporter: &mut dyn ScpReporter) -> Result<ScpFileMeta> {
        // Tell the source we are ready to receive.
        self.send_byte(SCP_OK).await?;
        loop {
            match self.read_control().await? {
                ScpControl::File { mode, size, name } => {
                    // Ack the header; the payload follows immediately.
                    self.send_byte(SCP_OK).await?;
                    return Ok(ScpFileMeta { mode, size, name });
                }
                ScpControl::Time => {
                    // Timestamps precede the file header; ack and continue.
                    self.send_byte(SCP_OK).await?;
                }
                ScpControl::Warning(msg) => {
                    reporter.info(&format!("scp: {msg}"));
                }
                ScpControl::Fatal(msg) => {
                    reporter.fail(&msg);
                    return Err(CurlError::RemoteFileNotFound);
                }
                ScpControl::StartDir | ScpControl::EndDir => {
                    reporter.fail("scp: directory transfer is not supported (single-file only)");
                    return Err(CurlError::Ssh);
                }
            }
        }
    }

    /// DOWNLOAD data plane (≈ `scp_recv`). Reads exactly `size` payload bytes,
    /// handing each chunk to `deliver`, then consumes the source's trailing
    /// status byte and sends the sink's final ack. Never reads past `size`.
    async fn recv_body<F>(
        &mut self,
        size: u64,
        reporter: &mut dyn ScpReporter,
        mut deliver: F,
    ) -> Result<()>
    where
        F: FnMut(&[u8]) -> Result<()>,
    {
        let mut remaining = size;
        while remaining > 0 {
            if !self.fill().await? {
                reporter.fail("scp: connection closed before the file was fully received");
                return Err(CurlError::PartialFile);
            }
            let avail = self.available();
            // Clamp to `remaining` so the trailing status byte is never read as
            // payload.
            let cap = usize::try_from(remaining).unwrap_or(usize::MAX);
            let take = avail.len().min(cap);
            deliver(&avail[..take])?;
            self.consume(take);
            remaining -= take as u64;
        }
        // The source sends a status byte once the payload is complete.
        let ack = self.read_ack().await?;
        Self::classify_ack(ack, reporter)?;
        // Sink's final acknowledgement.
        self.send_byte(SCP_OK).await
    }

    /// UPLOAD negotiation (`scp -t`; we are the source). Waits for the sink's
    /// readiness ack, sends the `C<mode> <size> <name>` header, and waits for
    /// the sink to ack it.
    async fn negotiate_upload(
        &mut self,
        mode: u32,
        size: u64,
        name: &str,
        reporter: &mut dyn ScpReporter,
    ) -> Result<()> {
        // Sink must signal readiness first.
        self.expect_ack(reporter).await?;
        // Send the file header line.
        let line = build_upload_control_line(mode, size, name);
        self.chan.write_all(&line).await?;
        // Sink acks the header.
        self.expect_ack(reporter).await
    }

    /// UPLOAD data plane (≈ `scp_send`). Pulls exactly `size` payload bytes via
    /// `fill` (which returns the count written into the scratch buffer, `0` at
    /// source EOF), writes them to the channel, then sends the trailing success
    /// byte and waits for the sink's final ack. A source that ends early is a
    /// [`CurlError::PartialFile`].
    async fn send_body<F>(
        &mut self,
        size: u64,
        reporter: &mut dyn ScpReporter,
        mut fill: F,
    ) -> Result<()>
    where
        F: FnMut(&mut [u8]) -> Result<usize>,
    {
        let mut scratch = vec![0u8; SCP_XFER_CHUNK];
        let mut remaining = size;
        while remaining > 0 {
            let cap = usize::try_from(remaining).unwrap_or(usize::MAX);
            let want = scratch.len().min(cap);
            let n = fill(&mut scratch[..want])?;
            if n == 0 {
                reporter.fail("scp: local source ended before the announced size");
                return Err(CurlError::PartialFile);
            }
            self.chan.write_all(&scratch[..n]).await?;
            remaining -= n as u64;
        }
        // Trailing success status, then the sink's final ack.
        self.send_byte(SCP_OK).await?;
        self.expect_ack(reporter).await
    }

    /// SCP teardown (≈ the C `SSH_SCP_DONE` → `SEND_EOF` → `WAIT_EOF` →
    /// `WAIT_CLOSE` → `CHANNEL_FREE` sequence). On **upload** we send EOF and
    /// wait for the peer's EOF/close before freeing the channel; on **download**
    /// the C oracle goes straight to channel-free. Every step is best-effort:
    /// failures are logged but never made fatal (matching libssh2.c).
    async fn teardown(&mut self, upload: bool, reporter: &mut dyn ScpReporter) {
        if upload {
            if let Err(e) = self.chan.send_eof().await {
                reporter.info(&format!("scp: failed to send channel EOF: {e}"));
            }
            if let Err(e) = self.chan.drain().await {
                reporter.info(&format!("scp: failed waiting for channel EOF/close: {e}"));
            }
        }
        if let Err(e) = self.chan.close().await {
            reporter.info(&format!("scp: failed to close channel: {e}"));
        }
    }
}

// ===========================================================================
// Channel open helper + error remap
// ===========================================================================

/// Open a session channel on the connection's authenticated `russh` session and
/// `exec` the SCP `cmd`. The returned channel is owned, so the caller regains
/// access to `conn` (e.g. for diagnostics) afterwards.
///
/// `conn` is taken by **mutable** reference and the session handle is reached by
/// `&mut` (`proto_state_mut` → `&mut SshConn` → `&mut Handle`). This is what
/// keeps the future `Send` for the multi-thread Multi runtime: `&mut Connection`,
/// `&mut SshConn`, and `&mut Handle` are all `Send` (their referents are `Send`),
/// and `channel_open_session(&self)` reborrows to a `&Handle`, which is `Send`
/// because `russh`'s `Handle` is `Sync` (its tokio mpsc `Sender`/`Receiver` are
/// `Send + Sync`). A captured **shared** `&Connection` would instead be `!Send`
/// (because `Connection` is `!Sync`) and would poison the whole transfer future.
async fn open_exec_channel(
    conn: &mut Connection,
    cmd: &str,
) -> Result<russh::Channel<russh::client::Msg>> {
    let channel = {
        let sshc = conn.proto_state_mut::<SshConn>().ok_or(CurlError::Ssh)?;
        let handle = sshc.handle.as_mut().ok_or(CurlError::Ssh)?;
        handle.channel_open_session().await.map_err(map_ssh_err)?
    };
    channel
        .exec(true, cmd.as_bytes().to_vec())
        .await
        .map_err(map_ssh_err)?;
    Ok(channel)
}

/// Remap upload-start errors exactly as the C `scp_upload_init`: a generic SSH
/// failure or a "remote file not found" becomes [`CurlError::UploadFailed`];
/// every other error passes through unchanged.
fn remap_upload_error(e: CurlError) -> CurlError {
    match e {
        CurlError::Ssh | CurlError::RemoteFileNotFound => CurlError::UploadFailed,
        other => other,
    }
}

// ===========================================================================
// Protocol entry points (called by `ScpHandler` in `ssh/mod.rs`)
// ===========================================================================

/// C `ssh_do` → `scp_perform`'s DO phase. Decides the transfer direction,
/// validates the upload size up front (the SCP `C` control line carries the
/// length, so an unknown size cannot be uploaded), and returns the
/// [`ProtocolTransfer`] descriptor for the engine.
///
/// The exec channel cannot be persisted between here and the data plane (the
/// connection's single `proto_state` slot already holds the [`SshConn`], the
/// handler is zero-sized, and [`ProtocolTransfer`] has no stream field), so the
/// channel open, the wire handshake, the payload transfer, and the teardown all
/// happen in [`run_download`] / [`run_upload`]. Consequently the download size
/// is reported as unknown here and learned during [`run_download`].
pub(super) async fn do_it(data: &mut Easy, conn: &mut Connection) -> Result<ProtocolTransfer> {
    let verbose = data.set.verbose;
    let upload = data.set.method == HttpReq::Put;

    if upload {
        let infilesize = data.set.filesize;
        if infilesize < 0 {
            // C `scp_upload_init` requires `data->state.infilesize`; an unknown
            // size maps to CURLE_UPLOAD_FAILED.
            crate::failf!(
                &mut conn.filter_data.error_buffer,
                "SCP upload requires a known file size (set CURLOPT_INFILESIZE)"
            );
            return Err(CurlError::UploadFailed);
        }
        let size = infilesize as u64;
        crate::infof!(verbose, "scp: upload, {size} bytes");
        // Mirrors `scp_upload_init`: req.size = infilesize; Curl_pgrsSetUploadSize;
        // Curl_xfer_setup_send(FIRSTSOCKET).
        Ok(ProtocolTransfer::new(TransferDirection::Upload).with_size(size))
    } else {
        crate::infof!(verbose, "scp: download");
        // `scp_download_init` learns the size from the wire handshake; here the
        // size is learned in `run_download` (the channel cannot persist), so the
        // engine treats this as curl's unknown length (`k->size == -1`).
        Ok(ProtocolTransfer::new(TransferDirection::Download))
    }
}

/// DOWNLOAD data plane (`scp -f`; we are the sink). Opens and `exec`s the SCP
/// command, negotiates the file header, streams exactly the announced number of
/// payload bytes into the client-writer chain, and tears the channel down.
///
/// Made `pub` (like `mqtt.rs`'s `run_subscription`) so it is not flagged as dead
/// code before the transfer engine's data-plane glue invokes it; it is exercised
/// end-to-end by the curl 8.x test suite.
pub async fn run_download(
    data: &Easy,
    conn: &mut Connection,
    writer: &mut ClientWriter,
    sink: &mut dyn WriteCallbacks,
) -> Result<()> {
    let verbose = data.set.verbose;
    let path = get_working_path(data, conn, None)?;
    let cmd = build_scp_command(false, &path);
    crate::infof!(verbose, "scp: exec '{cmd}'");

    let channel = match open_exec_channel(conn, &cmd).await {
        Ok(c) => c,
        Err(e) => {
            crate::failf!(
                &mut conn.filter_data.error_buffer,
                "scp: could not open download channel: {e}"
            );
            return Err(e);
        }
    };

    let mut session = ScpSession::new(RusshChannelAdapter::new(channel));
    let mut reporter = ConnReporter {
        verbose,
        error_buffer: &mut conn.filter_data.error_buffer,
    };

    let meta = session.negotiate_download(&mut reporter).await?;
    crate::infof!(
        verbose,
        "scp: receiving '{}' ({} bytes)",
        meta.name,
        meta.size
    );

    // Stream exactly `meta.size` payload bytes into the client-writer chain.
    let recv = session
        .recv_body(meta.size, &mut reporter, |chunk| {
            writer.write(ClientWriteType::BODY, chunk, sink)
        })
        .await;

    // On success, signal end-of-stream so the writer chain flushes/closes
    // (mirrors `mqtt.rs`'s `run_subscription`).
    if recv.is_ok() {
        writer.write(
            ClientWriteType::BODY | ClientWriteType::EOS | ClientWriteType::ZERO_LEN,
            &[],
            sink,
        )?;
    }

    // Download teardown: the C oracle frees the channel directly (no EOF wait).
    session.teardown(false, &mut reporter).await;
    recv
}

/// UPLOAD data plane (`scp -t`; we are the source). Opens and `exec`s the SCP
/// command, sends the `C<mode> <size> <name>` header, streams exactly
/// `CURLOPT_INFILESIZE` bytes from the upload read callback, and tears the
/// channel down. Upload-start failures are remapped to
/// [`CurlError::UploadFailed`] (C `scp_upload_init`).
///
/// Made `pub` for the same reason as [`run_download`].
pub async fn run_upload(
    data: &Easy,
    conn: &mut Connection,
    reader: &mut dyn ReadCallback,
) -> Result<()> {
    let verbose = data.set.verbose;
    let infilesize = data.set.filesize;
    if infilesize < 0 {
        crate::failf!(
            &mut conn.filter_data.error_buffer,
            "SCP upload requires a known file size (set CURLOPT_INFILESIZE)"
        );
        return Err(CurlError::UploadFailed);
    }
    let size = infilesize as u64;
    let perms = data.set.new_file_perms;
    let mode = if perms == 0 {
        DEFAULT_FILE_PERMS
    } else {
        perms
    };

    let path = match get_working_path(data, conn, None) {
        Ok(p) => p,
        Err(e) => return Err(remap_upload_error(e)),
    };
    let name = basename(&path).to_string();
    if name.is_empty() {
        // libssh2: the destination must include a file name (or end in "/").
        crate::failf!(
            &mut conn.filter_data.error_buffer,
            "SCP upload destination must include a file name"
        );
        return Err(CurlError::UploadFailed);
    }
    let cmd = build_scp_command(true, &path);
    crate::infof!(verbose, "scp: exec '{cmd}'");

    let channel = match open_exec_channel(conn, &cmd).await {
        Ok(c) => c,
        Err(e) => {
            crate::failf!(
                &mut conn.filter_data.error_buffer,
                "scp: could not open upload channel: {e}"
            );
            return Err(remap_upload_error(e));
        }
    };

    let mut session = ScpSession::new(RusshChannelAdapter::new(channel));
    let mut reporter = ConnReporter {
        verbose,
        error_buffer: &mut conn.filter_data.error_buffer,
    };

    // SCP cannot pause mid-frame (the `C` line fixes the length), so the upload
    // reader is created with `can_pause = false`: a PAUSE request from the read
    // callback then fails the transfer rather than stalling the channel.
    let mut up = UploadReader::new(Some(size), false);

    // Negotiate the header, then stream exactly `size` bytes from the callback.
    let neg = session
        .negotiate_upload(mode, size, &name, &mut reporter)
        .await;
    let result = match neg {
        Err(e) => Err(e),
        Ok(()) => {
            session
                .send_body(size, &mut reporter, |scratch| {
                    match up.read(scratch, reader)? {
                        ReadStep::Data(n) => Ok(n),
                        // can_pause == false ⇒ PAUSE never reaches here; EOF
                        // before `size` is handled by `send_body` as PartialFile.
                        ReadStep::Eof | ReadStep::Paused => Ok(0),
                    }
                })
                .await
        }
    };

    // Upload teardown: EOF → wait for peer EOF/close → free channel.
    session.teardown(true, &mut reporter).await;
    result.map_err(remap_upload_error)
}

/// C `scp_done`: SCP teardown finalizer.
///
/// The channel EOF/wait/close/free sequence is performed at the end of
/// [`run_download`] / [`run_upload`], where the exec channel is in scope (it
/// cannot be parked on the connection). Like the C `scp_done`, this finalizer
/// introduces no new error — the transfer's own `status` is preserved by the
/// engine — so it returns `Ok(())`. The SSH session itself is **not** torn down
/// here; that is the connection's `disconnect_hook` installed by `ssh/mod.rs`
/// (the C `SSH_SESSION_DISCONNECT` state).
pub(super) async fn done(
    data: &mut Easy,
    _conn: &mut Connection,
    status: Result<()>,
    premature: bool,
) -> Result<()> {
    let verbose = data.set.verbose;
    if premature {
        crate::infof!(verbose, "scp: transfer ended prematurely");
    }
    // The transfer result is owned by the engine; the finalizer adds no error.
    let _ = status;
    Ok(())
}

// ===========================================================================
// Tests — pure helpers, control-line parsing, and the rcp source/sink framing
// exercised against an in-memory mock channel (no SSH server required).
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{SchemeDescriptor, TRNSPRT_TCP};
    use crate::protocols::SCHEME_SCP;
    use std::collections::VecDeque;

    // ---- Mock channel: a scripted byte transport implementing `ScpChannel` --

    /// In-memory [`ScpChannel`]: serves `inbound` chunks (one per `read_chunk`,
    /// `None`/EOF once exhausted), records everything written, and tracks the
    /// teardown calls so tests can assert the exact wire exchange.
    struct MockChannel {
        inbound: VecDeque<Vec<u8>>,
        written: Vec<u8>,
        eof_sent: bool,
        drained: bool,
        closed: bool,
    }

    impl MockChannel {
        fn new(inbound: Vec<Vec<u8>>) -> Self {
            Self {
                inbound: inbound.into_iter().collect(),
                written: Vec::new(),
                eof_sent: false,
                drained: false,
                closed: false,
            }
        }
    }

    impl ScpChannel for MockChannel {
        async fn read_chunk(&mut self) -> Result<Option<Vec<u8>>> {
            Ok(self.inbound.pop_front())
        }
        async fn write_all(&mut self, data: &[u8]) -> Result<()> {
            self.written.extend_from_slice(data);
            Ok(())
        }
        async fn send_eof(&mut self) -> Result<()> {
            self.eof_sent = true;
            Ok(())
        }
        async fn drain(&mut self) -> Result<()> {
            self.drained = true;
            Ok(())
        }
        async fn close(&mut self) -> Result<()> {
            self.closed = true;
            Ok(())
        }
    }

    /// Capturing [`ScpReporter`]: records `info`/`fail` messages for assertions.
    #[derive(Default)]
    struct MockReporter {
        infos: Vec<String>,
        fails: Vec<String>,
    }

    impl ScpReporter for MockReporter {
        fn info(&mut self, msg: &str) {
            self.infos.push(msg.to_string());
        }
        fn fail(&mut self, msg: &str) {
            self.fails.push(msg.to_string());
        }
    }

    fn session(inbound: Vec<Vec<u8>>) -> ScpSession<MockChannel> {
        ScpSession::new(MockChannel::new(inbound))
    }

    fn make_scp_conn() -> Connection {
        let scheme = &SCHEME_SCP;
        let desc = SchemeDescriptor::new(
            scheme.name,
            scheme.default_port,
            scheme.flags,
            scheme.protocol,
        );
        Connection::new(
            format!("{}:{}", scheme.name, scheme.default_port),
            TRNSPRT_TCP,
            desc,
        )
    }

    // ---- shell_quote ------------------------------------------------------

    #[test]
    fn shell_quote_plain_path_is_single_quoted() {
        assert_eq!(shell_quote("/tmp/file.txt"), "'/tmp/file.txt'");
    }

    #[test]
    fn shell_quote_escapes_embedded_single_quote() {
        // a'b  ->  'a'\''b'  (close, escaped quote, reopen)
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn shell_quote_neutralizes_metacharacters() {
        // Spaces, ';', '$', and '`' are all inert inside the single quotes.
        let q = shell_quote("a b; rm -rf $HOME `id`");
        assert_eq!(q, "'a b; rm -rf $HOME `id`'");
        assert!(q.starts_with('\'') && q.ends_with('\''));
    }

    // ---- build_scp_command ------------------------------------------------

    #[test]
    fn build_scp_command_download_uses_dash_f() {
        assert_eq!(
            build_scp_command(false, "/srv/data.bin"),
            "scp -f -- '/srv/data.bin'"
        );
    }

    #[test]
    fn build_scp_command_upload_uses_dash_t() {
        assert_eq!(
            build_scp_command(true, "/srv/data.bin"),
            "scp -t -- '/srv/data.bin'"
        );
    }

    // ---- basename ---------------------------------------------------------

    #[test]
    fn basename_variants() {
        assert_eq!(basename("/a/b/c.txt"), "c.txt");
        assert_eq!(basename("file.txt"), "file.txt");
        // A trailing slash means no file-name component.
        assert_eq!(basename("/a/b/"), "");
    }

    // ---- format_mode ------------------------------------------------------

    #[test]
    fn format_mode_pads_and_masks() {
        assert_eq!(format_mode(0o644), "0644");
        assert_eq!(format_mode(0o755), "0755");
        assert_eq!(format_mode(0), "0000");
        // File-type bits above 0o7777 (e.g. S_IFREG 0o100000) are masked off.
        assert_eq!(format_mode(0o100_644), "0644");
    }

    // ---- build_upload_control_line ----------------------------------------

    #[test]
    fn build_upload_control_line_format() {
        assert_eq!(
            build_upload_control_line(0o644, 1234, "file.txt"),
            b"C0644 1234 file.txt\n".to_vec()
        );
    }

    // ---- parse_control_line -----------------------------------------------

    #[test]
    fn parse_control_line_file() {
        assert_eq!(
            parse_control_line(b"C0644 5 hello").unwrap(),
            ScpControl::File {
                mode: 0o644,
                size: 5,
                name: "hello".to_string()
            }
        );
    }

    #[test]
    fn parse_control_line_file_name_with_spaces() {
        // `splitn(3, ' ')` preserves spaces inside the file name.
        assert_eq!(
            parse_control_line(b"C0644 10 my file.txt").unwrap(),
            ScpControl::File {
                mode: 0o644,
                size: 10,
                name: "my file.txt".to_string()
            }
        );
    }

    #[test]
    fn parse_control_line_time_dir_warning_fatal() {
        assert_eq!(
            parse_control_line(b"T1700000000 0 1700000000 0").unwrap(),
            ScpControl::Time
        );
        assert_eq!(
            parse_control_line(b"D0755 0 dir").unwrap(),
            ScpControl::StartDir
        );
        assert_eq!(parse_control_line(b"E").unwrap(), ScpControl::EndDir);
        assert_eq!(
            parse_control_line(b"\x01scp: warning text").unwrap(),
            ScpControl::Warning("scp: warning text".to_string())
        );
        assert_eq!(
            parse_control_line(b"\x02scp: no such file").unwrap(),
            ScpControl::Fatal("scp: no such file".to_string())
        );
    }

    #[test]
    fn parse_control_line_rejects_malformed() {
        assert_eq!(parse_control_line(b"").unwrap_err(), CurlError::Ssh);
        assert_eq!(parse_control_line(b"Cxyz 5 f").unwrap_err(), CurlError::Ssh);
        assert_eq!(
            parse_control_line(b"C0644 notnum f").unwrap_err(),
            CurlError::Ssh
        );
        assert_eq!(parse_control_line(b"C0644").unwrap_err(), CurlError::Ssh);
        assert_eq!(parse_control_line(b"Z bogus").unwrap_err(), CurlError::Ssh);
    }

    // ---- ConnReporter (production reporter) -------------------------------

    #[test]
    fn conn_reporter_records_first_failure() {
        let mut buf: Option<String> = None;
        {
            let mut r = ConnReporter {
                verbose: false,
                error_buffer: &mut buf,
            };
            r.info("verbose-gated, no buffer write");
            r.fail("boom");
        }
        assert_eq!(buf.as_deref(), Some("boom"));
    }

    // ---- DOWNLOAD negotiation --------------------------------------------

    #[tokio::test]
    async fn negotiate_download_simple_file() {
        let mut s = session(vec![b"C0644 5 hello\n".to_vec()]);
        let mut rep = MockReporter::default();
        let meta = s.negotiate_download(&mut rep).await.unwrap();
        assert_eq!(
            meta,
            ScpFileMeta {
                mode: 0o644,
                size: 5,
                name: "hello".to_string()
            }
        );
        // Sink sends the ready byte, then acks the control line.
        assert_eq!(s.chan.written, vec![SCP_OK, SCP_OK]);
    }

    #[tokio::test]
    async fn negotiate_download_acks_time_line_then_file() {
        let mut s = session(vec![b"T1700000000 0 1700000000 0\nC0644 3 abc\n".to_vec()]);
        let mut rep = MockReporter::default();
        let meta = s.negotiate_download(&mut rep).await.unwrap();
        assert_eq!(meta.size, 3);
        assert_eq!(meta.name, "abc");
        // ready, ack(T), ack(C).
        assert_eq!(s.chan.written, vec![SCP_OK, SCP_OK, SCP_OK]);
    }

    #[tokio::test]
    async fn negotiate_download_logs_warning_then_proceeds() {
        let mut s = session(vec![b"\x01disk slow\nC0644 1 x\n".to_vec()]);
        let mut rep = MockReporter::default();
        let meta = s.negotiate_download(&mut rep).await.unwrap();
        assert_eq!(meta.name, "x");
        assert!(rep.infos.iter().any(|m| m.contains("disk slow")));
    }

    #[tokio::test]
    async fn negotiate_download_fatal_is_remote_file_not_found() {
        let mut s = session(vec![b"\x02scp: /nope: No such file\n".to_vec()]);
        let mut rep = MockReporter::default();
        let err = s.negotiate_download(&mut rep).await.unwrap_err();
        assert_eq!(err, CurlError::RemoteFileNotFound);
        assert!(rep.fails.iter().any(|m| m.contains("No such file")));
    }

    #[tokio::test]
    async fn negotiate_download_directory_unsupported() {
        let mut s = session(vec![b"D0755 0 adir\n".to_vec()]);
        let mut rep = MockReporter::default();
        let err = s.negotiate_download(&mut rep).await.unwrap_err();
        assert_eq!(err, CurlError::Ssh);
        assert!(!rep.fails.is_empty());
    }

    // ---- DOWNLOAD data plane (recv_body) ----------------------------------

    #[tokio::test]
    async fn recv_body_reads_exact_and_consumes_status() {
        // Payload "hello" immediately followed by the source's trailing 0x00.
        let mut s = session(vec![b"hello\x00".to_vec()]);
        let mut rep = MockReporter::default();
        let mut got = Vec::new();
        s.recv_body(5, &mut rep, |c| {
            got.extend_from_slice(c);
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(got, b"hello".to_vec());
        // Sink replies with a final OK; the trailing status was NOT delivered.
        assert_eq!(s.chan.written, vec![SCP_OK]);
    }

    #[tokio::test]
    async fn recv_body_does_not_read_past_size() {
        // 2 payload bytes, then status; ensure only "AB" is delivered.
        let mut s = session(vec![b"AB\x00".to_vec()]);
        let mut rep = MockReporter::default();
        let mut got = Vec::new();
        s.recv_body(2, &mut rep, |c| {
            got.extend_from_slice(c);
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(got, b"AB".to_vec());
    }

    #[tokio::test]
    async fn recv_body_short_transfer_is_partial_file() {
        // Channel closes after 3 bytes though 10 were announced.
        let mut s = session(vec![b"abc".to_vec()]);
        let mut rep = MockReporter::default();
        let mut got = Vec::new();
        let err = s
            .recv_body(10, &mut rep, |c| {
                got.extend_from_slice(c);
                Ok(())
            })
            .await
            .unwrap_err();
        assert_eq!(err, CurlError::PartialFile);
        assert_eq!(got, b"abc".to_vec());
        assert!(!rep.fails.is_empty());
    }

    #[tokio::test]
    async fn recv_body_fatal_trailing_status() {
        // Payload complete, then the source signals a fatal status.
        let mut s = session(vec![b"hello\x02write error\n".to_vec()]);
        let mut rep = MockReporter::default();
        let mut got = Vec::new();
        let err = s
            .recv_body(5, &mut rep, |c| {
                got.extend_from_slice(c);
                Ok(())
            })
            .await
            .unwrap_err();
        assert_eq!(err, CurlError::Ssh);
        assert_eq!(got, b"hello".to_vec());
        assert!(rep.fails.iter().any(|m| m.contains("write error")));
    }

    // ---- UPLOAD negotiation -----------------------------------------------

    #[tokio::test]
    async fn negotiate_upload_sends_control_line() {
        // Sink: ready ack, then header ack.
        let mut s = session(vec![vec![SCP_OK, SCP_OK]]);
        let mut rep = MockReporter::default();
        s.negotiate_upload(0o644, 7, "f.txt", &mut rep)
            .await
            .unwrap();
        assert_eq!(s.chan.written, b"C0644 7 f.txt\n".to_vec());
    }

    #[tokio::test]
    async fn negotiate_upload_fatal_ready_byte() {
        let mut s = session(vec![b"\x02permission denied\n".to_vec()]);
        let mut rep = MockReporter::default();
        let err = s
            .negotiate_upload(0o644, 7, "f.txt", &mut rep)
            .await
            .unwrap_err();
        assert_eq!(err, CurlError::Ssh);
        assert!(rep.fails.iter().any(|m| m.contains("permission denied")));
    }

    // ---- UPLOAD data plane (send_body) ------------------------------------

    #[tokio::test]
    async fn send_body_writes_payload_then_success_byte() {
        // Sink acks the final success byte.
        let mut s = session(vec![vec![SCP_OK]]);
        let mut rep = MockReporter::default();
        let src = b"ABCDE";
        let mut pos = 0usize;
        s.send_body(5, &mut rep, |buf| {
            let n = (src.len() - pos).min(buf.len());
            buf[..n].copy_from_slice(&src[pos..pos + n]);
            pos += n;
            Ok(n)
        })
        .await
        .unwrap();
        // Exactly the payload, then the trailing 0x00 success byte.
        assert_eq!(s.chan.written, b"ABCDE\x00".to_vec());
    }

    #[tokio::test]
    async fn send_body_source_underrun_is_partial_file() {
        let mut s = session(vec![vec![SCP_OK]]);
        let mut rep = MockReporter::default();
        let src = b"ABC"; // only 3 bytes for an announced 10
        let mut pos = 0usize;
        let err = s
            .send_body(10, &mut rep, |buf| {
                let n = (src.len() - pos).min(buf.len());
                buf[..n].copy_from_slice(&src[pos..pos + n]);
                pos += n;
                Ok(n)
            })
            .await
            .unwrap_err();
        assert_eq!(err, CurlError::PartialFile);
        assert!(!rep.fails.is_empty());
    }

    // ---- teardown ---------------------------------------------------------

    #[tokio::test]
    async fn teardown_upload_sends_eof_drains_and_closes() {
        let mut s = session(vec![]);
        let mut rep = MockReporter::default();
        s.teardown(true, &mut rep).await;
        assert!(s.chan.eof_sent);
        assert!(s.chan.drained);
        assert!(s.chan.closed);
    }

    #[tokio::test]
    async fn teardown_download_only_closes() {
        let mut s = session(vec![]);
        let mut rep = MockReporter::default();
        s.teardown(false, &mut rep).await;
        assert!(!s.chan.eof_sent);
        assert!(!s.chan.drained);
        assert!(s.chan.closed);
    }

    // ---- remap_upload_error ------------------------------------------------

    #[test]
    fn remap_upload_error_collapses_to_upload_failed() {
        assert_eq!(remap_upload_error(CurlError::Ssh), CurlError::UploadFailed);
        assert_eq!(
            remap_upload_error(CurlError::RemoteFileNotFound),
            CurlError::UploadFailed
        );
        // Unrelated errors pass through unchanged.
        assert_eq!(
            remap_upload_error(CurlError::PartialFile),
            CurlError::PartialFile
        );
    }

    // ---- do_it / done -----------------------------------------------------

    #[tokio::test]
    async fn do_it_download_reports_unknown_size() {
        let mut data = Easy::new();
        data.set.method = HttpReq::Get;
        let mut conn = make_scp_conn();
        let xfer = do_it(&mut data, &mut conn).await.unwrap();
        assert_eq!(xfer.direction, TransferDirection::Download);
        // Download size is learned on the wire, so it is unknown here.
        assert_eq!(xfer.expected_size, None);
    }

    #[tokio::test]
    async fn do_it_upload_with_known_size() {
        let mut data = Easy::new();
        data.set.method = HttpReq::Put;
        data.set.filesize = 42;
        let mut conn = make_scp_conn();
        let xfer = do_it(&mut data, &mut conn).await.unwrap();
        assert_eq!(xfer.direction, TransferDirection::Upload);
        assert_eq!(xfer.expected_size, Some(42));
    }

    #[tokio::test]
    async fn do_it_upload_unknown_size_fails() {
        let mut data = Easy::new();
        data.set.method = HttpReq::Put;
        data.set.filesize = -1;
        let mut conn = make_scp_conn();
        let err = do_it(&mut data, &mut conn).await.unwrap_err();
        assert_eq!(err, CurlError::UploadFailed);
        // The failure is recorded into the error buffer for the CLI/diagnostics.
        assert!(conn.filter_data.error_buffer.is_some());
    }

    #[tokio::test]
    async fn done_is_a_noop_finalizer() {
        let mut data = Easy::new();
        let mut conn = make_scp_conn();
        assert!(done(&mut data, &mut conn, Ok(()), false).await.is_ok());
        assert!(
            done(&mut data, &mut conn, Err(CurlError::PartialFile), true)
                .await
                .is_ok()
        );
    }

    // ---- additional framing-branch coverage -------------------------------

    #[tokio::test]
    async fn negotiate_upload_fatal_header_ack() {
        // Ready ack OK, but the sink rejects the header with a fatal status.
        let mut s = session(vec![vec![SCP_OK], b"\x02disk full\n".to_vec()]);
        let mut rep = MockReporter::default();
        let err = s
            .negotiate_upload(0o644, 3, "f", &mut rep)
            .await
            .unwrap_err();
        assert_eq!(err, CurlError::Ssh);
        assert!(rep.fails.iter().any(|m| m.contains("disk full")));
        // The control line was written before the fatal header ack arrived.
        assert_eq!(s.chan.written, b"C0644 3 f\n".to_vec());
    }

    #[tokio::test]
    async fn read_ack_rejects_out_of_protocol_byte() {
        // 0x05 is neither OK (0x00), warning (0x01) nor fatal (0x02).
        let mut s = session(vec![vec![0x05]]);
        let mut rep = MockReporter::default();
        let err = s
            .negotiate_upload(0o644, 1, "f", &mut rep)
            .await
            .unwrap_err();
        assert_eq!(err, CurlError::Ssh);
    }

    #[tokio::test]
    async fn recv_body_warning_trailing_status_is_tolerated() {
        // Payload complete, then a non-fatal warning status; transfer succeeds.
        let mut s = session(vec![b"hello\x01slow link\n".to_vec()]);
        let mut rep = MockReporter::default();
        let mut got = Vec::new();
        s.recv_body(5, &mut rep, |c| {
            got.extend_from_slice(c);
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(got, b"hello".to_vec());
        assert!(rep.infos.iter().any(|m| m.contains("slow link")));
        assert_eq!(s.chan.written, vec![SCP_OK]);
    }

    #[tokio::test]
    async fn control_line_spanning_multiple_chunks() {
        // The control line arrives split across two channel reads, exercising
        // the `read_until_lf` cross-chunk accumulation path.
        let mut s = session(vec![b"C0644 5 hel".to_vec(), b"lo\n".to_vec()]);
        let mut rep = MockReporter::default();
        let meta = s.negotiate_download(&mut rep).await.unwrap();
        assert_eq!(meta.name, "hello");
        assert_eq!(meta.size, 5);
    }

    #[tokio::test]
    async fn fill_skips_empty_chunks() {
        // An empty channel chunk is skipped; the next non-empty chunk is used.
        let mut s = session(vec![Vec::new(), b"C0644 1 z\n".to_vec()]);
        let mut rep = MockReporter::default();
        let meta = s.negotiate_download(&mut rep).await.unwrap();
        assert_eq!(meta.name, "z");
    }

    #[tokio::test]
    async fn negotiate_download_truncated_is_recv_error() {
        // The source closed before sending any control line.
        let mut s = session(vec![]);
        let mut rep = MockReporter::default();
        let err = s.negotiate_download(&mut rep).await.unwrap_err();
        assert_eq!(err, CurlError::RecvError);
    }

    #[tokio::test]
    async fn do_it_upload_verbose_path() {
        // Exercises the verbose `infof!` branch in `do_it`.
        let mut data = Easy::new();
        data.set.verbose = true;
        data.set.method = HttpReq::Put;
        data.set.filesize = 10;
        let mut conn = make_scp_conn();
        let xfer = do_it(&mut data, &mut conn).await.unwrap();
        assert_eq!(xfer.expected_size, Some(10));
    }

    #[tokio::test]
    async fn do_it_download_verbose_path() {
        let mut data = Easy::new();
        data.set.verbose = true;
        data.set.method = HttpReq::Get;
        let mut conn = make_scp_conn();
        let xfer = do_it(&mut data, &mut conn).await.unwrap();
        assert_eq!(xfer.direction, TransferDirection::Download);
    }
}
