//! SMB / SMBS protocol handler — a faithful, idiomatic-Rust port of curl's
//! minimal **SMBv1** client (`lib/smb.c`, `lib/smb.h`).
//!
//! curl implements just enough of the venerable SMB/CIFS **version 1** wire
//! protocol to download and upload a single file from a share:
//!
//! ```text
//! NEGOTIATE ─► SESSION SETUP (NTLMv1) ─► TREE CONNECT ─► NT_CREATE (open)
//!                                                          │
//!                                            ┌─────────────┴─────────────┐
//!                                       READ_ANDX loop            WRITE_ANDX loop
//!                                            └─────────────┬─────────────┘
//!                                                       CLOSE ─► TREE DISCONNECT
//! ```
//!
//! # Minimal Change Mandate
//!
//! This module reproduces curl's SMBv1 client **exactly** — the same messages,
//! the same little-endian byte layout, the same NTLMv1 authentication, the same
//! error mapping. It deliberately does **not** add SMB2/SMB3, message signing,
//! DFS, or anything `lib/smb.c` lacks. Byte-for-byte functional parity with
//! curl 8.x is the success condition.
//!
//! # Authentication
//!
//! SMB authenticates with **raw NTLMv1** LM/NT responses embedded directly in
//! the `SESSION SETUP ANDX` security fields — *not* base64 NTLMSSP messages.
//! curl builds these with `Curl_ntlm_core_mk_lm_hash` / `mk_nt_hash` /
//! `lm_resp` (`lib/curl_ntlm_core.c`). That raw 24-byte-response primitive is
//! specific to SMB's on-the-wire security blob — the HTTP / SASL NTLM path
//! emits base64 NTLMSSP messages instead — so this handler carries its own
//! self-contained, pure-Rust port of the three primitives in the private
//! `ntlm` submodule. This keeps the SMB handler entirely within `protocols/`,
//! exactly as the TFTP, TELNET, and LDAP handlers hand-roll their own wire
//! primitives, with no dependency on the crate's HTTP-oriented `auth` module.
//! The port is byte-for-byte identical to curl and contains zero
//! memory-unchecked code.
//!
//! # Byte order
//!
//! Every multi-byte SMB1 field is **little-endian**, with the single exception
//! of the NetBIOS session-service length prefix (`nbt_length`), which is
//! **big-endian** (network order, written by curl via `htons`). All packing is
//! done with safe `to_le_bytes` / `to_be_bytes` and slice writes — there is
//! **zero memory-unchecked code** here (the crate sets the `#![forbid(...)]` lint).
//!
//! # `smbs`
//!
//! The `smbs` scheme is ordinary SMB carried over a TLS stream. Exactly as in
//! curl (`smb_connection_state` calls `Curl_conn_connect` and lets the filter
//! chain perform the handshake), the TLS layer is established by the connection
//! filter chain (`crate::conn` / [`crate::tls`]); this handler then drives the
//! identical SMB message flow over whatever stream it is handed. The engine is
//! therefore generic over any [`tokio::io::AsyncRead`] + [`tokio::io::AsyncWrite`]
//! transport.

use crate::conn::Connection;
use crate::error::{CurlCode, Error, Result};
use crate::protocols::{ProtoFuture, Protocol, TransferCtx};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Self-contained NTLMv1 primitives for SMB `SESSION SETUP`.
///
/// curl's SMB handler embeds the bare 24-byte LM and NT responses
/// (`Curl_ntlm_core_mk_lm_hash` / `mk_nt_hash` / `lm_resp`,
/// `lib/curl_ntlm_core.c`) directly in the `SESSION SETUP ANDX` security blob —
/// not a base64 NTLMSSP message. These three primitives (and the small DES /
/// MD4 helpers they need) are reproduced here rather than reaching into the
/// crate's HTTP-oriented `auth::ntlm` module, so the SMB protocol handler stays
/// entirely self-contained within `protocols/` — consistent with how the TFTP,
/// TELNET, and LDAP handlers hand-roll their own wire primitives.
///
/// Every routine is pure safe Rust built on the [`des`] and [`md4`] crates (no
/// C linkage, and no memory-unchecked code — the crate-wide safe-code lint in
/// `lib.rs` applies) and is byte-for-byte identical to curl's
/// `curl_ntlm_core.c`.
mod ntlm {
    use des::cipher::generic_array::GenericArray;
    use des::cipher::{BlockEncrypt, KeyInit};
    use des::Des;
    use md4::{Digest as _, Md4};

    /// The LM-hash magic constant `"KGS!@#$%"` (`lib/curl_ntlm_core.c` L357-359).
    const LM_MAGIC: [u8; 8] = [0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25];

    /// Encode ASCII/Latin-1 bytes as UTF-16LE by interleaving a zero high byte
    /// (port of curl's byte-wise `ascii_to_unicode_le`; curl does not perform
    /// real UTF-8→UTF-16 transcoding, and that quirk is preserved).
    fn ascii_to_unicode_le(src: &[u8]) -> Vec<u8> {
        src.iter().flat_map(|&b| [b, 0u8]).collect()
    }

    /// Expand a 7-byte (56-bit) key to the 8-byte layout DES consumes
    /// (port of the bit-spreading in `curl_ntlm_core.c`). On `u8` the shift
    /// already truncates to eight bits, so C's `& 0xFF` masks are implicit.
    fn extend_key_56_to_64(key56: &[u8; 7]) -> [u8; 8] {
        [
            key56[0],
            (key56[0] << 7) | (key56[1] >> 1),
            (key56[1] << 6) | (key56[2] >> 2),
            (key56[2] << 5) | (key56[3] >> 3),
            (key56[3] << 4) | (key56[4] >> 4),
            (key56[4] << 3) | (key56[5] >> 5),
            (key56[5] << 2) | (key56[6] >> 6),
            key56[6] << 1,
        ]
    }

    /// Apply odd parity to every byte (port of `curl_des_set_odd_parity`). DES
    /// ignores the parity bit, so this does not change the cipher output; it is
    /// reproduced for exact fidelity with curl.
    fn des_set_odd_parity(bytes: &mut [u8; 8]) {
        for b in bytes.iter_mut() {
            let x = *b;
            let parity =
                ((x >> 7) ^ (x >> 6) ^ (x >> 5) ^ (x >> 4) ^ (x >> 3) ^ (x >> 2) ^ (x >> 1)) & 0x01;
            if parity == 0 {
                *b |= 0x01;
            } else {
                *b &= 0xFE;
            }
        }
    }

    /// Expand a 7-byte key to a parity-adjusted 8-byte DES key
    /// (port of `setup_des_key`).
    fn setup_des_key(key56: &[u8; 7]) -> [u8; 8] {
        let mut key = extend_key_56_to_64(key56);
        des_set_odd_parity(&mut key);
        key
    }

    /// Encrypt one 8-byte block with single DES in ECB mode using an already
    /// expanded 8-byte key, through the pure-Rust [`des`] crate's safe `cipher`
    /// API only (no raw crypto-library calls, no C linkage).
    fn des_block_encrypt(key8: &[u8; 8], plaintext: &[u8; 8]) -> [u8; 8] {
        let cipher = Des::new(&GenericArray::from(*key8));
        let mut block = GenericArray::from(*plaintext);
        cipher.encrypt_block(&mut block);
        let mut out = [0u8; 8];
        out.copy_from_slice(block.as_slice());
        out
    }

    /// Expand a 7-byte key and DES-ECB-encrypt an 8-byte block in one step.
    fn des_encrypt_with_56(key56: &[u8; 7], plaintext: &[u8; 8]) -> [u8; 8] {
        des_block_encrypt(&setup_des_key(key56), plaintext)
    }

    /// Copy a 7-byte window out of a key buffer at `start` (always a multiple of
    /// seven within a 14- or 21-byte buffer, so the window is always seven bytes).
    fn seven(keys: &[u8], start: usize) -> [u8; 7] {
        let mut k = [0u8; 7];
        k.copy_from_slice(&keys[start..start + 7]);
        k
    }

    /// Treat a 21-byte key as three 56-bit DES keys, DES-ECB-encrypt the 8-byte
    /// `plaintext` with each, and concatenate the three ciphertexts into a
    /// 24-byte response (port of `Curl_ntlm_core_lm_resp`). This computes both
    /// the NTLMv1 NT response and the LM response.
    pub(super) fn lm_resp(keys: &[u8; 21], plaintext: &[u8; 8]) -> [u8; 24] {
        let mut out = [0u8; 24];
        out[0..8].copy_from_slice(&des_encrypt_with_56(&seven(keys, 0), plaintext));
        out[8..16].copy_from_slice(&des_encrypt_with_56(&seven(keys, 7), plaintext));
        out[16..24].copy_from_slice(&des_encrypt_with_56(&seven(keys, 14), plaintext));
        out
    }

    /// Build the 21-byte LAN Manager hashed password
    /// (port of `Curl_ntlm_core_mk_lm_hash`).
    ///
    /// The password is upper-cased (ASCII) and truncated/zero-padded to 14
    /// bytes, split into two 7-byte DES keys each of which encrypts the LM magic
    /// constant; the two 8-byte ciphertexts are concatenated and the buffer is
    /// zero-padded to 21 bytes.
    pub(super) fn mk_lm_hash(password: &str) -> [u8; 21] {
        let pw_bytes = password.as_bytes();
        let len = pw_bytes.len().min(14);
        let mut pw = [0u8; 14];
        for (dst, &src) in pw.iter_mut().zip(&pw_bytes[..len]) {
            *dst = src.to_ascii_uppercase();
        }

        let mut lm = [0u8; 21];
        lm[0..8].copy_from_slice(&des_encrypt_with_56(&seven(&pw, 0), &LM_MAGIC));
        lm[8..16].copy_from_slice(&des_encrypt_with_56(&seven(&pw, 7), &LM_MAGIC));
        // lm[16..21] remains zero.
        lm
    }

    /// Build the 21-byte NT hashed password
    /// (port of `Curl_ntlm_core_mk_nt_hash`).
    ///
    /// The password is encoded as UTF-16LE, MD4-hashed into the first 16 bytes,
    /// and the buffer is zero-padded to 21 bytes.
    pub(super) fn mk_nt_hash(password: &str) -> [u8; 21] {
        let unicode_pw = ascii_to_unicode_le(password.as_bytes());
        let digest = Md4::digest(unicode_pw);
        let mut nt = [0u8; 21];
        nt[0..16].copy_from_slice(&digest);
        // nt[16..21] remains zero.
        nt
    }
}

// ===========================================================================
// SMB command codes (← `lib/smb.c` L112-120). One byte each, on the wire in the
// SMB header `command` field.
// ===========================================================================

const SMB_COM_CLOSE: u8 = 0x04;
const SMB_COM_READ_ANDX: u8 = 0x2e;
const SMB_COM_WRITE_ANDX: u8 = 0x2f;
const SMB_COM_TREE_DISCONNECT: u8 = 0x71;
const SMB_COM_NEGOTIATE: u8 = 0x72;
const SMB_COM_SETUP_ANDX: u8 = 0x73;
const SMB_COM_TREE_CONNECT_ANDX: u8 = 0x75;
const SMB_COM_NT_CREATE_ANDX: u8 = 0xa2;
const SMB_COM_NO_ANDX_COMMAND: u8 = 0xff;

// ===========================================================================
// SMB word counts (← `lib/smb.c` L122-127). The `word_count` byte that leads
// each command body counts the 16-bit parameter words that follow.
// ===========================================================================

const SMB_WC_CLOSE: u8 = 0x03;
const SMB_WC_READ_ANDX: u8 = 0x0c;
const SMB_WC_WRITE_ANDX: u8 = 0x0e;
const SMB_WC_SETUP_ANDX: u8 = 0x0d;
const SMB_WC_TREE_CONNECT_ANDX: u8 = 0x04;
const SMB_WC_NT_CREATE_ANDX: u8 = 0x18;

// ===========================================================================
// SMB header flags / capabilities / access masks (← `lib/smb.c` L129-141).
// ===========================================================================

const SMB_FLAGS_CANONICAL_PATHNAMES: u8 = 0x10;
const SMB_FLAGS_CASELESS_PATHNAMES: u8 = 0x08;
const SMB_FLAGS2_IS_LONG_NAME: u16 = 0x0040;
const SMB_FLAGS2_KNOWS_LONG_NAME: u16 = 0x0001;

const SMB_CAP_LARGE_FILES: u32 = 0x08;
const SMB_GENERIC_WRITE: u32 = 0x4000_0000;
const SMB_GENERIC_READ: u32 = 0x8000_0000;
const SMB_FILE_SHARE_ALL: u32 = 0x07;
const SMB_FILE_OPEN: u32 = 0x01;
const SMB_FILE_OVERWRITE_IF: u32 = 0x05;

/// The NT status `STATUS_ACCESS_DENIED`-style value curl special-cases to map a
/// tree-connect/open failure to `CURLE_REMOTE_ACCESS_DENIED` (← `SMB_ERR_NOACCESS`,
/// `lib/smb.c` L143). Compared against the header `status` field as stored on
/// the wire (little-endian), i.e. `status == SMB_ERR_NOACCESS`.
const SMB_ERR_NOACCESS: u32 = 0x0005_0001;

// ===========================================================================
// Sizes and fixed strings (← `lib/smb.c` L292-295).
// ===========================================================================

/// Maximum SMB read/write payload per message (`MAX_PAYLOAD_SIZE`).
const MAX_PAYLOAD_SIZE: usize = 0x8000;
/// Maximum total NetBIOS/SMB message size (`MAX_MESSAGE_SIZE`).
const MAX_MESSAGE_SIZE: usize = MAX_PAYLOAD_SIZE + 0x1000;
/// The NetBIOS "called/calling" client name curl advertises (`CLIENTNAME`).
const CLIENTNAME: &str = "curl";
/// The service type for TREE CONNECT — `"?????"` means "any type" (`SERVICENAME`).
const SERVICENAME: &str = "?????";

/// The made-up process id curl stamps into every SMB header (`lib/smb.c` L577).
const SMB_PID: u32 = 0x00bad71d;

/// Length of the NetBIOS session header (type + flags + 16-bit length).
const NETBIOS_HEADER_LEN: usize = 4;
/// Length of the full framing header curl treats as one unit: the 4-byte
/// NetBIOS session header immediately followed by the 32-byte SMB header
/// (`sizeof(struct smb_header)` == 36).
const SMB_HEADER_LEN: usize = 36;
/// `sizeof(struct smb_negotiate_response)` for the packed C struct (`lib/smb.c`
/// L162-179): 36-byte header + 38 bytes of fixed fields + `bytes[1]`.
const SMB_NEGOTIATE_RESPONSE_LEN: usize = 74;
/// `sizeof(struct smb_nt_create_response)` for the packed C struct (`lib/smb.c`
/// L229-244): header + parameters through `end_of_file`.
const SMB_NT_CREATE_RESPONSE_LEN: usize = 100;

/// The `CURL_OS` string curl embeds in the SESSION SETUP "native OS" field.
///
/// In C this is a configure-detected host triple (e.g. `x86_64-pc-linux-gnu`),
/// so it is inherently build-environment specific rather than part of any
/// deterministic wire contract; SMB servers treat it as a purely informational
/// label. We reproduce curl's convention with a per-target constant covering
/// the supported build matrix (see `[blitzy-docs] §0.6.5`), with a neutral
/// fallback for any other target.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
const CLIENT_OS: &str = "x86_64-pc-linux-gnu";
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
const CLIENT_OS: &str = "aarch64-unknown-linux-gnu";
#[cfg(all(target_arch = "x86_64", target_os = "macos"))]
const CLIENT_OS: &str = "x86_64-apple-darwin";
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
const CLIENT_OS: &str = "aarch64-apple-darwin";
#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "linux"),
    all(target_arch = "aarch64", target_os = "linux"),
    all(target_arch = "x86_64", target_os = "macos"),
    all(target_arch = "aarch64", target_os = "macos"),
)))]
const CLIENT_OS: &str = "unknown";

// ===========================================================================
// Endian-safe slice readers. Every SMB1 field is little-endian except the
// NetBIOS length prefix (big-endian). Each reader is *checked*: it validates
// that the requested window lies within the buffer and returns
// [`CurlCode::RecvError`] otherwise, so a malformed or truncated server frame
// yields a curl receive error instead of a panic (← the length guards that
// protect every field access in `smb_recv_message` / `smb_request_state`).
// ===========================================================================

/// The receive error returned when a reader's window falls outside the buffer
/// (a truncated or malformed frame). Centralized so every checked reader maps a
/// short frame to the identical `CURLE_RECV_ERROR` curl would produce.
#[inline]
fn short_frame() -> Error {
    Error::with_context(CurlCode::RecvError, "SMB: truncated response frame")
}

/// Read a little-endian `u16` at `off`, or [`CurlCode::RecvError`] when the two
/// bytes are not fully present in `buf`.
#[inline]
fn le_u16(buf: &[u8], off: usize) -> Result<u16> {
    let b = buf.get(off..off + 2).ok_or_else(short_frame)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

/// Read a little-endian `u32` at `off`, or [`CurlCode::RecvError`] when the four
/// bytes are not fully present in `buf`.
#[inline]
fn le_u32(buf: &[u8], off: usize) -> Result<u32> {
    let b = buf.get(off..off + 4).ok_or_else(short_frame)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a little-endian `i64` at `off` (SMB `curl_off_t` fields are signed), or
/// [`CurlCode::RecvError`] when the eight bytes are not fully present in `buf`.
#[inline]
fn le_i64(buf: &[u8], off: usize) -> Result<i64> {
    let b = buf.get(off..off + 8).ok_or_else(short_frame)?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(b);
    Ok(i64::from_le_bytes(arr))
}

/// Read a big-endian `u16` at `off` (the NetBIOS session length prefix), or
/// [`CurlCode::RecvError`] when the two bytes are not fully present in `buf`.
#[inline]
fn be_u16(buf: &[u8], off: usize) -> Result<u16> {
    let b = buf.get(off..off + 2).ok_or_else(short_frame)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

// ===========================================================================
// State machines. Variant names and discriminants are preserved verbatim from
// the C enums so `--trace` / diagnostic vocabulary stays identical to curl.
// ===========================================================================

/// Connection-level state (← `enum smb_conn_state`, `lib/smb.h`).
///
/// Discriminants match the C enumeration order exactly
/// (`SMB_NOT_CONNECTED = 0`, then `CONNECTING`, `NEGOTIATE`, `SETUP`,
/// `CONNECTED`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmbConnState {
    /// `SMB_NOT_CONNECTED` — freshly allocated, nothing sent yet.
    NotConnected = 0,
    /// `SMB_CONNECTING` — TCP (and, for `smbs`, TLS) is up; about to NEGOTIATE.
    Connecting,
    /// `SMB_NEGOTIATE` — NEGOTIATE sent; awaiting the server dialect + challenge.
    Negotiate,
    /// `SMB_SETUP` — SESSION SETUP (NTLM) sent; awaiting authentication result.
    Setup,
    /// `SMB_CONNECTED` — authenticated; UID captured; ready for requests.
    Connected,
}

/// Per-request state (← `enum smb_req_state`, `lib/smb.h`).
///
/// Discriminants match the C enumeration order exactly (`SMB_REQUESTING = 0`
/// through `SMB_DONE`). The names double as the `--trace` state labels curl
/// prints in `request_state()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmbReqState {
    /// `SMB_REQUESTING` — initial state; TREE CONNECT is about to be sent.
    Requesting = 0,
    /// `SMB_TREE_CONNECT` — TREE CONNECT sent; awaiting the tree id.
    TreeConnect,
    /// `SMB_OPEN` — NT_CREATE_ANDX sent; awaiting the file id / size.
    Open,
    /// `SMB_DOWNLOAD` — READ_ANDX in progress.
    Download,
    /// `SMB_UPLOAD` — WRITE_ANDX in progress.
    Upload,
    /// `SMB_CLOSE` — CLOSE sent.
    Close,
    /// `SMB_TREE_DISCONNECT` — TREE DISCONNECT sent.
    TreeDisconnect,
    /// `SMB_DONE` — the request finished (successfully or with `result`).
    Done,
}

// ===========================================================================
// Connection and request state (← `struct smb_conn` / `struct smb_request`,
// `lib/smb.h`). curl keeps `smb_conn` at the connection meta (shared across
// requests on a reused connection, per `PROTOPT_CONN_REUSE`) and `smb_request`
// at the easy-handle meta.
// ===========================================================================

/// Per-connection SMB state and message engine (← `struct smb_conn`).
///
/// Owns the send/receive scratch buffers, the authenticated session identity
/// (`uid`, `session_key`), the server `challenge`, and the parsed
/// credentials/share. All wire building, parsing, and the NEGOTIATE→SETUP
/// handshake live here.
#[derive(Debug)]
pub struct SmbConn {
    /// Current connection-level state.
    pub state: SmbConnState,
    /// Authentication user (after any `DOMAIN\`/`DOMAIN/` split).
    user: String,
    /// Authentication domain (the part before the slash, or the host name).
    domain: String,
    /// Authentication password (used to derive the NTLMv1 LM/NT responses).
    passwd: String,
    /// Server host name, used to build the `\\host\share` UNC path.
    host: String,
    /// The share parsed from the URL path (`Some` once `setup_connection`
    /// succeeds). `smb_do` returns `CURLE_URL_MALFORMAT` when this is `None`.
    pub share: Option<String>,
    /// The 8-byte NTLM challenge extracted from the NEGOTIATE response.
    challenge: [u8; 8],
    /// The server session key from the NEGOTIATE response (echoed in SETUP).
    session_key: u32,
    /// The user id assigned by the server in the SESSION SETUP response.
    pub uid: u16,
    /// Receive buffer (`recv_buf`, capacity `MAX_MESSAGE_SIZE`).
    recv_buf: Vec<u8>,
    /// Number of valid bytes currently accumulated in `recv_buf` (`got`).
    got: usize,
}

/// Per-request SMB state (← `struct smb_request`).
///
/// Tracks the request state machine, the tree/file ids, and the transfer
/// bookkeeping (offset/size/bytecount) that curl keeps in `data->req`.
#[derive(Debug)]
pub struct SmbRequest {
    /// Current request-level state.
    pub state: SmbReqState,
    /// The file path within the share, using SMB backslash separators.
    pub path: String,
    /// The tree id returned by TREE CONNECT.
    pub tid: u16,
    /// The file id returned by NT_CREATE_ANDX.
    pub fid: u16,
    /// Whether this request uploads (`true`) or downloads (`false`).
    upload: bool,
    /// For uploads, the known input size (`data->state.infilesize`); SMB
    /// requires the size up front and errors otherwise.
    infilesize: i64,
    /// Current byte offset into the file (`data->req.offset`).
    offset: u64,
    /// Total transfer size (download EOF, or upload `infilesize`).
    size: i64,
    /// Bytes transferred so far (`data->req.bytecount`), used by the upload loop.
    bytecount: u64,
    /// Whether the caller requested the file's modification time (`-R`).
    get_filetime: bool,
    /// The POSIX modification time decoded from NT_CREATE, when requested.
    filetime: i64,
    /// The final result code, mirroring `req->result`.
    result: CurlCode,
}

// ===========================================================================
// URL path parsing (← `smb_parse_url_path`, `lib/smb.c` L397-438).
// ===========================================================================

/// URL-decode `input` exactly as curl's `Curl_urldecode(..., REJECT_CTRL)` does
/// at the top of `smb_parse_url_path`.
///
/// A `%XX` escape whose two following characters are both hex digits decodes to
/// the corresponding byte; any other `%` (or ordinary character) is taken
/// literally (← curl's `('%' == in) && ISXDIGIT(h1) && ISXDIGIT(h2)` guard).
/// Every resulting byte is then checked: a control byte (`< 0x20`, which
/// includes NUL) invalidates the whole path, exactly as `REJECT_CTRL` makes
/// `Curl_urldecode` return `CURLE_URL_MALFORMAT`.
///
/// Decoding happens *before* the share/file split so percent-encoded
/// separators (`%2F`, `%5C`) resolve to real separators — matching curl — and
/// an undecoded escape can never be smuggled into an SMB message.
///
/// # Errors
///
/// Returns [`CurlCode::UrlMalformat`] when a decoded byte is a control
/// character, or when the decoded bytes are not valid UTF-8 (the SMB path is
/// carried as text here, so a non-UTF-8 path is rejected rather than embedded
/// raw).
fn smb_urldecode_reject_ctrl(input: &str) -> Result<String> {
    // Branch-free single hex digit → nibble (only ever called on bytes already
    // verified with `is_ascii_hexdigit`, so the `_` arm is unreachable).
    let hexval = |b: u8| -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => 0,
        }
    };

    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let byte = if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            let decoded = (hexval(bytes[i + 1]) << 4) | hexval(bytes[i + 2]);
            i += 3;
            decoded
        } else {
            let literal = bytes[i];
            i += 1;
            literal
        };
        // REJECT_CTRL: any control byte (including NUL) invalidates the path.
        if byte < 0x20 {
            return Err(Error::with_context(
                CurlCode::UrlMalformat,
                "control byte in SMB URL path",
            ));
        }
        out.push(byte);
    }

    String::from_utf8(out)
        .map_err(|_| Error::with_context(CurlCode::UrlMalformat, "non-UTF-8 byte in SMB URL path"))
}

/// Parse an SMB URL path into `(share, file_path)` (← `smb_parse_url_path`).
///
/// `url_path` is first URL-decoded with control-byte rejection
/// ([`smb_urldecode_reject_ctrl`], ← curl's `Curl_urldecode(..., REJECT_CTRL)`),
/// then interpreted as `[/]share/file/path`: an optional leading `/` or `\` is
/// stripped, the first subsequent `/` or `\` separates the share from the file
/// path, and every forward slash in the file path is converted to a backslash.
/// The share is mandatory — a path with no separator after the share yields
/// `CURLE_URL_MALFORMAT`, exactly as curl's "missing share in URL path".
///
/// # Errors
///
/// Returns [`CurlCode::UrlMalformat`] when the decoded path contains a control
/// byte (`REJECT_CTRL`), is not valid UTF-8, or contains no share separator.
pub fn parse_url_path(url_path: &str) -> Result<(String, String)> {
    // URL-decode with REJECT_CTRL *first* (← the `Curl_urldecode` at the top of
    // `smb_parse_url_path`), so percent-encoded separators resolve to real
    // separators and control bytes are rejected before the share/file split.
    let decoded = smb_urldecode_reject_ctrl(url_path)?;

    // Strip a single leading slash/backslash (`(*path=='/'||*path=='\\') ? path+1 : path`).
    let stripped = match decoded.as_bytes().first() {
        Some(b'/') | Some(b'\\') => &decoded[1..],
        _ => decoded.as_str(),
    };

    // The share ends at the first '/' or '\\'; the remainder is the file path.
    let Some(sep) = stripped.find(['/', '\\']) else {
        return Err(Error::with_context(
            CurlCode::UrlMalformat,
            "missing share in URL path for SMB",
        ));
    };

    let share = stripped[..sep].to_string();
    // `req->path = slash + 1`, with every '/' rewritten to '\\'.
    let path = stripped[sep + 1..].replace('/', "\\");

    Ok((share, path))
}

impl SmbRequest {
    /// Build a fresh request in the initial [`SmbReqState::Requesting`] state
    /// (← `curlx_calloc(1, sizeof(struct smb_request))` plus the transfer
    /// options curl reads from `data`).
    ///
    /// * `path` — the file path within the share (from [`parse_url_path`]).
    /// * `upload` — mirrors `data->state.upload`.
    /// * `infilesize` — mirrors `data->state.infilesize` (`< 0` if unknown).
    /// * `get_filetime` — mirrors `data->set.get_filetime` (`-R`).
    #[must_use]
    pub fn new(path: String, upload: bool, infilesize: i64, get_filetime: bool) -> Self {
        SmbRequest {
            state: SmbReqState::Requesting,
            path,
            tid: 0,
            fid: 0,
            upload,
            infilesize,
            offset: 0,
            size: 0,
            bytecount: 0,
            get_filetime,
            filetime: 0,
            result: CurlCode::Ok,
        }
    }

    /// The decoded POSIX modification time captured during NT_CREATE, if the
    /// caller requested it (`get_filetime`); otherwise `0` (← `data->info.filetime`).
    #[must_use]
    pub fn filetime(&self) -> i64 {
        self.filetime
    }
}

impl SmbConn {
    /// Build the per-connection state from a [`Connection`] and the share parsed
    /// from the URL (← `smb_connect`, `lib/smb.c` L464-507, composed with the
    /// share half of `smb_setup_connection`).
    ///
    /// Reproduces curl's credential handling exactly (see
    /// [`from_request`](Self::from_request), to which this thin adapter
    /// delegates after pulling the credentials and host off `conn`):
    /// * A username is required — its absence maps to `CURLE_LOGIN_DENIED`
    ///   (curl's `if(!data->state.aptr.user) return CURLE_LOGIN_DENIED;`).
    /// * If the username contains a `/` or `\`, the part before it is the
    ///   domain and the part after is the user; otherwise the user is taken
    ///   verbatim and the domain defaults to the connection host name.
    ///
    /// # Errors
    ///
    /// Returns [`CurlCode::LoginDenied`] when the connection carries no username.
    pub fn from_connection(conn: &Connection, share: String) -> Result<Self> {
        Self::from_request(
            conn.user.as_deref(),
            conn.passwd.as_deref(),
            &conn.host.name,
            share,
        )
    }

    /// Build the per-connection state from the raw request parts the
    /// [`SmbHandler`] reads off a [`TransferCtx`] — the username, password,
    /// target host, and the share parsed from the URL — reproducing
    /// `smb_connect`'s credential handling exactly (← `smb_connect`,
    /// `lib/smb.c` L464-507):
    ///
    /// * A username is required — its absence, or an empty string, maps to
    ///   `CURLE_LOGIN_DENIED` (curl's `if(!data->state.aptr.user) ...`).
    /// * If the username contains a `/` or `\`, the part before it is the
    ///   domain and the part after is the user; otherwise the user is taken
    ///   verbatim and the domain defaults to `host`.
    ///
    /// # Errors
    ///
    /// Returns [`CurlCode::LoginDenied`] when `user` is `None` or empty.
    pub fn from_request(
        user: Option<&str>,
        passwd: Option<&str>,
        host: &str,
        share: String,
    ) -> Result<Self> {
        // "Check we have a username ... to authenticate with".
        let raw_user = user
            .filter(|u| !u.is_empty())
            .ok_or_else(|| Error::from(CurlCode::LoginDenied))?;

        let host = host.to_string();

        // Split "DOMAIN\user" / "DOMAIN/user"; else user verbatim, domain = host.
        let (user, domain) = match raw_user.find(['/', '\\']) {
            Some(idx) => (raw_user[idx + 1..].to_string(), raw_user[..idx].to_string()),
            None => (raw_user.to_string(), host.clone()),
        };

        Ok(SmbConn {
            state: SmbConnState::Connecting,
            user,
            domain,
            passwd: passwd.unwrap_or_default().to_string(),
            host,
            share: Some(share),
            challenge: [0u8; 8],
            session_key: 0,
            uid: 0,
            recv_buf: vec![0u8; MAX_MESSAGE_SIZE],
            got: 0,
        })
    }

    // -----------------------------------------------------------------------
    // Header framing (← `smb_format_message` / `smb_send_message`, `lib/smb.c`
    // L571-589 / L633-648).
    // -----------------------------------------------------------------------

    /// Build the 36-byte NetBIOS+SMB framing header for a message whose body is
    /// `body_len` bytes (← `smb_format_message`). `body_len` is the length of
    /// the command body that follows this header.
    fn format_header(uid: u16, tid: u16, cmd: u8, body_len: usize) -> [u8; SMB_HEADER_LEN] {
        let mut h = [0u8; SMB_HEADER_LEN];

        // nbt_type (@0) and nbt_flags (@1) are 0 (NetBIOS SESSION MESSAGE).
        // nbt_length (@2, big-endian) = SMB header (32) + body length.
        let nbt_len = (SMB_HEADER_LEN - NETBIOS_HEADER_LEN + body_len) as u16;
        h[2..4].copy_from_slice(&nbt_len.to_be_bytes());

        // magic (@4) = 0xFF 'S' 'M' 'B'.
        h[4..8].copy_from_slice(&[0xff, b'S', b'M', b'B']);

        // command (@8); status (@9..13) stays 0.
        h[8] = cmd;

        // flags (@13); flags2 (@14, little-endian).
        h[13] = SMB_FLAGS_CANONICAL_PATHNAMES | SMB_FLAGS_CASELESS_PATHNAMES;
        h[14..16]
            .copy_from_slice(&(SMB_FLAGS2_IS_LONG_NAME | SMB_FLAGS2_KNOWS_LONG_NAME).to_le_bytes());

        // pid_high (@16, little-endian) = high 16 bits of the made-up PID.
        h[16..18].copy_from_slice(&((SMB_PID >> 16) as u16).to_le_bytes());

        // signature (@18..26) and pad (@26..28) stay 0.
        // tid (@28), pid low (@30), uid (@32) — all little-endian; mid (@34) = 0.
        h[28..30].copy_from_slice(&tid.to_le_bytes());
        h[30..32].copy_from_slice(&((SMB_PID & 0xffff) as u16).to_le_bytes());
        h[32..34].copy_from_slice(&uid.to_le_bytes());

        h
    }

    /// Frame a complete SMB message: the 36-byte header followed by `body`
    /// (← `smb_send_message`, which formats the header then copies the body).
    fn frame_message(&self, tid: u16, cmd: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(SMB_HEADER_LEN + body.len());
        out.extend_from_slice(&Self::format_header(self.uid, tid, cmd, body.len()));
        out.extend_from_slice(body);
        out
    }

    // -----------------------------------------------------------------------
    // Message builders. Each returns the full wire bytes ready to send. Every
    // multi-byte integer is little-endian (packed with `to_le_bytes`); the sole
    // big-endian field, the NetBIOS length, is written by `format_header`.
    // The `char bytes[1024]` guards in curl map to `CURLE_FILESIZE_EXCEEDED`.
    // -----------------------------------------------------------------------

    /// Maximum size of the variable `bytes[]` trailer in the fixed-layout C
    /// message structs (`char bytes[1024]`). Overflowing it is
    /// `CURLE_FILESIZE_EXCEEDED` in curl.
    const MAX_VARIABLE_BYTES: usize = 1024;

    /// NEGOTIATE (← `smb_send_negotiate`, `lib/smb.c` L650-657). The body is the
    /// fixed 15-byte dialect list offering only `NT LM 0.12` (including its
    /// trailing NUL, which C takes from the string literal).
    fn build_negotiate(&self, req: &SmbRequest) -> Vec<u8> {
        // word_count(0) | byte_count(0x000c) | dialect_format(0x02) | "NT LM 0.12\0"
        const BODY: [u8; 15] = [
            0x00, 0x0c, 0x00, 0x02, b'N', b'T', b' ', b'L', b'M', b' ', b'0', b'.', b'1', b'2',
            0x00,
        ];
        self.frame_message(req.tid, SMB_COM_NEGOTIATE, &BODY)
    }

    /// SESSION SETUP ANDX with NTLMv1 (← `smb_send_setup`, `lib/smb.c` L659-712).
    ///
    /// Builds the raw NTLMv1 LM and NT responses from the password and the
    /// server challenge using this handler's self-contained `ntlm` primitives,
    /// then embeds them (24 bytes each) followed by
    /// `user\0domain\0OS\0clientname\0`.
    ///
    /// # Errors
    ///
    /// [`CurlCode::FilesizeExceeded`] if the trailer exceeds the C `bytes[1024]`.
    fn build_setup(&self, req: &SmbRequest) -> Result<Vec<u8>> {
        // Raw NTLMv1 responses (DESL of the LM/NT hashes over the challenge),
        // exactly as `smb_send_setup` computes them via Curl_ntlm_core_*.
        let lm = ntlm::lm_resp(&ntlm::mk_lm_hash(&self.passwd), &self.challenge);
        let nt = ntlm::lm_resp(&ntlm::mk_nt_hash(&self.passwd), &self.challenge);

        // Variable trailer: lm(24) || nt(24) || user\0 || domain\0 || OS\0 || clientname\0
        let mut var = Vec::with_capacity(
            lm.len()
                + nt.len()
                + self.user.len()
                + self.domain.len()
                + CLIENT_OS.len()
                + CLIENTNAME.len()
                + 4,
        );
        var.extend_from_slice(&lm);
        var.extend_from_slice(&nt);
        var.extend_from_slice(self.user.as_bytes());
        var.push(0);
        var.extend_from_slice(self.domain.as_bytes());
        var.push(0);
        var.extend_from_slice(CLIENT_OS.as_bytes());
        var.push(0);
        var.extend_from_slice(CLIENTNAME.as_bytes());
        var.push(0);

        let byte_count = var.len();
        if byte_count > Self::MAX_VARIABLE_BYTES {
            return Err(Error::from(CurlCode::FilesizeExceeded));
        }

        // Fixed 29-byte parameter block.
        let mut body = Vec::with_capacity(29 + byte_count);
        body.push(SMB_WC_SETUP_ANDX); // word_count @0
        body.push(SMB_COM_NO_ANDX_COMMAND); // andx.command @1
        body.push(0); // andx.pad @2
        body.extend_from_slice(&0u16.to_le_bytes()); // andx.offset @3
        body.extend_from_slice(&(MAX_MESSAGE_SIZE as u16).to_le_bytes()); // max_buffer_size @5
        body.extend_from_slice(&1u16.to_le_bytes()); // max_mpx_count @7
        body.extend_from_slice(&1u16.to_le_bytes()); // vc_number @9
        body.extend_from_slice(&self.session_key.to_le_bytes()); // session_key @11
        body.extend_from_slice(&24u16.to_le_bytes()); // lengths[0] = LM response len @15
        body.extend_from_slice(&24u16.to_le_bytes()); // lengths[1] = NT response len @17
        body.extend_from_slice(&0u32.to_le_bytes()); // pad @19
        body.extend_from_slice(&SMB_CAP_LARGE_FILES.to_le_bytes()); // capabilities @23
        body.extend_from_slice(&(byte_count as u16).to_le_bytes()); // byte_count @27
        body.extend_from_slice(&var); // bytes @29

        Ok(self.frame_message(req.tid, SMB_COM_SETUP_ANDX, &body))
    }

    /// TREE CONNECT ANDX to `\\host\share` (← `smb_send_tree_connect`,
    /// `lib/smb.c` L714-743). The trailer is `\\host\share\0?????\0`.
    ///
    /// # Errors
    ///
    /// [`CurlCode::FilesizeExceeded`] if the trailer exceeds the C `bytes[1024]`.
    fn build_tree_connect(&self, req: &SmbRequest) -> Result<Vec<u8>> {
        let share = self.share.as_deref().unwrap_or_default();

        // Trailer: "\\{host}\{share}\0{SERVICENAME}\0".
        let mut var = Vec::with_capacity(self.host.len() + share.len() + SERVICENAME.len() + 5);
        var.extend_from_slice(b"\\\\");
        var.extend_from_slice(self.host.as_bytes());
        var.push(b'\\');
        var.extend_from_slice(share.as_bytes());
        var.push(0);
        var.extend_from_slice(SERVICENAME.as_bytes());
        var.push(0);

        let byte_count = var.len();
        if byte_count > Self::MAX_VARIABLE_BYTES {
            return Err(Error::from(CurlCode::FilesizeExceeded));
        }

        // Fixed 11-byte parameter block.
        let mut body = Vec::with_capacity(11 + byte_count);
        body.push(SMB_WC_TREE_CONNECT_ANDX); // word_count @0
        body.push(SMB_COM_NO_ANDX_COMMAND); // andx.command @1
        body.push(0); // andx.pad @2
        body.extend_from_slice(&0u16.to_le_bytes()); // andx.offset @3
        body.extend_from_slice(&0u16.to_le_bytes()); // flags @5
        body.extend_from_slice(&0u16.to_le_bytes()); // pw_len @7
        body.extend_from_slice(&(byte_count as u16).to_le_bytes()); // byte_count @9
        body.extend_from_slice(&var); // bytes @11

        Ok(self.frame_message(req.tid, SMB_COM_TREE_CONNECT_ANDX, &body))
    }

    /// NT_CREATE_ANDX to open the file for read or write (← `smb_send_open`,
    /// `lib/smb.c` L745-773). Upload opens `READ|WRITE` with `OVERWRITE_IF`;
    /// download opens `READ` with `FILE_OPEN`.
    ///
    /// # Errors
    ///
    /// [`CurlCode::FilesizeExceeded`] if the path + NUL exceeds the C `bytes[1024]`.
    fn build_open(&self, req: &SmbRequest) -> Result<Vec<u8>> {
        let path_bytes = req.path.as_bytes();
        let byte_count = path_bytes.len() + 1; // path + trailing NUL
        if byte_count > Self::MAX_VARIABLE_BYTES {
            return Err(Error::from(CurlCode::FilesizeExceeded));
        }

        let (access, disposition) = if req.upload {
            (SMB_GENERIC_READ | SMB_GENERIC_WRITE, SMB_FILE_OVERWRITE_IF)
        } else {
            (SMB_GENERIC_READ, SMB_FILE_OPEN)
        };

        // Fixed 51-byte parameter block.
        let mut body = Vec::with_capacity(51 + byte_count);
        body.push(SMB_WC_NT_CREATE_ANDX); // word_count @0
        body.push(SMB_COM_NO_ANDX_COMMAND); // andx.command @1
        body.push(0); // andx.pad @2
        body.extend_from_slice(&0u16.to_le_bytes()); // andx.offset @3
        body.push(0); // pad @5
        body.extend_from_slice(&((byte_count - 1) as u16).to_le_bytes()); // name_length @6
        body.extend_from_slice(&0u32.to_le_bytes()); // flags @8
        body.extend_from_slice(&0u32.to_le_bytes()); // root_fid @12
        body.extend_from_slice(&access.to_le_bytes()); // access @16
        body.extend_from_slice(&0i64.to_le_bytes()); // allocation_size @20 (curl_off_t)
        body.extend_from_slice(&0u32.to_le_bytes()); // ext_file_attributes @28
        body.extend_from_slice(&SMB_FILE_SHARE_ALL.to_le_bytes()); // share_access @32
        body.extend_from_slice(&disposition.to_le_bytes()); // create_disposition @36
        body.extend_from_slice(&0u32.to_le_bytes()); // create_options @40
        body.extend_from_slice(&0u32.to_le_bytes()); // impersonation_level @44
        body.push(0); // security_flags @48
        body.extend_from_slice(&(byte_count as u16).to_le_bytes()); // byte_count @49
        body.extend_from_slice(path_bytes); // bytes @51: path
        body.push(0); // trailing NUL

        Ok(self.frame_message(req.tid, SMB_COM_NT_CREATE_ANDX, &body))
    }

    /// READ_ANDX for `MAX_PAYLOAD_SIZE` bytes at `req.offset` (← `smb_send_read`,
    /// `lib/smb.c` L798-816).
    fn build_read(&self, req: &SmbRequest) -> Vec<u8> {
        let offset = req.offset;

        // struct smb_read, 27 bytes.
        let mut body = Vec::with_capacity(27);
        body.push(SMB_WC_READ_ANDX); // word_count @0
        body.push(SMB_COM_NO_ANDX_COMMAND); // andx.command @1
        body.push(0); // andx.pad @2
        body.extend_from_slice(&0u16.to_le_bytes()); // andx.offset @3
        body.extend_from_slice(&req.fid.to_le_bytes()); // fid @5
        body.extend_from_slice(&(offset as u32).to_le_bytes()); // offset (low) @7
        body.extend_from_slice(&(MAX_PAYLOAD_SIZE as u16).to_le_bytes()); // max_bytes @11
        body.extend_from_slice(&(MAX_PAYLOAD_SIZE as u16).to_le_bytes()); // min_bytes @13
        body.extend_from_slice(&0u32.to_le_bytes()); // timeout @15
        body.extend_from_slice(&0u16.to_le_bytes()); // remaining @19
        body.extend_from_slice(&((offset >> 32) as u32).to_le_bytes()); // offset_high @21
        body.extend_from_slice(&0u16.to_le_bytes()); // byte_count @25

        self.frame_message(req.tid, SMB_COM_READ_ANDX, &body)
    }

    /// The 68-byte WRITE_ANDX header for `upload_size` payload bytes
    /// (← `smb_send_write`, `lib/smb.c` L818-844). Unlike the other builders,
    /// `struct smb_write` embeds the SMB header, and the payload bytes are
    /// streamed by the caller immediately after this 68-byte prefix.
    fn build_write_header(&self, req: &SmbRequest, upload_size: usize) -> Vec<u8> {
        let offset = req.offset;

        // The header's body length = sizeof(*msg) - sizeof(h) + upload_size.
        let body_after_header = 32 + upload_size;
        let mut msg =
            Self::format_header(self.uid, req.tid, SMB_COM_WRITE_ANDX, body_after_header).to_vec();

        // 32-byte parameter block after the 36-byte header.
        msg.push(SMB_WC_WRITE_ANDX); // word_count @36
        msg.push(SMB_COM_NO_ANDX_COMMAND); // andx.command @37
        msg.push(0); // andx.pad @38
        msg.extend_from_slice(&0u16.to_le_bytes()); // andx.offset @39
        msg.extend_from_slice(&req.fid.to_le_bytes()); // fid @41
        msg.extend_from_slice(&(offset as u32).to_le_bytes()); // offset (low) @43
        msg.extend_from_slice(&0u32.to_le_bytes()); // timeout @47
        msg.extend_from_slice(&0u16.to_le_bytes()); // write_mode @51
        msg.extend_from_slice(&0u16.to_le_bytes()); // remaining @53
        msg.extend_from_slice(&0u16.to_le_bytes()); // pad @55
        msg.extend_from_slice(&(upload_size as u16).to_le_bytes()); // data_length @57
        msg.extend_from_slice(&64u16.to_le_bytes()); // data_offset = sizeof(*msg)-4 @59
        msg.extend_from_slice(&((offset >> 32) as u32).to_le_bytes()); // offset_high @61
        msg.extend_from_slice(&((upload_size + 1) as u16).to_le_bytes()); // byte_count @65
        msg.push(0); // pad2 @67

        msg
    }

    /// CLOSE the open file id (← `smb_send_close`, `lib/smb.c` L775-786).
    fn build_close(&self, req: &SmbRequest) -> Vec<u8> {
        // struct smb_close, 9 bytes.
        let mut body = Vec::with_capacity(9);
        body.push(SMB_WC_CLOSE); // word_count @0
        body.extend_from_slice(&req.fid.to_le_bytes()); // fid @1
        body.extend_from_slice(&0u32.to_le_bytes()); // last_mtime @3
        body.extend_from_slice(&0u16.to_le_bytes()); // byte_count @7

        self.frame_message(req.tid, SMB_COM_CLOSE, &body)
    }

    /// TREE DISCONNECT (← `smb_send_tree_disconnect`, `lib/smb.c` L788-796). The
    /// whole struct is zeroed, so `word_count` is 0 (curl does not set it).
    fn build_tree_disconnect(&self, req: &SmbRequest) -> Vec<u8> {
        // struct smb_tree_disconnect, 3 bytes (word_count = 0, byte_count = 0).
        let mut body = Vec::with_capacity(3);
        body.push(0); // word_count @0
        body.extend_from_slice(&0u16.to_le_bytes()); // byte_count @1

        self.frame_message(req.tid, SMB_COM_TREE_DISCONNECT, &body)
    }

    // -----------------------------------------------------------------------
    // Receiving and framing (← `smb_recv_message` / `smb_pop_message`,
    // `lib/smb.c` L509-568).
    // -----------------------------------------------------------------------

    /// Read from `stream` into the receive buffer until a complete NetBIOS/SMB
    /// message is present, then return its size in bytes (← `smb_recv_message`).
    ///
    /// After this returns `Ok(n)`, the message occupies `self.recv_buf[..self.got]`
    /// and `self.got >= n`. Call [`SmbConn::pop_message`] once processing is done.
    ///
    /// # Errors
    ///
    /// [`CurlCode::RecvError`] on a malformed frame, an oversized message, or an
    /// unexpected end of stream.
    async fn recv_message<S>(&mut self, stream: &mut S) -> Result<usize>
    where
        S: AsyncRead + Unpin + ?Sized,
    {
        loop {
            if let Some(nbt_size) = frame_complete(&self.recv_buf, self.got)? {
                return Ok(nbt_size);
            }
            if self.got >= self.recv_buf.len() {
                return Err(Error::with_context(
                    CurlCode::RecvError,
                    "SMB message exceeds maximum size",
                ));
            }
            let n = stream
                .read(&mut self.recv_buf[self.got..])
                .await
                .map_err(|_| Error::from(CurlCode::RecvError))?;
            if n == 0 {
                // End of stream before a full message arrived.
                return Err(Error::from(CurlCode::RecvError));
            }
            self.got += n;
        }
    }

    /// Discard the current message so the next one can be received
    /// (← `smb_pop_message`, which resets `smbc->got` to 0).
    fn pop_message(&mut self) {
        self.got = 0;
    }

    /// Send all `bytes` on `stream`, mapping any I/O error to
    /// [`CurlCode::SendError`]. Tokio's `write_all` transparently handles
    /// partial writes, subsuming curl's manual `smb_flush` send-size bookkeeping.
    async fn send_all<S>(stream: &mut S, bytes: &[u8]) -> Result<()>
    where
        S: AsyncWrite + Unpin + ?Sized,
    {
        stream
            .write_all(bytes)
            .await
            .map_err(|_| Error::from(CurlCode::SendError))
    }
}

// ===========================================================================
// SMB header / response field accessors. Offsets are relative to the start of
// the NetBIOS frame (`msg[0]`); the SMB header occupies `msg[0..36]`.
// ===========================================================================

/// The 32-bit SMB `status` field (`msg[9..13]`, little-endian on the wire). A
/// non-zero value is an error; curl compares it directly (including against the
/// little-endian `SMB_ERR_NOACCESS`).
#[inline]
fn header_status(msg: &[u8]) -> Result<u32> {
    le_u32(msg, 9)
}

/// The SMB `uid` field (`msg[32..34]`), captured after SESSION SETUP.
#[inline]
fn header_uid(msg: &[u8]) -> Result<u16> {
    le_u16(msg, 32)
}

/// The SMB `tid` field (`msg[28..30]`), captured after TREE CONNECT.
#[inline]
fn header_tid(msg: &[u8]) -> Result<u16> {
    le_u16(msg, 28)
}

/// Determine whether a NetBIOS/SMB message of `got` accumulated bytes in `buf`
/// is complete, returning its total size (← the framing logic inside
/// `smb_recv_message`, `lib/smb.c` L523-559).
///
/// Returns `Ok(Some(nbt_size))` when a whole message is buffered, `Ok(None)`
/// when more bytes are required, or [`CurlCode::RecvError`] for a frame whose
/// declared size is out of range or internally inconsistent.
fn frame_complete(buf: &[u8], got: usize) -> Result<Option<usize>> {
    // A 32-bit NetBIOS header is needed before the length can be read.
    if got < NETBIOS_HEADER_LEN {
        return Ok(None);
    }

    // nbt_size = big-endian 16-bit length (at offset 2) + the 4-byte header.
    let nbt_size = be_u16(buf, 2)? as usize + NETBIOS_HEADER_LEN;
    if nbt_size > MAX_MESSAGE_SIZE {
        return Err(Error::with_context(
            CurlCode::RecvError,
            "too large NetBIOS frame size",
        ));
    }
    if nbt_size < SMB_HEADER_LEN {
        return Err(Error::with_context(
            CurlCode::RecvError,
            "too small NetBIOS frame size",
        ));
    }
    if got < nbt_size {
        return Ok(None);
    }

    // Validate the declared size against the word-count and byte-count fields.
    // curl writes `nbt_size >= msg_size + 1`; `nbt_size > msg_size` is the
    // identical integer predicate (there is room for the word-count byte).
    let mut msg_size = SMB_HEADER_LEN;
    if nbt_size > msg_size {
        // The word-count byte lives at `msg_size`; validate it is buffered
        // (checked read) before deriving the parameter-block length from this
        // untrusted count, so a malformed frame cannot advance the offset past
        // the buffer.
        let word_count = *buf.get(msg_size).ok_or_else(short_frame)? as usize;
        msg_size += 1 + word_count * 2;
        if nbt_size >= msg_size + 2 {
            // The 16-bit byte-count follows the parameter block; the checked
            // read validates the derived offset before indexing.
            msg_size += 2 + le_u16(buf, msg_size)? as usize;
            if nbt_size < msg_size {
                return Err(Error::with_context(
                    CurlCode::RecvError,
                    "inconsistent NetBIOS frame size",
                ));
            }
        }
    }

    Ok(Some(nbt_size))
}

/// Parse a NEGOTIATE response into `(challenge, session_key)` (← the
/// `SMB_NEGOTIATE` arm of `smb_connection_state`, `lib/smb.c` L933-951).
///
/// Requires the response to be at least `sizeof(smb_negotiate_response) +
/// sizeof(challenge) - 1` bytes (74 + 8 - 1 = 81) with a zero status; the
/// 8-byte challenge lives in the trailing `bytes[]` at offset 73 and the
/// session key at offset 52.
///
/// # Errors
///
/// [`CurlCode::CouldntConnect`] if the response is short or reports an error.
fn parse_negotiate_response(msg: &[u8], got: usize) -> Result<([u8; 8], u32)> {
    if got < SMB_NEGOTIATE_RESPONSE_LEN + 8 - 1 || header_status(msg)? != 0 {
        return Err(Error::with_context(
            CurlCode::CouldntConnect,
            "SMB: negotiation failed",
        ));
    }
    let mut challenge = [0u8; 8];
    challenge.copy_from_slice(msg.get(73..81).ok_or_else(short_frame)?);
    let session_key = le_u32(msg, 52)?;
    Ok((challenge, session_key))
}

/// The file id from an NT_CREATE response (`msg[42..44]`).
#[inline]
fn nt_create_fid(msg: &[u8]) -> Result<u16> {
    le_u16(msg, 42)
}

/// The end-of-file (file size) from an NT_CREATE response (`msg[92..100]`).
#[inline]
fn nt_create_end_of_file(msg: &[u8]) -> Result<i64> {
    le_i64(msg, 92)
}

/// The last-change time (Windows FILETIME) from an NT_CREATE response
/// (`msg[72..80]`).
#[inline]
fn nt_create_last_change_time(msg: &[u8]) -> Result<i64> {
    le_i64(msg, 72)
}

/// The `data_length` from a READ_ANDX response (`msg[header + 11]`).
#[inline]
fn read_andx_len(msg: &[u8]) -> Result<u16> {
    le_u16(msg, SMB_HEADER_LEN + 11)
}

/// The `data_offset` from a READ_ANDX response (`msg[header + 13]`), measured
/// from the start of the SMB header.
#[inline]
fn read_andx_off(msg: &[u8]) -> Result<u16> {
    le_u16(msg, SMB_HEADER_LEN + 13)
}

/// The `count` (bytes written) from a WRITE_ANDX response (`msg[header + 5]`).
#[inline]
fn write_andx_count(msg: &[u8]) -> Result<u16> {
    le_u16(msg, SMB_HEADER_LEN + 5)
}

/// Convert a Windows FILETIME (100 ns units since 1601-01-01) to POSIX seconds
/// (← `get_posix_time`, `lib/smb.c` L1187-1200). Timestamps before the Unix
/// epoch — and the sentinel `0` — map to `0`. On the supported 64-bit `time_t`
/// targets no saturation is required.
fn get_posix_time(timestamp: i64) -> i64 {
    /// 100 ns units between 1601-01-01 and 1970-01-01.
    const EPOCH_OFFSET: i64 = 116_444_736_000_000_000;
    if timestamp >= EPOCH_OFFSET {
        (timestamp - EPOCH_OFFSET) / 10_000_000
    } else {
        0
    }
}

// ===========================================================================
// Async drivers. These are the concrete realisations of curl's `connecting`
// (`smb_connection_state`) and `doing` (`smb_request_state`) hooks, expressed
// as `async` loops over a generic transport. curl advances one state per multi
// iteration; because a Rust future can `.await` I/O directly, the equivalent
// logic collapses into a straight-line send/recv sequence with the identical
// message order, byte layout, and error mapping.
// ===========================================================================

impl SmbConn {
    /// Drive the NEGOTIATE → SESSION SETUP handshake to
    /// [`SmbConnState::Connected`] (← `smb_connection_state`, `lib/smb.c`
    /// L883-974).
    ///
    /// For `smbs`, `stream` is already TLS-wrapped by the connection filter
    /// chain — mirroring curl, which completes TLS via `Curl_conn_connect`
    /// before sending NEGOTIATE, and then speaks plain SMB over the secure
    /// channel.
    ///
    /// # Errors
    ///
    /// [`CurlCode::CouldntConnect`] if NEGOTIATE fails, [`CurlCode::LoginDenied`]
    /// if authentication is rejected, or [`CurlCode::SendError`]/
    /// [`CurlCode::RecvError`] on transport failures.
    pub async fn run_connect<S>(&mut self, req: &SmbRequest, stream: &mut S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
        self.state = SmbConnState::Connecting;

        // NEGOTIATE — offer only the `NT LM 0.12` dialect.
        let negotiate = self.build_negotiate(req);
        Self::send_all(stream, &negotiate).await?;
        self.state = SmbConnState::Negotiate;

        self.recv_message(stream).await?;
        let got = self.got;
        let (challenge, session_key) = parse_negotiate_response(&self.recv_buf[..got], got)?;
        self.challenge = challenge;
        self.session_key = session_key;
        self.pop_message();

        // SESSION SETUP ANDX with the raw NTLMv1 responses.
        let setup = self.build_setup(req)?;
        Self::send_all(stream, &setup).await?;
        self.state = SmbConnState::Setup;

        self.recv_message(stream).await?;
        let got = self.got;
        if header_status(&self.recv_buf[..got])? != 0 {
            return Err(Error::with_context(
                CurlCode::LoginDenied,
                "SMB: authentication failed",
            ));
        }
        self.uid = header_uid(&self.recv_buf[..got])?;
        self.state = SmbConnState::Connected;
        self.pop_message();

        Ok(())
    }

    /// Drive the request state machine from TREE CONNECT through DONE
    /// (← `smb_request_state`, `lib/smb.c` L998-1185).
    ///
    /// * `write_body` receives downloaded file bytes (← `Curl_client_write`,
    ///   `CLIENTWRITE_BODY`).
    /// * `read_src` supplies upload bytes (← `Curl_client_read`); it fills the
    ///   provided buffer and returns the number of bytes produced (0 = EOF).
    ///
    /// # Errors
    ///
    /// The mapped `CURLE_*` code for a failed request: `CURLE_REMOTE_FILE_NOT_FOUND`
    /// / `CURLE_REMOTE_ACCESS_DENIED` (tree connect / open), `CURLE_WEIRD_SERVER_REPLY`
    /// (negative size), `CURLE_RECV_ERROR` (download), `CURLE_UPLOAD_FAILED`
    /// (upload), or `CURLE_SEND_ERROR` (missing upload size).
    pub async fn run_request<S, WB, RS>(
        &mut self,
        req: &mut SmbRequest,
        stream: &mut S,
        mut write_body: WB,
        mut read_src: RS,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + ?Sized,
        WB: FnMut(&[u8]) -> Result<()>,
        RS: FnMut(&mut [u8]) -> Result<usize>,
    {
        // "SMB upload needs to know the size up front" (← the infilesize guard).
        if req.upload && req.infilesize < 0 {
            return Err(Error::with_context(
                CurlCode::SendError,
                "SMB upload needs to know the size up front",
            ));
        }

        // Kick off the request with TREE CONNECT.
        let tree_connect = self.build_tree_connect(req)?;
        Self::send_all(stream, &tree_connect).await?;
        req.state = SmbReqState::TreeConnect;

        loop {
            // Receive the response to the message just sent.
            self.recv_message(stream).await?;
            let got = self.got;
            let status = header_status(&self.recv_buf[..got])?;

            // Process the response for the current state, deciding the next one.
            let next = match req.state {
                SmbReqState::TreeConnect => {
                    if status != 0 {
                        req.result = Self::access_error(status);
                        SmbReqState::Done
                    } else {
                        req.tid = header_tid(&self.recv_buf[..got])?;
                        SmbReqState::Open
                    }
                }
                SmbReqState::Open => {
                    if status != 0 || got < SMB_NT_CREATE_RESPONSE_LEN {
                        req.result = Self::access_error(status);
                        SmbReqState::TreeDisconnect
                    } else {
                        req.fid = nt_create_fid(&self.recv_buf[..got])?;
                        req.offset = 0;
                        if req.upload {
                            req.size = req.infilesize;
                            SmbReqState::Upload
                        } else {
                            let eof = nt_create_end_of_file(&self.recv_buf[..got])?;
                            req.size = eof;
                            if eof < 0 {
                                req.result = CurlCode::WeirdServerReply;
                                SmbReqState::Close
                            } else {
                                if req.get_filetime {
                                    let raw = nt_create_last_change_time(&self.recv_buf[..got])?;
                                    req.filetime = get_posix_time(raw);
                                }
                                SmbReqState::Download
                            }
                        }
                    }
                }
                SmbReqState::Download => {
                    if status != 0 || got < SMB_HEADER_LEN + 15 {
                        req.result = CurlCode::RecvError;
                        SmbReqState::Close
                    } else {
                        let len = read_andx_len(&self.recv_buf[..got])? as usize;
                        let off = read_andx_off(&self.recv_buf[..got])? as usize;
                        if len > 0 {
                            // Data begins `sizeof(unsigned int)` past `off`, which is
                            // measured from the SMB header start.
                            if off + NETBIOS_HEADER_LEN + len > got {
                                return Err(Error::with_context(
                                    CurlCode::RecvError,
                                    "Invalid input packet",
                                ));
                            }
                            let start = off + NETBIOS_HEADER_LEN;
                            write_body(&self.recv_buf[start..start + len])?;
                        }
                        req.offset += len as u64;
                        if len < MAX_PAYLOAD_SIZE {
                            SmbReqState::Close
                        } else {
                            SmbReqState::Download
                        }
                    }
                }
                SmbReqState::Upload => {
                    if status != 0 || got < SMB_HEADER_LEN + 7 {
                        req.result = CurlCode::UploadFailed;
                        SmbReqState::Close
                    } else {
                        let len = u64::from(write_andx_count(&self.recv_buf[..got])?);
                        req.bytecount += len;
                        req.offset += len;
                        if req.bytecount >= req.size as u64 {
                            SmbReqState::Close
                        } else {
                            SmbReqState::Upload
                        }
                    }
                }
                // "We do not care if the close failed, proceed to tree disconnect."
                SmbReqState::Close => SmbReqState::TreeDisconnect,
                SmbReqState::TreeDisconnect => SmbReqState::Done,
                // Requesting / Done should never be observed here; mirror curl's
                // "ignore" default by finishing cleanly.
                _ => {
                    self.pop_message();
                    return Ok(());
                }
            };

            self.pop_message();

            // Dispatch the next message (or finish).
            match next {
                SmbReqState::Open => {
                    let msg = self.build_open(req)?;
                    Self::send_all(stream, &msg).await?;
                }
                SmbReqState::Download => {
                    let msg = self.build_read(req);
                    Self::send_all(stream, &msg).await?;
                }
                SmbReqState::Upload => {
                    self.send_write(req, stream, &mut read_src).await?;
                }
                SmbReqState::Close => {
                    let msg = self.build_close(req);
                    Self::send_all(stream, &msg).await?;
                }
                SmbReqState::TreeDisconnect => {
                    let msg = self.build_tree_disconnect(req);
                    Self::send_all(stream, &msg).await?;
                }
                SmbReqState::Done => {
                    req.state = SmbReqState::Done;
                    return if req.result == CurlCode::Ok {
                        Ok(())
                    } else {
                        Err(Error::from(req.result))
                    };
                }
                // Requesting / TreeConnect are never produced as a next state.
                _ => {}
            }

            req.state = next;
        }
    }

    /// Map a non-zero tree-connect/open status to the `CURLE_*` code curl
    /// returns: `SMB_ERR_NOACCESS` → `REMOTE_ACCESS_DENIED`, else
    /// `REMOTE_FILE_NOT_FOUND` (← the identical branch in `smb_request_state`).
    fn access_error(status: u32) -> CurlCode {
        if status == SMB_ERR_NOACCESS {
            CurlCode::RemoteAccessDenied
        } else {
            CurlCode::RemoteFileNotFound
        }
    }

    /// Send one WRITE_ANDX message: the 68-byte header followed by up to
    /// `MAX_PAYLOAD_SIZE - 1` payload bytes pulled from `read_src`
    /// (← `smb_send_write` plus the upload half of `smb_send_and_recv`).
    async fn send_write<S, RS>(
        &mut self,
        req: &SmbRequest,
        stream: &mut S,
        read_src: &mut RS,
    ) -> Result<()>
    where
        S: AsyncWrite + Unpin + ?Sized,
        RS: FnMut(&mut [u8]) -> Result<usize>,
    {
        // upload_size = min(remaining, MAX_PAYLOAD_SIZE - 1); "one byte of padding".
        let remaining = req.size - req.bytecount as i64;
        let upload_size = remaining.clamp(0, (MAX_PAYLOAD_SIZE - 1) as i64) as usize;

        let header = self.build_write_header(req, upload_size);
        Self::send_all(stream, &header).await?;

        // Stream exactly `upload_size` payload bytes from the read source.
        let mut buf = vec![0u8; upload_size];
        let mut sent = 0usize;
        while sent < upload_size {
            let n = read_src(&mut buf[sent..upload_size])?;
            if n == 0 {
                break;
            }
            Self::send_all(stream, &buf[sent..sent + n]).await?;
            sent += n;
        }

        Ok(())
    }
}

// ===========================================================================
// Protocol vtable — SmbHandler (← `Curl_handler_smb` / `Curl_handler_smbs`,
// `lib/smb.c` L1209-1246).
// ===========================================================================

/// The SMB/SMBS behavior implementation, registered as [`HANDLER`] and
/// referenced by both `SCHEME_SMB` and `SCHEME_SMBS` in
/// [`crate::protocols`](crate::protocols).
///
/// curl fills a `struct Curl_handler` with C function pointers; each slot maps
/// onto this type as follows:
///
/// | curl vtable slot                  | realisation                                                              |
/// |-----------------------------------|--------------------------------------------------------------------------|
/// | `setup_connection`                | [`parse_url_path`] (share + path) + [`SmbRequest::new`]                   |
/// | `connect_it`                      | [`SmbConn::from_request`] (buffers, user/domain)                          |
/// | `connecting`                      | [`SmbConn::run_connect`] — NEGOTIATE → SESSION SETUP (NTLMv1)             |
/// | `do_it`                           | [`SmbHandler::do_it`] — drives the connect + request sequence end-to-end  |
/// | `doing`                           | [`SmbConn::run_request`] — TREE CONNECT → OPEN → …/… → DONE               |
/// | `done`                            | `ZERO_NULL` → [`SmbHandler::done`] (no-op)                                |
/// | `proto_pollset` / `doing_pollset` | `FIRSTSOCKET` `IN | OUT` (← `smb_pollset`, `lib/smb.c` L1180-1185)        |
///
/// The connect/request engine ([`SmbConn::run_connect`] and
/// [`SmbConn::run_request`]) operates directly on the connection's live,
/// optionally TLS-wrapped byte stream (`smb` is plain TCP; `smbs` layers the
/// stream through [`crate::tls`]). [`SmbHandler::do_it`] threads that stream
/// off [`TransferCtx::io`](crate::protocols::TransferCtx) and drives the full
/// SMB exchange — deriving the share/credentials from
/// [`TransferCtx::request`](crate::protocols::TransferCtx), then running
/// [`SmbConn::run_connect`] (NEGOTIATE → SESSION SETUP) followed by
/// [`SmbConn::run_request`] (TREE CONNECT → OPEN → READ/WRITE → CLOSE → TREE
/// DISCONNECT) — collapsing curl's per-iteration `connecting`/`doing` state
/// machine into a single straight-line async run, exactly as the other
/// stream-oriented handlers do. Received body bytes are pushed to
/// [`TransferCtx::sink`](crate::protocols::TransferCtx); upload bytes are pulled
/// from [`TransferRequest::body`](crate::protocols::TransferRequest).
#[derive(Debug, Clone, Copy, Default)]
pub struct SmbHandler;

impl Protocol for SmbHandler {
    /// **Required "DO" phase** — the full SMB exchange (← `smb_do` +
    /// `smb_connection_state` + `smb_request_state`, collapsed into one async
    /// run). curl spreads SMB across `setup_connection` (parse the share),
    /// `connect_it` (derive credentials), `connecting` (NEGOTIATE → SESSION
    /// SETUP) and `doing` (TREE CONNECT → OPEN → READ/WRITE → CLOSE → TREE
    /// DISCONNECT); because a Rust future can `.await` the socket directly, this
    /// drives that entire sequence over [`TransferCtx::io`] to completion and
    /// returns `Ok(true)` ("DO phase complete"), exactly like the crate's other
    /// stream-oriented handlers.
    ///
    /// The share and file path come from
    /// [`parse_url_path`] (percent-decoded, control-rejected — curl's
    /// `smb_parse_url_path`); the credentials/host from the
    /// [`TransferCtx::request`] fields ([`SmbConn::from_request`], ←
    /// `smb_connect`). Downloaded bytes are streamed to
    /// [`TransferCtx::sink`]; upload bytes are pulled from the in-memory
    /// [`TransferRequest::body`](crate::protocols::TransferRequest) (SMB needs
    /// the upload size up front, so it is taken from the body length).
    ///
    /// # Errors
    ///
    /// `CURLE_URL_MALFORMAT` (no share / bad path), `CURLE_LOGIN_DENIED`
    /// (missing username or rejected authentication), `CURLE_COULDNT_CONNECT`
    /// (no transport installed), or the request engine's mapped code
    /// (`CURLE_REMOTE_FILE_NOT_FOUND` / `CURLE_REMOTE_ACCESS_DENIED` /
    /// `CURLE_WEIRD_SERVER_REPLY` / `CURLE_RECV_ERROR` / `CURLE_UPLOAD_FAILED` /
    /// `CURLE_SEND_ERROR`).
    fn do_it<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        Box::pin(async move {
            // setup_connection: parse the share + file path from the URL path
            // (percent-decoded with REJECT_CTRL, ← `smb_parse_url_path`).
            let (share, path) = parse_url_path(&ctx.request.path)?;

            // connect_it: derive user/domain/passwd (← `smb_connect`).
            let mut conn = SmbConn::from_request(
                ctx.request.user.as_deref(),
                ctx.request.password.as_deref(),
                &ctx.request.host,
                share,
            )?;

            // Per-request state. SMB requires the upload size up front, so take
            // it from the in-memory body length (← `data->state.infilesize`);
            // downloads leave it unknown (`-1`).
            let upload = ctx.request.upload;
            let body: Vec<u8> = if upload {
                ctx.request.body.clone().unwrap_or_default()
            } else {
                Vec::new()
            };
            let infilesize = if upload { body.len() as i64 } else { -1 };
            let mut req = SmbRequest::new(path, upload, infilesize, false);

            // Thread the live transport off `ctx.io` (installed by the
            // connection filter chain — plain TCP for `smb`, TLS-wrapped for
            // `smbs`). Its borrow is disjoint from `ctx.sink` below.
            let stream = ctx.io.as_deref_mut().ok_or_else(|| {
                Error::with_context(CurlCode::CouldntConnect, "no transport for SMB")
            })?;

            // connecting: NEGOTIATE → SESSION SETUP (NTLMv1).
            conn.run_connect(&req, stream).await?;

            // doing: TREE CONNECT → OPEN → READ/WRITE → CLOSE → TREE DISCONNECT.
            // `write_body` forwards downloaded bytes to the client sink (←
            // `Curl_client_write`); `read_src` supplies upload bytes from the
            // in-memory body cursor (← `Curl_client_read`).
            let sink_slot = &mut ctx.sink;
            let mut write_body = |data: &[u8]| -> Result<()> {
                match sink_slot.as_deref_mut() {
                    Some(s) => s.write(data),
                    None => Ok(()),
                }
            };
            let mut pos = 0usize;
            let mut read_src = move |buf: &mut [u8]| -> Result<usize> {
                let n = (body.len() - pos).min(buf.len());
                buf[..n].copy_from_slice(&body[pos..pos + n]);
                pos += n;
                Ok(n)
            };
            conn.run_request(&mut req, stream, &mut write_body, &mut read_src)
                .await?;

            Ok(true)
        })
    }

    /// Per-request teardown (← `ZERO_NULL` in the SMB vtable). curl installs no
    /// `done` handler for SMB: the authenticated session is retained for reuse
    /// (`PROTOPT_CONN_REUSE`) and released only at `disconnect`. No-op.
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

/// The single, shared SMB/SMBS handler instance (← the `&Curl_handler_smb`
/// vtable pointer). Both `SCHEME_SMB` and `SCHEME_SMBS` reference this static;
/// the schemes differ only in their `PROTOPT_*` flags (SMBS adds `PROTOPT_SSL`)
/// and default transport, never in behavior — exactly as curl shares the
/// `smb_*` functions across `Curl_handler_smb` and `Curl_handler_smbs`.
pub static HANDLER: SmbHandler = SmbHandler;

// ===========================================================================
// Tests. These exercise the byte-exact wire builders, the NetBIOS framing, the
// response parsers, the NTLMv1 embedding, the error mapping, and — via in-memory
// `tokio::io::duplex` mock servers — the full NEGOTIATE→SETUP handshake and the
// TREE CONNECT→…→DONE request state machine (download, multi-read download, and
// upload). No external daemon is required; the mock server frames responses
// exactly as `tests/smbserver.py` would on the wire.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{Connection, Scheme};
    use crate::protocols::{Protocol, TransferCtx, TransferSink};
    use std::sync::{Arc, Mutex};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};

    // Trusted-buffer readers for the byte-layout assertions below. Production
    // code uses the checked `Result`-returning readers (a malformed server
    // frame must yield `CURLE_RECV_ERROR`, never panic); these thin wrappers
    // shadow them *inside the test module only* so the byte-exact layout
    // assertions — which run over buffers the test just built, with
    // compile-time offsets — stay terse. Unwrapping is correct here precisely
    // because the buffers are trusted and long enough by construction.
    fn le_u16(buf: &[u8], off: usize) -> u16 {
        super::le_u16(buf, off).unwrap()
    }
    fn le_u32(buf: &[u8], off: usize) -> u32 {
        super::le_u32(buf, off).unwrap()
    }
    fn be_u16(buf: &[u8], off: usize) -> u16 {
        super::be_u16(buf, off).unwrap()
    }
    fn header_status(msg: &[u8]) -> u32 {
        super::header_status(msg).unwrap()
    }
    fn header_uid(msg: &[u8]) -> u16 {
        super::header_uid(msg).unwrap()
    }
    fn header_tid(msg: &[u8]) -> u16 {
        super::header_tid(msg).unwrap()
    }
    fn nt_create_fid(msg: &[u8]) -> u16 {
        super::nt_create_fid(msg).unwrap()
    }
    fn nt_create_end_of_file(msg: &[u8]) -> i64 {
        super::nt_create_end_of_file(msg).unwrap()
    }

    /// A [`TransferSink`] that records everything written, so a handler test can
    /// assert the exact bytes the wired [`SmbHandler`] streamed to the client.
    struct RecordingSink(Arc<Mutex<Vec<u8>>>);
    impl TransferSink for RecordingSink {
        fn write(&mut self, data: &[u8]) -> Result<()> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Test helpers: build byte-valid server responses and a lockstep reader.
    // -----------------------------------------------------------------------

    /// Build a framed SMB response: the 36-byte NetBIOS+SMB header (carrying
    /// `status`, `uid`, `tid`), then the `params` word block (`word_count =
    /// params.len() / 2`), the 16-bit byte count, and the `data` byte block.
    /// The NetBIOS length and internal word/byte counts are kept mutually
    /// consistent so [`frame_complete`] accepts the frame.
    fn frame_response(status: u32, uid: u16, tid: u16, params: &[u8], data: &[u8]) -> Vec<u8> {
        assert_eq!(params.len() % 2, 0, "params must be whole 16-bit words");
        let word_count = (params.len() / 2) as u8;
        let byte_count = data.len() as u16;

        let mut v = vec![0u8; SMB_HEADER_LEN];
        v[4..8].copy_from_slice(&[0xff, b'S', b'M', b'B']);
        v[9..13].copy_from_slice(&status.to_le_bytes());
        v[28..30].copy_from_slice(&tid.to_le_bytes());
        v[32..34].copy_from_slice(&uid.to_le_bytes());
        v.push(word_count);
        v.extend_from_slice(params);
        v.extend_from_slice(&byte_count.to_le_bytes());
        v.extend_from_slice(data);

        let nbt = (v.len() - NETBIOS_HEADER_LEN) as u16;
        v[2..4].copy_from_slice(&nbt.to_be_bytes());
        v
    }

    /// A NEGOTIATE response with the session key at offset 52 and the 8-byte
    /// challenge in the trailing bytes at offset 73 (total length 81).
    fn negotiate_response(session_key: u32, challenge: [u8; 8]) -> Vec<u8> {
        let mut params = [0u8; 34];
        params[15..19].copy_from_slice(&session_key.to_le_bytes()); // absolute offset 52
        frame_response(0, 0, 0, &params, &challenge)
    }

    /// A SESSION SETUP response carrying `uid` and `status`.
    fn setup_response(uid: u16, status: u32) -> Vec<u8> {
        frame_response(status, uid, 0, &[], &[])
    }

    /// A TREE CONNECT response carrying `tid` and `status`.
    fn tree_connect_response(uid: u16, tid: u16, status: u32) -> Vec<u8> {
        frame_response(status, uid, tid, &[], &[])
    }

    /// An NT_CREATE_ANDX response (length 103 ≥ 100) with `fid` at offset 42,
    /// the last-change FILETIME at offset 72, and the end-of-file at offset 92.
    fn nt_create_response(
        uid: u16,
        tid: u16,
        fid: u16,
        end_of_file: i64,
        last_change: i64,
        status: u32,
    ) -> Vec<u8> {
        let mut params = [0u8; 64];
        params[5..7].copy_from_slice(&fid.to_le_bytes()); // absolute offset 42
        params[35..43].copy_from_slice(&last_change.to_le_bytes()); // absolute offset 72
        params[55..63].copy_from_slice(&end_of_file.to_le_bytes()); // absolute offset 92
        frame_response(status, uid, tid, &params, &[])
    }

    /// A READ_ANDX response whose payload `data` starts at buffer offset 63, so
    /// `data_length` (offset 47) = `data.len()` and `data_offset` (offset 49) =
    /// 59 (= 63 − `sizeof(unsigned int)`).
    fn read_andx_response(uid: u16, tid: u16, data: &[u8]) -> Vec<u8> {
        let mut params = [0u8; 24];
        params[10..12].copy_from_slice(&(data.len() as u16).to_le_bytes()); // len @47
        params[12..14].copy_from_slice(&59u16.to_le_bytes()); // off @49
        frame_response(0, uid, tid, &params, data)
    }

    /// A WRITE_ANDX response reporting `count` bytes written at offset 41.
    /// (Absolute offset 41 = `params[4]`, since the word block starts at
    /// offset 37 — one byte past the `word_count` at 36.)
    fn write_andx_response(uid: u16, tid: u16, count: u16) -> Vec<u8> {
        let mut params = [0u8; 12];
        params[4..6].copy_from_slice(&count.to_le_bytes()); // count @41
        frame_response(0, uid, tid, &params, &[])
    }

    /// A minimal all-zero-status response (used for CLOSE and TREE DISCONNECT).
    fn ok_response(uid: u16, tid: u16) -> Vec<u8> {
        frame_response(0, uid, tid, &[], &[])
    }

    /// Read exactly one NetBIOS-framed message from `stream` (header + declared
    /// body), so the mock server stays in lockstep with the client.
    async fn recv_one(stream: &mut DuplexStream) -> Vec<u8> {
        let mut hdr = [0u8; NETBIOS_HEADER_LEN];
        stream.read_exact(&mut hdr).await.expect("netbios header");
        let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await.expect("netbios body");
        let mut msg = hdr.to_vec();
        msg.extend_from_slice(&body);
        msg
    }

    /// A fresh, pre-connect [`SmbConn`] with a known password.
    fn fresh_conn(passwd: &str) -> SmbConn {
        SmbConn {
            state: SmbConnState::Connecting,
            user: "user".into(),
            domain: "WORKGROUP".into(),
            passwd: passwd.into(),
            host: "server".into(),
            share: Some("share".into()),
            challenge: [0u8; 8],
            session_key: 0,
            uid: 0,
            recv_buf: vec![0u8; MAX_MESSAGE_SIZE],
            got: 0,
        }
    }

    /// An already-authenticated [`SmbConn`] (state `Connected`) with the given
    /// `uid`, ready to drive the request state machine.
    fn connected_conn(uid: u16) -> SmbConn {
        let mut c = fresh_conn("pass");
        c.state = SmbConnState::Connected;
        c.uid = uid;
        c
    }

    // -----------------------------------------------------------------------
    // Constants, enum discriminants, and flags (parity with smb.h).
    // -----------------------------------------------------------------------

    #[test]
    fn command_codes_match_smb_h() {
        assert_eq!(SMB_COM_CLOSE, 0x04);
        assert_eq!(SMB_COM_READ_ANDX, 0x2e);
        assert_eq!(SMB_COM_WRITE_ANDX, 0x2f);
        assert_eq!(SMB_COM_TREE_DISCONNECT, 0x71);
        assert_eq!(SMB_COM_NEGOTIATE, 0x72);
        assert_eq!(SMB_COM_SETUP_ANDX, 0x73);
        assert_eq!(SMB_COM_TREE_CONNECT_ANDX, 0x75);
        assert_eq!(SMB_COM_NT_CREATE_ANDX, 0xa2);
        assert_eq!(SMB_COM_NO_ANDX_COMMAND, 0xff);
    }

    #[test]
    fn word_counts_match_smb_h() {
        assert_eq!(SMB_WC_CLOSE, 0x03);
        assert_eq!(SMB_WC_READ_ANDX, 0x0c);
        assert_eq!(SMB_WC_WRITE_ANDX, 0x0e);
        assert_eq!(SMB_WC_SETUP_ANDX, 0x0d);
        assert_eq!(SMB_WC_TREE_CONNECT_ANDX, 0x04);
        assert_eq!(SMB_WC_NT_CREATE_ANDX, 0x18);
    }

    #[test]
    fn sizes_and_errors_are_frozen() {
        assert_eq!(MAX_PAYLOAD_SIZE, 0x8000);
        assert_eq!(MAX_MESSAGE_SIZE, 0x8000 + 0x1000);
        assert_eq!(SMB_HEADER_LEN, 36);
        assert_eq!(NETBIOS_HEADER_LEN, 4);
        assert_eq!(SMB_NEGOTIATE_RESPONSE_LEN, 74);
        assert_eq!(SMB_NT_CREATE_RESPONSE_LEN, 100);
        assert_eq!(SMB_ERR_NOACCESS, 0x0005_0001);
        assert_eq!(SMB_PID, 0x00bad71d);
    }

    #[test]
    fn conn_state_discriminants_match_c() {
        assert_eq!(SmbConnState::NotConnected as u8, 0);
        assert_eq!(SmbConnState::Connecting as u8, 1);
        assert_eq!(SmbConnState::Negotiate as u8, 2);
        assert_eq!(SmbConnState::Setup as u8, 3);
        assert_eq!(SmbConnState::Connected as u8, 4);
    }

    #[test]
    fn req_state_discriminants_match_c() {
        assert_eq!(SmbReqState::Requesting as u8, 0);
        assert_eq!(SmbReqState::TreeConnect as u8, 1);
        assert_eq!(SmbReqState::Open as u8, 2);
        assert_eq!(SmbReqState::Download as u8, 3);
        assert_eq!(SmbReqState::Upload as u8, 4);
        assert_eq!(SmbReqState::Close as u8, 5);
        assert_eq!(SmbReqState::TreeDisconnect as u8, 6);
        assert_eq!(SmbReqState::Done as u8, 7);
    }

    // -----------------------------------------------------------------------
    // URL path parsing (← smb_parse_url_path).
    // -----------------------------------------------------------------------

    #[test]
    fn parse_url_path_extracts_share_and_path() {
        let (share, path) = parse_url_path("/myshare/dir/file.txt").unwrap();
        assert_eq!(share, "myshare");
        assert_eq!(path, "dir\\file.txt");
    }

    #[test]
    fn parse_url_path_without_leading_slash() {
        let (share, path) = parse_url_path("share/a/b").unwrap();
        assert_eq!(share, "share");
        assert_eq!(path, "a\\b");
    }

    #[test]
    fn parse_url_path_accepts_backslash_separators() {
        let (share, path) = parse_url_path("\\share\\deep\\name").unwrap();
        assert_eq!(share, "share");
        assert_eq!(path, "deep\\name");
    }

    #[test]
    fn parse_url_path_missing_share_is_url_malformat() {
        let err = parse_url_path("/justshare").unwrap_err();
        assert_eq!(err.code(), CurlCode::UrlMalformat);
    }

    #[test]
    fn parse_url_path_percent_decodes_before_split() {
        // `%20` → space in the file path (← `Curl_urldecode`).
        let (share, path) = parse_url_path("/share/a%20b/c").unwrap();
        assert_eq!(share, "share");
        assert_eq!(path, "a b\\c");
    }

    #[test]
    fn parse_url_path_decodes_encoded_separators() {
        // `%2F` decodes to `/` *before* the split, so an encoded slash now acts
        // as a real separator — matching curl, which decodes first.
        let (share, path) = parse_url_path("/share%2Fdir%5Cfile").unwrap();
        assert_eq!(share, "share");
        // The decoded `/` splits share/path; the decoded `\` stays a backslash.
        assert_eq!(path, "dir\\file");
    }

    #[test]
    fn parse_url_path_rejects_encoded_nul() {
        // `%00` decodes to a NUL control byte → REJECT_CTRL → URL_MALFORMAT.
        let err = parse_url_path("/share/a%00b").unwrap_err();
        assert_eq!(err.code(), CurlCode::UrlMalformat);
    }

    #[test]
    fn parse_url_path_rejects_encoded_control_byte() {
        // `%01` decodes to a control byte (< 0x20) → REJECT_CTRL → URL_MALFORMAT.
        let err = parse_url_path("/share/%01").unwrap_err();
        assert_eq!(err.code(), CurlCode::UrlMalformat);
    }

    #[test]
    fn parse_url_path_keeps_literal_percent_when_not_an_escape() {
        // A `%` not followed by two hex digits is literal (← curl's guard); the
        // path is otherwise parsed normally.
        let (share, path) = parse_url_path("/share/50%off").unwrap();
        assert_eq!(share, "share");
        assert_eq!(path, "50%off");
    }

    // -----------------------------------------------------------------------
    // from_connection: credential handling (← smb_connect).
    // -----------------------------------------------------------------------

    fn conn_with(user: Option<&str>, passwd: Option<&str>, host: &str) -> Connection {
        let mut c = Connection::new(Scheme::new("smb", 445), host, 445);
        c.user = user.map(String::from);
        c.passwd = passwd.map(String::from);
        c
    }

    #[test]
    fn from_connection_requires_username() {
        let conn = conn_with(None, Some("secret"), "fileserver");
        let err = SmbConn::from_connection(&conn, "share".into()).unwrap_err();
        assert_eq!(err.code(), CurlCode::LoginDenied);
    }

    #[test]
    fn from_connection_defaults_domain_to_host() {
        let conn = conn_with(Some("alice"), Some("pw"), "fileserver");
        let smbc = SmbConn::from_connection(&conn, "share".into()).unwrap();
        assert_eq!(smbc.user, "alice");
        assert_eq!(smbc.domain, "fileserver");
        assert_eq!(smbc.host, "fileserver");
        assert_eq!(smbc.state, SmbConnState::Connecting);
        assert_eq!(smbc.share.as_deref(), Some("share"));
    }

    #[test]
    fn from_connection_splits_domain_backslash() {
        let conn = conn_with(Some("CORP\\bob"), Some("pw"), "fileserver");
        let smbc = SmbConn::from_connection(&conn, "share".into()).unwrap();
        assert_eq!(smbc.domain, "CORP");
        assert_eq!(smbc.user, "bob");
    }

    #[test]
    fn from_connection_splits_domain_forward_slash() {
        let conn = conn_with(Some("CORP/carol"), Some("pw"), "fileserver");
        let smbc = SmbConn::from_connection(&conn, "share".into()).unwrap();
        assert_eq!(smbc.domain, "CORP");
        assert_eq!(smbc.user, "carol");
    }

    // -----------------------------------------------------------------------
    // Header framing and message builders (byte-exact).
    // -----------------------------------------------------------------------

    #[test]
    fn format_header_byte_layout() {
        let h = SmbConn::format_header(0x1234, 0x5678, SMB_COM_NEGOTIATE, 15);
        // nbt_length (big-endian) = 32 + body_len.
        assert_eq!(
            be_u16(&h, 2) as usize,
            SMB_HEADER_LEN - NETBIOS_HEADER_LEN + 15
        );
        assert_eq!(&h[4..8], b"\xffSMB");
        assert_eq!(h[8], SMB_COM_NEGOTIATE);
        assert_eq!(
            h[13],
            SMB_FLAGS_CANONICAL_PATHNAMES | SMB_FLAGS_CASELESS_PATHNAMES
        );
        assert_eq!(
            le_u16(&h, 14),
            SMB_FLAGS2_IS_LONG_NAME | SMB_FLAGS2_KNOWS_LONG_NAME
        );
        assert_eq!(le_u16(&h, 16), (SMB_PID >> 16) as u16);
        assert_eq!(le_u16(&h, 28), 0x5678); // tid
        assert_eq!(le_u16(&h, 30), (SMB_PID & 0xffff) as u16); // pid low
        assert_eq!(le_u16(&h, 32), 0x1234); // uid
    }

    #[test]
    fn negotiate_message_offers_nt_lm_012() {
        let conn = fresh_conn("pw");
        let req = SmbRequest::new(String::new(), false, -1, false);
        let msg = conn.build_negotiate(&req);
        assert_eq!(msg.len(), SMB_HEADER_LEN + 15);
        assert_eq!(msg[8], SMB_COM_NEGOTIATE);
        // Body: word_count(0) | byte_count(0x000c) | dialect(0x02) | "NT LM 0.12\0".
        assert_eq!(&msg[SMB_HEADER_LEN..], b"\x00\x0c\x00\x02NT LM 0.12\x00");
    }

    #[test]
    fn setup_message_embeds_raw_ntlmv1_responses() {
        let mut conn = fresh_conn("Passw0rd!");
        conn.challenge = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        conn.session_key = 0x0a0b_0c0d;
        let req = SmbRequest::new(String::new(), false, -1, false);
        let msg = conn.build_setup(&req).unwrap();

        // Independently recompute the raw NTLMv1 LM/NT responses.
        let lm = ntlm::lm_resp(&ntlm::mk_lm_hash("Passw0rd!"), &conn.challenge);
        let nt = ntlm::lm_resp(&ntlm::mk_nt_hash("Passw0rd!"), &conn.challenge);

        // word_count @36, session_key @47, lengths @51/@53, byte_count @63,
        // then lm @65..89, nt @89..113.
        assert_eq!(msg[36], SMB_WC_SETUP_ANDX);
        assert_eq!(le_u32(&msg, 47), conn.session_key);
        assert_eq!(le_u16(&msg, 51), 24);
        assert_eq!(le_u16(&msg, 53), 24);
        assert_eq!(&msg[65..89], &lm[..]);
        assert_eq!(&msg[89..113], &nt[..]);
        // Trailer strings follow: user\0 domain\0 OS\0 clientname\0.
        let trailer = &msg[113..];
        let expected = format!("user\0WORKGROUP\0{CLIENT_OS}\0{CLIENTNAME}\0");
        assert_eq!(trailer, expected.as_bytes());
    }

    #[test]
    fn tree_connect_builds_unc_path() {
        let conn = fresh_conn("pw");
        let req = SmbRequest::new(String::new(), false, -1, false);
        let msg = conn.build_tree_connect(&req).unwrap();
        assert_eq!(msg[8], SMB_COM_TREE_CONNECT_ANDX);
        assert_eq!(msg[36], SMB_WC_TREE_CONNECT_ANDX);
        // Trailer: "\\server\share\0?????\0".
        let expected = format!("\\\\server\\share\0{SERVICENAME}\0");
        assert_eq!(&msg[SMB_HEADER_LEN + 11..], expected.as_bytes());
    }

    #[test]
    fn open_download_requests_read_access_and_file_open() {
        let conn = fresh_conn("pw");
        let req = SmbRequest::new("dir\\f.bin".into(), false, -1, false);
        let msg = conn.build_open(&req).unwrap();
        assert_eq!(msg[8], SMB_COM_NT_CREATE_ANDX);
        assert_eq!(msg[36], SMB_WC_NT_CREATE_ANDX);
        // access @ body+16 → 36+16=52; disposition @ body+36 → 36+36=72.
        assert_eq!(le_u32(&msg, 52), SMB_GENERIC_READ);
        assert_eq!(le_u32(&msg, 72), SMB_FILE_OPEN);
        // Trailer is the path plus a trailing NUL.
        assert_eq!(&msg[SMB_HEADER_LEN + 51..], b"dir\\f.bin\0");
    }

    #[test]
    fn open_upload_requests_readwrite_and_overwrite_if() {
        let conn = fresh_conn("pw");
        let req = SmbRequest::new("up.bin".into(), true, 10, false);
        let msg = conn.build_open(&req).unwrap();
        assert_eq!(le_u32(&msg, 52), SMB_GENERIC_READ | SMB_GENERIC_WRITE);
        assert_eq!(le_u32(&msg, 72), SMB_FILE_OVERWRITE_IF);
    }

    #[test]
    fn read_message_encodes_fid_and_offset() {
        let mut conn = fresh_conn("pw");
        conn.uid = 9;
        let mut req = SmbRequest::new("f".into(), false, -1, false);
        req.fid = 0xbeef;
        req.tid = 0x0007;
        req.offset = 0x1_0000_0002; // spans low and high 32 bits
        let msg = conn.build_read(&req);
        assert_eq!(msg[8], SMB_COM_READ_ANDX);
        assert_eq!(msg[36], SMB_WC_READ_ANDX);
        assert_eq!(le_u16(&msg, SMB_HEADER_LEN + 5), 0xbeef); // fid
        assert_eq!(le_u32(&msg, SMB_HEADER_LEN + 7), 2); // offset low
        assert_eq!(le_u16(&msg, SMB_HEADER_LEN + 11), MAX_PAYLOAD_SIZE as u16); // max
        assert_eq!(le_u32(&msg, SMB_HEADER_LEN + 21), 1); // offset high
    }

    #[test]
    fn write_header_layout_is_68_bytes() {
        let mut conn = fresh_conn("pw");
        conn.uid = 3;
        let mut req = SmbRequest::new("f".into(), true, 100, false);
        req.fid = 0x00aa;
        req.offset = 5;
        let hdr = conn.build_write_header(&req, 40);
        assert_eq!(hdr.len(), 68);
        assert_eq!(hdr[8], SMB_COM_WRITE_ANDX);
        assert_eq!(hdr[36], SMB_WC_WRITE_ANDX);
        assert_eq!(le_u16(&hdr, 41), 0x00aa); // fid
        assert_eq!(le_u32(&hdr, 43), 5); // offset low
        assert_eq!(le_u16(&hdr, 57), 40); // data_length
        assert_eq!(le_u16(&hdr, 59), 64); // data_offset = sizeof(*msg) - 4
        assert_eq!(le_u16(&hdr, 65), 41); // byte_count = upload_size + 1
        assert_eq!(be_u16(&hdr, 2) as usize, 32 + 32 + 40); // nbt = 32 + (32 + upload_size)
    }

    #[test]
    fn close_and_tree_disconnect_layout() {
        let mut conn = fresh_conn("pw");
        let mut req = SmbRequest::new("f".into(), false, -1, false);
        req.fid = 0x1357;
        let close = conn.build_close(&req);
        assert_eq!(close[8], SMB_COM_CLOSE);
        assert_eq!(close[36], SMB_WC_CLOSE);
        assert_eq!(le_u16(&close, SMB_HEADER_LEN + 1), 0x1357); // fid

        conn.uid = 0;
        let td = conn.build_tree_disconnect(&req);
        assert_eq!(td[8], SMB_COM_TREE_DISCONNECT);
        assert_eq!(td[36], 0); // word_count zeroed
    }

    #[test]
    fn oversized_setup_trailer_is_filesize_exceeded() {
        let mut conn = fresh_conn("pw");
        // A very long user name overflows the C `bytes[1024]` trailer.
        conn.user = "u".repeat(2000);
        let req = SmbRequest::new(String::new(), false, -1, false);
        let err = conn.build_setup(&req).unwrap_err();
        assert_eq!(err.code(), CurlCode::FilesizeExceeded);
    }

    // -----------------------------------------------------------------------
    // Framing and response parsers.
    // -----------------------------------------------------------------------

    #[test]
    fn frame_complete_needs_full_message() {
        let frame = ok_response(1, 2);
        // Fewer than 4 bytes → cannot even read the length.
        assert_eq!(frame_complete(&frame, 2).unwrap(), None);
        // Header present but body incomplete.
        assert_eq!(frame_complete(&frame, NETBIOS_HEADER_LEN).unwrap(), None);
        // Whole frame present → its total size.
        assert_eq!(
            frame_complete(&frame, frame.len()).unwrap(),
            Some(frame.len())
        );
    }

    #[test]
    fn frame_complete_rejects_oversize() {
        let mut buf = vec![0u8; 8];
        // Declare a NetBIOS length larger than MAX_MESSAGE_SIZE.
        buf[2..4].copy_from_slice(&(MAX_MESSAGE_SIZE as u16).to_be_bytes());
        let err = frame_complete(&buf, 8).unwrap_err();
        assert_eq!(err.code(), CurlCode::RecvError);
    }

    #[test]
    fn parse_negotiate_extracts_challenge_and_key() {
        let challenge = [9u8, 8, 7, 6, 5, 4, 3, 2];
        let frame = negotiate_response(0x1122_3344, challenge);
        let (got_challenge, key) = parse_negotiate_response(&frame, frame.len()).unwrap();
        assert_eq!(got_challenge, challenge);
        assert_eq!(key, 0x1122_3344);
    }

    #[test]
    fn parse_negotiate_rejects_short_response() {
        let frame = negotiate_response(0, [0; 8]);
        let err = parse_negotiate_response(&frame, 80).unwrap_err();
        assert_eq!(err.code(), CurlCode::CouldntConnect);
    }

    #[test]
    fn parse_negotiate_rejects_error_status() {
        let mut frame = negotiate_response(0, [1; 8]);
        frame[9..13].copy_from_slice(&1u32.to_le_bytes()); // non-zero status
        let err = parse_negotiate_response(&frame, frame.len()).unwrap_err();
        assert_eq!(err.code(), CurlCode::CouldntConnect);
    }

    #[test]
    fn header_and_nt_create_accessors() {
        let frame = nt_create_response(0x00c1, 0x00d2, 0x00e3, 4096, 0, 0);
        assert_eq!(header_status(&frame), 0);
        assert_eq!(header_uid(&frame), 0x00c1);
        assert_eq!(header_tid(&frame), 0x00d2);
        assert_eq!(nt_create_fid(&frame), 0x00e3);
        assert_eq!(nt_create_end_of_file(&frame), 4096);
    }

    #[test]
    fn get_posix_time_converts_filetime() {
        // Exactly the epoch offset → 0 seconds.
        assert_eq!(get_posix_time(116_444_736_000_000_000), 0);
        // 100 seconds past the Unix epoch (100 * 10^7 100 ns units).
        assert_eq!(get_posix_time(116_444_736_000_000_000 + 1_000_000_000), 100);
        // Anything before the Unix epoch (and the 0 sentinel) → 0.
        assert_eq!(get_posix_time(0), 0);
        assert_eq!(get_posix_time(1000), 0);
    }

    #[test]
    fn access_error_maps_status() {
        assert_eq!(
            SmbConn::access_error(SMB_ERR_NOACCESS),
            CurlCode::RemoteAccessDenied
        );
        assert_eq!(
            SmbConn::access_error(0x0000_0001),
            CurlCode::RemoteFileNotFound
        );
    }

    // -----------------------------------------------------------------------
    // End-to-end async drivers against an in-memory lockstep mock server.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn run_connect_performs_negotiate_and_setup() {
        let (mut client, mut server) = duplex(64 * 1024);
        let challenge = [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18];
        let session_key = 0x1234_5678u32;
        let uid = 0x4242u16;
        let passwd = "s3cret";

        let server_task = tokio::spawn(async move {
            let neg = recv_one(&mut server).await;
            assert_eq!(neg[8], SMB_COM_NEGOTIATE);
            server
                .write_all(&negotiate_response(session_key, challenge))
                .await
                .unwrap();

            let setup = recv_one(&mut server).await;
            assert_eq!(setup[8], SMB_COM_SETUP_ANDX);
            server.write_all(&setup_response(uid, 0)).await.unwrap();
            setup
        });

        let mut conn = fresh_conn(passwd);
        let req = SmbRequest::new(String::new(), false, -1, false);
        conn.run_connect(&req, &mut client).await.unwrap();

        assert_eq!(conn.state, SmbConnState::Connected);
        assert_eq!(conn.uid, uid);
        assert_eq!(conn.challenge, challenge);
        assert_eq!(conn.session_key, session_key);

        // The captured SETUP message must echo the session key and embed the
        // raw NTLMv1 responses derived from the password and challenge.
        let setup = server_task.await.unwrap();
        assert_eq!(le_u32(&setup, 47), session_key);
        let lm = ntlm::lm_resp(&ntlm::mk_lm_hash(passwd), &challenge);
        let nt = ntlm::lm_resp(&ntlm::mk_nt_hash(passwd), &challenge);
        assert_eq!(&setup[65..89], &lm[..]);
        assert_eq!(&setup[89..113], &nt[..]);
    }

    #[tokio::test]
    async fn run_connect_reports_login_denied_on_setup_failure() {
        let (mut client, mut server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let _ = recv_one(&mut server).await;
            server
                .write_all(&negotiate_response(1, [0; 8]))
                .await
                .unwrap();
            let _ = recv_one(&mut server).await;
            // Non-zero SESSION SETUP status → authentication rejected.
            server
                .write_all(&setup_response(0, 0xC000_0022))
                .await
                .unwrap();
        });

        let mut conn = fresh_conn("pw");
        let req = SmbRequest::new(String::new(), false, -1, false);
        let err = conn.run_connect(&req, &mut client).await.unwrap_err();
        assert_eq!(err.code(), CurlCode::LoginDenied);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn run_request_downloads_file() {
        let (mut client, mut server) = duplex(64 * 1024);
        let (uid, tid, fid) = (0x0055u16, 0x00abu16, 0x00cdu16);
        let file = b"hello, smb world!".to_vec();
        let file_len = file.len() as i64;

        let file_srv = file.clone();
        let server_task = tokio::spawn(async move {
            let tc = recv_one(&mut server).await;
            assert_eq!(tc[8], SMB_COM_TREE_CONNECT_ANDX);
            server
                .write_all(&tree_connect_response(uid, tid, 0))
                .await
                .unwrap();

            let op = recv_one(&mut server).await;
            assert_eq!(op[8], SMB_COM_NT_CREATE_ANDX);
            server
                .write_all(&nt_create_response(uid, tid, fid, file_len, 0, 0))
                .await
                .unwrap();

            let rd = recv_one(&mut server).await;
            assert_eq!(rd[8], SMB_COM_READ_ANDX);
            server
                .write_all(&read_andx_response(uid, tid, &file_srv))
                .await
                .unwrap();

            let cl = recv_one(&mut server).await;
            assert_eq!(cl[8], SMB_COM_CLOSE);
            server.write_all(&ok_response(uid, tid)).await.unwrap();

            let td = recv_one(&mut server).await;
            assert_eq!(td[8], SMB_COM_TREE_DISCONNECT);
            server.write_all(&ok_response(uid, tid)).await.unwrap();
        });

        let mut conn = connected_conn(uid);
        let mut req = SmbRequest::new("dir\\file.txt".into(), false, -1, false);
        let mut downloaded = Vec::new();
        conn.run_request(
            &mut req,
            &mut client,
            |chunk: &[u8]| {
                downloaded.extend_from_slice(chunk);
                Ok(())
            },
            |_buf: &mut [u8]| Ok(0usize),
        )
        .await
        .unwrap();

        assert_eq!(downloaded, file);
        assert_eq!(req.tid, tid);
        assert_eq!(req.fid, fid);
        assert_eq!(req.size, file_len);
        assert_eq!(req.state, SmbReqState::Done);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn run_request_downloads_across_multiple_reads() {
        let (mut client, mut server) = duplex(128 * 1024);
        let (uid, tid, fid) = (1u16, 2u16, 3u16);
        // First chunk is exactly MAX_PAYLOAD_SIZE → the loop must continue;
        // the shorter second chunk ends it.
        let chunk0 = vec![0xABu8; MAX_PAYLOAD_SIZE];
        let chunk1 = b"tail-bytes".to_vec();
        let total = (chunk0.len() + chunk1.len()) as i64;

        let (c0, c1) = (chunk0.clone(), chunk1.clone());
        let server_task = tokio::spawn(async move {
            recv_one(&mut server).await;
            server
                .write_all(&tree_connect_response(uid, tid, 0))
                .await
                .unwrap();
            recv_one(&mut server).await;
            server
                .write_all(&nt_create_response(uid, tid, fid, total, 0, 0))
                .await
                .unwrap();
            recv_one(&mut server).await;
            server
                .write_all(&read_andx_response(uid, tid, &c0))
                .await
                .unwrap();
            recv_one(&mut server).await;
            server
                .write_all(&read_andx_response(uid, tid, &c1))
                .await
                .unwrap();
            recv_one(&mut server).await;
            server.write_all(&ok_response(uid, tid)).await.unwrap();
            recv_one(&mut server).await;
            server.write_all(&ok_response(uid, tid)).await.unwrap();
        });

        let mut conn = connected_conn(uid);
        let mut req = SmbRequest::new("big.bin".into(), false, -1, false);
        let mut downloaded = Vec::new();
        conn.run_request(
            &mut req,
            &mut client,
            |chunk: &[u8]| {
                downloaded.extend_from_slice(chunk);
                Ok(())
            },
            |_buf: &mut [u8]| Ok(0usize),
        )
        .await
        .unwrap();

        assert_eq!(downloaded.len(), MAX_PAYLOAD_SIZE + chunk1.len());
        assert_eq!(&downloaded[..MAX_PAYLOAD_SIZE], &chunk0[..]);
        assert_eq!(&downloaded[MAX_PAYLOAD_SIZE..], &chunk1[..]);
        assert_eq!(req.offset, total as u64);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn run_request_uploads_file() {
        let (mut client, mut server) = duplex(64 * 1024);
        let (uid, tid, fid) = (0x11u16, 0x22u16, 0x33u16);
        let payload = b"upload me to the share".to_vec();
        let size = payload.len() as i64;

        let server_task = tokio::spawn(async move {
            recv_one(&mut server).await;
            server
                .write_all(&tree_connect_response(uid, tid, 0))
                .await
                .unwrap();

            let op = recv_one(&mut server).await;
            assert_eq!(op[8], SMB_COM_NT_CREATE_ANDX);
            server
                .write_all(&nt_create_response(uid, tid, fid, 0, 0, 0))
                .await
                .unwrap();

            // WRITE_ANDX: 68-byte header then the payload. `data_length` is at
            // offset 57; the payload begins at offset 68 (data_offset 64 + 4).
            let wr = recv_one(&mut server).await;
            assert_eq!(wr[8], SMB_COM_WRITE_ANDX);
            let dlen = u16::from_le_bytes([wr[57], wr[58]]) as usize;
            let received = wr[68..68 + dlen].to_vec();
            server
                .write_all(&write_andx_response(uid, tid, dlen as u16))
                .await
                .unwrap();

            recv_one(&mut server).await;
            server.write_all(&ok_response(uid, tid)).await.unwrap();
            recv_one(&mut server).await;
            server.write_all(&ok_response(uid, tid)).await.unwrap();
            received
        });

        let mut conn = connected_conn(uid);
        let mut req = SmbRequest::new("out.bin".into(), true, size, false);
        let src = payload.clone();
        let mut pos = 0usize;
        conn.run_request(
            &mut req,
            &mut client,
            |_chunk: &[u8]| Ok(()),
            move |buf: &mut [u8]| {
                let n = (src.len() - pos).min(buf.len());
                buf[..n].copy_from_slice(&src[pos..pos + n]);
                pos += n;
                Ok(n)
            },
        )
        .await
        .unwrap();

        assert_eq!(req.state, SmbReqState::Done);
        assert_eq!(req.bytecount, size as u64);
        let received = server_task.await.unwrap();
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn run_request_tree_connect_access_denied() {
        let (mut client, mut server) = duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            recv_one(&mut server).await;
            server
                .write_all(&tree_connect_response(1, 0, SMB_ERR_NOACCESS))
                .await
                .unwrap();
        });

        let mut conn = connected_conn(1);
        let mut req = SmbRequest::new("x\\y".into(), false, -1, false);
        let err = conn
            .run_request(
                &mut req,
                &mut client,
                |_c: &[u8]| Ok(()),
                |_b: &mut [u8]| Ok(0usize),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::RemoteAccessDenied);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn run_request_open_file_not_found() {
        let (mut client, mut server) = duplex(16 * 1024);
        let (uid, tid) = (1u16, 2u16);
        let server_task = tokio::spawn(async move {
            recv_one(&mut server).await;
            server
                .write_all(&tree_connect_response(uid, tid, 0))
                .await
                .unwrap();
            recv_one(&mut server).await;
            // A generic non-zero, non-NOACCESS open failure.
            server
                .write_all(&nt_create_response(uid, tid, 0, 0, 0, 0xC000_0034))
                .await
                .unwrap();
            recv_one(&mut server).await; // TREE DISCONNECT
            server.write_all(&ok_response(uid, tid)).await.unwrap();
        });

        let mut conn = connected_conn(uid);
        let mut req = SmbRequest::new("missing.txt".into(), false, -1, false);
        let err = conn
            .run_request(
                &mut req,
                &mut client,
                |_c: &[u8]| Ok(()),
                |_b: &mut [u8]| Ok(0usize),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::RemoteFileNotFound);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn run_request_negative_size_is_weird_server_reply() {
        let (mut client, mut server) = duplex(16 * 1024);
        let (uid, tid, fid) = (1u16, 2u16, 3u16);
        let server_task = tokio::spawn(async move {
            recv_one(&mut server).await;
            server
                .write_all(&tree_connect_response(uid, tid, 0))
                .await
                .unwrap();
            recv_one(&mut server).await;
            // Open succeeds but reports a negative end-of-file.
            server
                .write_all(&nt_create_response(uid, tid, fid, -1, 0, 0))
                .await
                .unwrap();
            recv_one(&mut server).await; // CLOSE
            server.write_all(&ok_response(uid, tid)).await.unwrap();
            recv_one(&mut server).await; // TREE DISCONNECT
            server.write_all(&ok_response(uid, tid)).await.unwrap();
        });

        let mut conn = connected_conn(uid);
        let mut req = SmbRequest::new("f.bin".into(), false, -1, false);
        let err = conn
            .run_request(
                &mut req,
                &mut client,
                |_c: &[u8]| Ok(()),
                |_b: &mut [u8]| Ok(0usize),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::WeirdServerReply);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn run_request_upload_without_size_fails() {
        let (mut client, _server) = duplex(1024);
        let mut conn = connected_conn(1);
        // infilesize < 0 with upload → the up-front size guard fires.
        let mut req = SmbRequest::new("x".into(), true, -1, false);
        let err = conn
            .run_request(
                &mut req,
                &mut client,
                |_c: &[u8]| Ok(()),
                |_b: &mut [u8]| Ok(0usize),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::SendError);
    }

    #[tokio::test]
    async fn handler_done_is_noop_and_object_safe() {
        // Usable through `&dyn Protocol` (object safety for the scheme table),
        // and `done` is a no-op (curl installs no SMB `done` handler).
        let dynh: &dyn Protocol = &HANDLER;
        let mut ctx = TransferCtx::new();
        dynh.done(&mut ctx, Ok(()), false).await.unwrap();
    }

    #[tokio::test]
    async fn handler_do_it_missing_share_is_url_malformat() {
        // A path with no separator after the share → `CURLE_URL_MALFORMAT`
        // (← `smb_parse_url_path`'s "missing share in URL path"), raised before
        // any transport is touched.
        let mut ctx = TransferCtx::new();
        ctx.request.path = "/justshare".into();
        ctx.request.host = "server".into();
        ctx.request.user = Some("user".into());
        let err = HANDLER.do_it(&mut ctx).await.unwrap_err();
        assert_eq!(err.code(), CurlCode::UrlMalformat);
    }

    #[tokio::test]
    async fn handler_do_it_missing_user_is_login_denied() {
        // A valid share/path but no username → `CURLE_LOGIN_DENIED`
        // (← `smb_connect`'s username requirement), before the transport check.
        let mut ctx = TransferCtx::new();
        ctx.request.path = "/share/file.txt".into();
        ctx.request.host = "server".into();
        let err = HANDLER.do_it(&mut ctx).await.unwrap_err();
        assert_eq!(err.code(), CurlCode::LoginDenied);
    }

    #[tokio::test]
    async fn handler_do_it_without_transport_is_couldnt_connect() {
        // Valid share + credentials but no `ctx.io` installed → the transport
        // guard fires with `CURLE_COULDNT_CONNECT`.
        let mut ctx = TransferCtx::new();
        ctx.request.path = "/share/file.txt".into();
        ctx.request.host = "server".into();
        ctx.request.user = Some("user".into());
        ctx.request.password = Some("pass".into());
        let err = HANDLER.do_it(&mut ctx).await.unwrap_err();
        assert_eq!(err.code(), CurlCode::CouldntConnect);
    }

    #[tokio::test]
    async fn handler_do_it_downloads_over_duplex() {
        // Drive the *whole* SMB exchange through `do_it` over one in-memory
        // stream: NEGOTIATE → SESSION SETUP → TREE CONNECT → OPEN → READ →
        // CLOSE → TREE DISCONNECT, and assert the sink received the file bytes.
        let (client, mut server) = duplex(64 * 1024);
        let challenge = [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18];
        let session_key = 0x1234_5678u32;
        let (uid, tid, fid) = (0x0055u16, 0x00abu16, 0x00cdu16);
        let file = b"hello, smb world!".to_vec();
        let file_len = file.len() as i64;
        let file_srv = file.clone();

        let server_task = tokio::spawn(async move {
            let neg = recv_one(&mut server).await;
            assert_eq!(neg[8], SMB_COM_NEGOTIATE);
            server
                .write_all(&negotiate_response(session_key, challenge))
                .await
                .unwrap();
            let setup = recv_one(&mut server).await;
            assert_eq!(setup[8], SMB_COM_SETUP_ANDX);
            server.write_all(&setup_response(uid, 0)).await.unwrap();

            let tc = recv_one(&mut server).await;
            assert_eq!(tc[8], SMB_COM_TREE_CONNECT_ANDX);
            server
                .write_all(&tree_connect_response(uid, tid, 0))
                .await
                .unwrap();
            let op = recv_one(&mut server).await;
            assert_eq!(op[8], SMB_COM_NT_CREATE_ANDX);
            server
                .write_all(&nt_create_response(uid, tid, fid, file_len, 0, 0))
                .await
                .unwrap();
            let rd = recv_one(&mut server).await;
            assert_eq!(rd[8], SMB_COM_READ_ANDX);
            server
                .write_all(&read_andx_response(uid, tid, &file_srv))
                .await
                .unwrap();
            let cl = recv_one(&mut server).await;
            assert_eq!(cl[8], SMB_COM_CLOSE);
            server.write_all(&ok_response(uid, tid)).await.unwrap();
            let td = recv_one(&mut server).await;
            assert_eq!(td[8], SMB_COM_TREE_DISCONNECT);
            server.write_all(&ok_response(uid, tid)).await.unwrap();
        });

        let received = Arc::new(Mutex::new(Vec::new()));
        let mut ctx = TransferCtx::new();
        ctx.request.path = "/share/dir/file.txt".into();
        ctx.request.host = "server".into();
        ctx.request.user = Some("user".into());
        ctx.request.password = Some("pass".into());
        ctx.io = Some(Box::new(client));
        ctx.sink = Some(Box::new(RecordingSink(received.clone())));

        let done = HANDLER.do_it(&mut ctx).await.unwrap();
        assert!(done, "do_it drives the exchange to completion");
        assert_eq!(*received.lock().unwrap(), file);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handler_do_it_uploads_body_over_duplex() {
        // Upload path: the in-memory body is the read source and its length is
        // the up-front size. Assert the server received the payload verbatim.
        let (client, mut server) = duplex(64 * 1024);
        let (uid, tid, fid) = (0x0007u16, 0x0008u16, 0x0009u16);
        let payload = b"upload me over the handler".to_vec();
        let dlen = payload.len();

        let server_task = tokio::spawn(async move {
            recv_one(&mut server).await; // NEGOTIATE
            server
                .write_all(&negotiate_response(0, [0u8; 8]))
                .await
                .unwrap();
            recv_one(&mut server).await; // SESSION SETUP
            server.write_all(&setup_response(uid, 0)).await.unwrap();
            recv_one(&mut server).await; // TREE CONNECT
            server
                .write_all(&tree_connect_response(uid, tid, 0))
                .await
                .unwrap();
            recv_one(&mut server).await; // OPEN
            server
                .write_all(&nt_create_response(uid, tid, fid, 0, 0, 0))
                .await
                .unwrap();
            // WRITE_ANDX: 68-byte header then payload; data begins at offset 68.
            let wr = recv_one(&mut server).await;
            assert_eq!(wr[8], SMB_COM_WRITE_ANDX);
            let got = u16::from_le_bytes([wr[57], wr[58]]) as usize;
            let received = wr[68..68 + got].to_vec();
            server
                .write_all(&write_andx_response(uid, tid, got as u16))
                .await
                .unwrap();
            recv_one(&mut server).await; // CLOSE
            server.write_all(&ok_response(uid, tid)).await.unwrap();
            recv_one(&mut server).await; // TREE DISCONNECT
            server.write_all(&ok_response(uid, tid)).await.unwrap();
            received
        });

        let mut ctx = TransferCtx::new();
        ctx.request.path = "/share/out.bin".into();
        ctx.request.host = "server".into();
        ctx.request.user = Some("user".into());
        ctx.request.password = Some("pass".into());
        ctx.request.upload = true;
        ctx.request.body = Some(payload.clone());
        ctx.io = Some(Box::new(client));

        let done = HANDLER.do_it(&mut ctx).await.unwrap();
        assert!(done);
        let received = server_task.await.unwrap();
        assert_eq!(received.len(), dlen);
        assert_eq!(received, payload);
    }
}
