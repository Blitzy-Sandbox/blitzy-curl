//! SMB / SMBS protocol engine — the Rust analog of curl's `lib/smb.c`.
//!
//! curl's SMB support is a deliberately minimal **SMBv1** client that can read
//! or write a single file on a share, authenticated with **NTLM** (the LM + NT
//! responses computed over the server's 8-byte challenge). It is *not* a full
//! SMB stack: there is no signing, no SMB2/3, no DFS, no enumeration — only the
//! exact command sequence
//!
//! ```text
//! NEGOTIATE → SESSION_SETUP_ANDX (NTLM) → TREE_CONNECT_ANDX
//!     → NT_CREATE_ANDX (open) → READ_ANDX (download) | WRITE_ANDX (upload)
//!     → CLOSE → TREE_DISCONNECT
//! ```
//!
//! that the C implementation drives. This module reproduces that wire behavior
//! **byte-for-byte**: the NetBIOS session header (4 bytes, big-endian length)
//! followed by the 32-byte SMB header and the per-command parameter/data blocks,
//! all little-endian, are laid out to match `lib/smb.c` exactly so the existing
//! curl SMB test (`tests/data/test1451`, driven by `tests/server/smbserver.py`)
//! passes unmodified.
//!
//! # Relationship to the C oracle
//!
//! `lib/smb.c` splits the work across the C handler vtable callbacks
//! (`setup_connection`, `connect_it`, the re-entrant `connecting` and `doing`
//! state machines, `disconnect == ZERO_NULL`). Because the Rust core is
//! `async`, the equivalent logic collapses into a single linear flow inside
//! [`SmbProtocol::do_it`]: each `send` is simply `await`-ed before the matching
//! `recv`, so the C "send-ahead, process-on-next-iteration" state machine
//! becomes ordinary sequential `async` code while preserving the identical wire
//! exchange and the identical `CURLcode` error mapping.
//!
//! # Memory safety
//!
//! The whole crate compiles under the crate-root `#![forbid(unsafe_code)]`; this
//! module contains **zero** `unsafe`. All binary buffers are `Vec<u8>` and every
//! field is read/written through `to_le_bytes` / `from_le_bytes` (the SMB wire
//! format is little-endian) or `to_be_bytes` / `from_be_bytes` (the NetBIOS
//! length is big-endian), which is correct on every target without any byte-swap
//! abstraction.
//!
//! # NTLM delegation
//!
//! SMB authenticates with raw NTLMv1: the 24-byte LM and NT responses computed
//! from the password and the server challenge. That cryptography is **delegated
//! entirely** to [`crate::auth::ntlm`] (the analog of curl's
//! `USE_CURL_NTLM_CORE` gate, which is exactly why this module is only compiled
//! when both the `smb` and `ntlm` features are enabled). No NTLM crypto is
//! reimplemented here.

use std::sync::Mutex;

use crate::auth::ntlm::{lm_resp, mk_lm_hash, mk_nt_hash};
use crate::conn::{BoxFuture, Connection, Curl_conn_recv, Curl_conn_send, FIRSTSOCKET};
use crate::easy::Easy;
use crate::error::{CurlError, Result};
use crate::protocols::{Protocol, ProtocolTransfer, Scheme, TransferDirection};
// `StrId` / `HttpReq` live in `crate::setopt`, but they are the *public option
// vocabulary* of the `Easy` handle (a declared dependency): the only way to read
// `CURLOPT_USERNAME` / `CURLOPT_PASSWORD` (the `-u user:pass` form that
// `tests/data/test1451` uses) and to detect upload mode (`CURLOPT_UPLOAD` ⇒
// `HttpReq::Put`) is through `data.set.str(StrId::…)` / `data.set.method`. They
// are imported here for that reason.
use crate::setopt::{HttpReq, StrId};
use crate::transfer::uc_to_curlcode;
use crate::url::{CurlUPart, CurlUrl, CURLU_URLDECODE};
use crate::util::sendf::failf;

// ===========================================================================
// Protocol constants — copied verbatim from `lib/smb.c` (the `#define` block).
// ===========================================================================

// --- SMB command codes (`SMB_COM_*`) -----------------------------------------
const SMB_COM_CLOSE: u8 = 0x04;
const SMB_COM_READ_ANDX: u8 = 0x2e;
const SMB_COM_WRITE_ANDX: u8 = 0x2f;
const SMB_COM_TREE_DISCONNECT: u8 = 0x71;
const SMB_COM_NEGOTIATE: u8 = 0x72;
const SMB_COM_SETUP_ANDX: u8 = 0x73;
const SMB_COM_TREE_CONNECT_ANDX: u8 = 0x75;
const SMB_COM_NT_CREATE_ANDX: u8 = 0xa2;
/// The AndX "no further command" sentinel (`SMB_COM_NO_ANDX_COMMAND`).
const SMB_COM_NO_ANDX_COMMAND: u8 = 0xff;

// --- Word counts (`SMB_WC_*`) ------------------------------------------------
const SMB_WC_CLOSE: u8 = 0x03;
const SMB_WC_READ_ANDX: u8 = 0x0c;
const SMB_WC_WRITE_ANDX: u8 = 0x0e;
const SMB_WC_SETUP_ANDX: u8 = 0x0d;
const SMB_WC_TREE_CONNECT_ANDX: u8 = 0x04;
const SMB_WC_NT_CREATE_ANDX: u8 = 0x18;

// --- Header flags (`SMB_FLAGS*`) ---------------------------------------------
const SMB_FLAGS_CANONICAL_PATHNAMES: u8 = 0x10;
const SMB_FLAGS_CASELESS_PATHNAMES: u8 = 0x08;
const SMB_FLAGS2_IS_LONG_NAME: u16 = 0x0040;
const SMB_FLAGS2_KNOWS_LONG_NAME: u16 = 0x0001;

// --- Capability / file-access bits -------------------------------------------
const SMB_CAP_LARGE_FILES: u32 = 0x08;
const SMB_GENERIC_WRITE: u32 = 0x4000_0000;
const SMB_GENERIC_READ: u32 = 0x8000_0000;
const SMB_FILE_SHARE_ALL: u32 = 0x07;
const SMB_FILE_OPEN: u32 = 0x01;
const SMB_FILE_OVERWRITE_IF: u32 = 0x05;
/// The `STATUS_ACCESS_DENIED`-class status curl special-cases (`SMB_ERR_NOACCESS`).
const SMB_ERR_NOACCESS: u32 = 0x0005_0001;

// --- Sizes (bytes) -----------------------------------------------------------
/// The combined NetBIOS (4) + SMB (32) header length (`sizeof(struct smb_header)`).
const SMB_HEADER_LEN: usize = 36;
/// Largest single READ/WRITE payload (`MAX_PAYLOAD_SIZE`).
const MAX_PAYLOAD_SIZE: usize = 0x8000;
/// Largest whole message, including headers (`MAX_MESSAGE_SIZE`).
const MAX_MESSAGE_SIZE: usize = MAX_PAYLOAD_SIZE + 0x1000; // 0x9000
/// The fixed `bytes[]` capacity of the SETUP / TREE_CONNECT / NT_CREATE structs
/// (`sizeof(msg.bytes)` in `lib/smb.c`); requests whose trailing data would
/// exceed it are rejected with [`CurlError::FilesizeExceeded`], exactly as the C
/// code does.
const SMB_MAX_BYTES: usize = 1024;

/// Minimum byte count of a NEGOTIATE response that still carries the full 8-byte
/// challenge: `sizeof(struct smb_negotiate_response) + sizeof(challenge) - 1`
/// = `74 + 8 - 1` (the `- 1` accounts for the struct's `bytes[1]` flexible tail).
const SMB_NEGOTIATE_RESPONSE_MIN: usize = 81;

// --- Fixed strings / identifiers ---------------------------------------------
/// Client name advertised in SESSION_SETUP (`CLIENTNAME`).
const CLIENTNAME: &str = "curl";
/// Service type requested in TREE_CONNECT (`SERVICENAME`, the "any" wildcard).
const SERVICENAME: &str = "?????";
/// The "native OS" string advertised in SESSION_SETUP (curl uses its build-time
/// `CURL_OS`). The server ignores its value; only its length affects framing.
const CURL_OS: &str = "Rust";
/// The made-up process id curl stamps into every SMB header (`pid = 0xbad71d`).
const SMB_PID: u32 = 0x00ba_d71d;

/// The NEGOTIATE request payload: word_count=0, byte_count=0x000c, buffer
/// format 0x02 ("dialect"), then the NUL-terminated dialect string
/// `"NT LM 0.12"`. Exactly 15 bytes (`smb_send_negotiate` passes `15`).
const SMB_NEGOTIATE_PAYLOAD: &[u8] = b"\x00\x0c\x00\x02NT LM 0.12\x00";

// ===========================================================================
// Little/big-endian field readers. The SMB body is little-endian; the NetBIOS
// length is big-endian. Callers always bounds-check (`got >= …`) before reading,
// mirroring the C code's size guards, so the slice indexing below never panics.
// ===========================================================================

#[inline]
fn rd_u16_le(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

#[inline]
fn rd_u16_be(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

#[inline]
fn rd_u32_le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

#[inline]
fn rd_i64_le(b: &[u8], off: usize) -> i64 {
    i64::from_le_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
        b[off + 4],
        b[off + 5],
        b[off + 6],
        b[off + 7],
    ])
}

/// The SMB header `status` field (NT status, little-endian) at offset 9.
#[inline]
fn smb_status(buf: &[u8]) -> u32 {
    rd_u32_le(buf, 9)
}

/// The SMB header `tid` (tree id) field at offset 28.
#[inline]
fn smb_tid(buf: &[u8]) -> u16 {
    rd_u16_le(buf, 28)
}

/// The SMB header `uid` (user id) field at offset 32.
#[inline]
fn smb_uid(buf: &[u8]) -> u16 {
    rd_u16_le(buf, 32)
}

// ===========================================================================
// Message codec — the byte-exact analog of `smb_format_message` /
// `smb_send_message` and the per-command `smb_send_*` builders in `lib/smb.c`.
// Every encoder returns the *payload* that follows the 36-byte header; the
// header is prepended by `build_message` (the exception is WRITE_ANDX, whose C
// struct embeds the header, handled by `build_write_frame`).
// ===========================================================================

/// Encode the 36-byte NetBIOS + SMB header into `out` (`smb_format_message`).
///
/// `payload_len` is the number of SMB body bytes that will follow; the NetBIOS
/// length covers everything after the 4-byte NetBIOS prefix, i.e.
/// `32 + payload_len` (`sizeof(header) - sizeof(u32) + len`), big-endian.
fn encode_header(out: &mut Vec<u8>, command: u8, payload_len: usize, uid: u16, tid: u16) {
    let nbt_length = (SMB_HEADER_LEN - 4 + payload_len) as u16; // 32 + payload_len
    out.push(0x00); // nbt_type
    out.push(0x00); // nbt_flags
    out.extend_from_slice(&nbt_length.to_be_bytes()); // nbt_length (big-endian)
    out.extend_from_slice(b"\xffSMB"); // magic
    out.push(command);
    out.extend_from_slice(&0u32.to_le_bytes()); // status (request: 0)
    out.push(SMB_FLAGS_CANONICAL_PATHNAMES | SMB_FLAGS_CASELESS_PATHNAMES); // flags = 0x18
    out.extend_from_slice(&(SMB_FLAGS2_IS_LONG_NAME | SMB_FLAGS2_KNOWS_LONG_NAME).to_le_bytes()); // flags2 = 0x0041
    out.extend_from_slice(&((SMB_PID >> 16) as u16).to_le_bytes()); // pid_high
    out.extend_from_slice(&[0u8; 8]); // signature
    out.extend_from_slice(&0u16.to_le_bytes()); // pad
    out.extend_from_slice(&tid.to_le_bytes()); // tid
    out.extend_from_slice(&((SMB_PID & 0xffff) as u16).to_le_bytes()); // pid (low)
    out.extend_from_slice(&uid.to_le_bytes()); // uid
    out.extend_from_slice(&0u16.to_le_bytes()); // mid
}

/// Prepend the SMB header to `payload`, producing a complete wire message
/// (`smb_send_message`: header followed by the command payload).
fn build_message(command: u8, uid: u16, tid: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SMB_HEADER_LEN + payload.len());
    encode_header(&mut out, command, payload.len(), uid, tid);
    out.extend_from_slice(payload);
    out
}

/// Build the SESSION_SETUP_ANDX payload (`smb_send_setup`).
///
/// Layout: a 29-byte fixed prefix (word_count, AndX, buffer sizes, the echoed
/// `session_key`, the LM/NT response lengths, capabilities, byte_count) followed
/// by `bytes[]` = LM(24) ‖ NT(24) ‖ user\0 ‖ domain\0 ‖ os\0 ‖ client\0.
fn enc_session_setup_payload(
    session_key: u32,
    lm: &[u8; 24],
    nt: &[u8; 24],
    user: &str,
    domain: &str,
    os: &str,
    client: &str,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        lm.len() + nt.len() + user.len() + domain.len() + os.len() + client.len() + 4,
    );
    bytes.extend_from_slice(lm);
    bytes.extend_from_slice(nt);
    bytes.extend_from_slice(user.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(os.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(client.as_bytes());
    bytes.push(0);

    let mut p = Vec::with_capacity(29 + bytes.len());
    p.push(SMB_WC_SETUP_ANDX); // word_count = 0x0d
    p.push(SMB_COM_NO_ANDX_COMMAND); // andx.command
    p.push(0); // andx.pad
    p.extend_from_slice(&0u16.to_le_bytes()); // andx.offset
    p.extend_from_slice(&(MAX_MESSAGE_SIZE as u16).to_le_bytes()); // max_buffer_size = 0x9000
    p.extend_from_slice(&1u16.to_le_bytes()); // max_mpx_count
    p.extend_from_slice(&1u16.to_le_bytes()); // vc_number
    p.extend_from_slice(&session_key.to_le_bytes()); // session_key (echoed)
    p.extend_from_slice(&(lm.len() as u16).to_le_bytes()); // lengths[0] = 24
    p.extend_from_slice(&(nt.len() as u16).to_le_bytes()); // lengths[1] = 24
    p.extend_from_slice(&0u32.to_le_bytes()); // pad
    p.extend_from_slice(&SMB_CAP_LARGE_FILES.to_le_bytes()); // capabilities
    p.extend_from_slice(&(bytes.len() as u16).to_le_bytes()); // byte_count
    p.extend_from_slice(&bytes);
    p
}

/// Build the TREE_CONNECT_ANDX payload (`smb_send_tree_connect`).
///
/// Layout: an 11-byte fixed prefix followed by `bytes[]` =
/// `\\host\share\0service\0`.
fn enc_tree_connect_payload(host: &str, share: &str, service: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(2 + host.len() + 1 + share.len() + 1 + service.len() + 1);
    bytes.extend_from_slice(b"\\\\"); // two leading backslashes
    bytes.extend_from_slice(host.as_bytes());
    bytes.push(b'\\');
    bytes.extend_from_slice(share.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(service.as_bytes());
    bytes.push(0);

    let mut p = Vec::with_capacity(11 + bytes.len());
    p.push(SMB_WC_TREE_CONNECT_ANDX); // word_count = 0x04
    p.push(SMB_COM_NO_ANDX_COMMAND); // andx.command
    p.push(0); // andx.pad
    p.extend_from_slice(&0u16.to_le_bytes()); // andx.offset
    p.extend_from_slice(&0u16.to_le_bytes()); // flags
    p.extend_from_slice(&0u16.to_le_bytes()); // pw_len
    p.extend_from_slice(&(bytes.len() as u16).to_le_bytes()); // byte_count
    p.extend_from_slice(&bytes);
    p
}

/// Build the NT_CREATE_ANDX (open) payload (`smb_send_open`).
///
/// Layout: a 51-byte fixed prefix followed by `bytes[]` = `path\0`. `upload`
/// selects read+write / overwrite-if-exists vs read-only / open-existing.
fn enc_open_payload(path: &str, upload: bool) -> Vec<u8> {
    let path_bytes = path.as_bytes();
    let byte_count = path_bytes.len() + 1; // path + NUL
    let (access, disposition) = if upload {
        (SMB_GENERIC_READ | SMB_GENERIC_WRITE, SMB_FILE_OVERWRITE_IF)
    } else {
        (SMB_GENERIC_READ, SMB_FILE_OPEN)
    };

    let mut p = Vec::with_capacity(51 + byte_count);
    p.push(SMB_WC_NT_CREATE_ANDX); // word_count = 0x18
    p.push(SMB_COM_NO_ANDX_COMMAND); // andx.command
    p.push(0); // andx.pad
    p.extend_from_slice(&0u16.to_le_bytes()); // andx.offset
    p.push(0); // pad
    p.extend_from_slice(&((byte_count - 1) as u16).to_le_bytes()); // name_length = strlen(path)
    p.extend_from_slice(&0u32.to_le_bytes()); // flags
    p.extend_from_slice(&0u32.to_le_bytes()); // root_fid
    p.extend_from_slice(&access.to_le_bytes()); // access
    p.extend_from_slice(&0i64.to_le_bytes()); // allocation_size
    p.extend_from_slice(&0u32.to_le_bytes()); // ext_file_attributes
    p.extend_from_slice(&SMB_FILE_SHARE_ALL.to_le_bytes()); // share_access
    p.extend_from_slice(&disposition.to_le_bytes()); // create_disposition
    p.extend_from_slice(&0u32.to_le_bytes()); // create_options
    p.extend_from_slice(&0u32.to_le_bytes()); // impersonation_level
    p.push(0); // security_flags
    p.extend_from_slice(&(byte_count as u16).to_le_bytes()); // byte_count = strlen(path)+1
    p.extend_from_slice(path_bytes);
    p.push(0); // NUL terminator
    p
}

/// Build the READ_ANDX request payload (`smb_send_read`). 27 bytes, no body.
fn enc_read_payload(fid: u16, offset: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(27);
    p.push(SMB_WC_READ_ANDX); // word_count = 0x0c
    p.push(SMB_COM_NO_ANDX_COMMAND); // andx.command
    p.push(0); // andx.pad
    p.extend_from_slice(&0u16.to_le_bytes()); // andx.offset
    p.extend_from_slice(&fid.to_le_bytes()); // fid
    p.extend_from_slice(&((offset & 0xffff_ffff) as u32).to_le_bytes()); // offset (low 32)
    p.extend_from_slice(&(MAX_PAYLOAD_SIZE as u16).to_le_bytes()); // max_bytes = 0x8000
    p.extend_from_slice(&(MAX_PAYLOAD_SIZE as u16).to_le_bytes()); // min_bytes = 0x8000
    p.extend_from_slice(&0u32.to_le_bytes()); // timeout
    p.extend_from_slice(&0u16.to_le_bytes()); // remaining
    p.extend_from_slice(&((offset >> 32) as u32).to_le_bytes()); // offset_high
    p.extend_from_slice(&0u16.to_le_bytes()); // byte_count
    p
}

/// Build the CLOSE request payload (`smb_send_close`). 9 bytes.
fn enc_close_payload(fid: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(9);
    p.push(SMB_WC_CLOSE); // word_count = 0x03
    p.extend_from_slice(&fid.to_le_bytes()); // fid
    p.extend_from_slice(&0u32.to_le_bytes()); // last_mtime
    p.extend_from_slice(&0u16.to_le_bytes()); // byte_count
    p
}

/// Build the TREE_DISCONNECT request payload (`smb_send_tree_disconnect`).
/// 3 zero bytes (word_count=0, byte_count=0).
fn enc_tree_disconnect_payload() -> Vec<u8> {
    vec![0u8; 3]
}

/// Build a complete WRITE_ANDX frame *header* (`smb_send_write`).
///
/// Unlike the other commands, the C `struct smb_write` embeds the SMB header, so
/// this returns the full 68-byte frame (header + parameters); the `data_len`
/// body bytes are appended by the caller. `data_offset` is `sizeof(struct) - 4`
/// = 64 (relative to the SMB header), `byte_count` is `data_len + 1`, and the
/// NetBIOS length is `64 + data_len`.
fn build_write_frame(uid: u16, tid: u16, fid: u16, offset: u64, data_len: usize) -> Vec<u8> {
    // payload_len passed to encode_header is the SMB body following the header:
    // (68 - 36) struct-minus-header + data_len = 32 + data_len, giving the
    // NetBIOS length 32 + (32 + data_len) = 64 + data_len.
    let mut out = Vec::with_capacity(68 + data_len);
    encode_header(&mut out, SMB_COM_WRITE_ANDX, 32 + data_len, uid, tid);
    out.push(SMB_WC_WRITE_ANDX); // word_count = 0x0e
    out.push(SMB_COM_NO_ANDX_COMMAND); // andx.command
    out.push(0); // andx.pad
    out.extend_from_slice(&0u16.to_le_bytes()); // andx.offset
    out.extend_from_slice(&fid.to_le_bytes()); // fid
    out.extend_from_slice(&((offset & 0xffff_ffff) as u32).to_le_bytes()); // offset (low 32)
    out.extend_from_slice(&0u32.to_le_bytes()); // timeout
    out.extend_from_slice(&0u16.to_le_bytes()); // write_mode
    out.extend_from_slice(&0u16.to_le_bytes()); // remaining
    out.extend_from_slice(&0u16.to_le_bytes()); // pad
    out.extend_from_slice(&(data_len as u16).to_le_bytes()); // data_length
    out.extend_from_slice(&((68 - 4) as u16).to_le_bytes()); // data_offset = 64
    out.extend_from_slice(&((offset >> 32) as u32).to_le_bytes()); // offset_high
    out.extend_from_slice(&((data_len + 1) as u16).to_le_bytes()); // byte_count
    out.push(0); // pad2
    out
}

// ===========================================================================
// NTLM — delegated to `crate::auth::ntlm`. SMB uses raw NTLMv1: the 24-byte LM
// and NT responses computed from the password and the 8-byte server challenge
// (`smb_send_setup`'s `Curl_ntlm_core_mk_lm_hash` / `mk_nt_hash` /
// `lm_resp` calls). No NTLM cryptography is implemented here.
// ===========================================================================

/// Compute the `(LM, NT)` NTLMv1 responses for `password` over `challenge`.
///
/// Mirrors `smb_send_setup`:
/// `lm = lm_resp(mk_lm_hash(pw), ch)`, `nt = lm_resp(mk_nt_hash(pw), ch)`.
fn ntlm_responses(password: &[u8], challenge: &[u8; 8]) -> ([u8; 24], [u8; 24]) {
    let lm_hash = mk_lm_hash(password);
    let lm = lm_resp(&lm_hash, challenge);
    let nt_hash = mk_nt_hash(password);
    let nt = lm_resp(&nt_hash, challenge);
    (lm, nt)
}

// ===========================================================================
// URL path / credential parsing — the analog of `smb_parse_url_path` and the
// user/domain split in `smb_connect`.
// ===========================================================================

/// Parse a (URL-decoded) SMB path into `(share, file_path)` (`smb_parse_url_path`).
///
/// A leading `/` or `\` is dropped, then the first `/` (or, if none, the first
/// `\`) splits the share from the file path. The file path has every forward
/// slash converted to a backslash. A path with no separator (i.e. no file
/// component after the share) is rejected with [`CurlError::UrlMalformat`],
/// matching curl's "missing share in URL path for SMB".
fn parse_url_path(decoded: &str) -> Result<(String, String)> {
    let trimmed = decoded
        .strip_prefix('/')
        .or_else(|| decoded.strip_prefix('\\'))
        .unwrap_or(decoded);

    // curl looks for '/' first, then '\\' (two separate strchr calls).
    let pos = trimmed.find('/').or_else(|| trimmed.find('\\'));
    let Some(i) = pos else {
        return Err(CurlError::UrlMalformat);
    };

    let share = trimmed[..i].to_string();
    let file_path: String = trimmed[i + 1..]
        .chars()
        .map(|c| if c == '/' { '\\' } else { c })
        .collect();
    Ok((share, file_path))
}

/// Split a connection username into `(user, domain)` (`smb_connect`).
///
/// If the username contains `/` (or, failing that, `\`), the part before the
/// separator is the domain and the part after is the user. Otherwise the whole
/// string is the user and the `host` is used as the domain.
fn split_user_domain(user: &str, host: &str) -> (String, String) {
    match user.find('/').or_else(|| user.find('\\')) {
        Some(i) => (user[i + 1..].to_string(), user[..i].to_string()),
        None => (user.to_string(), host.to_string()),
    }
}

/// Convert a Windows `FILETIME` (100-ns ticks since 1601-01-01) to POSIX seconds
/// (`get_posix_time`). Values before the Unix epoch clamp to `0`. On all
/// supported targets `i64` holds the result without the C code's `time_t`
/// clamping.
fn get_posix_time(timestamp: i64) -> i64 {
    const EPOCH_DIFF: i64 = 116_444_736_000_000_000; // 1601→1970 in 100-ns ticks
    if timestamp >= EPOCH_DIFF {
        (timestamp - EPOCH_DIFF) / 10_000_000
    } else {
        0
    }
}

// ===========================================================================
// Response parsers. Each assumes the caller has already verified the message is
// large enough (the `got >= …` guards in the state machine), matching the C
// code's checks before it dereferences the response structs.
// ===========================================================================

/// The NEGOTIATE response's 8-byte challenge (`nrsp->bytes`, offset 73) and the
/// echoed `session_key` (offset 52). Mirrors `smb_connection_state`'s
/// `SMB_NEGOTIATE` arm.
fn parse_negotiate(buf: &[u8]) -> ([u8; 8], u32) {
    let mut challenge = [0u8; 8];
    challenge.copy_from_slice(&buf[73..81]);
    let session_key = rd_u32_le(buf, 52);
    (challenge, session_key)
}

/// The result of parsing an NT_CREATE_ANDX (open) response.
struct OpenResponse {
    /// The opened file handle (`fid`, offset 42).
    fid: u16,
    /// The file size (`end_of_file`, offset 92).
    end_of_file: i64,
    /// The last-change Windows FILETIME (`last_change_time`, offset 72).
    last_change: i64,
}

/// Parse an NT_CREATE_ANDX response (`smb_request_state`'s `SMB_OPEN` arm). The
/// caller must have verified `got >= 100`.
fn parse_open_response(buf: &[u8]) -> OpenResponse {
    OpenResponse {
        fid: rd_u16_le(buf, 42),
        end_of_file: rd_i64_le(buf, 92),
        last_change: rd_i64_le(buf, 72),
    }
}

// ===========================================================================
// I/O abstractions.
//
// `SmbTransport` is the byte pipe the state machine drives. The real
// implementation ([`ConnTransport`]) forwards to the connection filter chain via
// `Curl_conn_send` / `Curl_conn_recv` (so `smbs` TLS is transparent — the TLS
// filter sits in the chain), but keeping it a trait lets the entire SMB engine
// be unit-tested against a scripted in-memory mock with no live socket.
//
// `SmbBodySink` / `SmbBodySource` are the body delivery seam. The SMB protocol
// itself extracts/embeds file bytes inside READ/WRITE PDUs, so it cannot defer
// body movement to a generic transfer engine; it pushes downloaded bytes into a
// sink and pulls upload bytes from a source. Bridging those to the user's
// `CURLOPT_WRITEFUNCTION` / `CURLOPT_READFUNCTION` (raw C function pointers) is
// the FFI layer's job — invoking a C callback requires `unsafe`, which is
// forbidden in this crate — so here the sink/source are safe, owned buffers.
// ===========================================================================

/// An async, object-safe byte transport for the SMB exchange.
///
/// `Send` is a supertrait so the futures that hold `&mut dyn SmbTransport`
/// across `.await` points remain `Send`, matching the [`BoxFuture`] contract of
/// [`Protocol`].
pub(crate) trait SmbTransport: Send {
    /// Send the whole of `buf` may take multiple calls; returns bytes accepted.
    fn send<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, Result<usize>>;
    /// Receive up to `buf.len()` bytes; `Ok(0)` signals the peer closed.
    fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize>>;
    /// Record a user-facing failure message (the `failf` sink).
    fn fail(&mut self, message: &str);
}

/// The live transport: the connection's `FIRSTSOCKET` filter chain.
struct ConnTransport<'c> {
    conn: &'c mut Connection,
}

impl SmbTransport for ConnTransport<'_> {
    fn send<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move { Curl_conn_send(self.conn, FIRSTSOCKET, buf, false).await })
    }

    fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move { Curl_conn_recv(self.conn, FIRSTSOCKET, buf).await })
    }

    fn fail(&mut self, message: &str) {
        failf(&mut self.conn.filter_data.error_buffer, message);
    }
}

/// A sink for downloaded response-body bytes.
///
/// `Send` is a supertrait for the same reason as [`SmbTransport`].
pub(crate) trait SmbBodySink: Send {
    /// Deliver `data` (a contiguous run of body bytes). Returning an error
    /// aborts the download with that error, mirroring a failed `Curl_client_write`.
    fn write_body(&mut self, data: &[u8]) -> Result<()>;
}

/// A source of upload-body bytes.
///
/// `Send` is a supertrait for the same reason as [`SmbTransport`].
pub(crate) trait SmbBodySource: Send {
    /// Fill up to `buf.len()` bytes, returning the count read (`0` == EOF).
    fn read_body(&mut self, buf: &mut [u8]) -> Result<usize>;
}

/// A [`SmbBodySink`] that appends every delivery to an owned `Vec<u8>`.
struct VecBodySink<'a> {
    out: &'a mut Vec<u8>,
}

impl SmbBodySink for VecBodySink<'_> {
    fn write_body(&mut self, data: &[u8]) -> Result<()> {
        self.out.extend_from_slice(data);
        Ok(())
    }
}

/// A [`SmbBodySink`] that discards everything (used as the unused sink slot on
/// the upload path, where no body is delivered to the client).
struct NullBodySink;

impl SmbBodySink for NullBodySink {
    fn write_body(&mut self, _data: &[u8]) -> Result<()> {
        Ok(())
    }
}

/// A [`SmbBodySource`] reading sequentially from an in-memory slice.
struct SliceBodySource<'a> {
    data: &'a [u8],
    pos: usize,
}

impl SmbBodySource for SliceBodySource<'_> {
    fn read_body(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = (self.data.len() - self.pos).min(buf.len());
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Send the entirety of `buf`, looping until every byte is accepted
/// (`smb_send` + `smb_flush`'s partial-write handling). A zero-length accept is
/// treated as a send failure.
async fn send_all(t: &mut dyn SmbTransport, buf: &[u8]) -> Result<()> {
    let mut sent = 0;
    while sent < buf.len() {
        let n = t.send(&buf[sent..]).await?;
        if n == 0 {
            return Err(CurlError::SendError);
        }
        sent += n;
    }
    Ok(())
}

// ===========================================================================
// SmbSession — the SMBv1 state machine (the analog of `smb_connection_state`
// for NEGOTIATE/SESSION_SETUP and `smb_request_state` for the request flow).
// Because the engine is async, each "send the next message / process the
// previous response" step is just `send` then `await recv`.
// ===========================================================================

/// The outcome of a successful request: the transfer size and the file's
/// last-change FILETIME (used to satisfy `CURLOPT_FILETIME`).
struct RequestOutcome {
    /// Bytes transferred (download: server `end_of_file`; upload: `infilesize`).
    size: i64,
    /// The opened file's last-change FILETIME (Windows ticks).
    last_change: i64,
}

/// The full SMB session: the parsed request parameters plus the negotiated and
/// per-request protocol state, and a reusable receive buffer.
struct SmbSession {
    // --- request parameters (parsed from the URL / credentials) -------------
    host: String,
    share: String,
    user: String,
    domain: String,
    file_path: String,
    // --- negotiated / per-request state -------------------------------------
    challenge: [u8; 8],
    session_key: u32,
    uid: u16,
    tid: u16,
    fid: u16,
    // --- receive buffer (the C `smbc->recv_buf` + `got`) --------------------
    recv_buf: Vec<u8>,
    got: usize,
}

impl SmbSession {
    /// Create a session for the given parsed request parameters.
    fn new(host: String, share: String, user: String, domain: String, file_path: String) -> Self {
        Self {
            host,
            share,
            user,
            domain,
            file_path,
            challenge: [0u8; 8],
            session_key: 0,
            uid: 0,
            tid: 0,
            fid: 0,
            recv_buf: vec![0u8; MAX_MESSAGE_SIZE],
            got: 0,
        }
    }

    /// The bytes of the message currently in the receive buffer.
    fn frame(&self) -> &[u8] {
        &self.recv_buf[..self.got]
    }

    /// Receive one complete SMB message into `recv_buf` (`smb_recv_message`).
    ///
    /// Resets the accumulator, then reads until a whole NetBIOS frame is present
    /// (`nbt_size = read16_be(buf+2) + 4`), validating the frame size against
    /// the SMB minimum / maximum and the embedded word/byte counts exactly as
    /// the C code does.
    async fn recv_message(&mut self, t: &mut dyn SmbTransport) -> Result<()> {
        self.got = 0;
        loop {
            if self.got >= MAX_MESSAGE_SIZE {
                return Err(CurlError::RecvError);
            }
            let n = {
                let slice = &mut self.recv_buf[self.got..MAX_MESSAGE_SIZE];
                t.recv(slice).await?
            };
            if n == 0 {
                // Peer closed before a complete message arrived.
                return Err(CurlError::RecvError);
            }
            self.got += n;

            // Need the 4-byte NetBIOS header before we can size the frame.
            if self.got < 4 {
                continue;
            }
            let nbt_size = rd_u16_be(&self.recv_buf, 2) as usize + 4;
            if nbt_size > MAX_MESSAGE_SIZE {
                t.fail("too large NetBIOS frame");
                return Err(CurlError::RecvError);
            }
            if nbt_size < SMB_HEADER_LEN {
                t.fail("too small NetBIOS frame");
                return Err(CurlError::RecvError);
            }
            if self.got < nbt_size {
                continue;
            }
            return self.validate_frame(nbt_size);
        }
    }

    /// Validate that the received frame is internally consistent: its declared
    /// word count and byte count fit within the NetBIOS size (`smb_recv_message`
    /// tail). A truncated structure is a [`CurlError::RecvError`].
    fn validate_frame(&self, nbt_size: usize) -> Result<()> {
        let mut msg_size = SMB_HEADER_LEN;
        // C: `if(nbt_size >= msg_size + 1)` — identical to `> msg_size` for usize.
        if nbt_size > msg_size {
            let word_count = self.recv_buf[msg_size] as usize;
            msg_size += 1 + word_count * 2;
            if nbt_size >= msg_size + 2 {
                let byte_count = rd_u16_le(&self.recv_buf, msg_size) as usize;
                msg_size += 2 + byte_count;
                if nbt_size < msg_size {
                    return Err(CurlError::RecvError);
                }
            }
        }
        Ok(())
    }

    /// Send NEGOTIATE and process the response, capturing the challenge and the
    /// echoed session key (`smb_send_negotiate` + the `SMB_NEGOTIATE` arm).
    async fn negotiate(&mut self, t: &mut dyn SmbTransport) -> Result<()> {
        let msg = build_message(SMB_COM_NEGOTIATE, 0, 0, SMB_NEGOTIATE_PAYLOAD);
        send_all(t, &msg).await?;
        self.recv_message(t).await?;
        if self.got < SMB_NEGOTIATE_RESPONSE_MIN || smb_status(self.frame()) != 0 {
            return Err(CurlError::CouldntConnect);
        }
        let (challenge, session_key) = parse_negotiate(self.frame());
        self.challenge = challenge;
        self.session_key = session_key;
        Ok(())
    }

    /// Send SESSION_SETUP_ANDX with the NTLM responses and process the response,
    /// capturing the assigned `uid` (`smb_send_setup` + the `SMB_SETUP` arm).
    async fn session_setup(&mut self, t: &mut dyn SmbTransport, password: &[u8]) -> Result<()> {
        let byte_count =
            24 + 24 + self.user.len() + self.domain.len() + CURL_OS.len() + CLIENTNAME.len() + 4; // four NUL terminators
        if byte_count > SMB_MAX_BYTES {
            return Err(CurlError::FilesizeExceeded);
        }

        let (lm, nt) = ntlm_responses(password, &self.challenge);
        let payload = enc_session_setup_payload(
            self.session_key,
            &lm,
            &nt,
            &self.user,
            &self.domain,
            CURL_OS,
            CLIENTNAME,
        );
        let msg = build_message(SMB_COM_SETUP_ANDX, self.uid, self.tid, &payload);
        send_all(t, &msg).await?;
        self.recv_message(t).await?;
        if smb_status(self.frame()) != 0 {
            return Err(CurlError::LoginDenied);
        }
        self.uid = smb_uid(self.frame());
        Ok(())
    }

    /// Run the request: TREE_CONNECT, then (open → download/upload → close) with
    /// a guaranteed TREE_DISCONNECT once the tree is connected. Mirrors the
    /// cleanup ordering of `smb_request_state`.
    async fn transfer(
        &mut self,
        t: &mut dyn SmbTransport,
        upload: bool,
        source: &mut dyn SmbBodySource,
        sink: &mut dyn SmbBodySink,
        infilesize: i64,
    ) -> Result<RequestOutcome> {
        // TREE_CONNECT. On failure the tree is not connected, so there is
        // nothing to disconnect — return straight away (C: next_state = DONE).
        self.tree_connect(t).await?;

        // From here the tree IS connected: always TREE_DISCONNECT on the way
        // out, regardless of how the inner phase ends.
        let inner = self.open_and_io(t, upload, source, sink, infilesize).await;
        let _ = self.tree_disconnect(t).await; // ignore disconnect failure
        inner
    }

    /// Open the file, perform the body transfer, and CLOSE. On open failure the
    /// file is not open, so CLOSE is skipped (C: open failure → TREE_DISCONNECT
    /// directly); otherwise CLOSE always runs after the transfer.
    async fn open_and_io(
        &mut self,
        t: &mut dyn SmbTransport,
        upload: bool,
        source: &mut dyn SmbBodySource,
        sink: &mut dyn SmbBodySink,
        infilesize: i64,
    ) -> Result<RequestOutcome> {
        let open = self.open(t, upload).await?;

        // The file is open: CLOSE must run before returning, success or error.
        let result = self
            .io_after_open(t, upload, source, sink, infilesize, &open)
            .await;
        let _ = self.close(t).await; // ignore close failure (C ignores it too)
        result
    }

    /// Decide size/direction and drive READ_ANDX or WRITE_ANDX to completion
    /// (the `SMB_OPEN` size logic plus the `SMB_DOWNLOAD` / `SMB_UPLOAD` arms).
    async fn io_after_open(
        &mut self,
        t: &mut dyn SmbTransport,
        upload: bool,
        source: &mut dyn SmbBodySource,
        sink: &mut dyn SmbBodySink,
        infilesize: i64,
        open: &OpenResponse,
    ) -> Result<RequestOutcome> {
        if upload {
            let size = infilesize;
            self.do_upload(t, source, size).await?;
            Ok(RequestOutcome {
                size,
                last_change: open.last_change,
            })
        } else {
            let size = open.end_of_file;
            if size < 0 {
                return Err(CurlError::WeirdServerReply);
            }
            self.do_download(t, sink).await?;
            Ok(RequestOutcome {
                size,
                last_change: open.last_change,
            })
        }
    }

    /// Send TREE_CONNECT_ANDX and process the response, capturing the `tid`
    /// (`smb_send_tree_connect` + the `SMB_TREE_CONNECT` arm). A non-zero status
    /// maps to [`CurlError::RemoteAccessDenied`] for `STATUS_ACCESS_DENIED`,
    /// otherwise [`CurlError::RemoteFileNotFound`].
    async fn tree_connect(&mut self, t: &mut dyn SmbTransport) -> Result<()> {
        let byte_count = self.host.len() + self.share.len() + SERVICENAME.len() + 5;
        if byte_count > SMB_MAX_BYTES {
            return Err(CurlError::FilesizeExceeded);
        }
        let payload = enc_tree_connect_payload(&self.host, &self.share, SERVICENAME);
        let msg = build_message(SMB_COM_TREE_CONNECT_ANDX, self.uid, self.tid, &payload);
        send_all(t, &msg).await?;
        self.recv_message(t).await?;
        let status = smb_status(self.frame());
        if status != 0 {
            return Err(if status == SMB_ERR_NOACCESS {
                CurlError::RemoteAccessDenied
            } else {
                CurlError::RemoteFileNotFound
            });
        }
        self.tid = smb_tid(self.frame());
        Ok(())
    }

    /// Send NT_CREATE_ANDX (open) and process the response, capturing the `fid`
    /// (`smb_send_open` + the `SMB_OPEN` arm).
    async fn open(&mut self, t: &mut dyn SmbTransport, upload: bool) -> Result<OpenResponse> {
        if self.file_path.len() + 1 > SMB_MAX_BYTES {
            return Err(CurlError::FilesizeExceeded);
        }
        let payload = enc_open_payload(&self.file_path, upload);
        let msg = build_message(SMB_COM_NT_CREATE_ANDX, self.uid, self.tid, &payload);
        send_all(t, &msg).await?;
        self.recv_message(t).await?;
        let status = smb_status(self.frame());
        if status != 0 || self.got < 100 {
            return Err(if status == SMB_ERR_NOACCESS {
                CurlError::RemoteAccessDenied
            } else {
                CurlError::RemoteFileNotFound
            });
        }
        let open = parse_open_response(self.frame());
        self.fid = open.fid;
        Ok(open)
    }

    /// Drive READ_ANDX until a short read terminates the download
    /// (the `SMB_DOWNLOAD` arm). Body runs are pushed to `sink`.
    async fn do_download(
        &mut self,
        t: &mut dyn SmbTransport,
        sink: &mut dyn SmbBodySink,
    ) -> Result<()> {
        let mut offset: u64 = 0;
        loop {
            let payload = enc_read_payload(self.fid, offset);
            let msg = build_message(SMB_COM_READ_ANDX, self.uid, self.tid, &payload);
            send_all(t, &msg).await?;
            self.recv_message(t).await?;
            if smb_status(self.frame()) != 0 || self.got < SMB_HEADER_LEN + 15 {
                return Err(CurlError::RecvError);
            }
            let len = rd_u16_le(self.frame(), SMB_HEADER_LEN + 11) as usize; // data_length @47
            let off = rd_u16_le(self.frame(), SMB_HEADER_LEN + 13) as usize; // data_offset @49
            if len > 0 {
                // `off` is relative to the SMB header (after the 4-byte NetBIOS
                // prefix), so the body starts at `off + 4`.
                if off + 4 + len > self.got {
                    t.fail("Invalid input packet");
                    return Err(CurlError::RecvError);
                }
                sink.write_body(&self.recv_buf[off + 4..off + 4 + len])?;
            }
            offset += len as u64;
            if len < MAX_PAYLOAD_SIZE {
                return Ok(());
            }
        }
    }

    /// Drive WRITE_ANDX until `size` bytes are written (the `SMB_UPLOAD` arm).
    /// Body chunks are pulled from `source` (each capped at `MAX_PAYLOAD_SIZE-1`,
    /// the one byte reserved for padding).
    async fn do_upload(
        &mut self,
        t: &mut dyn SmbTransport,
        source: &mut dyn SmbBodySource,
        size: i64,
    ) -> Result<()> {
        let mut offset: u64 = 0;
        let mut bytecount: i64 = 0;
        let mut chunk = vec![0u8; MAX_PAYLOAD_SIZE - 1];
        loop {
            let remaining = size - bytecount;
            if remaining <= 0 {
                return Ok(());
            }
            let want = remaining.min((MAX_PAYLOAD_SIZE - 1) as i64) as usize;
            let n = source.read_body(&mut chunk[..want])?;
            if n == 0 {
                // Source exhausted before `size`; stop rather than spin.
                return Ok(());
            }
            let mut frame = build_write_frame(self.uid, self.tid, self.fid, offset, n);
            frame.extend_from_slice(&chunk[..n]);
            send_all(t, &frame).await?;
            self.recv_message(t).await?;
            if smb_status(self.frame()) != 0 || self.got < SMB_HEADER_LEN + 7 {
                return Err(CurlError::UploadFailed);
            }
            let count = rd_u16_le(self.frame(), SMB_HEADER_LEN + 5) as i64; // count @41
            bytecount += count;
            offset += count as u64;
            if bytecount >= size {
                return Ok(());
            }
        }
    }

    /// Send CLOSE and consume its response. The response status is ignored (the
    /// C `SMB_CLOSE` arm proceeds to TREE_DISCONNECT regardless).
    async fn close(&mut self, t: &mut dyn SmbTransport) -> Result<()> {
        let payload = enc_close_payload(self.fid);
        let msg = build_message(SMB_COM_CLOSE, self.uid, self.tid, &payload);
        send_all(t, &msg).await?;
        self.recv_message(t).await?;
        Ok(())
    }

    /// Send TREE_DISCONNECT and consume its response (the `SMB_TREE_DISCONNECT`
    /// arm). The status is ignored.
    async fn tree_disconnect(&mut self, t: &mut dyn SmbTransport) -> Result<()> {
        let payload = enc_tree_disconnect_payload();
        let msg = build_message(SMB_COM_TREE_DISCONNECT, self.uid, self.tid, &payload);
        send_all(t, &msg).await?;
        self.recv_message(t).await?;
        Ok(())
    }
}

// ===========================================================================
// SmbProtocol — the `crate::protocols::Protocol` handler (the analog of the C
// `Curl_protocol_smb` vtable and the `Curl_scheme_smb` / `Curl_scheme_smbs`
// descriptors).
// ===========================================================================

/// The SMB / SMBS protocol handler.
///
/// One instance backs a single transfer (the engine creates it from
/// `scheme_handler`). Because [`Protocol`] methods take `&self`, the body
/// buffers are behind a [`Mutex`]: they are the **seam** where the
/// async SMB engine meets the synchronous C body callbacks. The FFI / transfer
/// engine (which owns the `unsafe` bridge to `CURLOPT_WRITEFUNCTION` /
/// `CURLOPT_READFUNCTION`) fills [`set_upload_body`](Self::set_upload_body)
/// before an upload and drains [`take_download_body`](Self::take_download_body)
/// after a download.
pub struct SmbProtocol {
    scheme: &'static Scheme,
    /// Bytes downloaded during [`do_it`](Protocol::do_it), awaiting delivery to
    /// the client write callback.
    download_body: Mutex<Vec<u8>>,
    /// Bytes to upload, supplied by the client read callback before transfer.
    upload_body: Mutex<Vec<u8>>,
}

impl SmbProtocol {
    /// Create a handler for the given scheme descriptor (`SCHEME_SMB` or
    /// `SCHEME_SMBS`).
    #[must_use]
    pub fn new(scheme: &'static Scheme) -> Self {
        Self {
            scheme,
            download_body: Mutex::new(Vec::new()),
            upload_body: Mutex::new(Vec::new()),
        }
    }

    /// Take the bytes downloaded by the last [`do_it`](Protocol::do_it), leaving
    /// the buffer empty. Used by the engine/FFI to forward the body to the
    /// client write callback.
    #[must_use]
    pub fn take_download_body(&self) -> Vec<u8> {
        let mut guard = self.download_body.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *guard)
    }

    /// Provide the body to upload on the next [`do_it`](Protocol::do_it). Used by
    /// the engine/FFI to stage bytes pulled from the client read callback.
    pub fn set_upload_body(&self, data: Vec<u8>) {
        let mut guard = self.upload_body.lock().unwrap_or_else(|e| e.into_inner());
        *guard = data;
    }
}

impl Protocol for SmbProtocol {
    fn scheme(&self) -> &'static Scheme {
        self.scheme
    }

    /// Validate the URL path up front (`smb_setup_connection` →
    /// `smb_parse_url_path`): the share component must be present.
    fn setup_connection<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let Some(url_str) = data.url().map(str::to_string) else {
                return Err(CurlError::UrlMalformat);
            };
            let mut u = CurlUrl::new();
            u.set(CurlUPart::Url, Some(&url_str), 0)
                .map_err(uc_to_curlcode)?;
            let path = u
                .get(CurlUPart::Path, CURLU_URLDECODE)
                .map_err(uc_to_curlcode)?;
            match parse_url_path(&path) {
                Ok(_) => Ok(()),
                Err(e) => {
                    failf(
                        &mut conn.filter_data.error_buffer,
                        "missing share in URL path for SMB",
                    );
                    Err(e)
                }
            }
        })
    }

    /// Drive the entire SMB exchange (the fused `smb_connect` +
    /// `smb_connection_state` + `smb_request_state` flow): NEGOTIATE →
    /// SESSION_SETUP (NTLM) → TREE_CONNECT → open → download/upload → close →
    /// TREE_DISCONNECT.
    fn do_it<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<ProtocolTransfer>> {
        Box::pin(async move {
            // --- Resolve the URL path and credentials --------------------------
            let Some(url_str) = data.url().map(str::to_string) else {
                return Err(CurlError::UrlMalformat);
            };
            let mut u = CurlUrl::new();
            u.set(CurlUPart::Url, Some(&url_str), 0)
                .map_err(uc_to_curlcode)?;
            let decoded_path = u
                .get(CurlUPart::Path, CURLU_URLDECODE)
                .map_err(uc_to_curlcode)?;
            let (share, file_path) = match parse_url_path(&decoded_path) {
                Ok(parts) => parts,
                Err(e) => {
                    failf(
                        &mut conn.filter_data.error_buffer,
                        "missing share in URL path for SMB",
                    );
                    return Err(e);
                }
            };

            // Credentials: CURLOPT_USERNAME / CURLOPT_PASSWORD (the `-u` form)
            // take precedence over any URL userinfo, mirroring curl's resolved
            // `conn->user` / `conn->passwd`.
            let opt_user = data.set.str(StrId::Username).map(str::to_string);
            let opt_pass = data.set.str(StrId::Password).map(str::to_string);
            let url_user = u.get(CurlUPart::User, CURLU_URLDECODE).ok();
            let url_pass = u.get(CurlUPart::Password, CURLU_URLDECODE).ok();

            let full_user = match opt_user.or(url_user) {
                Some(name) if !name.is_empty() => name,
                _ => {
                    // C `smb_connect`: no username ⇒ CURLE_LOGIN_DENIED.
                    return Err(CurlError::LoginDenied);
                }
            };
            let password = opt_pass.or(url_pass).unwrap_or_default();

            let host = conn.remote_host.clone();
            let (user, domain) = split_user_domain(&full_user, &host);

            // --- Transfer parameters ------------------------------------------
            let upload = data.set.method == HttpReq::Put;
            let get_filetime = data.set.get_filetime;
            let infilesize = data.set.filesize;

            if upload && infilesize < 0 {
                failf(
                    &mut conn.filter_data.error_buffer,
                    "SMB upload needs to know the size up front",
                );
                return Err(CurlError::SendError);
            }

            // --- Drive the session over the connection ------------------------
            let mut transport = ConnTransport { conn };
            let mut session = SmbSession::new(host, share, user, domain, file_path);

            session.negotiate(&mut transport).await?;
            session
                .session_setup(&mut transport, password.as_bytes())
                .await?;

            if upload {
                let upload_data = {
                    let mut guard = self.upload_body.lock().unwrap_or_else(|e| e.into_inner());
                    std::mem::take(&mut *guard)
                };
                let mut source = SliceBodySource {
                    data: &upload_data,
                    pos: 0,
                };
                let mut sink = NullBodySink;
                let outcome = session
                    .transfer(&mut transport, true, &mut source, &mut sink, infilesize)
                    .await?;
                Ok(ProtocolTransfer::new(TransferDirection::Upload)
                    .with_size(outcome.size.max(0) as u64))
            } else {
                let mut downloaded = Vec::new();
                let outcome = {
                    let mut sink = VecBodySink {
                        out: &mut downloaded,
                    };
                    let mut source = SliceBodySource { data: &[], pos: 0 };
                    session
                        .transfer(&mut transport, false, &mut source, &mut sink, infilesize)
                        .await?
                };

                // Satisfy CURLOPT_FILETIME from the file's last-change time.
                if get_filetime {
                    data.info.filetime = get_posix_time(outcome.last_change);
                }

                // Stage the body for the engine/FFI to forward to the client.
                {
                    let mut guard = self.download_body.lock().unwrap_or_else(|e| e.into_inner());
                    *guard = downloaded;
                }

                Ok(ProtocolTransfer::new(TransferDirection::Download)
                    .with_size(outcome.size.max(0) as u64))
            }
        })
    }
}

// ===========================================================================
// Tests. These exercise the byte-exact codec, the NTLM delegation (a known-
// answer test against `crate::auth::ntlm`), the response parsers, the URL /
// credential splitting, and the full async state machine driven over a scripted
// in-memory transport (no live socket). Every layout assertion is checked
// against the offsets in `lib/smb.c`.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::{SCHEME_SMB, SCHEME_SMBS};
    use std::collections::VecDeque;
    use tokio_test::block_on;

    /// Decode an even-length hex string into bytes (test-only helper).
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    /// Build a structurally-valid response frame of `total` bytes carrying
    /// `status`. The NetBIOS length and SMB magic are set so [`recv_message`]
    /// accepts it; word/byte counts are left zero so `validate_frame` passes for
    /// any `total >= 39`. Callers overwrite the specific fields under test.
    fn craft(total: usize, status: u32) -> Vec<u8> {
        assert!(total >= 39);
        let mut b = vec![0u8; total];
        b[2..4].copy_from_slice(&((total - 4) as u16).to_be_bytes()); // NetBIOS length (BE)
        b[4..8].copy_from_slice(b"\xffSMB"); // magic
        b[9..13].copy_from_slice(&status.to_le_bytes()); // status @9
        b
    }

    /// A scripted, in-memory [`SmbTransport`]: `recv` replays queued frames in
    /// order (one per call), `send` records all written bytes (accepting at most
    /// `send_limit` per call, to exercise partial-write looping).
    struct MockTransport {
        inbound: VecDeque<Vec<u8>>,
        sent: Vec<u8>,
        failures: Vec<String>,
        send_limit: usize,
    }

    impl MockTransport {
        fn new(frames: Vec<Vec<u8>>) -> Self {
            Self {
                inbound: frames.into_iter().collect(),
                sent: Vec::new(),
                failures: Vec::new(),
                send_limit: usize::MAX,
            }
        }
    }

    impl SmbTransport for MockTransport {
        fn send<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, Result<usize>> {
            Box::pin(async move {
                let n = buf.len().min(self.send_limit);
                self.sent.extend_from_slice(&buf[..n]);
                Ok(n)
            })
        }

        fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize>> {
            Box::pin(async move {
                match self.inbound.pop_front() {
                    Some(chunk) => {
                        let n = chunk.len().min(buf.len());
                        buf[..n].copy_from_slice(&chunk[..n]);
                        Ok(n)
                    }
                    None => Ok(0),
                }
            })
        }

        fn fail(&mut self, message: &str) {
            self.failures.push(message.to_string());
        }
    }

    fn new_session() -> SmbSession {
        SmbSession::new(
            "HOST".to_string(),
            "TESTS".to_string(),
            "user".to_string(),
            "DOMAIN".to_string(),
            "file".to_string(),
        )
    }

    // ---- Header / field readers ------------------------------------------

    #[test]
    fn header_layout_is_byte_exact() {
        let msg = build_message(SMB_COM_NEGOTIATE, 0x1234, 0x5678, &[0xAA, 0xBB]);
        assert_eq!(msg.len(), SMB_HEADER_LEN + 2);
        assert_eq!(msg[0], 0x00); // nbt_type
        assert_eq!(msg[1], 0x00); // nbt_flags
                                  // NetBIOS length is big-endian and covers 32 + payload (here 34).
        assert_eq!(&msg[2..4], &(34u16).to_be_bytes());
        assert_eq!(&msg[4..8], b"\xffSMB"); // magic
        assert_eq!(msg[8], SMB_COM_NEGOTIATE); // command
        assert_eq!(rd_u32_le(&msg, 9), 0); // status
        assert_eq!(msg[13], 0x18); // flags = canonical|caseless
        assert_eq!(rd_u16_le(&msg, 14), 0x0041); // flags2
        assert_eq!(rd_u16_le(&msg, 16), 0x00ba); // pid_high
        assert_eq!(&msg[18..26], &[0u8; 8]); // signature
        assert_eq!(rd_u16_le(&msg, 26), 0); // pad
        assert_eq!(rd_u16_le(&msg, 28), 0x5678); // tid
        assert_eq!(rd_u16_le(&msg, 30), 0xd71d); // pid_low
        assert_eq!(rd_u16_le(&msg, 32), 0x1234); // uid
        assert_eq!(rd_u16_le(&msg, 34), 0); // mid
        assert_eq!(&msg[36..38], &[0xAA, 0xBB]); // payload
                                                 // The header readers see the right fields.
        assert_eq!(smb_status(&msg), 0);
        assert_eq!(smb_tid(&msg), 0x5678);
        assert_eq!(smb_uid(&msg), 0x1234);
    }

    #[test]
    fn field_readers_roundtrip() {
        let b = [0x78, 0x56, 0x34, 0x12, 0x11, 0x22, 0x33, 0x44];
        assert_eq!(rd_u16_le(&b, 0), 0x5678);
        assert_eq!(rd_u16_be(&b, 0), 0x7856);
        assert_eq!(rd_u32_le(&b, 0), 0x1234_5678);
        let v = [0x01, 0, 0, 0, 0, 0, 0, 0x80];
        assert_eq!(rd_i64_le(&v, 0), i64::from_le_bytes(v));
    }

    // ---- Per-command request layouts -------------------------------------

    #[test]
    fn negotiate_request_layout() {
        let msg = build_message(SMB_COM_NEGOTIATE, 0, 0, SMB_NEGOTIATE_PAYLOAD);
        assert_eq!(msg.len(), SMB_HEADER_LEN + 15);
        assert_eq!(msg[8], SMB_COM_NEGOTIATE);
        assert_eq!(&msg[2..4], &(47u16).to_be_bytes()); // 32 + 15
        assert_eq!(&msg[36..], b"\x00\x0c\x00\x02NT LM 0.12\x00");
    }

    #[test]
    fn session_setup_layout() {
        let lm = [0xAAu8; 24];
        let nt = [0xBBu8; 24];
        let p = enc_session_setup_payload(0xDEAD_BEEF, &lm, &nt, "user", "DOMAIN", "Rust", "curl");
        assert_eq!(p[0], SMB_WC_SETUP_ANDX);
        assert_eq!(p[1], SMB_COM_NO_ANDX_COMMAND);
        assert_eq!(p[2], 0); // andx.pad
        assert_eq!(rd_u16_le(&p, 3), 0); // andx.offset
        assert_eq!(rd_u16_le(&p, 5), MAX_MESSAGE_SIZE as u16); // max_buffer_size
        assert_eq!(rd_u16_le(&p, 7), 1); // max_mpx
        assert_eq!(rd_u16_le(&p, 9), 1); // vc
        assert_eq!(rd_u32_le(&p, 11), 0xDEAD_BEEF); // session_key (echoed)
        assert_eq!(rd_u16_le(&p, 15), 24); // lengths[0]
        assert_eq!(rd_u16_le(&p, 17), 24); // lengths[1]
        assert_eq!(rd_u32_le(&p, 19), 0); // pad
        assert_eq!(rd_u32_le(&p, 23), SMB_CAP_LARGE_FILES); // capabilities
        let byte_count = 24 + 24 + 5 + 7 + 5 + 5; // lm+nt+user\0+DOMAIN\0+Rust\0+curl\0
        assert_eq!(rd_u16_le(&p, 27), byte_count as u16);
        assert_eq!(&p[29..53], &lm); // LM response
        assert_eq!(&p[53..77], &nt); // NT response
        assert_eq!(&p[77..], b"user\x00DOMAIN\x00Rust\x00curl\x00");
        assert_eq!(p.len(), 29 + byte_count);
    }

    #[test]
    fn tree_connect_path_formatting() {
        let p = enc_tree_connect_payload("HOST", "TESTS", SERVICENAME);
        assert_eq!(p[0], SMB_WC_TREE_CONNECT_ANDX);
        let byte_count = 2 + 4 + 1 + 5 + 1 + 5 + 1; // \\ + HOST + \ + TESTS + \0 + ????? + \0
        assert_eq!(rd_u16_le(&p, 9), byte_count as u16);
        assert_eq!(&p[11..], b"\\\\HOST\\TESTS\x00?????\x00");
    }

    #[test]
    fn open_request_layout_download_and_upload() {
        // Download: read-only access, open-existing disposition.
        let p = enc_open_payload("file.txt", false);
        assert_eq!(p[0], SMB_WC_NT_CREATE_ANDX);
        assert_eq!(rd_u16_le(&p, 6), 8); // name_length = strlen("file.txt")
        assert_eq!(rd_u32_le(&p, 16), SMB_GENERIC_READ); // access
        assert_eq!(rd_u32_le(&p, 32), SMB_FILE_SHARE_ALL); // share_access
        assert_eq!(rd_u32_le(&p, 36), SMB_FILE_OPEN); // create_disposition
        assert_eq!(rd_u16_le(&p, 49), 9); // byte_count = strlen + NUL
        assert_eq!(&p[51..], b"file.txt\x00");

        // Upload: read+write access, overwrite-if disposition.
        let u = enc_open_payload("file.txt", true);
        assert_eq!(rd_u32_le(&u, 16), SMB_GENERIC_READ | SMB_GENERIC_WRITE);
        assert_eq!(rd_u32_le(&u, 36), SMB_FILE_OVERWRITE_IF);
    }

    #[test]
    fn read_request_layout() {
        let p = enc_read_payload(0x1234, 0x1_0000_5678);
        assert_eq!(p.len(), 27);
        assert_eq!(p[0], SMB_WC_READ_ANDX);
        assert_eq!(rd_u16_le(&p, 5), 0x1234); // fid
        assert_eq!(rd_u32_le(&p, 7), 0x5678); // offset (low 32)
        assert_eq!(rd_u16_le(&p, 11), MAX_PAYLOAD_SIZE as u16); // max_bytes
        assert_eq!(rd_u16_le(&p, 13), MAX_PAYLOAD_SIZE as u16); // min_bytes
        assert_eq!(rd_u32_le(&p, 21), 1); // offset_high
        assert_eq!(rd_u16_le(&p, 25), 0); // byte_count
    }

    #[test]
    fn write_frame_layout() {
        let f = build_write_frame(0x1111, 0x2222, 0x3333, 0x44, 10);
        assert_eq!(f.len(), 68); // frame only; body appended by caller
        assert_eq!(f[8], SMB_COM_WRITE_ANDX);
        assert_eq!(&f[2..4], &(64u16 + 10).to_be_bytes()); // NetBIOS length
        assert_eq!(rd_u16_le(&f, 28), 0x2222); // tid
        assert_eq!(rd_u16_le(&f, 32), 0x1111); // uid
        assert_eq!(f[36], SMB_WC_WRITE_ANDX);
        assert_eq!(f[37], SMB_COM_NO_ANDX_COMMAND);
        assert_eq!(rd_u16_le(&f, 41), 0x3333); // fid
        assert_eq!(rd_u32_le(&f, 43), 0x44); // offset (low)
        assert_eq!(rd_u16_le(&f, 57), 10); // data_length
        assert_eq!(rd_u16_le(&f, 59), 64); // data_offset = sizeof - 4
        assert_eq!(rd_u16_le(&f, 65), 11); // byte_count = len + 1
    }

    #[test]
    fn close_and_tree_disconnect_layout() {
        let c = enc_close_payload(0xBEEF);
        assert_eq!(c.len(), 9);
        assert_eq!(c[0], SMB_WC_CLOSE);
        assert_eq!(rd_u16_le(&c, 1), 0xBEEF); // fid
        assert_eq!(rd_u32_le(&c, 3), 0); // last_mtime
        assert_eq!(rd_u16_le(&c, 7), 0); // byte_count
        assert_eq!(enc_tree_disconnect_payload(), vec![0u8; 3]);
    }

    // ---- NTLM (delegated to crate::auth::ntlm) ---------------------------

    #[test]
    fn ntlm_responses_known_answer() {
        // Eric Glass NTLM doc: password "SecREt01", challenge 0x0123456789abcdef.
        let challenge = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let (lm, nt) = ntlm_responses(b"SecREt01", &challenge);
        assert_eq!(
            lm.as_slice(),
            hex("C337CD5CBD44FC9782A667AF6D427C6DE67C20C2D3E77C56").as_slice()
        );
        assert_eq!(
            nt.as_slice(),
            hex("25A98C1C31E81847466B29B2DF4680F39958FB8C213A9CC6").as_slice()
        );
    }

    // ---- Response parsers ------------------------------------------------

    #[test]
    fn parse_negotiate_extracts_challenge_and_key() {
        let mut buf = vec![0u8; SMB_NEGOTIATE_RESPONSE_MIN];
        buf[52..56].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        let challenge = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11];
        buf[73..81].copy_from_slice(&challenge);
        let (got_ch, got_key) = parse_negotiate(&buf);
        assert_eq!(got_ch, challenge);
        assert_eq!(got_key, 0x1122_3344);
    }

    #[test]
    fn parse_open_response_extracts_fields() {
        let mut buf = vec![0u8; 100];
        buf[42..44].copy_from_slice(&0x3000u16.to_le_bytes());
        buf[72..80].copy_from_slice(&0x0123_4567_89AB_CDEFi64.to_le_bytes());
        buf[92..100].copy_from_slice(&123_456i64.to_le_bytes());
        let r = parse_open_response(&buf);
        assert_eq!(r.fid, 0x3000);
        assert_eq!(r.last_change, 0x0123_4567_89AB_CDEF);
        assert_eq!(r.end_of_file, 123_456);
    }

    // ---- URL / credential parsing ----------------------------------------

    #[test]
    fn parse_url_path_cases() {
        assert_eq!(
            parse_url_path("/TESTS/1451").unwrap(),
            ("TESTS".to_string(), "1451".to_string())
        );
        assert_eq!(
            parse_url_path("/share/dir/file.txt").unwrap(),
            ("share".to_string(), "dir\\file.txt".to_string())
        );
        // No leading slash is accepted too.
        assert_eq!(
            parse_url_path("TESTS/1451").unwrap(),
            ("TESTS".to_string(), "1451".to_string())
        );
        // Backslash separators behave like forward slashes.
        assert_eq!(
            parse_url_path("\\share\\file").unwrap(),
            ("share".to_string(), "file".to_string())
        );
        // No share separator at all is rejected.
        assert!(matches!(
            parse_url_path("/noseparator"),
            Err(CurlError::UrlMalformat)
        ));
    }

    #[test]
    fn split_user_domain_cases() {
        assert_eq!(
            split_user_domain("DOMAIN/user", "host"),
            ("user".to_string(), "DOMAIN".to_string())
        );
        assert_eq!(
            split_user_domain("DOMAIN\\user", "host"),
            ("user".to_string(), "DOMAIN".to_string())
        );
        // No separator: the host becomes the domain.
        assert_eq!(
            split_user_domain("user", "host"),
            ("user".to_string(), "host".to_string())
        );
    }

    #[test]
    fn get_posix_time_cases() {
        const EPOCH_DIFF: i64 = 116_444_736_000_000_000;
        assert_eq!(get_posix_time(0), 0); // before the Unix epoch clamps to 0
        assert_eq!(get_posix_time(EPOCH_DIFF), 0); // exactly the epoch
        assert_eq!(get_posix_time(EPOCH_DIFF + 10_000_000), 1); // +1 second
        assert_eq!(get_posix_time(EPOCH_DIFF + 5_000_000), 0); // sub-second truncates
    }

    // ---- Transport helpers -----------------------------------------------

    #[test]
    fn send_all_loops_on_partial_writes() {
        let mut mock = MockTransport::new(vec![]);
        mock.send_limit = 1; // accept one byte per call
        block_on(send_all(&mut mock, b"abcdef")).expect("send_all completes");
        assert_eq!(mock.sent, b"abcdef");
    }

    #[test]
    fn send_all_treats_zero_accept_as_error() {
        let mut mock = MockTransport::new(vec![]);
        mock.send_limit = 0; // never accepts anything
        let err = block_on(send_all(&mut mock, b"x")).unwrap_err();
        assert_eq!(err, CurlError::SendError);
    }

    // ---- recv_message framing --------------------------------------------

    #[test]
    fn recv_message_assembles_split_frame() {
        // A valid 51-byte frame split across two reads.
        let frame = craft(51, 0);
        let mut mock = MockTransport::new(vec![frame[..20].to_vec(), frame[20..].to_vec()]);
        let mut s = new_session();
        block_on(s.recv_message(&mut mock)).expect("frame assembled");
        assert_eq!(s.got, 51);
        assert_eq!(s.frame(), &frame[..]);
    }

    #[test]
    fn recv_message_rejects_too_large() {
        // NetBIOS length 0xFFFF → nbt_size 65539 > MAX_MESSAGE_SIZE.
        let mut mock = MockTransport::new(vec![vec![0x00, 0x00, 0xFF, 0xFF]]);
        let mut s = new_session();
        let err = block_on(s.recv_message(&mut mock)).unwrap_err();
        assert_eq!(err, CurlError::RecvError);
        assert!(mock.failures.iter().any(|m| m.contains("too large")));
    }

    #[test]
    fn recv_message_rejects_too_small() {
        // NetBIOS length 0 → nbt_size 4 < SMB_HEADER_LEN.
        let mut mock = MockTransport::new(vec![vec![0x00, 0x00, 0x00, 0x00]]);
        let mut s = new_session();
        let err = block_on(s.recv_message(&mut mock)).unwrap_err();
        assert_eq!(err, CurlError::RecvError);
        assert!(mock.failures.iter().any(|m| m.contains("too small")));
    }

    // ---- Session phase methods -------------------------------------------

    #[test]
    fn negotiate_parses_response() {
        let mut resp = craft(85, 0);
        resp[52..56].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        let challenge = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11];
        resp[73..81].copy_from_slice(&challenge);
        let mut mock = MockTransport::new(vec![resp]);
        let mut s = new_session();
        block_on(s.negotiate(&mut mock)).expect("negotiate ok");
        assert_eq!(s.session_key, 0x1122_3344);
        assert_eq!(s.challenge, challenge);
        assert_eq!(mock.sent[8], SMB_COM_NEGOTIATE); // a NEGOTIATE was sent
    }

    #[test]
    fn negotiate_rejects_short_or_failed() {
        // Too short to carry the challenge.
        let mut mock = MockTransport::new(vec![craft(64, 0)]);
        let mut s = new_session();
        assert_eq!(
            block_on(s.negotiate(&mut mock)).unwrap_err(),
            CurlError::CouldntConnect
        );
        // Long enough but a non-zero status.
        let mut mock = MockTransport::new(vec![craft(85, 1)]);
        let mut s = new_session();
        assert_eq!(
            block_on(s.negotiate(&mut mock)).unwrap_err(),
            CurlError::CouldntConnect
        );
    }

    #[test]
    fn session_setup_sets_uid() {
        let mut resp = craft(100, 0);
        resp[32..34].copy_from_slice(&0xABCDu16.to_le_bytes()); // uid @32
        let mut mock = MockTransport::new(vec![resp]);
        let mut s = new_session();
        s.challenge = [0, 1, 2, 3, 4, 5, 6, 7];
        block_on(s.session_setup(&mut mock, b"password")).expect("setup ok");
        assert_eq!(s.uid, 0xABCD);
        assert_eq!(mock.sent[8], SMB_COM_SETUP_ANDX); // a SESSION_SETUP was sent
    }

    #[test]
    fn session_setup_login_denied_on_status() {
        let mut mock = MockTransport::new(vec![craft(100, 0x00C0_0000)]);
        let mut s = new_session();
        s.challenge = [0; 8];
        assert_eq!(
            block_on(s.session_setup(&mut mock, b"pw")).unwrap_err(),
            CurlError::LoginDenied
        );
    }

    // ---- Full download / upload over the scripted transport --------------

    #[test]
    fn full_download_via_mock() {
        let body = b"Hello, SMB world!"; // 17 bytes
        let filetime = 130_000_000_000_000_000i64;

        // 1: NEGOTIATE response.
        let mut neg = craft(85, 0);
        neg[52..56].copy_from_slice(&0u32.to_le_bytes());
        neg[73..81].copy_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7]);
        // 2: SESSION_SETUP response (assigns uid).
        let mut setup = craft(64, 0);
        setup[32..34].copy_from_slice(&0x1000u16.to_le_bytes());
        // 3: TREE_CONNECT response (assigns tid).
        let mut tree = craft(64, 0);
        tree[28..30].copy_from_slice(&0x2000u16.to_le_bytes());
        // 4: NT_CREATE response (fid, last_change, end_of_file).
        let mut open = craft(110, 0);
        open[42..44].copy_from_slice(&0x3000u16.to_le_bytes());
        open[72..80].copy_from_slice(&filetime.to_le_bytes());
        open[92..100].copy_from_slice(&(body.len() as i64).to_le_bytes());
        // 5: READ response (len @47, data_offset @49, body at off+4).
        let off: u16 = 55;
        let read_total = off as usize + 4 + body.len();
        let mut read = craft(read_total, 0);
        read[47..49].copy_from_slice(&(body.len() as u16).to_le_bytes());
        read[49..51].copy_from_slice(&off.to_le_bytes());
        read[(off as usize + 4)..(off as usize + 4 + body.len())].copy_from_slice(body);
        // 6, 7: CLOSE + TREE_DISCONNECT responses.
        let close = craft(64, 0);
        let tdis = craft(64, 0);

        let mut mock = MockTransport::new(vec![neg, setup, tree, open, read, close, tdis]);
        let mut s = new_session();
        block_on(s.negotiate(&mut mock)).unwrap();
        block_on(s.session_setup(&mut mock, b"pw")).unwrap();

        let mut downloaded = Vec::new();
        {
            let mut sink = VecBodySink {
                out: &mut downloaded,
            };
            let mut src = SliceBodySource { data: &[], pos: 0 };
            let outcome = block_on(s.transfer(&mut mock, false, &mut src, &mut sink, -1)).unwrap();
            assert_eq!(outcome.size, body.len() as i64);
            assert_eq!(outcome.last_change, filetime);
        }
        assert_eq!(downloaded.as_slice(), body);
        // The tree id captured from TREE_CONNECT was used.
        assert_eq!(s.tid, 0x2000);
        assert_eq!(s.fid, 0x3000);
    }

    #[test]
    fn full_upload_via_mock() {
        let body = b"upload-me"; // 9 bytes
        let infilesize = body.len() as i64;

        let mut neg = craft(85, 0);
        neg[73..81].copy_from_slice(&[0; 8]);
        let mut setup = craft(64, 0);
        setup[32..34].copy_from_slice(&0x1000u16.to_le_bytes());
        let tree = craft(64, 0);
        let mut open = craft(110, 0);
        open[42..44].copy_from_slice(&0x4242u16.to_le_bytes());
        open[92..100].copy_from_slice(&infilesize.to_le_bytes());
        // WRITE response: bytes-written count @ offset 41.
        let mut write = craft(64, 0);
        write[41..43].copy_from_slice(&(body.len() as u16).to_le_bytes());
        let close = craft(64, 0);
        let tdis = craft(64, 0);

        let mut mock = MockTransport::new(vec![neg, setup, tree, open, write, close, tdis]);
        let mut s = new_session();
        block_on(s.negotiate(&mut mock)).unwrap();
        block_on(s.session_setup(&mut mock, b"pw")).unwrap();

        let mut sink = NullBodySink;
        let mut src = SliceBodySource { data: body, pos: 0 };
        let outcome =
            block_on(s.transfer(&mut mock, true, &mut src, &mut sink, infilesize)).unwrap();
        assert_eq!(outcome.size, infilesize);
        // The uploaded body bytes were written to the wire after the WRITE frame.
        assert!(mock.sent.windows(body.len()).any(|w| w == body));
    }

    #[test]
    fn tree_connect_access_denied_maps_error() {
        let mut mock = MockTransport::new(vec![craft(64, SMB_ERR_NOACCESS)]);
        let mut s = new_session();
        assert_eq!(
            block_on(s.tree_connect(&mut mock)).unwrap_err(),
            CurlError::RemoteAccessDenied
        );
    }

    // ---- SmbProtocol handler ---------------------------------------------

    #[test]
    fn smb_protocol_scheme_and_body_accessors() {
        let p = SmbProtocol::new(&SCHEME_SMB);
        assert_eq!(p.scheme(), &SCHEME_SMB);
        assert_eq!(SmbProtocol::new(&SCHEME_SMBS).scheme().name, "smbs");

        // Download body drains on take.
        assert!(p.take_download_body().is_empty());
        *p.download_body.lock().unwrap() = vec![1, 2, 3];
        assert_eq!(p.take_download_body(), vec![1, 2, 3]);
        assert!(p.take_download_body().is_empty());

        // Upload body is stored by the setter.
        p.set_upload_body(vec![9, 8, 7]);
        assert_eq!(*p.upload_body.lock().unwrap(), vec![9, 8, 7]);
    }
}
