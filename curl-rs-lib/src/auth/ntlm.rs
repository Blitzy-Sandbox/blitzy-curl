//! NTLM authentication — type-1 (negotiate), type-2 (challenge) decode, and
//! type-3 (authenticate), including the NTLMv2 response.
//!
//! This module is a pure-Rust language rewrite of the curl 8.19.0-DEV files
//! `lib/vauth/ntlm.c` (NTLM message construction and parsing) and
//! `lib/curl_ntlm_core.c` (the NT/LM hash and challenge-response crypto). It
//! reproduces curl's on-the-wire NTLM behaviour byte-for-byte: NTLM is a binary
//! protocol in which every field offset, length, and multi-byte integer (all
//! little-endian) is load-bearing, so the layouts here mirror the C source
//! exactly.
//!
//! # Parity with curl 8.x
//!
//! * Only the non-SSPI code paths are reproduced. curl gates the Windows SSPI
//!   implementation behind `USE_WINDOWS_SSPI` in `lib/vauth/ntlm_sspi.c`; that
//!   file is intentionally **dropped** (Windows is out of scope) and this module
//!   is the sole NTLM implementation, corresponding to curl's
//!   `#if defined(USE_NTLM) && !defined(USE_WINDOWS_SSPI)` branch.
//! * In C, the DES and MD4 primitives were borrowed from whichever TLS backend
//!   was linked (OpenSSL / GnuTLS / mbedTLS / ...), guarded by a thicket of
//!   `#if defined(USE_*_DES)` branches. Here there is exactly one path: the
//!   pure-Rust [`des`] and [`md4`] crates. No C library is linked, and — per the
//!   crate-wide memory-safety policy enforced at the crate root — this module
//!   contains no raw-pointer, FFI, or otherwise unchecked code whatsoever: the
//!   crypto crates are used only through their safe, bounds-checked APIs.
//! * The winbind (`NTLM_WB`) helper is **not** implemented; curl removed it in
//!   8.8.0 and it is out of scope here (Minimal Change Mandate).
//!
//! # Public surface
//!
//! The three message primitives ([`create_type1_message`],
//! [`decode_type2_message`], [`create_type3_message`]) mirror the corresponding
//! `Curl_auth_*_ntlm_*` functions. The multi-step NTLM state machine that drives
//! them (HTTP `WWW-Authenticate` / `Authorization` round-trips) lives in curl's
//! `lib/http_ntlm.c`, which is a separate concern and not part of this file; the
//! shared [`NtlmData`] state struct is what the connection layer
//! ([`crate::auth::ConnAuthState`]) owns across those steps.

use crate::error::{Error, Result};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use des::cipher::generic_array::GenericArray;
use des::cipher::{BlockEncrypt, KeyInit};
use des::Des;
use hmac::{Hmac, Mac};
use md4::{Digest as _, Md4};
use md5::Md5;
use rand::RngCore;

/// Concrete HMAC-MD5 instantiation used by the NTLMv2 response crypto.
type HmacMd5 = Hmac<Md5>;

// ---------------------------------------------------------------------------
// Phase A — constants, flag bitmask, and little-endian helpers
// (← lib/vauth/ntlm.c L44-158, lib/curl_ntlm_core.h SHORTPAIR/LONGQUARTET)
// ---------------------------------------------------------------------------

/// The `"NTLMSSP\0"` signature that prefixes every NTLM message.
///
/// curl notes that this signature is always ASCII regardless of the platform
/// (`lib/vauth/ntlm.c` L44-45: `"\x4e\x54\x4c\x4d\x53\x53\x50"` plus the
/// trailing NUL written separately). Here it is the full 8-byte sequence
/// `4e 54 4c 4d 53 53 50 00`.
const NTLMSSP_SIGNATURE: &[u8] = b"NTLMSSP\0";

/// Fixed NTLM working-buffer size, matching curl's `NTLM_BUFSIZE`
/// (`lib/vauth/ntlm.c` L48). A type-3 message larger than this is rejected with
/// [`CurlCode::TooLarge`](crate::error::CurlCode::TooLarge), exactly as curl
/// does, to bound the amount of user/domain/host data that can be encoded.
const NTLM_BUFSIZE: usize = 1024;

// NTLM flag bits, transcribed verbatim from `lib/vauth/ntlm.c` L53-159 (based on
// <https://davenport.sourceforge.net/ntlm.html>). curl compiles most of these
// only under `DEBUG_ME`, but the Minimal Change Mandate is to reproduce the full
// set exactly; they form the public flag vocabulary of the protocol and several
// are referenced by the connection/driver layer, so all are `pub const`.

/// Unicode strings are supported in security-buffer data.
pub const NTLMFLAG_NEGOTIATE_UNICODE: u32 = 1 << 0;
/// OEM (ASCII) strings are supported in security-buffer data.
pub const NTLMFLAG_NEGOTIATE_OEM: u32 = 1 << 1;
/// Requests that the server's authentication realm be included in the type-2
/// message.
pub const NTLMFLAG_REQUEST_TARGET: u32 = 1 << 2;
/* bit 3 is unused/unknown in curl */
/// Authenticated communication should carry a digital signature.
pub const NTLMFLAG_NEGOTIATE_SIGN: u32 = 1 << 4;
/// Authenticated communication should be encrypted.
pub const NTLMFLAG_NEGOTIATE_SEAL: u32 = 1 << 5;
/// Datagram-style authentication is in use.
pub const NTLMFLAG_NEGOTIATE_DATAGRAM_STYLE: u32 = 1 << 6;
/// The LAN Manager session key should be used for signing and sealing.
pub const NTLMFLAG_NEGOTIATE_LM_KEY: u32 = 1 << 7;
/// NTLM authentication is being used.
pub const NTLMFLAG_NEGOTIATE_NTLM_KEY: u32 = 1 << 9;
/// An anonymous context has been established (type-3).
pub const NTLMFLAG_NEGOTIATE_ANONYMOUS: u32 = 1 << 11;
/// A desired authentication realm is included in the type-1 message.
pub const NTLMFLAG_NEGOTIATE_DOMAIN_SUPPLIED: u32 = 1 << 12;
/// The client workstation name is included in the type-1 message.
pub const NTLMFLAG_NEGOTIATE_WORKSTATION_SUPPLIED: u32 = 1 << 13;
/// Server and client are on the same machine (local security context).
pub const NTLMFLAG_NEGOTIATE_LOCAL_CALL: u32 = 1 << 14;
/// Authenticated communication should be signed with a dummy signature.
pub const NTLMFLAG_NEGOTIATE_ALWAYS_SIGN: u32 = 1 << 15;
/// The target authentication realm is a domain (type-2).
pub const NTLMFLAG_TARGET_TYPE_DOMAIN: u32 = 1 << 16;
/// The target authentication realm is a server (type-2).
pub const NTLMFLAG_TARGET_TYPE_SERVER: u32 = 1 << 17;
/// The target authentication realm is a share (type-2).
pub const NTLMFLAG_TARGET_TYPE_SHARE: u32 = 1 << 18;
/// The NTLM2 signing/sealing scheme (a.k.a. NTLMv2 session security) should be
/// used. Its presence in the decoded type-2 flags selects the NTLMv2 response
/// path in [`create_type3_message`].
pub const NTLMFLAG_NEGOTIATE_NTLM2_KEY: u32 = 1 << 19;
/// Request init response (unknown purpose in curl).
pub const NTLMFLAG_REQUEST_INIT_RESPONSE: u32 = 1 << 20;
/// Request accept response (unknown purpose in curl).
pub const NTLMFLAG_REQUEST_ACCEPT_RESPONSE: u32 = 1 << 21;
/// Request non-NT session key (unknown purpose in curl).
pub const NTLMFLAG_REQUEST_NONNT_SESSION_KEY: u32 = 1 << 22;
/// The server is including a Target Information block (type-2).
pub const NTLMFLAG_NEGOTIATE_TARGET_INFO: u32 = 1 << 23;
/// 128-bit encryption is supported.
pub const NTLMFLAG_NEGOTIATE_128: u32 = 1 << 29;
/// The client will provide an encrypted master key in the type-3 Session Key
/// field.
pub const NTLMFLAG_NEGOTIATE_KEY_EXCHANGE: u32 = 1 << 30;
/// 56-bit encryption is supported.
pub const NTLMFLAG_NEGOTIATE_56: u32 = 1 << 31;

/// Append `value` as a little-endian 16-bit integer (curl's `SHORTPAIR`).
#[inline]
fn push_u16_le(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_le_bytes());
}

/// Append `value` as a little-endian 32-bit integer (curl's `LONGQUARTET`).
#[inline]
fn push_u32_le(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

/// Read a little-endian 16-bit integer at `off` (curl's `Curl_read16_le`).
///
/// The two callers guard the buffer length first (mirroring curl), so `off + 1`
/// is always in range.
#[inline]
fn read_u16_le(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([bytes[off], bytes[off + 1]])
}

/// Read a little-endian 32-bit integer at `off` (curl's `Curl_read32_le`).
///
/// The callers guard the buffer length first (mirroring curl), so `off + 3` is
/// always in range.
#[inline]
fn read_u32_le(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

/// Encode an ASCII byte slice as UTF-16LE (`lib/curl_ntlm_core.c`
/// `ascii_to_unicode_le` / `lib/vauth/ntlm.c` `unicodecpy`): every source byte
/// is followed by a `0x00` high byte.
fn ascii_to_unicode_le(src: &[u8]) -> Vec<u8> {
    src.iter().flat_map(|&b| [b, 0u8]).collect()
}

/// Encode an ASCII byte slice as **uppercased** UTF-16LE
/// (`lib/curl_ntlm_core.c` `ascii_uppercase_to_unicode_le`): each byte is
/// upper-cased (ASCII) then followed by a `0x00` high byte. Used for the NTLMv2
/// hash identity, where only the user name (not the domain) is upper-cased.
fn ascii_upper_to_unicode_le(src: &[u8]) -> Vec<u8> {
    src.iter()
        .flat_map(|&b| [b.to_ascii_uppercase(), 0u8])
        .collect()
}

// ---------------------------------------------------------------------------
// Phase B — NtlmData connection state
// (← `struct ntlmdata` non-SSPI branch, lib/vauth/vauth.h L163-186)
// ---------------------------------------------------------------------------

/// Per-connection NTLM state carried between the three message steps.
///
/// This is the Rust equivalent of curl's non-SSPI `struct ntlmdata`
/// (`lib/vauth/vauth.h`). The type-2 decode fills [`flags`](Self::flags),
/// [`nonce`](Self::nonce) (the 8-byte server challenge), and
/// [`target_info`](Self::target_info); the type-3 build reads them back.
///
/// curl stored the target info as a raw `void *target_info` plus a separate
/// `unsigned int target_info_len`, freed by a hand-written destructor. Here the
/// two collapse into an owned [`Vec<u8>`]: its length replaces `target_info_len`
/// and Rust's ownership/`Drop` replaces the manual `free`, so [`reset`] never
/// leaks and never double-frees.
///
/// [`crate::auth::ConnAuthState`] stores this as `Option<NtlmData>` for both the
/// origin host and the proxy.
///
/// [`reset`]: NtlmData::reset
#[derive(Debug, Default, Clone)]
pub struct NtlmData {
    /// The NTLM flags negotiated by the server, decoded from the type-2 message
    /// (`ntlmdata.flags`). Read back when building the type-3 message, and
    /// echoed into it.
    pub flags: u32,
    /// The 8-byte server challenge from the type-2 message (`ntlmdata.nonce`).
    pub nonce: [u8; 8],
    /// The Target Information block from the type-2 message
    /// (`ntlmdata.target_info` + `ntlmdata.target_info_len`), used verbatim
    /// inside the NTLMv2 response blob. Empty when the server sent none.
    pub target_info: Vec<u8>,
}

impl NtlmData {
    /// Clear all NTLM state (port of `Curl_auth_cleanup_ntlm`,
    /// `lib/vauth/ntlm.c` L850-857).
    ///
    /// curl freed `target_info` and zeroed `target_info_len`; this additionally
    /// resets `flags` and `nonce` so a reused struct starts from a clean slate.
    /// No manual free is needed — replacing the [`Vec`] drops the old buffer.
    pub fn reset(&mut self) {
        self.flags = 0;
        self.nonce = [0u8; 8];
        self.target_info.clear();
    }
}

// ---------------------------------------------------------------------------
// Phase C — capability probe
// (← `Curl_auth_is_ntlm_supported`, lib/vauth/ntlm.c L315-318)
// ---------------------------------------------------------------------------

/// Report whether NTLM is available.
///
/// Always `true`. In C this depended on the linked TLS backend providing DES and
/// MD4 (`Curl_auth_is_ntlm_supported` returned `TRUE` whenever NTLM was compiled
/// in); the pure-Rust build always has the [`des`] and [`md4`] crates, so NTLM
/// is unconditionally supported.
#[must_use]
pub fn is_ntlm_supported() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Phase F — cryptographic core
// (← lib/curl_ntlm_core.c: DES key setup, LM/NT hashes, NTLMv2 responses)
// ---------------------------------------------------------------------------

/// Turn a 56-bit (7-byte) key into a 64-bit (8-byte) key by redistributing the
/// bits (port of `extend_key_56_to_64`, `lib/curl_ntlm_core.c` L164-174).
///
/// This bit layout is load-bearing: a single wrong bit breaks every NTLM
/// handshake, so it is transcribed verbatim. In C each expression was masked
/// with `& 0xFF` because the operands were promoted to `int`; on `u8` the shift
/// already truncates to eight bits, so the mask is implicit.
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

/// Apply odd parity to every byte (port of `curl_des_set_odd_parity`,
/// `lib/curl_ntlm_core.c` L142-158).
///
/// For each byte, the parity of its top seven bits is computed; if that parity
/// is even the low bit is set, otherwise it is cleared, making the whole byte's
/// popcount odd. DES itself ignores the parity bit, so this does not change the
/// cipher output, but it is reproduced for exact fidelity with curl.
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
/// (port of `setup_des_key`, `lib/curl_ntlm_core.c` L181-193).
fn setup_des_key(key56: &[u8; 7]) -> [u8; 8] {
    let mut key = extend_key_56_to_64(key56);
    des_set_odd_parity(&mut key);
    key
}

/// Encrypt one 8-byte block with single DES in ECB mode, using an already
/// expanded 8-byte key. Uses the pure-Rust [`des`] crate through its safe
/// `cipher` API only (no raw crypto-library calls, no C linkage).
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

/// Copy a 7-byte window out of a key buffer at `start`.
///
/// `start` is always a multiple of 7 within a 21-byte (or 14-byte) buffer, so
/// the source slice is always exactly seven bytes long.
fn seven(keys: &[u8], start: usize) -> [u8; 7] {
    let mut k = [0u8; 7];
    k.copy_from_slice(&keys[start..start + 7]);
    k
}

/// Treat a 21-byte key as three 56-bit DES keys, DES-ECB-encrypt the 8-byte
/// `plaintext` with each, and concatenate the three ciphertexts into a 24-byte
/// response (port of `Curl_ntlm_core_lm_resp`, `lib/curl_ntlm_core.c`
/// L312-348). This computes both the NTLMv1 NT response and the LM response.
///
/// `pub(crate)` because the SMB protocol handler
/// (`crate::protocols::smb`) reuses this raw NTLMv1 DESL primitive directly —
/// curl's SMB `SESSION SETUP` embeds the bare 24-byte LM/NT responses
/// (`Curl_ntlm_core_lm_resp`) in the security blob rather than a base64
/// NTLMSSP message, so it must call this the same way `smb_send_setup` does.
pub(crate) fn lm_resp(keys: &[u8; 21], plaintext: &[u8; 8]) -> [u8; 24] {
    let mut out = [0u8; 24];
    out[0..8].copy_from_slice(&des_encrypt_with_56(&seven(keys, 0), plaintext));
    out[8..16].copy_from_slice(&des_encrypt_with_56(&seven(keys, 7), plaintext));
    out[16..24].copy_from_slice(&des_encrypt_with_56(&seven(keys, 14), plaintext));
    out
}

/// The LM-hash magic constant `"KGS!@#$%"` (`lib/curl_ntlm_core.c` L357-359).
const LM_MAGIC: [u8; 8] = [0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25];

/// Build the 21-byte LAN Manager hashed password
/// (port of `Curl_ntlm_core_mk_lm_hash`, `lib/curl_ntlm_core.c` L353-394).
///
/// The password is upper-cased (ASCII) and truncated/zero-padded to 14 bytes,
/// split into two 7-byte DES keys, each of which encrypts the LM magic constant;
/// the two 8-byte ciphertexts are concatenated and the buffer is zero-padded to
/// 21 bytes.
///
/// `pub(crate)` so the SMB handler (`crate::protocols::smb`) can build the LM
/// key exactly as curl's `smb_send_setup` does (`Curl_ntlm_core_mk_lm_hash`).
pub(crate) fn mk_lm_hash(password: &str) -> [u8; 21] {
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
/// (port of `Curl_ntlm_core_mk_nt_hash`, `lib/curl_ntlm_core.c` L410-432).
///
/// The password is encoded as UTF-16LE (each byte followed by `0x00`, matching
/// curl's byte-wise `ascii_to_unicode_le` — curl does not perform real
/// UTF-8→UTF-16 transcoding, and that quirk is preserved), MD4-hashed into the
/// first 16 bytes, and the buffer is zero-padded to 21 bytes.
///
/// `pub(crate)` so the SMB handler (`crate::protocols::smb`) can build the NT
/// key exactly as curl's `smb_send_setup` does (`Curl_ntlm_core_mk_nt_hash`).
pub(crate) fn mk_nt_hash(password: &str) -> [u8; 21] {
    let unicode_pw = ascii_to_unicode_le(password.as_bytes());
    let digest = Md4::digest(unicode_pw);
    let mut nt = [0u8; 21];
    nt[0..16].copy_from_slice(&digest);
    // nt[16..21] remains zero.
    nt
}

/// Compute HMAC-MD5 over `data` with `key`, returning the 16-byte tag
/// (the pure-Rust equivalent of curl's `Curl_hmacit(&Curl_HMAC_MD5, ...)`).
///
/// HMAC accepts keys of any length, so `new_from_slice` cannot actually fail;
/// the error is nonetheless mapped rather than unwrapped so this module contains
/// no panic paths, mirroring curl's fallible `CURLcode` return.
fn hmac_md5(key: &[u8], data: &[u8]) -> Result<[u8; 16]> {
    // Fully-qualify `Mac::new_from_slice`: both `hmac::Mac` and
    // `des::cipher::KeyInit` are in scope and each provides a `new_from_slice`,
    // so an unqualified call is ambiguous (E0034).
    let mut mac = <HmacMd5 as Mac>::new_from_slice(key)
        .map_err(|_| Error::auth("NTLM: invalid HMAC-MD5 key length"))?;
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag);
    Ok(out)
}

/// Convert Unix seconds to an MS FILETIME — tenths of a microsecond since
/// 1601-01-01 UTC (port of `time2filetime`, 64-bit path,
/// `lib/curl_ntlm_core.c` L446-451).
///
/// The returned `u64`'s little-endian byte order already places the low 32 bits
/// first, which is exactly the `LONGQUARTET(low), LONGQUARTET(high)` sequence
/// curl writes into the NTLMv2 blob. Wrapping arithmetic guards against overflow
/// for absurd inputs; for any realistic timestamp the value is exact.
fn time2filetime(unix_seconds: i64) -> u64 {
    /// Seconds between 1601-01-01 and 1970-01-01 (134774 days).
    const EPOCH_BIAS_SECS: i64 = 11_644_473_600;
    let biased = unix_seconds.wrapping_add(EPOCH_BIAS_SECS);
    (biased as u64).wrapping_mul(10_000_000)
}

/// Build the 16-byte NTLMv2 hash: `HMAC-MD5(NT-hash, UTF16LE(UPPER(user) +
/// domain))` (port of `Curl_ntlm_core_mk_ntlmv2_hash`,
/// `lib/curl_ntlm_core.c` L502-529).
///
/// Only the user name is upper-cased; the domain is encoded as-is. The HMAC key
/// is the first 16 bytes of the NT hash.
fn mk_ntlmv2_hash(user: &str, domain: &str, nt_hash: &[u8; 21]) -> Result<[u8; 16]> {
    let mut identity = ascii_upper_to_unicode_le(user.as_bytes());
    identity.extend_from_slice(&ascii_to_unicode_le(domain.as_bytes()));
    hmac_md5(&nt_hash[..16], &identity)
}

/// Build the NTLMv2 response placed in the type-3 message
/// (port of `Curl_ntlm_core_mk_ntlmv2_resp`, `lib/curl_ntlm_core.c` L548-625).
///
/// Layout (little-endian throughout):
///
/// ```text
///  0   HMAC-MD5           16 bytes
/// ---- BLOB ---------------------------------------------------------------
/// 16   Signature          0x01 0x01 0x00 0x00
/// 20   Reserved           0x00000000
/// 24   Timestamp          64-bit MS FILETIME
/// 32   Client nonce       8 bytes
/// 40   Reserved           0x00000000
/// 44   Target info        N bytes (from the type-2 message)
/// 44+N Reserved           0x00000000
/// ```
///
/// The HMAC is computed over `server_challenge || BLOB` and then written over
/// the leading 16 bytes, exactly as curl does.
fn mk_ntlmv2_resp(
    ntlmv2hash: &[u8; 16],
    client_nonce: &[u8; 8],
    ntlm: &NtlmData,
    unix_seconds: i64,
) -> Result<Vec<u8>> {
    let target_info = &ntlm.target_info;
    // NTLMv2_BLOB_LEN = (44 - 16) + target_info_len + 4 = 32 + N.
    let blob_len = 32 + target_info.len();
    // HMAC_MD5_LENGTH (16) + blob.
    let total_len = 16 + blob_len;
    let mut resp = vec![0u8; total_len];

    // BLOB signature at offset 16.
    resp[16] = 0x01;
    resp[17] = 0x01;
    // resp[18], resp[19] remain zero.
    // resp[20..24] reserved — remain zero.
    // Timestamp at offset 24 (64-bit LE = low quartet then high quartet).
    resp[24..32].copy_from_slice(&time2filetime(unix_seconds).to_le_bytes());
    // Client nonce at offset 32.
    resp[32..40].copy_from_slice(client_nonce);
    // resp[40..44] reserved — remain zero.
    // Target info at offset 44.
    if !target_info.is_empty() {
        resp[44..44 + target_info.len()].copy_from_slice(target_info);
    }
    // resp[44+N..48+N] trailing reserved — remain zero.

    // Place the server challenge at [8..16] so the HMAC input is the contiguous
    // `server_challenge || BLOB`, hash it, then overwrite [0..16] with the tag.
    resp[8..16].copy_from_slice(&ntlm.nonce);
    let tag = hmac_md5(&ntlmv2hash[..], &resp[8..8 + blob_len + 8])?;
    resp[0..16].copy_from_slice(&tag);

    Ok(resp)
}

/// Build the 24-byte LMv2 response
/// (port of `Curl_ntlm_core_mk_lmv2_resp`, `lib/curl_ntlm_core.c` L641-663):
/// `HMAC-MD5(NTLMv2-hash, server_nonce || client_nonce)` followed by the
/// 8-byte client nonce.
fn mk_lmv2_resp(
    ntlmv2hash: &[u8; 16],
    client_nonce: &[u8; 8],
    server_nonce: &[u8; 8],
) -> Result<[u8; 24]> {
    let mut data = [0u8; 16];
    data[0..8].copy_from_slice(server_nonce);
    data[8..16].copy_from_slice(client_nonce);

    let tag = hmac_md5(&ntlmv2hash[..], &data)?;

    let mut lmresp = [0u8; 24];
    lmresp[0..16].copy_from_slice(&tag);
    lmresp[16..24].copy_from_slice(client_nonce);
    Ok(lmresp)
}

// ---------------------------------------------------------------------------
// Phase D — type-1 (negotiate) message
// (← `Curl_auth_create_ntlm_type1_message`, lib/vauth/ntlm.c L423-526)
// ---------------------------------------------------------------------------

/// Build the base64-encoded NTLM type-1 (negotiate) message.
///
/// This is the first message the client sends. curl always emits a fixed 32-byte
/// message with empty domain/workstation security buffers and the flag set
/// `OEM | REQUEST_TARGET | NEGOTIATE_NTLM_KEY | NEGOTIATE_NTLM2_KEY |
/// ALWAYS_SIGN` (`0x0008_8206`). The [`NtlmData`] state is reset first (curl
/// calls `Curl_auth_cleanup_ntlm`).
///
/// The returned string is the raw base64 payload; the HTTP layer wraps it as
/// `Authorization: NTLM <payload>`.
///
/// # Errors
///
/// Infallible in practice; returns [`Result`] for signature symmetry with the
/// other message builders.
pub fn create_type1_message(ntlm: &mut NtlmData) -> Result<String> {
    // Clean up any former leftovers and initialise to defaults.
    ntlm.reset();

    let flags = NTLMFLAG_NEGOTIATE_OEM
        | NTLMFLAG_REQUEST_TARGET
        | NTLMFLAG_NEGOTIATE_NTLM_KEY
        | NTLMFLAG_NEGOTIATE_NTLM2_KEY
        | NTLMFLAG_NEGOTIATE_ALWAYS_SIGN;

    // Host and domain are empty in curl's type-1, so every security-buffer field
    // is zero and the total message is exactly 32 bytes.
    //  0: signature (8 bytes)
    //  8: message type = 1
    // 12: flags
    // 16: Supplied Domain security buffer — empty (len, alloc, offset, +2 zero)
    // 24: Supplied Workstation security buffer — empty
    // 32: no data block (host/domain empty)
    let mut buf = Vec::with_capacity(32);
    buf.extend_from_slice(NTLMSSP_SIGNATURE);
    push_u32_le(&mut buf, 1);
    push_u32_le(&mut buf, flags);
    push_secbuf(&mut buf, 0, 0);
    push_secbuf(&mut buf, 0, 0);

    debug_assert_eq!(buf.len(), 32);
    Ok(BASE64.encode(&buf))
}

// ---------------------------------------------------------------------------
// Phase E — type-2 (challenge) message decode
// (← `Curl_auth_decode_ntlm_type2_message` + `ntlm_decode_type2_target`,
//    lib/vauth/ntlm.c L256-392)
// ---------------------------------------------------------------------------

/// The "bad type-2 message" error curl reports via
/// `CURLE_BAD_CONTENT_ENCODING`.
fn bad_type2() -> Error {
    Error::bad_content_encoding("NTLM handshake failure (bad type-2 message)")
}

/// Decode the target-info security buffer of a type-2 message
/// (port of `ntlm_decode_type2_target`, `lib/vauth/ntlm.c` L256-288).
fn decode_type2_target(type2: &[u8], ntlm: &mut NtlmData) -> Result<()> {
    let type2len = type2.len();

    if type2len >= 48 {
        let target_info_len = usize::from(read_u16_le(type2, 40));
        let target_info_offset = read_u32_le(type2, 44) as usize;
        if target_info_len > 0 {
            // Bounds-check the buffer against the message length. The
            // `offset + len` arithmetic cannot overflow `usize` here because
            // both terms are already bounded (`len` ≤ u16::MAX, and `offset`
            // ≤ u32::MAX) far below `usize::MAX` on the supported 64-bit targets.
            if target_info_offset > type2len
                || target_info_offset + target_info_len > type2len
                || target_info_offset < 48
            {
                return Err(bad_type2());
            }
            ntlm.target_info =
                type2[target_info_offset..target_info_offset + target_info_len].to_vec();
        }
    }

    Ok(())
}

/// Decode a base64-encoded NTLM type-2 (challenge) message into `ntlm`.
///
/// On success the server challenge is stored in [`NtlmData::nonce`], the
/// negotiated flags in [`NtlmData::flags`], and (when the server set
/// [`NTLMFLAG_NEGOTIATE_TARGET_INFO`]) the target-information block in
/// [`NtlmData::target_info`]. These feed the subsequent
/// [`create_type3_message`] call.
///
/// # Errors
///
/// Returns [`CurlCode::BadContentEncoding`](crate::error::CurlCode::BadContentEncoding)
/// (curl's `CURLE_BAD_CONTENT_ENCODING`) if the payload is not valid base64, is
/// shorter than 32 bytes, lacks the `"NTLMSSP\0"` signature, does not carry the
/// type-2 marker, or has an out-of-bounds target-info security buffer.
pub fn decode_type2_message(type2_b64: &str, ntlm: &mut NtlmData) -> Result<()> {
    // Reset the fields this decode fills. curl only zeroes `flags` here and
    // relies on the preceding type-1 cleanup to have emptied `target_info`; we
    // clear it explicitly so a stale block can never leak into a fresh decode.
    ntlm.flags = 0;
    ntlm.target_info.clear();

    let type2 = BASE64
        .decode(type2_b64.as_bytes())
        .map_err(|_| bad_type2())?;
    let type2len = type2.len();

    // Validate minimum length, signature, and the type-2 marker (little-endian
    // message type == 2). The `||` short-circuits exactly like curl's check, so
    // the signature/marker indexing only runs once the length is known good.
    if type2len < 32
        || type2[0..8] != *NTLMSSP_SIGNATURE
        || type2[8..12] != [0x02, 0x00, 0x00, 0x00]
    {
        return Err(bad_type2());
    }

    ntlm.flags = read_u32_le(&type2, 20);
    ntlm.nonce.copy_from_slice(&type2[24..32]);

    if ntlm.flags & NTLMFLAG_NEGOTIATE_TARGET_INFO != 0 {
        decode_type2_target(&type2, ntlm)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Phase G — type-3 (authenticate) message
// (← `Curl_auth_create_ntlm_type3_message`, lib/vauth/ntlm.c L544-838)
// ---------------------------------------------------------------------------

/// The fixed workstation name curl advertises, to avoid leaking the real local
/// host name (`lib/vauth/ntlm.c` L579-581).
const TYPE3_HOST: &str = "WORKSTATION";

/// Append an NTLM security buffer: `(length, allocated, offset)` where
/// `allocated == length` and the offset is a 32-bit little-endian value whose
/// high 16 bits are always zero (curl writes `SHORTPAIR(len) SHORTPAIR(len)
/// SHORTPAIR(off) 0 0`). All NTLM offsets/lengths fit in 16 bits, well under
/// [`NTLM_BUFSIZE`].
fn push_secbuf(buf: &mut Vec<u8>, len: usize, offset: usize) {
    push_u16_le(buf, len as u16); // length
    push_u16_le(buf, len as u16); // allocated space (mirrors length)
    push_u16_le(buf, offset as u16); // offset, low 16 bits
    push_u16_le(buf, 0); // offset, high 16 bits (always zero)
}

/// Append a domain/user/host string, UTF-16LE-encoded when `unicode` is set
/// (curl's `unicodecpy`) or raw OEM bytes otherwise.
fn append_string(buf: &mut Vec<u8>, s: &[u8], unicode: bool) {
    if unicode {
        buf.extend(ascii_to_unicode_le(s));
    } else {
        buf.extend_from_slice(s);
    }
}

/// Split a username into `(domain, user)`.
///
/// Mirrors curl (`lib/vauth/ntlm.c` L593-603): the domain is the text before the
/// first `\` (preferred) or `/` separator; with no separator the domain is empty
/// and the whole string is the user. Both separators are single-byte ASCII, so
/// slicing at `idx`/`idx + 1` always lands on a UTF-8 char boundary.
fn split_domain_user(userp: &str) -> (&str, &str) {
    match userp.find('\\').or_else(|| userp.find('/')) {
        Some(idx) => (&userp[..idx], &userp[idx + 1..]),
        None => ("", userp),
    }
}

/// Current time as whole Unix seconds, falling back to `0` if the system clock
/// predates the Unix epoch (never panics).
fn current_unix_seconds() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Build the base64-encoded NTLM type-3 (authenticate) message.
///
/// `user` may be a bare username or `Domain\User` / `Domain/User`; `passwd` is
/// the password. The decoded type-2 state in `ntlm` selects the response
/// variant: if the server negotiated [`NTLMFLAG_NEGOTIATE_NTLM2_KEY`] an NTLMv2
/// response is produced, otherwise NTLMv1. String fields are encoded UTF-16LE or
/// OEM according to [`NTLMFLAG_NEGOTIATE_UNICODE`] in the negotiated flags. After
/// the message is built, `ntlm` is reset (curl calls `Curl_auth_cleanup_ntlm`).
///
/// The client nonce is drawn from the thread RNG and the NTLMv2 timestamp from
/// the system clock; see [`create_type3_message_with`] for a deterministic seam.
///
/// # Errors
///
/// Propagates HMAC failures and returns
/// [`CurlCode::TooLarge`](crate::error::CurlCode::TooLarge) if the assembled
/// message would exceed [`NTLM_BUFSIZE`], matching curl's `CURLE_TOO_LARGE`.
pub fn create_type3_message(user: &str, passwd: &str, ntlm: &mut NtlmData) -> Result<String> {
    let mut client_nonce = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut client_nonce);
    create_type3_message_with(user, passwd, ntlm, client_nonce, current_unix_seconds())
}

/// Deterministic variant of [`create_type3_message`] that takes the NTLMv2
/// client nonce and timestamp as explicit inputs.
///
/// This is the wire-parity test seam: NTLM's NTLMv2 response embeds a random
/// client nonce and a timestamp, so byte-for-byte comparison against a reference
/// requires pinning both. Production code calls [`create_type3_message`], which
/// supplies a fresh random nonce and the current time.
pub(crate) fn create_type3_message_with(
    user: &str,
    passwd: &str,
    ntlm: &mut NtlmData,
    client_nonce: [u8; 8],
    unix_seconds: i64,
) -> Result<String> {
    // `unicode` is captured from the negotiated flags before any modification.
    let unicode = ntlm.flags & NTLMFLAG_NEGOTIATE_UNICODE != 0;

    // Split "Domain\User" / "Domain/User"; both `domain` and `user` borrow the
    // caller's string.
    let (domain, user) = split_domain_user(user);

    // Compute the LM and NT responses. NTLMv2 when the server negotiated the
    // NTLM2 session-security key, NTLMv1 otherwise.
    let (lmresp, ntresp): ([u8; 24], Vec<u8>) = if ntlm.flags & NTLMFLAG_NEGOTIATE_NTLM2_KEY != 0 {
        // Full NTLMv2. Although it cannot be explicitly negotiated, curl uses
        // it whenever the server advertises extended (NTLM2) security.
        let nt_hash = mk_nt_hash(passwd);
        let ntlmv2hash = mk_ntlmv2_hash(user, domain, &nt_hash)?;
        let lm = mk_lmv2_resp(&ntlmv2hash, &client_nonce, &ntlm.nonce)?;
        let nt = mk_ntlmv2_resp(&ntlmv2hash, &client_nonce, ntlm, unix_seconds)?;
        (lm, nt)
    } else {
        // NTLMv1.
        let nt_hash = mk_nt_hash(passwd);
        let nt = lm_resp(&nt_hash, &ntlm.nonce);
        let lm_hash = mk_lm_hash(passwd);
        let lm = lm_resp(&lm_hash, &ntlm.nonce);
        // NTLMv1 does not use NTLM2 session security; clear the bit so the
        // flags echoed into the message match curl exactly.
        ntlm.flags &= !NTLMFLAG_NEGOTIATE_NTLM2_KEY;
        (lm, nt.to_vec())
    };

    let ntresplen = ntresp.len();

    // Byte lengths of the string fields; doubled for UTF-16LE.
    let mut domlen = domain.len();
    let mut userlen = user.len();
    let mut hostlen = TYPE3_HOST.len();
    if unicode {
        domlen *= 2;
        userlen *= 2;
        hostlen *= 2;
    }

    // Offsets of each variable-length field within the message (curl L675-679).
    let lmrespoff = 64usize; // size of the fixed message header
    let ntrespoff = lmrespoff + 0x18;
    let domoff = ntrespoff + ntresplen;
    let useroff = domoff + domlen;
    let hostoff = useroff + userlen;

    // Reproduce curl's two `CURLE_TOO_LARGE` overflow guards (L776, L799).
    if ntrespoff + ntresplen > NTLM_BUFSIZE {
        return Err(Error::TooLarge);
    }
    if hostoff + hostlen >= NTLM_BUFSIZE {
        return Err(Error::TooLarge);
    }

    let mut buf: Vec<u8> = Vec::with_capacity(hostoff + hostlen);

    // Fixed 64-byte header.
    buf.extend_from_slice(NTLMSSP_SIGNATURE); // 0: signature (8)
    push_u32_le(&mut buf, 3); // 8: message type = 3
    push_secbuf(&mut buf, 0x18, lmrespoff); // 12: LM/LMv2 response
    push_secbuf(&mut buf, ntresplen, ntrespoff); // 20: NTLM/NTLMv2 response
    push_secbuf(&mut buf, domlen, domoff); // 28: Target Name (domain)
    push_secbuf(&mut buf, userlen, useroff); // 36: User Name
    push_secbuf(&mut buf, hostlen, hostoff); // 44: Workstation (host)
    push_secbuf(&mut buf, 0, 0); // 52: Session Key (empty)
    push_u32_le(&mut buf, ntlm.flags); // 60: flags
    debug_assert_eq!(buf.len(), 64);

    // Data block: the binary responses, then the strings in curl's order.
    buf.extend_from_slice(&lmresp); // 64: LM/LMv2 response (24 bytes)
    debug_assert_eq!(buf.len(), ntrespoff);
    buf.extend_from_slice(&ntresp); // 88: NT/NTLMv2 response
    debug_assert_eq!(buf.len(), domoff);
    append_string(&mut buf, domain.as_bytes(), unicode); // domain
    debug_assert_eq!(buf.len(), useroff);
    append_string(&mut buf, user.as_bytes(), unicode); // user
    debug_assert_eq!(buf.len(), hostoff);
    append_string(&mut buf, TYPE3_HOST.as_bytes(), unicode); // host

    // curl clears the NTLM state after emitting the type-3 message.
    ntlm.reset();

    Ok(BASE64.encode(&buf))
}

// ===========================================================================
// Tests
//
// All expected values are computed by an independent reference implementation
// (a pure-Python MD4 + DES + HMAC-MD5, distinct from the `des`/`md4`/`hmac`
// crates used here) and cross-checked against the canonical published NTLM
// test vectors: the davenport document (password "SecREt01") and the
// [MS-NLMP] §4.2 worked examples (User / Domain / Password). Because NTLM is a
// binary wire protocol, these are byte-exact parity assertions, not smoke
// tests: a single wrong bit in the DES key expansion, MD4, or a field offset
// would change the emitted base64 and fail here.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a hex string into a byte vector (test helper).
    ///
    /// Uses `chunks_exact(2)` (stable since Rust 1.31) rather than a
    /// modulo/`is_multiple_of` length check so the helper both compiles on the
    /// MSRV-1.75 toolchain and satisfies stable clippy.
    fn hx(s: &str) -> Vec<u8> {
        let mut chunks = s.as_bytes().chunks_exact(2);
        let out: Vec<u8> = (&mut chunks)
            .map(|pair| {
                let byte = std::str::from_utf8(pair).expect("ascii hex");
                u8::from_str_radix(byte, 16).expect("valid hex")
            })
            .collect();
        assert!(
            chunks.remainder().is_empty(),
            "hex string must have even length"
        );
        out
    }

    // The 8-byte server challenge and client nonce shared by the wire vectors.
    const SERVER_NONCE: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
    const CLIENT_NONCE: [u8; 8] = [0xAA; 8];

    // -- capability probe ---------------------------------------------------

    #[test]
    fn ntlm_is_always_supported() {
        assert!(is_ntlm_supported());
    }

    // -- DES / key-expansion primitives -------------------------------------

    #[test]
    fn des_empty_lm_half_matches_known_vector() {
        // DES-ECB of the LM magic under an all-zero 56-bit key yields the first
        // half of the well-known LM hash of the empty password. This exercises
        // extend_key_56_to_64 + des_set_odd_parity + the `des` crate together.
        let out = des_encrypt_with_56(&[0u8; 7], &LM_MAGIC);
        assert_eq!(out.to_vec(), hx("aad3b435b51404ee"));
    }

    #[test]
    fn des_key_expansion_sets_odd_parity() {
        // Every output byte of setup_des_key must have odd popcount (DES parity).
        let key = setup_des_key(&[0x13, 0x24, 0x57, 0x68, 0x9A, 0xBC, 0xDE]);
        for b in key {
            assert_eq!(b.count_ones() % 2, 1, "byte {b:#04x} must have odd parity");
        }
    }

    #[test]
    fn extend_key_56_to_64_layout() {
        // Spot-check the documented bit redistribution for a known input.
        // key56 = FF 00 00 00 00 00 00 -> byte0 = FF, byte1 = FF<<7 = 0x80.
        let e = extend_key_56_to_64(&[0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(e[0], 0xFF);
        assert_eq!(e[1], 0x80);
        assert_eq!(&e[2..], &[0u8; 6]);
    }

    // -- NT / LM hashes (canonical vectors) ---------------------------------

    #[test]
    fn nt_hash_empty_password() {
        assert_eq!(
            mk_nt_hash("")[..16].to_vec(),
            hx("31d6cfe0d16ae931b73c59d7e0c089c0")
        );
        // The buffer is zero-padded from 16 to 21 bytes.
        assert_eq!(&mk_nt_hash("")[16..], &[0u8; 5]);
    }

    #[test]
    fn lm_hash_empty_password() {
        assert_eq!(
            mk_lm_hash("")[..16].to_vec(),
            hx("aad3b435b51404eeaad3b435b51404ee")
        );
        assert_eq!(&mk_lm_hash("")[16..], &[0u8; 5]);
    }

    #[test]
    fn nt_and_lm_hash_davenport_secret01() {
        // davenport <https://davenport.sourceforge.net/ntlm.html> worked example.
        assert_eq!(
            mk_nt_hash("SecREt01")[..16].to_vec(),
            hx("cd06ca7c7e10c99b1d33b7485a2ed808")
        );
        assert_eq!(
            mk_lm_hash("SecREt01")[..16].to_vec(),
            hx("ff3750bcc2b22412c2265b23734e0dac")
        );
    }

    #[test]
    fn nt_hash_password_msnlmp() {
        // [MS-NLMP] §4.2.2.1.2 NTOWFv1("Password").
        assert_eq!(
            mk_nt_hash("Password")[..16].to_vec(),
            hx("a4f49c406510bdcab6824ee7c30fd852")
        );
    }

    #[test]
    fn lm_hash_uppercases_and_truncates() {
        // Password is upper-cased before hashing, so these must be identical.
        assert_eq!(mk_lm_hash("secret01"), mk_lm_hash("SECRET01"));
    }

    // -- NTLMv1 challenge-response (davenport) -------------------------------

    #[test]
    fn ntlmv1_responses_davenport() {
        // davenport: password "SecREt01", server challenge 0x0123456789abcdef.
        let nt = lm_resp(&mk_nt_hash("SecREt01"), &SERVER_NONCE);
        assert_eq!(
            nt.to_vec(),
            hx("25a98c1c31e81847466b29b2df4680f39958fb8c213a9cc6")
        );
        let lm = lm_resp(&mk_lm_hash("SecREt01"), &SERVER_NONCE);
        assert_eq!(
            lm.to_vec(),
            hx("c337cd5cbd44fc9782a667af6d427c6de67c20c2d3e77c56")
        );
    }

    // -- NTLMv2 crypto (MS-NLMP + reference) --------------------------------

    #[test]
    fn ntlmv2_hash_msnlmp() {
        // [MS-NLMP] §4.2.4.1.1 NTOWFv2("Password", "User", "Domain").
        let v2 = mk_ntlmv2_hash("User", "Domain", &mk_nt_hash("Password")).unwrap();
        assert_eq!(v2.to_vec(), hx("0c868a403bfd7a93a3001ef22ef02e3f"));
    }

    #[test]
    fn ntlmv2_hash_uppercases_user_not_domain() {
        // Only the user name is upper-cased in the identity; the domain is not.
        let base = mk_ntlmv2_hash("User", "Domain", &mk_nt_hash("Password")).unwrap();
        assert_eq!(
            mk_ntlmv2_hash("USER", "Domain", &mk_nt_hash("Password")).unwrap(),
            base,
            "user name must be case-folded"
        );
        assert_ne!(
            mk_ntlmv2_hash("User", "DOMAIN", &mk_nt_hash("Password")).unwrap(),
            base,
            "domain must be case-sensitive"
        );
    }

    #[test]
    fn lmv2_response_reference() {
        let v2 = mk_ntlmv2_hash("User", "Domain", &mk_nt_hash("Password")).unwrap();
        let lm = mk_lmv2_resp(&v2, &CLIENT_NONCE, &SERVER_NONCE).unwrap();
        assert_eq!(
            lm.to_vec(),
            hx("86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa")
        );
        // The trailing 8 bytes are the client nonce verbatim.
        assert_eq!(&lm[16..], &CLIENT_NONCE);
    }

    #[test]
    fn time2filetime_epoch() {
        // Unix 0 -> tenths of a microsecond since 1601-01-01 = 0x019DB1DED53E8000.
        assert_eq!(time2filetime(0), 0x019D_B1DE_D53E_8000);
        assert_eq!(
            time2filetime(0).to_le_bytes().to_vec(),
            hx("00803ed5deb19d01")
        );
    }

    // -- type-1 negotiate message -------------------------------------------

    #[test]
    fn type1_message_matches_curl() {
        let mut ntlm = NtlmData::default();
        let msg = create_type1_message(&mut ntlm).unwrap();
        // Fixed 32-byte message for flags 0x00088206 (OEM | REQUEST_TARGET |
        // NTLM_KEY | NTLM2_KEY | ALWAYS_SIGN), empty domain/workstation.
        assert_eq!(msg, "TlRMTVNTUAABAAAABoIIAAAAAAAAAAAAAAAAAAAAAAA=");
        // Decode and re-check the raw bytes for good measure.
        let raw = BASE64.decode(msg.as_bytes()).unwrap();
        assert_eq!(raw.len(), 32);
        assert_eq!(&raw[0..8], NTLMSSP_SIGNATURE);
        assert_eq!(&raw[8..12], &[0x01, 0x00, 0x00, 0x00]); // type = 1
        assert_eq!(read_u32_le(&raw, 12), 0x0008_8206); // flags
        assert_eq!(&raw[16..32], &[0u8; 16]); // empty domain + host secbufs
    }

    #[test]
    fn type1_resets_prior_state() {
        let mut ntlm = NtlmData {
            flags: 0xDEAD_BEEF,
            nonce: [9u8; 8],
            target_info: vec![1, 2, 3],
        };
        create_type1_message(&mut ntlm).unwrap();
        assert_eq!(ntlm.flags, 0);
        assert_eq!(ntlm.nonce, [0u8; 8]);
        assert!(ntlm.target_info.is_empty());
    }

    // -- type-2 challenge decode --------------------------------------------

    // Type-2 message crafted with OEM flag, no target info (NTLMv1 scenario).
    const TYPE2_V1: &str = "TlRMTVNTUAACAAAAAAAAAAAAAAACAAAAASNFZ4mrze8AAAAAAAAAAAAAAAAAAAAA";
    // Type-2 with UNICODE | NTLM2_KEY | TARGET_INFO and a 20-byte target info.
    const TYPE2_V2: &str =
        "TlRMTVNTUAACAAAAAAAAAAAAAAABAIgAASNFZ4mrze8AAAAAAAAAABQAFAAwAAAAAgAMAEQATwBNAEEASQBOAAAAAAA=";

    #[test]
    fn decode_type2_v1() {
        let mut ntlm = NtlmData::default();
        decode_type2_message(TYPE2_V1, &mut ntlm).unwrap();
        assert_eq!(ntlm.nonce, SERVER_NONCE);
        assert_eq!(ntlm.flags, NTLMFLAG_NEGOTIATE_OEM);
        assert!(ntlm.target_info.is_empty());
    }

    #[test]
    fn decode_type2_v2_with_target_info() {
        let mut ntlm = NtlmData::default();
        decode_type2_message(TYPE2_V2, &mut ntlm).unwrap();
        assert_eq!(ntlm.nonce, SERVER_NONCE);
        assert_eq!(
            ntlm.flags,
            NTLMFLAG_NEGOTIATE_UNICODE
                | NTLMFLAG_NEGOTIATE_NTLM2_KEY
                | NTLMFLAG_NEGOTIATE_TARGET_INFO
        );
        assert_eq!(
            ntlm.target_info,
            hx("02000c0044004f004d00410049004e0000000000")
        );
    }

    #[test]
    fn decode_type2_rejects_bad_base64() {
        let mut ntlm = NtlmData::default();
        let err = decode_type2_message("not valid base64!!!", &mut ntlm).unwrap_err();
        assert_eq!(err.code(), crate::error::CurlCode::BadContentEncoding);
    }

    #[test]
    fn decode_type2_rejects_short_message() {
        let mut ntlm = NtlmData::default();
        // Valid base64 but far shorter than the 32-byte minimum.
        let short = BASE64.encode(b"NTLMSSP\0");
        assert!(decode_type2_message(&short, &mut ntlm).is_err());
    }

    #[test]
    fn decode_type2_rejects_bad_signature() {
        let mut ntlm = NtlmData::default();
        let mut bytes = vec![0u8; 32];
        bytes[0..8].copy_from_slice(b"XXXXSSP\0");
        bytes[8] = 0x02;
        let bad = BASE64.encode(&bytes);
        assert!(decode_type2_message(&bad, &mut ntlm).is_err());
    }

    #[test]
    fn decode_type2_rejects_wrong_message_type() {
        let mut ntlm = NtlmData::default();
        let mut bytes = vec![0u8; 32];
        bytes[0..8].copy_from_slice(NTLMSSP_SIGNATURE);
        bytes[8] = 0x01; // type 1, not 2
        let bad = BASE64.encode(&bytes);
        assert!(decode_type2_message(&bad, &mut ntlm).is_err());
    }

    #[test]
    fn decode_type2_rejects_out_of_bounds_target_info() {
        let mut ntlm = NtlmData::default();
        let mut bytes = vec![0u8; 48];
        bytes[0..8].copy_from_slice(NTLMSSP_SIGNATURE);
        bytes[8] = 0x02;
        // TARGET_INFO negotiated, but the buffer points past the message end.
        bytes[20..24].copy_from_slice(&NTLMFLAG_NEGOTIATE_TARGET_INFO.to_le_bytes());
        bytes[40..42].copy_from_slice(&100u16.to_le_bytes()); // len = 100
        bytes[44..48].copy_from_slice(&48u32.to_le_bytes()); // offset = 48
        let bad = BASE64.encode(&bytes);
        assert!(decode_type2_message(&bad, &mut ntlm).is_err());
    }

    // -- type-3 authenticate message (end-to-end wire parity) ---------------

    #[test]
    fn type3_ntlmv1_matches_curl() {
        // Decode the OEM/NTLMv1 type-2, then build the type-3. The client nonce
        // and timestamp are irrelevant to NTLMv1 but the seam still takes them.
        let mut ntlm = NtlmData::default();
        decode_type2_message(TYPE2_V1, &mut ntlm).unwrap();
        let msg =
            create_type3_message_with("User", "Password", &mut ntlm, CLIENT_NONCE, 0).unwrap();
        assert_eq!(
            msg,
            "TlRMTVNTUAADAAAAGAAYAEAAAAAYABgAWAAAAAAAAABwAAAABAAEAHAAAAALAAsAdAAAAAAAAAAA\
             AAAAAgAAAJje97h/iKpdr+Lfd5aIoXLe8Rx9XM3vE2fEMBHzApiirTXs5k8WMxxEvb7ZJ4QflFV\
             zZXJXT1JLU1RBVElPTg=="
                .replace(['\n', ' '], "")
        );
    }

    #[test]
    fn type3_ntlmv2_matches_reference() {
        // Decode the UNICODE/NTLM2 type-2 (with target info), then build the
        // NTLMv2 type-3 with a fixed client nonce (0xAA*8) and timestamp (0).
        let mut ntlm = NtlmData::default();
        decode_type2_message(TYPE2_V2, &mut ntlm).unwrap();
        let msg = create_type3_message_with("Domain\\User", "Password", &mut ntlm, CLIENT_NONCE, 0)
            .unwrap();
        assert_eq!(
            msg,
            "TlRMTVNTUAADAAAAGAAYAEAAAABEAEQAWAAAAAwADACcAAAACAAIAKgAAAAWABYAsAAAAAAAAAAA\
             AAAAAQCIAIbDUJesnOwQJVR2SlfMzBmqqqqqqqqqqvE8k6DvIvBdYm53VSi7P+sBAQAAAAAAAACA\
             PtXesZ0BqqqqqqqqqqoAAAAAAgAMAEQATwBNAEEASQBOAAAAAAAAAAAARABvAG0AYQBpAG4AVQBz\
             AGUAcgBXAE8AUgBLAFMAVABBAFQASQBPAE4A"
                .replace(['\n', ' '], "")
        );
    }

    #[test]
    fn type3_accepts_forward_slash_domain_separator() {
        // "Domain/User" must parse identically to "Domain\\User".
        let mut a = NtlmData::default();
        let mut b = NtlmData::default();
        decode_type2_message(TYPE2_V2, &mut a).unwrap();
        decode_type2_message(TYPE2_V2, &mut b).unwrap();
        let with_bs =
            create_type3_message_with("Domain\\User", "Password", &mut a, CLIENT_NONCE, 0).unwrap();
        let with_fs =
            create_type3_message_with("Domain/User", "Password", &mut b, CLIENT_NONCE, 0).unwrap();
        assert_eq!(with_bs, with_fs);
    }

    #[test]
    fn type3_clears_ntlm2_bit_for_ntlmv1() {
        // For the NTLMv1 branch curl clears NEGOTIATE_NTLM2_KEY before echoing
        // the flags into the message; decode a type-2 that has the bit unset and
        // confirm the emitted flags long is exactly the OEM flag.
        let mut ntlm = NtlmData::default();
        decode_type2_message(TYPE2_V1, &mut ntlm).unwrap();
        let msg =
            create_type3_message_with("User", "Password", &mut ntlm, CLIENT_NONCE, 0).unwrap();
        let raw = BASE64.decode(msg.as_bytes()).unwrap();
        // flags long at offset 60.
        assert_eq!(read_u32_le(&raw, 60), NTLMFLAG_NEGOTIATE_OEM);
    }

    #[test]
    fn type3_resets_state_afterwards() {
        let mut ntlm = NtlmData::default();
        decode_type2_message(TYPE2_V2, &mut ntlm).unwrap();
        create_type3_message_with("Domain\\User", "Password", &mut ntlm, CLIENT_NONCE, 0).unwrap();
        // curl calls Curl_auth_cleanup_ntlm at the end of type-3 creation.
        assert_eq!(ntlm.flags, 0);
        assert_eq!(ntlm.nonce, [0u8; 8]);
        assert!(ntlm.target_info.is_empty());
    }

    #[test]
    fn type3_structure_offsets_are_consistent() {
        // Verify the security-buffer offsets in a produced NTLMv2 message point
        // at the right places and are internally consistent.
        let mut ntlm = NtlmData::default();
        decode_type2_message(TYPE2_V2, &mut ntlm).unwrap();
        let msg = create_type3_message_with("Domain\\User", "Password", &mut ntlm, CLIENT_NONCE, 0)
            .unwrap();
        let raw = BASE64.decode(msg.as_bytes()).unwrap();

        assert_eq!(&raw[0..8], NTLMSSP_SIGNATURE);
        assert_eq!(&raw[8..12], &[0x03, 0x00, 0x00, 0x00]); // type = 3

        // LM response security buffer: len 0x18, offset 64.
        assert_eq!(read_u16_le(&raw, 12), 0x18);
        assert_eq!(read_u32_le(&raw, 16), 64);
        // NT response security buffer: len 68 (48 + 20 target info), offset 88.
        assert_eq!(read_u16_le(&raw, 20), 68);
        assert_eq!(read_u32_le(&raw, 24), 88);
        // Domain "Domain" in UTF-16LE = 12 bytes at offset 88 + 68 = 156.
        assert_eq!(read_u16_le(&raw, 28), 12);
        assert_eq!(read_u32_le(&raw, 32), 156);
        // User "User" in UTF-16LE = 8 bytes.
        assert_eq!(read_u16_le(&raw, 36), 8);
        assert_eq!(read_u32_le(&raw, 40), 168);
        // Host "WORKSTATION" in UTF-16LE = 22 bytes.
        assert_eq!(read_u16_le(&raw, 44), 22);
        assert_eq!(read_u32_le(&raw, 48), 176);
        // Total length = 176 + 22 = 198.
        assert_eq!(raw.len(), 198);
    }

    #[test]
    fn ntlmdata_reset_clears_everything() {
        let mut ntlm = NtlmData {
            flags: 0x1234,
            nonce: [7u8; 8],
            target_info: vec![9, 9, 9],
        };
        ntlm.reset();
        assert_eq!(ntlm.flags, 0);
        assert_eq!(ntlm.nonce, [0u8; 8]);
        assert!(ntlm.target_info.is_empty());
    }
}
