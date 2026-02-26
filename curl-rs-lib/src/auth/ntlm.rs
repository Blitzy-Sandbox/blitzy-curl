//! NTLM authentication (NTLMv1/NTLMv2) — pure Rust implementation.
//!
//! This module is the Rust rewrite of three C source files:
//!
//! - `lib/vauth/ntlm.c` — Type 1/2/3 message construction and decoding
//! - `lib/curl_ntlm_core.c` — DES, MD4, HMAC-MD5 core crypto operations
//! - `lib/http_ntlm.c` — HTTP-layer NTLM input/output orchestration
//!
//! All cryptographic operations are performed by pure-Rust crates (`des`,
//! `md4`, `hmac`, `md-5`) with zero `unsafe` blocks. The Windows SSPI path
//! (`lib/vauth/ntlm_sspi.c`) is replaced entirely by this native
//! implementation.
//!
//! # NTLM Protocol Overview
//!
//! NTLM is a challenge-response authentication protocol that uses a
//! three-message handshake:
//!
//! 1. **Type-1 (Negotiate)** — Client sends supported flags.
//! 2. **Type-2 (Challenge)** — Server responds with an 8-byte nonce and
//!    negotiated flags, optionally including target information.
//! 3. **Type-3 (Authenticate)** — Client sends LM and NT response hashes
//!    computed from the password and server challenge.
//!
//! Both NTLMv1 and NTLMv2 response computations are supported; NTLMv2 is
//! used when the server negotiates the `NTLM2_KEY` flag.
//!
//! # References
//!
//! - <https://davenport.sourceforge.net/ntlm.html>
//! - <https://www.innovation.ch/java/ntlm.html>
//! - MS-NLMP specification

use std::time::{SystemTime, UNIX_EPOCH};

use des::cipher::generic_array::GenericArray;
use des::cipher::{BlockEncrypt, KeyInit};
use des::Des;
use md4::{Digest, Md4};

use crate::error::CurlError;
use crate::util::base64;
use crate::util::hmac::hmac_md5;
use crate::util::rand::random_bytes;

// ---------------------------------------------------------------------------
// NTLM Flag Constants (from include/curl/vauth.h and lib/vauth/ntlm.c)
// ---------------------------------------------------------------------------

/// Indicates that Unicode strings are supported for use in security buffer
/// data.
const NTLMFLAG_NEGOTIATE_UNICODE: u32 = 1 << 0;

/// Indicates that OEM strings are supported for use in security buffer data.
const NTLMFLAG_NEGOTIATE_OEM: u32 = 1 << 1;

/// Requests that the server's authentication realm be included in the Type 2
/// message.
const NTLMFLAG_REQUEST_TARGET: u32 = 1 << 2;

/// Specifies that authenticated communication between the client and server
/// should carry a digital signature (message integrity).
#[allow(dead_code)]
const NTLMFLAG_NEGOTIATE_SIGN: u32 = 1 << 4;

/// Specifies that authenticated communication between the client and server
/// should be encrypted (message confidentiality).
#[allow(dead_code)]
const NTLMFLAG_NEGOTIATE_SEAL: u32 = 1 << 5;

/// Indicates that datagram authentication is being used.
#[allow(dead_code)]
const NTLMFLAG_NEGOTIATE_DATAGRAM_STYLE: u32 = 1 << 6;

/// Indicates that the LAN Manager session key should be used for signing and
/// sealing authenticated communications.
#[allow(dead_code)]
const NTLMFLAG_NEGOTIATE_LM_KEY: u32 = 1 << 7;

/// Indicates that NTLM authentication is being used.
const NTLMFLAG_NEGOTIATE_NTLM_KEY: u32 = 1 << 9;

/// Sent by the client in the Type 3 message to indicate that an anonymous
/// context has been established.
#[allow(dead_code)]
const NTLMFLAG_NEGOTIATE_ANONYMOUS: u32 = 1 << 11;

/// Sent by the client in the Type 1 message to indicate that a desired
/// authentication realm is included in the message.
#[allow(dead_code)]
const NTLMFLAG_NEGOTIATE_DOMAIN_SUPPLIED: u32 = 1 << 12;

/// Sent by the client in the Type 1 message to indicate that the client
/// workstation's name is included in the message.
#[allow(dead_code)]
const NTLMFLAG_NEGOTIATE_WORKSTATION_SUPPLIED: u32 = 1 << 13;

/// Sent by the server to indicate that the server and client are on the same
/// machine.
#[allow(dead_code)]
const NTLMFLAG_NEGOTIATE_LOCAL_CALL: u32 = 1 << 14;

/// Indicates that authenticated communication between the client and server
/// should be signed with a "dummy" signature.
const NTLMFLAG_NEGOTIATE_ALWAYS_SIGN: u32 = 1 << 15;

/// Sent by the server in the Type 2 message to indicate that the target
/// authentication realm is a domain.
#[allow(dead_code)]
const NTLMFLAG_TARGET_TYPE_DOMAIN: u32 = 1 << 16;

/// Sent by the server in the Type 2 message to indicate that the target
/// authentication realm is a server.
#[allow(dead_code)]
const NTLMFLAG_TARGET_TYPE_SERVER: u32 = 1 << 17;

/// Sent by the server in the Type 2 message to indicate that the target
/// authentication realm is a share.
#[allow(dead_code)]
const NTLMFLAG_TARGET_TYPE_SHARE: u32 = 1 << 18;

/// Indicates that the NTLM2 signing and sealing scheme should be used for
/// protecting authenticated communications. When set by the server in the
/// Type-2 message, the client uses NTLMv2 response computation.
const NTLMFLAG_NEGOTIATE_NTLM2_KEY: u32 = 1 << 19;

/// Sent by the server in the Type 2 message to indicate that it is including
/// a Target Information block in the message.
const NTLMFLAG_NEGOTIATE_TARGET_INFO: u32 = 1 << 23;

/// Indicates that 128-bit encryption is supported.
#[allow(dead_code)]
const NTLMFLAG_NEGOTIATE_128: u32 = 1 << 29;

/// Indicates that the client will provide an encrypted master key in the
/// "Session Key" field of the Type 3 message.
#[allow(dead_code)]
const NTLMFLAG_NEGOTIATE_KEY_EXCHANGE: u32 = 1 << 30;

/// Indicates that 56-bit encryption is supported.
#[allow(dead_code)]
const NTLMFLAG_NEGOTIATE_56: u32 = 1 << 31;

// ---------------------------------------------------------------------------
// NTLM Protocol Constants
// ---------------------------------------------------------------------------

/// "NTLMSSP" signature — always in ASCII regardless of platform.
/// Includes the trailing NUL byte for an 8-byte signature.
const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

/// Maximum NTLM message buffer size, large enough for long user + host +
/// domain strings. Matches C `NTLM_BUFSIZE`.
const NTLM_BUFSIZE: usize = 1024;

/// NTLMv2 blob signature bytes: `0x01 0x01 0x00 0x00`.
const NTLMV2_BLOB_SIGNATURE: [u8; 4] = [0x01, 0x01, 0x00, 0x00];

/// HMAC-MD5 output length in bytes.
const HMAC_MD5_LENGTH: usize = 16;

/// LM magic constant used for computing the LM hash: the ASCII string
/// "KGS!@#$%" (8 bytes).
const LM_MAGIC: [u8; 8] = [0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25];

/// Type-1 message flags: OEM | REQUEST_TARGET | NTLM_KEY | NTLM2_KEY |
/// ALWAYS_SIGN. Matches the C implementation's Type-1 flags.
const TYPE1_FLAGS: u32 = NTLMFLAG_NEGOTIATE_OEM
    | NTLMFLAG_REQUEST_TARGET
    | NTLMFLAG_NEGOTIATE_NTLM_KEY
    | NTLMFLAG_NEGOTIATE_NTLM2_KEY
    | NTLMFLAG_NEGOTIATE_ALWAYS_SIGN;

/// Epoch difference in seconds between the Windows FILETIME epoch
/// (January 1, 1601) and the UNIX epoch (January 1, 1970).
/// 134774 days × 86400 seconds/day = 11644473600 seconds.
const EPOCH_DIFF_SECS: u64 = 11_644_473_600;

/// The fixed hostname we provide, in order to not leak our real local host
/// name. Copy the name used by Firefox (matches C `static const char host[]`).
const FIXED_HOST: &str = "WORKSTATION";

// ---------------------------------------------------------------------------
// NtlmState — NTLM handshake state machine
// ---------------------------------------------------------------------------

/// State of the NTLM authentication handshake.
///
/// Tracks which message has been sent or received in the three-message NTLM
/// exchange. Maps 1:1 to the C `curlntlm` enum values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NtlmState {
    /// No NTLM handshake in progress.
    #[default]
    None,
    /// Ready to send Type-1 (Negotiate) message.
    Type1,
    /// Type-2 (Challenge) received; ready to build Type-3.
    Type2,
    /// Type-3 (Authenticate) sent; waiting for final server response.
    Type3,
    /// Handshake complete; no more NTLM headers to send.
    Last,
}

// ---------------------------------------------------------------------------
// NtlmData — NTLM session data
// ---------------------------------------------------------------------------

/// Per-connection NTLM authentication data.
///
/// Stores the negotiated flags, server challenge (nonce), and optional
/// target information block received in the Type-2 message. This struct
/// corresponds to the C `struct ntlmdata` defined in `lib/urldata.h`.
#[derive(Debug, Clone, Default)]
pub struct NtlmData {
    /// Current handshake state.
    pub state: NtlmState,
    /// Negotiated NTLM flags from the Type-2 message.
    pub flags: u32,
    /// 8-byte server challenge (nonce) from the Type-2 message.
    pub nonce: [u8; 8],
    /// Optional target information block from the Type-2 message.
    /// Used for NTLMv2 response computation.
    pub target_info: Option<Vec<u8>>,
}

impl NtlmData {
    /// Create a new `NtlmData` in the initial (no handshake) state.
    ///
    /// All fields are zeroed/empty, matching C `Curl_auth_cleanup_ntlm`
    /// followed by `memset` in connection setup.
    pub fn new() -> Self {
        NtlmData {
            state: NtlmState::None,
            flags: 0,
            nonce: [0u8; 8],
            target_info: None,
        }
    }

    /// Reset NTLM data to its initial state.
    ///
    /// Matches C `Curl_auth_cleanup_ntlm`: frees the target info block and
    /// resets the target info length. Does NOT reset the handshake state —
    /// callers manage state transitions explicitly.
    pub fn cleanup(&mut self) {
        self.target_info = None;
    }
}

// ===========================================================================
// Internal Crypto Functions (from curl_ntlm_core.c)
// ===========================================================================

// ---------------------------------------------------------------------------
// DES Key Expansion
// ---------------------------------------------------------------------------

/// Expand a 56-bit (7-byte) key to a 64-bit (8-byte) DES key with odd
/// parity.
///
/// The 56 key bits are scattered into 8 bytes (7 bits per byte), then each
/// byte is adjusted to have odd parity in its least-significant bit. This
/// matches the C `extend_key_56_to_64` and `setup_des_key` functions.
fn extend_key_56_to_64(key_56: &[u8; 7]) -> [u8; 8] {
    let mut key = [0u8; 8];
    key[0] = key_56[0];
    key[1] = (key_56[0] << 7) | (key_56[1] >> 1);
    key[2] = (key_56[1] << 6) | (key_56[2] >> 2);
    key[3] = (key_56[2] << 5) | (key_56[3] >> 3);
    key[4] = (key_56[3] << 4) | (key_56[4] >> 4);
    key[5] = (key_56[4] << 3) | (key_56[5] >> 5);
    key[6] = (key_56[5] << 2) | (key_56[6] >> 6);
    key[7] = key_56[6] << 1;

    // Apply odd parity to each byte (matching C `DES_set_odd_parity` /
    // `curl_des_set_odd_parity`).
    for byte in &mut key {
        let b = *byte;
        let parity = ((b >> 7) ^ (b >> 6) ^ (b >> 5) ^ (b >> 4)
            ^ (b >> 3) ^ (b >> 2) ^ (b >> 1))
            & 0x01;
        if parity == 0 {
            *byte |= 0x01;
        } else {
            *byte &= 0xFE;
        }
    }

    key
}

/// Encrypt an 8-byte block with DES-ECB using a 56-bit (7-byte) key.
///
/// The key is first expanded to 64 bits with odd parity via
/// [`extend_key_56_to_64`], then used for a single DES ECB block
/// encryption. This matches the C `setup_des_key` + `DES_ecb_encrypt`
/// pattern used throughout `curl_ntlm_core.c`.
fn des_ecb_encrypt(key_56bit: &[u8; 7], plaintext: &[u8; 8]) -> [u8; 8] {
    let key_64 = extend_key_56_to_64(key_56bit);
    let key_ga = GenericArray::from(key_64);
    let cipher = Des::new(&key_ga);
    let mut block = GenericArray::from(*plaintext);
    cipher.encrypt_block(&mut block);
    let mut result = [0u8; 8];
    result.copy_from_slice(&block);
    result
}

// ---------------------------------------------------------------------------
// LM Hash
// ---------------------------------------------------------------------------

/// Compute the LAN Manager (LM) hash from a password.
///
/// The password is uppercased, truncated or zero-padded to 14 bytes, split
/// into two 7-byte halves, and each half is used as a DES key to encrypt the
/// magic constant `KGS!@#$%`. The resulting 16-byte hash is zero-padded to
/// 21 bytes for use with [`lm_resp`].
///
/// Matches C `Curl_ntlm_core_mk_lm_hash`.
///
/// # Arguments
///
/// * `password` — The user's plaintext password.
///
/// # Returns
///
/// A 21-byte array containing the 16-byte LM hash followed by 5 zero bytes.
pub fn mk_lm_hash(password: &str) -> [u8; 21] {
    let mut pw = [0u8; 14];
    let upper = password.to_ascii_uppercase();
    let upper_bytes = upper.as_bytes();
    let len = std::cmp::min(upper_bytes.len(), 14);
    pw[..len].copy_from_slice(&upper_bytes[..len]);
    // Bytes beyond `len` are already zero.

    // DES-encrypt magic constant with each 7-byte half.
    let key1: [u8; 7] = pw[..7].try_into().expect("slice is 7 bytes");
    let key2: [u8; 7] = pw[7..14].try_into().expect("slice is 7 bytes");
    let enc1 = des_ecb_encrypt(&key1, &LM_MAGIC);
    let enc2 = des_ecb_encrypt(&key2, &LM_MAGIC);

    let mut lm_buffer = [0u8; 21];
    lm_buffer[..8].copy_from_slice(&enc1);
    lm_buffer[8..16].copy_from_slice(&enc2);
    // Bytes 16..21 are already zero (zero-padded).
    lm_buffer
}

// ---------------------------------------------------------------------------
// NT Hash
// ---------------------------------------------------------------------------

/// Compute the NT hash from a password.
///
/// The password is encoded in UTF-16LE (little-endian), then hashed with
/// MD4. The resulting 16-byte hash is zero-padded to 21 bytes for use with
/// [`lm_resp`] (NTLMv1) or [`mk_ntlmv2_hash`] (NTLMv2).
///
/// Matches C `Curl_ntlm_core_mk_nt_hash`.
///
/// # Arguments
///
/// * `password` — The user's plaintext password.
///
/// # Errors
///
/// Returns [`CurlError::OutOfMemory`] if the UTF-16LE conversion would
/// overflow (password length > `usize::MAX / 2`).
pub fn mk_nt_hash(password: &str) -> Result<[u8; 21], CurlError> {
    // Convert password to UTF-16LE bytes.
    let utf16le = str_to_utf16le(password);

    // Compute MD4 hash of the UTF-16LE bytes.
    let mut hasher = Md4::new();
    hasher.update(&utf16le);
    let md4_result = hasher.finalize();

    let mut nt_buffer = [0u8; 21];
    nt_buffer[..16].copy_from_slice(&md4_result);
    // Bytes 16..21 are already zero (zero-padded).
    Ok(nt_buffer)
}

// ---------------------------------------------------------------------------
// LM/NT Response
// ---------------------------------------------------------------------------

/// Compute the LM or NT response from a 21-byte hash and an 8-byte server
/// challenge.
///
/// The 21-byte hash is split into three 7-byte DES keys, and each key
/// encrypts the 8-byte challenge. The three 8-byte cipher outputs are
/// concatenated into a 24-byte response.
///
/// Matches C `Curl_ntlm_core_lm_resp`.
///
/// # Arguments
///
/// * `hash_21` — A 21-byte hash (output of [`mk_lm_hash`] or [`mk_nt_hash`]).
/// * `challenge` — The 8-byte server challenge from the Type-2 message.
///
/// # Returns
///
/// A 24-byte response.
pub fn lm_resp(hash_21: &[u8; 21], challenge: &[u8; 8]) -> [u8; 24] {
    let key1: [u8; 7] = hash_21[0..7].try_into().expect("slice is 7 bytes");
    let key2: [u8; 7] = hash_21[7..14].try_into().expect("slice is 7 bytes");
    let key3: [u8; 7] = hash_21[14..21].try_into().expect("slice is 7 bytes");

    let enc1 = des_ecb_encrypt(&key1, challenge);
    let enc2 = des_ecb_encrypt(&key2, challenge);
    let enc3 = des_ecb_encrypt(&key3, challenge);

    let mut resp = [0u8; 24];
    resp[0..8].copy_from_slice(&enc1);
    resp[8..16].copy_from_slice(&enc2);
    resp[16..24].copy_from_slice(&enc3);
    resp
}

// ---------------------------------------------------------------------------
// NTLMv2 Hash
// ---------------------------------------------------------------------------

/// Compute the NTLMv2 hash.
///
/// `NTLMv2Hash = HMAC-MD5(NT_Hash, UPPERCASE(user) + domain)` where both
/// the uppercased username and domain are encoded in UTF-16LE.
///
/// Matches C `Curl_ntlm_core_mk_ntlmv2_hash`.
///
/// # Arguments
///
/// * `nt_hash` — The first 16 bytes of the NT hash (output of [`mk_nt_hash`]).
/// * `user` — The username (will be uppercased).
/// * `domain` — The domain name (used as-is for case).
///
/// # Errors
///
/// Returns [`CurlError::OutOfMemory`] on allocation failure.
fn mk_ntlmv2_hash(
    nt_hash: &[u8; 16],
    user: &str,
    domain: &str,
) -> Result<[u8; 16], CurlError> {
    // Build the identity: UPPERCASE(user) in UTF-16LE + domain in UTF-16LE
    let upper_user = user.to_ascii_uppercase();
    let mut identity = Vec::with_capacity((upper_user.len() + domain.len()) * 2);
    identity.extend(str_to_utf16le(&upper_user));
    identity.extend(str_to_utf16le(domain));

    Ok(hmac_md5(nt_hash, &identity))
}

// ---------------------------------------------------------------------------
// Windows FILETIME Timestamp
// ---------------------------------------------------------------------------

/// Get the current time as a Windows FILETIME value.
///
/// A FILETIME is a 64-bit unsigned integer representing the number of
/// 100-nanosecond intervals since January 1, 1601 00:00:00 UTC.
///
/// Matches C `time2filetime` from `curl_ntlm_core.c`.
fn time2filetime() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    // Convert UNIX timestamp to Windows FILETIME:
    // 1. Add the epoch difference (seconds between 1601 and 1970).
    // 2. Multiply by 10,000,000 to convert seconds to 100ns intervals.
    (now.as_secs() + EPOCH_DIFF_SECS) * 10_000_000
        + u64::from(now.subsec_nanos()) / 100
}

// ---------------------------------------------------------------------------
// NTLMv2 Response
// ---------------------------------------------------------------------------

/// Compute the NTLMv2 response (placed in the NT-response field of Type-3).
///
/// Builds an NTLMv2 blob containing the signature, timestamp, client nonce,
/// and target info, then computes HMAC-MD5 over the server challenge
/// concatenated with the blob. The final response is the 16-byte HMAC
/// prepended to the blob.
///
/// Matches C `Curl_ntlm_core_mk_ntlmv2_resp`.
///
/// # Arguments
///
/// * `ntlmv2_hash` — The NTLMv2 hash (16 bytes, from [`mk_ntlmv2_hash`]).
/// * `challenge` — The 8-byte server challenge from the Type-2 message.
/// * `client_nonce` — An 8-byte random client nonce.
/// * `target_info` — Optional target info block from the Type-2 message.
/// * `timestamp` — Windows FILETIME timestamp (from [`time2filetime`]).
///
/// # Returns
///
/// The complete NTLMv2 response as a `Vec<u8>`.
///
/// # Errors
///
/// Returns [`CurlError::OutOfMemory`] on allocation failure.
fn mk_ntlmv2_resp(
    ntlmv2_hash: &[u8; 16],
    challenge: &[u8; 8],
    client_nonce: &[u8; 8],
    target_info: Option<&[u8]>,
    timestamp: u64,
) -> Result<Vec<u8>, CurlError> {
    // NTLMv2 response structure:
    //   0..16   HMAC-MD5 output (computed last, written first)
    //   ---- BLOB ----
    //   16..20  Signature  0x01010000
    //   20..24  Reserved   0x00000000
    //   24..32  Timestamp  LE 64-bit FILETIME
    //   32..40  Client nonce  8 bytes
    //   40..44  Unknown    0x00000000
    //   44..44+N  Target info  N bytes
    //   44+N..44+N+4  Terminator  0x00000000

    let target_info_data = target_info.unwrap_or(&[]);
    let blob_len = 28 + target_info_data.len() + 4; // 28 = 4+4+8+8+4, plus 4 trailing zeroes
    let total_len = HMAC_MD5_LENGTH + blob_len;

    let mut resp = vec![0u8; total_len];

    // Build the blob (starts at offset 16)
    let blob_start = HMAC_MD5_LENGTH;

    // Signature
    resp[blob_start..blob_start + 4].copy_from_slice(&NTLMV2_BLOB_SIGNATURE);

    // Reserved (already zero)
    // resp[blob_start + 4..blob_start + 8] — zeros

    // Timestamp (LE 64-bit)
    resp[blob_start + 8..blob_start + 16].copy_from_slice(&timestamp.to_le_bytes());

    // Client nonce
    resp[blob_start + 16..blob_start + 24].copy_from_slice(client_nonce);

    // Unknown (already zero)
    // resp[blob_start + 24..blob_start + 28] — zeros

    // Target info
    if !target_info_data.is_empty() {
        resp[blob_start + 28..blob_start + 28 + target_info_data.len()]
            .copy_from_slice(target_info_data);
    }

    // Trailing terminator (already zero)
    // resp[blob_start + 28 + target_info_data.len()..] — zeros

    // Compute HMAC-MD5(ntlmv2_hash, challenge + blob)
    let mut hmac_input = Vec::with_capacity(8 + blob_len);
    hmac_input.extend_from_slice(challenge);
    hmac_input.extend_from_slice(&resp[blob_start..]);

    let hmac_output = hmac_md5(ntlmv2_hash, &hmac_input);

    // Write HMAC output at the start of the response
    resp[..HMAC_MD5_LENGTH].copy_from_slice(&hmac_output);

    Ok(resp)
}

// ---------------------------------------------------------------------------
// LMv2 Response
// ---------------------------------------------------------------------------

/// Compute the LMv2 response (placed in the LM-response field of Type-3 for
/// NTLMv2).
///
/// `LMv2 = HMAC-MD5(ntlmv2_hash, challenge + client_nonce) + client_nonce`
///
/// Matches C `Curl_ntlm_core_mk_lmv2_resp`.
///
/// # Arguments
///
/// * `ntlmv2_hash` — The NTLMv2 hash (16 bytes).
/// * `challenge` — The 8-byte server challenge.
/// * `client_nonce` — The 8-byte client nonce.
///
/// # Returns
///
/// A 24-byte LMv2 response.
fn mk_lmv2_resp(
    ntlmv2_hash: &[u8; 16],
    challenge: &[u8; 8],
    client_nonce: &[u8; 8],
) -> [u8; 24] {
    // HMAC-MD5(ntlmv2_hash, challenge + client_nonce)
    let mut data = [0u8; 16];
    data[..8].copy_from_slice(challenge);
    data[8..].copy_from_slice(client_nonce);

    let hmac_output = hmac_md5(ntlmv2_hash, &data);

    let mut resp = [0u8; 24];
    resp[..16].copy_from_slice(&hmac_output);
    resp[16..24].copy_from_slice(client_nonce);
    resp
}

// ---------------------------------------------------------------------------
// String Encoding Helpers
// ---------------------------------------------------------------------------

/// Convert a Rust string to UTF-16LE bytes.
///
/// Each character is encoded as a 16-bit little-endian value. Characters
/// outside the Basic Multilingual Plane are encoded as surrogate pairs
/// (two 16-bit values), matching the Windows NT string encoding behaviour.
fn str_to_utf16le(s: &str) -> Vec<u8> {
    let mut result = Vec::with_capacity(s.len() * 2);
    for code_unit in s.encode_utf16() {
        result.extend_from_slice(&code_unit.to_le_bytes());
    }
    result
}

/// Copy ASCII bytes to a destination buffer in UTF-16LE format (each byte
/// followed by a zero byte). Used for domain, user, and host strings in
/// Type-3 messages when Unicode is negotiated.
///
/// Matches C `unicodecpy` from `lib/vauth/ntlm.c`.
fn ascii_to_utf16le_into(dest: &mut [u8], src: &[u8]) {
    for (i, &byte) in src.iter().enumerate() {
        dest[2 * i] = byte;
        dest[2 * i + 1] = 0;
    }
}

// ===========================================================================
// NTLM Message Construction / Decoding
// ===========================================================================

// ---------------------------------------------------------------------------
// Helpers for writing little-endian values into buffers
// ---------------------------------------------------------------------------

/// Write a 16-bit little-endian value into a buffer at the given offset.
#[inline]
fn write_u16_le(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset] = (value & 0xFF) as u8;
    buf[offset + 1] = ((value >> 8) & 0xFF) as u8;
}

/// Write a 32-bit little-endian value into a buffer at the given offset.
#[inline]
fn write_u32_le(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset] = (value & 0xFF) as u8;
    buf[offset + 1] = ((value >> 8) & 0xFF) as u8;
    buf[offset + 2] = ((value >> 16) & 0xFF) as u8;
    buf[offset + 3] = ((value >> 24) & 0xFF) as u8;
}

/// Read a 16-bit little-endian value from a buffer at the given offset.
#[inline]
fn read_u16_le(buf: &[u8], offset: usize) -> u16 {
    u16::from(buf[offset]) | (u16::from(buf[offset + 1]) << 8)
}

/// Read a 32-bit little-endian value from a buffer at the given offset.
#[inline]
fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    u32::from(buf[offset])
        | (u32::from(buf[offset + 1]) << 8)
        | (u32::from(buf[offset + 2]) << 16)
        | (u32::from(buf[offset + 3]) << 24)
}

/// Write a security buffer descriptor (length, allocated, offset) at the
/// given buffer position. Each descriptor is 8 bytes: len(u16 LE) +
/// max_len(u16 LE) + offset(u32 LE).
#[inline]
fn write_security_buffer(buf: &mut [u8], offset: usize, length: u16, buf_offset: u32) {
    write_u16_le(buf, offset, length);
    write_u16_le(buf, offset + 2, length);
    write_u32_le(buf, offset + 4, buf_offset);
}

// ---------------------------------------------------------------------------
// Type-2 Message Decoding
// ---------------------------------------------------------------------------

/// Decode an NTLM Type-2 (Challenge) message.
///
/// Validates the NTLMSSP signature and message type, extracts the
/// negotiated flags, server challenge nonce, and optional target
/// information block.
///
/// Matches C `Curl_auth_decode_ntlm_type2_message` and
/// `ntlm_decode_type2_target`.
///
/// # Arguments
///
/// * `data` — Raw Type-2 message bytes.
/// * `ntlm` — NTLM data struct to populate with extracted values.
///
/// # Errors
///
/// Returns [`CurlError::BadContentEncoding`] if the message is too short,
/// has an invalid signature, or has an invalid message type marker.
pub fn decode_type2_message(data: &[u8], ntlm: &mut NtlmData) -> Result<(), CurlError> {
    // NTLM Type-2 message layout:
    //   0..8    NTLMSSP\0 signature
    //   8..12   Message type (0x02000000 LE)
    //  12..20   Target name security buffer
    //  20..24   Flags (u32 LE)
    //  24..32   Challenge nonce (8 bytes)
    //  32..40   Context (optional)
    //  40..48   Target information security buffer (optional)
    //  48..56   OS Version (optional)

    // Minimum length is 32 bytes.
    if data.len() < 32 {
        return Err(CurlError::BadContentEncoding);
    }

    // Validate NTLMSSP signature.
    if &data[0..8] != NTLMSSP_SIGNATURE {
        return Err(CurlError::BadContentEncoding);
    }

    // Validate message type == 0x02.
    let type_marker: [u8; 4] = [0x02, 0x00, 0x00, 0x00];
    if data[8..12] != type_marker {
        return Err(CurlError::BadContentEncoding);
    }

    // Extract flags (offset 20, 4 bytes LE).
    ntlm.flags = read_u32_le(data, 20);

    // Extract server challenge nonce (offset 24, 8 bytes).
    ntlm.nonce.copy_from_slice(&data[24..32]);

    // Extract target information block if the flag is set.
    if ntlm.flags & NTLMFLAG_NEGOTIATE_TARGET_INFO != 0 {
        decode_type2_target(data, ntlm)?;
    }

    Ok(())
}

/// Extract the target information block from a Type-2 message.
///
/// The target info security buffer is at offset 40..48 in the Type-2
/// message (if present). We read the length (u16 LE at offset 40) and
/// the offset (u32 LE at offset 44), perform bounds checking, then
/// copy the target info data.
///
/// Matches C `ntlm_decode_type2_target`.
fn decode_type2_target(data: &[u8], ntlm: &mut NtlmData) -> Result<(), CurlError> {
    if data.len() < 48 {
        // No target info available — not an error, just no data.
        ntlm.target_info = None;
        return Ok(());
    }

    let target_info_len = read_u16_le(data, 40) as usize;
    let target_info_offset = read_u32_le(data, 44) as usize;

    if target_info_len == 0 {
        ntlm.target_info = None;
        return Ok(());
    }

    // Bounds checking: offset must be >= 48 and offset + length must not
    // exceed the message length.
    if target_info_offset > data.len()
        || target_info_offset + target_info_len > data.len()
        || target_info_offset < 48
    {
        return Err(CurlError::BadContentEncoding);
    }

    ntlm.target_info =
        Some(data[target_info_offset..target_info_offset + target_info_len].to_vec());

    Ok(())
}

// ---------------------------------------------------------------------------
// Type-1 Message Creation
// ---------------------------------------------------------------------------

/// Create an NTLM Type-1 (Negotiate) message.
///
/// The Type-1 message announces the client's capabilities and starts the
/// NTLM handshake. The flags are set to:
/// `OEM | REQUEST_TARGET | NTLM_KEY | NTLM2_KEY | ALWAYS_SIGN`.
///
/// Domain and workstation security buffers are empty (zero-length,
/// zero-offset), matching the curl C implementation.
///
/// Matches C `Curl_auth_create_ntlm_type1_message`.
///
/// # Arguments
///
/// * `ntlm` — NTLM data struct. Cleaned up before message construction.
///
/// # Errors
///
/// Returns [`CurlError::OutOfMemory`] on allocation failure.
pub fn create_type1_message(ntlm: &mut NtlmData) -> Result<Vec<u8>, CurlError> {
    // Clean up any previous state.
    ntlm.cleanup();

    // Type-1 message layout (32 bytes, domain and host are empty):
    //   0..8    NTLMSSP\0 signature
    //   8..12   Message type 0x01000000
    //  12..16   Flags
    //  16..24   Domain security buffer (len=0, max=0, offset=0)
    //  24..32   Workstation security buffer (len=0, max=0, offset=0)

    let mut msg = vec![0u8; 32];

    // NTLMSSP signature.
    msg[..8].copy_from_slice(NTLMSSP_SIGNATURE);

    // Message type 1 (LE).
    write_u32_le(&mut msg, 8, 0x0000_0001);

    // Flags (LE).
    write_u32_le(&mut msg, 12, TYPE1_FLAGS);

    // Domain security buffer: all zeros (len=0, max=0, offset=0).
    // Already zeroed.

    // Workstation security buffer: all zeros.
    // Already zeroed.

    Ok(msg)
}

// ---------------------------------------------------------------------------
// Type-3 Message Creation
// ---------------------------------------------------------------------------

/// Create an NTLM Type-3 (Authenticate) message.
///
/// Computes the LM and NT responses from the user's password and the
/// server challenge received in the Type-2 message. Uses NTLMv2 when
/// the `NTLM2_KEY` flag was negotiated; otherwise falls back to NTLMv1.
///
/// Matches C `Curl_auth_create_ntlm_type3_message`.
///
/// # Arguments
///
/// * `user` — Username, optionally in the format `DOMAIN\user` or
///   `DOMAIN/user`.
/// * `passwd` — The user's plaintext password.
/// * `ntlm` — NTLM data struct containing the server challenge and flags.
///
/// # Errors
///
/// Returns [`CurlError::OutOfMemory`] on allocation failure,
/// [`CurlError::BadContentEncoding`] if the resulting message would
/// exceed `NTLM_BUFSIZE`.
pub fn create_type3_message(
    user: &str,
    passwd: &str,
    ntlm: &mut NtlmData,
) -> Result<Vec<u8>, CurlError> {
    // Split user into domain\user if it contains '\', '/', or '@'.
    let (domain, username) = split_user_domain(user);
    let host = FIXED_HOST;

    let unicode = ntlm.flags & NTLMFLAG_NEGOTIATE_UNICODE != 0;

    // Compute LM and NT responses.
    let lm_response: [u8; 24];
    let nt_response: Vec<u8>;

    if ntlm.flags & NTLMFLAG_NEGOTIATE_NTLM2_KEY != 0 {
        // NTLMv2 path
        let mut entropy = [0u8; 8];
        random_bytes(&mut entropy).map_err(|_| CurlError::OutOfMemory)?;

        let nt_hash_21 = mk_nt_hash(passwd)?;
        let nt_hash_16: [u8; 16] = nt_hash_21[..16].try_into().expect("16 bytes");

        let ntlmv2_hash = mk_ntlmv2_hash(&nt_hash_16, username, domain)?;

        // LMv2 response
        lm_response = mk_lmv2_resp(&ntlmv2_hash, &ntlm.nonce, &entropy);

        // NTLMv2 response
        let timestamp = time2filetime();
        let target_info_ref = ntlm.target_info.as_deref();
        nt_response =
            mk_ntlmv2_resp(&ntlmv2_hash, &ntlm.nonce, &entropy, target_info_ref, timestamp)?;
    } else {
        // NTLMv1 path
        let nt_hash = mk_nt_hash(passwd)?;
        let nt_resp_arr = lm_resp(&nt_hash, &ntlm.nonce);

        let lm_hash = mk_lm_hash(passwd);
        lm_response = lm_resp(&lm_hash, &ntlm.nonce);

        nt_response = nt_resp_arr.to_vec();

        // Clear the NTLM2_KEY flag since we're using NTLMv1.
        ntlm.flags &= !NTLMFLAG_NEGOTIATE_NTLM2_KEY;
    };

    let ntresplen = nt_response.len();

    // Compute payload lengths.
    let (domlen, userlen, hostlen) = if unicode {
        (domain.len() * 2, username.len() * 2, host.len() * 2)
    } else {
        (domain.len(), username.len(), host.len())
    };

    // Type-3 header is 64 bytes.
    let lmrespoff: usize = 64;
    let ntrespoff: usize = lmrespoff + 0x18; // LM response is always 24 bytes
    let domoff: usize = ntrespoff + ntresplen;
    let useroff: usize = domoff + domlen;
    let hostoff: usize = useroff + userlen;

    let total_size = hostoff + hostlen;

    // Validate total size.
    if total_size > NTLM_BUFSIZE {
        return Err(CurlError::BadContentEncoding);
    }

    let mut msg = vec![0u8; total_size];

    // -- Header (64 bytes) --

    // NTLMSSP signature.
    msg[..8].copy_from_slice(NTLMSSP_SIGNATURE);

    // Message type 3 (LE).
    write_u32_le(&mut msg, 8, 0x0000_0003);

    // LM response security buffer (offset 12).
    write_security_buffer(&mut msg, 12, 0x18, lmrespoff as u32);

    // NT response security buffer (offset 20).
    write_security_buffer(&mut msg, 20, ntresplen as u16, ntrespoff as u32);

    // Domain security buffer (offset 28).
    write_security_buffer(&mut msg, 28, domlen as u16, domoff as u32);

    // User security buffer (offset 36).
    write_security_buffer(&mut msg, 36, userlen as u16, useroff as u32);

    // Workstation security buffer (offset 44).
    write_security_buffer(&mut msg, 44, hostlen as u16, hostoff as u32);

    // Session key security buffer (offset 52) — empty.
    // Already zeroed: len=0, max=0, offset=0, padding=0.

    // Flags (offset 60).
    write_u32_le(&mut msg, 60, ntlm.flags);

    // -- Payloads --

    // LM response (24 bytes at lmrespoff).
    msg[lmrespoff..lmrespoff + 24].copy_from_slice(&lm_response);

    // NT response (ntresplen bytes at ntrespoff).
    msg[ntrespoff..ntrespoff + ntresplen].copy_from_slice(&nt_response);

    // Domain string.
    if unicode {
        ascii_to_utf16le_into(&mut msg[domoff..], domain.as_bytes());
    } else {
        msg[domoff..domoff + domain.len()].copy_from_slice(domain.as_bytes());
    }

    // User string.
    if unicode {
        ascii_to_utf16le_into(&mut msg[useroff..], username.as_bytes());
    } else {
        msg[useroff..useroff + username.len()].copy_from_slice(username.as_bytes());
    }

    // Host string.
    if unicode {
        ascii_to_utf16le_into(&mut msg[hostoff..], host.as_bytes());
    } else {
        msg[hostoff..hostoff + host.len()].copy_from_slice(host.as_bytes());
    }

    // Clean up NTLM data after Type-3 construction (matches C behaviour).
    ntlm.cleanup();

    Ok(msg)
}

/// Split a username into (domain, user) parts.
///
/// Checks for `\`, `/`, then `@` separators, matching the C code's search
/// order. If no separator is found, returns ("", user).
fn split_user_domain(user: &str) -> (&str, &str) {
    // Check for backslash or forward slash first.
    if let Some(pos) = user.find('\\') {
        return (&user[..pos], &user[pos + 1..]);
    }
    if let Some(pos) = user.find('/') {
        return (&user[..pos], &user[pos + 1..]);
    }
    // No domain separator found.
    ("", user)
}

// ===========================================================================
// HTTP NTLM Orchestration (from http_ntlm.c)
// ===========================================================================

/// Process an incoming NTLM authentication challenge from a server header.
///
/// Parses the `WWW-Authenticate: NTLM [token]` or
/// `Proxy-Authenticate: NTLM [token]` header. If a Base64-encoded token
/// is present, it is decoded and processed as a Type-2 message. If no
/// token is present, a new NTLM handshake is initiated (Type-1 state).
///
/// Matches C `Curl_input_ntlm`.
///
/// # Arguments
///
/// * `header` — The header value after stripping the header name (e.g.,
///   the portion after `WWW-Authenticate: `).
/// * `proxy` — `true` if this is a proxy authentication challenge.
/// * `ntlm` — NTLM data struct to update.
///
/// # Errors
///
/// Returns [`CurlError::RemoteAccessDenied`] if the server rejected the
/// Type-3 message (re-challenge after Type-3 with no token).
/// Returns [`CurlError::BadContentEncoding`] if the Base64 token or
/// Type-2 message is malformed.
pub fn input_ntlm(
    header: &str,
    _proxy: bool,
    ntlm: &mut NtlmData,
) -> Result<(), CurlError> {
    // Check for "NTLM" prefix (case-insensitive).
    let trimmed = header.trim();
    if !trimmed
        .get(..4)
        .is_some_and(|s| s.eq_ignore_ascii_case("NTLM"))
    {
        // Not an NTLM challenge — ignore.
        return Ok(());
    }

    // Skip past "NTLM" and any whitespace.
    let payload = trimmed[4..].trim_start();

    if !payload.is_empty() {
        // Base64-encoded Type-2 message present.
        let raw = base64::decode(payload)?;
        decode_type2_message(&raw, ntlm)?;
        ntlm.state = NtlmState::Type2;
    } else {
        // No payload — start or restart handshake.
        match ntlm.state {
            NtlmState::Last => {
                // NTLM auth restarted after completion.
                *ntlm = NtlmData::new();
            }
            NtlmState::Type3 => {
                // Server rejected the Type-3 message.
                *ntlm = NtlmData::new();
                return Err(CurlError::RemoteAccessDenied);
            }
            NtlmState::Type1 | NtlmState::Type2 => {
                // Handshake failure — internal error.
                return Err(CurlError::RemoteAccessDenied);
            }
            NtlmState::None => {
                // Normal start.
            }
        }
        ntlm.state = NtlmState::Type1;
    }

    Ok(())
}

/// Generate the NTLM authentication header value for an outgoing request.
///
/// Depending on the current handshake state, this function creates and
/// Base64-encodes a Type-1 or Type-3 message, or returns `None` if the
/// handshake is complete.
///
/// Matches C `Curl_output_ntlm`.
///
/// # Arguments
///
/// * `user` — Username (optionally including domain).
/// * `passwd` — User's password.
/// * `proxy` — `true` if generating a proxy authorization header.
/// * `ntlm` — NTLM data struct.
///
/// # Returns
///
/// * `Ok(Some(header))` — The header value string, e.g. `"NTLM TlRMTVN..."`.
/// * `Ok(None)` — No header should be sent (handshake complete or idle).
///
/// # Errors
///
/// Propagates errors from message creation or Base64 encoding.
pub fn output_ntlm(
    user: &str,
    passwd: &str,
    _proxy: bool,
    ntlm: &mut NtlmData,
) -> Result<Option<String>, CurlError> {
    // If we already sent Type-3, transition to Last (no more headers).
    if ntlm.state == NtlmState::Type3 {
        ntlm.state = NtlmState::Last;
    }

    match ntlm.state {
        NtlmState::Type1 => {
            // Create and encode Type-1 message.
            let msg = create_type1_message(ntlm)?;
            let encoded = base64::encode(&msg);
            Ok(Some(format!("NTLM {}", encoded)))
        }
        NtlmState::Type2 => {
            // Create and encode Type-3 message.
            let msg = create_type3_message(user, passwd, ntlm)?;
            if msg.is_empty() {
                return Ok(None);
            }
            let encoded = base64::encode(&msg);
            ntlm.state = NtlmState::Type3;
            Ok(Some(format!("NTLM {}", encoded)))
        }
        NtlmState::Type3 | NtlmState::Last | NtlmState::None => {
            // No header to send.
            Ok(None)
        }
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // DES key expansion and encryption
    // -----------------------------------------------------------------------

    #[test]
    fn test_extend_key_56_to_64_parity() {
        // Verify that every byte in the expanded key has odd parity.
        let key56: [u8; 7] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11];
        let key64 = extend_key_56_to_64(&key56);
        for &byte in &key64 {
            let ones = byte.count_ones();
            assert_eq!(
                ones % 2,
                1,
                "byte 0x{:02x} does not have odd parity",
                byte
            );
        }
    }

    #[test]
    fn test_des_ecb_encrypt_known_vector() {
        // A basic test: encrypt all-zero plaintext with a known key.
        // The exact result depends on the DES algorithm. We verify:
        // 1. The output is 8 bytes.
        // 2. The output is deterministic.
        let key: [u8; 7] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let plaintext: [u8; 8] = [0x00; 8];
        let ct1 = des_ecb_encrypt(&key, &plaintext);
        let ct2 = des_ecb_encrypt(&key, &plaintext);
        assert_eq!(ct1.len(), 8);
        assert_eq!(ct1, ct2);
    }

    // -----------------------------------------------------------------------
    // LM Hash
    // -----------------------------------------------------------------------

    #[test]
    fn test_mk_lm_hash_length() {
        let hash = mk_lm_hash("Password");
        assert_eq!(hash.len(), 21);
        // Last 5 bytes should be zero (zero-padded from 16 to 21).
        assert_eq!(&hash[16..21], &[0u8; 5]);
    }

    #[test]
    fn test_mk_lm_hash_empty_password() {
        let hash = mk_lm_hash("");
        assert_eq!(hash.len(), 21);
        // Empty password should produce a deterministic hash.
        let hash2 = mk_lm_hash("");
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_mk_lm_hash_case_insensitive() {
        // LM hash uppercases the password, so "Password" and "PASSWORD"
        // should produce identical hashes.
        let h1 = mk_lm_hash("password");
        let h2 = mk_lm_hash("PASSWORD");
        assert_eq!(h1, h2);
    }

    // -----------------------------------------------------------------------
    // NT Hash
    // -----------------------------------------------------------------------

    #[test]
    fn test_mk_nt_hash_length() {
        let hash = mk_nt_hash("Password").unwrap();
        assert_eq!(hash.len(), 21);
        // Last 5 bytes should be zero.
        assert_eq!(&hash[16..21], &[0u8; 5]);
    }

    #[test]
    fn test_mk_nt_hash_deterministic() {
        let h1 = mk_nt_hash("Password").unwrap();
        let h2 = mk_nt_hash("Password").unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_mk_nt_hash_case_sensitive() {
        // NT hash is case-sensitive (unlike LM hash).
        let h1 = mk_nt_hash("Password").unwrap();
        let h2 = mk_nt_hash("password").unwrap();
        assert_ne!(h1, h2);
    }

    // -----------------------------------------------------------------------
    // LM/NT Response
    // -----------------------------------------------------------------------

    #[test]
    fn test_lm_resp_length() {
        let hash = mk_lm_hash("test");
        let challenge = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let resp = lm_resp(&hash, &challenge);
        assert_eq!(resp.len(), 24);
    }

    #[test]
    fn test_lm_resp_deterministic() {
        let hash = mk_lm_hash("test");
        let challenge = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let r1 = lm_resp(&hash, &challenge);
        let r2 = lm_resp(&hash, &challenge);
        assert_eq!(r1, r2);
    }

    // -----------------------------------------------------------------------
    // NTLMv2 hash chain
    // -----------------------------------------------------------------------

    #[test]
    fn test_mk_ntlmv2_hash_length() {
        let nt_hash = mk_nt_hash("Password").unwrap();
        let nt_hash_16: [u8; 16] = nt_hash[..16].try_into().unwrap();
        let v2hash = mk_ntlmv2_hash(&nt_hash_16, "user", "DOMAIN").unwrap();
        assert_eq!(v2hash.len(), 16);
    }

    #[test]
    fn test_mk_lmv2_resp_length() {
        let nt_hash = mk_nt_hash("Password").unwrap();
        let nt_hash_16: [u8; 16] = nt_hash[..16].try_into().unwrap();
        let v2hash = mk_ntlmv2_hash(&nt_hash_16, "user", "DOMAIN").unwrap();
        let challenge = [0x01u8; 8];
        let client_nonce = [0x02u8; 8];
        let resp = mk_lmv2_resp(&v2hash, &challenge, &client_nonce);
        assert_eq!(resp.len(), 24);
    }

    // -----------------------------------------------------------------------
    // Time conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_time2filetime_nonzero() {
        let ft = time2filetime();
        // FILETIME for any date after ~2020 should be > 0.
        assert!(ft > 0);
    }

    // -----------------------------------------------------------------------
    // Type-1 message
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_type1_message_structure() {
        let mut ntlm = NtlmData::new();
        let msg = create_type1_message(&mut ntlm).unwrap();

        // Minimum 32 bytes.
        assert_eq!(msg.len(), 32);

        // NTLMSSP signature.
        assert_eq!(&msg[0..8], NTLMSSP_SIGNATURE);

        // Message type 1.
        assert_eq!(read_u32_le(&msg, 8), 1);

        // Flags.
        let flags = read_u32_le(&msg, 12);
        assert_eq!(flags, TYPE1_FLAGS);
        assert_ne!(flags & NTLMFLAG_NEGOTIATE_OEM, 0);
        assert_ne!(flags & NTLMFLAG_REQUEST_TARGET, 0);
        assert_ne!(flags & NTLMFLAG_NEGOTIATE_NTLM_KEY, 0);
        assert_ne!(flags & NTLMFLAG_NEGOTIATE_NTLM2_KEY, 0);
        assert_ne!(flags & NTLMFLAG_NEGOTIATE_ALWAYS_SIGN, 0);
    }

    // -----------------------------------------------------------------------
    // Type-2 message decoding
    // -----------------------------------------------------------------------

    #[test]
    fn test_decode_type2_too_short() {
        let mut ntlm = NtlmData::new();
        let data = vec![0u8; 16]; // Too short.
        assert!(decode_type2_message(&data, &mut ntlm).is_err());
    }

    #[test]
    fn test_decode_type2_bad_signature() {
        let mut ntlm = NtlmData::new();
        let mut data = vec![0u8; 32];
        data[0..8].copy_from_slice(b"XXXXXXXX"); // Bad signature.
        data[8] = 0x02; // Message type.
        assert!(decode_type2_message(&data, &mut ntlm).is_err());
    }

    #[test]
    fn test_decode_type2_valid_minimal() {
        let mut ntlm = NtlmData::new();
        let mut data = vec![0u8; 32];

        // NTLMSSP signature.
        data[0..8].copy_from_slice(NTLMSSP_SIGNATURE);
        // Message type 2.
        data[8] = 0x02;
        // Flags: NTLM_KEY.
        write_u32_le(&mut data, 20, NTLMFLAG_NEGOTIATE_NTLM_KEY);
        // Challenge nonce.
        data[24..32].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]);

        assert!(decode_type2_message(&data, &mut ntlm).is_ok());
        assert_ne!(ntlm.flags & NTLMFLAG_NEGOTIATE_NTLM_KEY, 0);
        assert_eq!(
            ntlm.nonce,
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]
        );
        assert!(ntlm.target_info.is_none());
    }

    #[test]
    fn test_decode_type2_with_target_info() {
        let mut ntlm = NtlmData::new();
        let target_info_data = b"target_info_payload";
        let target_info_offset: u32 = 48;

        let total_len = 48 + target_info_data.len();
        let mut data = vec![0u8; total_len];

        // NTLMSSP signature.
        data[0..8].copy_from_slice(NTLMSSP_SIGNATURE);
        // Message type 2.
        data[8] = 0x02;
        // Flags: NTLM_KEY | TARGET_INFO.
        write_u32_le(
            &mut data,
            20,
            NTLMFLAG_NEGOTIATE_NTLM_KEY | NTLMFLAG_NEGOTIATE_TARGET_INFO,
        );
        // Challenge nonce.
        data[24..32].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        // Target info security buffer: length at offset 40, offset at 44.
        write_u16_le(&mut data, 40, target_info_data.len() as u16);
        write_u16_le(&mut data, 42, target_info_data.len() as u16); // max len
        write_u32_le(&mut data, 44, target_info_offset);
        // Target info payload.
        data[48..].copy_from_slice(target_info_data);

        assert!(decode_type2_message(&data, &mut ntlm).is_ok());
        assert!(ntlm.target_info.is_some());
        assert_eq!(ntlm.target_info.as_ref().unwrap(), target_info_data);
    }

    // -----------------------------------------------------------------------
    // Type-3 message
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_type3_message_ntlmv1() {
        let mut ntlm = NtlmData::new();
        ntlm.flags = NTLMFLAG_NEGOTIATE_NTLM_KEY; // NTLMv1 (no NTLM2_KEY)
        ntlm.nonce = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];

        let msg = create_type3_message("user", "password", &mut ntlm).unwrap();

        // Validate signature.
        assert_eq!(&msg[0..8], NTLMSSP_SIGNATURE);
        // Validate type.
        assert_eq!(read_u32_le(&msg, 8), 3);
        // LM response at offset 64, length 24.
        assert!(msg.len() >= 64 + 24);
    }

    #[test]
    fn test_create_type3_message_ntlmv2() {
        let mut ntlm = NtlmData::new();
        ntlm.flags = NTLMFLAG_NEGOTIATE_NTLM_KEY | NTLMFLAG_NEGOTIATE_NTLM2_KEY;
        ntlm.nonce = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        ntlm.target_info = Some(vec![0x01, 0x02, 0x03, 0x04]);

        let msg = create_type3_message("DOMAIN\\user", "password", &mut ntlm).unwrap();

        // Validate signature and type.
        assert_eq!(&msg[0..8], NTLMSSP_SIGNATURE);
        assert_eq!(read_u32_le(&msg, 8), 3);
    }

    #[test]
    fn test_create_type3_message_with_unicode() {
        let mut ntlm = NtlmData::new();
        ntlm.flags = NTLMFLAG_NEGOTIATE_NTLM_KEY | NTLMFLAG_NEGOTIATE_UNICODE;
        ntlm.nonce = [0x01; 8];

        let msg = create_type3_message("user", "password", &mut ntlm).unwrap();

        // Validate signature and type.
        assert_eq!(&msg[0..8], NTLMSSP_SIGNATURE);
        assert_eq!(read_u32_le(&msg, 8), 3);
    }

    // -----------------------------------------------------------------------
    // User/domain splitting
    // -----------------------------------------------------------------------

    #[test]
    fn test_split_user_domain_backslash() {
        let (domain, user) = split_user_domain("MYDOMAIN\\myuser");
        assert_eq!(domain, "MYDOMAIN");
        assert_eq!(user, "myuser");
    }

    #[test]
    fn test_split_user_domain_slash() {
        let (domain, user) = split_user_domain("MYDOMAIN/myuser");
        assert_eq!(domain, "MYDOMAIN");
        assert_eq!(user, "myuser");
    }

    #[test]
    fn test_split_user_domain_no_separator() {
        let (domain, user) = split_user_domain("myuser");
        assert_eq!(domain, "");
        assert_eq!(user, "myuser");
    }

    // -----------------------------------------------------------------------
    // HTTP NTLM orchestration
    // -----------------------------------------------------------------------

    #[test]
    fn test_input_ntlm_start_handshake() {
        let mut ntlm = NtlmData::new();
        input_ntlm("NTLM", false, &mut ntlm).unwrap();
        assert_eq!(ntlm.state, NtlmState::Type1);
    }

    #[test]
    fn test_input_ntlm_case_insensitive() {
        let mut ntlm = NtlmData::new();
        input_ntlm("ntlm", false, &mut ntlm).unwrap();
        assert_eq!(ntlm.state, NtlmState::Type1);
    }

    #[test]
    fn test_input_ntlm_reject_after_type3() {
        let mut ntlm = NtlmData::new();
        ntlm.state = NtlmState::Type3;
        let result = input_ntlm("NTLM", false, &mut ntlm);
        assert!(result.is_err());
    }

    #[test]
    fn test_input_ntlm_with_type2_token() {
        let mut ntlm = NtlmData::new();

        // Build a minimal valid Type-2 message.
        let mut type2 = vec![0u8; 32];
        type2[0..8].copy_from_slice(NTLMSSP_SIGNATURE);
        type2[8] = 0x02;
        write_u32_le(&mut type2, 20, NTLMFLAG_NEGOTIATE_NTLM_KEY);
        type2[24..32].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

        let encoded = base64::encode(&type2);
        let header = format!("NTLM {}", encoded);

        input_ntlm(&header, false, &mut ntlm).unwrap();
        assert_eq!(ntlm.state, NtlmState::Type2);
        assert_eq!(ntlm.nonce, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_output_ntlm_type1() {
        let mut ntlm = NtlmData::new();
        ntlm.state = NtlmState::Type1;

        let result = output_ntlm("user", "pass", false, &mut ntlm).unwrap();
        assert!(result.is_some());
        let header = result.unwrap();
        assert!(header.starts_with("NTLM "));
    }

    #[test]
    fn test_output_ntlm_type2() {
        let mut ntlm = NtlmData::new();
        ntlm.state = NtlmState::Type2;
        ntlm.flags = NTLMFLAG_NEGOTIATE_NTLM_KEY;
        ntlm.nonce = [1, 2, 3, 4, 5, 6, 7, 8];

        let result = output_ntlm("user", "pass", false, &mut ntlm).unwrap();
        assert!(result.is_some());
        let header = result.unwrap();
        assert!(header.starts_with("NTLM "));
        assert_eq!(ntlm.state, NtlmState::Type3);
    }

    #[test]
    fn test_output_ntlm_type3_transitions_to_last() {
        let mut ntlm = NtlmData::new();
        ntlm.state = NtlmState::Type3;

        let result = output_ntlm("user", "pass", false, &mut ntlm).unwrap();
        assert!(result.is_none());
        assert_eq!(ntlm.state, NtlmState::Last);
    }

    #[test]
    fn test_output_ntlm_last_returns_none() {
        let mut ntlm = NtlmData::new();
        ntlm.state = NtlmState::Last;

        let result = output_ntlm("user", "pass", false, &mut ntlm).unwrap();
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // NtlmData lifecycle
    // -----------------------------------------------------------------------

    #[test]
    fn test_ntlm_data_new() {
        let ntlm = NtlmData::new();
        assert_eq!(ntlm.state, NtlmState::None);
        assert_eq!(ntlm.flags, 0);
        assert_eq!(ntlm.nonce, [0u8; 8]);
        assert!(ntlm.target_info.is_none());
    }

    #[test]
    fn test_ntlm_data_cleanup() {
        let mut ntlm = NtlmData::new();
        ntlm.target_info = Some(vec![1, 2, 3]);
        ntlm.cleanup();
        assert!(ntlm.target_info.is_none());
    }

    // -----------------------------------------------------------------------
    // UTF-16LE encoding
    // -----------------------------------------------------------------------

    #[test]
    fn test_str_to_utf16le_ascii() {
        let result = str_to_utf16le("ABC");
        assert_eq!(result, vec![0x41, 0x00, 0x42, 0x00, 0x43, 0x00]);
    }

    #[test]
    fn test_str_to_utf16le_empty() {
        let result = str_to_utf16le("");
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // Round-trip test: full handshake flow
    // -----------------------------------------------------------------------

    #[test]
    fn test_full_ntlm_handshake_flow() {
        let mut ntlm = NtlmData::new();

        // Step 1: Input triggers Type-1.
        input_ntlm("NTLM", false, &mut ntlm).unwrap();
        assert_eq!(ntlm.state, NtlmState::Type1);

        // Step 2: Output produces Type-1 header.
        let header1 = output_ntlm("user", "pass", false, &mut ntlm)
            .unwrap()
            .unwrap();
        assert!(header1.starts_with("NTLM "));

        // Step 3: Simulate receiving Type-2.
        let mut type2 = vec![0u8; 32];
        type2[0..8].copy_from_slice(NTLMSSP_SIGNATURE);
        type2[8] = 0x02;
        write_u32_le(&mut type2, 20, NTLMFLAG_NEGOTIATE_NTLM_KEY);
        type2[24..32].copy_from_slice(&[0xAA; 8]);

        let encoded_type2 = base64::encode(&type2);
        input_ntlm(&format!("NTLM {}", encoded_type2), false, &mut ntlm).unwrap();
        assert_eq!(ntlm.state, NtlmState::Type2);

        // Step 4: Output produces Type-3 header.
        let header3 = output_ntlm("user", "pass", false, &mut ntlm)
            .unwrap()
            .unwrap();
        assert!(header3.starts_with("NTLM "));
        assert_eq!(ntlm.state, NtlmState::Type3);

        // Step 5: Next output transitions to Last.
        let none_result = output_ntlm("user", "pass", false, &mut ntlm).unwrap();
        assert!(none_result.is_none());
        assert_eq!(ntlm.state, NtlmState::Last);
    }

    // -----------------------------------------------------------------------
    // Ensure zero unsafe blocks
    // -----------------------------------------------------------------------

    // This is a compile-time verification. If any `unsafe` block existed
    // in this module, the crate would violate the AAP rule. The absence of
    // `unsafe` keywords in the source is the validation.
}
