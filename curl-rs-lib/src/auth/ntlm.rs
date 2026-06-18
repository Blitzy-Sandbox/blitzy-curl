//! NTLM authentication: type-1/2/3 message construction and the NTLMv1/v2
//! response cryptography.
//!
//! This module is the memory-safe Rust replacement for libcurl's NTLM stack,
//! which is spread across three C translation units that this module fuses into
//! one cohesive, feature-gated unit:
//!
//! * `lib/vauth/ntlm.c` — the message layer: decode the server's type-2
//!   challenge, and build the client's type-1 (negotiate) and type-3
//!   (authenticate) messages.
//! * `lib/curl_ntlm_core.c` — the crypto core: single-block DES-ECB, the
//!   LAN Manager (LM) and NT password hashes, and the NTLMv2 / LMv2 HMAC-MD5
//!   responses.
//! * `lib/http_ntlm.c` — the HTTP glue: the per-connection NTLM state machine
//!   driven by `Curl_input_ntlm` (consume a `WWW-Authenticate: NTLM …` header)
//!   and `Curl_output_ntlm` (emit the next `Authorization: NTLM …` header).
//!
//! The C sources are treated as a **behavioral oracle**: the goal is
//! byte-for-byte identical wire output (so the curl 8.x regression suite passes
//! unmodified), not a line-by-line transliteration of the C.
//!
//! # Feature gating (`ntlm`, default ON)
//!
//! The whole module is compiled only when the `ntlm` Cargo feature is enabled
//! (the inner `#![cfg(feature = "ntlm")]` below). NTLM is ON in curl's default
//! build — `curl --version` reports the `NTLM` capability / `CURL_VERSION_NTLM`
//! bit (`1 << 4`) whenever DES-capable crypto is present, and Rust always has
//! the pure-Rust [`des`] crate — so the default feature set keeps this module
//! present, in lockstep with [`crate::version`]'s `("NTLM", true)` report. When
//! the feature is off, the module compiles to nothing and the
//! `CURL_VERSION_NTLM` capability must likewise be withheld.
//!
//! # Memory safety
//!
//! This module contains **zero `unsafe`** and compiles cleanly under the
//! crate-root `#![forbid(unsafe_code)]`. All buffers are owned Rust arrays /
//! [`Vec`]s; there is no manual allocation, no raw pointers, and no explicit
//! `free`. The single most safety-critical point — bounds-checking the
//! attacker-controlled Target Info offset/length in the type-2 message — is
//! reproduced exactly (see [`decode_type2_message`]); an out-of-bounds offset
//! is rejected with [`CurlError::BadContentEncoding`] rather than indexing past
//! the buffer.
//!
//! # Little-endian packing
//!
//! NTLM is a little-endian wire protocol. curl uses `Curl_read16_le` /
//! `Curl_read32_le` to read and the `SHORTPAIR` / `LONGQUARTET` macros to write
//! multi-byte fields; here those are replaced by the explicit [`read16_le`] /
//! [`read32_le`] helpers and [`u16::to_le_bytes`] / [`u32::to_le_bytes`].
//!
//! # Public surface (parity names in parentheses)
//!
//! | C entry point                              | Rust equivalent              |
//! |--------------------------------------------|------------------------------|
//! | `Curl_auth_is_ntlm_supported`              | [`is_ntlm_supported`]        |
//! | `Curl_auth_decode_ntlm_type2_message`      | [`decode_type2_message`]     |
//! | `Curl_auth_create_ntlm_type1_message`      | [`create_type1_message`]     |
//! | `Curl_auth_create_ntlm_type3_message`      | [`create_type3_message`]     |
//! | `Curl_auth_cleanup_ntlm`                   | [`cleanup`]                  |
//! | `curlntlm` (state enum)                    | [`NtlmState`]                |
//! | `struct ntlmdata`                          | [`NtlmData`]                 |
//! | `Curl_input_ntlm` / `Curl_output_ntlm`     | [`NtlmHandshake::input`] /   |
//! |                                            | [`NtlmHandshake::output`]    |
//!
//! The crypto primitives (`extend_key_56_to_64`, `mk_nt_hash`, …) are private to
//! the module and exercised through the unit tests at the bottom of the file
//! against published NTLM / MS-NLMP known-answer vectors.

#![cfg(feature = "ntlm")]

use crate::error::{CurlError, Result};
use crate::util::base64::{base64_decode, base64_encode};
use crate::util::hmac::hmac_md5;
use crate::util::md5::md4it;
use crate::util::rand::rand_bytes;

use des::cipher::generic_array::GenericArray;
use des::cipher::{BlockEncrypt, KeyInit};
use des::Des;

// ===========================================================================
// Phase A — constants, flags, and per-connection state
// ===========================================================================

/// The NTLMSSP signature that prefixes every NTLM message: the ASCII string
/// `"NTLMSSP"` followed by a NUL terminator (`4e 54 4c 4d 53 53 50 00`).
///
/// curl spells this as `NTLMSSP_SIGNATURE "\x4e\x54\x4c\x4d\x53\x53\x50"` (seven
/// bytes) and writes the trailing NUL separately via a `"%c"` with argument `0`;
/// here the full eight-byte token — including the NUL — is one constant.
const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

/// Fixed working-buffer size for the type-3 message, matching curl's
/// `NTLM_BUFSIZE`. It is large enough for a long user + host + domain plus the
/// NTLMv2 response blob; anything that would exceed it yields
/// [`CurlError::TooLarge`].
const NTLM_BUFSIZE: usize = 1024;

/// The fixed workstation name curl reports, copied from Firefox so that the
/// real local hostname is not leaked. Used verbatim in the type-3 message.
const WORKSTATION: &[u8] = b"WORKSTATION";

// ---- NTLM negotiate flags (only the actively used subset) -----------------
// Values per https://davenport.sourceforge.net/ntlm.html, matching the
// `NTLMFLAG_*` macros in lib/vauth/ntlm.c.

/// Unicode (UTF-16LE) strings are supported in security-buffer data.
const NTLMFLAG_NEGOTIATE_UNICODE: u32 = 1 << 0;
/// OEM (single-byte) strings are supported in security-buffer data.
const NTLMFLAG_NEGOTIATE_OEM: u32 = 1 << 1;
/// Requests that the server's authentication realm be included in the type-2.
const NTLMFLAG_REQUEST_TARGET: u32 = 1 << 2;
/// Indicates that NTLM authentication is being used.
const NTLMFLAG_NEGOTIATE_NTLM_KEY: u32 = 1 << 9;
/// Authenticated communication should be signed with a "dummy" signature.
const NTLMFLAG_NEGOTIATE_ALWAYS_SIGN: u32 = 1 << 15;
/// The NTLM2 (extended security) signing/sealing scheme should be used. When
/// the server sets this in its type-2, the client answers with NTLMv2.
const NTLMFLAG_NEGOTIATE_NTLM2_KEY: u32 = 1 << 19;
/// The server is including a Target Information block in the type-2 message.
const NTLMFLAG_NEGOTIATE_TARGET_INFO: u32 = 1 << 23;

/// The flag set curl always advertises in a type-1 message:
/// `OEM | REQUEST_TARGET | NTLM_KEY | NTLM2_KEY | ALWAYS_SIGN` (`0x0008_8206`).
const TYPE1_FLAGS: u32 = NTLMFLAG_NEGOTIATE_OEM
    | NTLMFLAG_REQUEST_TARGET
    | NTLMFLAG_NEGOTIATE_NTLM_KEY
    | NTLMFLAG_NEGOTIATE_NTLM2_KEY
    | NTLMFLAG_NEGOTIATE_ALWAYS_SIGN;

/// The HTTP authentication bit that corresponds to `CURLAUTH_NTLM` in the
/// public curl headers (`1 << 3`). It is surfaced through
/// [`NtlmOutput::picked`] so the connection layer can record which scheme was
/// ultimately selected, mirroring curl setting
/// `data->info.httpauthpicked = CURLAUTH_NTLM` in `Curl_output_ntlm`.
pub const CURLAUTH_NTLM: u64 = 1 << 3;

/// The per-connection NTLM handshake state, mirroring curl's `curlntlm` enum
/// (`NTLMSTATE_*`). NTLM authenticates a *connection* rather than a single
/// request, so this state is tracked per connection and, independently, for the
/// origin host and for an HTTP proxy (curl keeps `http_ntlm_state` and
/// `proxy_ntlm_state` on `connectdata`). The connection layer owns one
/// [`NtlmHandshake`] per role.
///
/// The discriminants match curl's ordering so that the "already past type-1"
/// rejection in [`NtlmHandshake::input`] is faithful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(u8)]
pub enum NtlmState {
    /// No NTLM exchange in progress (`NTLMSTATE_NONE`).
    #[default]
    None = 0,
    /// A type-1 (negotiate) message is queued to be sent (`NTLMSTATE_TYPE1`).
    Type1 = 1,
    /// A type-2 (challenge) message has been received (`NTLMSTATE_TYPE2`).
    Type2 = 2,
    /// A type-3 (authenticate) message has been sent (`NTLMSTATE_TYPE3`).
    Type3 = 3,
    /// The handshake is complete; no further NTLM headers are emitted on this
    /// connection (`NTLMSTATE_LAST`).
    Last = 4,
}

/// The mutable NTLM crypto state extracted from the server's type-2 message and
/// consumed when building the type-3 response — curl's `struct ntlmdata`
/// (excluding the SSPI-only fields, which are out of scope for the pure-Rust
/// backend).
///
/// * `flags` — the negotiate flags the server advertised in its type-2 message
///   (`Curl_read32_le(&type2[20])`). The presence of
///   [`NTLMFLAG_NEGOTIATE_NTLM2_KEY`] selects the NTLMv2 response path, and
///   [`NTLMFLAG_NEGOTIATE_UNICODE`] selects UTF-16LE string encoding.
/// * `nonce` — the 8-byte server challenge (`type2[24..32]`).
/// * `target_info` / `target_info_len` — the Target Information block copied out
///   of the type-2 message, fed verbatim into the NTLMv2 response blob.
#[derive(Debug, Clone, Default)]
pub struct NtlmData {
    /// Negotiate flags received from the server in the type-2 message.
    pub flags: u32,
    /// The 8-byte server challenge (nonce) from the type-2 message.
    pub nonce: [u8; 8],
    /// Length, in bytes, of [`Self::target_info`] (kept as a separate `u16` to
    /// mirror curl's `unsigned short target_info_len` and the on-the-wire
    /// width).
    pub target_info_len: u16,
    /// The Target Information block copied from the type-2 message.
    pub target_info: Vec<u8>,
}

/// A complete, self-contained NTLM handshake for one connection role (origin
/// host *or* proxy). It pairs the [`NtlmState`] (curl's per-connection
/// `curlntlm`) with the [`NtlmData`] crypto state (curl's `struct ntlmdata`,
/// obtained via `Curl_auth_ntlm_get`).
///
/// The connection layer creates one instance per role and drives it with
/// [`input`](Self::input) (on each `WWW-Authenticate`/`Proxy-Authenticate`
/// header) and [`output`](Self::output) (to produce the next request's
/// `Authorization`/`Proxy-Authorization` header).
#[derive(Debug, Clone, Default)]
pub struct NtlmHandshake {
    /// The current handshake state.
    pub state: NtlmState,
    /// The crypto state extracted from the most recent type-2 message.
    pub data: NtlmData,
}

/// The result of [`NtlmHandshake::output`]: the header to emit (if any) plus the
/// auth-tracking signals curl sets on `data->state`/`data->info`.
///
/// This replaces curl's in-place mutation of `*allocuserpwd` (the cached header
/// string), `authp->done`, and `data->info.[proxy]authpicked` with explicit
/// return values, keeping this module free of any dependency on the connection
/// or easy-handle types.
#[derive(Debug, Clone)]
pub struct NtlmOutput {
    /// The full header line to send — e.g.
    /// `"Authorization: NTLM <base64>\r\n"` (or the `"Proxy-"` variant) — or
    /// [`None`] when no header should be emitted (the connection is already
    /// authenticated).
    pub header: Option<String>,
    /// Whether the auth phase is done for this scheme (curl's `authp->done`).
    pub done: bool,
    /// Whether NTLM was the picked scheme and the caller should record
    /// [`CURLAUTH_NTLM`] (curl's `data->info.[proxy]authpicked`).
    pub picked: bool,
}

// ---- little-endian read helpers (replacing Curl_read16_le/read32_le) ------

/// Reads a little-endian `u16` from the first two bytes of `b`.
///
/// The caller must guarantee `b.len() >= 2`; every call site here first
/// validates the message length (mirroring curl's explicit bounds checks before
/// each `Curl_read16_le`).
#[inline]
fn read16_le(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

/// Reads a little-endian `u32` from the first four bytes of `b`.
///
/// The caller must guarantee `b.len() >= 4`; see [`read16_le`].
#[inline]
fn read32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

// ===========================================================================
// Phase E — crypto core (from lib/curl_ntlm_core.c)
// ===========================================================================

/// Encodes `src` as little-endian UTF-16 the way curl's `ascii_to_unicode_le` /
/// `unicodecpy` do: each input byte becomes a 16-bit code unit whose low byte is
/// the input byte and whose high byte is zero.
///
/// This is curl's exact (and deliberately byte-wise, *not* code-point-aware)
/// behavior, so it is reproduced as-is for wire parity rather than performing a
/// correct UTF-8 → UTF-16 transcoding.
fn ascii_to_utf16le(src: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(src.len() * 2);
    for &b in src {
        out.push(b);
        out.push(0);
    }
    out
}

/// Like [`ascii_to_utf16le`], but upper-cases each ASCII byte first (curl's
/// `ascii_uppercase_to_unicode_le`, used only for the *username* half of the
/// NTLMv2 identity). Upper-casing is ASCII-only (`a`–`z` → `A`–`Z`), matching
/// curl's `Curl_raw_toupper`.
fn ascii_uppercase_to_utf16le(src: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(src.len() * 2);
    for &b in src {
        out.push(b.to_ascii_uppercase());
        out.push(0);
    }
    out
}

/// Expands a 56-bit (7-byte) key into the 64-bit (8-byte) layout DES expects,
/// spreading the bits exactly as curl's `extend_key_56_to_64`: each output byte
/// takes 7 bits from the input, MSB-aligned, leaving the low parity bit for
/// [`set_des_odd_parity`].
///
/// All shifts are on `u8`, so the high bits that C masks with `& 0xFF` are
/// dropped here implicitly; the shift amounts (1–7) are always `< 8`, so no
/// shift ever panics.
fn extend_key_56_to_64(key7: &[u8; 7]) -> [u8; 8] {
    [
        key7[0],
        (key7[0] << 7) | (key7[1] >> 1),
        (key7[1] << 6) | (key7[2] >> 2),
        (key7[2] << 5) | (key7[3] >> 3),
        (key7[3] << 4) | (key7[4] >> 4),
        (key7[4] << 3) | (key7[5] >> 5),
        (key7[5] << 2) | (key7[6] >> 6),
        key7[6] << 1,
    ]
}

/// Adjusts each byte of `block` to odd parity, matching curl's
/// `curl_des_set_odd_parity`: if the XOR of bits 1–7 is zero (an even count of
/// set bits in the top seven), set bit 0; otherwise clear it. The result always
/// has an odd number of set bits per byte, as DES key bytes require.
fn set_des_odd_parity(block: &mut [u8; 8]) {
    for b in block.iter_mut() {
        let v = *b;
        let parity = (v >> 7) ^ (v >> 6) ^ (v >> 5) ^ (v >> 4) ^ (v >> 3) ^ (v >> 2) ^ (v >> 1);
        if parity & 0x01 == 0 {
            *b |= 0x01;
        } else {
            *b &= 0xFE;
        }
    }
}

/// Encrypts a single 8-byte block with DES-ECB under the given 8-byte key,
/// using the pure-Rust [`des`] crate.
///
/// `key8` must already be parity-adjusted (see [`des56`]). `GenericArray`
/// construction from a fixed `[u8; 8]` cannot fail (the length is exactly the
/// DES key/block size), so this needs no fallible path and contains no
/// `unsafe`.
fn des_encrypt_ecb(key8: &[u8; 8], plaintext8: &[u8; 8]) -> [u8; 8] {
    let cipher = Des::new(GenericArray::from_slice(key8));
    let mut block = GenericArray::clone_from_slice(plaintext8);
    cipher.encrypt_block(&mut block);
    let mut out = [0u8; 8];
    out.copy_from_slice(block.as_slice());
    out
}

/// Combines [`extend_key_56_to_64`], [`set_des_odd_parity`] and
/// [`des_encrypt_ecb`] into curl's `setup_des_key` + `DES_ecb_encrypt` pair:
/// derive a DES key from a 7-byte key fragment and encrypt one 8-byte block.
fn des56(key7: &[u8; 7], plaintext8: &[u8; 8]) -> [u8; 8] {
    let mut key8 = extend_key_56_to_64(key7);
    set_des_odd_parity(&mut key8);
    des_encrypt_ecb(&key8, plaintext8)
}

/// Treats a 21-byte key as three 56-bit DES keys, encrypts `plaintext8` under
/// each, and concatenates the three 8-byte results into a 24-byte response.
/// This is curl's `Curl_ntlm_core_lm_resp`, used for both the LM and the NTLMv1
/// responses.
fn lm_resp(keys21: &[u8; 21], plaintext8: &[u8; 8]) -> [u8; 24] {
    let mut out = [0u8; 24];
    let mut k = [0u8; 7];

    k.copy_from_slice(&keys21[0..7]);
    out[0..8].copy_from_slice(&des56(&k, plaintext8));

    k.copy_from_slice(&keys21[7..14]);
    out[8..16].copy_from_slice(&des56(&k, plaintext8));

    k.copy_from_slice(&keys21[14..21]);
    out[16..24].copy_from_slice(&des56(&k, plaintext8));

    out
}

/// Builds the LAN Manager hashed password, curl's
/// `Curl_ntlm_core_mk_lm_hash`: upper-case (ASCII) the password, truncate or
/// NUL-pad it to 14 bytes, then DES-encrypt the magic constant `"KGS!@#$%"`
/// under each 7-byte half. The two 8-byte ciphertexts form the 16-byte LM hash,
/// zero-extended to 21 bytes so it can drive [`lm_resp`].
fn mk_lm_hash(password: &[u8]) -> [u8; 21] {
    /// The fixed DES plaintext for the LM hash (ASCII `"KGS!@#$%"`).
    const MAGIC: [u8; 8] = *b"KGS!@#$%";

    let mut pw = [0u8; 14];
    let len = password.len().min(14);
    for (dst, &src) in pw.iter_mut().zip(&password[..len]) {
        *dst = src.to_ascii_uppercase();
    }
    // pw[len..14] remains zero (curl's `memset(&pw[len], 0, 14 - len)`).

    let mut out = [0u8; 21];
    let mut k = [0u8; 7];

    k.copy_from_slice(&pw[0..7]);
    out[0..8].copy_from_slice(&des56(&k, &MAGIC));

    k.copy_from_slice(&pw[7..14]);
    out[8..16].copy_from_slice(&des56(&k, &MAGIC));

    // out[16..21] remains zero (curl's `memset(lmbuffer + 16, 0, 21 - 16)`).
    out
}

/// Builds the NT hashed password, curl's `Curl_ntlm_core_mk_nt_hash`: MD4 of
/// the UTF-16LE password, zero-extended to 21 bytes so it can drive
/// [`lm_resp`].
fn mk_nt_hash(password: &[u8]) -> [u8; 21] {
    let unicode = ascii_to_utf16le(password);
    let digest = md4it(&unicode); // [u8; 16]
    let mut out = [0u8; 21];
    out[0..16].copy_from_slice(&digest);
    out
}

/// Builds the NTLMv2 hash, curl's `Curl_ntlm_core_mk_ntlmv2_hash`: HMAC-MD5
/// keyed by the (first 16 bytes of the) NT hash over the identity
/// `UTF16LE(UPPERCASE(user)) || UTF16LE(domain)`. Only the username is
/// upper-cased; the domain is left as-is.
fn mk_ntlmv2_hash(user: &[u8], domain: &[u8], nt_hash: &[u8; 21]) -> [u8; 16] {
    let mut identity = ascii_uppercase_to_utf16le(user);
    identity.extend_from_slice(&ascii_to_utf16le(domain));
    hmac_md5(&nt_hash[0..16], &identity)
}

/// Computes the NTLMv2 timestamp: a Windows `FILETIME`, i.e. the number of
/// tenths of a microsecond since 1601-01-01 00:00:00 UTC, as a little-endian
/// 64-bit value.
///
/// In debug builds, if the `CURL_FORCETIME` environment variable is set the
/// timestamp is forced to the value for Unix time `0`
/// (`116_444_736_000_000_000`), reproducing curl's `#ifdef DEBUGBUILD` /
/// `getenv("CURL_FORCETIME")` hook so the regression suite gets deterministic
/// NTLMv2 output. This hook is compiled out of release builds entirely.
fn ntlmv2_timestamp() -> u64 {
    #[cfg(debug_assertions)]
    if std::env::var_os("CURL_FORCETIME").is_some() {
        return filetime_from_unix_secs(0);
    }

    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0_i64, |d| d.as_secs() as i64);
    filetime_from_unix_secs(secs)
}

/// Converts a Unix timestamp (seconds since 1970-01-01) to a Windows `FILETIME`
/// in tenths of a microsecond since 1601-01-01, matching the `SIZEOF_TIME_T > 4`
/// branch of curl's `time2filetime`. The intermediate product is computed in
/// `i128` to avoid any overflow before the final, in-range `u64` cast.
fn filetime_from_unix_secs(t: i64) -> u64 {
    // 11_644_473_600 = seconds between 1601-01-01 and 1970-01-01.
    ((i128::from(t) + 11_644_473_600_i128) * 10_000_000_i128) as u64
}

/// Builds the NTLMv2 response, curl's `Curl_ntlm_core_mk_ntlmv2_resp`.
///
/// The response is `HMAC-MD5 || BLOB`, where the 16-byte HMAC-MD5 (keyed by the
/// NTLMv2 hash) is computed over `server_nonce || BLOB`:
///
/// ```text
///  0   HMAC-MD5         16 bytes   (filled in last)
///  --- BLOB --------------------------------------------------------------
/// 16   Signature        0x01 0x01 0x00 0x00
/// 20   Reserved         0x00000000
/// 24   Timestamp        8 bytes, little-endian FILETIME
/// 32   Client nonce     8 bytes
/// 40   Unknown          0x00000000
/// 44   Target Info      N bytes (from the type-2 message)
/// 44+N Unknown          0x00000000
/// ```
///
/// The total length is `16 + (32 + target_info_len)`. To compute the MAC, the
/// server nonce is temporarily written to bytes `[8..16]` (immediately before
/// the BLOB), the HMAC is taken over `[8..]`, and the 16-byte result then
/// overwrites bytes `[0..16]`.
fn mk_ntlmv2_resp(ntlmv2_hash: &[u8; 16], client_nonce: &[u8; 8], data: &NtlmData) -> Vec<u8> {
    let ti_len = data.target_info_len as usize;
    let blob_len = 32 + ti_len; // curl's NTLMv2_BLOB_LEN
    let total = 16 + blob_len; // HMAC_MD5_LENGTH + NTLMv2_BLOB_LEN
    let mut out = vec![0u8; total];

    // BLOB signature 0x01010000 at offset 16; reserved (20..24) stays zero.
    out[16] = 0x01;
    out[17] = 0x01;
    // out[18], out[19] already zero.

    // Timestamp (little-endian FILETIME) at offset 24.
    out[24..32].copy_from_slice(&ntlmv2_timestamp().to_le_bytes());

    // Client nonce at offset 32; the 4 "unknown" bytes (40..44) stay zero.
    out[32..40].copy_from_slice(client_nonce);

    // Target Info at offset 44; the trailing 4 "unknown" bytes stay zero.
    if ti_len > 0 {
        out[44..44 + ti_len].copy_from_slice(&data.target_info[..ti_len]);
    }

    // Prepend the server challenge, MAC over [8..], then overwrite [0..16].
    out[8..16].copy_from_slice(&data.nonce);
    let mac = hmac_md5(ntlmv2_hash, &out[8..]);
    out[0..16].copy_from_slice(&mac);

    out
}

/// Builds the LMv2 response, curl's `Curl_ntlm_core_mk_lmv2_resp`:
/// `HMAC-MD5(ntlmv2_hash, server_challenge || client_nonce) || client_nonce`,
/// for a fixed 24-byte result.
fn mk_lmv2_resp(
    ntlmv2_hash: &[u8; 16],
    client_nonce: &[u8; 8],
    server_challenge: &[u8; 8],
) -> [u8; 24] {
    let mut data = [0u8; 16];
    data[0..8].copy_from_slice(server_challenge);
    data[8..16].copy_from_slice(client_nonce);

    let mac = hmac_md5(ntlmv2_hash, &data);

    let mut out = [0u8; 24];
    out[0..16].copy_from_slice(&mac);
    out[16..24].copy_from_slice(client_nonce);
    out
}

// ===========================================================================
// Phase B/C/D — message layer (from lib/vauth/ntlm.c)
// ===========================================================================

/// Reports whether NTLM is supported, curl's `Curl_auth_is_ntlm_supported`.
///
/// Always `true`: this pure-Rust backend ships DES-capable crypto (the [`des`]
/// crate) unconditionally when the `ntlm` feature is on.
#[must_use]
pub fn is_ntlm_supported() -> bool {
    true
}

/// Clears the NTLM crypto state, curl's `Curl_auth_cleanup_ntlm`: free the
/// Target Information block and reset its length. The `flags` and `nonce`
/// fields are intentionally left untouched, exactly as in C.
pub fn cleanup(data: &mut NtlmData) {
    data.target_info = Vec::new();
    data.target_info_len = 0;
}

/// Decodes the Target Information block of a type-2 message, curl's
/// `ntlm_decode_type2_target`.
///
/// The offset and length are attacker-controlled, so the bounds check here is
/// **safety- and parity-critical**. The block is read only when the message is
/// at least 48 bytes long; an offset that runs past the buffer, that overflows
/// when added to the length, or that points into the fixed header (`< 48`) is
/// rejected with [`CurlError::BadContentEncoding`] — never indexed.
fn decode_type2_target(type2: &[u8], data: &mut NtlmData) -> Result<()> {
    let type2len = type2.len();
    let mut target_info_len: u16 = 0;

    if type2len >= 48 {
        target_info_len = read16_le(&type2[40..42]);
        let target_info_offset = read32_le(&type2[44..48]) as usize;
        let ti_len = target_info_len as usize;

        if target_info_len > 0 {
            // Reproduce curl's three guards exactly. `usize` arithmetic on a
            // 64-bit target cannot overflow for a u32 offset plus a u16 length,
            // and the explicit `offset > type2len` guard additionally rejects
            // any offset that is itself out of range.
            if target_info_offset > type2len
                || target_info_offset + ti_len > type2len
                || target_info_offset < 48
            {
                return Err(CurlError::BadContentEncoding);
            }

            data.target_info = type2[target_info_offset..target_info_offset + ti_len].to_vec();
        }
    }

    data.target_info_len = target_info_len;
    Ok(())
}

/// Decodes a type-2 (challenge) message, curl's
/// `Curl_auth_decode_ntlm_type2_message`.
///
/// `type2` is the already base64-decoded message (the HTTP glue performs the
/// base64 step). On success, `data` is populated with the server's negotiate
/// flags, the 8-byte challenge nonce, and — when the server set
/// [`NTLMFLAG_NEGOTIATE_TARGET_INFO`] — the Target Information block. The
/// message is validated for a minimum length of 32 bytes, the `NTLMSSP\0`
/// signature, and the `{0x02, 0, 0, 0}` type-2 marker at offset 8; any failure
/// yields [`CurlError::BadContentEncoding`].
pub fn decode_type2_message(type2: &[u8], data: &mut NtlmData) -> Result<()> {
    /// The little-endian type marker for a type-2 message at offset 8.
    const TYPE2_MARKER: [u8; 4] = [0x02, 0x00, 0x00, 0x00];

    data.flags = 0;

    let type2len = type2.len();
    if type2len < 32 || &type2[0..8] != NTLMSSP_SIGNATURE.as_slice() || type2[8..12] != TYPE2_MARKER
    {
        // Not a good enough type-2 message.
        return Err(CurlError::BadContentEncoding);
    }

    data.flags = read32_le(&type2[20..24]);
    data.nonce.copy_from_slice(&type2[24..32]);

    if data.flags & NTLMFLAG_NEGOTIATE_TARGET_INFO != 0 {
        decode_type2_target(type2, data)?;
    }

    Ok(())
}

/// Appends an 8-byte NTLM "security buffer" (length, allocated space, offset) to
/// `buf`. curl writes `SHORTPAIR(len)` twice followed by `SHORTPAIR(offset)` and
/// two zero bytes; since every offset here is well under 65536, the 4-byte
/// little-endian `offset` is byte-for-byte identical to that encoding.
fn push_security_buffer(buf: &mut Vec<u8>, len: u16, offset: u32) {
    buf.extend_from_slice(&len.to_le_bytes()); // length
    buf.extend_from_slice(&len.to_le_bytes()); // allocated space (== length)
    buf.extend_from_slice(&offset.to_le_bytes()); // 4-byte offset
}

/// Creates a type-1 (negotiate) message, curl's
/// `Curl_auth_create_ntlm_type1_message`.
///
/// Any prior NTLM state on `data` is cleared first (curl calls
/// `Curl_auth_cleanup_ntlm` at the top). The result is the **fixed 32-byte**
/// message — signature, type marker, the constant [`TYPE1_FLAGS`], and empty
/// domain and workstation security buffers — returned as raw bytes; the HTTP
/// glue base64-encodes it for the header.
pub fn create_type1_message(data: &mut NtlmData) -> Result<Vec<u8>> {
    cleanup(data);

    let mut msg = Vec::with_capacity(32);
    msg.extend_from_slice(NTLMSSP_SIGNATURE); // 8 bytes: "NTLMSSP\0"
    msg.extend_from_slice(&1u32.to_le_bytes()); // message type = 1
    msg.extend_from_slice(&TYPE1_FLAGS.to_le_bytes()); // negotiate flags

    // Empty domain security buffer (len = alloc = offset = 0).
    push_security_buffer(&mut msg, 0, 0);
    // Empty workstation security buffer (len = alloc = offset = 0).
    push_security_buffer(&mut msg, 0, 0);

    debug_assert_eq!(msg.len(), 32);
    Ok(msg)
}

/// Creates a type-3 (authenticate) message, curl's
/// `Curl_auth_create_ntlm_type3_message`.
///
/// `userp` is the username, optionally prefixed with a domain as `Domain\User`
/// or `Domain/User`; `passwd` is the password. The response path is chosen by
/// the server's flags recorded in `data`:
///
/// * If [`NTLMFLAG_NEGOTIATE_NTLM2_KEY`] is set, the **NTLMv2** path is taken: a
///   fresh 8-byte client nonce is drawn (via [`rand_bytes`], which honors the
///   `CURL_ENTROPY` test hook), and the LMv2 and NTLMv2 responses are built.
/// * Otherwise the **NTLMv1** path is taken: the NT and LM responses are three
///   DES blocks each, and the `NTLM2_KEY` flag is cleared in the emitted
///   message.
///
/// String fields are UTF-16LE-encoded when [`NTLMFLAG_NEGOTIATE_UNICODE`] is
/// set. The message is laid out as a 64-byte header of security buffers
/// followed by the LM response (always 24 bytes), the NT response, and the
/// domain/user/host strings. Sizes are checked against [`NTLM_BUFSIZE`]; an
/// overflow yields [`CurlError::TooLarge`]. The raw bytes are returned; the HTTP
/// glue base64-encodes them. `data` is cleared before returning (curl calls
/// `Curl_auth_cleanup_ntlm` at the end).
pub fn create_type3_message(data: &mut NtlmData, userp: &str, passwd: &str) -> Result<Vec<u8>> {
    let passwd_bytes = passwd.as_bytes();

    // Split "Domain\User" / "Domain/User"; backslash takes priority, matching
    // curl's `strchr(userp, '\\')` then `strchr(userp, '/')`.
    let (domain, user) = match userp.find('\\').or_else(|| userp.find('/')) {
        Some(idx) => (&userp[..idx], &userp[idx + 1..]),
        None => ("", userp),
    };
    let domain_bytes = domain.as_bytes();
    let user_bytes = user.as_bytes();

    let unicode = data.flags & NTLMFLAG_NEGOTIATE_UNICODE != 0;

    // The 24-byte LM response and the variable-length NT response.
    let lmresp: [u8; 24];
    let ntresp: Vec<u8>;

    if data.flags & NTLMFLAG_NEGOTIATE_NTLM2_KEY != 0 {
        // ---- NTLMv2 path ----------------------------------------------------
        let mut client_nonce = [0u8; 8];
        rand_bytes(&mut client_nonce)?;

        let nt_hash = mk_nt_hash(passwd_bytes);
        let ntlmv2_hash = mk_ntlmv2_hash(user_bytes, domain_bytes, &nt_hash);

        lmresp = mk_lmv2_resp(&ntlmv2_hash, &client_nonce, &data.nonce);
        ntresp = mk_ntlmv2_resp(&ntlmv2_hash, &client_nonce, data);
    } else {
        // ---- NTLMv1 path ----------------------------------------------------
        let nt_hash = mk_nt_hash(passwd_bytes);
        ntresp = lm_resp(&nt_hash, &data.nonce).to_vec();

        let lm_hash = mk_lm_hash(passwd_bytes);
        lmresp = lm_resp(&lm_hash, &data.nonce);

        // NTLMv2 was not negotiated; clear the bit in the emitted flags.
        data.flags &= !NTLMFLAG_NEGOTIATE_NTLM2_KEY;
    }

    let ntresplen = ntresp.len();

    // Encode the string fields in the negotiated charset; their encoded lengths
    // feed both the security-buffer fields and the payload offsets.
    let dom_enc = encode_field(domain_bytes, unicode);
    let user_enc = encode_field(user_bytes, unicode);
    let host_enc = encode_field(WORKSTATION, unicode);
    let domlen = dom_enc.len();
    let userlen = user_enc.len();
    let hostlen = host_enc.len();

    // Offsets within the message (curl's fixed 64-byte header, then payload).
    let lmrespoff: usize = 64;
    let ntrespoff: usize = lmrespoff + 0x18; // LM response is always 0x18 bytes
    let domoff = ntrespoff + ntresplen;
    let useroff = domoff + domlen;
    let hostoff = useroff + userlen;

    // ---- 64-byte header of security buffers ------------------------------
    let mut msg = Vec::with_capacity(NTLM_BUFSIZE);
    msg.extend_from_slice(NTLMSSP_SIGNATURE); // 8 bytes: "NTLMSSP\0"
    msg.extend_from_slice(&3u32.to_le_bytes()); // message type = 3

    // The lengths below are all bounded well under u16::MAX by the NTLM_BUFSIZE
    // checks performed when the payload is appended, so the `as u16` / `as u32`
    // narrowing casts cannot lose information.
    push_security_buffer(&mut msg, 0x18, lmrespoff as u32); // LM response
    push_security_buffer(&mut msg, ntresplen as u16, ntrespoff as u32); // NT response
    push_security_buffer(&mut msg, domlen as u16, domoff as u32); // domain
    push_security_buffer(&mut msg, userlen as u16, useroff as u32); // user
    push_security_buffer(&mut msg, hostlen as u16, hostoff as u32); // host
    push_security_buffer(&mut msg, 0, 0); // session key (unused)
    msg.extend_from_slice(&data.flags.to_le_bytes()); // negotiate flags

    debug_assert_eq!(msg.len(), 64);
    debug_assert_eq!(msg.len(), lmrespoff);

    // ---- payload ---------------------------------------------------------
    // LM response (always 24 bytes). curl guards this with
    // `size < NTLM_BUFSIZE - 0x18`, which is always true at size == 64.
    msg.extend_from_slice(&lmresp);

    // NT response. curl: `if(ntresplen + size > sizeof(ntlmbuf)) too_large`,
    // where `size` is 64 + 0x18 == 88 at this point.
    if ntresplen + msg.len() > NTLM_BUFSIZE {
        return Err(CurlError::TooLarge);
    }
    debug_assert_eq!(msg.len(), ntrespoff);
    msg.extend_from_slice(&ntresp);

    // domain / user / host strings. curl:
    // `if(size + userlen + domlen + hostlen >= NTLM_BUFSIZE) too_large`.
    if msg.len() + userlen + domlen + hostlen >= NTLM_BUFSIZE {
        return Err(CurlError::TooLarge);
    }
    debug_assert_eq!(msg.len(), domoff);
    msg.extend_from_slice(&dom_enc);
    debug_assert_eq!(msg.len(), useroff);
    msg.extend_from_slice(&user_enc);
    debug_assert_eq!(msg.len(), hostoff);
    msg.extend_from_slice(&host_enc);

    // curl clears the NTLM state at the end of type-3 construction.
    cleanup(data);

    Ok(msg)
}

/// Encodes a string field for the type-3 payload: UTF-16LE when `unicode` is
/// set (curl's `unicodecpy`), otherwise the raw bytes (curl's `memcpy`).
fn encode_field(src: &[u8], unicode: bool) -> Vec<u8> {
    if unicode {
        ascii_to_utf16le(src)
    } else {
        src.to_vec()
    }
}

// ===========================================================================
// Phase F — HTTP glue / state machine (from lib/http_ntlm.c)
// ===========================================================================

/// Formats an `Authorization` (or `Proxy-Authorization`) header line carrying a
/// base64-encoded NTLM message, matching curl's
/// `"%sAuthorization: NTLM %s\r\n"`.
///
/// base64 output is pure ASCII, so the UTF-8 validation can never realistically
/// fail; the fallible conversion is handled (rather than unwrapped) to keep the
/// module panic-free.
fn ntlm_header(proxy: bool, msg: &[u8]) -> Result<String> {
    let b64 = base64_encode(msg)?;
    let b64_str = core::str::from_utf8(&b64).map_err(|_| CurlError::OutOfMemory)?;
    let prefix = if proxy { "Proxy-" } else { "" };
    Ok(format!("{prefix}Authorization: NTLM {b64_str}\r\n"))
}

impl NtlmHandshake {
    /// Creates a fresh handshake in the [`NtlmState::None`] state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the current handshake state.
    #[must_use]
    pub fn state(&self) -> NtlmState {
        self.state
    }

    /// Resets the handshake to its initial state, clearing any cached crypto
    /// state (curl's `Curl_auth_ntlm_remove` followed by re-initialization).
    pub fn reset(&mut self) {
        cleanup(&mut self.data);
        self.state = NtlmState::None;
    }

    /// Consumes a `WWW-Authenticate` / `Proxy-Authenticate` header value,
    /// curl's `Curl_input_ntlm`.
    ///
    /// `header` is the raw header value (the connection layer has already
    /// selected the host or proxy handshake instance). If it begins with the
    /// case-insensitive `"NTLM"` token:
    ///
    /// * **with trailing data** — the data is base64-decoded and parsed as a
    ///   type-2 message (advancing to [`NtlmState::Type2`]);
    /// * **bare `"NTLM"`** — the state machine advances per curl's rules: from
    ///   [`NtlmState::Last`] the handshake restarts (state →
    ///   [`NtlmState::Type1`]); from [`NtlmState::Type3`] it is a rejection
    ///   (state → [`NtlmState::None`], [`CurlError::RemoteAccessDenied`]); from
    ///   [`NtlmState::Type1`]/[`NtlmState::Type2`] it is an internal error
    ///   ([`CurlError::RemoteAccessDenied`]); from [`NtlmState::None`] a type-1
    ///   is queued (state → [`NtlmState::Type1`]).
    ///
    /// A header that does not start with `"NTLM"` is ignored (returns `Ok`),
    /// matching curl's `checkprefix` guard.
    pub fn input(&mut self, header: &str) -> Result<()> {
        let bytes = header.as_bytes();
        if bytes.len() < 4 || !bytes[..4].eq_ignore_ascii_case(b"NTLM") {
            return Ok(());
        }

        // Skip the "NTLM" token, then any blanks (spaces / tabs), mirroring
        // curl's `while(*header && ISBLANK(*header)) header++;`. The first four
        // bytes are ASCII, so byte index 4 is a valid char boundary. A `&[char]`
        // slice pattern (via `as_slice`) is used rather than a `|c| c == ' ' ||
        // c == '\t'` closure (which clippy flags as a manual char comparison)
        // and rather than the `[' ', '\t']` array pattern clippy suggests (whose
        // `Pattern for [char; N]` impl postdates the 1.75 MSRV).
        const BLANKS: [char; 2] = [' ', '\t'];
        let rest = header[4..].trim_start_matches(BLANKS.as_slice());

        if !rest.is_empty() {
            let decoded = base64_decode(rest.as_bytes())?;
            decode_type2_message(&decoded, &mut self.data)?;
            self.state = NtlmState::Type2;
        } else {
            match self.state {
                NtlmState::Last => {
                    // NTLM auth restarted: drop cached state, then queue type-1.
                    cleanup(&mut self.data);
                    self.state = NtlmState::Type1;
                }
                NtlmState::Type3 => {
                    // NTLM handshake rejected by the server.
                    cleanup(&mut self.data);
                    self.state = NtlmState::None;
                    return Err(CurlError::RemoteAccessDenied);
                }
                NtlmState::Type1 | NtlmState::Type2 => {
                    // Already past type-1 with no challenge: internal failure.
                    return Err(CurlError::RemoteAccessDenied);
                }
                NtlmState::None => {
                    self.state = NtlmState::Type1;
                }
            }
        }

        Ok(())
    }

    /// Produces the next `Authorization` / `Proxy-Authorization` header, curl's
    /// `Curl_output_ntlm`.
    ///
    /// `proxy` selects the `"Proxy-"` header prefix; `userp` is the username
    /// (optionally `Domain\User`) and `passwd` the password. The returned
    /// [`NtlmOutput`] carries the header to send (if any) plus the `done` and
    /// `picked` signals:
    ///
    /// * [`NtlmState::Type1`] / [`NtlmState::None`] — emit a type-1 message;
    ///   `done = false`.
    /// * [`NtlmState::Type2`] — emit a type-3 message, advance to
    ///   [`NtlmState::Type3`]; `done = true`.
    /// * [`NtlmState::Type3`] — already authenticated; converted to
    ///   [`NtlmState::Last`] and handled as below.
    /// * [`NtlmState::Last`] — emit no header but record [`CURLAUTH_NTLM`] as
    ///   the picked scheme; `done = true`, `picked = true`.
    ///
    /// The `service` parameter present in curl's signature is omitted: it has no
    /// effect on NTLM message construction (curl's type-1 builder ignores it).
    pub fn output(&mut self, proxy: bool, userp: &str, passwd: &str) -> Result<NtlmOutput> {
        // An already-authenticated connection sends no further headers.
        if self.state == NtlmState::Type3 {
            self.state = NtlmState::Last;
        }

        match self.state {
            NtlmState::Type2 => {
                // We received the type-2 challenge: answer with a type-3.
                let msg = create_type3_message(&mut self.data, userp, passwd)?;
                let header = ntlm_header(proxy, &msg)?;
                self.state = NtlmState::Type3;
                Ok(NtlmOutput {
                    header: Some(header),
                    done: true,
                    picked: false,
                })
            }
            NtlmState::Last => {
                // Already authenticated: emit nothing, record NTLM as picked.
                Ok(NtlmOutput {
                    header: None,
                    done: true,
                    picked: true,
                })
            }
            // NtlmState::Type1 and NtlmState::None (curl's `case TYPE1: default:`).
            _ => {
                let msg = create_type1_message(&mut self.data)?;
                let header = ntlm_header(proxy, &msg)?;
                Ok(NtlmOutput {
                    header: Some(header),
                    done: false,
                    picked: false,
                })
            }
        }
    }
}

// ===========================================================================
// Phase G — unit tests
//
// The crypto primitives are pinned against published known-answer vectors:
//   * a FIPS-81 single-block DES vector (the `des`-crate wiring),
//   * the canonical NTLMv1 vectors from Eric Glass's "The NTLM Authentication
//     Protocol" (password "SecREt01"),
//   * the [MS-NLMP] §4.2.4 NTLMv2 example vectors (User / Domain / Password).
// Determinism for the random client nonce and the NTLMv2 timestamp is obtained
// via the `CURL_ENTROPY` and `CURL_FORCETIME` debug hooks, mirroring curl's
// DEBUGBUILD behavior.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    /// RAII guard that sets an environment variable for the duration of a test
    /// and restores its previous value (or removes it) on drop — including on
    /// panic-unwind — so the deterministic `CURL_ENTROPY` / `CURL_FORCETIME`
    /// hooks never leak into sibling tests. `set_var` / `remove_var` are safe in
    /// edition 2021, keeping this within the crate-wide `#![forbid(unsafe_code)]`.
    struct EnvGuard {
        key: &'static str,
        prev: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, val: &str) -> Self {
            let prev = std::env::var_os(key);
            std::env::set_var(key, val);
            Self { key, prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.prev.take() {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    /// Decodes a hex string (even length, no separators) into bytes.
    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "hex string must have even length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    fn arr8(s: &str) -> [u8; 8] {
        let v = hex(s);
        let mut a = [0u8; 8];
        a.copy_from_slice(&v);
        a
    }

    // ---- crypto primitive vectors ----------------------------------------

    #[test]
    fn des_ecb_fips_vector() {
        // Classic FIPS-81 / "Now is the time for all " DES known-answer.
        let key = arr8("0123456789ABCDEF");
        let pt = arr8("4E6F772069732074"); // "Now is t"
        let ct = des_encrypt_ecb(&key, &pt);
        assert_eq!(ct, arr8("3FA40E8A984D4815"));
    }

    #[test]
    fn extend_key_bit_spreading() {
        let key7 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        // Hand-computed expansion (see extend_key_56_to_64 docs).
        assert_eq!(
            extend_key_56_to_64(&key7),
            [0x01, 0x81, 0x80, 0x60, 0x40, 0x28, 0x18, 0x0E]
        );
    }

    #[test]
    fn odd_parity_adjustment() {
        let mut block = [0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0x80, 0x7F];
        set_des_odd_parity(&mut block);
        assert_eq!(block, [0x01, 0x01, 0x02, 0x02, 0xFE, 0xFE, 0x80, 0x7F]);
        // Every byte must now have an odd number of set bits.
        for b in block {
            assert_eq!(b.count_ones() % 2, 1, "byte {b:#04x} is not odd parity");
        }
    }

    #[test]
    fn lm_hash_vector() {
        // Eric Glass NTLM doc, password "SecREt01".
        let h = mk_lm_hash(b"SecREt01");
        assert_eq!(
            &h[0..16],
            hex("FF3750BCC2B22412C2265B23734E0DAC").as_slice()
        );
        assert_eq!(&h[16..21], &[0, 0, 0, 0, 0]); // zero-extended tail
    }

    #[test]
    fn nt_hash_vectors() {
        // MD4 of the empty UTF-16LE string — a rock-solid independent anchor.
        assert_eq!(
            &mk_nt_hash(b"")[0..16],
            hex("31D6CFE0D16AE931B73C59D7E0C089C0").as_slice()
        );
        // [MS-NLMP] NTOWFv1("Password").
        assert_eq!(
            &mk_nt_hash(b"Password")[0..16],
            hex("A4F49C406510BDCAB6824EE7C30FD852").as_slice()
        );
        // Eric Glass NTLM doc, password "SecREt01".
        assert_eq!(
            &mk_nt_hash(b"SecREt01")[0..16],
            hex("CD06CA7C7E10C99B1D33B7485A2ED808").as_slice()
        );
    }

    #[test]
    fn ntlmv1_responses() {
        // Eric Glass NTLM doc: challenge 0x0123456789abcdef, password "SecREt01".
        let challenge = arr8("0123456789ABCDEF");

        let lm_hash = mk_lm_hash(b"SecREt01");
        assert_eq!(
            lm_resp(&lm_hash, &challenge),
            hex("C337CD5CBD44FC9782A667AF6D427C6DE67C20C2D3E77C56").as_slice()
        );

        let nt_hash = mk_nt_hash(b"SecREt01");
        assert_eq!(
            lm_resp(&nt_hash, &challenge),
            hex("25A98C1C31E81847466B29B2DF4680F39958FB8C213A9CC6").as_slice()
        );
    }

    /// The [MS-NLMP] §4.2.4 Target Information (AV_PAIR) block.
    fn msnlmp_target_info() -> Vec<u8> {
        // AvId=2 (NbDomainName) "Domain", AvId=1 (NbComputerName) "Server",
        // AvId=0 (EOL). Strings are UTF-16LE.
        hex(concat!(
            "02000c00",
            "44006f006d00610069006e00", // MsvAvNbDomainName "Domain"
            "01000c00",
            "530065007200760065007200", // MsvAvNbComputerName "Server"
            "00000000"                  // MsvAvEOL
        ))
    }

    #[test]
    fn ntlmv2_hash_vector() {
        // [MS-NLMP] §4.2.4.1.1: NTOWFv2 = 0c868a403bfd7a93a3001ef22ef02e3f.
        let nt_hash = mk_nt_hash(b"Password");
        let v2 = mk_ntlmv2_hash(b"User", b"Domain", &nt_hash);
        assert_eq!(v2, hex("0C868A403BFD7A93A3001EF22EF02E3F").as_slice());
    }

    #[test]
    fn lmv2_response_vector() {
        // [MS-NLMP] §4.2.4.2.1.
        let v2 = arr16(&hex("0C868A403BFD7A93A3001EF22EF02E3F"));
        let client_nonce = arr8("AAAAAAAAAAAAAAAA");
        let server_challenge = arr8("0123456789ABCDEF");
        let resp = mk_lmv2_resp(&v2, &client_nonce, &server_challenge);
        assert_eq!(
            resp,
            hex("86C35097AC9CEC102554764A57CCCC19AAAAAAAAAAAAAAAA").as_slice()
        );
    }

    #[test]
    fn ntlmv2_ntproofstr_vector() {
        // Independent [MS-NLMP] §4.2.4.2.2 cross-check of the NTProofStr using
        // a literal-zero timestamp (as the spec example does). This validates
        // the blob/temp layout and target-info placement independently of
        // mk_ntlmv2_resp's (nonzero) FILETIME.
        let v2 = arr16(&hex("0C868A403BFD7A93A3001EF22EF02E3F"));
        let client_nonce = arr8("AAAAAAAAAAAAAAAA");
        let server_challenge = arr8("0123456789ABCDEF");
        let target_info = msnlmp_target_info();

        let mut temp = Vec::new();
        temp.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]); // RespType/HiRespType/Reserved1
        temp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Reserved2
        temp.extend_from_slice(&[0u8; 8]); // Time = 0 (spec example)
        temp.extend_from_slice(&client_nonce); // ChallengeFromClient
        temp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Reserved3
        temp.extend_from_slice(&target_info); // AvPairs
        temp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // trailing Z

        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&server_challenge);
        mac_input.extend_from_slice(&temp);
        let nt_proof = hmac_md5(&v2, &mac_input);
        assert_eq!(nt_proof, hex("68CD0AB851E51C96AABC927BEBEF6A1C").as_slice());
    }

    #[test]
    fn filetime_zero() {
        // (0 + 11_644_473_600) * 10_000_000.
        assert_eq!(filetime_from_unix_secs(0), 116_444_736_000_000_000);
    }

    #[test]
    fn ntlmv2_resp_layout_and_mac() {
        // CURL_FORCETIME makes the timestamp deterministic (FILETIME of t=0).
        let _forcetime = EnvGuard::set("CURL_FORCETIME", "0");

        let v2 = arr16(&hex("0C868A403BFD7A93A3001EF22EF02E3F"));
        let client_nonce = arr8("1122334455667788");
        let data = NtlmData {
            flags: NTLMFLAG_NEGOTIATE_NTLM2_KEY,
            nonce: arr8("0123456789ABCDEF"),
            target_info_len: 8,
            target_info: hex("AABBCCDDEEFF0011"),
        };

        let resp = mk_ntlmv2_resp(&v2, &client_nonce, &data);

        // Length = 16 (HMAC) + 32 + target_info_len.
        assert_eq!(resp.len(), 16 + 32 + 8);
        // BLOB signature + reserved.
        assert_eq!(&resp[16..20], &[0x01, 0x01, 0x00, 0x00]);
        assert_eq!(&resp[20..24], &[0, 0, 0, 0]);
        // Timestamp = FILETIME(0), little-endian.
        assert_eq!(&resp[24..32], &116_444_736_000_000_000u64.to_le_bytes());
        // Client nonce + the trailing "unknown" zero quad.
        assert_eq!(&resp[32..40], &client_nonce);
        assert_eq!(&resp[40..44], &[0, 0, 0, 0]);
        // Target info + final zero quad.
        assert_eq!(&resp[44..52], data.target_info.as_slice());
        assert_eq!(&resp[52..56], &[0, 0, 0, 0]);

        // The leading 16 bytes are HMAC-MD5(v2, server_nonce || blob).
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&data.nonce);
        mac_input.extend_from_slice(&resp[16..]);
        assert_eq!(&resp[0..16], hmac_md5(&v2, &mac_input).as_slice());
    }

    fn arr16(v: &[u8]) -> [u8; 16] {
        let mut a = [0u8; 16];
        a.copy_from_slice(v);
        a
    }

    // ---- type-1 message ---------------------------------------------------

    #[test]
    fn type1_message_exact() {
        let mut data = NtlmData::default();
        let msg = create_type1_message(&mut data).expect("type-1");
        assert_eq!(msg.len(), 32);
        // Signature, type marker, flags, then 16 zero bytes (two empty bufs).
        assert_eq!(&msg[0..8], b"NTLMSSP\0");
        assert_eq!(&msg[8..12], &1u32.to_le_bytes());
        assert_eq!(&msg[12..16], &0x0008_8206u32.to_le_bytes());
        assert_eq!(&msg[16..32], &[0u8; 16]);
        // The well-known curl NTLM type-1 base64.
        let b64 = base64_encode(&msg).expect("b64");
        assert_eq!(b64, b"TlRMTVNTUAABAAAABoIIAAAAAAAAAAAAAAAAAAAAAAA=");
    }

    // ---- type-2 decode ----------------------------------------------------

    /// Builds a minimal type-2 message with the given flags, challenge, and
    /// (optional) target info placed at offset 48.
    fn build_type2(flags: u32, challenge: &[u8; 8], target_info: &[u8]) -> Vec<u8> {
        let mut m = vec![0u8; 48];
        m[0..8].copy_from_slice(b"NTLMSSP\0");
        m[8..12].copy_from_slice(&[0x02, 0, 0, 0]);
        // target-name security buffer (12..20) left zero.
        m[20..24].copy_from_slice(&flags.to_le_bytes());
        m[24..32].copy_from_slice(challenge);
        // context (32..40) left zero.
        m[40..42].copy_from_slice(&(target_info.len() as u16).to_le_bytes());
        m[42..44].copy_from_slice(&(target_info.len() as u16).to_le_bytes());
        m[44..48].copy_from_slice(&48u32.to_le_bytes());
        m.extend_from_slice(target_info);
        m
    }

    #[test]
    fn type2_decode_with_target_info() {
        let challenge = arr8("0123456789ABCDEF");
        let ti = hex("01020304");
        let flags = NTLMFLAG_NEGOTIATE_TARGET_INFO | NTLMFLAG_NEGOTIATE_NTLM2_KEY;
        let msg = build_type2(flags, &challenge, &ti);

        let mut data = NtlmData::default();
        decode_type2_message(&msg, &mut data).expect("decode");
        assert_eq!(data.flags, flags);
        assert_eq!(data.nonce, challenge);
        assert_eq!(data.target_info_len, 4);
        assert_eq!(data.target_info, ti);
    }

    #[test]
    fn type2_decode_without_target_info_flag() {
        // Target info present in the buffer but the flag is unset: curl reads
        // the flags/nonce but does NOT decode the target info.
        let challenge = arr8("FEDCBA9876543210");
        let ti = hex("DEADBEEF");
        let msg = build_type2(NTLMFLAG_NEGOTIATE_NTLM_KEY, &challenge, &ti);

        let mut data = NtlmData::default();
        decode_type2_message(&msg, &mut data).expect("decode");
        assert_eq!(data.nonce, challenge);
        assert_eq!(data.target_info_len, 0);
        assert!(data.target_info.is_empty());
    }

    #[test]
    fn type2_decode_rejects_malformed() {
        let mut data = NtlmData::default();

        // Too short (< 32 bytes).
        assert_eq!(
            decode_type2_message(&[0u8; 16], &mut data),
            Err(CurlError::BadContentEncoding)
        );

        // Bad signature.
        let mut bad_sig = vec![0u8; 32];
        bad_sig[8..12].copy_from_slice(&[0x02, 0, 0, 0]);
        assert_eq!(
            decode_type2_message(&bad_sig, &mut data),
            Err(CurlError::BadContentEncoding)
        );

        // Good signature, wrong type marker.
        let mut bad_marker = vec![0u8; 32];
        bad_marker[0..8].copy_from_slice(b"NTLMSSP\0");
        bad_marker[8..12].copy_from_slice(&[0x03, 0, 0, 0]);
        assert_eq!(
            decode_type2_message(&bad_marker, &mut data),
            Err(CurlError::BadContentEncoding)
        );
    }

    #[test]
    fn type2_decode_rejects_out_of_bounds_target_info() {
        let challenge = arr8("0123456789ABCDEF");
        let flags = NTLMFLAG_NEGOTIATE_TARGET_INFO;

        // Offset beyond the message length.
        let mut m = build_type2(flags, &challenge, &hex("01020304"));
        m[44..48].copy_from_slice(&1000u32.to_le_bytes());
        let mut data = NtlmData::default();
        assert_eq!(
            decode_type2_message(&m, &mut data),
            Err(CurlError::BadContentEncoding)
        );

        // Offset inside the fixed header (< 48).
        let mut m = build_type2(flags, &challenge, &hex("01020304"));
        m[44..48].copy_from_slice(&40u32.to_le_bytes());
        let mut data = NtlmData::default();
        assert_eq!(
            decode_type2_message(&m, &mut data),
            Err(CurlError::BadContentEncoding)
        );

        // offset + len runs past the end.
        let mut m = build_type2(flags, &challenge, &hex("01020304"));
        m[40..42].copy_from_slice(&64u16.to_le_bytes()); // claim 64 bytes at off 48
        let mut data = NtlmData::default();
        assert_eq!(
            decode_type2_message(&m, &mut data),
            Err(CurlError::BadContentEncoding)
        );
    }

    // ---- type-3 message ---------------------------------------------------

    #[test]
    fn type3_ntlmv1_layout_and_vectors() {
        // NTLMv1 path (no NTLM2_KEY): deterministic, no randomness.
        let challenge = arr8("0123456789ABCDEF");
        let mut data = NtlmData {
            flags: NTLMFLAG_NEGOTIATE_NTLM_KEY,
            nonce: challenge,
            target_info_len: 0,
            target_info: Vec::new(),
        };
        let msg = create_type3_message(&mut data, "User", "SecREt01").expect("type-3");

        // Header sanity.
        assert_eq!(&msg[0..8], b"NTLMSSP\0");
        assert_eq!(&msg[8..12], &3u32.to_le_bytes());
        // LM response security buffer: len 0x18 at offset 64.
        assert_eq!(read16_le(&msg[12..14]), 0x18);
        assert_eq!(read32_le(&msg[16..20]), 64);
        // NT response security buffer: len 0x18 at offset 88.
        assert_eq!(read16_le(&msg[20..22]), 0x18);
        assert_eq!(read32_le(&msg[24..28]), 88);
        // Emitted flags (offset 60) — NTLM2_KEY was never set.
        assert_eq!(read32_le(&msg[60..64]), NTLMFLAG_NEGOTIATE_NTLM_KEY);

        // Embedded responses match the canonical NTLMv1 vectors.
        assert_eq!(
            &msg[64..88],
            hex("C337CD5CBD44FC9782A667AF6D427C6DE67C20C2D3E77C56").as_slice()
        );
        assert_eq!(
            &msg[88..112],
            hex("25A98C1C31E81847466B29B2DF4680F39958FB8C213A9CC6").as_slice()
        );

        // User string "User" appears (ASCII, no unicode flag). The user
        // security buffer is the 4th in the header: len at [36..38], maxlen at
        // [38..40], offset at [40..44].
        let userlen = read16_le(&msg[36..38]) as usize;
        let useroff = read32_le(&msg[40..44]) as usize;
        assert_eq!(userlen, 4);
        assert_eq!(&msg[useroff..useroff + 4], b"User");
    }

    #[test]
    fn type3_ntlmv2_unicode_self_consistent() {
        let _entropy = EnvGuard::set("CURL_ENTROPY", "12345678");
        let _forcetime = EnvGuard::set("CURL_FORCETIME", "0");

        let challenge = arr8("0123456789ABCDEF");
        let target_info = msnlmp_target_info();
        let mut data = NtlmData {
            flags: NTLMFLAG_NEGOTIATE_NTLM2_KEY
                | NTLMFLAG_NEGOTIATE_UNICODE
                | NTLMFLAG_NEGOTIATE_TARGET_INFO,
            nonce: challenge,
            target_info_len: target_info.len() as u16,
            target_info: target_info.clone(),
        };
        let data_before = data.clone();

        let msg = create_type3_message(&mut data, "Domain\\User", "Password").expect("type-3");

        assert_eq!(&msg[0..8], b"NTLMSSP\0");
        assert_eq!(&msg[8..12], &3u32.to_le_bytes());

        // Extract the security buffers.
        let lmlen = read16_le(&msg[12..14]) as usize;
        let lmoff = read32_le(&msg[16..20]) as usize;
        let ntlen = read16_le(&msg[20..22]) as usize;
        let ntoff = read32_le(&msg[24..28]) as usize;
        assert_eq!(lmlen, 0x18);
        assert_eq!(lmoff, 64);
        assert_eq!(ntoff, 88);

        let lmresp = &msg[lmoff..lmoff + lmlen];
        let ntresp = &msg[ntoff..ntoff + ntlen];

        // The client nonce is the trailing 8 bytes of the LMv2 response.
        let mut client_nonce = [0u8; 8];
        client_nonce.copy_from_slice(&lmresp[16..24]);

        // Recompute the expected responses with the validated primitives.
        let nt_hash = mk_nt_hash(b"Password");
        let v2 = mk_ntlmv2_hash(b"User", b"Domain", &nt_hash);
        let expected_lm = mk_lmv2_resp(&v2, &client_nonce, &challenge);
        let expected_nt = mk_ntlmv2_resp(&v2, &client_nonce, &data_before);
        assert_eq!(lmresp, expected_lm.as_slice());
        assert_eq!(ntresp, expected_nt.as_slice());

        // Unicode user string ("User") is UTF-16LE in the payload. User
        // security buffer: len at [36..38], offset at [40..44].
        let userlen = read16_le(&msg[36..38]) as usize;
        let useroff = read32_le(&msg[40..44]) as usize;
        assert_eq!(userlen, 8); // "User" * 2 bytes
        assert_eq!(&msg[useroff..useroff + 8], b"U\0s\0e\0r\0");

        // NTLM2_KEY remains set in the emitted flags for the v2 path.
        assert_ne!(read32_le(&msg[60..64]) & NTLMFLAG_NEGOTIATE_NTLM2_KEY, 0);
    }

    #[test]
    fn type3_rejects_oversized_target_info() {
        // A target info large enough to push the NT response past NTLM_BUFSIZE.
        let challenge = arr8("0123456789ABCDEF");
        let big = vec![0x41u8; 1000];
        let mut data = NtlmData {
            flags: NTLMFLAG_NEGOTIATE_NTLM2_KEY,
            nonce: challenge,
            target_info_len: big.len() as u16,
            target_info: big,
        };
        assert_eq!(
            create_type3_message(&mut data, "User", "Password"),
            Err(CurlError::TooLarge)
        );
    }

    // ---- HTTP glue / state machine ---------------------------------------

    #[test]
    fn supported_and_cleanup() {
        assert!(is_ntlm_supported());
        let mut data = NtlmData {
            flags: 0x1234,
            nonce: [9; 8],
            target_info_len: 3,
            target_info: vec![1, 2, 3],
        };
        cleanup(&mut data);
        assert_eq!(data.target_info_len, 0);
        assert!(data.target_info.is_empty());
        // flags / nonce are intentionally preserved by cleanup.
        assert_eq!(data.flags, 0x1234);
    }

    #[test]
    fn handshake_full_flow() {
        let mut hs = NtlmHandshake::new();
        assert_eq!(hs.state(), NtlmState::None);

        // First output (no challenge yet) → a type-1 header.
        let out = hs.output(false, "User", "SecREt01").expect("type-1 out");
        let hdr = out.header.expect("header");
        assert!(hdr.starts_with("Authorization: NTLM "));
        assert!(hdr.ends_with("\r\n"));
        assert!(!out.done);

        // Server sends the type-2 challenge.
        let challenge = arr8("0123456789ABCDEF");
        let type2 = build_type2(NTLMFLAG_NEGOTIATE_NTLM_KEY, &challenge, &[]);
        let b64 = base64_encode(&type2).expect("b64");
        let header_val = format!("NTLM {}", core::str::from_utf8(&b64).unwrap());
        hs.input(&header_val).expect("input type-2");
        assert_eq!(hs.state(), NtlmState::Type2);

        // Second output → type-3 header, done, state advances to Type3.
        let out = hs.output(false, "User", "SecREt01").expect("type-3 out");
        assert!(out
            .header
            .expect("header")
            .starts_with("Authorization: NTLM "));
        assert!(out.done);
        assert_eq!(hs.state(), NtlmState::Type3);

        // Third output → connection authenticated: no header, NTLM picked.
        let out = hs.output(false, "User", "SecREt01").expect("last out");
        assert!(out.header.is_none());
        assert!(out.done);
        assert!(out.picked);
        assert_eq!(hs.state(), NtlmState::Last);
    }

    #[test]
    fn proxy_header_prefix() {
        let mut hs = NtlmHandshake::new();
        let out = hs.output(true, "User", "secret").expect("type-1");
        assert!(out
            .header
            .expect("header")
            .starts_with("Proxy-Authorization: NTLM "));
    }

    #[test]
    fn input_non_ntlm_header_ignored() {
        let mut hs = NtlmHandshake::new();
        hs.input("Basic realm=\"x\"").expect("ignored");
        assert_eq!(hs.state(), NtlmState::None);
    }

    #[test]
    fn input_rejects_after_type3() {
        let mut hs = NtlmHandshake::new();
        hs.state = NtlmState::Type3;
        // A bare "NTLM" header while in Type3 → rejection.
        assert_eq!(hs.input("NTLM"), Err(CurlError::RemoteAccessDenied));
        assert_eq!(hs.state(), NtlmState::None);
    }

    #[test]
    fn input_restarts_from_last() {
        let mut hs = NtlmHandshake::new();
        hs.state = NtlmState::Last;
        hs.data.target_info = vec![1, 2, 3];
        hs.input("NTLM").expect("restart");
        assert_eq!(hs.state(), NtlmState::Type1);
        assert!(hs.data.target_info.is_empty());
    }
}
