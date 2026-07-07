// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! SCRAM-SHA-1 (RFC 5802) and SCRAM-SHA-256 (RFC 7677) SASL client mechanisms.
//!
//! # Provenance
//!
//! In curl 8.19.0-DEV the SCRAM family is **not** implemented in-tree: it is
//! delegated wholesale to the external **libgsasl** C library, driven through a
//! thin wrapper (`lib/vauth/gsasl.c`) whose [`Curl_auth_gsasl_token`] pumps
//! `gsasl_step()` and returns the raw response bytes, while the mechanism names
//! `"SCRAM-SHA-1"` and `"SCRAM-SHA-256"` are registered in the SASL mechanism
//! table (`lib/curl_sasl.c`). Because the Rust rewrite eliminates all C-library
//! linkage, this module reimplements the **client side** of SCRAM in pure Rust,
//! directly from RFC 5802 and RFC 7677. The two C files remain the
//! source-of-truth for the *wiring* (what the SASL engine feeds in and expects
//! back); the RFCs are the source-of-truth for the *algorithm*.
//!
//! # Driving model
//!
//! [`ScramClient::step`] mirrors the `SASL_GSASL` state in `lib/curl_sasl.c`,
//! which repeatedly calls `Curl_auth_gsasl_token(challenge) -> response` until
//! the response is empty:
//!
//! 1. An empty initial challenge produces the **client-first** message.
//! 2. The **server-first** message produces the **client-final** message
//!    (carrying the client proof).
//! 3. The **server-final** message is verified against the locally computed
//!    `ServerSignature`, and an empty response terminates the exchange.
//!
//! Every step returns the **raw** message bytes; the SASL layer (`sasl.rs`)
//! owns Base64 transport encoding (curl's `SASL_FLAG_BASE64`), exactly as the C
//! gsasl wrapper returned the raw `response` for the SASL layer to encode.
//!
//! # Security notes
//!
//! * The `ServerSignature` check in [`ScramClient::verify_server_final`] uses a
//!   constant-time comparison so a mismatch cannot be timed.
//! * Passwords are used as UTF-8 bytes; full SASLprep (RFC 4013) normalization
//!   is intentionally **not** applied, matching pragmatic SCRAM client behavior
//!   (and the RFC test vectors, which use ASCII credentials). The username is
//!   `saslname`-escaped per RFC 5802 §5.1.
//! * This module contains **zero** `unsafe` code (the crate root sets
//!   `#![forbid(unsafe_code)]`); all cryptography is provided by pure-Rust
//!   RustCrypto crates.

// DEP NOTE: SCRAM-SHA-1 requires the `sha1` crate to be added to
// curl-rs-lib/Cargo.toml (workspace dep). It was not listed in the original
// dependency inventory (§0.5.1), which enumerated `sha2` but not `sha1`; it has
// been added (root `[workspace.dependencies]` + this crate's `[dependencies]`)
// because SCRAM-SHA-1 cannot be implemented without SHA-1 and the folder spec
// mandates BOTH SCRAM-SHA-1 and SCRAM-SHA-256. `sha1` is the RustCrypto crate
// from the same `Digest` trait family as `sha2`.
//
// PBKDF2-HMAC implemented manually over `hmac` (no `pbkdf2` crate dependency):
// SCRAM's `Hi(str, salt, i)` is PBKDF2-HMAC with a derived-key length equal to
// the hash output length, i.e. exactly one output block, so the classic
// iterated `U_1 XOR U_2 XOR ... XOR U_i` construction is spelled out below to
// keep the dependency surface minimal (§0.5.1).

use std::fmt;

use crate::error::{CurlCode, Error, Result};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// The GS2 header for the non-channel-binding case: "no channel binding, no
/// authorization identity" (`gs2-cbind-flag = "n"`, empty authzid).
const GS2_HEADER: &str = "n,,";

/// Base64 of [`GS2_HEADER`] (`base64("n,,")`), used verbatim as the `c=` field
/// of the client-final message in the non-channel-binding case.
const GS2_HEADER_B64: &str = "biws";

/// The RFC 5802 constant hashed to derive the `ClientKey`.
const CLIENT_KEY_LABEL: &[u8] = b"Client Key";

/// The RFC 5802 constant hashed to derive the `ServerKey`.
const SERVER_KEY_LABEL: &[u8] = b"Server Key";

/// Length (in characters) of the randomly generated client nonce.
const CLIENT_NONCE_LEN: usize = 32;

/// Alphabet for the random client nonce. All characters are printable ASCII and
/// none is `,` (the SASL attribute separator), so the value is a valid SCRAM
/// `printable` nonce token.
const NONCE_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// A hash primitive: `H(data) -> digest`.
type HashFn = fn(&[u8]) -> Vec<u8>;

/// An HMAC primitive: `HMAC(key, msg) -> mac`.
type HmacFn = fn(&[u8], &[u8]) -> Vec<u8>;

/// The SCRAM hash variant, selecting both the underlying hash function and the
/// advertised SASL mechanism name.
///
/// SCRAM-SHA-1 and SCRAM-SHA-256 are the *same* algorithm parameterized by a
/// different hash; this enum is the single selector that drives that
/// parameterization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScramHash {
    /// SCRAM-SHA-1 (RFC 5802), backed by SHA-1 (20-byte digest).
    Sha1,
    /// SCRAM-SHA-256 (RFC 7677), backed by SHA-256 (32-byte digest).
    Sha256,
}

impl ScramHash {
    /// The SASL mechanism name exactly as registered in curl's mechanism table
    /// (`lib/curl_sasl.c`): `"SCRAM-SHA-1"` or `"SCRAM-SHA-256"`.
    #[must_use]
    pub fn mech_name(&self) -> &'static str {
        match self {
            ScramHash::Sha1 => "SCRAM-SHA-1",
            ScramHash::Sha256 => "SCRAM-SHA-256",
        }
    }

    /// The output length, in bytes, of the underlying hash (20 for SHA-1, 32 for
    /// SHA-256).
    #[must_use]
    pub fn digest_len(&self) -> usize {
        match self {
            ScramHash::Sha1 => 20,
            ScramHash::Sha256 => 32,
        }
    }

    /// Returns the concrete `(hash, hmac)` primitive pair for this variant.
    ///
    /// The pair is passed to the hash-agnostic core routines
    /// ([`scram_proof`], [`pbkdf2_hmac`]) so the SCRAM algorithm is written
    /// exactly once regardless of the selected hash.
    fn crypto(self) -> (HashFn, HmacFn) {
        match self {
            ScramHash::Sha1 => (sha1_digest, sha1_hmac),
            ScramHash::Sha256 => (sha256_digest, sha256_hmac),
        }
    }
}

// ---------------------------------------------------------------------------
// Concrete cryptographic primitives
//
// RustCrypto's `Sha1`/`Sha256` and `Hmac<Sha1>`/`Hmac<Sha256>` are distinct
// concrete types with intricate generic bounds, so each hash gets a pair of
// thin byte-in/byte-out wrappers. Everything above these wrappers is hash-
// agnostic and shared, so the SCRAM algorithm itself is never duplicated.
// ---------------------------------------------------------------------------

/// SHA-1 digest of `data`.
fn sha1_digest(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().as_slice().to_vec()
}

/// HMAC-SHA-1 of `msg` under `key`.
fn sha1_hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    // HMAC accepts a key of any length, so `new_from_slice` cannot fail here.
    let mut mac = <Hmac<Sha1>>::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(msg);
    mac.finalize().into_bytes().as_slice().to_vec()
}

/// SHA-256 digest of `data`.
fn sha256_digest(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().as_slice().to_vec()
}

/// HMAC-SHA-256 of `msg` under `key`.
fn sha256_hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(msg);
    mac.finalize().into_bytes().as_slice().to_vec()
}

// ---------------------------------------------------------------------------
// Hash-agnostic SCRAM core
// ---------------------------------------------------------------------------

/// `Hi(str, salt, i)` from RFC 5802 §2.2 — PBKDF2-HMAC with the derived-key
/// length fixed to the hash output length (a single PBKDF2 block).
///
/// Implemented manually over the supplied HMAC primitive (no `pbkdf2` crate):
/// `U_1 = HMAC(str, salt || INT(1))`, `U_n = HMAC(str, U_{n-1})`, and the result
/// is `U_1 XOR U_2 XOR ... XOR U_i`.
fn pbkdf2_hmac(hmac: HmacFn, password: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    // Block index 1 as a 32-bit big-endian integer, appended to the salt.
    let mut salted_input = Vec::with_capacity(salt.len() + 4);
    salted_input.extend_from_slice(salt);
    salted_input.extend_from_slice(&1u32.to_be_bytes());

    let mut u = hmac(password, &salted_input); // U_1
    let mut result = u.clone();
    for _ in 1..iterations {
        u = hmac(password, &u); // U_n = HMAC(str, U_{n-1})
        for (acc, byte) in result.iter_mut().zip(u.iter()) {
            *acc ^= *byte;
        }
    }
    result
}

/// Computes `(ClientProof, ServerSignature)` for the given credentials and
/// `AuthMessage`, following RFC 5802 §3.
///
/// * `SaltedPassword = Hi(password, salt, i)`
/// * `ClientKey      = HMAC(SaltedPassword, "Client Key")`
/// * `StoredKey      = H(ClientKey)`
/// * `ClientSignature = HMAC(StoredKey, AuthMessage)`
/// * `ClientProof    = ClientKey XOR ClientSignature`
/// * `ServerKey      = HMAC(SaltedPassword, "Server Key")`
/// * `ServerSignature = HMAC(ServerKey, AuthMessage)`
fn scram_proof(
    hash: HashFn,
    hmac: HmacFn,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    auth_message: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let salted_password = pbkdf2_hmac(hmac, password, salt, iterations);
    let client_key = hmac(&salted_password, CLIENT_KEY_LABEL);
    let stored_key = hash(&client_key);
    let client_signature = hmac(&stored_key, auth_message);
    let client_proof = xor(&client_key, &client_signature);
    let server_key = hmac(&salted_password, SERVER_KEY_LABEL);
    let server_signature = hmac(&server_key, auth_message);
    (client_proof, server_signature)
}

/// Byte-wise XOR of two equal-length slices (the shorter length wins if they
/// differ, which never happens for the equal-length hash outputs used here).
fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// Constant-time equality for two byte slices.
///
/// The length comparison short-circuits (lengths are public — they are fixed
/// hash-output sizes), but the content comparison accumulates all byte diffs so
/// its timing does not depend on where a mismatch occurs.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// `saslname` escaping for the `n=` (username) field per RFC 5802 §5.1.
///
/// `'='` must be escaped **before** `','`, otherwise the `'='` introduced by the
/// `"=2C"` escape would itself be re-escaped into `"=3D2C"`.
fn escape_saslname(name: &str) -> String {
    name.replace('=', "=3D").replace(',', "=2C")
}

/// Generates a random printable-ASCII client nonce of [`CLIENT_NONCE_LEN`]
/// characters drawn from [`NONCE_ALPHABET`].
fn generate_nonce() -> String {
    let mut rng = rand::thread_rng();
    (0..CLIENT_NONCE_LEN)
        .map(|_| char::from(NONCE_ALPHABET[rng.gen_range(0..NONCE_ALPHABET.len())]))
        .collect()
}

/// The parsed, validated fields of a SCRAM server-first-message.
struct ServerFirst {
    /// The combined (client + server) nonce echoed by the server.
    combined_nonce: String,
    /// The decoded per-user salt.
    salt: Vec<u8>,
    /// The PBKDF2 iteration count.
    iterations: u32,
}

/// Parses and validates a SCRAM server-first-message
/// (`r=<nonce>,s=<base64 salt>,i=<iterations>`, optionally with extensions).
///
/// Every malformed input — a field without `=`, a missing `r`/`s`/`i`, a server
/// nonce that does not extend the client nonce, an invalid Base64 salt, a
/// non-numeric or zero iteration count, or an unsupported mandatory extension
/// (`m=`) — maps to [`CurlCode::BadContentEncoding`], mirroring the
/// `CURLE_BAD_CONTENT_ENCODING` that libgsasl returned from a bad `gsasl_step`.
fn parse_server_first(message: &str, client_nonce: &str) -> Result<ServerFirst> {
    let mut combined_nonce: Option<&str> = None;
    let mut salt_b64: Option<&str> = None;
    let mut iterations_str: Option<&str> = None;

    for field in message.split(',') {
        let (key, value) = field.split_once('=').ok_or_else(|| {
            Error::bad_content_encoding("SCRAM: malformed server-first-message attribute")
        })?;
        match key {
            "r" => combined_nonce = Some(value),
            "s" => salt_b64 = Some(value),
            "i" => iterations_str = Some(value),
            // A mandatory extension the client does not understand => abort
            // (RFC 5802 §7 `reserved-mext`).
            "m" => {
                return Err(Error::bad_content_encoding(
                    "SCRAM: unsupported mandatory extension in server-first-message",
                ))
            }
            // Ignore other/optional extension attributes.
            _ => {}
        }
    }

    let combined_nonce = combined_nonce.ok_or_else(|| {
        Error::bad_content_encoding("SCRAM: server-first-message missing r= (nonce)")
    })?;
    let salt_b64 = salt_b64.ok_or_else(|| {
        Error::bad_content_encoding("SCRAM: server-first-message missing s= (salt)")
    })?;
    let iterations_str = iterations_str.ok_or_else(|| {
        Error::bad_content_encoding("SCRAM: server-first-message missing i= (iteration count)")
    })?;

    // The server nonce MUST begin with the full client nonce we sent.
    if !combined_nonce.starts_with(client_nonce) {
        return Err(Error::bad_content_encoding(
            "SCRAM: server nonce does not extend the client nonce",
        ));
    }

    let salt = BASE64
        .decode(salt_b64)
        .map_err(|e| Error::bad_content_encoding(format!("SCRAM: invalid base64 salt: {e}")))?;

    let iterations: u32 = iterations_str
        .parse()
        .map_err(|_| Error::bad_content_encoding("SCRAM: invalid iteration count"))?;
    if iterations == 0 {
        return Err(Error::bad_content_encoding(
            "SCRAM: iteration count must be a positive integer",
        ));
    }

    Ok(ServerFirst {
        combined_nonce: combined_nonce.to_string(),
        salt,
        iterations,
    })
}

/// Progression of the SCRAM message exchange, enforcing the correct sequence of
/// [`ScramClient::step`] calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScramState {
    /// No message has been produced yet; the next step emits client-first.
    Initial,
    /// client-first has been sent; the next step consumes server-first.
    ClientFirstSent,
    /// client-final has been sent; the next step verifies server-final.
    ClientFinalSent,
    /// The exchange has completed successfully.
    Done,
}

/// A SCRAM (RFC 5802 / RFC 7677) SASL **client** state machine.
///
/// Construct one with [`ScramClient::new`] (random nonce) or
/// [`ScramClient::with_nonce`] (fixed nonce, for deterministic/wire-parity
/// testing), then drive it with [`ScramClient::step`], feeding each server
/// message and transmitting each returned response until the response is empty.
pub struct ScramClient {
    /// The selected hash / mechanism.
    hash: ScramHash,
    /// The authentication identity (username).
    username: String,
    /// The password (used as UTF-8 bytes; see the module security notes).
    password: String,
    /// The client-generated nonce (`r=` in client-first).
    client_nonce: String,
    /// Saved `client-first-message-bare` (`n=...,r=...`) for the AuthMessage.
    client_first_bare: String,
    /// Saved server-first-message (raw) for the AuthMessage.
    server_first: String,
    /// The locally computed `ServerSignature`, checked against server-final.
    server_signature: Vec<u8>,
    /// Current position in the exchange.
    state: ScramState,
}

impl fmt::Debug for ScramClient {
    /// Redacts the password so credentials never leak through debug output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScramClient")
            .field("hash", &self.hash)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("client_nonce", &self.client_nonce)
            .field("state", &self.state)
            .finish()
    }
}

impl ScramClient {
    /// Creates a SCRAM client with a freshly generated random client nonce.
    pub fn new(hash: ScramHash, username: impl Into<String>, password: impl Into<String>) -> Self {
        Self::with_nonce(hash, username, password, generate_nonce())
    }

    /// Creates a SCRAM client with a caller-supplied fixed client nonce.
    ///
    /// This is the nonce-injection seam that makes the message exchange
    /// deterministic; it is used to reproduce the RFC 5802 / RFC 7677 test
    /// vectors byte-for-byte. Production code should prefer [`ScramClient::new`],
    /// which generates a cryptographically random nonce.
    pub fn with_nonce(
        hash: ScramHash,
        username: impl Into<String>,
        password: impl Into<String>,
        client_nonce: impl Into<String>,
    ) -> Self {
        ScramClient {
            hash,
            username: username.into(),
            password: password.into(),
            client_nonce: client_nonce.into(),
            client_first_bare: String::new(),
            server_first: String::new(),
            server_signature: Vec::new(),
            state: ScramState::Initial,
        }
    }

    /// Advances the SCRAM exchange by one round.
    ///
    /// Mirrors the `SASL_GSASL` pump in `lib/curl_sasl.c`: feed the latest
    /// server message (empty on the first call) and transmit the returned bytes;
    /// an empty return value signals the exchange is complete.
    ///
    /// * **Initial** — ignores the (empty) input and returns the client-first
    ///   message.
    /// * **ClientFirstSent** — parses the server-first message and returns the
    ///   client-final message (client proof).
    /// * **ClientFinalSent** — verifies the server-final message and returns an
    ///   empty response.
    /// * **Done** — any further call is a protocol misuse and returns an error.
    ///
    /// # Errors
    ///
    /// Returns [`CurlCode::BadContentEncoding`] for a malformed server message,
    /// [`CurlCode::LoginDenied`] if the server signature does not verify or the
    /// server reports an error, and [`CurlCode::AuthError`] if called after the
    /// exchange has already completed.
    pub fn step(&mut self, server_message: &[u8]) -> Result<Vec<u8>> {
        match self.state {
            ScramState::Initial => {
                let response = self.client_first();
                self.state = ScramState::ClientFirstSent;
                Ok(response)
            }
            ScramState::ClientFirstSent => {
                let response = self.client_final(server_message)?;
                self.state = ScramState::ClientFinalSent;
                Ok(response)
            }
            ScramState::ClientFinalSent => {
                self.verify_server_final(server_message)?;
                self.state = ScramState::Done;
                Ok(Vec::new())
            }
            ScramState::Done => Err(Error::auth(
                "SCRAM: step() called after the exchange completed",
            )),
        }
    }

    /// Builds the client-first message and records `client-first-bare`.
    ///
    /// `gs2-header || "n=" saslname(user) "," "r=" cnonce`, e.g.
    /// `n,,n=user,r=<cnonce>`.
    fn client_first(&mut self) -> Vec<u8> {
        let user_escaped = escape_saslname(&self.username);
        self.client_first_bare = format!("n={user_escaped},r={}", self.client_nonce);
        format!("{GS2_HEADER}{}", self.client_first_bare).into_bytes()
    }

    /// Parses the server-first message and builds the client-final message,
    /// computing and storing the `ServerSignature` for later verification.
    fn client_final(&mut self, server_message: &[u8]) -> Result<Vec<u8>> {
        let server_first = std::str::from_utf8(server_message).map_err(|_| {
            Error::bad_content_encoding("SCRAM: server-first-message is not valid UTF-8")
        })?;
        let parsed = parse_server_first(server_first, &self.client_nonce)?;

        // Remember the exact bytes received; they feed the AuthMessage verbatim.
        self.server_first = server_first.to_string();

        // client-final-message-without-proof = "c=biws,r=<combined nonce>".
        let client_final_without_proof = format!("c={GS2_HEADER_B64},r={}", parsed.combined_nonce);

        // AuthMessage = client-first-bare "," server-first "," client-final-
        // without-proof  (RFC 5802 §3).
        let auth_message = format!(
            "{},{},{}",
            self.client_first_bare, self.server_first, client_final_without_proof
        );

        let (hash, hmac) = self.hash.crypto();
        let (client_proof, server_signature) = scram_proof(
            hash,
            hmac,
            self.password.as_bytes(),
            &parsed.salt,
            parsed.iterations,
            auth_message.as_bytes(),
        );

        // Store ServerSignature so server-final can be verified in Phase E.
        self.server_signature = server_signature;

        let proof_b64 = BASE64.encode(client_proof);
        Ok(format!("{client_final_without_proof},p={proof_b64}").into_bytes())
    }

    /// Verifies the server-final message against the stored `ServerSignature`.
    ///
    /// Accepts either `v=<base64 ServerSignature>` (verifier) or `e=<reason>`
    /// (server error). Any trailing `,`-separated extensions after the primary
    /// field are ignored.
    fn verify_server_final(&self, server_message: &[u8]) -> Result<()> {
        let message = std::str::from_utf8(server_message).map_err(|_| {
            Error::bad_content_encoding("SCRAM: server-final-message is not valid UTF-8")
        })?;

        // server-final-message = (verifier / server-error) ["," extensions].
        let primary = message.split(',').next().unwrap_or(message);

        // A server-error ("e=...") means authentication was rejected.
        if let Some(reason) = primary.strip_prefix("e=") {
            return Err(Error::with_context(
                CurlCode::LoginDenied,
                format!("SCRAM server rejected authentication: {reason}"),
            ));
        }

        let verifier_b64 = primary.strip_prefix("v=").ok_or_else(|| {
            Error::bad_content_encoding("SCRAM: malformed server-final-message (expected v= or e=)")
        })?;
        let server_signature = BASE64.decode(verifier_b64).map_err(|e| {
            Error::bad_content_encoding(format!("SCRAM: invalid base64 server signature: {e}"))
        })?;

        // Constant-time comparison against the locally computed ServerSignature.
        if constant_time_eq(&server_signature, &self.server_signature) {
            Ok(())
        } else {
            Err(Error::LoginDenied)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5802 §5 — the complete SCRAM-SHA-1 example exchange
    /// (username `user`, password `pencil`, `i=4096`), driven through the full
    /// three-step [`ScramClient::step`] state machine.
    #[test]
    fn rfc5802_scram_sha1_full_exchange() {
        let mut client = ScramClient::with_nonce(
            ScramHash::Sha1,
            "user",
            "pencil",
            "fyko+d2lbbFgONRv9qkxdawL",
        );

        // Step 1: empty input -> client-first message.
        let client_first = client.step(b"").unwrap();
        assert_eq!(
            client_first,
            b"n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL".to_vec()
        );

        // Step 2: server-first -> client-final (with the RFC's exact proof).
        let server_first =
            b"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096";
        let client_final = client.step(server_first).unwrap();
        assert_eq!(
            std::str::from_utf8(&client_final).unwrap(),
            "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,\
             p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts="
        );

        // Step 3: server-final -> verified, empty response.
        let server_final = b"v=rmF9pqV8S7suAoZWja4dJRkFsKQ=";
        assert!(client.step(server_final).unwrap().is_empty());
    }

    /// RFC 7677 §3 — the complete SCRAM-SHA-256 example exchange.
    #[test]
    fn rfc7677_scram_sha256_full_exchange() {
        let mut client =
            ScramClient::with_nonce(ScramHash::Sha256, "user", "pencil", "rOprNGfwEbeRWgbNEkqO");

        let client_first = client.step(b"").unwrap();
        assert_eq!(client_first, b"n,,n=user,r=rOprNGfwEbeRWgbNEkqO".to_vec());

        let server_first = b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
                             s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        let client_final = client.step(server_first).unwrap();
        assert_eq!(
            std::str::from_utf8(&client_final).unwrap(),
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
             p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );

        let server_final = b"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";
        assert!(client.step(server_final).unwrap().is_empty());
    }

    #[test]
    fn mech_name_and_digest_len_match_the_spec() {
        assert_eq!(ScramHash::Sha1.mech_name(), "SCRAM-SHA-1");
        assert_eq!(ScramHash::Sha256.mech_name(), "SCRAM-SHA-256");
        assert_eq!(ScramHash::Sha1.digest_len(), 20);
        assert_eq!(ScramHash::Sha256.digest_len(), 32);
    }

    #[test]
    fn gs2_header_base64_constant_is_biws() {
        // `c=biws` is a hard-coded constant only because it equals base64("n,,").
        assert_eq!(BASE64.encode(GS2_HEADER.as_bytes()), GS2_HEADER_B64);
    }

    #[test]
    fn saslname_escaping_is_rfc_correct() {
        assert_eq!(escape_saslname("user"), "user");
        assert_eq!(escape_saslname("a,b"), "a=2Cb");
        assert_eq!(escape_saslname("a=b"), "a=3Db");
        // '=' escaped before ',' so the '=' inside "=2C" is not itself escaped.
        assert_eq!(escape_saslname("=,"), "=3D=2C");
        assert_eq!(escape_saslname("us,er=name"), "us=2Cer=3Dname");
    }

    #[test]
    fn username_with_special_characters_is_escaped_in_client_first() {
        let mut client = ScramClient::with_nonce(ScramHash::Sha256, "a,b=c", "pw", "NONCE");
        let client_first = client.step(b"").unwrap();
        assert_eq!(
            std::str::from_utf8(&client_first).unwrap(),
            "n,,n=a=2Cb=3Dc,r=NONCE"
        );
    }

    #[test]
    fn generated_nonce_is_valid_and_unique() {
        let a = ScramClient::new(ScramHash::Sha256, "u", "p");
        let b = ScramClient::new(ScramHash::Sha256, "u", "p");
        assert_eq!(a.client_nonce.len(), CLIENT_NONCE_LEN);
        assert!(a
            .client_nonce
            .bytes()
            .all(|byte| NONCE_ALPHABET.contains(&byte)));
        // Two independent nonces essentially never collide.
        assert_ne!(a.client_nonce, b.client_nonce);
    }

    #[test]
    fn pbkdf2_hmac_matches_a_known_vector() {
        // The RFC 5802 SaltedPassword for ("pencil", base64("QSXCR+Q6sek8bf92"),
        // 4096) is well-known; verify the manual PBKDF2 against it.
        let salt = BASE64.decode("QSXCR+Q6sek8bf92").unwrap();
        let salted = pbkdf2_hmac(sha1_hmac, b"pencil", &salt, 4096);
        assert_eq!(
            salted,
            vec![
                0x1d, 0x96, 0xee, 0x3a, 0x52, 0x9b, 0x5a, 0x5f, 0x9e, 0x47, 0xc0, 0x1f, 0x22, 0x9a,
                0x2c, 0xb8, 0xa6, 0xe1, 0x5f, 0x7d,
            ]
        );
    }

    #[test]
    fn constant_time_eq_behaves_like_equality() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    /// A server nonce that does not begin with the client nonce is rejected as
    /// `CURLE_BAD_CONTENT_ENCODING`.
    #[test]
    fn server_nonce_mismatch_is_rejected() {
        let mut client = ScramClient::with_nonce(ScramHash::Sha1, "user", "pencil", "clientnonce");
        client.step(b"").unwrap();
        let err = client
            .step(b"r=WRONGprefix,s=QSXCR+Q6sek8bf92,i=4096")
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::BadContentEncoding);
    }

    /// Every flavor of malformed server-first message maps to
    /// `CURLE_BAD_CONTENT_ENCODING`.
    #[test]
    fn malformed_server_first_messages_are_rejected() {
        let cases: &[&[u8]] = &[
            b"s=QSXCR+Q6sek8bf92,i=4096",                            // missing r=
            b"r=clientnonceX,i=4096",                                // missing s=
            b"r=clientnonceX,s=QSXCR+Q6sek8bf92",                    // missing i=
            b"r=clientnonceX,s=!!not-base64!!,i=4096",               // invalid base64 salt
            b"r=clientnonceX,s=QSXCR+Q6sek8bf92,i=notanint",         // non-numeric i
            b"r=clientnonceX,s=QSXCR+Q6sek8bf92,i=0",                // zero iteration count
            b"m=mandatory,r=clientnonceX,s=QSXCR+Q6sek8bf92,i=4096", // unknown mandatory ext
            b"noequalsign",                                          // attribute without '='
        ];
        for case in cases {
            let mut client =
                ScramClient::with_nonce(ScramHash::Sha1, "user", "pencil", "clientnonce");
            client.step(b"").unwrap();
            let err = client.step(case).unwrap_err();
            assert_eq!(
                err.code(),
                CurlCode::BadContentEncoding,
                "case {:?} should be BadContentEncoding",
                std::str::from_utf8(case)
            );
        }
    }

    /// A wrong `ServerSignature` denies the login (`CURLE_LOGIN_DENIED`).
    #[test]
    fn server_signature_mismatch_denies_login() {
        let mut client = ScramClient::with_nonce(
            ScramHash::Sha1,
            "user",
            "pencil",
            "fyko+d2lbbFgONRv9qkxdawL",
        );
        client.step(b"").unwrap();
        client
            .step(b"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096")
            .unwrap();
        // A syntactically valid but incorrect signature (20 zero bytes).
        let wrong = format!("v={}", BASE64.encode([0u8; 20]));
        let err = client.step(wrong.as_bytes()).unwrap_err();
        assert_eq!(err.code(), CurlCode::LoginDenied);
    }

    /// A server-error (`e=`) in the final message denies the login.
    #[test]
    fn server_error_message_denies_login() {
        let mut client = ScramClient::with_nonce(
            ScramHash::Sha1,
            "user",
            "pencil",
            "fyko+d2lbbFgONRv9qkxdawL",
        );
        client.step(b"").unwrap();
        client
            .step(b"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096")
            .unwrap();
        let err = client.step(b"e=invalid-proof").unwrap_err();
        assert_eq!(err.code(), CurlCode::LoginDenied);
    }

    /// A malformed server-final (neither `v=` nor `e=`) is bad content encoding.
    #[test]
    fn malformed_server_final_is_rejected() {
        let mut client = ScramClient::with_nonce(
            ScramHash::Sha1,
            "user",
            "pencil",
            "fyko+d2lbbFgONRv9qkxdawL",
        );
        client.step(b"").unwrap();
        client
            .step(b"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096")
            .unwrap();
        let err = client.step(b"garbage").unwrap_err();
        assert_eq!(err.code(), CurlCode::BadContentEncoding);
    }

    /// Trailing extensions after the verifier are ignored.
    #[test]
    fn server_final_with_trailing_extension_verifies() {
        let mut client = ScramClient::with_nonce(
            ScramHash::Sha1,
            "user",
            "pencil",
            "fyko+d2lbbFgONRv9qkxdawL",
        );
        client.step(b"").unwrap();
        client
            .step(b"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096")
            .unwrap();
        let out = client
            .step(b"v=rmF9pqV8S7suAoZWja4dJRkFsKQ=,extra=ignored")
            .unwrap();
        assert!(out.is_empty());
    }

    /// Calling `step` after the exchange completed is a protocol misuse and
    /// surfaces as `CURLE_AUTH_ERROR`.
    #[test]
    fn step_after_completion_is_an_auth_error() {
        let mut client = ScramClient::with_nonce(
            ScramHash::Sha1,
            "user",
            "pencil",
            "fyko+d2lbbFgONRv9qkxdawL",
        );
        client.step(b"").unwrap();
        client
            .step(b"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096")
            .unwrap();
        client.step(b"v=rmF9pqV8S7suAoZWja4dJRkFsKQ=").unwrap();
        let err = client.step(b"").unwrap_err();
        assert_eq!(err.code(), CurlCode::AuthError);
    }

    /// The redacting `Debug` impl must never print the password.
    #[test]
    fn debug_impl_redacts_password() {
        let client = ScramClient::with_nonce(ScramHash::Sha256, "user", "s3cr3t", "NONCE");
        let rendered = format!("{client:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("s3cr3t"));
    }
}
