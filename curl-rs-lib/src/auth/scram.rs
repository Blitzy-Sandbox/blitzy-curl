//! SCRAM authentication (RFC 5802) — SCRAM-SHA-1 and SCRAM-SHA-256.
//!
//! Pure-Rust implementation of the Salted Challenge Response Authentication
//! Mechanism (SCRAM) as defined in RFC 5802 (SCRAM-SHA-1) and RFC 7677
//! (SCRAM-SHA-256). Replaces the C GSASL library dependency
//! (`lib/vauth/gsasl.c`) with a zero-`unsafe`, pure-Rust implementation.
//!
//! # Protocol Overview
//!
//! SCRAM is a SASL mechanism that provides mutual authentication via a
//! password-based challenge-response exchange:
//!
//! 1. **Client-first**: client sends username + random nonce
//! 2. **Server-first**: server responds with combined nonce, salt, iteration count
//! 3. **Client-final**: client derives salted password via PBKDF2, computes
//!    proof, sends it along with channel-binding data
//! 4. **Server-final**: server responds with its own signature for mutual auth
//!
//! # C Correspondence
//!
//! | Rust                       | C                                  |
//! |----------------------------|------------------------------------|
//! | `ScramData`                | `struct gsasldata`                 |
//! | `ScramMechanism`           | implicit in `gsasl_client_start`   |
//! | `is_scram_supported()`     | `Curl_auth_gsasl_is_supported()`   |
//! | `start()`                  | `Curl_auth_gsasl_start()`          |
//! | `token()`                  | `Curl_auth_gsasl_token()`          |
//! | `process_server_first()`   | internal `gsasl_step()` step 1     |
//! | `process_server_final()`   | internal `gsasl_step()` step 2     |
//! | `ScramData::cleanup()`     | `Curl_auth_gsasl_cleanup()`        |

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::error::CurlError;
use crate::util::base64;
use crate::util::rand;

// ---------------------------------------------------------------------------
// Type aliases for HMAC variants used throughout the module.
// ---------------------------------------------------------------------------

/// HMAC-SHA-256 type alias used in SCRAM-SHA-256 operations.
type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA-1 type alias used in SCRAM-SHA-1 operations.
type HmacSha1 = Hmac<Sha1>;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// GS2 header for "no channel binding" — the standard prefix for SCRAM
/// client-first messages when channel binding is not in use.
const GS2_HEADER: &str = "n,,";

/// Base64-encoded GS2 header ("n,,") — always "biws" per RFC 5802.
/// Used in the client-final message `c=` attribute.
const GS2_HEADER_BASE64: &str = "biws";

/// Minimum PBKDF2 iteration count per RFC 5802 §5.1.
/// Servers MUST specify at least 4096 iterations.
const MIN_ITERATION_COUNT: u32 = 4096;

/// Maximum PBKDF2 iteration count to prevent denial-of-service.
/// 10 million iterations is far beyond any legitimate server requirement.
const MAX_ITERATION_COUNT: u32 = 10_000_000;

/// Number of random bytes to generate for the client nonce.
/// 24 bytes yields 32 base64 characters — sufficient entropy for SCRAM.
const NONCE_BYTE_LENGTH: usize = 24;

// ---------------------------------------------------------------------------
// ScramMechanism
// ---------------------------------------------------------------------------

/// Identifies which SCRAM variant is in use.
///
/// Determines the hash function and HMAC variant for PBKDF2 key derivation,
/// `ClientKey`, `StoredKey`, `ClientSignature`, and `ServerSignature` steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScramMechanism {
    /// SCRAM-SHA-1 as defined in RFC 5802.
    /// Uses SHA-1 (20-byte digest) and HMAC-SHA-1.
    Sha1,

    /// SCRAM-SHA-256 as defined in RFC 7677.
    /// Uses SHA-256 (32-byte digest) and HMAC-SHA-256.
    Sha256,
}

impl ScramMechanism {
    /// Returns the SASL mechanism name string (e.g. `"SCRAM-SHA-256"`).
    ///
    /// Used by callers to advertise the mechanism during SASL negotiation.
    pub fn name(&self) -> &'static str {
        match self {
            ScramMechanism::Sha1 => "SCRAM-SHA-1",
            ScramMechanism::Sha256 => "SCRAM-SHA-256",
        }
    }

    /// Returns the hash output length in bytes for this mechanism.
    ///
    /// SHA-1 produces 20 bytes; SHA-256 produces 32 bytes.
    pub fn hash_len(&self) -> usize {
        match self {
            ScramMechanism::Sha1 => 20,
            ScramMechanism::Sha256 => 32,
        }
    }
}

// ---------------------------------------------------------------------------
// ScramStep
// ---------------------------------------------------------------------------

/// Tracks the current state of the SCRAM authentication exchange.
///
/// The exchange proceeds linearly through four states:
/// `Initial` → `ServerFirstReceived` → `ServerFinalReceived` → `Complete`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScramStep {
    /// Initial state — `start()` has been called, client-first message sent.
    Initial,

    /// The server's first challenge has been received and parsed.
    /// The client-final message has been sent.
    ServerFirstReceived,

    /// The server's final response has been received.
    /// Awaiting verification.
    ServerFinalReceived,

    /// Authentication is complete — server signature verified successfully.
    Complete,
}

// ---------------------------------------------------------------------------
// ScramData
// ---------------------------------------------------------------------------

/// Persistent state for a SCRAM authentication session.
///
/// Carries all data accumulated across the multi-step SCRAM exchange:
/// nonces, salt, derived keys, and the concatenated `AuthMessage` needed
/// for signature computation and verification.
///
/// # Lifecycle
///
/// 1. Construct via [`ScramData::new()`]
/// 2. Call [`start()`] to generate the client-first message
/// 3. Call [`process_server_first()`] (or [`token()`]) with the server's
///    first challenge to produce the client-final message
/// 4. Call [`process_server_final()`] (or [`token()`]) with the server's
///    final response to verify the server signature
/// 5. Call [`ScramData::cleanup()`] when finished
pub struct ScramData {
    /// Which SCRAM variant is in use (SHA-1 or SHA-256).
    pub mechanism: ScramMechanism,

    /// The random client nonce generated in `start()`, base64-encoded.
    pub client_nonce: Option<String>,

    /// The combined nonce received from the server (client nonce + server
    /// nonce extension). Must start with `client_nonce`.
    pub server_nonce: Option<String>,

    /// The salt received from the server, already base64-decoded to raw bytes.
    pub salt: Option<Vec<u8>>,

    /// The PBKDF2 iteration count received from the server.
    pub iteration_count: u32,

    /// The concatenated `AuthMessage` used for signing:
    /// `client-first-message-bare + "," + server-first-message + "," +
    ///  client-final-message-without-proof`.
    pub auth_message: Option<String>,

    /// The bare client-first message (without the GS2 header).
    /// Stored for inclusion in the `AuthMessage` computation.
    pub client_first_bare: Option<String>,

    /// The PBKDF2-derived salted password (`SaltedPassword = Hi(password,
    /// salt, i)`). Stored for `ServerSignature` computation in the final step.
    pub salted_password: Option<Vec<u8>>,

    /// Current step in the SCRAM exchange.
    pub step: ScramStep,

    /// The user's password, stored after `start()` for use in
    /// `process_server_first()` where key derivation occurs.
    password: Option<String>,
}

impl ScramData {
    /// Create a new SCRAM session for the given mechanism variant.
    ///
    /// All fields are initialized to their default/empty states. The session
    /// is ready for [`start()`] to be called.
    pub fn new(mechanism: ScramMechanism) -> Self {
        ScramData {
            mechanism,
            client_nonce: None,
            server_nonce: None,
            salt: None,
            iteration_count: 0,
            auth_message: None,
            client_first_bare: None,
            salted_password: None,
            step: ScramStep::Initial,
            password: None,
        }
    }

    /// Reset all session state, releasing any stored credentials and keys.
    ///
    /// Matches the C `Curl_auth_gsasl_cleanup()` function. After calling
    /// this method the `ScramData` instance can be reused for a new
    /// authentication exchange via another call to [`start()`].
    pub fn cleanup(&mut self) {
        self.client_nonce = None;
        self.server_nonce = None;
        self.salt = None;
        self.iteration_count = 0;
        self.auth_message = None;
        self.client_first_bare = None;
        self.salted_password = None;
        self.step = ScramStep::Initial;
        self.password = None;
    }
}

// ---------------------------------------------------------------------------
// Public API — Support Detection
// ---------------------------------------------------------------------------

/// Check whether the given SASL mechanism name is a supported SCRAM variant.
///
/// Matches the C `Curl_auth_gsasl_is_supported()` function which
/// initialized the GSASL library and attempted to start a client session
/// for the requested mechanism. In Rust, we simply check the mechanism
/// string against the two supported variants.
///
/// # Arguments
///
/// * `mechanism` — the SASL mechanism name, e.g. `"SCRAM-SHA-1"` or
///   `"SCRAM-SHA-256"`. The comparison is case-sensitive per SASL conventions.
///
/// # Returns
///
/// `true` if the mechanism is `"SCRAM-SHA-1"` or `"SCRAM-SHA-256"`.
pub fn is_scram_supported(mechanism: &str) -> bool {
    mechanism == "SCRAM-SHA-1" || mechanism == "SCRAM-SHA-256"
}

// ---------------------------------------------------------------------------
// Public API — Client-First Message
// ---------------------------------------------------------------------------

/// Generate the SCRAM client-first message and initialize the session.
///
/// Matches the C `Curl_auth_gsasl_start()` function. Generates a random
/// client nonce, constructs the `client-first-message` as specified in
/// RFC 5802 §7, and stores session state for subsequent steps.
///
/// # Client-First Message Format
///
/// ```text
/// gs2-header     = "n,,"          (no channel binding, no authzid)
/// client-first-bare = "n=" saslname ",r=" c-nonce
/// client-first-message = gs2-header client-first-bare
/// ```
///
/// # Arguments
///
/// * `user` — the authentication identity (username). Will have `=` and `,`
///   characters escaped per RFC 5802 §5.1 SASLprep requirements.
/// * `passwd` — the user's password, stored for PBKDF2 key derivation
///   in the next step.
/// * `scram` — mutable reference to the session state.
///
/// # Returns
///
/// The complete `client-first-message` as bytes, ready to be sent to the
/// server (typically after base64 encoding by the calling SASL framework).
///
/// # Errors
///
/// * [`CurlError::OutOfMemory`] — if random byte generation fails.
pub fn start(user: &str, passwd: &str, scram: &mut ScramData) -> Result<Vec<u8>, CurlError> {
    // Generate 24 random bytes for the client nonce.
    let mut nonce_bytes = [0u8; NONCE_BYTE_LENGTH];
    rand::random_bytes(&mut nonce_bytes)?;

    // Base64-encode the random bytes to produce a printable nonce string.
    let client_nonce = base64::encode(&nonce_bytes);
    scram.client_nonce = Some(client_nonce.clone());

    // Store the password for PBKDF2 derivation in process_server_first().
    scram.password = Some(passwd.to_owned());

    // SASLprep username normalization (minimal):
    // RFC 5802 §5.1 requires `=` → `=3D` and `,` → `=2C` in usernames.
    let sasl_user = saslprep_username(user);

    // Build client-first-message-bare: "n=<user>,r=<nonce>"
    let client_first_bare = format!("n={},r={}", sasl_user, client_nonce);
    scram.client_first_bare = Some(client_first_bare.clone());

    // Build full client-first-message: "n,,n=<user>,r=<nonce>"
    let client_first_message = format!("{}{}", GS2_HEADER, client_first_bare);

    scram.step = ScramStep::Initial;

    Ok(client_first_message.into_bytes())
}

// ---------------------------------------------------------------------------
// Public API — Process Server-First Challenge
// ---------------------------------------------------------------------------

/// Process the server's first challenge and produce the client-final message.
///
/// Parses the `server-first-message`, validates the nonce, derives the
/// `SaltedPassword` via PBKDF2, computes the `ClientProof`, and constructs
/// the `client-final-message` as specified in RFC 5802 §7.
///
/// # Server-First Message Format
///
/// ```text
/// server-first-message = [reserved "="] nonce "," salt "," iteration-count
///                       = "r=" nonce ",s=" base64(salt) ",i=" iteration-count
/// ```
///
/// # Client-Final Message Format
///
/// ```text
/// client-final-without-proof = "c=" base64(GS2-header) ",r=" nonce
/// client-final-message = client-final-without-proof ",p=" base64(ClientProof)
/// ```
///
/// # Arguments
///
/// * `challenge` — the raw bytes of the server-first-message.
/// * `scram` — mutable reference to the session state (must have been
///   initialized by [`start()`]).
///
/// # Returns
///
/// The complete `client-final-message` as bytes.
///
/// # Errors
///
/// * [`CurlError::BadContentEncoding`] — if the server-first-message is
///   malformed, the nonce is invalid, the salt cannot be decoded, or the
///   iteration count is out of range.
/// * [`CurlError::OutOfMemory`] — if HMAC initialization fails.
/// * [`CurlError::LoginDenied`] — if a server error (`e=`) attribute is
///   present in the challenge.
pub fn process_server_first(
    challenge: &[u8],
    scram: &mut ScramData,
) -> Result<Vec<u8>, CurlError> {
    let challenge_str =
        std::str::from_utf8(challenge).map_err(|_| CurlError::BadContentEncoding)?;

    // Parse the server-first-message attributes.
    let mut nonce: Option<&str> = None;
    let mut salt_b64: Option<&str> = None;
    let mut iteration_count: Option<u32> = None;

    for attr in challenge_str.split(',') {
        if let Some(value) = attr.strip_prefix("r=") {
            nonce = Some(value);
        } else if let Some(value) = attr.strip_prefix("s=") {
            salt_b64 = Some(value);
        } else if let Some(value) = attr.strip_prefix("i=") {
            iteration_count = Some(
                value
                    .parse::<u32>()
                    .map_err(|_| CurlError::BadContentEncoding)?,
            );
        } else if attr.starts_with("e=") {
            // Server error — authentication rejected.
            return Err(CurlError::LoginDenied);
        }
        // Ignore unknown attributes per RFC 5802 §7: "the client MUST
        // ignore any additional unknown attributes".
    }

    // All three required attributes must be present.
    let server_nonce = nonce.ok_or(CurlError::BadContentEncoding)?;
    let salt_b64 = salt_b64.ok_or(CurlError::BadContentEncoding)?;
    let iter_count = iteration_count.ok_or(CurlError::BadContentEncoding)?;

    // Validate: server nonce MUST start with our client nonce.
    let client_nonce = scram
        .client_nonce
        .as_deref()
        .ok_or(CurlError::BadContentEncoding)?;
    if !server_nonce.starts_with(client_nonce) {
        return Err(CurlError::BadContentEncoding);
    }

    // Validate iteration count bounds.
    if !(MIN_ITERATION_COUNT..=MAX_ITERATION_COUNT).contains(&iter_count) {
        return Err(CurlError::BadContentEncoding);
    }

    // Decode salt from base64.
    let salt = base64::decode(salt_b64)?;
    if salt.is_empty() {
        return Err(CurlError::BadContentEncoding);
    }

    // Store parsed values.
    scram.server_nonce = Some(server_nonce.to_owned());
    scram.salt = Some(salt.clone());
    scram.iteration_count = iter_count;

    // Retrieve the stored password.
    let password = scram
        .password
        .as_deref()
        .ok_or(CurlError::BadContentEncoding)?;

    // Compute SaltedPassword = Hi(password, salt, i) via PBKDF2.
    let salted_password = match scram.mechanism {
        ScramMechanism::Sha1 => pbkdf2_hmac_sha1(password.as_bytes(), &salt, iter_count)?,
        ScramMechanism::Sha256 => pbkdf2_hmac_sha256(password.as_bytes(), &salt, iter_count)?,
    };
    scram.salted_password = Some(salted_password.clone());

    // Compute ClientKey = HMAC(SaltedPassword, "Client Key")
    let client_key = match scram.mechanism {
        ScramMechanism::Sha1 => hmac_sha1(&salted_password, b"Client Key")?,
        ScramMechanism::Sha256 => hmac_sha256(&salted_password, b"Client Key")?,
    };

    // Compute StoredKey = Hash(ClientKey)
    let stored_key = match scram.mechanism {
        ScramMechanism::Sha1 => {
            let mut hasher = sha1::Sha1::new();
            Digest::update(&mut hasher, &client_key);
            hasher.finalize().to_vec()
        }
        ScramMechanism::Sha256 => {
            let mut hasher = Sha256::new();
            Digest::update(&mut hasher, &client_key);
            hasher.finalize().to_vec()
        }
    };

    // Build client-final-message-without-proof:
    //   "c=" base64(GS2-header) ",r=" nonce
    let client_final_without_proof =
        format!("c={},r={}", GS2_HEADER_BASE64, server_nonce);

    // Build AuthMessage:
    //   client-first-message-bare + "," + server-first-message + "," +
    //   client-final-message-without-proof
    let client_first_bare = scram
        .client_first_bare
        .as_deref()
        .ok_or(CurlError::BadContentEncoding)?;
    let auth_message = format!(
        "{},{},{}",
        client_first_bare, challenge_str, client_final_without_proof
    );
    scram.auth_message = Some(auth_message.clone());

    // Compute ClientSignature = HMAC(StoredKey, AuthMessage)
    let client_signature = match scram.mechanism {
        ScramMechanism::Sha1 => hmac_sha1(&stored_key, auth_message.as_bytes())?,
        ScramMechanism::Sha256 => hmac_sha256(&stored_key, auth_message.as_bytes())?,
    };

    // Compute ClientProof = ClientKey XOR ClientSignature
    let client_proof = xor_bytes(&client_key, &client_signature);

    // Base64-encode the ClientProof.
    let proof_b64 = base64::encode(&client_proof);

    // Build complete client-final-message:
    //   client-final-without-proof ",p=" base64(ClientProof)
    let client_final_message = format!("{},p={}", client_final_without_proof, proof_b64);

    scram.step = ScramStep::ServerFirstReceived;

    Ok(client_final_message.into_bytes())
}

// ---------------------------------------------------------------------------
// Public API — Process Server-Final Response
// ---------------------------------------------------------------------------

/// Verify the server's final response and complete the authentication.
///
/// Parses the `server-final-message`, computes the expected
/// `ServerSignature`, and verifies that it matches the server's claim.
/// This provides mutual authentication — the server proves that it
/// knows the correct password hash.
///
/// # Server-Final Message Format
///
/// ```text
/// server-final-message = "v=" base64(ServerSignature)
/// ```
///
/// # Arguments
///
/// * `response` — the raw bytes of the server-final-message.
/// * `scram` — mutable reference to the session state.
///
/// # Errors
///
/// * [`CurlError::BadContentEncoding`] — if the response is malformed
///   or cannot be parsed.
/// * [`CurlError::AuthError`] — if the server signature does not match
///   the expected value (server failed to prove identity).
/// * [`CurlError::LoginDenied`] — if the server sent an error attribute.
pub fn process_server_final(
    response: &[u8],
    scram: &mut ScramData,
) -> Result<(), CurlError> {
    let response_str =
        std::str::from_utf8(response).map_err(|_| CurlError::BadContentEncoding)?;

    // Check for server error attribute.
    if response_str.starts_with("e=") {
        return Err(CurlError::LoginDenied);
    }

    // Parse server signature: "v=<base64>"
    let server_sig_b64 = response_str
        .strip_prefix("v=")
        .ok_or(CurlError::BadContentEncoding)?;

    let received_signature = base64::decode(server_sig_b64)?;

    // Retrieve stored values for verification.
    let salted_password = scram
        .salted_password
        .as_ref()
        .ok_or(CurlError::AuthError)?;
    let auth_message = scram.auth_message.as_deref().ok_or(CurlError::AuthError)?;

    // Compute ServerKey = HMAC(SaltedPassword, "Server Key")
    let server_key = match scram.mechanism {
        ScramMechanism::Sha1 => hmac_sha1(salted_password, b"Server Key")?,
        ScramMechanism::Sha256 => hmac_sha256(salted_password, b"Server Key")?,
    };

    // Compute expected ServerSignature = HMAC(ServerKey, AuthMessage)
    let expected_signature = match scram.mechanism {
        ScramMechanism::Sha1 => hmac_sha1(&server_key, auth_message.as_bytes())?,
        ScramMechanism::Sha256 => hmac_sha256(&server_key, auth_message.as_bytes())?,
    };

    // Constant-time comparison to prevent timing attacks.
    if !constant_time_eq(&received_signature, &expected_signature) {
        return Err(CurlError::AuthError);
    }

    scram.step = ScramStep::Complete;
    Ok(())
}

// ---------------------------------------------------------------------------
// Public API — Unified Token Interface
// ---------------------------------------------------------------------------

/// Process a SCRAM challenge and produce the appropriate response token.
///
/// Dispatches to [`process_server_first()`] or [`process_server_final()`]
/// based on the current step. Matches the C `Curl_auth_gsasl_token()`
/// function which called `gsasl_step()` and returned the response in a
/// `bufref`.
///
/// # Arguments
///
/// * `challenge` — raw bytes of the server's challenge/response.
/// * `scram` — mutable reference to the session state.
///
/// # Returns
///
/// * For `ServerFirstReceived` step (processing server-first): the
///   client-final-message as bytes.
/// * For `ServerFinalReceived` step (processing server-final): an empty
///   `Vec<u8>` (no further data to send after verification succeeds).
///
/// # Errors
///
/// Propagates errors from the underlying step functions. Returns
/// [`CurlError::BadContentEncoding`] if called in an unexpected state.
pub fn token(
    challenge: &[u8],
    scram: &mut ScramData,
) -> Result<Vec<u8>, CurlError> {
    match scram.step {
        ScramStep::Initial => {
            // After start() has been called, the next incoming data is the
            // server-first-message. Process it and advance the state.
            let response = process_server_first(challenge, scram)?;
            Ok(response)
        }
        ScramStep::ServerFirstReceived => {
            // The server-final-message has arrived. Verify the server
            // signature and return an empty response (nothing more to send).
            process_server_final(challenge, scram)?;
            Ok(Vec::new())
        }
        ScramStep::ServerFinalReceived | ScramStep::Complete => {
            // Authentication is already complete or in an unexpected state.
            Err(CurlError::BadContentEncoding)
        }
    }
}

// ---------------------------------------------------------------------------
// Internal — PBKDF2 Key Derivation (Hi function)
// ---------------------------------------------------------------------------

/// PBKDF2-HMAC-SHA-256 key derivation as specified in RFC 5802 §2.2.
///
/// Implements the `Hi(str, salt, i)` function:
///   `U1 = HMAC(str, salt + INT(1))`
///   `U2 = HMAC(str, U1)`
///   `...`
///   `Hi = U1 XOR U2 XOR ... XOR Ui`
fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32) -> Result<Vec<u8>, CurlError> {
    let mut mac =
        HmacSha256::new_from_slice(password).map_err(|_| CurlError::OutOfMemory)?;

    // U1 = HMAC(password, salt || INT(1))
    // INT(1) is a 4-byte big-endian encoding of the integer 1.
    Mac::update(&mut mac, salt);
    Mac::update(&mut mac, &1u32.to_be_bytes());
    let u1 = mac.finalize_reset().into_bytes();

    let mut result = u1.to_vec();
    let mut u_prev = u1.to_vec();

    // U2 through U_iterations
    for _ in 1..iterations {
        Mac::update(&mut mac, &u_prev);
        let u_next = mac.finalize_reset().into_bytes();
        u_prev = u_next.to_vec();

        // XOR into the running result.
        for (r, &u) in result.iter_mut().zip(u_prev.iter()) {
            *r ^= u;
        }
    }

    Ok(result)
}

/// PBKDF2-HMAC-SHA-1 key derivation for the SCRAM-SHA-1 variant.
///
/// Identical algorithm to [`pbkdf2_hmac_sha256()`] but using HMAC-SHA-1
/// and producing a 20-byte key.
fn pbkdf2_hmac_sha1(password: &[u8], salt: &[u8], iterations: u32) -> Result<Vec<u8>, CurlError> {
    let mut mac =
        HmacSha1::new_from_slice(password).map_err(|_| CurlError::OutOfMemory)?;

    // U1 = HMAC(password, salt || INT(1))
    Mac::update(&mut mac, salt);
    Mac::update(&mut mac, &1u32.to_be_bytes());
    let u1 = mac.finalize_reset().into_bytes();

    let mut result = u1.to_vec();
    let mut u_prev = u1.to_vec();

    for _ in 1..iterations {
        Mac::update(&mut mac, &u_prev);
        let u_next = mac.finalize_reset().into_bytes();
        u_prev = u_next.to_vec();

        for (r, &u) in result.iter_mut().zip(u_prev.iter()) {
            *r ^= u;
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Internal — HMAC Wrappers
// ---------------------------------------------------------------------------

/// Compute HMAC-SHA-256(key, data) and return the raw bytes.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CurlError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| CurlError::OutOfMemory)?;
    Mac::update(&mut mac, data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Compute HMAC-SHA-1(key, data) and return the raw bytes.
fn hmac_sha1(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CurlError> {
    let mut mac = HmacSha1::new_from_slice(key).map_err(|_| CurlError::OutOfMemory)?;
    Mac::update(&mut mac, data);
    Ok(mac.finalize().into_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// Internal — Utility Functions
// ---------------------------------------------------------------------------

/// XOR two byte slices of equal length.
///
/// # Panics
///
/// Panics in debug mode if the slices have different lengths.
fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    debug_assert_eq!(a.len(), b.len(), "xor_bytes: length mismatch");
    a.iter().zip(b.iter()).map(|(&x, &y)| x ^ y).collect()
}

/// Constant-time byte-slice equality comparison.
///
/// Prevents timing side-channel attacks during server signature
/// verification. Always examines every byte regardless of early mismatch.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Minimal SASLprep username normalization per RFC 5802 §5.1.
///
/// Escapes the two characters that have special meaning in SCRAM attribute
/// values:
/// - `=` → `=3D`
/// - `,` → `=2C`
///
/// A full SASLprep (RFC 4013) profile of stringprep would involve Unicode
/// normalization, but for practical compatibility with curl's existing
/// behavior, we only perform the mandatory SCRAM escaping.
fn saslprep_username(user: &str) -> String {
    let mut result = String::with_capacity(user.len());
    for ch in user.chars() {
        match ch {
            '=' => result.push_str("=3D"),
            ',' => result.push_str("=2C"),
            _ => result.push(ch),
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- ScramMechanism tests -----------------------------------------------

    #[test]
    fn mechanism_names() {
        assert_eq!(ScramMechanism::Sha1.name(), "SCRAM-SHA-1");
        assert_eq!(ScramMechanism::Sha256.name(), "SCRAM-SHA-256");
    }

    #[test]
    fn mechanism_hash_lengths() {
        assert_eq!(ScramMechanism::Sha1.hash_len(), 20);
        assert_eq!(ScramMechanism::Sha256.hash_len(), 32);
    }

    // -- is_scram_supported tests -------------------------------------------

    #[test]
    fn supported_mechanisms() {
        assert!(is_scram_supported("SCRAM-SHA-1"));
        assert!(is_scram_supported("SCRAM-SHA-256"));
    }

    #[test]
    fn unsupported_mechanisms() {
        assert!(!is_scram_supported("PLAIN"));
        assert!(!is_scram_supported("SCRAM-SHA-512"));
        assert!(!is_scram_supported("scram-sha-1")); // case-sensitive
        assert!(!is_scram_supported(""));
    }

    // -- SASLprep username escaping -----------------------------------------

    #[test]
    fn saslprep_no_escaping_needed() {
        assert_eq!(saslprep_username("testuser"), "testuser");
    }

    #[test]
    fn saslprep_escape_equals() {
        assert_eq!(saslprep_username("user=name"), "user=3Dname");
    }

    #[test]
    fn saslprep_escape_comma() {
        assert_eq!(saslprep_username("user,name"), "user=2Cname");
    }

    #[test]
    fn saslprep_escape_both() {
        assert_eq!(saslprep_username("u=,n"), "u=3D=2Cn");
    }

    // -- ScramData lifecycle ------------------------------------------------

    #[test]
    fn scram_data_new_defaults() {
        let data = ScramData::new(ScramMechanism::Sha256);
        assert_eq!(data.mechanism, ScramMechanism::Sha256);
        assert!(data.client_nonce.is_none());
        assert!(data.server_nonce.is_none());
        assert!(data.salt.is_none());
        assert_eq!(data.iteration_count, 0);
        assert!(data.auth_message.is_none());
        assert!(data.client_first_bare.is_none());
        assert!(data.salted_password.is_none());
        assert_eq!(data.step, ScramStep::Initial);
    }

    #[test]
    fn scram_data_cleanup_resets() {
        let mut data = ScramData::new(ScramMechanism::Sha1);
        data.client_nonce = Some("test_nonce".to_owned());
        data.iteration_count = 4096;
        data.step = ScramStep::Complete;

        data.cleanup();

        assert!(data.client_nonce.is_none());
        assert_eq!(data.iteration_count, 0);
        assert_eq!(data.step, ScramStep::Initial);
    }

    // -- start() tests ------------------------------------------------------

    #[test]
    fn start_produces_valid_client_first() {
        let mut scram = ScramData::new(ScramMechanism::Sha256);
        let msg = start("user", "pencil", &mut scram).unwrap();
        let msg_str = String::from_utf8(msg).unwrap();

        // Must start with GS2 header "n,,"
        assert!(msg_str.starts_with("n,,"), "Expected GS2 header prefix");

        // Must contain "n=user"
        assert!(msg_str.contains("n=user,"), "Expected username attribute");

        // Must contain "r=" with a nonce
        assert!(msg_str.contains(",r="), "Expected nonce attribute");

        // client_first_bare should be stored
        assert!(scram.client_first_bare.is_some());
        let bare = scram.client_first_bare.as_ref().unwrap();
        assert!(bare.starts_with("n=user,r="));

        // client_nonce should be stored
        assert!(scram.client_nonce.is_some());
        assert!(!scram.client_nonce.as_ref().unwrap().is_empty());

        // Step should still be Initial
        assert_eq!(scram.step, ScramStep::Initial);
    }

    #[test]
    fn start_escapes_special_username_chars() {
        let mut scram = ScramData::new(ScramMechanism::Sha256);
        let msg = start("user=,test", "pass", &mut scram).unwrap();
        let msg_str = String::from_utf8(msg).unwrap();

        // Username "user=,test" should be escaped to "user=3D=2Ctest"
        assert!(
            msg_str.contains("n=user=3D=2Ctest,"),
            "Expected escaped username"
        );
    }

    // -- PBKDF2 test vectors from RFC 5802 / RFC 7677 ----------------------

    #[test]
    fn pbkdf2_sha256_rfc7677_vector() {
        // RFC 7677 test vector:
        // Password: "pencil"
        // Salt: "W22ZaJ0SNY7soEsUEjb6gQ==" (base64)
        // Iterations: 4096
        let salt = base64::decode("W22ZaJ0SNY7soEsUEjb6gQ==").unwrap();
        let result = pbkdf2_hmac_sha256(b"pencil", &salt, 4096).unwrap();

        // Expected SaltedPassword — verified against Python hashlib.pbkdf2_hmac.
        // RFC 7677 §3 defines the exchange but does not publish the intermediate
        // SaltedPassword value explicitly; this value was computed independently
        // using Python's hashlib.pbkdf2_hmac('sha256', b'pencil', salt, 4096).
        let expected = base64::decode("xKSVEDI6tPlSysH6mUQZOeeOp01r6B3fcJbodRPcYV0=").unwrap();
        assert_eq!(result, expected, "PBKDF2-HMAC-SHA256 does not match expected");
    }

    #[test]
    fn pbkdf2_sha1_rfc5802_vector() {
        // RFC 5802 test vector:
        // Password: "pencil"
        // Salt: "QSXCR+Q6sek8bf92" (base64)
        // Iterations: 4096
        let salt = base64::decode("QSXCR+Q6sek8bf92").unwrap();
        let result = pbkdf2_hmac_sha1(b"pencil", &salt, 4096).unwrap();

        // Expected SaltedPassword from RFC 5802:
        // HZbuOlKbWl+eR8AfIposuKbhX30=
        let expected = base64::decode("HZbuOlKbWl+eR8AfIposuKbhX30=").unwrap();
        assert_eq!(result, expected, "PBKDF2-HMAC-SHA1 does not match RFC 5802");
    }

    // -- Full SCRAM-SHA-256 exchange (RFC 7677 test vector) -----------------

    #[test]
    fn full_scram_sha256_exchange() {
        // This test uses the RFC 7677 test vectors.
        // We need to inject a known client nonce for reproducibility.
        let mut scram = ScramData::new(ScramMechanism::Sha256);

        // Step 1: Simulate start() with a known nonce.
        // RFC 7677 uses client nonce "rOprNGfwEbeRWgbNEkqO"
        scram.client_nonce = Some("rOprNGfwEbeRWgbNEkqO".to_owned());
        scram.password = Some("pencil".to_owned());
        scram.client_first_bare = Some("n=user,r=rOprNGfwEbeRWgbNEkqO".to_owned());
        scram.step = ScramStep::Initial;

        // Step 2: Process server-first-message from RFC 7677.
        let server_first =
            b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";

        let client_final = process_server_first(server_first, &mut scram).unwrap();
        let client_final_str = String::from_utf8(client_final).unwrap();

        // Verify the client-final message format.
        assert!(client_final_str.starts_with("c=biws,r="));
        assert!(client_final_str.contains(",p="));

        // Verify the nonce includes the server extension.
        assert!(client_final_str
            .contains("r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"));

        // Verify step advanced.
        assert_eq!(scram.step, ScramStep::ServerFirstReceived);

        // Step 3: Process server-final-message.
        // Compute expected server signature for verification.
        let salted_password = scram.salted_password.as_ref().unwrap();
        let server_key = hmac_sha256(salted_password, b"Server Key").unwrap();
        let auth_message = scram.auth_message.as_ref().unwrap();
        let server_sig = hmac_sha256(&server_key, auth_message.as_bytes()).unwrap();
        let server_final = format!("v={}", base64::encode(&server_sig));

        process_server_final(server_final.as_bytes(), &mut scram).unwrap();
        assert_eq!(scram.step, ScramStep::Complete);
    }

    // -- Full SCRAM-SHA-1 exchange (RFC 5802 test vector) -------------------

    #[test]
    fn full_scram_sha1_exchange() {
        // RFC 5802 §5 test vector.
        let mut scram = ScramData::new(ScramMechanism::Sha1);

        // Inject known client nonce from RFC 5802.
        scram.client_nonce = Some("fyko+d2lbbFgONRv9qkxdawL".to_owned());
        scram.password = Some("pencil".to_owned());
        scram.client_first_bare =
            Some("n=user,r=fyko+d2lbbFgONRv9qkxdawL".to_owned());
        scram.step = ScramStep::Initial;

        // Server-first-message from RFC 5802 §5.
        let server_first =
            b"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096";

        let client_final = process_server_first(server_first, &mut scram).unwrap();
        let client_final_str = String::from_utf8(client_final).unwrap();

        // Expected client-final from RFC 5802 §5:
        // c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=
        assert_eq!(
            client_final_str,
            "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts="
        );

        assert_eq!(scram.step, ScramStep::ServerFirstReceived);

        // Server-final-message from RFC 5802 §5.
        let server_final = b"v=rmF9pqV8S7suAoZWja4dJRkFsKQ=";
        process_server_final(server_final, &mut scram).unwrap();
        assert_eq!(scram.step, ScramStep::Complete);
    }

    // -- token() dispatch tests ---------------------------------------------

    #[test]
    fn token_dispatches_server_first() {
        let mut scram = ScramData::new(ScramMechanism::Sha1);

        // Prepare state as if start() was called.
        scram.client_nonce = Some("fyko+d2lbbFgONRv9qkxdawL".to_owned());
        scram.password = Some("pencil".to_owned());
        scram.client_first_bare =
            Some("n=user,r=fyko+d2lbbFgONRv9qkxdawL".to_owned());
        scram.step = ScramStep::Initial;

        let server_first =
            b"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096";

        let result = token(server_first, &mut scram).unwrap();
        assert!(!result.is_empty());
        assert_eq!(scram.step, ScramStep::ServerFirstReceived);
    }

    #[test]
    fn token_dispatches_server_final() {
        let mut scram = ScramData::new(ScramMechanism::Sha1);

        // Prepare full state through server-first.
        scram.client_nonce = Some("fyko+d2lbbFgONRv9qkxdawL".to_owned());
        scram.password = Some("pencil".to_owned());
        scram.client_first_bare =
            Some("n=user,r=fyko+d2lbbFgONRv9qkxdawL".to_owned());
        scram.step = ScramStep::Initial;

        let server_first =
            b"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096";
        let _ = process_server_first(server_first, &mut scram).unwrap();

        // Now token() should dispatch to process_server_final.
        let server_final = b"v=rmF9pqV8S7suAoZWja4dJRkFsKQ=";
        let result = token(server_final, &mut scram).unwrap();
        assert!(result.is_empty()); // No data to send after verification.
        assert_eq!(scram.step, ScramStep::Complete);
    }

    #[test]
    fn token_rejects_complete_state() {
        let mut scram = ScramData::new(ScramMechanism::Sha256);
        scram.step = ScramStep::Complete;

        let err = token(b"anything", &mut scram).unwrap_err();
        assert_eq!(err, CurlError::BadContentEncoding);
    }

    // -- Error handling tests -----------------------------------------------

    #[test]
    fn server_first_missing_nonce() {
        let mut scram = ScramData::new(ScramMechanism::Sha256);
        scram.client_nonce = Some("test".to_owned());
        scram.password = Some("pass".to_owned());
        scram.client_first_bare = Some("n=user,r=test".to_owned());

        let result = process_server_first(b"s=c2FsdA==,i=4096", &mut scram);
        assert_eq!(result.unwrap_err(), CurlError::BadContentEncoding);
    }

    #[test]
    fn server_first_missing_salt() {
        let mut scram = ScramData::new(ScramMechanism::Sha256);
        scram.client_nonce = Some("test".to_owned());
        scram.password = Some("pass".to_owned());
        scram.client_first_bare = Some("n=user,r=test".to_owned());

        let result = process_server_first(b"r=testXYZ,i=4096", &mut scram);
        assert_eq!(result.unwrap_err(), CurlError::BadContentEncoding);
    }

    #[test]
    fn server_first_missing_iteration_count() {
        let mut scram = ScramData::new(ScramMechanism::Sha256);
        scram.client_nonce = Some("test".to_owned());
        scram.password = Some("pass".to_owned());
        scram.client_first_bare = Some("n=user,r=test".to_owned());

        let result = process_server_first(b"r=testXYZ,s=c2FsdA==", &mut scram);
        assert_eq!(result.unwrap_err(), CurlError::BadContentEncoding);
    }

    #[test]
    fn server_first_nonce_mismatch() {
        let mut scram = ScramData::new(ScramMechanism::Sha256);
        scram.client_nonce = Some("myNonce".to_owned());
        scram.password = Some("pass".to_owned());
        scram.client_first_bare = Some("n=user,r=myNonce".to_owned());

        // Server nonce doesn't start with client nonce.
        let result = process_server_first(b"r=differentNonce,s=c2FsdA==,i=4096", &mut scram);
        assert_eq!(result.unwrap_err(), CurlError::BadContentEncoding);
    }

    #[test]
    fn server_first_iteration_too_low() {
        let mut scram = ScramData::new(ScramMechanism::Sha256);
        scram.client_nonce = Some("test".to_owned());
        scram.password = Some("pass".to_owned());
        scram.client_first_bare = Some("n=user,r=test".to_owned());

        let result = process_server_first(b"r=testXYZ,s=c2FsdA==,i=100", &mut scram);
        assert_eq!(result.unwrap_err(), CurlError::BadContentEncoding);
    }

    #[test]
    fn server_first_iteration_too_high() {
        let mut scram = ScramData::new(ScramMechanism::Sha256);
        scram.client_nonce = Some("test".to_owned());
        scram.password = Some("pass".to_owned());
        scram.client_first_bare = Some("n=user,r=test".to_owned());

        let result =
            process_server_first(b"r=testXYZ,s=c2FsdA==,i=99999999", &mut scram);
        assert_eq!(result.unwrap_err(), CurlError::BadContentEncoding);
    }

    #[test]
    fn server_first_error_attribute() {
        let mut scram = ScramData::new(ScramMechanism::Sha256);
        scram.client_nonce = Some("test".to_owned());
        scram.password = Some("pass".to_owned());
        scram.client_first_bare = Some("n=user,r=test".to_owned());

        let result = process_server_first(b"e=invalid-encoding", &mut scram);
        assert_eq!(result.unwrap_err(), CurlError::LoginDenied);
    }

    #[test]
    fn server_final_error_attribute() {
        let mut scram = ScramData::new(ScramMechanism::Sha256);
        scram.salted_password = Some(vec![0u8; 32]);
        scram.auth_message = Some("test".to_owned());

        let result = process_server_final(b"e=invalid-proof", &mut scram);
        assert_eq!(result.unwrap_err(), CurlError::LoginDenied);
    }

    #[test]
    fn server_final_wrong_signature() {
        let mut scram = ScramData::new(ScramMechanism::Sha256);
        scram.salted_password = Some(vec![0u8; 32]);
        scram.auth_message = Some("test_auth_message".to_owned());

        // Provide a valid-looking but incorrect signature.
        let bad_sig = base64::encode(&[0u8; 32]);
        let server_final = format!("v={}", bad_sig);

        let result = process_server_final(server_final.as_bytes(), &mut scram);
        assert_eq!(result.unwrap_err(), CurlError::AuthError);
    }

    #[test]
    fn server_final_malformed() {
        let mut scram = ScramData::new(ScramMechanism::Sha256);
        scram.salted_password = Some(vec![0u8; 32]);
        scram.auth_message = Some("test".to_owned());

        let result = process_server_final(b"garbage", &mut scram);
        assert_eq!(result.unwrap_err(), CurlError::BadContentEncoding);
    }

    // -- Utility tests ------------------------------------------------------

    #[test]
    fn xor_bytes_works() {
        let a = vec![0xFF, 0x00, 0xAA];
        let b = vec![0x0F, 0xF0, 0x55];
        let result = xor_bytes(&a, &b);
        assert_eq!(result, vec![0xF0, 0xF0, 0xFF]);
    }

    #[test]
    fn constant_time_eq_equal() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn constant_time_eq_not_equal() {
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"ab", b"abc"));
    }
}
