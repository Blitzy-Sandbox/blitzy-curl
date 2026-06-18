//! SASL SCRAM authentication (RFC 5802 / RFC 7677), **feature-gated off**.
//!
//! This module is the memory-safe Rust successor to curl's `lib/vauth/gsasl.c`,
//! which is a thin wrapper over the external C `libgsasl` library and is itself
//! compiled only when curl is built `--with-gsasl` (`#ifdef USE_GSASL`). In
//! curl, `libgsasl` provides the SCRAM family (`SCRAM-SHA-1` per RFC 5802 and
//! `SCRAM-SHA-256` per RFC 7677) used by the IMAP, POP3 and SMTP SASL layers.
//!
//! Unlike the C version, this is **not** a binding to a C library: SCRAM is a
//! pure composition of a hash, HMAC, PBKDF2, base64 and a random nonce, all of
//! which are available natively in this workspace, so the mechanism is
//! reimplemented directly on top of [`crate::util`]. There is **no `libgsasl`
//! linkage** and **no `unsafe`** anywhere in this file.
//!
//! # Why this whole module is gated behind the `gsasl` feature (off by default)
//!
//! curl's *default* build is **not** linked against `libgsasl`, so a stock curl
//! does **not** report the `CURL_VERSION_GSASL` capability bit (`1 << 29`) and
//! does **not** offer the SCRAM mechanisms. To keep `curl_version_info()` /
//! `curl --version` byte-identical with stock curl — which is what drives the
//! feature-gated test selection in the regression suite (AAP §0.7.3) — this
//! module is compiled **only** when the crate's `gsasl` Cargo feature is
//! enabled, and that feature is **excluded from the default set**. The gate is
//! kept in lockstep with `crate::version`, which reports `gsasl_version: None`
//! and omits `CURL_VERSION_GSASL` in the default build.
//!
//! The gate is expressed as a file-level inner attribute
//! (`#![cfg(feature = "gsasl")]`) so the entire module body is excluded from
//! the default build regardless of how the parent `auth` module declares it.
//!
//! # Scope: `SCRAM-SHA-256` only (a deliberate, documented choice)
//!
//! `libgsasl` offers both `SCRAM-SHA-1` and `SCRAM-SHA-256`. This module
//! implements **`SCRAM-SHA-256`** (RFC 7677) and intentionally does *not*
//! implement `SCRAM-SHA-1`, for the following reasons:
//!
//! * The crate's crypto utilities ([`crate::util::sha256`],
//!   [`crate::util::hmac`]) provide SHA-256 and HMAC-SHA-256 but **no SHA-1 /
//!   HMAC-SHA-1** primitive — by design, since curl uses HMAC with only MD5 and
//!   SHA-256 (see `crate::util::hmac`).
//! * Adding a SHA-1 dependency is not viable under the workspace's pinned,
//!   audited dependency set: the pinned `hmac 0.12` requires `digest 0.10`,
//!   whereas the available `sha1` crate line requires `digest 0.11`, so the two
//!   cannot interoperate; and hand-rolling a hash contradicts this crate's
//!   "use audited crates, never transliterate crypto" rule (`crate::util::hmac`).
//! * `SCRAM-SHA-256` is the modern, preferred mechanism (the SASL layer selects
//!   it ahead of `SCRAM-SHA-1`), and because the module is off in the default
//!   build there is **no test-suite-parity impact** from omitting SHA-1.
//!
//! [`ScramMechanism`] is nevertheless modelled as an `enum` so a SHA-1 variant
//! can be added later without an API break, should a compatible SHA-1 primitive
//! land in [`crate::util`].
//!
//! # The SCRAM exchange, and how it maps to the gsasl step model
//!
//! curl drives `libgsasl` with a small four-call lifecycle
//! (`is_supported` → `start` → `token`\* → `cleanup`). [`ScramClient`] mirrors
//! that shape so the SASL layer can drive it identically:
//!
//! | gsasl (C)                     | this module                         |
//! |-------------------------------|-------------------------------------|
//! | `Curl_auth_gsasl_is_supported`| [`ScramMechanism::from_name`] + [`ScramClient::new`] |
//! | `Curl_auth_gsasl_start`       | [`ScramClient::start`]              |
//! | `Curl_auth_gsasl_token`       | [`ScramClient::token`] (multi-step) |
//! | `Curl_auth_gsasl_cleanup`     | `Drop` (automatic)                 |
//!
//! The three SCRAM messages produced/consumed by successive [`token`] calls are:
//!
//! 1. **client-first** (`token` with an empty challenge) →
//!    `n,,n=<user>,r=<client-nonce>`.
//! 2. **server-first** (`r=<nonce>,s=<salt>,i=<iters>`) → **client-final**
//!    `c=biws,r=<nonce>,p=<ClientProof>`.
//! 3. **server-final** (`v=<ServerSignature>`) → empty output; the server
//!    signature is verified and the exchange is marked complete.
//!
//! The cryptographic core (RFC 5802 §3, with `H = SHA-256` for RFC 7677) is:
//!
//! ```text
//! SaltedPassword  = PBKDF2(HMAC-H, password, salt, iters, dkLen = H.len)
//! ClientKey       = HMAC-H(SaltedPassword, "Client Key")
//! StoredKey       = H(ClientKey)
//! AuthMessage     = client-first-bare ++ "," ++ server-first ++ ","
//!                                     ++ client-final-without-proof
//! ClientSignature = HMAC-H(StoredKey, AuthMessage)
//! ClientProof     = ClientKey XOR ClientSignature
//! ServerKey       = HMAC-H(SaltedPassword, "Server Key")
//! ServerSignature = HMAC-H(ServerKey, AuthMessage)
//! ```
//!
//! `biws` in the client-final channel-binding field is the fixed constant
//! `base64("n,,")` (no channel binding; `SCRAM-*-PLUS` is not implemented).
//!
//! # Normalization caveat
//!
//! RFC 5802 specifies that the username and password be processed with SASLprep
//! (RFC 4013). This module applies the mandatory username `=`/`,` escaping
//! (`saslname`, RFC 5802 §5.1) but does **not** perform full SASLprep Unicode
//! normalization; for ASCII credentials — which all SCRAM test vectors use, and
//! which is the overwhelmingly common case — SASLprep is a no-op, so behavior
//! is identical there.
//!
//! # Memory safety
//!
//! Contains **zero** `unsafe` and compiles cleanly under the crate-wide
//! `#![forbid(unsafe_code)]` (AAP §0.7.1). All randomness, hashing, HMAC and
//! base64 come from audited safe-Rust utilities in [`crate::util`].

#![cfg(feature = "gsasl")]

use crate::error::{CurlError, Result};
use crate::util::base64::{base64_decode, base64_encode};
use crate::util::hmac::hmac_sha256;
use crate::util::rand::rand_alnum;
use crate::util::sha256::sha256it;

/// The GS2 header for a client that supports no channel binding: the
/// `gs2-cbind-flag` `n` followed by an empty `authzid`, i.e. `"n,,"`.
///
/// It prefixes the client-first message and, base64-encoded, becomes the
/// [`CHANNEL_BINDING`] value in the client-final message.
const GS2_HEADER: &str = "n,,";

/// The fixed channel-binding field for client-final, `base64("n,,")` = `"biws"`.
///
/// Because `SCRAM-*-PLUS` (real channel binding) is not implemented, the
/// `cbind-input` is exactly the [`GS2_HEADER`], so this constant never varies.
/// It is asserted equal to `base64_encode(GS2_HEADER)` in the unit tests.
const CHANNEL_BINDING: &str = "biws";

/// The constant key string for deriving `ClientKey` (RFC 5802 §3).
const CLIENT_KEY_LABEL: &[u8] = b"Client Key";

/// The constant key string for deriving `ServerKey` (RFC 5802 §3).
const SERVER_KEY_LABEL: &[u8] = b"Server Key";

/// Number of random alphanumeric characters in a generated client nonce.
///
/// RFC 5802 requires only that the nonce be a "sequence of random printable
/// ASCII characters" of sufficient length; 32 alphanumerics (~190 bits) is a
/// conservative, common choice. The [`rand_alnum`] alphabet (`[A-Za-z0-9]`)
/// excludes `,` and `=`, so a generated nonce never needs `saslname` escaping.
const CLIENT_NONCE_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Mechanism selection.
// ---------------------------------------------------------------------------

/// A SCRAM hash mechanism.
///
/// Only [`Sha256`](ScramMechanism::Sha256) is implemented (see the module-level
/// documentation for the rationale). The type is an `enum` precisely so a
/// `Sha1` variant could be added later without a breaking API change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScramMechanism {
    /// `SCRAM-SHA-256`, the RFC 7677 mechanism (`H = SHA-256`).
    Sha256,
}

impl ScramMechanism {
    /// The IANA SASL mechanism name, as it appears in protocol negotiation
    /// (e.g. an IMAP `AUTH=` capability or the `AUTHENTICATE` verb argument).
    #[must_use]
    pub const fn mechanism_name(self) -> &'static str {
        match self {
            ScramMechanism::Sha256 => "SCRAM-SHA-256",
        }
    }

    /// Parse a SASL mechanism name into a [`ScramMechanism`].
    ///
    /// The comparison is case-sensitive against the canonical IANA name, which
    /// is how the mechanism is advertised on the wire. Returns [`None`] for any
    /// name this module does not implement (including `SCRAM-SHA-1` and the
    /// `*-PLUS` channel-binding variants), mirroring `libgsasl`'s
    /// `gsasl_client_start` rejecting an unsupported mechanism in
    /// `Curl_auth_gsasl_is_supported`.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "SCRAM-SHA-256" => Some(ScramMechanism::Sha256),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Cryptographic / encoding helpers (private).
// ---------------------------------------------------------------------------

/// PBKDF2 with HMAC-SHA-256 as the PRF, specialized to `dkLen == hLen == 32`.
///
/// This is the `SaltedPassword` derivation of RFC 5802 §3 (RFC 7677 fixes
/// `H = SHA-256`). For SCRAM the derived-key length always equals the hash
/// output length (32 bytes), so PBKDF2 produces exactly **one** block and the
/// general multi-block construction collapses to:
///
/// ```text
/// U_1 = HMAC(password, salt || INT32_BE(1))
/// U_k = HMAC(password, U_{k-1})            for k = 2..=iters
/// T   = U_1 XOR U_2 XOR ... XOR U_iters
/// ```
///
/// Implemented locally from the [`hmac_sha256`] primitive (a short, audited
/// loop) rather than pulling in a `pbkdf2` crate, per the minimal-dependency
/// mandate. `iters` is the server-supplied iteration count; callers validate it
/// is non-zero before calling, so the `1..iters` follow-up loop is well-defined
/// (`iters == 1` simply yields `T = U_1`).
fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iters: u32) -> [u8; 32] {
    // U_1 = HMAC(password, salt || INT(1)), where INT(1) is the 32-bit
    // big-endian block index 1 (this is the only block, dkLen == hLen).
    let mut block_input = Vec::with_capacity(salt.len() + 4);
    block_input.extend_from_slice(salt);
    block_input.extend_from_slice(&1u32.to_be_bytes());

    let mut u = hmac_sha256(password, &block_input);
    let mut result = u;

    // Fold in U_2..U_iters. `result ^= U_k` accumulates the XOR sum T.
    for _ in 1..iters {
        u = hmac_sha256(password, &u);
        for (acc, byte) in result.iter_mut().zip(u.iter()) {
            *acc ^= *byte;
        }
    }
    result
}

/// XOR two 32-byte arrays element-wise.
///
/// Used to form `ClientProof = ClientKey XOR ClientSignature`; both inputs are
/// SHA-256-sized (32 bytes), so the output is also 32 bytes.
fn xor32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = a[i] ^ b[i];
    }
    out
}

/// Apply the SCRAM `saslname` escaping to a username (RFC 5802 §5.1).
///
/// Within the `n=` attribute of the client-first message, a literal `,` must be
/// sent as `=2C` and a literal `=` as `=3D` (every other byte is passed
/// through). This keeps the comma-delimited, `=`-using attribute syntax
/// unambiguous. The transformation is order-sensitive — `=` must be escaped
/// before `,` would be, which the single left-to-right pass below guarantees.
fn escape_saslname(username: &str) -> String {
    let mut escaped = String::with_capacity(username.len());
    for ch in username.chars() {
        match ch {
            '=' => escaped.push_str("=3D"),
            ',' => escaped.push_str("=2C"),
            other => escaped.push(other),
        }
    }
    escaped
}

// ---------------------------------------------------------------------------
// Client state machine.
// ---------------------------------------------------------------------------

/// The step the [`ScramClient`] expects to perform on the next [`token`] call.
///
/// [`token`]: ScramClient::token
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScramStep {
    /// No message exchanged yet; the next `token` emits **client-first**.
    Initial,
    /// client-first was emitted; the next `token` consumes **server-first** and
    /// emits **client-final**.
    ClientFirstSent,
    /// client-final was emitted; the next `token` consumes **server-final**,
    /// verifies the server signature, and completes the exchange.
    ClientFinalSent,
    /// The exchange finished and the server signature verified. Any further
    /// `token` call is a protocol error.
    Complete,
}

/// Client-side driver for a single SCRAM authentication exchange.
///
/// Construct with [`new`](Self::new), supply credentials with
/// [`start`](Self::start), then call [`token`](Self::token) once per SASL round
/// trip until [`is_complete`](Self::is_complete) returns `true`. The struct
/// carries the state required to span those calls (the negotiated nonce, the
/// `SaltedPassword`, and the `AuthMessage`), mirroring how `libgsasl` carries
/// state inside its opaque `Gsasl_session`.
///
/// A `ScramClient` drives **one** exchange and is not reusable after it
/// completes; create a fresh instance for each authentication attempt.
pub struct ScramClient {
    /// The negotiated SCRAM hash mechanism (currently always
    /// [`ScramMechanism::Sha256`]).
    mechanism: ScramMechanism,
    /// The authentication identity (`AUTHID`), used unescaped for PBKDF2 keying
    /// context and `saslname`-escaped in the client-first message.
    username: String,
    /// The plaintext password, consumed only as the PBKDF2 input key.
    password: String,
    /// The client nonce (`c-nonce`). Empty until [`start`](Self::start)
    /// generates it (or a test injects one via the test-only hook); a real
    /// nonce is never empty, so empty doubles as the "not yet set" sentinel.
    client_nonce: String,
    /// Cached `client-first-message-bare` (`n=<user>,r=<c-nonce>`), needed
    /// verbatim when assembling the `AuthMessage`.
    client_first_bare: String,
    /// `SaltedPassword`, computed while producing client-final and reused to
    /// derive `ServerKey` during server-final verification.
    salted_password: Vec<u8>,
    /// The full `AuthMessage`, retained from client-final so the server
    /// signature can be recomputed and checked in server-final.
    auth_message: String,
    /// Which step the next [`token`](Self::token) call performs.
    step: ScramStep,
}

impl ScramClient {
    /// Create a client driver for `mechanism`.
    ///
    /// Parity with the mechanism-selection half of curl's
    /// `Curl_auth_gsasl_is_supported` (which calls `gsasl_client_start` with the
    /// mechanism name). Credentials are supplied separately via
    /// [`start`](Self::start), mirroring the gsasl `is_supported` → `start`
    /// split.
    #[must_use]
    pub fn new(mechanism: ScramMechanism) -> Self {
        Self {
            mechanism,
            username: String::new(),
            password: String::new(),
            client_nonce: String::new(),
            client_first_bare: String::new(),
            salted_password: Vec::new(),
            auth_message: String::new(),
            step: ScramStep::Initial,
        }
    }

    /// Supply the credentials for the exchange.
    ///
    /// Parity with `Curl_auth_gsasl_start`, which sets the `GSASL_AUTHID` and
    /// `GSASL_PASSWORD` properties. It also generates the random client nonce
    /// here (unless one was already injected by the test-only hook), so the
    /// nonce is fixed before the first [`token`](Self::token) call.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::FailedInit`] if the OS entropy source cannot be read
    /// while generating the nonce (propagated from [`rand_alnum`]).
    pub fn start(&mut self, username: &str, password: &str) -> Result<()> {
        self.username = username.to_string();
        self.password = password.to_string();
        if self.client_nonce.is_empty() {
            self.client_nonce = generate_client_nonce()?;
        }
        Ok(())
    }

    /// The mechanism this client was constructed for.
    #[must_use]
    pub fn mechanism(&self) -> ScramMechanism {
        self.mechanism
    }

    /// Whether the exchange has completed **and** the server signature verified.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.step == ScramStep::Complete
    }

    /// Test-only hook to force the client nonce to a fixed value.
    ///
    /// Production code always uses the random nonce from [`start`](Self::start)
    /// (which honors the `CURL_ENTROPY` deterministic test hook of
    /// [`crate::util::rand`] in debug builds). This setter exists so the
    /// known-answer RFC 7677 vector — which pins a specific client nonce — can
    /// be reproduced exactly. It must be called **before** [`start`](Self::start)
    /// so the latter does not overwrite it.
    #[cfg(test)]
    fn set_client_nonce(&mut self, nonce: &str) {
        self.client_nonce = nonce.to_string();
    }
}

/// Generate a fresh random client nonce of [`CLIENT_NONCE_LEN`] alphanumeric
/// characters.
///
/// Uses [`rand_alnum`], whose `[A-Za-z0-9]` alphabet is a subset of the SCRAM
/// `printable` nonce charset and excludes the `,` and `=` delimiters, so the
/// result is always a valid, escaping-free nonce. In debug builds `rand_alnum`
/// honors `CURL_ENTROPY`, giving the regression suite reproducible nonces.
fn generate_client_nonce() -> Result<String> {
    // `rand_alnum` writes `num - 1` alnum characters followed by a NUL, so the
    // buffer is one byte longer than the desired nonce length.
    let mut buf = [0u8; CLIENT_NONCE_LEN + 1];
    rand_alnum(&mut buf, CLIENT_NONCE_LEN + 1)?;
    // The first CLIENT_NONCE_LEN bytes are guaranteed ASCII alphanumerics, so
    // UTF-8 validation cannot fail; map the impossible error defensively rather
    // than panicking, keeping this function total and `unsafe`-free.
    let nonce = core::str::from_utf8(&buf[..CLIENT_NONCE_LEN])
        .map_err(|_| CurlError::AuthError)?
        .to_string();
    Ok(nonce)
}

impl ScramClient {
    /// Process one SASL round trip: consume the server's `challenge` and produce
    /// the next client message.
    ///
    /// Parity with `Curl_auth_gsasl_token` (`gsasl_step`): it is called once per
    /// round trip, advancing an internal state machine and returning the bytes
    /// to send back to the server. The returned buffer is the raw SCRAM message
    /// **before** any base64 transport encoding (the SASL layer applies that, as
    /// curl does around `gsasl_step`).
    ///
    /// The call sequence is:
    ///
    /// 1. first call — `challenge` is ignored (SCRAM is client-first); returns
    ///    the **client-first** message;
    /// 2. second call — `challenge` is **server-first**; returns
    ///    **client-final**;
    /// 3. third call — `challenge` is **server-final**; verifies the server
    ///    signature and returns an empty buffer, after which
    ///    [`is_complete`](Self::is_complete) is `true`.
    ///
    /// # Errors
    ///
    /// * [`CurlError::BadContentEncoding`] — a malformed/unexpected server
    ///   message, a server nonce that does not extend the client nonce, an
    ///   unsupported reserved extension, or an extra call after completion
    ///   (mirrors `gsasl_step` returning neither `GSASL_OK` nor
    ///   `GSASL_NEEDS_MORE`, which curl maps to `CURLE_BAD_CONTENT_ENCODING`).
    /// * [`CurlError::LoginDenied`] — the server reported an error in
    ///   server-final, or the verified `ServerSignature` did not match (the
    ///   server failed to prove knowledge of the password).
    /// * [`CurlError::AuthError`] — [`token`](Self::token) was called before
    ///   [`start`](Self::start) supplied credentials.
    pub fn token(&mut self, challenge: &[u8]) -> Result<Vec<u8>> {
        match self.step {
            ScramStep::Initial => self.build_client_first(),
            ScramStep::ClientFirstSent => self.handle_server_first(challenge),
            ScramStep::ClientFinalSent => self.handle_server_final(challenge),
            // A fourth call has no defined message; treat it as a protocol
            // error, consistent with gsasl's post-completion step failing.
            ScramStep::Complete => Err(CurlError::BadContentEncoding),
        }
    }

    /// Step 1: build the client-first message `n,,n=<user>,r=<c-nonce>`.
    ///
    /// Caches the `client-first-message-bare` (the part after the GS2 header)
    /// for later inclusion in the `AuthMessage`.
    fn build_client_first(&mut self) -> Result<Vec<u8>> {
        // `start` must have run: a real client nonce is never empty. Guard so a
        // misuse surfaces as a clear auth error rather than an invalid message.
        if self.client_nonce.is_empty() {
            return Err(CurlError::AuthError);
        }

        let bare = format!(
            "n={user},r={nonce}",
            user = escape_saslname(&self.username),
            nonce = self.client_nonce
        );
        let message = format!("{GS2_HEADER}{bare}");
        self.client_first_bare = bare;
        self.step = ScramStep::ClientFirstSent;
        Ok(message.into_bytes())
    }

    /// Step 2: consume server-first and build client-final.
    ///
    /// Performs the full RFC 5802 §3 derivation (with `H = SHA-256`), verifies
    /// the server nonce extends the client nonce, and stores the
    /// `SaltedPassword` and `AuthMessage` for the server-final check.
    fn handle_server_first(&mut self, challenge: &[u8]) -> Result<Vec<u8>> {
        // SCRAM messages are ASCII text; reject non-UTF-8 as malformed.
        let server_first =
            core::str::from_utf8(challenge).map_err(|_| CurlError::BadContentEncoding)?;
        let (server_nonce, salt, iters) = parse_server_first(server_first)?;

        // The server nonce MUST begin with the client nonce (RFC 5802 §5): the
        // server appends its own randomness to ours. A failure here means the
        // server response is invalid or tampered with.
        if !server_nonce.starts_with(&self.client_nonce) {
            return Err(CurlError::BadContentEncoding);
        }

        // SaltedPassword = PBKDF2(HMAC-SHA-256, password, salt, iters, 32).
        let salted = pbkdf2_hmac_sha256(self.password.as_bytes(), &salt, iters);
        // ClientKey = HMAC(SaltedPassword, "Client Key"); StoredKey = H(ClientKey).
        let client_key = hmac_sha256(&salted, CLIENT_KEY_LABEL);
        let stored_key = sha256it(&client_key);

        // client-final-without-proof = c=biws,r=<server-nonce>.
        let client_final_bare = format!("c={CHANNEL_BINDING},r={server_nonce}");

        // AuthMessage = client-first-bare , server-first , client-final-no-proof.
        // The server-first part MUST be byte-exact as received.
        let auth_message = format!(
            "{client_first_bare},{server_first},{client_final_bare}",
            client_first_bare = self.client_first_bare,
        );

        // ClientSignature = HMAC(StoredKey, AuthMessage);
        // ClientProof = ClientKey XOR ClientSignature.
        let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());
        let client_proof = xor32(&client_key, &client_signature);
        let proof_b64 = base64_to_string(&client_proof)?;

        // Persist what server-final verification needs.
        self.salted_password = salted.to_vec();
        self.auth_message = auth_message;
        self.step = ScramStep::ClientFinalSent;

        let client_final = format!("{client_final_bare},p={proof_b64}");
        Ok(client_final.into_bytes())
    }

    /// Step 3: consume server-final and verify the server signature.
    ///
    /// Recomputes `ServerSignature = HMAC(ServerKey, AuthMessage)` from the
    /// stored `SaltedPassword` and `AuthMessage` and compares it (in constant
    /// time) against the `v=` value the server sent. A mismatch — or a server
    /// `e=` error attribute — means authentication failed.
    fn handle_server_final(&mut self, challenge: &[u8]) -> Result<Vec<u8>> {
        let server_final =
            core::str::from_utf8(challenge).map_err(|_| CurlError::BadContentEncoding)?;
        let received_signature = parse_server_final(server_final)?;

        // ServerKey = HMAC(SaltedPassword, "Server Key");
        // ServerSignature = HMAC(ServerKey, AuthMessage).
        let server_key = hmac_sha256(&self.salted_password, SERVER_KEY_LABEL);
        let expected_signature = hmac_sha256(&server_key, self.auth_message.as_bytes());

        // A signature mismatch means the server could not prove knowledge of the
        // password: per the agent task, this maps to CURLE_LOGIN_DENIED.
        if !constant_time_eq(&received_signature, &expected_signature) {
            return Err(CurlError::LoginDenied);
        }

        self.step = ScramStep::Complete;
        // server-final yields no further client message.
        Ok(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// Server-message parsing (private free functions).
// ---------------------------------------------------------------------------

/// Parse a SCRAM server-first message into `(server-nonce, salt, iterations)`.
///
/// Accepts `r=<nonce>,s=<salt-b64>,i=<iters>` and tolerates unknown attributes
/// for forward compatibility, but rejects the reserved mandatory-extension
/// attribute `m=` (RFC 5802 §7: a client that does not understand it MUST
/// abort). Each attribute is split on its **first** `=` so base64 padding in the
/// salt and `=` characters permitted inside the nonce are preserved.
///
/// # Errors
///
/// Returns [`CurlError::BadContentEncoding`] if a required attribute is missing
/// or empty, an attribute lacks a `=`, the salt is not valid base64, or the
/// iteration count is not a positive integer.
fn parse_server_first(message: &str) -> Result<(String, Vec<u8>, u32)> {
    let mut nonce: Option<&str> = None;
    let mut salt_b64: Option<&str> = None;
    let mut iters_str: Option<&str> = None;

    for token in message.split(',') {
        let (key, value) = token.split_once('=').ok_or(CurlError::BadContentEncoding)?;
        match key {
            "r" => nonce = Some(value),
            "s" => salt_b64 = Some(value),
            "i" => iters_str = Some(value),
            // Reserved mandatory extension we do not understand: MUST abort.
            "m" => return Err(CurlError::BadContentEncoding),
            // Ignore other attributes (e.g. future optional extensions).
            _ => {}
        }
    }

    let nonce = nonce.ok_or(CurlError::BadContentEncoding)?;
    let salt_b64 = salt_b64.ok_or(CurlError::BadContentEncoding)?;
    let iters_str = iters_str.ok_or(CurlError::BadContentEncoding)?;

    if nonce.is_empty() {
        return Err(CurlError::BadContentEncoding);
    }

    let salt = base64_decode(salt_b64.as_bytes())?;
    let iters: u32 = iters_str
        .parse()
        .map_err(|_| CurlError::BadContentEncoding)?;
    if iters == 0 {
        return Err(CurlError::BadContentEncoding);
    }

    Ok((nonce.to_string(), salt, iters))
}

/// Parse a SCRAM server-final message into the server-signature bytes.
///
/// `server-final` is either a verifier (`v=<server-signature-b64>`) or an error
/// (`e=<error>`); only the first attribute is significant. A `v=` is base64
/// decoded and returned; an `e=` is reported as [`CurlError::LoginDenied`]
/// (the server rejected authentication); anything else is malformed.
fn parse_server_final(message: &str) -> Result<Vec<u8>> {
    // Only the first attribute (before any optional extensions) matters.
    let first = match message.split_once(',') {
        Some((head, _)) => head,
        None => message,
    };
    let (key, value) = first.split_once('=').ok_or(CurlError::BadContentEncoding)?;
    match key {
        // base64_decode already yields CURLE_BAD_CONTENT_ENCODING on bad input.
        "v" => base64_decode(value.as_bytes()),
        // The server signalled an authentication error.
        "e" => Err(CurlError::LoginDenied),
        _ => Err(CurlError::BadContentEncoding),
    }
}

/// Base64-encode `bytes` and return the result as a [`String`].
///
/// [`base64_encode`] emits ASCII base64 text, which is always valid UTF-8, so
/// the [`String::from_utf8`] conversion never fails in practice; the `map_err`
/// guards that impossible path without a panic, keeping the call total.
fn base64_to_string(bytes: &[u8]) -> Result<String> {
    String::from_utf8(base64_encode(bytes)?).map_err(|_| CurlError::AuthError)
}

/// Constant-time equality for two byte slices.
///
/// Compares every byte regardless of where the first difference is, so the
/// running time depends only on the input length, not its contents. Used for
/// the `ServerSignature` check so the comparison does not leak, via timing, how
/// much of a forged signature was correct.
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

#[cfg(test)]
mod tests {
    use super::*;

    // The canonical RFC 7677 §3 SCRAM-SHA-256 worked example.
    const RFC7677_USER: &str = "user";
    const RFC7677_PASS: &str = "pencil";
    const RFC7677_CLIENT_NONCE: &str = "rOprNGfwEbeRWgbNEkqO";
    const RFC7677_SERVER_FIRST: &str =
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    const RFC7677_CLIENT_FINAL: &str =
        "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
         p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
    const RFC7677_SERVER_FINAL: &str = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

    fn to_str(bytes: &[u8]) -> &str {
        core::str::from_utf8(bytes).expect("SCRAM messages are ASCII text")
    }

    /// Lower-case hex helper for comparing derived keys to published vectors.
    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// The fixed `biws` constant must equal `base64("n,,")`.
    #[test]
    fn channel_binding_is_base64_of_gs2_header() {
        assert_eq!(CHANNEL_BINDING, "biws");
        assert_eq!(
            CHANNEL_BINDING,
            base64_to_string(GS2_HEADER.as_bytes()).expect("encode n,,")
        );
    }

    /// Mechanism naming and parsing round-trips; unsupported names are rejected.
    #[test]
    fn mechanism_name_and_parse() {
        assert_eq!(ScramMechanism::Sha256.mechanism_name(), "SCRAM-SHA-256");
        assert_eq!(
            ScramMechanism::from_name("SCRAM-SHA-256"),
            Some(ScramMechanism::Sha256)
        );
        // SHA-1 and channel-binding variants are intentionally unsupported.
        assert_eq!(ScramMechanism::from_name("SCRAM-SHA-1"), None);
        assert_eq!(ScramMechanism::from_name("SCRAM-SHA-256-PLUS"), None);
        assert_eq!(ScramMechanism::from_name("PLAIN"), None);
        assert_eq!(ScramMechanism::from_name(""), None);
    }

    /// `saslname` escaping replaces `=` then `,` (RFC 5802 §5.1).
    #[test]
    fn saslname_escaping() {
        assert_eq!(escape_saslname("user"), "user");
        assert_eq!(escape_saslname("a,b"), "a=2Cb");
        assert_eq!(escape_saslname("a=b"), "a=3Db");
        // `=` is escaped to `=3D`; the `3D` is literal and must not be re-escaped.
        assert_eq!(escape_saslname("a=,b"), "a=3D=2Cb");
    }

    /// PBKDF2-HMAC-SHA-256 produces the RFC 7677 `SaltedPassword`.
    #[test]
    fn pbkdf2_matches_rfc7677_salted_password() {
        let salt = base64_decode(b"W22ZaJ0SNY7soEsUEjb6gQ==").expect("decode salt");
        let salted = pbkdf2_hmac_sha256(RFC7677_PASS.as_bytes(), &salt, 4096);
        assert_eq!(
            hex(&salted),
            "c4a49510323ab4f952cac1fa99441939e78ea74d6be81ddf7096e87513dc615d"
        );
    }

    /// `iters == 1` yields exactly `U_1` (the single-iteration PBKDF2 edge case).
    #[test]
    fn pbkdf2_single_iteration_is_u1() {
        let salt = b"salt";
        let one = pbkdf2_hmac_sha256(b"pw", salt, 1);
        // U_1 = HMAC(pw, salt || INT(1)).
        let mut block = Vec::new();
        block.extend_from_slice(salt);
        block.extend_from_slice(&1u32.to_be_bytes());
        let expected = hmac_sha256(b"pw", &block);
        assert_eq!(one, expected);
    }

    /// The full RFC 7677 exchange: client-first, client-final (ClientProof), and
    /// successful server-final verification, all against the published vector.
    #[test]
    fn rfc7677_full_exchange() {
        let mut client = ScramClient::new(ScramMechanism::Sha256);
        client.set_client_nonce(RFC7677_CLIENT_NONCE);
        client.start(RFC7677_USER, RFC7677_PASS).expect("start");

        // Step 1: client-first.
        let client_first = client.token(b"").expect("client-first");
        assert_eq!(to_str(&client_first), "n,,n=user,r=rOprNGfwEbeRWgbNEkqO");
        assert!(!client.is_complete());

        // Step 2: server-first -> client-final (carries the ClientProof).
        let client_final = client
            .token(RFC7677_SERVER_FIRST.as_bytes())
            .expect("client-final");
        assert_eq!(to_str(&client_final), RFC7677_CLIENT_FINAL);
        assert!(!client.is_complete());

        // Step 3: server-final -> verify, empty output, complete.
        let out = client
            .token(RFC7677_SERVER_FINAL.as_bytes())
            .expect("server-final verify");
        assert!(out.is_empty());
        assert!(client.is_complete());
    }

    /// A wrong server signature in server-final must fail with LOGIN_DENIED.
    #[test]
    fn server_signature_mismatch_is_login_denied() {
        let mut client = ScramClient::new(ScramMechanism::Sha256);
        client.set_client_nonce(RFC7677_CLIENT_NONCE);
        client.start(RFC7677_USER, RFC7677_PASS).expect("start");
        client.token(b"").expect("client-first");
        client
            .token(RFC7677_SERVER_FIRST.as_bytes())
            .expect("client-final");

        // A valid-base64 but incorrect 32-byte signature.
        let wrong = base64_to_string(&[0u8; 32]).expect("encode zeros");
        let bad_final = format!("v={wrong}");
        let err = client.token(bad_final.as_bytes()).unwrap_err();
        assert_eq!(err, CurlError::LoginDenied);
        assert!(!client.is_complete());
    }

    /// A server `e=` error attribute in server-final maps to LOGIN_DENIED.
    #[test]
    fn server_error_attribute_is_login_denied() {
        let mut client = ScramClient::new(ScramMechanism::Sha256);
        client.set_client_nonce(RFC7677_CLIENT_NONCE);
        client.start(RFC7677_USER, RFC7677_PASS).expect("start");
        client.token(b"").expect("client-first");
        client
            .token(RFC7677_SERVER_FIRST.as_bytes())
            .expect("client-final");

        let err = client.token(b"e=invalid-proof").unwrap_err();
        assert_eq!(err, CurlError::LoginDenied);
    }

    /// A server nonce that does not extend the client nonce is rejected.
    #[test]
    fn server_nonce_mismatch_is_bad_content_encoding() {
        let mut client = ScramClient::new(ScramMechanism::Sha256);
        client.set_client_nonce(RFC7677_CLIENT_NONCE);
        client.start(RFC7677_USER, RFC7677_PASS).expect("start");
        client.token(b"").expect("client-first");

        // Server nonce starts with someone else's nonce, not ours.
        let bad_first = "r=XXXXXXXXdeadbeef,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        let err = client.token(bad_first.as_bytes()).unwrap_err();
        assert_eq!(err, CurlError::BadContentEncoding);
    }

    /// `token` before `start` is a misuse and surfaces as an auth error.
    #[test]
    fn token_before_start_is_auth_error() {
        let mut client = ScramClient::new(ScramMechanism::Sha256);
        let err = client.token(b"").unwrap_err();
        assert_eq!(err, CurlError::AuthError);
    }

    /// An extra `token` call after completion is a protocol error.
    #[test]
    fn token_after_complete_is_bad_content_encoding() {
        let mut client = ScramClient::new(ScramMechanism::Sha256);
        client.set_client_nonce(RFC7677_CLIENT_NONCE);
        client.start(RFC7677_USER, RFC7677_PASS).expect("start");
        client.token(b"").expect("client-first");
        client
            .token(RFC7677_SERVER_FIRST.as_bytes())
            .expect("client-final");
        client
            .token(RFC7677_SERVER_FINAL.as_bytes())
            .expect("server-final");
        assert!(client.is_complete());

        let err = client.token(b"").unwrap_err();
        assert_eq!(err, CurlError::BadContentEncoding);
    }

    /// Malformed server-first messages each map to BAD_CONTENT_ENCODING.
    #[test]
    fn parse_server_first_rejects_malformed() {
        // Well-formed baseline parses.
        assert!(parse_server_first(RFC7677_SERVER_FIRST).is_ok());

        // Missing the iteration count.
        assert_eq!(
            parse_server_first("r=abc,s=W22ZaJ0SNY7soEsUEjb6gQ==").unwrap_err(),
            CurlError::BadContentEncoding
        );
        // Missing the salt.
        assert_eq!(
            parse_server_first("r=abc,i=4096").unwrap_err(),
            CurlError::BadContentEncoding
        );
        // Empty nonce.
        assert_eq!(
            parse_server_first("r=,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096").unwrap_err(),
            CurlError::BadContentEncoding
        );
        // Non-numeric iteration count.
        assert_eq!(
            parse_server_first("r=abc,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=xyz").unwrap_err(),
            CurlError::BadContentEncoding
        );
        // Zero iteration count.
        assert_eq!(
            parse_server_first("r=abc,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=0").unwrap_err(),
            CurlError::BadContentEncoding
        );
        // Invalid base64 salt (length 4 but illegal symbols).
        assert_eq!(
            parse_server_first("r=abc,s=!!!!,i=4096").unwrap_err(),
            CurlError::BadContentEncoding
        );
        // Reserved mandatory extension we do not understand: MUST abort.
        assert_eq!(
            parse_server_first("m=x,r=abc,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096").unwrap_err(),
            CurlError::BadContentEncoding
        );
        // A token without '='.
        assert_eq!(
            parse_server_first("r=abc,sW22ZaJ0SNY7soEsUEjb6gQ==,i=4096").unwrap_err(),
            CurlError::BadContentEncoding
        );
    }

    /// `parse_server_first` keeps base64 padding in the salt and a `=` inside the
    /// nonce intact (first-`=` splitting).
    #[test]
    fn parse_server_first_preserves_padding_and_nonce_equals() {
        let (nonce, salt, iters) =
            parse_server_first("r=ab=cd,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096").expect("parse");
        assert_eq!(nonce, "ab=cd");
        assert_eq!(iters, 4096);
        assert_eq!(salt.len(), 16);
    }

    /// `parse_server_final` decodes a verifier, reports an error attribute, and
    /// rejects anything else.
    #[test]
    fn parse_server_final_cases() {
        let sig = parse_server_final(RFC7677_SERVER_FINAL).expect("verifier");
        assert_eq!(sig.len(), 32);

        assert_eq!(
            parse_server_final("e=other-error").unwrap_err(),
            CurlError::LoginDenied
        );
        assert_eq!(
            parse_server_final("x=whatever").unwrap_err(),
            CurlError::BadContentEncoding
        );
        // Not valid base64 after v=.
        assert_eq!(
            parse_server_final("v=!!!").unwrap_err(),
            CurlError::BadContentEncoding
        );
    }

    /// `constant_time_eq` matches plain equality on equal/unequal/short inputs.
    #[test]
    fn constant_time_eq_semantics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }

    /// `xor32` is its own inverse: `(a ^ b) ^ b == a`.
    #[test]
    fn xor32_roundtrip() {
        let a = [0x5a_u8; 32];
        let b: [u8; 32] = core::array::from_fn(|i| i as u8);
        let x = xor32(&a, &b);
        assert_eq!(xor32(&x, &b), a);
    }

    /// Without a preset nonce, `start` generates a 32-char alphanumeric nonce and
    /// the produced client-first message is well-formed.
    #[test]
    fn generated_nonce_is_wellformed() {
        let mut client = ScramClient::new(ScramMechanism::Sha256);
        client.start("alice", "secret").expect("start");
        let client_first = client.token(b"").expect("client-first");
        let msg = to_str(&client_first);
        assert!(msg.starts_with("n,,n=alice,r="));
        let nonce = &msg["n,,n=alice,r=".len()..];
        assert_eq!(nonce.len(), CLIENT_NONCE_LEN);
        assert!(nonce.bytes().all(|b| b.is_ascii_alphanumeric()));
    }
}
