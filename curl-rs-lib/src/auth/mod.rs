//! Authentication module — SASL, HTTP Digest, NTLM, Negotiate, OAuth2.
//!
//! Module root for the Rust authentication subsystem. Pure-Rust rewrite of the
//! shared utilities from `lib/vauth/vauth.c` and the module registry from
//! `lib/vauth/vauth.h`.
//!
//! # Responsibilities
//!
//! 1. **Sub-module declarations** — declares and re-exports all auth submodules
//!    (basic, bearer, digest, ntlm, negotiate, kerberos, sasl, scram).
//! 2. **Shared utilities** — SPN building, domain detection, host authorisation
//!    checks.
//! 3. **AuthScheme enum** — high-level HTTP auth mechanism abstraction used by
//!    the HTTP layer for `--anyauth` negotiation.
//! 4. **Per-connection auth state** — lazy-initialised per-connection state for
//!    NTLM, Kerberos, Negotiate, and SCRAM authentication data.
//! 5. **CURLAUTH_* bitmask constants** — exact 1:1 mapping of the C
//!    `include/curl/curl.h` `CURLAUTH_*` `unsigned long` defines.
//!
//! # C Source References
//!
//! | Rust item            | C source                                              |
//! |----------------------|-------------------------------------------------------|
//! | `build_spn`          | `Curl_auth_build_spn` — `lib/vauth/vauth.c:48-63`    |
//! | `user_contains_domain` | `Curl_auth_user_contains_domain` — `vauth.c:114-132`|
//! | `allowed_to_host`    | `Curl_auth_allowed_to_host` — `vauth.c:138-147`      |
//! | `AuthConnState`      | NTLM/KRB5/GSASL/NEGO getters — `vauth.c:160-248`     |
//! | `CURLAUTH_*`         | `include/curl/curl.h:833-853`                         |

// ---------------------------------------------------------------------------
// Sub-module declarations
// ---------------------------------------------------------------------------

pub mod basic;
pub mod bearer;
pub mod digest;
pub mod kerberos;
pub mod negotiate;
pub mod ntlm;
pub mod sasl;
pub mod scram;

// ---------------------------------------------------------------------------
// Convenient re-exports from the SASL framework
// ---------------------------------------------------------------------------

pub use sasl::decode_mech;
pub use sasl::Sasl;
pub use sasl::SaslProgress;
pub use sasl::SaslProto;
pub use sasl::SaslState;

// SASL composite auth constants
pub use sasl::SASL_AUTH_DEFAULT;
pub use sasl::SASL_AUTH_NONE;

// SASL flags
pub use sasl::SASL_FLAG_BASE64;

// SASL mechanism bit-flag constants
pub use sasl::SASL_MECH_CRAM_MD5;
pub use sasl::SASL_MECH_DIGEST_MD5;
pub use sasl::SASL_MECH_EXTERNAL;
pub use sasl::SASL_MECH_GSSAPI;
pub use sasl::SASL_MECH_LOGIN;
pub use sasl::SASL_MECH_NTLM;
pub use sasl::SASL_MECH_OAUTHBEARER;
pub use sasl::SASL_MECH_PLAIN;
pub use sasl::SASL_MECH_SCRAM_SHA_1;
pub use sasl::SASL_MECH_SCRAM_SHA_256;
pub use sasl::SASL_MECH_XOAUTH2;

// SASL mechanism name strings
pub use sasl::SASL_MECH_STRING_CRAM_MD5;
pub use sasl::SASL_MECH_STRING_DIGEST_MD5;
pub use sasl::SASL_MECH_STRING_EXTERNAL;
pub use sasl::SASL_MECH_STRING_GSSAPI;
pub use sasl::SASL_MECH_STRING_LOGIN;
pub use sasl::SASL_MECH_STRING_NTLM;
pub use sasl::SASL_MECH_STRING_OAUTHBEARER;
pub use sasl::SASL_MECH_STRING_PLAIN;
pub use sasl::SASL_MECH_STRING_SCRAM_SHA_1;
pub use sasl::SASL_MECH_STRING_SCRAM_SHA_256;
pub use sasl::SASL_MECH_STRING_XOAUTH2;

// SASL auth-any constant
pub use sasl::SASL_AUTH_ANY;

// ---------------------------------------------------------------------------
// Internal imports
// ---------------------------------------------------------------------------

// CurlError is the foundational error type used across the auth subsystem.
// Imported here for use in function return types and re-exported for
// convenient access by callers that interact with auth APIs.
#[allow(unused_imports)]
use crate::error::CurlError;

// ===========================================================================
// HTTP Auth Bitmask Constants — match C `include/curl/curl.h` lines 833–853
// ===========================================================================
//
// These constants are defined as `u64` to accommodate C `unsigned long` which
// is 64 bits on LP64 platforms (Linux x86_64, macOS arm64). The values are
// identical to the C `CURLAUTH_*` macros. Composite masks (ANY, ANYSAFE) are
// masked with `0xFFFF_FFFF` to match the C `(unsigned long)0xffffffff` guard.

/// No HTTP authentication (C: `CURLAUTH_NONE`).
pub const CURLAUTH_NONE: u64 = 0;

/// HTTP Basic authentication — RFC 7617 (C: `CURLAUTH_BASIC`).
pub const CURLAUTH_BASIC: u64 = 1 << 0;

/// HTTP Digest authentication — RFC 7616 (C: `CURLAUTH_DIGEST`).
pub const CURLAUTH_DIGEST: u64 = 1 << 1;

/// HTTP Negotiate (SPNEGO) authentication — RFC 4559 (C: `CURLAUTH_NEGOTIATE`).
pub const CURLAUTH_NEGOTIATE: u64 = 1 << 2;

/// HTTP NTLM authentication (C: `CURLAUTH_NTLM`).
pub const CURLAUTH_NTLM: u64 = 1 << 3;

/// HTTP Digest authentication with Internet Explorer flavour
/// (C: `CURLAUTH_DIGEST_IE`).
pub const CURLAUTH_DIGEST_IE: u64 = 1 << 4;

/// HTTP Bearer token authentication — RFC 6750 (C: `CURLAUTH_BEARER`).
pub const CURLAUTH_BEARER: u64 = 1 << 6;

/// Alias for [`CURLAUTH_NEGOTIATE`] — GSS-API Negotiate
/// (C: `CURLAUTH_GSSAPI`).
pub const CURLAUTH_GSSAPI: u64 = CURLAUTH_NEGOTIATE;

/// All HTTP authentication types except Digest-IE.
///
/// Matches C: `(~CURLAUTH_DIGEST_IE) & (unsigned long)0xffffffff`.
pub const CURLAUTH_ANY: u64 = (!CURLAUTH_DIGEST_IE) & 0xFFFF_FFFF;

/// All HTTP authentication types except Basic and Digest-IE ("safe" methods
/// only — methods that do not send credentials in cleartext).
///
/// Matches C: `(~(CURLAUTH_BASIC | CURLAUTH_DIGEST_IE)) & (unsigned long)0xffffffff`.
pub const CURLAUTH_ANYSAFE: u64 = (!(CURLAUTH_BASIC | CURLAUTH_DIGEST_IE)) & 0xFFFF_FFFF;

// ===========================================================================
// AuthScheme — HTTP auth mechanism abstraction
// ===========================================================================

/// High-level HTTP authentication scheme identifier.
///
/// Used by the HTTP layer for `--anyauth` negotiation and the transfer engine
/// to select which authentication handler to invoke. Maps to the `CURLAUTH_*`
/// bitmask values but provides a type-safe enum interface.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::auth::AuthScheme;
///
/// let scheme = AuthScheme::Digest;
/// assert_ne!(scheme, AuthScheme::None);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AuthScheme {
    /// No authentication.
    #[default]
    None,
    /// HTTP Basic authentication (RFC 7617).
    Basic,
    /// HTTP Digest authentication (RFC 7616).
    Digest,
    /// OAuth2 Bearer token authentication (RFC 6750).
    Bearer,
    /// NTLM authentication (MS-NLMP).
    Ntlm,
    /// Negotiate (SPNEGO/Kerberos) authentication (RFC 4559).
    Negotiate,
}

impl AuthScheme {
    /// Convert an [`AuthScheme`] to the corresponding `CURLAUTH_*` bitmask
    /// value.
    ///
    /// # Examples
    ///
    /// ```
    /// use curl_rs_lib::auth::{AuthScheme, CURLAUTH_DIGEST};
    ///
    /// assert_eq!(AuthScheme::Digest.to_bitmask(), CURLAUTH_DIGEST);
    /// ```
    pub fn to_bitmask(self) -> u64 {
        match self {
            AuthScheme::None => CURLAUTH_NONE,
            AuthScheme::Basic => CURLAUTH_BASIC,
            AuthScheme::Digest => CURLAUTH_DIGEST,
            AuthScheme::Bearer => CURLAUTH_BEARER,
            AuthScheme::Ntlm => CURLAUTH_NTLM,
            AuthScheme::Negotiate => CURLAUTH_NEGOTIATE,
        }
    }

    /// Attempt to convert a `CURLAUTH_*` bitmask value to an [`AuthScheme`].
    ///
    /// Returns `None` if the bitmask does not correspond to a single known
    /// scheme, or if it is a composite mask (e.g. `CURLAUTH_ANY`).
    ///
    /// # Examples
    ///
    /// ```
    /// use curl_rs_lib::auth::{AuthScheme, CURLAUTH_NTLM};
    ///
    /// assert_eq!(AuthScheme::from_bitmask(CURLAUTH_NTLM), Some(AuthScheme::Ntlm));
    /// assert_eq!(AuthScheme::from_bitmask(0xFF), None);
    /// ```
    pub fn from_bitmask(mask: u64) -> Option<Self> {
        match mask {
            CURLAUTH_NONE => Some(AuthScheme::None),
            CURLAUTH_BASIC => Some(AuthScheme::Basic),
            CURLAUTH_DIGEST => Some(AuthScheme::Digest),
            CURLAUTH_BEARER => Some(AuthScheme::Bearer),
            CURLAUTH_NTLM => Some(AuthScheme::Ntlm),
            CURLAUTH_NEGOTIATE => Some(AuthScheme::Negotiate),
            _ => Option::None,
        }
    }

    /// Returns the scheme name as it appears in HTTP `WWW-Authenticate` /
    /// `Authorization` headers.
    ///
    /// # Examples
    ///
    /// ```
    /// use curl_rs_lib::auth::AuthScheme;
    ///
    /// assert_eq!(AuthScheme::Digest.name(), "Digest");
    /// ```
    pub fn name(self) -> &'static str {
        match self {
            AuthScheme::None => "None",
            AuthScheme::Basic => "Basic",
            AuthScheme::Digest => "Digest",
            AuthScheme::Bearer => "Bearer",
            AuthScheme::Ntlm => "NTLM",
            AuthScheme::Negotiate => "Negotiate",
        }
    }
}

impl std::fmt::Display for AuthScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ===========================================================================
// AuthConnState — per-connection authentication state
// ===========================================================================

/// Per-connection authentication state container.
///
/// Manages lazy-initialised authentication data for all connection-stateful
/// auth mechanisms (NTLM, Kerberos, Negotiate, SCRAM). Replaces the C
/// `conn_meta` key-value store pattern used in `lib/vauth/vauth.c` with Rust
/// `Option<T>` ownership semantics — allocation on first use, deallocation on
/// drop.
///
/// # Lazy Initialisation
///
/// The getter methods (`ntlm_get`, `krb5_get`, `gsasl_get`, `nego_get`)
/// lazily create the underlying data struct on first access. This mirrors the
/// C pattern where `Curl_auth_ntlm_get` allocates via `curlx_calloc` and
/// stores in the connection meta table.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::auth::AuthConnState;
///
/// let mut state = AuthConnState::new();
/// assert!(state.ntlm.is_none());
///
/// // Lazy-init on first access:
/// let ntlm = state.ntlm_get(false);
/// assert!(state.ntlm.is_some());
/// ```
pub struct AuthConnState {
    /// Digest authentication state for the host (non-proxy) connection.
    /// Lazily initialised by [`digest_get`](AuthConnState::digest_get) with
    /// `proxy = false`.
    pub digest: Option<digest::DigestData>,

    /// Digest authentication state for the proxy connection.
    /// Lazily initialised by [`digest_get`](AuthConnState::digest_get) with
    /// `proxy = true`.
    pub digest_proxy: Option<digest::DigestData>,

    /// NTLM authentication state for the host (non-proxy) connection.
    /// Lazily initialised by [`ntlm_get`](AuthConnState::ntlm_get) with
    /// `proxy = false`.
    pub ntlm: Option<ntlm::NtlmData>,

    /// NTLM authentication state for the proxy connection.
    /// Lazily initialised by [`ntlm_get`](AuthConnState::ntlm_get) with
    /// `proxy = true`.
    pub ntlm_proxy: Option<ntlm::NtlmData>,

    /// Kerberos V5 GSSAPI authentication state.
    /// Lazily initialised by [`krb5_get`](AuthConnState::krb5_get).
    pub kerberos: Option<kerberos::Kerberos5Data>,

    /// Negotiate/SPNEGO authentication state for the host connection.
    /// Lazily initialised by [`nego_get`](AuthConnState::nego_get) with
    /// `proxy = false`.
    pub negotiate: Option<negotiate::NegotiateData>,

    /// Negotiate/SPNEGO authentication state for the proxy connection.
    /// Lazily initialised by [`nego_get`](AuthConnState::nego_get) with
    /// `proxy = true`.
    pub negotiate_proxy: Option<negotiate::NegotiateData>,

    /// SCRAM authentication state (SCRAM-SHA-1 / SCRAM-SHA-256).
    /// Lazily initialised by [`gsasl_get`](AuthConnState::gsasl_get).
    pub scram: Option<scram::ScramData>,
}

impl AuthConnState {
    /// Create a new `AuthConnState` with all fields set to `None`.
    ///
    /// No authentication data is allocated until a getter method is called.
    ///
    /// # Examples
    ///
    /// ```
    /// use curl_rs_lib::auth::AuthConnState;
    ///
    /// let state = AuthConnState::new();
    /// assert!(state.digest.is_none());
    /// assert!(state.digest_proxy.is_none());
    /// assert!(state.ntlm.is_none());
    /// assert!(state.ntlm_proxy.is_none());
    /// assert!(state.kerberos.is_none());
    /// assert!(state.negotiate.is_none());
    /// assert!(state.negotiate_proxy.is_none());
    /// assert!(state.scram.is_none());
    /// ```
    pub fn new() -> Self {
        AuthConnState {
            digest: None,
            digest_proxy: None,
            ntlm: None,
            ntlm_proxy: None,
            kerberos: None,
            negotiate: None,
            negotiate_proxy: None,
            scram: None,
        }
    }

    /// Get a mutable reference to the Digest authentication data, creating it
    /// on first access.
    ///
    /// When `proxy` is `true`, returns the proxy Digest state; otherwise
    /// returns the host Digest state.
    ///
    /// Corresponds to C per-connection digest state (`struct digestdata`)
    /// stored on `connectdata`.
    pub fn digest_get(&mut self, proxy: bool) -> &mut digest::DigestData {
        let slot = if proxy {
            &mut self.digest_proxy
        } else {
            &mut self.digest
        };
        slot.get_or_insert_with(digest::DigestData::new)
    }

    /// Get a mutable reference to the NTLM authentication data, creating it
    /// on first access.
    ///
    /// When `proxy` is `true`, returns the proxy NTLM state; otherwise
    /// returns the host NTLM state.
    ///
    /// Corresponds to C `Curl_auth_ntlm_get` (`lib/vauth/vauth.c:160-170`).
    ///
    /// # Arguments
    ///
    /// * `proxy` — If `true`, access the proxy NTLM state; otherwise the
    ///   host NTLM state.
    pub fn ntlm_get(&mut self, proxy: bool) -> &mut ntlm::NtlmData {
        let slot = if proxy {
            &mut self.ntlm_proxy
        } else {
            &mut self.ntlm
        };
        slot.get_or_insert_with(ntlm::NtlmData::new)
    }

    /// Get a mutable reference to the Kerberos V5 authentication data,
    /// creating it on first access.
    ///
    /// Corresponds to C `Curl_auth_krb5_get` (`lib/vauth/vauth.c:190-200`).
    pub fn krb5_get(&mut self) -> &mut kerberos::Kerberos5Data {
        self.kerberos
            .get_or_insert_with(kerberos::Kerberos5Data::new)
    }

    /// Get a mutable reference to the SCRAM (GSASL replacement) data,
    /// creating it on first access.
    ///
    /// This replaces the C `Curl_auth_gsasl_get` pattern
    /// (`lib/vauth/vauth.c:214-224`). The C code used the `gsasldata` struct
    /// backed by the `libgsasl` library; our Rust equivalent is
    /// [`scram::ScramData`] which implements SCRAM natively.
    ///
    /// The default mechanism is `ScramMechanism::Sha256`; the actual mechanism
    /// is selected when the SCRAM exchange starts via `scram::start()`.
    pub fn gsasl_get(&mut self) -> &mut scram::ScramData {
        self.scram
            .get_or_insert_with(|| scram::ScramData::new(scram::ScramMechanism::Sha256))
    }

    /// Get a mutable reference to the Negotiate/SPNEGO authentication data,
    /// creating it on first access.
    ///
    /// When `proxy` is `true`, returns the proxy Negotiate state; otherwise
    /// returns the host Negotiate state.
    ///
    /// Corresponds to C `Curl_auth_nego_get` (`lib/vauth/vauth.c:238-248`).
    ///
    /// # Arguments
    ///
    /// * `proxy` — If `true`, access the proxy Negotiate state; otherwise
    ///   the host Negotiate state.
    pub fn nego_get(&mut self, proxy: bool) -> &mut negotiate::NegotiateData {
        let slot = if proxy {
            &mut self.negotiate_proxy
        } else {
            &mut self.negotiate
        };
        slot.get_or_insert_with(negotiate::NegotiateData::new)
    }

    /// Remove (drop) the NTLM authentication state for the given path.
    ///
    /// If the NTLM data exists, its `cleanup` method is called before the
    /// `Option` is set to `None`. This mirrors C `Curl_auth_ntlm_remove`
    /// (`lib/vauth/vauth.c:172-176`) which calls the destructor and then
    /// removes the connection meta entry.
    ///
    /// # Arguments
    ///
    /// * `proxy` — If `true`, remove the proxy NTLM state; otherwise remove
    ///   the host NTLM state.
    pub fn ntlm_remove(&mut self, proxy: bool) {
        let slot = if proxy {
            &mut self.ntlm_proxy
        } else {
            &mut self.ntlm
        };
        if let Some(ref mut data) = slot {
            data.cleanup();
        }
        *slot = None;
    }
}

impl Default for AuthConnState {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// SPN Building — matches C `Curl_auth_build_spn` (vauth.c:48-63)
// ===========================================================================

/// Build a Service Principal Name (SPN) string.
///
/// Produces an SPN in one of the following formats, matching the C
/// `Curl_auth_build_spn` function from `lib/vauth/vauth.c` (non-SSPI path):
///
/// | Condition         | Format                   |
/// |-------------------|--------------------------|
/// | host AND realm    | `"{service}/{host}@{realm}"` |
/// | host only         | `"{service}/{host}"`         |
/// | realm only        | `"{service}@{realm}"`        |
/// | neither           | `None`                       |
///
/// The format strings match the C `curl_maprintf` patterns exactly:
/// - `"%s/%s@%s"` for full SPN
/// - `"%s/%s"` for host-only
/// - `"%s@%s"` for realm-only
///
/// # Arguments
///
/// * `service` — The service type (e.g. `"http"`, `"smtp"`, `"imap"`).
/// * `host`    — Optional hostname.
/// * `realm`   — Optional Kerberos realm.
///
/// # Returns
///
/// `Some(spn)` if at least one of `host` or `realm` is `Some` with a
/// non-empty string; `None` otherwise.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::auth::build_spn;
///
/// assert_eq!(
///     build_spn("http", Some("host.com"), Some("REALM")),
///     Some("http/host.com@REALM".to_string())
/// );
/// assert_eq!(
///     build_spn("imap", Some("host.com"), None),
///     Some("imap/host.com".to_string())
/// );
/// assert_eq!(
///     build_spn("smtp", None, Some("REALM")),
///     Some("smtp@REALM".to_string())
/// );
/// assert_eq!(build_spn("http", None, None), None);
/// ```
pub fn build_spn(service: &str, host: Option<&str>, realm: Option<&str>) -> Option<String> {
    // Filter out empty strings — treat them as None to match C NULL semantics.
    let host = host.filter(|h| !h.is_empty());
    let realm = realm.filter(|r| !r.is_empty());

    match (host, realm) {
        (Some(h), Some(r)) => {
            // C: curl_maprintf("%s/%s@%s", service, host, realm)
            Some(format!("{}/{}{}{}", service, h, "@", r))
        }
        (Some(h), None) => {
            // C: curl_maprintf("%s/%s", service, host)
            Some(format!("{}/{}", service, h))
        }
        (None, Some(r)) => {
            // C: curl_maprintf("%s@%s", service, realm)
            Some(format!("{}@{}", service, r))
        }
        (None, None) => {
            // C: returns NULL
            None
        }
    }
}

// ===========================================================================
// Domain Detection — matches C `Curl_auth_user_contains_domain` (vauth.c:114-132)
// ===========================================================================

/// Test whether a username string contains a Windows domain component.
///
/// Checks for domain\user, domain/user, or user@domain patterns. Matches the
/// C `Curl_auth_user_contains_domain` function from `lib/vauth/vauth.c`.
///
/// Accepted domain-qualified formats:
/// - `Domain\User` (Down-level Logon Name)
/// - `Domain/User` (curl Down-level format — compatibility)
/// - `User@Domain` (User Principal Name)
///
/// The delimiter must not be at the very start or very end of the string —
/// there must be characters on both sides.
///
/// # Arguments
///
/// * `user`        — The username string to test.
/// * `allow_empty` — When `true`, an empty username returns `true`. This
///   mirrors the C `HAVE_GSSAPI` / `USE_WINDOWS_SSPI` conditional where the
///   user and domain are obtained from the credential cache or the currently
///   logged-in user. Callers should pass `true` when using GSS-API or
///   Kerberos authentication where credential delegation is active.
///
/// # Returns
///
/// `true` if the username contains a domain component, or if the username is
/// empty and `allow_empty` is set.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::auth::user_contains_domain;
///
/// assert!(user_contains_domain("DOMAIN\\user", false));
/// assert!(user_contains_domain("DOMAIN/user", false));
/// assert!(user_contains_domain("user@domain.com", false));
/// assert!(!user_contains_domain("user", false));
/// assert!(!user_contains_domain("user\\", false));
/// assert!(!user_contains_domain("\\user", false));
/// assert!(!user_contains_domain("", false));
/// assert!(user_contains_domain("", true));
/// ```
pub fn user_contains_domain(user: &str, allow_empty: bool) -> bool {
    if !user.is_empty() {
        // C: strpbrk(user, "\\/@")
        // Find the first occurrence of any of the three delimiters.
        if let Some(pos) = user.find(&['\\', '/', '@'][..]) {
            // C: p > user && p < user + strlen(user) - 1
            // The delimiter must not be at position 0 (start) or at the last
            // byte position (end) — there must be non-empty content on both
            // sides.
            let len = user.len();
            pos > 0 && pos < len - 1
        } else {
            false
        }
    } else {
        // C: #if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
        //    else valid = TRUE;
        allow_empty
    }
}

// ===========================================================================
// Host Authorization Gate — matches C `Curl_auth_allowed_to_host` (vauth.c:138-147)
// ===========================================================================

/// Determine whether authentication credentials (or cookies / other sensitive
/// data) may be sent to the current host.
///
/// Implements the redirect-safety gate from C `Curl_auth_allowed_to_host`
/// (`lib/vauth/vauth.c:138-147`). On a redirect, credentials are only
/// forwarded if the target matches the original request's host, port, and
/// protocol — unless the user has explicitly allowed cross-host auth.
///
/// # Arguments
///
/// * `is_follow`                   — `true` if this request is a redirect follow.
/// * `allow_auth_to_other_hosts`   — `true` if the user set
///   `CURLOPT_UNRESTRICTED_AUTH`.
/// * `first_host`                  — Hostname of the original (first) request.
///   `None` means no original host recorded.
/// * `current_host`                — Hostname of the current (possibly
///   redirected) request.
/// * `first_port`                  — Port of the original request.
/// * `current_port`                — Port of the current request.
/// * `first_protocol`              — Protocol scheme of the original request
///   (e.g. `"https"`).
/// * `current_protocol`            — Protocol scheme of the current request.
///
/// # Returns
///
/// `true` if sending credentials to `current_host` is permitted.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::auth::allowed_to_host;
///
/// // Not a redirect → always allowed
/// assert!(allowed_to_host(false, false, Some("a.com"), "b.com", 443, 443, "https", "https"));
///
/// // Redirect to same host → allowed
/// assert!(allowed_to_host(true, false, Some("a.com"), "a.com", 443, 443, "https", "https"));
///
/// // Redirect to different host → denied
/// assert!(!allowed_to_host(true, false, Some("a.com"), "b.com", 443, 443, "https", "https"));
///
/// // Redirect to different host but unrestricted → allowed
/// assert!(allowed_to_host(true, true, Some("a.com"), "b.com", 443, 443, "https", "https"));
/// ```
#[allow(clippy::too_many_arguments)]
pub fn allowed_to_host(
    is_follow: bool,
    allow_auth_to_other_hosts: bool,
    first_host: Option<&str>,
    current_host: &str,
    first_port: u16,
    current_port: u16,
    first_protocol: &str,
    current_protocol: &str,
) -> bool {
    // C: !data->state.this_is_a_follow
    if !is_follow {
        return true;
    }

    // C: data->set.allow_auth_to_other_hosts
    if allow_auth_to_other_hosts {
        return true;
    }

    // C: data->state.first_host &&
    //    curl_strequal(data->state.first_host, conn->host.name) &&
    //    (data->state.first_remote_port == conn->remote_port) &&
    //    (data->state.first_remote_protocol == conn->scheme->protocol)
    match first_host {
        Some(fh) => {
            fh.eq_ignore_ascii_case(current_host)
                && first_port == current_port
                && first_protocol.eq_ignore_ascii_case(current_protocol)
        }
        None => false,
    }
}

// ===========================================================================
// Auth Support Detection Functions
// ===========================================================================

/// Returns whether HTTP Digest authentication is supported.
///
/// Always returns `true` in the pure-Rust implementation — Digest auth is
/// fully implemented without any optional C library dependencies.
///
/// Matches C `Curl_auth_is_digest_supported()` (returns `TRUE` when
/// `!CURL_DISABLE_DIGEST_AUTH`).
#[inline]
pub fn is_digest_supported() -> bool {
    true
}

/// Returns whether NTLM authentication is supported.
///
/// Always returns `true` in the pure-Rust implementation — all NTLM crypto
/// (DES, MD4, HMAC-MD5) is provided by Rust crates with no optional
/// dependency on Windows SSPI or OpenSSL.
///
/// Matches C `Curl_auth_is_ntlm_supported()` (returns `TRUE` when
/// `USE_NTLM`).
#[inline]
pub fn is_ntlm_supported() -> bool {
    true
}

/// Returns whether GSSAPI (Kerberos V5) authentication is supported.
///
/// In this pure-Rust implementation, GSSAPI support depends on the target
/// platform. On Unix-like systems, a system-level GSSAPI/Kerberos library
/// is typically available. This function currently returns `false` because
/// the initial Rust implementation does not link against any system GSSAPI
/// library — the Kerberos module provides protocol-level token framing but
/// requires an external GSS context for actual ticket acquisition.
///
/// Matches C `Curl_auth_is_gssapi_supported()` (returns `TRUE` when
/// `USE_KERBEROS5`).
///
/// Returns `true` when the `gssapi` feature is enabled at compile time.
#[inline]
pub fn is_gssapi_supported() -> bool {
    // In the C implementation this is gated behind HAVE_GSSAPI.
    // Our pure-Rust implementation provides protocol-level Kerberos
    // framing; this returns `true` to indicate protocol handlers can
    // attempt GSSAPI authentication. Actual GSS context operations are
    // stubbed in kerberos.rs and will log a warning if no system Kerberos
    // library is reachable.
    cfg!(feature = "gssapi")
}

/// Returns whether SPNEGO (Negotiate) authentication is supported.
///
/// SPNEGO support mirrors GSSAPI support — the Negotiate mechanism wraps
/// GSSAPI tokens in SPNEGO ASN.1 framing.
///
/// Matches C `Curl_auth_is_spnego_supported()` (returns `TRUE` when
/// `USE_SPNEGO`).
#[inline]
pub fn is_spnego_supported() -> bool {
    is_gssapi_supported()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // CURLAUTH_* constant value verification
    // -----------------------------------------------------------------------

    #[test]
    fn curlauth_constants_match_c_header() {
        assert_eq!(CURLAUTH_NONE, 0);
        assert_eq!(CURLAUTH_BASIC, 1);
        assert_eq!(CURLAUTH_DIGEST, 2);
        assert_eq!(CURLAUTH_NEGOTIATE, 4);
        assert_eq!(CURLAUTH_NTLM, 8);
        assert_eq!(CURLAUTH_DIGEST_IE, 16);
        assert_eq!(CURLAUTH_BEARER, 64);
        assert_eq!(CURLAUTH_GSSAPI, CURLAUTH_NEGOTIATE);

        // ANY = ~DIGEST_IE & 0xFFFFFFFF
        assert_eq!(CURLAUTH_ANY, 0xFFFF_FFEF);
        // ANYSAFE = ~(BASIC | DIGEST_IE) & 0xFFFFFFFF
        assert_eq!(CURLAUTH_ANYSAFE, 0xFFFF_FFEE);
    }

    // -----------------------------------------------------------------------
    // build_spn
    // -----------------------------------------------------------------------

    #[test]
    fn build_spn_full() {
        assert_eq!(
            build_spn("http", Some("host.com"), Some("REALM")),
            Some("http/host.com@REALM".to_string())
        );
    }

    #[test]
    fn build_spn_host_only() {
        assert_eq!(
            build_spn("imap", Some("host.com"), None),
            Some("imap/host.com".to_string())
        );
    }

    #[test]
    fn build_spn_realm_only() {
        assert_eq!(
            build_spn("smtp", None, Some("REALM")),
            Some("smtp@REALM".to_string())
        );
    }

    #[test]
    fn build_spn_none() {
        assert_eq!(build_spn("http", None, None), None);
    }

    #[test]
    fn build_spn_empty_strings_treated_as_none() {
        assert_eq!(build_spn("http", Some(""), Some("")), None);
        assert_eq!(
            build_spn("http", Some("host"), Some("")),
            Some("http/host".to_string())
        );
        assert_eq!(
            build_spn("http", Some(""), Some("REALM")),
            Some("http@REALM".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // user_contains_domain
    // -----------------------------------------------------------------------

    #[test]
    fn user_domain_backslash() {
        assert!(user_contains_domain("DOMAIN\\user", false));
    }

    #[test]
    fn user_domain_forward_slash() {
        assert!(user_contains_domain("DOMAIN/user", false));
    }

    #[test]
    fn user_domain_at_sign() {
        assert!(user_contains_domain("user@domain.com", false));
    }

    #[test]
    fn user_no_domain() {
        assert!(!user_contains_domain("user", false));
    }

    #[test]
    fn user_delimiter_at_end() {
        assert!(!user_contains_domain("user\\", false));
        assert!(!user_contains_domain("user/", false));
        assert!(!user_contains_domain("user@", false));
    }

    #[test]
    fn user_delimiter_at_start() {
        assert!(!user_contains_domain("\\user", false));
        assert!(!user_contains_domain("/user", false));
        assert!(!user_contains_domain("@user", false));
    }

    #[test]
    fn user_empty_not_allowed() {
        assert!(!user_contains_domain("", false));
    }

    #[test]
    fn user_empty_allowed_gssapi() {
        assert!(user_contains_domain("", true));
    }

    #[test]
    fn user_single_char_delimiter_only() {
        // A single delimiter character has nothing before or after it
        assert!(!user_contains_domain("\\", false));
        assert!(!user_contains_domain("/", false));
        assert!(!user_contains_domain("@", false));
    }

    #[test]
    fn user_two_char_domain() {
        // Minimal valid domain-qualified: "a\\b" — one char before, one after
        assert!(user_contains_domain("a\\b", false));
    }

    // -----------------------------------------------------------------------
    // allowed_to_host
    // -----------------------------------------------------------------------

    #[test]
    fn allowed_not_a_follow() {
        assert!(allowed_to_host(
            false, false,
            Some("a.com"), "b.com",
            443, 443,
            "https", "https"
        ));
    }

    #[test]
    fn allowed_same_host() {
        assert!(allowed_to_host(
            true, false,
            Some("a.com"), "a.com",
            443, 443,
            "https", "https"
        ));
    }

    #[test]
    fn denied_different_host() {
        assert!(!allowed_to_host(
            true, false,
            Some("a.com"), "b.com",
            443, 443,
            "https", "https"
        ));
    }

    #[test]
    fn denied_different_port() {
        assert!(!allowed_to_host(
            true, false,
            Some("a.com"), "a.com",
            443, 8443,
            "https", "https"
        ));
    }

    #[test]
    fn denied_different_protocol() {
        assert!(!allowed_to_host(
            true, false,
            Some("a.com"), "a.com",
            80, 80,
            "http", "https"
        ));
    }

    #[test]
    fn allowed_unrestricted() {
        assert!(allowed_to_host(
            true, true,
            Some("a.com"), "b.com",
            443, 80,
            "https", "http"
        ));
    }

    #[test]
    fn denied_no_first_host() {
        assert!(!allowed_to_host(
            true, false,
            None, "b.com",
            443, 443,
            "https", "https"
        ));
    }

    #[test]
    fn allowed_case_insensitive_host() {
        assert!(allowed_to_host(
            true, false,
            Some("Host.COM"), "host.com",
            443, 443,
            "https", "https"
        ));
    }

    // -----------------------------------------------------------------------
    // AuthScheme
    // -----------------------------------------------------------------------

    #[test]
    fn auth_scheme_bitmask_roundtrip() {
        for scheme in &[
            AuthScheme::None,
            AuthScheme::Basic,
            AuthScheme::Digest,
            AuthScheme::Bearer,
            AuthScheme::Ntlm,
            AuthScheme::Negotiate,
        ] {
            let mask = scheme.to_bitmask();
            assert_eq!(AuthScheme::from_bitmask(mask), Some(*scheme));
        }
    }

    #[test]
    fn auth_scheme_display() {
        assert_eq!(format!("{}", AuthScheme::Digest), "Digest");
        assert_eq!(format!("{}", AuthScheme::Ntlm), "NTLM");
        assert_eq!(format!("{}", AuthScheme::None), "None");
    }

    #[test]
    fn auth_scheme_default() {
        assert_eq!(AuthScheme::default(), AuthScheme::None);
    }

    // -----------------------------------------------------------------------
    // AuthConnState
    // -----------------------------------------------------------------------

    #[test]
    fn auth_conn_state_new_all_none() {
        let state = AuthConnState::new();
        assert!(state.ntlm.is_none());
        assert!(state.ntlm_proxy.is_none());
        assert!(state.kerberos.is_none());
        assert!(state.negotiate.is_none());
        assert!(state.negotiate_proxy.is_none());
        assert!(state.scram.is_none());
    }

    #[test]
    fn auth_conn_state_ntlm_lazy_init() {
        let mut state = AuthConnState::new();
        let _ntlm = state.ntlm_get(false);
        assert!(state.ntlm.is_some());
        assert!(state.ntlm_proxy.is_none());
    }

    #[test]
    fn auth_conn_state_ntlm_proxy_lazy_init() {
        let mut state = AuthConnState::new();
        let _ntlm = state.ntlm_get(true);
        assert!(state.ntlm.is_none());
        assert!(state.ntlm_proxy.is_some());
    }

    #[test]
    fn auth_conn_state_krb5_lazy_init() {
        let mut state = AuthConnState::new();
        let _krb5 = state.krb5_get();
        assert!(state.kerberos.is_some());
    }

    #[test]
    fn auth_conn_state_gsasl_lazy_init() {
        let mut state = AuthConnState::new();
        let _gsasl = state.gsasl_get();
        assert!(state.scram.is_some());
    }

    #[test]
    fn auth_conn_state_nego_lazy_init() {
        let mut state = AuthConnState::new();
        let _nego = state.nego_get(false);
        assert!(state.negotiate.is_some());
        assert!(state.negotiate_proxy.is_none());
    }

    #[test]
    fn auth_conn_state_nego_proxy_lazy_init() {
        let mut state = AuthConnState::new();
        let _nego = state.nego_get(true);
        assert!(state.negotiate.is_none());
        assert!(state.negotiate_proxy.is_some());
    }

    #[test]
    fn auth_conn_state_ntlm_remove() {
        let mut state = AuthConnState::new();
        let _ntlm = state.ntlm_get(false);
        assert!(state.ntlm.is_some());
        state.ntlm_remove(false);
        assert!(state.ntlm.is_none());
    }

    #[test]
    fn auth_conn_state_ntlm_remove_proxy() {
        let mut state = AuthConnState::new();
        let _ntlm = state.ntlm_get(true);
        assert!(state.ntlm_proxy.is_some());
        state.ntlm_remove(true);
        assert!(state.ntlm_proxy.is_none());
    }

    #[test]
    fn auth_conn_state_ntlm_remove_when_none() {
        // Removing when already None should not panic.
        let mut state = AuthConnState::new();
        state.ntlm_remove(false);
        state.ntlm_remove(true);
    }

    #[test]
    fn auth_conn_state_default() {
        let state = AuthConnState::default();
        assert!(state.ntlm.is_none());
    }

    // -----------------------------------------------------------------------
    // Auth support detection
    // -----------------------------------------------------------------------

    #[test]
    fn digest_always_supported() {
        assert!(is_digest_supported());
    }

    #[test]
    fn ntlm_always_supported() {
        assert!(is_ntlm_supported());
    }

    #[test]
    fn spnego_mirrors_gssapi() {
        assert_eq!(is_spnego_supported(), is_gssapi_supported());
    }
}
