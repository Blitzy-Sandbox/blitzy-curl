//! Authentication mechanisms (Basic, Digest, Bearer, NTLM, Negotiate/Kerberos, SASL, SCRAM). Ported from curl `lib/vauth/`.
//!
//! This module is the **root** of the authentication subsystem. It is a language
//! rewrite of the curl 8.19.0-DEV files `lib/vauth/vauth.c` (implementation) and
//! `lib/vauth/vauth.h` (contract). It owns the pieces that are shared across every
//! mechanism:
//!
//! * the frozen [`CURLAUTH_NONE`]..[`CURLAUTH_ANYSAFE`] capability bitmask
//!   (transcribed verbatim from `include/curl/curl.h`), so an FFI consumer that
//!   relies on `CURLAUTH_BASIC == 1` keeps working;
//! * the per-host / per-proxy [`Auth`] negotiation-state struct (from
//!   `struct auth` in `lib/urldata.h`);
//! * the per-connection owned auth state [`ConnAuthState`], which replaces curl's
//!   generic connection meta-hashmap plus manual C destructors with plain owned
//!   `Option` fields (Rust's ownership + `Drop` do the cleanup);
//! * the shared helper functions [`build_spn`], [`user_contains_domain`], and
//!   [`allowed_to_host`], ported byte-for-byte from `vauth.c`;
//! * the [`AuthMechanism`] dispatch trait and the [`pick_strongest`] negotiation
//!   routine (mirroring `pickoneauth()` in `lib/http.c`), which the HTTP layer and
//!   the SASL engine use to select a single mechanism.
//!
//! # Design notes (parity with curl 8.x)
//!
//! * The Windows SSPI code paths of `vauth.c` are intentionally **collapsed**;
//!   only the `#ifndef USE_WINDOWS_SSPI` (pure) logic is reproduced here, matching
//!   the AAP decision to drop the Windows backend.
//! * The optional GSSAPI (Kerberos) and SPNEGO (Negotiate) portions live behind
//!   the `gssapi` / `spnego` Cargo features. The child-module declarations below
//!   are always present — when a feature is off, the module simply exposes an
//!   "unsupported" stub — but this file never `#[cfg]`-gates the `pub mod` lines.
//! * This module is written entirely in safe Rust; the crate root forbids the
//!   escape-hatch keyword crate-wide, and a CI grep audit enforces that no such
//!   blocks appear anywhere in this subtree.

// ---------------------------------------------------------------------------
// Phase A — child module declarations
// ---------------------------------------------------------------------------
// The eight sibling modules that together form the auth subtree. These names map
// 1:1 to the AAP §0.3.1 layout. `kerberos` and `negotiate` feature-gate only
// their optional-GSSAPI internals; the module declarations themselves are always
// unconditional so the modules (and their "unsupported" stubs) always exist.
pub mod basic;
pub mod bearer;
pub mod digest;
pub mod kerberos;
pub mod negotiate;
pub mod ntlm;
pub mod sasl;
pub mod scram;

// ---------------------------------------------------------------------------
// Phase B — CURLAUTH_* capability bitmask (frozen ABI values)
// ---------------------------------------------------------------------------
// Transcribed verbatim from `include/curl/curl.h` (lines 828-848). These integer
// values are a FROZEN ABI contract: FFI consumers hard-code them (e.g.
// `CURLAUTH_BASIC == 1`), so they must never change. They are represented as
// `u32` to match the `uint32_t want/picked/avail` fields of `struct auth`; the
// FFI crate widens them to `unsigned long` at the C boundary.

/// No HTTP authentication (`CURLAUTH_NONE`).
pub const CURLAUTH_NONE: u32 = 0;
/// HTTP Basic authentication (`CURLAUTH_BASIC`) — the default when credentials
/// are supplied.
pub const CURLAUTH_BASIC: u32 = 1 << 0;
/// HTTP Digest authentication (`CURLAUTH_DIGEST`).
pub const CURLAUTH_DIGEST: u32 = 1 << 1;
/// HTTP Negotiate (SPNEGO) authentication (`CURLAUTH_NEGOTIATE`).
pub const CURLAUTH_NEGOTIATE: u32 = 1 << 2;
/// Deprecated alias of [`CURLAUTH_NEGOTIATE`], kept for ABI compatibility
/// (`CURLAUTH_GSSNEGOTIATE`).
pub const CURLAUTH_GSSNEGOTIATE: u32 = CURLAUTH_NEGOTIATE;
/// Alias of [`CURLAUTH_NEGOTIATE`] used by `CURLOPT_SOCKS5_AUTH` for
/// terminological correctness (`CURLAUTH_GSSAPI`).
pub const CURLAUTH_GSSAPI: u32 = CURLAUTH_NEGOTIATE;
/// HTTP NTLM authentication (`CURLAUTH_NTLM`).
pub const CURLAUTH_NTLM: u32 = 1 << 3;
/// HTTP Digest authentication with an IE flavour (`CURLAUTH_DIGEST_IE`).
pub const CURLAUTH_DIGEST_IE: u32 = 1 << 4;
/// HTTP NTLM authentication delegated to a winbind helper (`CURLAUTH_NTLM_WB`).
///
/// The winbind helper backend was removed from curl in 8.8.0 and is **not**
/// implemented here; the bit is preserved purely for ABI parity. It selects
/// nothing beyond ordinary NTLM-style negotiation.
pub const CURLAUTH_NTLM_WB: u32 = 1 << 5;
/// HTTP Bearer-token authentication (`CURLAUTH_BEARER`).
pub const CURLAUTH_BEARER: u32 = 1 << 6;
/// AWS Signature V4 authentication (`CURLAUTH_AWS_SIGV4`).
pub const CURLAUTH_AWS_SIGV4: u32 = 1 << 7;
/// Modifier bit: use only the single companion type and force no other type to
/// be attempted (`CURLAUTH_ONLY`).
pub const CURLAUTH_ONLY: u32 = 1 << 31;
/// All "fine" auth types (`CURLAUTH_ANY`).
///
/// Mirrors the C macro `((~CURLAUTH_DIGEST_IE) & 0xffffffff)`. Because these
/// constants are `u32`, `!CURLAUTH_DIGEST_IE` is already masked to 32 bits, so
/// the explicit `& 0xffffffff` from the C source is a no-op and is omitted. The
/// value is `0xFFFF_FFEF` (every bit except the IE-flavour bit).
pub const CURLAUTH_ANY: u32 = !CURLAUTH_DIGEST_IE;
/// All "fine" auth types except Basic (`CURLAUTH_ANYSAFE`).
///
/// Mirrors the C macro `((~(CURLAUTH_BASIC | CURLAUTH_DIGEST_IE)) & 0xffffffff)`.
/// As with [`CURLAUTH_ANY`], the 32-bit mask is implicit for `u32`. The value is
/// `0xFFFF_FFEE`.
pub const CURLAUTH_ANYSAFE: u32 = !(CURLAUTH_BASIC | CURLAUTH_DIGEST_IE);

// ---------------------------------------------------------------------------
// Phase C — per-host / per-proxy auth negotiation state
// ---------------------------------------------------------------------------

/// Per-host or per-proxy authentication negotiation state.
///
/// Ported from `struct auth` in `lib/urldata.h`. There is one instance for the
/// origin host (`CURLOPT_HTTPAUTH`) and one for the proxy (`CURLOPT_PROXYAUTH`).
/// The C `BIT(x)` bitfields become plain `bool`s; the field names are preserved
/// so cross-module code and `--trace` diagnostics stay recognizable.
#[derive(Debug, Default, Clone)]
pub struct Auth {
    /// Methods wanted, from `CURLOPT_HTTPAUTH` / `CURLOPT_PROXYAUTH`
    /// (a `CURLAUTH_*` bitmask).
    pub want: u32,
    /// The single method actually picked for this exchange (a `CURLAUTH_*` bit).
    pub picked: u32,
    /// Bitmask of the methods the server reports supporting.
    pub avail: u32,
    /// `true` once the auth phase is complete and the real request may proceed.
    pub done: bool,
    /// `true` while not yet authenticated but within a multi-pass negotiation
    /// (e.g. NTLM / Negotiate).
    pub multipass: bool,
    /// `true` if Digest should use the IE-compatible style rather than being
    /// strictly RFC compliant.
    pub iestyle: bool,
}

// ---------------------------------------------------------------------------
// Phase D — shared helper functions (ported verbatim from vauth.c)
// ---------------------------------------------------------------------------

/// Build a Service Principal Name (SPN) string.
///
/// Port of `Curl_auth_build_spn` (`lib/vauth/vauth.c` L47-63), non-SSPI branch
/// only — the Windows SSPI variant is dropped. The SPN takes one of these forms,
/// exactly matching the C `curl_maprintf` format strings:
///
/// * `service/host@realm` — when both `host` and `realm` are present;
/// * `service/host`       — when only `host` is present;
/// * `service@realm`      — when only `realm` is present.
///
/// The C function returns `NULL` when neither `host` nor `realm` is supplied;
/// this port returns an **empty `String`** in that case (documented divergence
/// chosen for a simpler, allocation-free-of-`Option` signature). A `Some("")`
/// argument is treated like a non-`NULL` empty C string (matching the C
/// pointer-non-null check), whereas `None` is treated like a C `NULL`.
#[must_use]
pub fn build_spn(service: &str, host: Option<&str>, realm: Option<&str>) -> String {
    match (host, realm) {
        (Some(host), Some(realm)) => format!("{service}/{host}@{realm}"),
        (Some(host), None) => format!("{service}/{host}"),
        (None, Some(realm)) => format!("{service}@{realm}"),
        (None, None) => String::new(),
    }
}

/// Test whether a username embeds a Windows domain name.
///
/// Port of `Curl_auth_user_contains_domain` (`lib/vauth/vauth.c` L114-132).
/// Recognizes the three curl-supported forms:
///
/// * `Domain\User` (down-level logon name),
/// * `Domain/User` (curl's down-level compatibility format),
/// * `User@Domain` (user principal name).
///
/// A separator (`\`, `/`, or `@`) qualifies only when it is **neither the first
/// nor the last** byte of the string — matching the C predicate
/// `p > user && p < user + strlen(user) - 1` applied to `strpbrk(user, "\\/@")`.
///
/// For an **empty or absent** username the C code returns `TRUE` only when built
/// with GSS-API or Windows SSPI (credentials then come from the OS credential
/// cache). That branch is reproduced behind the optional `gssapi` feature via
/// `cfg!(feature = "gssapi")`: it is `false` in the default pure-Rust build and
/// `true` when the `gssapi` feature is enabled.
#[must_use]
pub fn user_contains_domain(user: Option<&str>) -> bool {
    match user {
        Some(user) if !user.is_empty() => {
            // Find the first byte in the set {'\\', '/', '@'} — the Rust
            // equivalent of C's `strpbrk(user, "\\/@")`.
            match user.bytes().position(|b| matches!(b, b'\\' | b'/' | b'@')) {
                // Valid iff the separator is neither the first nor the last byte.
                Some(idx) => idx > 0 && idx < user.len() - 1,
                None => false,
            }
        }
        // Empty username or `None`. Mirrors the C
        // `#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)` branch, which
        // is compiled in only when GSSAPI/SSPI support is present.
        _ => cfg!(feature = "gssapi"),
    }
}

/// Inputs to [`allowed_to_host`], mirroring the fields `Curl_auth_allowed_to_host`
/// reads off `struct Curl_easy` / `struct connectdata`.
///
/// The HTTP and connection layers populate this bundle from the live transfer and
/// connection state before calling [`allowed_to_host`]. Modeling the inputs as a plain
/// owned struct keeps [`allowed_to_host`] a pure, side-effect-free function that is
/// trivially unit-testable in isolation.
#[derive(Debug, Clone)]
pub struct AllowedToHostCtx<'a> {
    /// `data->state.this_is_a_follow` — `true` when handling a redirect.
    pub this_is_a_follow: bool,
    /// `data->set.allow_auth_to_other_hosts` — the `CURLOPT_UNRESTRICTED_AUTH`
    /// setting.
    pub allow_auth_to_other_hosts: bool,
    /// `data->state.first_host` — the host of the very first request in the
    /// transfer, or `None` if not yet recorded.
    pub first_host: Option<&'a str>,
    /// `conn->host.name` — the host of the current connection.
    pub conn_host_name: &'a str,
    /// `data->state.first_remote_port` — the port of the first request.
    pub first_remote_port: u16,
    /// `conn->remote_port` — the port of the current connection.
    pub conn_remote_port: u16,
    /// `data->state.first_remote_protocol` — the protocol id (`curl_prot_t`,
    /// a `CURLPROTO_*` bitmask) of the first request.
    pub first_remote_protocol: u32,
    /// `conn->scheme->protocol` — the protocol id of the current connection.
    pub conn_scheme_protocol: u32,
}

/// Decide whether authentication, cookies, or other "sensitive data" may still
/// be sent to the current host.
///
/// Port of `Curl_auth_allowed_to_host` (`lib/vauth/vauth.c` L138-147). The
/// boolean structure is preserved exactly: sensitive data is permitted when this
/// is **not** a redirect follow, OR when unrestricted auth is explicitly allowed,
/// OR when the current connection targets the very same host (case-insensitively,
/// matching `curl_strequal`), port, and protocol as the first request.
#[must_use]
pub fn allowed_to_host(ctx: &AllowedToHostCtx) -> bool {
    !ctx.this_is_a_follow
        || ctx.allow_auth_to_other_hosts
        || (ctx.first_host.is_some_and(|first| {
            first.eq_ignore_ascii_case(ctx.conn_host_name)
                && ctx.first_remote_port == ctx.conn_remote_port
                && ctx.first_remote_protocol == ctx.conn_scheme_protocol
        }))
}

// ---------------------------------------------------------------------------
// Phase E — per-connection owned auth state
// ---------------------------------------------------------------------------

/// Per-connection authentication blobs.
///
/// The C code (`lib/vauth/vauth.c` L149-249) stores these blobs in a generic
/// connection meta-hashmap keyed by strings such as `CURL_META_NTLM_CONN`, with
/// hand-written C destructors (`ntlm_conn_dtor`, `krb5_conn_dtor`,
/// `nego_conn_dtor`) freeing them. That whole pattern is an artifact of C's lack
/// of ownership. In Rust it collapses to plain **owned `Option` fields**:
/// ownership replaces the hashmap + key lookup, and `Drop` replaces the manual
/// destructors (each blob's own `Drop`, defined in its module, releases any OS
/// handle it holds — so `ConnAuthState` itself needs no manual `Drop`).
///
/// Where the C used separate `CURL_META_*_CONN` and `CURL_META_*_PROXY_CONN`
/// keys, this struct keeps distinct host and proxy fields.
///
/// Note: there is deliberately **no** `gsasl` field. GSASL was curl's optional
/// *external* SASL C library; here SASL/SCRAM/CRAM are implemented in pure Rust
/// in [`sasl`] / [`scram`], so no `gsasl` blob is needed.
#[derive(Debug, Default)]
pub struct ConnAuthState {
    /// NTLM state for the origin host. // <- Curl_auth_ntlm_get / ntlm_conn_dtor
    pub ntlm: Option<crate::auth::ntlm::NtlmData>,
    /// NTLM state for the proxy. // <- Curl_auth_ntlm_get(proxy=true)
    pub ntlm_proxy: Option<crate::auth::ntlm::NtlmData>,
    /// Kerberos V5 (GSSAPI) state. // <- Curl_auth_krb5_get / krb5_conn_dtor
    #[cfg(feature = "gssapi")]
    pub krb5: Option<crate::auth::kerberos::Kerberos5Data>,
    /// Negotiate (SPNEGO) state for the origin host.
    // <- Curl_auth_nego_get / nego_conn_dtor
    #[cfg(feature = "spnego")]
    pub nego: Option<crate::auth::negotiate::NegotiateData>,
    /// Negotiate (SPNEGO) state for the proxy.
    // <- Curl_auth_nego_get(proxy=true)
    #[cfg(feature = "spnego")]
    pub nego_proxy: Option<crate::auth::negotiate::NegotiateData>,
}

impl ConnAuthState {
    /// Get a mutable reference to the NTLM state for either the host or the
    /// proxy, lazily initializing it on first access.
    ///
    /// This is the ownership-based equivalent of C's `Curl_auth_ntlm_get`, which
    /// did a "get-or-`calloc`" against the connection meta-hashmap. Here
    /// `Option::get_or_insert_with(Default::default)` provides the same
    /// lazy-allocation behavior.
    // <- Curl_auth_ntlm_get / ntlm_conn_dtor
    pub fn ntlm_mut(&mut self, proxy: bool) -> &mut crate::auth::ntlm::NtlmData {
        if proxy {
            self.ntlm_proxy.get_or_insert_with(Default::default)
        } else {
            self.ntlm.get_or_insert_with(Default::default)
        }
    }

    /// Get a mutable reference to the Kerberos V5 (GSSAPI) state, lazily
    /// initializing it on first access. Equivalent to C's `Curl_auth_krb5_get`.
    // <- Curl_auth_krb5_get / krb5_conn_dtor
    #[cfg(feature = "gssapi")]
    pub fn krb5_mut(&mut self) -> &mut crate::auth::kerberos::Kerberos5Data {
        self.krb5.get_or_insert_with(Default::default)
    }

    /// Get a mutable reference to the Negotiate (SPNEGO) state for either the
    /// host or the proxy, lazily initializing it on first access. Equivalent to
    /// C's `Curl_auth_nego_get`.
    // <- Curl_auth_nego_get / nego_conn_dtor
    #[cfg(feature = "spnego")]
    pub fn nego_mut(&mut self, proxy: bool) -> &mut crate::auth::negotiate::NegotiateData {
        if proxy {
            self.nego_proxy.get_or_insert_with(Default::default)
        } else {
            self.nego.get_or_insert_with(Default::default)
        }
    }
}

// ---------------------------------------------------------------------------
// Phase F — mechanism trait + "pick strongest" negotiation
// ---------------------------------------------------------------------------

/// Credentials and request context shared by the auth mechanisms.
///
/// This is a pure, testable input bundle. The HTTP layer populates it from the
/// live easy/connection state before driving a mechanism; the mechanisms read it
/// (never mutate it) to compute their `Authorization` / `Proxy-Authorization`
/// header value.
#[derive(Debug, Clone, Default)]
pub struct AuthContext {
    /// The username (may be empty).
    pub username: String,
    /// The password (may be empty).
    pub password: String,
    /// The target host name (used by Digest / Negotiate SPN construction).
    pub host: String,
    /// The target port.
    pub port: u16,
    /// The HTTP request method (e.g. `GET`, `POST`) — Digest hashes it.
    pub method: String,
    /// The request-target / URI path — Digest hashes it.
    pub path: String,
    /// `true` when authenticating to a proxy (`Proxy-Authorization`) rather than
    /// the origin server (`Authorization`).
    pub proxy: bool,
}

/// Common shape of an HTTP authentication mechanism.
///
/// Each per-scheme module (`basic`, `digest`, `ntlm`, `negotiate`, ...)
/// implements this trait so that the HTTP layer and the SASL engine can drive
/// them generically. The trait is deliberately minimal (Minimal Change Mandate):
/// feed an optional server challenge, then produce the header value to send.
pub trait AuthMechanism {
    /// Feed a server challenge — the token that follows the scheme name in a
    /// `WWW-Authenticate` / `Proxy-Authenticate` header (for example the
    /// base64 blob of an NTLM type-2 message, or the parameters of a Digest
    /// challenge). Single-shot mechanisms such as Basic may ignore it.
    fn decode(&mut self, challenge: &str) -> crate::error::Result<()>;

    /// Produce the value to place after the scheme token in the outgoing
    /// `Authorization` / `Proxy-Authorization` header (without the header name,
    /// the leading scheme word where the caller adds it, or a trailing CRLF).
    fn output(&mut self, ctx: &AuthContext) -> crate::error::Result<String>;

    /// The `CURLAUTH_*` capability bit this mechanism implements.
    fn capability_bit(&self) -> u32;
}

/// Select the single strongest authentication method available.
///
/// Reproduces the selection logic of `pickoneauth()` in `lib/http.c` (L336). The
/// candidate set is the intersection of what the caller `wanted`
/// (`CURLOPT_HTTPAUTH` / `CURLOPT_PROXYAUTH`) and what the server said was
/// `available`. From that set the **strongest** method is chosen using curl's
/// exact, order-sensitive preference:
///
/// `Negotiate > Bearer > Digest > NTLM > Basic > AWS-SigV4`.
///
/// The order is preserved exactly so that wire behavior matches curl 8.x. When
/// the intersection is empty this returns [`CURLAUTH_NONE`]; the C code uses a
/// private in-library sentinel (`CURLAUTH_PICKNONE`, `lib/http.h`) that is not
/// part of the public ABI, so it is intentionally not surfaced here.
#[must_use]
pub fn pick_strongest(wanted: u32, available: u32) -> u32 {
    // Only consider methods that are both wanted and offered by the server.
    let avail = wanted & available;

    // The order of these checks is highly relevant — it is the order of
    // preference when the server accepts multiple types (see the identical
    // comment in curl's `pickoneauth`).
    if (avail & CURLAUTH_NEGOTIATE) != 0 {
        CURLAUTH_NEGOTIATE
    } else if (avail & CURLAUTH_BEARER) != 0 {
        CURLAUTH_BEARER
    } else if (avail & CURLAUTH_DIGEST) != 0 {
        CURLAUTH_DIGEST
    } else if (avail & CURLAUTH_NTLM) != 0 {
        CURLAUTH_NTLM
    } else if (avail & CURLAUTH_BASIC) != 0 {
        CURLAUTH_BASIC
    } else if (avail & CURLAUTH_AWS_SIGV4) != 0 {
        CURLAUTH_AWS_SIGV4
    } else {
        CURLAUTH_NONE
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    // --- Phase B: frozen CURLAUTH_* values ---------------------------------
    #[test]
    fn curlauth_constants_have_frozen_values() {
        // Each constant equals its exact decimal literal from curl.h.
        assert_eq!(CURLAUTH_NONE, 0);
        assert_eq!(CURLAUTH_BASIC, 1);
        assert_eq!(CURLAUTH_DIGEST, 2);
        assert_eq!(CURLAUTH_NEGOTIATE, 4);
        assert_eq!(CURLAUTH_NTLM, 8);
        assert_eq!(CURLAUTH_DIGEST_IE, 16);
        assert_eq!(CURLAUTH_NTLM_WB, 32);
        assert_eq!(CURLAUTH_BEARER, 64);
        assert_eq!(CURLAUTH_AWS_SIGV4, 128);
        assert_eq!(CURLAUTH_ONLY, 2_147_483_648); // 1 << 31
    }

    #[test]
    fn curlauth_negotiate_aliases_share_the_bit() {
        assert_eq!(CURLAUTH_GSSNEGOTIATE, CURLAUTH_NEGOTIATE);
        assert_eq!(CURLAUTH_GSSAPI, CURLAUTH_NEGOTIATE);
        assert_eq!(CURLAUTH_GSSAPI, 4);
    }

    #[test]
    fn curlauth_any_and_anysafe_match_c_macros() {
        // ANY = (~DIGEST_IE) & 0xffffffff == 0xFFFFFFEF; every bit but bit 4.
        assert_eq!(CURLAUTH_ANY, 0xFFFF_FFEF);
        assert_eq!(CURLAUTH_ANY, 4_294_967_279);
        assert_eq!(CURLAUTH_ANY & CURLAUTH_DIGEST_IE, 0);
        assert_eq!(CURLAUTH_ANY & CURLAUTH_BASIC, CURLAUTH_BASIC);

        // ANYSAFE = (~(BASIC | DIGEST_IE)) & 0xffffffff == 0xFFFFFFEE; bits 0 & 4 clear.
        assert_eq!(CURLAUTH_ANYSAFE, 0xFFFF_FFEE);
        assert_eq!(CURLAUTH_ANYSAFE, 4_294_967_278);
        assert_eq!(CURLAUTH_ANYSAFE & CURLAUTH_BASIC, 0);
        assert_eq!(CURLAUTH_ANYSAFE & CURLAUTH_DIGEST_IE, 0);
        assert_eq!(CURLAUTH_ANYSAFE & CURLAUTH_DIGEST, CURLAUTH_DIGEST);
    }

    // --- Phase C: Auth struct ----------------------------------------------
    #[test]
    fn auth_defaults_are_zeroed() {
        let a = Auth::default();
        assert_eq!(a.want, 0);
        assert_eq!(a.picked, 0);
        assert_eq!(a.avail, 0);
        assert!(!a.done);
        assert!(!a.multipass);
        assert!(!a.iestyle);
    }

    // --- Phase D.1: build_spn ----------------------------------------------
    #[test]
    fn build_spn_all_branches() {
        assert_eq!(
            build_spn("HTTP", Some("host"), Some("realm")),
            "HTTP/host@realm"
        );
        assert_eq!(build_spn("smtp", Some("mail"), None), "smtp/mail");
        assert_eq!(build_spn("imap", None, Some("realm")), "imap@realm");
        // Neither host nor realm -> empty string (this port's stand-in for C NULL).
        assert_eq!(build_spn("pop", None, None), "");
    }

    // --- Phase D.2: user_contains_domain -----------------------------------
    #[test]
    fn user_contains_domain_recognizes_domain_forms() {
        assert!(user_contains_domain(Some("Domain\\User"))); // down-level (backslash)
        assert!(user_contains_domain(Some("Domain/User"))); // curl compat (slash)
        assert!(user_contains_domain(Some("User@Domain"))); // UPN (at-sign)
    }

    #[test]
    fn user_contains_domain_rejects_plain_and_edge_separators() {
        assert!(!user_contains_domain(Some("user"))); // no separator at all
        assert!(!user_contains_domain(Some("\\user"))); // separator at first byte
        assert!(!user_contains_domain(Some("user\\"))); // separator at last byte
        assert!(!user_contains_domain(Some("user@"))); // '@' at last byte
        assert!(!user_contains_domain(Some("@user"))); // '@' at first byte
    }

    #[test]
    fn user_contains_domain_empty_or_none_follows_gssapi_feature() {
        // In the default (pure-Rust, no `gssapi` feature) build this is false; it
        // becomes true only under the optional GSSAPI/SSPI branch.
        let expected = cfg!(feature = "gssapi");
        assert_eq!(user_contains_domain(Some("")), expected);
        assert_eq!(user_contains_domain(None), expected);
    }

    // --- Phase D.3: allowed_to_host ----------------------------------------
    fn ctx_same() -> AllowedToHostCtx<'static> {
        AllowedToHostCtx {
            this_is_a_follow: true,
            allow_auth_to_other_hosts: false,
            first_host: Some("example.com"),
            conn_host_name: "example.com",
            first_remote_port: 443,
            conn_remote_port: 443,
            first_remote_protocol: 1,
            conn_scheme_protocol: 1,
        }
    }

    #[test]
    fn allowed_to_host_when_not_a_follow() {
        let mut c = ctx_same();
        c.this_is_a_follow = false;
        c.first_host = Some("a.example"); // even a different host is fine here
        c.conn_host_name = "b.example";
        assert!(allowed_to_host(&c));
    }

    #[test]
    fn allowed_to_host_when_unrestricted_flag_set() {
        let mut c = ctx_same();
        c.allow_auth_to_other_hosts = true;
        c.first_host = Some("a.example");
        c.conn_host_name = "b.example";
        assert!(allowed_to_host(&c));
    }

    #[test]
    fn allowed_to_host_same_host_case_insensitive() {
        let mut c = ctx_same();
        c.first_host = Some("Example.COM"); // curl_strequal is case-insensitive
        c.conn_host_name = "example.com";
        assert!(allowed_to_host(&c));
    }

    #[test]
    fn allowed_to_host_rejects_host_port_or_proto_mismatch() {
        // Different host.
        let mut c = ctx_same();
        c.conn_host_name = "other.example";
        assert!(!allowed_to_host(&c));

        // Different port.
        let mut c = ctx_same();
        c.conn_remote_port = 8443;
        assert!(!allowed_to_host(&c));

        // Different protocol.
        let mut c = ctx_same();
        c.conn_scheme_protocol = 2;
        assert!(!allowed_to_host(&c));

        // No recorded first host.
        let mut c = ctx_same();
        c.first_host = None;
        assert!(!allowed_to_host(&c));
    }

    // --- Phase E: ConnAuthState lazy accessors -----------------------------
    #[test]
    fn conn_auth_state_ntlm_lazily_initializes_host_and_proxy() {
        let mut s = ConnAuthState::default();
        assert!(s.ntlm.is_none());
        assert!(s.ntlm_proxy.is_none());

        let _ = s.ntlm_mut(false);
        assert!(s.ntlm.is_some());
        assert!(s.ntlm_proxy.is_none());

        let _ = s.ntlm_mut(true);
        assert!(s.ntlm_proxy.is_some());
    }

    // --- Phase F: pick_strongest -------------------------------------------
    #[test]
    fn pick_strongest_follows_curl_precedence() {
        // Negotiate is strongest.
        assert_eq!(
            pick_strongest(
                CURLAUTH_ANY,
                CURLAUTH_BASIC | CURLAUTH_DIGEST | CURLAUTH_NEGOTIATE
            ),
            CURLAUTH_NEGOTIATE
        );
        // Bearer outranks Digest/NTLM/Basic.
        assert_eq!(
            pick_strongest(
                CURLAUTH_ANY,
                CURLAUTH_BEARER | CURLAUTH_DIGEST | CURLAUTH_NTLM | CURLAUTH_BASIC
            ),
            CURLAUTH_BEARER
        );
        // Digest outranks NTLM and Basic.
        assert_eq!(
            pick_strongest(CURLAUTH_ANY, CURLAUTH_BASIC | CURLAUTH_DIGEST),
            CURLAUTH_DIGEST
        );
        // NTLM outranks Basic.
        assert_eq!(
            pick_strongest(CURLAUTH_ANY, CURLAUTH_NTLM | CURLAUTH_BASIC),
            CURLAUTH_NTLM
        );
        // Basic when it is the only fine type on offer.
        assert_eq!(pick_strongest(CURLAUTH_ANY, CURLAUTH_BASIC), CURLAUTH_BASIC);
        // AWS SigV4 is the weakest and only picked when nothing else is offered.
        assert_eq!(
            pick_strongest(CURLAUTH_ANY, CURLAUTH_AWS_SIGV4 | CURLAUTH_BASIC),
            CURLAUTH_BASIC
        );
        assert_eq!(
            pick_strongest(CURLAUTH_ANY, CURLAUTH_AWS_SIGV4),
            CURLAUTH_AWS_SIGV4
        );
    }

    #[test]
    fn pick_strongest_respects_wanted_mask_and_empty_intersection() {
        // `wanted` restricts the choice even when the server offers more.
        assert_eq!(
            pick_strongest(CURLAUTH_BASIC, CURLAUTH_DIGEST | CURLAUTH_BASIC),
            CURLAUTH_BASIC
        );
        // No overlap between wanted and available -> nothing picked.
        assert_eq!(
            pick_strongest(CURLAUTH_DIGEST, CURLAUTH_BASIC),
            CURLAUTH_NONE
        );
        assert_eq!(pick_strongest(CURLAUTH_ANY, CURLAUTH_NONE), CURLAUTH_NONE);
    }
}
