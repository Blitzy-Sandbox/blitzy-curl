//! Authentication subsystem root — the shared auth dispatch surface.
//!
//! This module is the memory-safe Rust rewrite of the *shared* parts of
//! libcurl's authentication machinery: the cross-scheme helpers in
//! `lib/vauth/vauth.c` / `lib/vauth/vauth.h` and the HTTP auth state machine in
//! `lib/http.c` (`pickoneauth`, `Curl_http_input_auth`, `Curl_http_auth_act`).
//! The C tree is consumed strictly as a *behavioral / ABI oracle*; nothing here
//! is a line-by-line transliteration.
//!
//! # Responsibilities
//!
//! * **Module root.** Declares every per-scheme submodule ([`basic`],
//!   [`bearer`], [`digest`], [`sasl`], and the feature-gated [`ntlm`],
//!   `negotiate`, `kerberos`, `scram`).
//! * **ABI surface.** Defines the [`CURLAUTH_NONE`]…[`CURLAUTH_ANYSAFE`] bit
//!   constants. Their integer values are a published libcurl ABI contract
//!   (surfaced through `curl_easy_setopt(CURLOPT_HTTPAUTH, …)`); they must match
//!   `include/curl/curl.h` byte-for-byte or every auth regression test breaks.
//! * **Per-handle state.** [`AuthState`] mirrors curl's `struct auth` (the
//!   `host` and `proxy` instances that live on the easy handle).
//! * **Challenge selection.** [`pick_one_auth`] reproduces `pickoneauth()` —
//!   the strongest-scheme selector whose preference order is itself a
//!   wire-parity requirement.
//! * **Response orchestration.** [`http_auth_act`] and its granular helpers
//!   ([`build_auth_mask`], [`host_should_pick`], [`proxy_should_pick`],
//!   [`needs_http1_downgrade_for_ntlm`], …) reproduce the auth-decision core of
//!   `Curl_http_auth_act()` as pure functions the `protocols::http` engine
//!   drives.
//! * **Challenge ingestion.** [`parse_auth_header`] reproduces
//!   `Curl_http_input_auth()`: it walks the comma-separated method tokens of a
//!   `WWW-Authenticate` / `Proxy-Authenticate` header, OAs the matching
//!   `CURLAUTH_*` bit into [`AuthState::avail`], and surfaces each recognized
//!   challenge so the HTTP engine can route the scheme-specific decode to the
//!   relevant submodule.
//! * **Shared helpers.** [`build_spn`], [`user_contains_domain`], and
//!   [`allowed_to_host`] port the cross-scheme utilities from `vauth.c`; they
//!   are deliberately *pure* (parameters in, value out) so the Kerberos and
//!   Negotiate backends can reuse them and they are trivially unit-testable.
//! * **Connection state types.** [`ConnectionAuthState`] and the per-scheme
//!   blobs ([`NtlmData`], …) model curl's per-connection conn-meta state. They
//!   are *owned by the connection* (`crate::conn`); this module only defines
//!   the types — it never holds mutable global state.
//!
//! # The picker order is **not** the SASL order
//!
//! The HTTP challenge picker here selects in the order
//! **Negotiate > Bearer > Digest > NTLM > Basic > AWS-SigV4**. That is a
//! distinct concept from the SASL mechanism *priority* (EXTERNAL > Kerberos5 >
//! SCRAM > DIGEST-MD5/CRAM-MD5 > NTLM > OAUTHBEARER > XOAUTH2 > PLAIN > LOGIN)
//! implemented in [`sasl`]. Do not conflate them.
//!
//! # Feature gating
//!
//! Scheme availability tracks curl's compile-time gates and stays in lockstep
//! with the capability bits reported by `crate::version`:
//!
//! | Scheme       | Cargo feature | Default | curl gate            |
//! |--------------|---------------|---------|----------------------|
//! | Basic        | *(always on)* | on      | `!CURL_DISABLE_BASIC_AUTH` |
//! | Bearer       | *(always on)* | on      | `!CURL_DISABLE_BEARER_AUTH` |
//! | Digest       | *(always on)* | on      | `!CURL_DISABLE_DIGEST_AUTH` |
//! | AWS SigV4    | `aws-sigv4`   | on      | `!CURL_DISABLE_AWS`  |
//! | NTLM         | `ntlm`        | on      | `USE_NTLM`           |
//! | Negotiate    | `spnego`      | off     | `USE_SPNEGO`         |
//! | Kerberos 5   | `gssapi`      | off     | `USE_KERBEROS5`      |
//! | GSASL/SCRAM  | `gsasl`       | off     | `USE_GSASL`          |
//!
//! A scheme that is compiled out is never selected by [`pick_one_auth`] and is
//! never recorded as available by [`parse_auth_header`].
//!
//! # Memory safety
//!
//! This module contains **zero** `unsafe` and is compiled under a module-level
//! `#![forbid(unsafe_code)]` (in addition to the crate-wide forbid), satisfying
//! AAP §0.7.1. All raw-pointer / FFI handling lives in `curl-rs-ffi`.

#![forbid(unsafe_code)]

// =============================================================================
// Phase A — per-scheme submodule declarations.
//
// `basic`, `bearer`, `digest`, and `sasl` are part of curl's default build and
// are always compiled. `ntlm`, `negotiate`, `kerberos`, and `scram` are gated
// by their Cargo features (`ntlm` default-on; `spnego` / `gssapi` / `gsasl`
// default-off), exactly mirroring curl's `USE_NTLM` / `USE_SPNEGO` /
// `USE_KERBEROS5` / `USE_GSASL` preprocessor gates. The sibling files are
// authored separately; this root only declares them.
// =============================================================================

pub mod basic;
pub mod bearer;
pub mod digest;
pub mod sasl;

#[cfg(feature = "ntlm")]
pub mod ntlm;

#[cfg(feature = "spnego")]
pub mod negotiate;

#[cfg(feature = "gssapi")]
pub mod kerberos;

#[cfg(feature = "gsasl")]
pub mod scram;

use crate::error::Result;
use crate::util::base64::{base64_decode, base64_encode};

// =============================================================================
// Phase B — `CURLAUTH_*` bitmask (ABI-exact constants).
//
// These mirror `include/curl/curl.h` exactly. curl declares them as
// `((unsigned long)1) << N`; libcurl masks the derived `ANY` / `ANYSAFE` values
// to 32 bits (`& 0xffffffff`), and every defined bit fits in 32 bits, so a
// `u32` reproduces the contract precisely: Rust's `!x` on a `u32` is identical
// to C's `(~x) & 0xffffffff`. The `curl-rs-ffi` boundary widens/narrows between
// this `u32` and the C `unsigned long` of `CURLOPT_HTTPAUTH` / `CURLOPT_PROXYAUTH`.
//
// An off-by-one here breaks every authentication test, so the values are pinned
// and asserted in the unit tests below.
// =============================================================================

/// No HTTP authentication (`CURLAUTH_NONE`).
pub const CURLAUTH_NONE: u32 = 0;

/// HTTP Basic authentication (`CURLAUTH_BASIC`, bit 0 — `1 << 0`).
pub const CURLAUTH_BASIC: u32 = 1;

/// HTTP Digest authentication (`CURLAUTH_DIGEST`).
pub const CURLAUTH_DIGEST: u32 = 1 << 1;

/// HTTP Negotiate (SPNEGO) authentication (`CURLAUTH_NEGOTIATE`).
pub const CURLAUTH_NEGOTIATE: u32 = 1 << 2;

/// Deprecated alias for [`CURLAUTH_NEGOTIATE`] (`CURLAUTH_GSSNEGOTIATE`).
pub const CURLAUTH_GSSNEGOTIATE: u32 = CURLAUTH_NEGOTIATE;

/// Alias for [`CURLAUTH_NEGOTIATE`], used by `CURLOPT_SOCKS5_AUTH`
/// (`CURLAUTH_GSSAPI`).
pub const CURLAUTH_GSSAPI: u32 = CURLAUTH_NEGOTIATE;

/// HTTP NTLM authentication (`CURLAUTH_NTLM`).
pub const CURLAUTH_NTLM: u32 = 1 << 3;

/// HTTP Digest with an IE-flavoured quirk (`CURLAUTH_DIGEST_IE`).
pub const CURLAUTH_DIGEST_IE: u32 = 1 << 4;

/// NTLM delegated to a winbind helper (`CURLAUTH_NTLM_WB`).
///
/// Functionality was removed in curl 8.8.0; the bit value is preserved for ABI
/// stability but is otherwise a no-op.
pub const CURLAUTH_NTLM_WB: u32 = 1 << 5;

/// HTTP Bearer token authentication (`CURLAUTH_BEARER`).
pub const CURLAUTH_BEARER: u32 = 1 << 6;

/// AWS SigV4 request signing (`CURLAUTH_AWS_SIGV4`).
pub const CURLAUTH_AWS_SIGV4: u32 = 1 << 7;

/// Use together with a single other type to force no "pick" of any other
/// available scheme (`CURLAUTH_ONLY`).
pub const CURLAUTH_ONLY: u32 = 1 << 31;

/// All "fine" types (everything except the IE Digest quirk) — `CURLAUTH_ANY`.
///
/// Equal to curl's `(~CURLAUTH_DIGEST_IE) & 0xffffffff` (= `0xFFFF_FFEF`).
pub const CURLAUTH_ANY: u32 = !CURLAUTH_DIGEST_IE;

/// All "fine" types except Basic — `CURLAUTH_ANYSAFE`.
///
/// Equal to curl's `(~(CURLAUTH_BASIC | CURLAUTH_DIGEST_IE)) & 0xffffffff`
/// (= `0xFFFF_FFEE`).
pub const CURLAUTH_ANYSAFE: u32 = !(CURLAUTH_BASIC | CURLAUTH_DIGEST_IE);

/// Internal sentinel meaning "select nothing" — curl's `CURLAUTH_PICKNONE`
/// (`lib/http.h`, `1 << 30`).
///
/// This is **not** part of the public `curl.h` ABI; it is an internal value
/// [`pick_one_auth`] writes into [`AuthState::picked`] when no acceptable
/// scheme is on offer. It is deliberately distinct from [`CURLAUTH_ONLY`]
/// (`1 << 31`).
pub const CURLAUTH_PICKNONE: u32 = 1 << 30;

// =============================================================================
// Phase C — per-`auth`-state model.
//
// Mirrors curl's `struct auth` (lib/urldata.h). Two instances live on the easy
// handle — one for the origin host, one for the proxy. `want`/`picked`/`avail`
// are `uint32_t` in C, so they are `u32` here.
// =============================================================================

/// The authentication state for a single endpoint (host *or* proxy).
///
/// This is the Rust analog of curl's `struct auth`. The HTTP engine keeps one
/// instance per endpoint on the easy handle.
///
/// Field lifecycle (identical to curl):
///
/// * [`want`](Self::want) is the bitmask the application requested via
///   `CURLOPT_HTTPAUTH` / `CURLOPT_PROXYAUTH`. It may have several bits set.
/// * [`picked`](Self::picked) is first seeded to the `want` value before the
///   request is sent; once **all** `401`/`407` challenge headers have been
///   parsed it is narrowed by [`pick_one_auth`] to a *single* preferred bit
///   (or [`CURLAUTH_PICKNONE`] if nothing acceptable was offered).
/// * [`avail`](Self::avail) accumulates the methods the server advertised for
///   this resource (set by [`parse_auth_header`]); it is cleared once a pick is
///   made.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuthState {
    /// Bitmask of the authentication methods wanted by the application.
    pub want: u32,
    /// The single method chosen after challenge parsing (or the seeded `want`
    /// value beforehand; [`CURLAUTH_PICKNONE`] if nothing was acceptable).
    pub picked: u32,
    /// Bitmask of the methods the server reports it supports for this resource.
    pub avail: u32,
    /// `true` once the auth phase is complete and the real request can proceed.
    pub done: bool,
    /// `true` while mid-way through a multi-pass negotiation (e.g. NTLM,
    /// Negotiate) that is not yet authenticated.
    pub multipass: bool,
    /// `true` if Digest should be performed IE-style rather than strictly
    /// RFC-compliant.
    pub iestyle: bool,
}

impl AuthState {
    /// Creates a fresh state for an endpoint that wants the given method mask.
    ///
    /// Per curl, [`picked`](Self::picked) is seeded to `want` (it is narrowed to
    /// a single bit later by [`pick_one_auth`]).
    #[must_use]
    pub const fn new(want: u32) -> Self {
        Self {
            want,
            picked: want,
            avail: CURLAUTH_NONE,
            done: false,
            multipass: false,
            iestyle: false,
        }
    }

    /// Returns `true` if any of `methods` is set in [`want`](Self::want).
    #[must_use]
    pub const fn wants(&self, methods: u32) -> bool {
        (self.want & methods) != 0
    }

    /// Returns `true` if any of `methods` was advertised in
    /// [`avail`](Self::avail).
    #[must_use]
    pub const fn available(&self, methods: u32) -> bool {
        (self.avail & methods) != 0
    }
}

// =============================================================================
// Phase D — challenge picker (`pickoneauth`) and the auth-decision helpers
// that `Curl_http_auth_act()` is built from.
// =============================================================================

/// Selects the single most-favoured method present in `avail`, honouring the
/// strict preference order and the compile-time scheme gates.
///
/// This is the inner half of [`pick_one_auth`]: it takes the already-masked
/// availability bitmask and returns the chosen `CURLAUTH_*` bit, or
/// [`CURLAUTH_PICKNONE`] when nothing acceptable is present.
///
/// The order **Negotiate > Bearer > Digest > NTLM > Basic > AWS-SigV4** is a
/// wire-parity requirement copied from `pickoneauth()` and **must not** be
/// reordered. Each scheme that curl wraps in a build gate is wrapped in the
/// matching `#[cfg(feature = …)]` here so a scheme compiled out can never be
/// selected even if the server offered it.
fn select_method(avail: u32) -> u32 {
    // Negotiate (SPNEGO) — highest preference.
    #[cfg(feature = "spnego")]
    {
        if (avail & CURLAUTH_NEGOTIATE) != 0 {
            return CURLAUTH_NEGOTIATE;
        }
    }

    // Bearer (always compiled — curl's `!CURL_DISABLE_BEARER_AUTH`).
    if (avail & CURLAUTH_BEARER) != 0 {
        return CURLAUTH_BEARER;
    }

    // Digest (always compiled — curl's `!CURL_DISABLE_DIGEST_AUTH`).
    if (avail & CURLAUTH_DIGEST) != 0 {
        return CURLAUTH_DIGEST;
    }

    // NTLM.
    #[cfg(feature = "ntlm")]
    {
        if (avail & CURLAUTH_NTLM) != 0 {
            return CURLAUTH_NTLM;
        }
    }

    // Basic (always compiled — curl's `!CURL_DISABLE_BASIC_AUTH`).
    if (avail & CURLAUTH_BASIC) != 0 {
        return CURLAUTH_BASIC;
    }

    // AWS SigV4 — lowest preference.
    #[cfg(feature = "aws-sigv4")]
    {
        if (avail & CURLAUTH_AWS_SIGV4) != 0 {
            return CURLAUTH_AWS_SIGV4;
        }
    }

    CURLAUTH_PICKNONE
}

/// Picks the most favourable authentication method for `pick`, mirroring
/// `pickoneauth()`.
///
/// The candidate set is `pick.avail & pick.want & mask`. On success
/// [`AuthState::picked`] is set to the single chosen bit and `true` is
/// returned; if nothing acceptable is on offer, `picked` becomes
/// [`CURLAUTH_PICKNONE`] and `false` is returned. In **either** case
/// [`AuthState::avail`] is reset to [`CURLAUTH_NONE`] afterwards, exactly as
/// curl clears it.
///
/// `mask` is the run-time authentication mask assembled by [`build_auth_mask`]
/// (host) or [`proxy_auth_mask`] (proxy).
pub fn pick_one_auth(pick: &mut AuthState, mask: u32) -> bool {
    // Only consider methods that are both wanted and currently allowed.
    let avail = pick.avail & pick.want & mask;
    let method = select_method(avail);

    pick.picked = method;
    pick.avail = CURLAUTH_NONE; // cleared here, exactly as curl does

    method != CURLAUTH_PICKNONE
}

/// Builds the host authentication mask, mirroring the `authmask` assembled at
/// the top of `Curl_http_auth_act()`.
///
/// The mask starts as "all bits" (`~0`). When no bearer token is configured the
/// [`CURLAUTH_BEARER`] bit is cleared so Bearer can never be picked for the
/// origin host.
#[must_use]
pub const fn build_auth_mask(have_bearer_token: bool) -> u32 {
    if have_bearer_token {
        // All bits allowed (curl's `~0UL`).
        u32::MAX
    } else {
        // `~0UL & ~CURLAUTH_BEARER` — every bit except Bearer.
        !CURLAUTH_BEARER
    }
}

/// Derives the proxy authentication mask from a host mask.
///
/// Mirrors curl passing `authmask & ~CURLAUTH_BEARER` to the proxy picker:
/// Bearer is **never** a valid proxy authentication method, regardless of
/// whether a bearer token is set.
#[must_use]
pub const fn proxy_auth_mask(host_mask: u32) -> u32 {
    host_mask & !CURLAUTH_BEARER
}

/// Returns `true` for a transient `1xx` status code (`100`–`199`).
///
/// `Curl_http_auth_act()` ignores these and makes no auth decision for them.
#[must_use]
pub fn is_transient_1xx(httpcode: i32) -> bool {
    (100..=199).contains(&httpcode)
}

/// Whether the host auth picker should run for this response.
///
/// Mirrors curl's host condition: a `401`, or — during the initial
/// authentication negotiation (`authneg`) — any non-final (`< 300`) code.
#[must_use]
pub fn host_should_pick(httpcode: i32, authneg: bool) -> bool {
    httpcode == 401 || (authneg && httpcode < 300)
}

/// Whether the proxy auth picker should run for this response.
///
/// Mirrors curl's proxy condition: a `407`, or — during `authneg` — any
/// non-final (`< 300`) code.
#[must_use]
pub fn proxy_should_pick(httpcode: i32, authneg: bool) -> bool {
    httpcode == 407 || (authneg && httpcode < 300)
}

/// Whether the connection must be forced down to HTTP/1.1 because NTLM was
/// picked over an HTTP/2-or-later connection.
///
/// NTLM is a connection-oriented, multi-pass scheme that does not work over
/// multiplexed HTTP/2 streams, so curl downgrades and closes the connection in
/// this case (`Curl_http_auth_act()` → "Forcing HTTP/1.1 for NTLM"). The actual
/// downgrade and `connclose` live in `protocols::http`; this predicate is the
/// hook that signals it. `httpversion_sent` uses curl's encoding where `11`
/// means HTTP/1.1 and anything `> 11` means HTTP/2 or HTTP/3.
#[must_use]
pub fn needs_http1_downgrade_for_ntlm(picked: u32, httpversion_sent: i32) -> bool {
    picked == CURLAUTH_NTLM && httpversion_sent > 11
}

/// The decision produced by [`http_auth_act`] for the HTTP engine to act on.
///
/// All fields are outputs; the engine is responsible for the side effects curl
/// performs after the decision (rewind handling, cloning the URL into
/// `req.newurl`, applying the `force_http1` downgrade, and the
/// `http_should_fail` check), none of which belong in this pure auth core.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuthActOutcome {
    /// `true` if a host authentication method was successfully picked.
    pub picked_host: bool,
    /// `true` if a proxy authentication method was successfully picked.
    pub picked_proxy: bool,
    /// `true` if a required pick failed — curl sets `data->state.authproblem`.
    pub authproblem: bool,
    /// `true` if the connection must be downgraded to HTTP/1.1 for NTLM (see
    /// [`needs_http1_downgrade_for_ntlm`]).
    pub force_http1: bool,
    /// The method recorded as picked for the host (`data->info.httpauthpicked`).
    pub httpauthpicked: u32,
    /// The method recorded as picked for the proxy
    /// (`data->info.proxyauthpicked`).
    pub proxyauthpicked: u32,
}

/// Reproduces the auth-decision core of `Curl_http_auth_act()` as a pure
/// function over the two [`AuthState`] instances and the response context.
///
/// It builds the run-time masks, ignores transient `1xx` responses, runs the
/// host picker (when host credentials are present and the response calls for
/// it) and the proxy picker (when proxy credentials are present and the
/// response calls for it), records the picked methods, and flags the NTLM
/// HTTP/1.1 downgrade. It does **not** perform the rewind / `newurl` /
/// `http_should_fail` side effects — those remain in `protocols::http`.
///
/// Parameters:
/// * `authhost`, `authproxy` — the host and proxy states (mutated in place by
///   the picker, exactly as curl mutates `data->state.authhost`/`authproxy`).
/// * `httpcode` — the response status code.
/// * `authneg` — `data->req.authneg`: `true` during the initial auth
///   negotiation round-trip.
/// * `have_host_creds` — `data->state.aptr.user || bearer-token-set`.
/// * `have_bearer_token` — whether `CURLOPT_XOAUTH2_BEARER` / a bearer token is
///   configured (controls the host Bearer mask bit).
/// * `have_proxy_creds` — `conn->bits.proxy_user_passwd`.
/// * `httpversion_sent` — curl's sent HTTP version code (`11` = HTTP/1.1).
#[allow(clippy::too_many_arguments)]
pub fn http_auth_act(
    authhost: &mut AuthState,
    authproxy: &mut AuthState,
    httpcode: i32,
    authneg: bool,
    have_host_creds: bool,
    have_bearer_token: bool,
    have_proxy_creds: bool,
    httpversion_sent: i32,
) -> AuthActOutcome {
    // Seed the recorded picks with the current values so a no-op round (e.g. a
    // transient response) leaves them unchanged, matching curl.
    let mut outcome = AuthActOutcome {
        httpauthpicked: authhost.picked,
        proxyauthpicked: authproxy.picked,
        ..AuthActOutcome::default()
    };

    // Transient 1xx — no auth decision (curl returns CURLE_OK immediately).
    if is_transient_1xx(httpcode) {
        return outcome;
    }

    let host_mask = build_auth_mask(have_bearer_token);

    // ---- host authentication -------------------------------------------------
    if have_host_creds && host_should_pick(httpcode, authneg) {
        outcome.picked_host = pick_one_auth(authhost, host_mask);
        if outcome.picked_host {
            outcome.httpauthpicked = authhost.picked;
            // NTLM over HTTP/2+ must drop back to HTTP/1.1.
            if needs_http1_downgrade_for_ntlm(authhost.picked, httpversion_sent) {
                outcome.force_http1 = true;
            }
        } else {
            outcome.authproblem = true;
        }
    }

    // ---- proxy authentication ------------------------------------------------
    if have_proxy_creds && proxy_should_pick(httpcode, authneg) {
        outcome.picked_proxy = pick_one_auth(authproxy, proxy_auth_mask(host_mask));
        if outcome.picked_proxy {
            outcome.proxyauthpicked = authproxy.picked;
        } else {
            outcome.authproblem = true;
        }
    }

    outcome
}

// =============================================================================
// Phase D (cont.) — input-side challenge parsing (`Curl_http_input_auth`).
// =============================================================================

/// A single authentication challenge recognized in a `WWW-Authenticate` /
/// `Proxy-Authenticate` header.
///
/// [`method`](Self::method) is the `CURLAUTH_*` bit the scheme maps to;
/// [`params`](Self::params) is the remainder of the header value following the
/// scheme token (with leading blanks removed) — i.e. exactly the text curl
/// hands to its per-scheme decoder. The decoder for the *picked* scheme parses
/// the portion it understands (a base64 blob for Negotiate/NTLM, the
/// comma-separated parameters for Digest, the realm for Basic). Decoding itself
/// lives in the per-scheme submodules and is driven by the HTTP engine, which
/// holds the per-connection state the decoders mutate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthChallenge {
    /// The `CURLAUTH_*` bit identifying the scheme.
    pub method: u32,
    /// The challenge text following the scheme token.
    pub params: String,
}

/// The result of [`parse_auth_header`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedAuth {
    /// Every recognized challenge, in the order encountered.
    pub challenges: Vec<AuthChallenge>,
    /// `true` if a challenge for the already-picked Basic/Bearer scheme came
    /// back (meaning the supplied credentials/token were rejected) — curl sets
    /// `data->state.authproblem` in this case.
    pub authproblem: bool,
}

/// Skips leading ASCII blanks (space and tab), mirroring
/// `curlx_str_passblanks`.
fn skip_blanks(s: &str) -> &str {
    s.trim_start_matches([' ', '\t'])
}

/// Case-insensitive scheme matcher, mirroring `authcmp()` in `lib/http.c`.
///
/// Returns `true` when `line` begins with `name` (compared case-insensitively)
/// and the character immediately following is **not** ASCII-alphanumeric (or
/// the string ends there). This prevents `"NTLM"` from matching `"NTLMSSP"` and
/// matches curl's `curl_strnequal(...) && !ISALNUM(line[n])`.
fn authcmp(name: &str, line: &str) -> bool {
    let n = name.len();
    let lb = line.as_bytes();
    if lb.len() < n || !lb[..n].eq_ignore_ascii_case(name.as_bytes()) {
        return false;
    }
    // No alphanumeric may directly follow the scheme name; end-of-string is OK.
    match lb.get(n) {
        Some(c) => !c.is_ascii_alphanumeric(),
        None => true,
    }
}

/// Returns the challenge text that follows a matched scheme token, with leading
/// blanks trimmed. `token` is known to begin with `scheme` (ASCII), so slicing
/// at `scheme.len()` is always on a character boundary.
fn challenge_after_scheme(scheme: &str, token: &str) -> String {
    skip_blanks(&token[scheme.len()..]).to_string()
}

/// Parses a `WWW-Authenticate` / `Proxy-Authenticate` header value, mirroring
/// `Curl_http_input_auth()`.
///
/// `state` is the [`AuthState`] for the endpoint the header came from (host or
/// proxy). For every scheme token recognized, the matching `CURLAUTH_*` bit is
/// OR-ed into [`AuthState::avail`]; the returned [`ParsedAuth`] additionally
/// carries the per-scheme challenge text (for the HTTP engine to route to the
/// scheme decoder) and an `authproblem` flag.
///
/// Behavioral parity notes (all from the C oracle):
/// * Multiple methods may appear on one line, comma-separated; parsing walks
///   token-by-token, skipping blanks after each comma.
/// * A **duplicate** Digest header is ignored (curl logs "Ignoring duplicate
///   digest auth header").
/// * If a Basic/Bearer challenge arrives while that same scheme is already
///   [`picked`](AuthState::picked), the credentials/token were rejected: the
///   advertised availability is reset and `authproblem` is set.
/// * Schemes compiled out (via their Cargo feature) are neither matched nor
///   recorded, exactly as curl's `#ifdef` gates suppress them.
///
/// The `header_value` should be the field value with the leading whitespace
/// already stripped (curl passes "the first non-space"); any remaining leading
/// blanks are tolerated.
pub fn parse_auth_header(state: &mut AuthState, header_value: &str) -> ParsedAuth {
    let mut result = ParsedAuth::default();
    let mut rest = skip_blanks(header_value);

    while !rest.is_empty() {
        // The checks run in curl's source order. A token starts with exactly
        // one scheme name, so at most one arm matches per iteration.

        // ---- Negotiate (SPNEGO) ---------------------------------------------
        #[cfg(feature = "spnego")]
        {
            if authcmp("Negotiate", rest) {
                state.avail |= CURLAUTH_NEGOTIATE;
                result.challenges.push(AuthChallenge {
                    method: CURLAUTH_NEGOTIATE,
                    params: challenge_after_scheme("Negotiate", rest),
                });
            }
        }

        // ---- NTLM ------------------------------------------------------------
        #[cfg(feature = "ntlm")]
        {
            if authcmp("NTLM", rest) {
                state.avail |= CURLAUTH_NTLM;
                result.challenges.push(AuthChallenge {
                    method: CURLAUTH_NTLM,
                    params: challenge_after_scheme("NTLM", rest),
                });
            }
        }

        // ---- Digest (always compiled) ---------------------------------------
        // A duplicate Digest header is ignored (curl logs "Ignoring duplicate
        // digest auth header"); only the first is recorded.
        if authcmp("Digest", rest) && (state.avail & CURLAUTH_DIGEST) == 0 {
            state.avail |= CURLAUTH_DIGEST;
            // curl stores the incoming digest data even before Digest is
            // activated, so the challenge is always surfaced.
            result.challenges.push(AuthChallenge {
                method: CURLAUTH_DIGEST,
                params: challenge_after_scheme("Digest", rest),
            });
        }

        // ---- Basic (always compiled) ----------------------------------------
        if authcmp("Basic", rest) {
            state.avail |= CURLAUTH_BASIC;
            if state.picked == CURLAUTH_BASIC {
                // We asked for Basic but got a 40x anyway → bad credentials.
                state.avail = CURLAUTH_NONE;
                result.authproblem = true;
            } else {
                result.challenges.push(AuthChallenge {
                    method: CURLAUTH_BASIC,
                    params: challenge_after_scheme("Basic", rest),
                });
            }
        }

        // ---- Bearer (always compiled) ---------------------------------------
        if authcmp("Bearer", rest) {
            state.avail |= CURLAUTH_BEARER;
            if state.picked == CURLAUTH_BEARER {
                // We asked for Bearer but got a 40x anyway → bad token.
                state.avail = CURLAUTH_NONE;
                result.authproblem = true;
            } else {
                result.challenges.push(AuthChallenge {
                    method: CURLAUTH_BEARER,
                    params: challenge_after_scheme("Bearer", rest),
                });
            }
        }

        // Advance to the next comma-separated method on the same line.
        match rest.find(',') {
            Some(idx) => rest = skip_blanks(&rest[idx + 1..]),
            None => break,
        }
    }

    result
}

// =============================================================================
// Phase E — shared, pure auth helpers (ported from `lib/vauth/vauth.c`).
//
// These are kept deliberately pure (parameters in, value out) so they are
// trivially unit-testable and reusable by the Kerberos and Negotiate backends.
// =============================================================================

/// Builds a Kerberos/Negotiate Service Principal Name, mirroring
/// `Curl_auth_build_spn()` (the non-SSPI path).
///
/// The format follows curl exactly:
///
/// * `host` **and** `realm` present → `"{service}/{host}@{realm}"`
/// * `host` only → `"{service}/{host}"`
/// * `realm` only → `"{service}@{realm}"`
/// * neither → an empty string (curl returns `NULL`; the empty `String` is the
///   Rust analog of "no SPN")
///
/// `host` / `realm` are [`Option`]s so the C pointer-nullness semantics map
/// directly (`None` ≙ `NULL`). The Windows SSPI UTF-16 conversion path is out
/// of scope.
#[must_use]
pub fn build_spn(service: &str, host: Option<&str>, realm: Option<&str>) -> String {
    match (host, realm) {
        (Some(host), Some(realm)) => format!("{service}/{host}@{realm}"),
        (Some(host), None) => format!("{service}/{host}"),
        (None, Some(realm)) => format!("{service}@{realm}"),
        (None, None) => String::new(),
    }
}

/// Tests whether `user` embeds a Windows domain name, mirroring
/// `Curl_auth_user_contains_domain()`.
///
/// Returns `true` when `user` contains a `\`, `/`, or `@` separator that is
/// neither the first nor the last character — i.e. one of the forms
/// `Domain\User`, `Domain/User`, or `User@Domain`.
///
/// An **empty** user is a special case: curl returns `TRUE` only when built
/// against GSS-API or Windows SSPI (the identity then comes from the
/// credentials cache / logged-in user). Here that maps to the `gssapi` feature;
/// in any other build an empty user yields `false`.
#[must_use]
pub fn user_contains_domain(user: &str) -> bool {
    if user.is_empty() {
        // Empty user is only "valid" under GSS-API (credentials cache) builds.
        return cfg!(feature = "gssapi");
    }

    // The separator must exist and lie strictly between the first and last
    // characters (curl: `p > user && p < user + strlen(user) - 1`).
    match user.find(['\\', '/', '@']) {
        Some(pos) => pos > 0 && pos < user.len() - 1,
        None => false,
    }
}

/// The redirect-safety gate, mirroring `Curl_auth_allowed_to_host()`.
///
/// Returns whether credentials (or other sensitive data) may still be sent to
/// the current host. Sending is permitted when **any** of the following holds:
///
/// * this request is **not** the result of following a redirect
///   (`is_follow == false`); or
/// * the application explicitly opted in with
///   `CURLOPT_UNRESTRICTED_AUTH` (`allow_auth_to_other_hosts == true`); or
/// * the current host/port/protocol all match those of the **first** request
///   in the redirect chain (host compared case-insensitively).
///
/// All inputs are passed explicitly (rather than read from a global) so the
/// gate is pure and unit-testable. `first_host` is an [`Option`] so a not-yet-
/// recorded first host (`NULL` in curl) correctly fails the host-match clause.
/// Ports are `i32` to preserve curl's `int` semantics (including the `-1`
/// "unset" sentinel); protocols are the `CURLPROTO_*` bitmask values.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn allowed_to_host(
    is_follow: bool,
    allow_auth_to_other_hosts: bool,
    first_host: Option<&str>,
    first_remote_port: i32,
    first_remote_protocol: u32,
    current_host: &str,
    current_remote_port: i32,
    current_protocol: u32,
) -> bool {
    if !is_follow || allow_auth_to_other_hosts {
        return true;
    }

    match first_host {
        Some(first) => {
            first.eq_ignore_ascii_case(current_host)
                && first_remote_port == current_remote_port
                && first_remote_protocol == current_protocol
        }
        None => false,
    }
}

// =============================================================================
// Shared base64 challenge helpers.
//
// The per-scheme challenge/response payloads (NTLM type-1/2/3, Negotiate SPNEGO
// tokens, SASL exchanges) are base64-framed on the wire. These thin wrappers
// over `crate::util::base64` give every scheme submodule one consistent place
// to decode a server challenge and encode a client response, matching curl's
// `curlx_base64_decode` / `curlx_base64_encode` usage in `vauth/`.
// =============================================================================

/// Decodes the base64 portion of an auth challenge into its raw bytes.
///
/// Leading and trailing ASCII whitespace is trimmed first (challenge tokens are
/// extracted from header values that may carry surrounding spaces); the
/// remaining text is decoded with curl's strict base64 rules (see
/// [`crate::util::base64::base64_decode`]).
pub fn decode_base64_challenge(challenge: &str) -> Result<Vec<u8>> {
    base64_decode(challenge.trim().as_bytes())
}

/// Encodes a raw auth response payload as standard base64 text (with `=`
/// padding), ready to splice into an `Authorization` / `Proxy-Authorization`
/// header value.
pub fn encode_base64_message(message: &[u8]) -> Result<Vec<u8>> {
    base64_encode(message)
}

// =============================================================================
// Phase F — per-connection scheme state.
//
// curl stores NTLM / Negotiate / Kerberos5 / GSASL state per *connection* via
// `Curl_conn_meta_set` (calloc-zeroed blobs with destructors), keeping separate
// host and proxy instances for NTLM and Negotiate. The Rust model replaces the
// string-keyed, manually-freed blobs with typed fields **owned by the
// connection** (`crate::conn`) and freed deterministically by `Drop`. There are
// no `static mut` globals and no interior-mutability hacks: ownership lives on
// the connection object.
//
// This root defines the state types; the scheme submodules implement the
// algorithms that operate on them. The conn-meta key strings are preserved
// below purely for parity / tracing — the Rust design does not key on them.
// =============================================================================

/// Connection-metadata key strings preserved verbatim from `lib/vauth/vauth.h`.
///
/// The Rust implementation owns the per-connection state as typed fields on
/// [`ConnectionAuthState`] rather than in a string-keyed map, so these are not
/// used for storage; they are retained for diagnostic/tracing parity with curl
/// (note the upstream `ntml` spelling in the NTLM keys is intentional and
/// reproduced as-is).
pub mod conn_meta {
    /// NTLM (origin host) connection-meta key.
    pub const NTLM_CONN: &str = "meta:auth:ntml:conn";
    /// NTLM (proxy) connection-meta key.
    pub const NTLM_PROXY_CONN: &str = "meta:auth:ntml-proxy:conn";
    /// Kerberos 5 connection-meta key.
    pub const KRB5_CONN: &str = "meta:auth:krb5:conn";
    /// GSASL connection-meta key.
    pub const GSASL_CONN: &str = "meta:auth:gsasl:conn";
    /// Negotiate (origin host) connection-meta key.
    pub const NEGO_CONN: &str = "meta:auth:nego:conn";
    /// Negotiate (proxy) connection-meta key.
    pub const NEGO_PROXY_CONN: &str = "meta:auth:nego-proxy:conn";
}

/// NTLM handshake progression, mirroring curl's `curlntlm` enum.
#[cfg(feature = "ntlm")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NtlmState {
    /// No NTLM message exchanged yet (`NTLMSTATE_NONE`).
    #[default]
    None,
    /// The type-1 (negotiate) message has been sent (`NTLMSTATE_TYPE1`).
    Type1,
    /// The type-2 (challenge) message has been received (`NTLMSTATE_TYPE2`).
    Type2,
    /// The type-3 (authenticate) message has been sent (`NTLMSTATE_TYPE3`).
    Type3,
}

/// Per-connection NTLM state, mirroring the non-SSPI `struct ntlmdata`.
///
/// One instance exists per direction (origin host and proxy). The crate's
/// `ntlm` submodule implements the type-1/2/3 message handling over this state;
/// the connection owns the instance.
#[cfg(feature = "ntlm")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NtlmData {
    /// NTLM negotiation flags received in the type-2 message.
    pub flags: u32,
    /// The 8-byte server challenge (nonce) from the type-2 message.
    pub nonce: [u8; 8],
    /// The raw `TargetInfo` block from the type-2 message (its length replaces
    /// curl's separate `target_info_len`).
    pub target_info: Vec<u8>,
    /// Current handshake phase.
    pub state: NtlmState,
}

/// Negotiate (SPNEGO) handshake progression, mirroring curl's `curlnegotiate`
/// enum.
#[cfg(feature = "spnego")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NegotiateState {
    /// No token exchanged yet (`GSS_AUTHNONE`).
    #[default]
    None,
    /// A token has been received from the server (`GSS_AUTHRECV`).
    Recv,
    /// A token has been sent to the server (`GSS_AUTHSENT`).
    Sent,
    /// The exchange is complete (`GSS_AUTHDONE`).
    Done,
    /// The exchange completed successfully (`GSS_AUTHSUCC`).
    Succ,
}

/// Per-connection Negotiate (SPNEGO) state, mirroring the persistence/progress
/// bits of `struct negotiatedata`.
///
/// One instance exists per direction (origin host and proxy). The GSS-API
/// context, name, and output-token handles are library-specific and are owned
/// by the `negotiate` submodule's backend; this struct models the
/// connection-level progress and connection-persistence flags curl tracks.
#[cfg(feature = "spnego")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NegotiateData {
    /// Current handshake phase.
    pub state: NegotiateState,
    /// Server requested that the authentication not persist on the connection.
    pub noauthpersist: bool,
    /// Whether [`noauthpersist`](Self::noauthpersist) has been determined.
    pub havenoauthpersist: bool,
    /// Whether negotiation data has been received.
    pub havenegdata: bool,
    /// Whether the server indicated multiple requests are required.
    pub havemultiplerequests: bool,
}

/// Per-connection Kerberos 5 (GSS-API) state, mirroring `struct kerberos5data`.
///
/// The GSS-API context and name handles are owned by the `kerberos` submodule's
/// backend; this struct holds the connection-level state the engine needs.
#[cfg(feature = "gssapi")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Kerberos5Data {
    /// Whether mutual authentication was requested for this security context.
    pub mutual_auth: bool,
}

/// Per-connection GSASL state, mirroring `struct gsasldata`.
///
/// The libgsasl context/session handles are owned by the `scram` submodule's
/// backend; this struct records the connection-level mechanism selection.
#[cfg(feature = "gsasl")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GsaslData {
    /// The negotiated SASL mechanism name, once chosen.
    pub mechanism: Option<String>,
}

/// Aggregates the per-connection authentication state owned by a connection.
///
/// This is the Rust replacement for curl's per-connection conn-meta auth blobs.
/// NTLM and Negotiate keep **separate host and proxy instances** (matching the
/// distinct `…_CONN` / `…_PROXY_CONN` meta keys). Each field is feature-gated to
/// the scheme that uses it, so a build that compiles a scheme out carries no
/// state for it. The connection owns this value and frees it via `Drop`.
#[derive(Debug, Clone, Default)]
pub struct ConnectionAuthState {
    /// NTLM state for the origin host.
    #[cfg(feature = "ntlm")]
    pub ntlm: Option<NtlmData>,
    /// NTLM state for the proxy.
    #[cfg(feature = "ntlm")]
    pub ntlm_proxy: Option<NtlmData>,
    /// Negotiate state for the origin host.
    #[cfg(feature = "spnego")]
    pub negotiate: Option<NegotiateData>,
    /// Negotiate state for the proxy.
    #[cfg(feature = "spnego")]
    pub negotiate_proxy: Option<NegotiateData>,
    /// Kerberos 5 state (no separate proxy instance in curl).
    #[cfg(feature = "gssapi")]
    pub kerberos5: Option<Kerberos5Data>,
    /// GSASL state (no separate proxy instance in curl).
    #[cfg(feature = "gsasl")]
    pub gsasl: Option<GsaslData>,
}

#[cfg(feature = "ntlm")]
impl ConnectionAuthState {
    /// Returns the NTLM state for the chosen direction, lazily creating it.
    ///
    /// Mirrors `Curl_auth_ntlm_get(conn, proxy)`: the appropriate (host or
    /// proxy) instance is initialized on first use with a zeroed state.
    pub fn ntlm_mut(&mut self, proxy: bool) -> &mut NtlmData {
        let slot = if proxy {
            &mut self.ntlm_proxy
        } else {
            &mut self.ntlm
        };
        slot.get_or_insert_with(NtlmData::default)
    }

    /// Removes the NTLM state for the chosen direction
    /// (`Curl_auth_ntlm_remove`).
    pub fn ntlm_remove(&mut self, proxy: bool) {
        if proxy {
            self.ntlm_proxy = None;
        } else {
            self.ntlm = None;
        }
    }
}

#[cfg(feature = "spnego")]
impl ConnectionAuthState {
    /// Returns the Negotiate state for the chosen direction, lazily creating it.
    ///
    /// Mirrors `Curl_auth_nego_get(conn, proxy)`.
    pub fn negotiate_mut(&mut self, proxy: bool) -> &mut NegotiateData {
        let slot = if proxy {
            &mut self.negotiate_proxy
        } else {
            &mut self.negotiate
        };
        slot.get_or_insert_with(NegotiateData::default)
    }
}

// =============================================================================
// Phase G — unit tests.
//
// These run under both the default feature set (ntlm + aws-sigv4 on; spnego /
// gssapi / gsasl off) and the all-auth-features set, so feature-dependent
// expectations are guarded with `#[cfg(...)]`.
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Phase B: ABI-exact constant values --------------------------------

    #[test]
    fn curlauth_constants_have_exact_abi_values() {
        assert_eq!(CURLAUTH_NONE, 0x0000_0000);
        assert_eq!(CURLAUTH_BASIC, 0x0000_0001);
        assert_eq!(CURLAUTH_DIGEST, 0x0000_0002);
        assert_eq!(CURLAUTH_NEGOTIATE, 0x0000_0004);
        assert_eq!(CURLAUTH_NTLM, 0x0000_0008);
        assert_eq!(CURLAUTH_DIGEST_IE, 0x0000_0010);
        assert_eq!(CURLAUTH_NTLM_WB, 0x0000_0020);
        assert_eq!(CURLAUTH_BEARER, 0x0000_0040);
        assert_eq!(CURLAUTH_AWS_SIGV4, 0x0000_0080);
        assert_eq!(CURLAUTH_ONLY, 0x8000_0000);
        // Derived masks (curl masks both to 32 bits).
        assert_eq!(CURLAUTH_ANY, 0xFFFF_FFEF);
        assert_eq!(CURLAUTH_ANYSAFE, 0xFFFF_FFEE);
        // Internal sentinel (lib/http.h).
        assert_eq!(CURLAUTH_PICKNONE, 0x4000_0000);
    }

    #[test]
    fn curlauth_aliases_equal_negotiate() {
        assert_eq!(CURLAUTH_GSSNEGOTIATE, CURLAUTH_NEGOTIATE);
        assert_eq!(CURLAUTH_GSSAPI, CURLAUTH_NEGOTIATE);
    }

    #[test]
    fn any_excludes_digest_ie_and_anysafe_also_excludes_basic() {
        // ANY must NOT contain the IE Digest bit.
        assert_eq!(CURLAUTH_ANY & CURLAUTH_DIGEST_IE, 0);
        assert_ne!(CURLAUTH_ANY & CURLAUTH_BASIC, 0);
        // ANYSAFE must exclude both IE Digest and Basic.
        assert_eq!(CURLAUTH_ANYSAFE & CURLAUTH_DIGEST_IE, 0);
        assert_eq!(CURLAUTH_ANYSAFE & CURLAUTH_BASIC, 0);
        // ...but still contain Digest, Negotiate, NTLM, Bearer.
        assert_ne!(CURLAUTH_ANYSAFE & CURLAUTH_DIGEST, 0);
        assert_ne!(CURLAUTH_ANYSAFE & CURLAUTH_NEGOTIATE, 0);
    }

    // ---- Phase C: AuthState ------------------------------------------------

    #[test]
    fn auth_state_new_seeds_picked_to_want() {
        let s = AuthState::new(CURLAUTH_ANY);
        assert_eq!(s.want, CURLAUTH_ANY);
        assert_eq!(s.picked, CURLAUTH_ANY); // seeded to `want`
        assert_eq!(s.avail, CURLAUTH_NONE);
        assert!(!s.done);
        assert!(!s.multipass);
        assert!(!s.iestyle);
        assert!(s.wants(CURLAUTH_BASIC));
        assert!(!s.available(CURLAUTH_BASIC));
    }

    // ---- Phase D: pick_one_auth preference order ---------------------------

    #[test]
    fn pick_prefers_digest_over_ntlm_and_basic() {
        // Required case: avail = BASIC|DIGEST|NTLM picks DIGEST (Digest and
        // Basic are always compiled; Digest outranks both NTLM and Basic).
        let mut p = AuthState::new(CURLAUTH_ANY);
        p.avail = CURLAUTH_BASIC | CURLAUTH_DIGEST | CURLAUTH_NTLM;
        assert!(pick_one_auth(&mut p, u32::MAX));
        assert_eq!(p.picked, CURLAUTH_DIGEST);
        // avail is cleared after a pick.
        assert_eq!(p.avail, CURLAUTH_NONE);
    }

    #[test]
    fn pick_respects_want_mask() {
        // Server offers Digest+Basic but the app only wants Basic.
        let mut p = AuthState::new(CURLAUTH_BASIC);
        p.avail = CURLAUTH_DIGEST | CURLAUTH_BASIC;
        assert!(pick_one_auth(&mut p, u32::MAX));
        assert_eq!(p.picked, CURLAUTH_BASIC);
    }

    #[test]
    fn pick_respects_runtime_mask() {
        // Bearer offered but masked out (no bearer token) → falls to Basic.
        let mut p = AuthState::new(CURLAUTH_ANY);
        p.avail = CURLAUTH_BEARER | CURLAUTH_BASIC;
        assert!(pick_one_auth(&mut p, build_auth_mask(false)));
        assert_eq!(p.picked, CURLAUTH_BASIC);
    }

    #[test]
    fn pick_none_when_nothing_acceptable() {
        // Only the IE Digest bit is offered, which CURLAUTH_ANY excludes.
        let mut p = AuthState::new(CURLAUTH_ANY);
        p.avail = CURLAUTH_DIGEST_IE;
        assert!(!pick_one_auth(&mut p, u32::MAX));
        assert_eq!(p.picked, CURLAUTH_PICKNONE);
        assert_eq!(p.avail, CURLAUTH_NONE);
    }

    #[test]
    fn pick_bearer_over_digest_when_offered() {
        let mut p = AuthState::new(CURLAUTH_ANY);
        p.avail = CURLAUTH_BEARER | CURLAUTH_DIGEST;
        // Bearer needs to remain in the mask (token present).
        assert!(pick_one_auth(&mut p, build_auth_mask(true)));
        assert_eq!(p.picked, CURLAUTH_BEARER);
    }

    #[cfg(feature = "spnego")]
    #[test]
    fn pick_prefers_negotiate_when_built() {
        // Required case: avail = NEGOTIATE|BASIC picks NEGOTIATE.
        let mut p = AuthState::new(CURLAUTH_ANY);
        p.avail = CURLAUTH_NEGOTIATE | CURLAUTH_BASIC;
        assert!(pick_one_auth(&mut p, u32::MAX));
        assert_eq!(p.picked, CURLAUTH_NEGOTIATE);
    }

    #[cfg(not(feature = "spnego"))]
    #[test]
    fn negotiate_not_picked_when_compiled_out() {
        // With SPNEGO compiled out, an offered Negotiate is skipped and the
        // next acceptable scheme (Basic) is chosen instead.
        let mut p = AuthState::new(CURLAUTH_ANY);
        p.avail = CURLAUTH_NEGOTIATE | CURLAUTH_BASIC;
        assert!(pick_one_auth(&mut p, u32::MAX));
        assert_eq!(p.picked, CURLAUTH_BASIC);
    }

    #[cfg(feature = "ntlm")]
    #[test]
    fn pick_ntlm_over_basic_when_built() {
        let mut p = AuthState::new(CURLAUTH_ANY);
        p.avail = CURLAUTH_NTLM | CURLAUTH_BASIC;
        assert!(pick_one_auth(&mut p, u32::MAX));
        assert_eq!(p.picked, CURLAUTH_NTLM);
    }

    #[cfg(feature = "aws-sigv4")]
    #[test]
    fn pick_aws_sigv4_lowest_preference() {
        let mut p = AuthState::new(CURLAUTH_ANY);
        p.avail = CURLAUTH_AWS_SIGV4;
        assert!(pick_one_auth(&mut p, u32::MAX));
        assert_eq!(p.picked, CURLAUTH_AWS_SIGV4);
        // But Basic outranks AWS SigV4 when both are offered.
        let mut p2 = AuthState::new(CURLAUTH_ANY);
        p2.avail = CURLAUTH_AWS_SIGV4 | CURLAUTH_BASIC;
        assert!(pick_one_auth(&mut p2, u32::MAX));
        assert_eq!(p2.picked, CURLAUTH_BASIC);
    }

    // ---- Phase D: masks and decision helpers -------------------------------

    #[test]
    fn auth_masks() {
        assert_eq!(build_auth_mask(true), u32::MAX);
        assert_eq!(build_auth_mask(false), !CURLAUTH_BEARER);
        assert_eq!(build_auth_mask(false) & CURLAUTH_BEARER, 0);
        // Proxy mask always clears Bearer, even when a token is present.
        assert_eq!(proxy_auth_mask(u32::MAX) & CURLAUTH_BEARER, 0);
        assert_eq!(proxy_auth_mask(build_auth_mask(true)) & CURLAUTH_BEARER, 0);
    }

    #[test]
    fn transient_1xx_detection() {
        assert!(is_transient_1xx(100));
        assert!(is_transient_1xx(150));
        assert!(is_transient_1xx(199));
        assert!(!is_transient_1xx(99));
        assert!(!is_transient_1xx(200));
        assert!(!is_transient_1xx(401));
    }

    #[test]
    fn should_pick_conditions() {
        assert!(host_should_pick(401, false));
        assert!(host_should_pick(200, true)); // authneg && < 300
        assert!(!host_should_pick(200, false));
        assert!(!host_should_pick(407, false)); // 407 is proxy, not host

        assert!(proxy_should_pick(407, false));
        assert!(proxy_should_pick(200, true));
        assert!(!proxy_should_pick(200, false));
        assert!(!proxy_should_pick(401, false)); // 401 is host, not proxy
    }

    #[test]
    fn ntlm_http1_downgrade_predicate() {
        assert!(needs_http1_downgrade_for_ntlm(CURLAUTH_NTLM, 20));
        assert!(needs_http1_downgrade_for_ntlm(CURLAUTH_NTLM, 30));
        assert!(!needs_http1_downgrade_for_ntlm(CURLAUTH_NTLM, 11));
        assert!(!needs_http1_downgrade_for_ntlm(CURLAUTH_BASIC, 20));
    }

    // ---- Phase D: http_auth_act orchestration ------------------------------

    #[test]
    fn auth_act_picks_host_on_401() {
        let mut host = AuthState::new(CURLAUTH_BASIC);
        host.avail = CURLAUTH_BASIC;
        let mut proxy = AuthState::default();
        let out = http_auth_act(&mut host, &mut proxy, 401, false, true, false, false, 11);
        assert!(out.picked_host);
        assert!(!out.authproblem);
        assert!(!out.force_http1);
        assert_eq!(out.httpauthpicked, CURLAUTH_BASIC);
        assert_eq!(host.picked, CURLAUTH_BASIC);
    }

    #[test]
    fn auth_act_ignores_transient_1xx() {
        let mut host = AuthState::new(CURLAUTH_BASIC);
        host.avail = CURLAUTH_BASIC;
        let mut proxy = AuthState::default();
        let out = http_auth_act(&mut host, &mut proxy, 100, false, true, false, false, 11);
        assert!(!out.picked_host);
        assert!(!out.picked_proxy);
        assert!(!out.authproblem);
    }

    #[test]
    fn auth_act_flags_authproblem_when_pick_fails() {
        let mut host = AuthState::new(CURLAUTH_BASIC);
        host.avail = CURLAUTH_NONE; // server offered nothing acceptable
        let mut proxy = AuthState::default();
        let out = http_auth_act(&mut host, &mut proxy, 401, false, true, false, false, 11);
        assert!(!out.picked_host);
        assert!(out.authproblem);
    }

    #[test]
    fn auth_act_picks_proxy_on_407() {
        let mut host = AuthState::default();
        let mut proxy = AuthState::new(CURLAUTH_ANY);
        proxy.avail = CURLAUTH_BASIC;
        let out = http_auth_act(&mut host, &mut proxy, 407, false, false, false, true, 11);
        assert!(out.picked_proxy);
        assert_eq!(out.proxyauthpicked, CURLAUTH_BASIC);
        assert_eq!(proxy.picked, CURLAUTH_BASIC);
    }

    #[cfg(feature = "ntlm")]
    #[test]
    fn auth_act_forces_http1_for_ntlm_over_h2() {
        let mut host = AuthState::new(CURLAUTH_NTLM);
        host.avail = CURLAUTH_NTLM;
        let mut proxy = AuthState::default();
        // httpversion_sent = 20 → HTTP/2 was sent.
        let out = http_auth_act(&mut host, &mut proxy, 401, false, true, false, false, 20);
        assert!(out.picked_host);
        assert_eq!(host.picked, CURLAUTH_NTLM);
        assert!(out.force_http1);
    }

    // ---- Phase D: parse_auth_header ----------------------------------------

    #[test]
    fn parse_basic_challenge() {
        let mut st = AuthState::new(CURLAUTH_ANY);
        let parsed = parse_auth_header(&mut st, "Basic realm=\"test\"");
        assert_ne!(st.avail & CURLAUTH_BASIC, 0);
        let c = parsed
            .challenges
            .iter()
            .find(|c| c.method == CURLAUTH_BASIC)
            .expect("basic challenge present");
        assert_eq!(c.params, "realm=\"test\"");
        assert!(!parsed.authproblem);
    }

    #[test]
    fn parse_multiple_methods_one_line() {
        let mut st = AuthState::new(CURLAUTH_ANY);
        // Digest has internal commas; Basic follows it on the same line.
        let parsed = parse_auth_header(
            &mut st,
            "Digest realm=\"x\", nonce=\"abc\", Basic realm=\"r\"",
        );
        assert_ne!(st.avail & CURLAUTH_DIGEST, 0);
        assert_ne!(st.avail & CURLAUTH_BASIC, 0);
        assert!(parsed
            .challenges
            .iter()
            .any(|c| c.method == CURLAUTH_DIGEST));
        assert!(parsed.challenges.iter().any(|c| c.method == CURLAUTH_BASIC));
    }

    #[test]
    fn parse_duplicate_digest_ignored() {
        let mut st = AuthState::new(CURLAUTH_ANY);
        let parsed = parse_auth_header(&mut st, "Digest realm=\"a\", Digest realm=\"b\"");
        // Only one Digest challenge is recorded.
        let digest_count = parsed
            .challenges
            .iter()
            .filter(|c| c.method == CURLAUTH_DIGEST)
            .count();
        assert_eq!(digest_count, 1);
    }

    #[test]
    fn parse_basic_rejected_when_already_picked() {
        let mut st = AuthState::new(CURLAUTH_BASIC);
        st.picked = CURLAUTH_BASIC; // we already chose Basic
        let parsed = parse_auth_header(&mut st, "Basic realm=\"x\"");
        assert!(parsed.authproblem);
        assert_eq!(st.avail, CURLAUTH_NONE);
    }

    #[test]
    fn parse_bearer_rejected_when_already_picked() {
        let mut st = AuthState::new(CURLAUTH_BEARER);
        st.picked = CURLAUTH_BEARER;
        let parsed = parse_auth_header(&mut st, "Bearer realm=\"x\"");
        assert!(parsed.authproblem);
        assert_eq!(st.avail, CURLAUTH_NONE);
    }

    #[cfg(feature = "spnego")]
    #[test]
    fn parse_negotiate_challenge_token() {
        let mut st = AuthState::new(CURLAUTH_ANY);
        let parsed = parse_auth_header(&mut st, "Negotiate YIIabc123");
        assert_ne!(st.avail & CURLAUTH_NEGOTIATE, 0);
        let c = parsed
            .challenges
            .iter()
            .find(|c| c.method == CURLAUTH_NEGOTIATE)
            .expect("negotiate challenge present");
        assert_eq!(c.params, "YIIabc123");
    }

    #[cfg(feature = "ntlm")]
    #[test]
    fn parse_ntlm_and_authcmp_boundary() {
        let mut st = AuthState::new(CURLAUTH_ANY);
        parse_auth_header(&mut st, "NTLM TlRMTVNTUA==");
        assert_ne!(st.avail & CURLAUTH_NTLM, 0);

        // "NTLMSSP" must NOT be recognized as the NTLM scheme (authcmp requires
        // a non-alphanumeric immediately after the scheme name).
        let mut st2 = AuthState::new(CURLAUTH_ANY);
        parse_auth_header(&mut st2, "NTLMSSP Zm9v");
        assert_eq!(st2.avail & CURLAUTH_NTLM, 0);
    }

    // ---- Phase E: build_spn ------------------------------------------------

    #[test]
    fn build_spn_all_branches() {
        assert_eq!(
            build_spn("HTTP", Some("host"), Some("realm")),
            "HTTP/host@realm"
        );
        assert_eq!(build_spn("HTTP", Some("host"), None), "HTTP/host");
        assert_eq!(build_spn("HTTP", None, Some("realm")), "HTTP@realm");
        assert_eq!(build_spn("HTTP", None, None), "");
    }

    // ---- Phase E: user_contains_domain -------------------------------------

    #[test]
    fn user_contains_domain_forms() {
        assert!(user_contains_domain("DOM\\user")); // Domain\User
        assert!(user_contains_domain("DOM/user")); // Domain/User
        assert!(user_contains_domain("user@dom")); // User@Domain
        assert!(!user_contains_domain("\\user")); // leading separator → false
        assert!(!user_contains_domain("user\\")); // trailing separator → false
        assert!(!user_contains_domain("user")); // no separator → false

        // Empty user is only valid under a GSS-API build. Bind the expectation
        // to a variable so this is not a bool-literal comparison.
        let empty_user_allowed = cfg!(feature = "gssapi");
        assert_eq!(user_contains_domain(""), empty_user_allowed);
    }

    // ---- Phase E: allowed_to_host ------------------------------------------

    #[test]
    fn allowed_to_host_gate() {
        // Not a follow → always allowed (even to a different host).
        assert!(allowed_to_host(
            false,
            false,
            Some("a.com"),
            443,
            1,
            "b.com",
            80,
            2
        ));
        // Follow + opt-in flag → allowed.
        assert!(allowed_to_host(
            true,
            true,
            Some("a.com"),
            443,
            1,
            "b.com",
            80,
            2
        ));
        // Follow, no opt-in, identical host/port/proto (host case-insensitive) → allowed.
        assert!(allowed_to_host(
            true,
            false,
            Some("A.COM"),
            443,
            1,
            "a.com",
            443,
            1
        ));
        // Required case: follow, no opt-in, different host → NOT allowed.
        assert!(!allowed_to_host(
            true,
            false,
            Some("a.com"),
            443,
            1,
            "b.com",
            443,
            1
        ));
        // Different port → NOT allowed.
        assert!(!allowed_to_host(
            true,
            false,
            Some("a.com"),
            443,
            1,
            "a.com",
            8443,
            1
        ));
        // Different protocol → NOT allowed.
        assert!(!allowed_to_host(
            true,
            false,
            Some("a.com"),
            443,
            1,
            "a.com",
            443,
            2
        ));
        // No recorded first host → NOT allowed.
        assert!(!allowed_to_host(true, false, None, 443, 1, "a.com", 443, 1));
    }

    // ---- shared base64 challenge helpers -----------------------------------

    #[test]
    fn base64_challenge_helpers_round_trip() {
        let encoded = encode_base64_message(b"hello").expect("encode");
        assert_eq!(encoded, b"aGVsbG8=");
        let decoded = decode_base64_challenge("aGVsbG8=").expect("decode");
        assert_eq!(decoded, b"hello");
        // Surrounding whitespace is trimmed before decoding.
        let decoded_ws = decode_base64_challenge("  aGVsbG8=  ").expect("decode ws");
        assert_eq!(decoded_ws, b"hello");
    }

    // ---- Phase F: per-connection state -------------------------------------

    #[cfg(feature = "ntlm")]
    #[test]
    fn connection_auth_state_ntlm_host_and_proxy_separate() {
        let mut cas = ConnectionAuthState::default();
        assert!(cas.ntlm.is_none());
        assert!(cas.ntlm_proxy.is_none());

        cas.ntlm_mut(false).flags = 0x1234;
        cas.ntlm_mut(false).state = NtlmState::Type1;
        assert!(cas.ntlm.is_some());
        assert!(cas.ntlm_proxy.is_none()); // proxy instance is independent
        assert_eq!(cas.ntlm.as_ref().unwrap().flags, 0x1234);
        assert_eq!(cas.ntlm.as_ref().unwrap().state, NtlmState::Type1);

        cas.ntlm_mut(true).nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        assert!(cas.ntlm_proxy.is_some());
        assert_eq!(cas.ntlm_proxy.as_ref().unwrap().nonce[7], 8);

        cas.ntlm_remove(false);
        assert!(cas.ntlm.is_none());
        assert!(cas.ntlm_proxy.is_some()); // proxy untouched
    }

    #[cfg(feature = "spnego")]
    #[test]
    fn connection_auth_state_negotiate_lazy_init() {
        let mut cas = ConnectionAuthState::default();
        assert!(cas.negotiate.is_none());
        cas.negotiate_mut(false).state = NegotiateState::Recv;
        assert_eq!(cas.negotiate.as_ref().unwrap().state, NegotiateState::Recv);
        assert!(cas.negotiate_proxy.is_none());
    }

    #[test]
    fn conn_meta_keys_match_curl() {
        assert_eq!(conn_meta::NTLM_CONN, "meta:auth:ntml:conn");
        assert_eq!(conn_meta::NTLM_PROXY_CONN, "meta:auth:ntml-proxy:conn");
        assert_eq!(conn_meta::KRB5_CONN, "meta:auth:krb5:conn");
        assert_eq!(conn_meta::GSASL_CONN, "meta:auth:gsasl:conn");
        assert_eq!(conn_meta::NEGO_CONN, "meta:auth:nego:conn");
        assert_eq!(conn_meta::NEGO_PROXY_CONN, "meta:auth:nego-proxy:conn");
    }
}
