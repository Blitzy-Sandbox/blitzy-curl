// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! Kerberos V5 (GSSAPI) authentication state.
//!
//! Language rewrite of curl `lib/vauth/krb5_gssapi.c` and the `struct kerberos5data` blob
//! (`lib/urldata.h`). Kerberos (and the Negotiate/SPNEGO mechanism built on it) is the ONLY
//! authentication path permitted to link an optional C library — the operating system's
//! GSSAPI/Kerberos implementation — behind the default-off `gssapi` feature (AAP §0.5.2). The
//! Windows SSPI variant is dropped. This module owns the per-connection Kerberos state; when
//! the `gssapi` feature is enabled the live GSSAPI security-context handle is tracked
//! alongside it.

/// Kerberos V5 handshake phase.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Kerberos5State {
    /// No exchange in progress.
    #[default]
    None,
    /// A GSSAPI security context is being established (token round-trips in progress).
    Negotiating,
    /// The security context is complete and the mechanism is authenticated.
    Complete,
}

/// Per-connection Kerberos V5 (GSSAPI) state (curl's `struct kerberos5data`).
///
/// In curl this blob was stored under `CURL_META_KRB5_CONN` and released by `krb5_conn_dtor`;
/// here ownership plus `Drop` replace that. The foundation state tracks the handshake phase
/// and the constructed service principal name; the OS GSSAPI context handle is attached to
/// this struct by the `gssapi`-gated context code.
#[derive(Debug, Default)]
pub struct Kerberos5Data {
    /// Current handshake phase.
    pub state: Kerberos5State,
    /// The service principal name (SPN) targeted for this connection, once built (for example
    /// `HTTP/host@REALM`).
    pub spn: Option<String>,
}
