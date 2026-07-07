// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! Negotiate (SPNEGO) authentication state.
//!
//! Language rewrite of curl `lib/vauth/spnego_gssapi.c` + `lib/http_negotiate.c` and the
//! `struct negotiatedata` blob (`lib/urldata.h`). Negotiate wraps the Kerberos V5 / GSSAPI
//! mechanism (see [`super::kerberos`]) in SPNEGO and is gated by the default-off `spnego`
//! feature; the Windows SSPI variant is dropped (AAP §0.2.2). This module owns the
//! per-connection Negotiate state that the challenge/response handler drives.

/// Negotiate (SPNEGO) handshake phase.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum NegotiateState {
    /// No exchange in progress.
    #[default]
    None,
    /// A SPNEGO token exchange is in progress.
    Negotiating,
    /// The exchange is complete and the mechanism is authenticated.
    Complete,
}

/// Per-connection Negotiate (SPNEGO) state (curl's `struct negotiatedata`).
///
/// In curl this blob was stored under `CURL_META_NEGO_CONN` and released by `nego_conn_dtor`;
/// here ownership plus `Drop` replace that. The boolean fields preserve curl's persistence and
/// multi-request tracking flags so `--trace` diagnostics and connection-reuse decisions match.
#[derive(Debug, Default)]
pub struct NegotiateData {
    /// Current handshake phase.
    pub state: NegotiateState,
    /// Whether the connection must NOT be kept authenticated across requests
    /// (`noauthpersist`).
    pub noauthpersist: bool,
    /// Whether `noauthpersist` has been determined for this connection
    /// (`havenoauthpersist`).
    pub havenoauthpersist: bool,
    /// Whether Negotiate response data is currently buffered (`havenegdata`).
    pub havenegdata: bool,
    /// Whether multiple requests have been observed on this connection
    /// (`havemultiplerequests`).
    pub havemultiplerequests: bool,
}
