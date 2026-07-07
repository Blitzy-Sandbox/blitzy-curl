// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! SASL authentication engine (RFC 4422).
//!
//! Language rewrite of curl `lib/curl_sasl.c` + the SASL mechanism helpers in `lib/vauth/`
//! (`cleartext.c` for PLAIN/LOGIN, `cram.c`, `digest.c`, `krb5_gssapi.c`, ...). SASL is the
//! shared authentication framework used by the mail protocols (IMAP/POP3/SMTP). curl's
//! optional external `gsasl` C library is intentionally NOT used — every mechanism is
//! implemented in pure Rust (AAP §0.2 / auth root docs). This module owns the shared SASL
//! negotiation state.

/// SASL negotiation phase (subset of curl's `saslstate`, `lib/curl_sasl.h`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum SaslState {
    /// Idle — no authentication in progress (`SASL_STOP`).
    #[default]
    Stop,
    /// Sending the initial client response (`SASL_INIT`).
    Initial,
    /// Awaiting the final server acknowledgement (`SASL_FINAL`).
    Final,
    /// Cancelling the exchange after an error (`SASL_CANCEL`).
    Cancel,
}

/// Shared SASL engine state (curl's `struct SASL`, `lib/urldata.h`).
///
/// Tracks the current negotiation phase and the mechanism selection. `enabled_mechs` and
/// `selected_mech` are bitmasks over curl's `SASL_MECH_*` capability bits, preserving the
/// mechanism-preference semantics used when choosing which mechanism to attempt.
#[derive(Debug, Default)]
pub struct Sasl {
    /// Current negotiation phase.
    pub state: SaslState,
    /// Bitmask of mechanisms enabled/offered (curl's `SASL_MECH_*`).
    pub enabled_mechs: u32,
    /// The single mechanism selected for this exchange (a `SASL_MECH_*` bit), or `0` before
    /// selection.
    pub selected_mech: u32,
}
