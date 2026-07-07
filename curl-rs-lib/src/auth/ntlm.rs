// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! NTLM authentication state (pure-Rust).
//!
//! Language rewrite of curl `lib/vauth/ntlm.c` + `lib/curl_ntlm_core.c` and the
//! `struct ntlmdata` blob (`lib/urldata.h`). curl selected between a portable implementation
//! and a Windows SSPI implementation with `#ifdef USE_WINDOWS_SSPI`; this rewrite keeps only
//! the portable, pure-Rust path (the SSPI variant is dropped with the Windows backend,
//! AAP §0.2.2). This module owns the per-connection NTLM state on which the
//! type-1 / type-2 / type-3 message handlers operate.

/// NTLM handshake phase (curl's `ntlmstate`, `lib/vauth/ntlm.h`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum NtlmState {
    /// No NTLM exchange in progress (`NTLMSTATE_NONE`).
    #[default]
    None,
    /// The type-1 (negotiate) message has been sent (`NTLMSTATE_TYPE1`).
    Type1,
    /// The server's type-2 (challenge) message has been parsed (`NTLMSTATE_TYPE2`).
    Type2,
    /// The type-3 (authenticate) message has been sent (`NTLMSTATE_TYPE3`).
    Type3,
}

/// Per-connection NTLM state (curl's `struct ntlmdata`, minus the dropped SSPI handles).
///
/// In curl this blob lived in the connection meta-hashmap under `CURL_META_NTLM_CONN` and was
/// released by a hand-written destructor (`ntlm_conn_dtor`). Here it is a plain owned struct:
/// ownership replaces the hashmap lookup and the automatic `Drop` replaces the destructor (it
/// holds no OS handle).
#[derive(Debug, Default)]
pub struct NtlmData {
    /// Current handshake phase.
    pub state: NtlmState,
    /// The 8-byte server challenge nonce extracted from the type-2 message.
    pub nonce: [u8; 8],
    /// The negotiated NTLM flags (`NTLMFLAG_*`) carried across the exchange.
    pub flags: u32,
    /// The target-information (AV_PAIR) block copied from the type-2 message, consumed when
    /// computing the NTLMv2 response.
    pub target_info: Vec<u8>,
}
