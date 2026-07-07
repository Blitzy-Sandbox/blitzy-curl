// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! HTTP Basic authentication (RFC 7617).
//!
//! Language rewrite of curl's Basic-credential producer (`http_output_basic`, `lib/http.c`).
//! Basic is a single-shot, stateless mechanism: it ignores any server challenge and emits
//! `base64(user ":" password)`. It is the canonical implementation of the shared
//! [`AuthMechanism`] trait defined by the parent module.

use super::{AuthContext, AuthMechanism, CURLAUTH_BASIC};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

/// HTTP Basic authentication mechanism (RFC 7617).
///
/// Carries no per-connection state — the credentials come from the [`AuthContext`] supplied at
/// [`output`](AuthMechanism::output) time — so it is a zero-sized type.
#[derive(Debug, Default, Clone, Copy)]
pub struct Basic;

impl AuthMechanism for Basic {
    /// Basic carries no challenge state. Any parameters after `Basic` in a
    /// `WWW-Authenticate` header (such as `realm`) do not affect the response, so they are
    /// accepted and ignored, matching curl.
    fn decode(&mut self, _challenge: &str) -> crate::error::Result<()> {
        Ok(())
    }

    /// Produce the `basic-credentials` token: `base64(user ":" password)` (RFC 7617 §2). curl
    /// builds the byte-identical value in `http_output_basic()`.
    fn output(&mut self, ctx: &AuthContext) -> crate::error::Result<String> {
        let credentials = format!("{}:{}", ctx.username, ctx.password);
        Ok(STANDARD.encode(credentials.as_bytes()))
    }

    fn capability_bit(&self) -> u32 {
        CURLAUTH_BASIC
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_encodes_user_and_password() {
        let mut basic = Basic;
        let ctx = AuthContext {
            username: "user".to_owned(),
            password: "pass".to_owned(),
            ..AuthContext::default()
        };
        // base64("user:pass") == "dXNlcjpwYXNz".
        assert_eq!(basic.output(&ctx).unwrap(), "dXNlcjpwYXNz");
        assert_eq!(basic.capability_bit(), CURLAUTH_BASIC);
    }

    #[test]
    fn basic_ignores_challenge() {
        let mut basic = Basic;
        assert!(basic.decode("realm=\"example\"").is_ok());
    }
}
