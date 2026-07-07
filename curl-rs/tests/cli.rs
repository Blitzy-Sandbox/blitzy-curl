// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! Black-box integration tests for the `curl-rs` binary.
//!
//! These run the real executable (located via the `CARGO_BIN_EXE_curl-rs` path Cargo provides
//! to integration tests) and assert the two behaviors the foundation entry point implements:
//! the `--version` banner (curl parity form) and the argument-less usage guidance with exit
//! code 2. They intentionally do not assert any transfer behavior. Using `std::process`
//! directly keeps the smoke test free of external test-harness dependencies.

use std::process::Command;

/// Absolute path to the freshly built `curl-rs` binary, injected by Cargo for this test target.
const CURL_RS_BIN: &str = env!("CARGO_BIN_EXE_curl-rs");

/// `curl-rs --version` must succeed and print the parity banner
/// `curl-rs/<version> rustls flate2 brotli zstd hyper quinn russh`.
#[test]
fn version_flag_prints_parity_banner() {
    let output = Command::new(CURL_RS_BIN)
        .arg("--version")
        .output()
        .expect("failed to run `curl-rs --version`");
    assert!(
        output.status.success(),
        "`--version` should exit 0, got {:?}",
        output.status.code()
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in [
        "curl-rs/", "rustls", "flate2", "brotli", "zstd", "hyper", "quinn", "russh",
    ] {
        assert!(
            stdout.contains(needle),
            "version banner missing {needle:?}; got: {stdout}"
        );
    }
}

/// With no arguments the tool must exit with status 2 and print usage guidance to stderr,
/// mirroring curl's no-operand behavior.
#[test]
fn no_arguments_exits_two_with_usage_guidance() {
    let output = Command::new(CURL_RS_BIN)
        .output()
        .expect("failed to run `curl-rs` with no arguments");
    assert_eq!(
        output.status.code(),
        Some(2),
        "an argument-less invocation should exit with status 2"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("try 'curl-rs --help'"),
        "expected usage guidance on stderr; got: {stderr}"
    );
}

/// An unrecognized flag must be rejected by the parser with exit code 2, preserving curl's
/// option-parsing contract (unknown options are hard errors).
#[test]
fn unknown_flag_is_rejected() {
    let output = Command::new(CURL_RS_BIN)
        .arg("--this-flag-does-not-exist")
        .output()
        .expect("failed to run `curl-rs` with an unknown flag");
    assert_eq!(
        output.status.code(),
        Some(2),
        "an unrecognized flag should be rejected with exit status 2"
    );
}
