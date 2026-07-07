// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! Build script for `curl-rs-ffi`.
//!
//! Its sole job is optional **verification** of the generated C header: when the `capi`
//! feature is enabled it invokes `cbindgen` to render this crate's `extern "C"` surface into
//! `$OUT_DIR/curl_verification.h`. That artifact exists only so CI can byte-diff the generated
//! `CURLcode` declaration against the authoritative, committed `include/curl/curl.h`; the build
//! script **never** writes over that committed header.
//!
//! `cbindgen` is a default-OFF, optional build-dependency (gated by `capi`) precisely so a
//! stock `cargo build` and the mandatory `cargo +1.75 check` MSRV gate never compile it — the
//! header-verification path is a CI concern and must not perturb the workspace's build or its
//! Minimum Supported Rust Version. When `capi` is disabled this script only records the
//! rerun triggers below.

fn main() {
    // Re-run whenever the ABI source or the cbindgen configuration changes so a stale
    // verification header is never reused.
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");

    #[cfg(feature = "capi")]
    generate_verification_header();
}

/// Render the crate's C ABI surface to a verification header in `OUT_DIR` via cbindgen.
///
/// This reads `cbindgen.toml` from the crate root and writes `$OUT_DIR/curl_verification.h`.
/// It deliberately targets `OUT_DIR` — never `include/curl/curl.h` — so the committed header
/// remains the single authoritative artifact. Any cbindgen failure is non-fatal: it emits a
/// cargo warning and leaves the committed header untouched, so a transient tooling issue can
/// never break the build.
#[cfg(feature = "capi")]
fn generate_verification_header() {
    use std::path::PathBuf;

    let crate_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR is always set for build scripts");
    let out_path =
        PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is always set for build scripts"))
            .join("curl_verification.h");

    match cbindgen::generate(&crate_dir) {
        Ok(bindings) => {
            // `write_to_file` only rewrites the file when the contents actually change.
            bindings.write_to_file(&out_path);
        }
        Err(err) => {
            println!(
                "cargo:warning=curl-rs-ffi: cbindgen verification header skipped ({err}); \
                 the committed include/curl/curl.h remains authoritative"
            );
        }
    }
}
