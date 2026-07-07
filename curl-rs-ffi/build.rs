// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! Build script for `curl-rs-ffi` — the cbindgen C-header **generator** half of the
//! header-reconciliation strategy (AAP §0.6.1, §0.6.5; reconciliation approach "a").
//!
//! Cargo compiles and runs this script before building the crate. Its sole job is to invoke
//! `cbindgen` over this crate's `#[no_mangle] extern "C"` surface and render a C header that CI
//! can byte-diff — on *declarations* — against the authoritative, committed
//! `include/curl/curl.h` to prove ABI stability: function signatures, enum integer values,
//! struct layouts, typedefs, and callback function-pointer types.
//!
//! # Non-clobbering contract (the crux)
//!
//! The committed `include/curl/curl.h` is kept **byte-for-byte identical to curl 8.x** by the
//! `include/` folder: it aggregates seven sibling headers via `#include` and carries a large
//! deprecation-alias / argument-count-macro surface that many repository consumers and the
//! *unmodified* `tests/libtest/*.c` + `tests/runtests.pl` corpus depend on. Raw cbindgen output
//! cannot reproduce that file, so this script **never** writes over it. The `include/` folder
//! owns the committed-header reconciliation; this crate owns the generator.
//!
//! * The primary artifact is **always** written to `$OUT_DIR/curl.h` — the per-build scratch
//!   directory Cargo provides — so a plain `cargo build` succeeds and produces the verification
//!   header without touching any committed file.
//! * If (and only if) the opt-in [`HEADER_OUT_ENV`] environment variable is set, the same
//!   header is *also* written to that path so CI can locate it for the byte-diff step. It is
//!   never defaulted to the committed header path; refreshing the committed header is a
//!   deliberate, separately reviewed action a maintainer performs explicitly.
//!
//! # Robustness
//!
//! Header verification is a CI gate, not a hard build dependency of `libcurl_rs_ffi.{so,dylib}`,
//! so generation is best-effort: any cbindgen error is downgraded to a `cargo:warning` (never a
//! panic) and the committed header remains authoritative, so a transient tooling issue can
//! never break the build or block downstream crates. Setting [`SKIP_ENV`] skips generation
//! entirely, which is useful for constrained or offline CI legs.
//!
//! # Offline, target-scoped metadata
//!
//! `cbindgen.toml` sets `parse_deps = true` so cbindgen also resolves the ABI types that
//! originate in the sibling `curl-rs-lib` crate and are re-exported here behind `extern "C"`.
//! That makes cbindgen invoke `cargo metadata`, which by default resolves dependencies for
//! *every* target platform — pulling crates irrelevant to the four supported targets that may
//! be uncached or require a newer Cargo edition than the pinned MSRV toolchain. Enabling
//! [`cbindgen::Builder::with_only_target_dependencies`] restricts that resolve to the current
//! build target (cbindgen passes `--filter-platform $TARGET`, and Cargo sets `TARGET` for build
//! scripts), keeping generation deterministic and fully offline-safe in line with the Minimal
//! Change Mandate. It must follow `with_config`, which otherwise replaces the whole config.
//!
//! This build script is ordinary safe Rust that runs at build time and needs no low-level
//! escape hatches; the crate's raw FFI primitives live exclusively in `src/`.

use std::path::PathBuf;

/// Opt-in environment variable naming an *additional* path to which the generated header is
/// written (on top of `$OUT_DIR/curl.h`) so CI can byte-diff it against the committed
/// `include/curl/curl.h`. Deliberately never defaulted to the committed header path.
const HEADER_OUT_ENV: &str = "CURL_RS_HEADER_OUT";

/// Escape-hatch environment variable that, when present (with any value), disables cbindgen
/// generation entirely — useful for constrained or offline CI legs.
const SKIP_ENV: &str = "CURL_RS_SKIP_CBINDGEN";

fn main() {
    // Re-run control: regenerate the verification header whenever the cbindgen configuration,
    // this crate's manifest, or any FFI source changes (Cargo watches `src` recursively), and
    // whenever the opt-in output path or the skip switch toggles.
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-env-changed={HEADER_OUT_ENV}");
    println!("cargo:rerun-if-env-changed={SKIP_ENV}");

    // Escape hatch: skip generation entirely when requested. The rerun directives above are
    // still emitted so toggling the switch correctly re-triggers this build script.
    if std::env::var_os(SKIP_ENV).is_some() {
        return;
    }

    generate_verification_header();
}

/// Render this crate's C ABI surface to a verification header via cbindgen.
///
/// Writes `$OUT_DIR/curl.h` (always, on success) and — when [`HEADER_OUT_ENV`] is set — the same
/// content to that path as well. It deliberately targets `$OUT_DIR`, never
/// `include/curl/curl.h`, so the committed header remains the single authoritative artifact.
/// Any cbindgen failure is non-fatal: it emits a `cargo:warning` and leaves every committed file
/// untouched.
fn generate_verification_header() {
    // Both variables are guaranteed to be set by Cargo when running a build script; a missing
    // value indicates a broken invocation environment and is a legitimate hard error.
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR is always set by Cargo for build scripts");
    let out_dir =
        std::env::var("OUT_DIR").expect("OUT_DIR is always set by Cargo for build scripts");

    // Load this crate's cbindgen configuration explicitly. `cbindgen.toml` is config-only (it
    // intentionally sets no output path); the output location is decided here so the committed
    // header can never be clobbered.
    //
    // Loading is best-effort, exactly like the generation step below: a missing or malformed
    // `cbindgen.toml` is downgraded to a `cargo:warning` and returns cleanly — never a panic —
    // so a transient tooling issue can never break the build or block downstream crates (module
    // docs, "# Robustness"). The committed include/curl/curl.h stays authoritative regardless.
    let config = match cbindgen::Config::from_file(format!("{crate_dir}/cbindgen.toml")) {
        Ok(config) => config,
        Err(err) => {
            println!(
                "cargo:warning=curl-rs-ffi: cbindgen config load skipped ({err}); \
                 the committed include/curl/curl.h remains authoritative"
            );
            return;
        }
    };

    // Build the bindings from this crate's `extern "C"` surface. See the module docs for why
    // `with_only_target_dependencies(true)` is required and must come after `with_config`.
    let bindings = cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .with_only_target_dependencies(true)
        .generate();

    match bindings {
        Ok(bindings) => {
            // Primary, non-clobbering artifact in the per-build scratch directory.
            bindings.write_to_file(PathBuf::from(&out_dir).join("curl.h"));

            // Optional opt-in verification path for the CI byte-diff step. Guard it so it can
            // never clobber the committed `include/curl/curl.h` even if a caller points the env
            // var straight at it (directly, or via a symlink / `..` path): that header is kept
            // byte-identical to curl 8.x and owned by the `include/` folder, and refreshing it is
            // a deliberate, separately reviewed maintainer action — a plain build must never
            // mutate it (module docs, "# Non-clobbering contract").
            if let Ok(extra) = std::env::var(HEADER_OUT_ENV) {
                if resolves_to_committed_header(&crate_dir, &extra) {
                    println!(
                        "cargo:warning=curl-rs-ffi: {HEADER_OUT_ENV} resolves to the committed \
                         include/curl/curl.h; refusing to overwrite it (wrote $OUT_DIR/curl.h only)"
                    );
                } else {
                    bindings.write_to_file(extra);
                }
            }
        }
        Err(err) => {
            // Non-fatal: header verification is a CI gate, not a hard build dependency of the
            // produced shared object. The committed include/curl/curl.h stays authoritative.
            println!(
                "cargo:warning=curl-rs-ffi: cbindgen header generation skipped ({err}); \
                 the committed include/curl/curl.h remains authoritative"
            );
        }
    }
}

/// Returns `true` when `target` resolves to the same file as the committed
/// `include/curl/curl.h` (the curl-8.x-identical reference header), so the opt-in
/// [`HEADER_OUT_ENV`] write can be refused rather than clobbering it.
///
/// The committed header sits at `{crate_dir}/../include/curl/curl.h`. Both paths are compared
/// after [`std::fs::canonicalize`], which resolves symlinks and `..` segments, so an indirect
/// path cannot smuggle the write through. If either path fails to canonicalize the paths are
/// treated as distinct and the write proceeds: the committed header already exists on disk, so a
/// `target` that cannot be canonicalized (because it does not exist yet) provably is not it.
fn resolves_to_committed_header(crate_dir: &str, target: &str) -> bool {
    let committed = PathBuf::from(crate_dir).join("../include/curl/curl.h");
    match (
        committed.canonicalize(),
        PathBuf::from(target).canonicalize(),
    ) {
        (Ok(committed), Ok(target)) => committed == target,
        _ => false,
    }
}
