//! Build script for `curl-rs-ffi` — the drop-in `libcurl` FFI crate.
//!
//! This script has exactly **two responsibilities**, both mandated by the Agent
//! Action Plan (§0.5.2 / §0.8.4 step 13). It deliberately does nothing else
//! (minimal-change mandate, AAP §0.8.1):
//!
//! 1. **C header generation via `cbindgen`.** Parse this crate's `extern "C"` /
//!    `#[no_mangle]` / `#[repr(C)]` items and (re)generate a consolidated C
//!    header, driven entirely by the curated `curl-rs-ffi/cbindgen.toml` (the
//!    config is *loaded*, never hardcoded here). The generated header is a
//!    *synchronization / verification* artifact, not a compile input of the
//!    `cdylib`; the published `include/curl/*.h` headers remain the
//!    authoritative libcurl ABI.
//!
//! 2. **macOS shared-library identity.** Stamp the `cdylib`'s `install_name`
//!    so it loads as `libcurl` at `@rpath/libcurl.4.dylib`, mirroring the Linux
//!    `DT_SONAME = libcurl.so.4` that the root `.cargo/config.toml` sets via
//!    target rustflags. This is a `cdylib`-scoped link arg and so must be
//!    emitted from a build script (not from global rustflags, which would also
//!    reach the `curl-rs` executable link and warn).
//!
//! # Three hard rules (do not violate)
//!
//! * **Single-colon `cargo:` directives ONLY.** The workspace MSRV is 1.75
//!   (edition 2021); Cargo 1.75 understands only the single-colon
//!   `cargo:KEY=VALUE` build-script syntax. The newer double-colon directive
//!   form (introduced in Cargo 1.77) would be ignored or error on 1.75. Every
//!   directive emitted below therefore uses single-colon `cargo:`.
//! * **install_name = `@rpath/libcurl.4.dylib`.** The SONAME/dylib-compat
//!   version is `4`, derived from `lib/Makefile.soname` (`-version-info 12:0:8`
//!   → current − age = 12 − 8 = 4). Emitted only when the *target* OS is macOS.
//! * **Curated header wins.** `build.rs` must never *unconditionally* overwrite
//!   the hand-curated `include/curl/curl.h`. By default the generated header is
//!   written only to the throwaway `OUT_DIR/curl.h` (for verification/diffing);
//!   writing into the source tree's `include/curl/` is an explicit, opt-in
//!   maintainer action gated on the `CURL_RS_REGEN_HEADER` environment variable.

use std::env;
use std::path::PathBuf;

fn main() {
    // ------------------------------------------------------------------------
    // Phase 1 — Cargo-provided locations.
    //
    // `CARGO_MANIFEST_DIR` is the crate root (holds Cargo.toml, cbindgen.toml,
    // src/). `OUT_DIR` is Cargo's per-build scratch directory (under `target/`,
    // already git-ignored). Both are guaranteed to be set for build scripts.
    // ------------------------------------------------------------------------
    let crate_dir = env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR is always set by Cargo for build scripts");
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR is always set by Cargo for build scripts");
    let crate_path = PathBuf::from(&crate_dir);
    let out_path = PathBuf::from(&out_dir);

    // ------------------------------------------------------------------------
    // Phase 2 — Scoped rerun triggers (single-colon `cargo:` only).
    //
    // Re-run this script only when the inputs that actually shape its output
    // change: the FFI source (the header is derived from these items), the
    // cbindgen config, this script itself, or the opt-in regen toggle. A blanket
    // rerun on the whole crate is intentionally avoided.
    // ------------------------------------------------------------------------
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-env-changed=CURL_RS_REGEN_HEADER");

    // ------------------------------------------------------------------------
    // Phase 5 — macOS `install_name` (delegated from `.cargo/config.toml`).
    //
    // A build script runs on the HOST, so the *target* OS must be read from the
    // Cargo-provided `CARGO_CFG_TARGET_OS` env var (NOT host `cfg!(...)`), which
    // makes cross-compiling to macOS work correctly. `rustc-cdylib-link-arg`
    // scopes the flag to the `cdylib` artifact only — it never reaches the
    // `curl-rs` executable link (where `-install_name` would warn).
    //
    // The Linux `DT_SONAME = libcurl.so.4` is set in `.cargo/config.toml`; the
    // macOS install_name is set HERE (the only place a cdylib-scoped link arg
    // can live). Both encode SONAME version `4` from `lib/Makefile.soname`
    // (`-version-info 12:0:8` → current − age = 12 − 8 = 4). Emitted before the
    // best-effort header generation below so the dylib's drop-in identity can
    // never be affected by the state of the (non-authoritative) generated header.
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "macos" {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/libcurl.4.dylib");
    }

    // ------------------------------------------------------------------------
    // Phase 4 (gate) — opt-in to regenerate the curated header.
    //
    // The curated `include/curl/*.h` headers win: cbindgen cannot reproduce
    // curl's full header surface (the C-variadic `curl_easy_setopt` /
    // `curl_easy_getinfo` / `curl_multi_setopt` signatures, the 8-header split,
    // the exact `CURLcode` integers, `CURL_TEMP_PRINTF`, and the typecheck-gcc
    // macros). Writing into the source tree is therefore OFF by default and only
    // enabled when `CURL_RS_REGEN_HEADER` is `1`/`true` (case-insensitive). This
    // is a documented maintainer convenience, not a runtime/build secret.
    let regen_requested = env::var("CURL_RS_REGEN_HEADER")
        .is_ok_and(|val| matches!(val.trim().to_ascii_lowercase().as_str(), "1" | "true"));

    // ------------------------------------------------------------------------
    // Phase 3 — cbindgen header generation (guarded; best-effort by default).
    //
    // The cbindgen configuration is LOADED from the curated `cbindgen.toml`
    // (never hardcoded here). A failure to read/parse that committed config is a
    // genuine misconfiguration, so it is propagated with a clear message.
    // ------------------------------------------------------------------------
    let config = cbindgen::Config::from_file(crate_path.join("cbindgen.toml"))
        .expect("failed to load curl-rs-ffi/cbindgen.toml");

    match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(bindings) => {
            // Always write to the safe, throwaway OUT_DIR target first. This is
            // git-ignored (under `target/`) and never clobbers anything curated.
            let out_header = out_path.join("curl.h");
            bindings.write_to_file(&out_header);

            if regen_requested {
                // Phase 4 (enabled) — ALSO (re)write the curated source header,
                // resolved from the crate root's parent (the workspace root):
                // `../include/curl/curl.h`. This is an explicit maintainer
                // action; the result MUST be reconciled by hand because cbindgen
                // cannot express several libcurl constructs (see the gate above).
                let curated_header = crate_path
                    .parent()
                    .expect("curl-rs-ffi crate dir must have a parent (the workspace root)")
                    .join("include")
                    .join("curl")
                    .join("curl.h");
                bindings.write_to_file(&curated_header);
                println!(
                    "cargo:warning=CURL_RS_REGEN_HEADER set: regenerated {} from cbindgen. \
                     REVIEW/DIFF REQUIRED before committing — cbindgen cannot reproduce the \
                     C-variadic curl_easy_setopt/curl_easy_getinfo/curl_multi_setopt \
                     signatures, the 8-header split, the exact CURLcode integers, \
                     CURL_TEMP_PRINTF, or the typecheck-gcc macros; restore those by hand.",
                    curated_header.display()
                );
            } else {
                // Phase 4 (default) — leave the curated header untouched; point
                // maintainers at the throwaway copy for verification/diffing.
                println!(
                    "cargo:warning=cbindgen header generated at {} for verification/diffing \
                     only; the curated include/curl/curl.h remains authoritative. Set \
                     CURL_RS_REGEN_HEADER=1 to also (re)write the curated header.",
                    out_header.display()
                );
            }
        }
        Err(err) => {
            if regen_requested {
                // A deliberate regeneration must not silently leave a stale
                // curated header, so fail loudly when explicitly requested.
                panic!(
                    "CURL_RS_REGEN_HEADER is set but cbindgen header generation failed; \
                     refusing to leave a stale curated include/curl/curl.h: {err}"
                );
            } else {
                // Default path: header generation is a synchronization aid, not a
                // compile dependency of the cdylib, and the crate may not yet
                // fully parse during early scaffolding. Warn and continue so the
                // zero-warnings BUILD gate (rustc/clippy) is unaffected.
                println!(
                    "cargo:warning=cbindgen header generation skipped (curated \
                     include/curl/*.h headers remain authoritative): {err}"
                );
            }
        }
    }
}
