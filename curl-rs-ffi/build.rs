//! Build script for `curl-rs-ffi` — the drop-in `libcurl` FFI crate.
//!
//! Two responsibilities, both mandated by the Agent Action Plan:
//!
//! 1. **C header generation (AAP §0.5.2 / §0.8.4 step 13).** Invoke `cbindgen`
//!    against this crate's `extern "C"` / `#[no_mangle]` / `#[repr(C)]` items to
//!    (re)generate a consolidated C header. The curated `include/curl/*.h`
//!    headers remain the authoritative libcurl ABI (see `cbindgen.toml`); the
//!    generated header is a *synchronization / verification* artifact, written
//!    to the git-ignored `curl-rs-ffi/generated_curl.h`. Generation is therefore
//!    **best-effort**: any failure emits a `cargo:warning` and never fails the
//!    build, so the zero-warnings build gate (AAP §0.8.1) is unaffected by the
//!    state of the (non-authoritative) generated header.
//!
//! 2. **macOS shared-library identity.** Stamp the drop-in `install_name` on the
//!    `cdylib` so it loads as `libcurl` at `@rpath/libcurl.4.dylib`, matching the
//!    Linux `DT_SONAME = libcurl.so.4` set in the root `.cargo/config.toml`.
//!    Applying it here (cdylib-scoped, gated on the *target* OS via
//!    `CARGO_CFG_TARGET_OS`) avoids the double-set that would occur if it were
//!    also placed in `.cargo/config.toml`.

use std::env;
use std::path::PathBuf;

fn main() {
    // The crate root directory (contains Cargo.toml, src/, cbindgen.toml).
    let crate_dir = env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR is always set by Cargo for build scripts");

    // -----------------------------------------------------------------------
    // Rerun triggers: regenerate the header only when the FFI surface, the
    // cbindgen configuration, or this script itself changes. Without these,
    // Cargo would rerun the script on every build (any change in the package).
    // -----------------------------------------------------------------------
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=build.rs");

    // -----------------------------------------------------------------------
    // macOS install_name (drop-in shared-library identity). Gated on the TARGET
    // OS so cross-compiling to macOS works and native Linux builds skip it.
    // `rustc-cdylib-link-arg` scopes the flag to the cdylib artifact only.
    // -----------------------------------------------------------------------
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "macos" {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/libcurl.4.dylib");
    }

    // -----------------------------------------------------------------------
    // Best-effort cbindgen header generation. The curated headers are
    // authoritative, so generation NEVER fails the build: on error we emit a
    // diagnostic `cargo:warning` and continue. `cbindgen.toml` is read from the
    // crate root (it pins `parse_deps = false`, so only this crate is parsed).
    // -----------------------------------------------------------------------
    let config = cbindgen::Config::from_root_or_default(&crate_dir);
    let output = PathBuf::from(&crate_dir).join("generated_curl.h");

    match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(bindings) => {
            // `write_to_file` only rewrites the file when the contents change,
            // so it does not needlessly bump mtimes / trigger downstream rebuilds.
            bindings.write_to_file(&output);
        }
        Err(err) => {
            println!(
                "cargo:warning=cbindgen header generation skipped (curated include/curl/*.h \
                 headers remain authoritative): {err}"
            );
        }
    }
}
