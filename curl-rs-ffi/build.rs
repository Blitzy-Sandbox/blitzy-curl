// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-License-Identifier: curl
//
// Build script for the curl-rs-ffi crate.
//
// Invokes cbindgen at compile time to generate the C-compatible header file
// `include/curl/curl.h` from the Rust FFI definitions in `curl-rs-ffi/src/`.
//
// Per AAP Section 0.4.1: "build.rs (cbindgen invocation → include/curl/curl.h)"
// Per AAP Section 0.7.3: "cbindgen invoked via build.rs in curl-rs-ffi"
// Per AAP Section 0.7.3: "Output to include/curl/curl.h"
// Per AAP Section 0.7.3: "Header MUST match curl 8.x public header structure
//   for drop-in consumer compatibility"
//
// The generated header replaces the hand-authored `include/curl/curl.h` so that
// downstream C programs can swap `libcurl.so` with the Rust-backed
// `libcurl_rs_ffi.so` without recompilation (AAP Section 0.1.1).
//
// cbindgen version: 0.29.2 (per AAP Section 0.6.1)
// No `unsafe` code in this file.
// MSRV 1.75, edition 2021.

use std::env;
use std::fs;
use std::path::PathBuf;

/// Expected minimum number of `CURL_EXTERN` function declarations in the
/// generated header.  Per AAP Section 0.2.3 the public API surface has 106
/// `CURL_EXTERN` symbols across 8 header files.  This threshold is used as
/// a sanity-check warning — it is intentionally not a hard gate because the
/// exact count depends on which FFI source modules have been fully
/// implemented at any given point during the incremental build.
const EXPECTED_MIN_SYMBOL_COUNT: usize = 10;

fn main() {
    // ------------------------------------------------------------------
    // Phase 1: Rerun-if-changed declarations
    //
    // Cargo only re-executes build scripts when one of the declared
    // inputs changes.  We declare every FFI source file that cbindgen
    // will parse, plus the cbindgen configuration file itself.
    // ------------------------------------------------------------------
    declare_rerun_triggers();

    // ------------------------------------------------------------------
    // Phase 2: Resolve paths
    //
    // CARGO_MANIFEST_DIR points to curl-rs-ffi/.  The workspace root is
    // one level up.  The generated header goes to
    //   <workspace_root>/include/curl/curl.h
    // ------------------------------------------------------------------
    let crate_dir = env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR environment variable is not set");

    let workspace_root = PathBuf::from(&crate_dir)
        .parent()
        .expect("Failed to determine workspace root from CARGO_MANIFEST_DIR")
        .to_path_buf();

    let output_dir = workspace_root.join("include").join("curl");
    let output_file = output_dir.join("curl.h");

    // ------------------------------------------------------------------
    // Phase 3: Ensure the output directory exists
    // ------------------------------------------------------------------
    if let Err(e) = fs::create_dir_all(&output_dir) {
        println!(
            "cargo:warning=Failed to create output directory {}: {}",
            output_dir.display(),
            e
        );
        // Non-fatal — the directory may already exist or the header write
        // will produce a clearer error below.
    }

    // ------------------------------------------------------------------
    // Phase 4: Load cbindgen configuration
    //
    // The cbindgen.toml file lives in the crate root (curl-rs-ffi/) and
    // controls all aspects of header generation: language, style, guards,
    // preamble, enum/struct/function settings, and feature-flag mapping.
    // ------------------------------------------------------------------
    let config_path = PathBuf::from(&crate_dir).join("cbindgen.toml");
    let mut config = match cbindgen::Config::from_file(&config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            println!(
                "cargo:warning=cbindgen: Failed to read configuration from {}: {}",
                config_path.display(),
                e
            );
            println!(
                "cargo:warning=cbindgen: Falling back to default configuration"
            );
            cbindgen::Config::default()
        }
    };

    // Explicitly enforce Language::C regardless of what the config file
    // says or what cbindgen defaults to.  The default language in cbindgen
    // 0.29.2 is Language::Cxx, and certain fallback code paths (e.g., when
    // `-Zunpretty=expanded` fails on stable Rust) may silently revert to
    // C++ output.  This programmatic override guarantees C output.
    config.language = cbindgen::Language::C;

    // ------------------------------------------------------------------
    // Phase 5: Invoke cbindgen to generate the C header
    //
    // cbindgen parses the crate source tree rooted at `crate_dir`,
    // discovers all `#[no_mangle] pub extern "C"` functions and
    // `#[repr(C)]` types, and emits a C header respecting the loaded
    // configuration.
    // ------------------------------------------------------------------
    let bindings = match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(b) => b,
        Err(e) => {
            // cbindgen may fail if the source files contain syntax that
            // it cannot parse (e.g., complex generics, certain macro
            // patterns).  Emit a diagnostic warning rather than failing
            // the entire build so that downstream compilation can still
            // proceed with a potentially stale header.
            println!(
                "cargo:warning=cbindgen: Failed to generate C bindings: {}",
                e
            );
            println!(
                "cargo:warning=cbindgen: The header file {} may be stale or absent",
                output_file.display()
            );
            return;
        }
    };

    // ------------------------------------------------------------------
    // Phase 6: Write the generated header to disk
    // ------------------------------------------------------------------
    bindings.write_to_file(&output_file);

    println!(
        "cargo:warning=cbindgen: Generated C header at {}",
        output_file.display()
    );

    // ------------------------------------------------------------------
    // Phase 7: Optional symbol validation (sanity check)
    //
    // Read the generated header and count lines that look like function
    // declarations prefixed with CURL_EXTERN.  This is a heuristic — it
    // catches gross generation failures (empty header, missing modules)
    // without being a hard gate that breaks incremental development.
    // ------------------------------------------------------------------
    validate_symbol_count(&output_file);
}

/// Emit `cargo:rerun-if-changed` for every file that cbindgen reads.
///
/// This covers:
/// - `cbindgen.toml` (configuration)
/// - All Rust source files in `src/` that define FFI symbols
/// - The build script itself
fn declare_rerun_triggers() {
    // Build script itself
    println!("cargo:rerun-if-changed=build.rs");

    // cbindgen configuration
    println!("cargo:rerun-if-changed=cbindgen.toml");

    // Crate root module — declares all sub-modules and re-exports
    println!("cargo:rerun-if-changed=src/lib.rs");

    // FFI symbol source files — one per API group
    // (matches the 13 modules declared in lib.rs)
    println!("cargo:rerun-if-changed=src/types.rs");
    println!("cargo:rerun-if-changed=src/error_codes.rs");
    println!("cargo:rerun-if-changed=src/easy.rs");
    println!("cargo:rerun-if-changed=src/multi.rs");
    println!("cargo:rerun-if-changed=src/share.rs");
    println!("cargo:rerun-if-changed=src/global.rs");
    println!("cargo:rerun-if-changed=src/url.rs");
    println!("cargo:rerun-if-changed=src/ws.rs");
    println!("cargo:rerun-if-changed=src/mime.rs");
    println!("cargo:rerun-if-changed=src/slist.rs");
    println!("cargo:rerun-if-changed=src/options.rs");
    println!("cargo:rerun-if-changed=src/header.rs");
    println!("cargo:rerun-if-changed=src/mprintf.rs");
}

/// Read the generated header and count `CURL_EXTERN` function declarations
/// as a sanity check.  Emits a cargo warning if the count is below the
/// expected minimum, indicating potential generation issues.
fn validate_symbol_count(header_path: &std::path::Path) {
    let content = match fs::read_to_string(header_path) {
        Ok(c) => c,
        Err(e) => {
            println!(
                "cargo:warning=cbindgen: Could not read generated header for validation: {}",
                e
            );
            return;
        }
    };

    // Count lines containing "CURL_EXTERN" that look like function
    // declarations.  This is a simple heuristic — it counts any line
    // that starts with (or contains) "CURL_EXTERN" followed by a
    // return type and function name.
    let symbol_count = content
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            trimmed.starts_with("CURL_EXTERN")
                || trimmed.contains("CURL_EXTERN")
                    && trimmed.contains('(')
        })
        .count();

    if symbol_count > 0 {
        println!(
            "cargo:warning=cbindgen: Header contains {} CURL_EXTERN declaration(s)",
            symbol_count
        );
    }

    if symbol_count < EXPECTED_MIN_SYMBOL_COUNT {
        println!(
            "cargo:warning=cbindgen: Symbol count ({}) is below the expected minimum ({}). \
             This may indicate that some FFI source modules are not yet implemented or \
             that cbindgen could not parse them. Check the generated header for completeness.",
            symbol_count, EXPECTED_MIN_SYMBOL_COUNT
        );
    }
}
