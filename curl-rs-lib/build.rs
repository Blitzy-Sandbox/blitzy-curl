//! Build script for the `curl-rs-lib` crate.
//!
//! This build script performs the following tasks at compile time:
//!
//! 1. **Symbol Inventory Generation** — Generates `symbol_inventory.rs` in `$OUT_DIR`
//!    containing a constant array of all public `CURL_EXTERN` symbol names from the
//!    libcurl 8.19.0-DEV C API headers. This is consumed by the FFI crate
//!    (`curl-rs-ffi`) to validate symbol coverage at compile time and ensure that
//!    every public API symbol has a corresponding Rust implementation.
//!
//! 2. **Version Information Embedding** — Exposes version constants from
//!    `include/curl/curlver.h` as `cargo:rustc-env` variables so they are available
//!    at compile time via `env!()` macros in library code.
//!
//! 3. **Platform Detection** — Detects the target operating system and architecture,
//!    emitting `cargo:rustc-cfg` directives for platform-specific code paths.
//!
//! 4. **Feature Reporting** — Emits metadata about enabled Cargo feature flags as
//!    environment variables for introspection by the version/info subsystem.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // =========================================================================
    // Rebuild triggers
    // =========================================================================
    // Only re-run this build script when it changes or when the feature
    // override environment variable changes. This avoids unnecessary rebuilds
    // for normal source code edits.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CURL_RS_FEATURES");

    // =========================================================================
    // Version information (matching include/curl/curlver.h for curl 8.19.0-DEV)
    // =========================================================================
    // These values are extracted from include/curl/curlver.h and exposed as
    // compile-time environment variables. Library code accesses them via:
    //   env!("CURL_RS_VERSION")
    //   env!("CURL_RS_VERSION_MAJOR")
    //   etc.
    //
    // Reference (curlver.h):
    //   #define LIBCURL_VERSION       "8.19.0-DEV"
    //   #define LIBCURL_VERSION_MAJOR  8
    //   #define LIBCURL_VERSION_MINOR  19
    //   #define LIBCURL_VERSION_PATCH  0
    //   #define LIBCURL_VERSION_NUM    0x081300
    //   #define LIBCURL_TIMESTAMP      "[unreleased]"
    println!("cargo:rustc-env=CURL_RS_VERSION=8.19.0-DEV");
    println!("cargo:rustc-env=CURL_RS_VERSION_MAJOR=8");
    println!("cargo:rustc-env=CURL_RS_VERSION_MINOR=19");
    println!("cargo:rustc-env=CURL_RS_VERSION_PATCH=0");
    println!("cargo:rustc-env=CURL_RS_VERSION_NUM=0x081300");
    println!("cargo:rustc-env=CURL_RS_TIMESTAMP=[unreleased]");

    // =========================================================================
    // Platform detection
    // =========================================================================
    // Detect the target OS and architecture from Cargo's target-specific
    // environment variables. Unlike `env::consts::OS` / `env::consts::ARCH`
    // (which return **host** platform values), `CARGO_CFG_TARGET_OS` and
    // `CARGO_CFG_TARGET_ARCH` correctly reflect the **target** platform
    // during cross-compilation (e.g., building on x86_64 for aarch64).
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    println!("cargo:rustc-env=CURL_RS_TARGET_OS={}", target_os);
    println!("cargo:rustc-env=CURL_RS_TARGET_ARCH={}", target_arch);

    // Emit platform-specific cfg flags for conditional compilation.
    // These supplement the standard `cfg!(target_os = "...")` checks with
    // curl-specific platform groupings.
    match target_os.as_str() {
        "linux" => println!("cargo:rustc-cfg=curl_unix"),
        "macos" => {
            println!("cargo:rustc-cfg=curl_unix");
            println!("cargo:rustc-cfg=curl_macos");
        }
        "freebsd" | "openbsd" | "netbsd" | "dragonfly" => {
            println!("cargo:rustc-cfg=curl_unix");
            println!("cargo:rustc-cfg=curl_bsd");
        }
        "windows" => println!("cargo:rustc-cfg=curl_windows"),
        _ => {}
    }

    // =========================================================================
    // Feature flag reporting
    // =========================================================================
    // Collect enabled features and emit them as a comma-separated environment
    // variable. This is used by the version/info subsystem to report which
    // protocols and capabilities are compiled in, mirroring the behavior of
    // curl_version_info() in C libcurl.
    let features = collect_enabled_features();
    println!("cargo:rustc-env=CURL_RS_FEATURES={}", features);

    // =========================================================================
    // Symbol inventory generation
    // =========================================================================
    // Generate a Rust source file containing all public CURL_EXTERN symbol
    // names as a constant array. The FFI crate includes this file to validate
    // that every symbol has a Rust implementation at compile time.
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set by Cargo");
    let dest_path = Path::new(&out_dir).join("symbol_inventory.rs");

    let symbol_inventory_source = generate_symbol_inventory();
    fs::write(&dest_path, symbol_inventory_source)
        .expect("Failed to write symbol_inventory.rs to OUT_DIR");

    // Emit the symbol count as a metadata variable for downstream use.
    println!("cargo:rustc-env=CURL_RS_SYMBOL_COUNT={}", TOTAL_SYMBOL_COUNT);
}

// =============================================================================
// Symbol inventory generation
// =============================================================================

/// Total number of public `CURL_EXTERN` symbols across all 8 public API headers.
///
/// Breakdown by header:
/// - `curl.h`:       41 symbols (includes 3 deprecated: formadd, formget, formfree)
/// - `easy.h`:       10 symbols
/// - `multi.h`:      24 symbols (includes 2 deprecated: multi_socket, multi_socket_all)
/// - `mprintf.h`:    10 symbols
/// - `urlapi.h`:      6 symbols
/// - `websockets.h`:  4 symbols
/// - `options.h`:     3 symbols
/// - `header.h`:      2 symbols
///
/// Total: 100 symbols
const TOTAL_SYMBOL_COUNT: usize = 100;

/// Generates the content of `symbol_inventory.rs`.
///
/// The generated file contains:
/// - A constant `CURL_PUBLIC_SYMBOLS` holding all symbol names as `&str`.
/// - A constant `CURL_SYMBOL_COUNT` with the total count.
/// - Per-header sub-arrays for grouping and documentation.
/// - A `SymbolInfo` struct and detailed inventory with header-of-origin metadata.
///
/// The file is designed to be included via:
/// ```rust,ignore
/// include!(concat!(env!("OUT_DIR"), "/symbol_inventory.rs"));
/// ```
fn generate_symbol_inventory() -> String {
    let mut output = String::with_capacity(16384);

    // File header
    output.push_str(
        "// This file is auto-generated by curl-rs-lib/build.rs\n\
         // DO NOT EDIT MANUALLY.\n\
         //\n\
         // Contains the complete inventory of public CURL_EXTERN symbols from\n\
         // the libcurl 8.19.0-DEV C API headers (include/curl/*.h).\n\
         //\n\
         // Used by the FFI crate to validate symbol coverage at compile time.\n\
         \n",
    );

    // -------------------------------------------------------------------------
    // Symbol info struct
    // -------------------------------------------------------------------------
    output.push_str(
        "/// Metadata about a single public API symbol.\n\
         #[derive(Debug, Clone, Copy, PartialEq, Eq)]\n\
         pub struct SymbolInfo {\n\
         \x20   /// The C function name (e.g., \"curl_easy_init\").\n\
         \x20   pub name: &'static str,\n\
         \x20   /// The header file where this symbol is declared.\n\
         \x20   pub header: &'static str,\n\
         \x20   /// Whether this symbol is deprecated in the C API.\n\
         \x20   pub deprecated: bool,\n\
         }\n\n",
    );

    // -------------------------------------------------------------------------
    // Total count
    // -------------------------------------------------------------------------
    output.push_str(&format!(
        "/// Total number of public CURL_EXTERN symbols.\n\
         pub const CURL_SYMBOL_COUNT: usize = {};\n\n",
        TOTAL_SYMBOL_COUNT
    ));

    // -------------------------------------------------------------------------
    // Per-header symbol arrays
    // -------------------------------------------------------------------------
    append_header_symbols(
        &mut output,
        "CURL_H",
        "curl.h",
        "Master API header — global functions, MIME, share, slist, version, etc.",
        &CURL_H_SYMBOLS,
    );

    append_header_symbols(
        &mut output,
        "EASY_H",
        "easy.h",
        "Easy interface — single-transfer handle operations.",
        &EASY_H_SYMBOLS,
    );

    append_header_symbols(
        &mut output,
        "MULTI_H",
        "multi.h",
        "Multi interface — concurrent transfer management.",
        &MULTI_H_SYMBOLS,
    );

    append_header_symbols(
        &mut output,
        "MPRINTF_H",
        "mprintf.h",
        "Printf family — formatted string output functions.",
        &MPRINTF_H_SYMBOLS,
    );

    append_header_symbols(
        &mut output,
        "URLAPI_H",
        "urlapi.h",
        "URL API — URL parsing and manipulation.",
        &URLAPI_H_SYMBOLS,
    );

    append_header_symbols(
        &mut output,
        "WEBSOCKETS_H",
        "websockets.h",
        "WebSocket API — WebSocket send/receive operations.",
        &WEBSOCKETS_H_SYMBOLS,
    );

    append_header_symbols(
        &mut output,
        "OPTIONS_H",
        "options.h",
        "Option introspection — metadata about curl_easy_setopt options.",
        &OPTIONS_H_SYMBOLS,
    );

    append_header_symbols(
        &mut output,
        "HEADER_H",
        "header.h",
        "Header API — HTTP header access and iteration.",
        &HEADER_H_SYMBOLS,
    );

    // -------------------------------------------------------------------------
    // Combined flat array of all symbol names (for simple iteration)
    // -------------------------------------------------------------------------
    output.push_str(
        "/// All public CURL_EXTERN symbol names as a flat array of strings.\n\
         ///\n\
         /// This is the primary constant used by the FFI crate to verify that\n\
         /// every public API symbol has a corresponding `extern \"C\"` function.\n\
         pub const CURL_PUBLIC_SYMBOLS: [&str; CURL_SYMBOL_COUNT] = [\n",
    );

    let all_symbols: &[&[(&str, bool)]] = &[
        &CURL_H_SYMBOLS,
        &EASY_H_SYMBOLS,
        &MULTI_H_SYMBOLS,
        &MPRINTF_H_SYMBOLS,
        &URLAPI_H_SYMBOLS,
        &WEBSOCKETS_H_SYMBOLS,
        &OPTIONS_H_SYMBOLS,
        &HEADER_H_SYMBOLS,
    ];

    for group in all_symbols {
        for &(name, _deprecated) in *group {
            output.push_str(&format!("    \"{}\",\n", name));
        }
    }
    output.push_str("];\n\n");

    // -------------------------------------------------------------------------
    // Detailed symbol inventory with metadata
    // -------------------------------------------------------------------------
    output.push_str(
        "/// Detailed inventory of all public symbols with header and deprecation metadata.\n\
         pub const CURL_SYMBOL_INVENTORY: [SymbolInfo; CURL_SYMBOL_COUNT] = [\n",
    );

    append_symbol_inventory_entries(&mut output, "curl.h", &CURL_H_SYMBOLS);
    append_symbol_inventory_entries(&mut output, "easy.h", &EASY_H_SYMBOLS);
    append_symbol_inventory_entries(&mut output, "multi.h", &MULTI_H_SYMBOLS);
    append_symbol_inventory_entries(&mut output, "mprintf.h", &MPRINTF_H_SYMBOLS);
    append_symbol_inventory_entries(&mut output, "urlapi.h", &URLAPI_H_SYMBOLS);
    append_symbol_inventory_entries(&mut output, "websockets.h", &WEBSOCKETS_H_SYMBOLS);
    append_symbol_inventory_entries(&mut output, "options.h", &OPTIONS_H_SYMBOLS);
    append_symbol_inventory_entries(&mut output, "header.h", &HEADER_H_SYMBOLS);
    output.push_str("];\n");

    output
}

/// Appends `SymbolInfo` entries for a single header to the inventory array output.
fn append_symbol_inventory_entries(
    output: &mut String,
    header: &str,
    symbols: &[(&str, bool)],
) {
    for &(name, deprecated) in symbols {
        output.push_str(&format!(
            "    SymbolInfo {{ name: \"{}\", header: \"{}\", deprecated: {} }},\n",
            name, header, deprecated,
        ));
    }
}

/// Appends a per-header symbol constant array to the output string.
fn append_header_symbols(
    output: &mut String,
    const_prefix: &str,
    header_name: &str,
    doc: &str,
    symbols: &[(&str, bool)],
) {
    output.push_str(&format!(
        "/// Symbols from `include/curl/{}` ({} symbols).\n\
         /// {}\n\
         pub const SYMBOLS_{}: [&str; {}] = [\n",
        header_name,
        symbols.len(),
        doc,
        const_prefix,
        symbols.len(),
    ));
    for &(name, _deprecated) in symbols {
        output.push_str(&format!("    \"{}\",\n", name));
    }
    output.push_str("];\n\n");
}

// =============================================================================
// Symbol tables — extracted from include/curl/*.h (curl 8.19.0-DEV)
// =============================================================================
// Each entry is (symbol_name, is_deprecated).
// Deprecated symbols are included for completeness and ABI compatibility.

/// Symbols declared in `include/curl/curl.h` (41 symbols).
///
/// Includes string comparison, MIME, deprecated form API, memory, global init,
/// slist, share, version, date parsing, error strings, pause, and SSL session
/// import/export.
const CURL_H_SYMBOLS: [(&str, bool); 41] = [
    // String comparison
    ("curl_strequal", false),
    ("curl_strnequal", false),
    // MIME API (14 symbols)
    ("curl_mime_init", false),
    ("curl_mime_free", false),
    ("curl_mime_addpart", false),
    ("curl_mime_name", false),
    ("curl_mime_filename", false),
    ("curl_mime_type", false),
    ("curl_mime_encoder", false),
    ("curl_mime_data", false),
    ("curl_mime_filedata", false),
    ("curl_mime_data_cb", false),
    ("curl_mime_subparts", false),
    ("curl_mime_headers", false),
    // Deprecated form API (3 symbols, deprecated since 7.56.0)
    ("curl_formadd", true),
    ("curl_formget", true),
    ("curl_formfree", true),
    // Environment and version
    ("curl_getenv", false),
    ("curl_version", false),
    // URL encoding/decoding
    ("curl_easy_escape", false),
    ("curl_escape", false),
    ("curl_easy_unescape", false),
    ("curl_unescape", false),
    // Memory
    ("curl_free", false),
    // Global init/cleanup
    ("curl_global_init", false),
    ("curl_global_init_mem", false),
    ("curl_global_cleanup", false),
    ("curl_global_trace", false),
    ("curl_global_sslset", false),
    // String list
    ("curl_slist_append", false),
    ("curl_slist_free_all", false),
    // Date parsing
    ("curl_getdate", false),
    // Share API
    ("curl_share_init", false),
    ("curl_share_setopt", false),
    ("curl_share_cleanup", false),
    // Version info
    ("curl_version_info", false),
    // Error strings
    ("curl_easy_strerror", false),
    ("curl_share_strerror", false),
    // Pause/unpause
    ("curl_easy_pause", false),
    // SSL session import/export
    ("curl_easy_ssls_import", false),
    ("curl_easy_ssls_export", false),
];

/// Symbols declared in `include/curl/easy.h` (10 symbols).
///
/// Core easy handle lifecycle and transfer operations.
const EASY_H_SYMBOLS: [(&str, bool); 10] = [
    ("curl_easy_init", false),
    ("curl_easy_setopt", false),
    ("curl_easy_perform", false),
    ("curl_easy_cleanup", false),
    ("curl_easy_getinfo", false),
    ("curl_easy_duphandle", false),
    ("curl_easy_reset", false),
    ("curl_easy_recv", false),
    ("curl_easy_send", false),
    ("curl_easy_upkeep", false),
];

/// Symbols declared in `include/curl/multi.h` (24 symbols).
///
/// Multi handle lifecycle, concurrent transfer management, socket action,
/// push headers, and notification API.
const MULTI_H_SYMBOLS: [(&str, bool); 24] = [
    ("curl_multi_init", false),
    ("curl_multi_add_handle", false),
    ("curl_multi_remove_handle", false),
    ("curl_multi_fdset", false),
    ("curl_multi_wait", false),
    ("curl_multi_poll", false),
    ("curl_multi_wakeup", false),
    ("curl_multi_perform", false),
    ("curl_multi_cleanup", false),
    ("curl_multi_info_read", false),
    ("curl_multi_strerror", false),
    // Deprecated since 7.19.5 — use curl_multi_socket_action() instead
    ("curl_multi_socket", true),
    ("curl_multi_socket_action", false),
    // Deprecated since 7.19.5 — use curl_multi_socket_action() instead
    ("curl_multi_socket_all", true),
    ("curl_multi_timeout", false),
    ("curl_multi_setopt", false),
    ("curl_multi_assign", false),
    ("curl_multi_get_handles", false),
    ("curl_multi_get_offt", false),
    // Push header inspection (for server push callbacks)
    ("curl_pushheader_bynum", false),
    ("curl_pushheader_byname", false),
    ("curl_multi_waitfds", false),
    // Notification API
    ("curl_multi_notify_disable", false),
    ("curl_multi_notify_enable", false),
];

/// Symbols declared in `include/curl/mprintf.h` (10 symbols).
///
/// curl's printf-family functions with portable formatting.
const MPRINTF_H_SYMBOLS: [(&str, bool); 10] = [
    ("curl_mprintf", false),
    ("curl_mfprintf", false),
    ("curl_msprintf", false),
    ("curl_msnprintf", false),
    ("curl_mvprintf", false),
    ("curl_mvfprintf", false),
    ("curl_mvsprintf", false),
    ("curl_mvsnprintf", false),
    ("curl_maprintf", false),
    ("curl_mvaprintf", false),
];

/// Symbols declared in `include/curl/urlapi.h` (6 symbols).
///
/// URL handle creation, manipulation, and error reporting.
const URLAPI_H_SYMBOLS: [(&str, bool); 6] = [
    ("curl_url", false),
    ("curl_url_cleanup", false),
    ("curl_url_dup", false),
    ("curl_url_get", false),
    ("curl_url_set", false),
    ("curl_url_strerror", false),
];

/// Symbols declared in `include/curl/websockets.h` (4 symbols).
///
/// WebSocket frame send, receive, start, and metadata access.
const WEBSOCKETS_H_SYMBOLS: [(&str, bool); 4] = [
    ("curl_ws_recv", false),
    ("curl_ws_send", false),
    ("curl_ws_start_frame", false),
    ("curl_ws_meta", false),
];

/// Symbols declared in `include/curl/options.h` (3 symbols).
///
/// Option introspection — enumerate and look up curl_easy_setopt option metadata.
const OPTIONS_H_SYMBOLS: [(&str, bool); 3] = [
    ("curl_easy_option_by_name", false),
    ("curl_easy_option_by_id", false),
    ("curl_easy_option_next", false),
];

/// Symbols declared in `include/curl/header.h` (2 symbols).
///
/// HTTP header access by name/index and sequential iteration.
const HEADER_H_SYMBOLS: [(&str, bool); 2] = [
    ("curl_easy_header", false),
    ("curl_easy_nextheader", false),
];

// =============================================================================
// Feature collection
// =============================================================================

/// Collects the names of all enabled Cargo features and returns them as a
/// comma-separated string.
///
/// This mirrors the C build system's feature detection (the `#ifdef CURL_DISABLE_*`
/// macros) and allows the Rust version/info subsystem to report capabilities.
fn collect_enabled_features() -> String {
    // Check for features that are enabled via Cargo's cfg system.
    // Cargo sets `CARGO_FEATURE_<UPPERCASED_NAME>` environment variables
    // for each enabled feature.
    let feature_names = [
        "http", "ftp", "smtp", "imap", "pop3", "tftp", "telnet", "dict",
        "mqtt", "rtsp", "cookies", "brotli", "zstd", "hickory-dns",
    ];

    let mut enabled = Vec::new();
    for name in &feature_names {
        // Cargo sets env vars like CARGO_FEATURE_HTTP, CARGO_FEATURE_FTP, etc.
        let env_name = format!("CARGO_FEATURE_{}", name.to_uppercase().replace('-', "_"));
        if env::var(&env_name).is_ok() {
            enabled.push(*name);
        }
    }

    enabled.join(",")
}
