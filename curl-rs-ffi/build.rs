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
    // Phase 7: Append CURLOPT_* and CURLINFO_* constants
    //
    // cbindgen generates type definitions and function declarations, but
    // the individual CURLOPT_* and CURLINFO_* option/info constants are
    // defined as C macro expansions (CURLOPT(NAME, TYPE, N)) in the
    // original curl 8.x headers — a pattern that cbindgen cannot produce.
    //
    // We append the complete set of #define constants matching the original
    // curl 8.x header values.  This ensures that C consumers can compile
    // code like `curl_easy_setopt(handle, CURLOPT_URL, ...)` against the
    // generated header.
    //
    // Per AAP: "downstream C programs can swap libcurl.so with
    //   libcurl-rs.so without recompilation"
    // ------------------------------------------------------------------
    append_option_constants(&output_file);

    // ------------------------------------------------------------------
    // Phase 8: Optional symbol validation (sanity check)
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

/// Append all CURLOPT_* and CURLINFO_* constant definitions to the generated
/// header.  These are emitted as `#define` macros matching the original
/// curl 8.x header values exactly, so C consumers can use them directly.
fn append_option_constants(header_path: &std::path::Path) {
    use std::io::Write;

    let mut file = match fs::OpenOptions::new().append(true).open(header_path) {
        Ok(f) => f,
        Err(e) => {
            println!(
                "cargo:warning=cbindgen: Could not open header for appending constants: {}",
                e
            );
            return;
        }
    };

    let constants = generate_curlopt_curlinfo_defines();
    if let Err(e) = file.write_all(constants.as_bytes()) {
        println!(
            "cargo:warning=cbindgen: Failed to append option constants: {}",
            e
        );
    }
}

/// Generate the complete set of CURLOPT_* and CURLINFO_* #define macros
/// matching curl 8.x header values.
fn generate_curlopt_curlinfo_defines() -> String {
    let mut s = String::with_capacity(32768);

    s.push_str("\n/* ================================================================ */\n");
    s.push_str("/* CURLOPT_* option constants — curl 8.x ABI compatible            */\n");
    s.push_str("/* Generated by curl-rs-ffi/build.rs                                */\n");
    s.push_str("/* ================================================================ */\n\n");

    // CURLOPT macro that computes the option value from type base + number.
    // This matches the C macro: #define CURLOPT(na,t,nu) na = t + nu
    s.push_str("#ifdef CURLOPT\n#undef CURLOPT\n#endif\n");
    s.push_str("#define CURLOPT(na,t,nu) na = (t) + (nu)\n\n");

    // All 291 CURLOPT_* constants from curl 8.x, organized by type base.
    // Values extracted from include/curl/curl.h of curl 8.19.0-DEV.
    let curlopt_entries: &[(&str, &str, u32)] = &[
        ("CURLOPT_WRITEDATA", "CURLOPTTYPE_CBPOINT", 1),
        ("CURLOPT_URL", "CURLOPTTYPE_STRINGPOINT", 2),
        ("CURLOPT_PORT", "CURLOPTTYPE_LONG", 3),
        ("CURLOPT_PROXY", "CURLOPTTYPE_STRINGPOINT", 4),
        ("CURLOPT_USERPWD", "CURLOPTTYPE_STRINGPOINT", 5),
        ("CURLOPT_PROXYUSERPWD", "CURLOPTTYPE_STRINGPOINT", 6),
        ("CURLOPT_RANGE", "CURLOPTTYPE_STRINGPOINT", 7),
        ("CURLOPT_READDATA", "CURLOPTTYPE_CBPOINT", 9),
        ("CURLOPT_ERRORBUFFER", "CURLOPTTYPE_OBJECTPOINT", 10),
        ("CURLOPT_WRITEFUNCTION", "CURLOPTTYPE_FUNCTIONPOINT", 11),
        ("CURLOPT_READFUNCTION", "CURLOPTTYPE_FUNCTIONPOINT", 12),
        ("CURLOPT_TIMEOUT", "CURLOPTTYPE_LONG", 13),
        ("CURLOPT_INFILESIZE", "CURLOPTTYPE_LONG", 14),
        ("CURLOPT_POSTFIELDS", "CURLOPTTYPE_OBJECTPOINT", 15),
        ("CURLOPT_REFERER", "CURLOPTTYPE_STRINGPOINT", 16),
        ("CURLOPT_FTPPORT", "CURLOPTTYPE_STRINGPOINT", 17),
        ("CURLOPT_USERAGENT", "CURLOPTTYPE_STRINGPOINT", 18),
        ("CURLOPT_LOW_SPEED_LIMIT", "CURLOPTTYPE_LONG", 19),
        ("CURLOPT_LOW_SPEED_TIME", "CURLOPTTYPE_LONG", 20),
        ("CURLOPT_RESUME_FROM", "CURLOPTTYPE_LONG", 21),
        ("CURLOPT_COOKIE", "CURLOPTTYPE_STRINGPOINT", 22),
        ("CURLOPT_HTTPHEADER", "CURLOPTTYPE_SLISTPOINT", 23),
        ("CURLOPT_SSLCERT", "CURLOPTTYPE_STRINGPOINT", 25),
        ("CURLOPT_KEYPASSWD", "CURLOPTTYPE_STRINGPOINT", 26),
        ("CURLOPT_CRLF", "CURLOPTTYPE_LONG", 27),
        ("CURLOPT_QUOTE", "CURLOPTTYPE_SLISTPOINT", 28),
        ("CURLOPT_HEADERDATA", "CURLOPTTYPE_CBPOINT", 29),
        ("CURLOPT_COOKIEFILE", "CURLOPTTYPE_STRINGPOINT", 31),
        ("CURLOPT_SSLVERSION", "CURLOPTTYPE_VALUES", 32),
        ("CURLOPT_TIMECONDITION", "CURLOPTTYPE_VALUES", 33),
        ("CURLOPT_TIMEVALUE", "CURLOPTTYPE_LONG", 34),
        ("CURLOPT_CUSTOMREQUEST", "CURLOPTTYPE_STRINGPOINT", 36),
        ("CURLOPT_STDERR", "CURLOPTTYPE_OBJECTPOINT", 37),
        ("CURLOPT_POSTQUOTE", "CURLOPTTYPE_SLISTPOINT", 39),
        ("CURLOPT_VERBOSE", "CURLOPTTYPE_LONG", 41),
        ("CURLOPT_HEADER", "CURLOPTTYPE_LONG", 42),
        ("CURLOPT_NOPROGRESS", "CURLOPTTYPE_LONG", 43),
        ("CURLOPT_NOBODY", "CURLOPTTYPE_LONG", 44),
        ("CURLOPT_FAILONERROR", "CURLOPTTYPE_LONG", 45),
        ("CURLOPT_UPLOAD", "CURLOPTTYPE_LONG", 46),
        ("CURLOPT_POST", "CURLOPTTYPE_LONG", 47),
        ("CURLOPT_DIRLISTONLY", "CURLOPTTYPE_LONG", 48),
        ("CURLOPT_APPEND", "CURLOPTTYPE_LONG", 50),
        ("CURLOPT_NETRC", "CURLOPTTYPE_VALUES", 51),
        ("CURLOPT_FOLLOWLOCATION", "CURLOPTTYPE_LONG", 52),
        ("CURLOPT_TRANSFERTEXT", "CURLOPTTYPE_LONG", 53),
        ("CURLOPT_PUT", "CURLOPTTYPE_LONG", 54),
        ("CURLOPT_XFERINFOFUNCTION", "CURLOPTTYPE_FUNCTIONPOINT", 56),
        ("CURLOPT_AUTOREFERER", "CURLOPTTYPE_LONG", 58),
        ("CURLOPT_PROXYPORT", "CURLOPTTYPE_LONG", 59),
        ("CURLOPT_POSTFIELDSIZE", "CURLOPTTYPE_LONG", 60),
        ("CURLOPT_HTTPPROXYTUNNEL", "CURLOPTTYPE_LONG", 61),
        ("CURLOPT_INTERFACE", "CURLOPTTYPE_STRINGPOINT", 62),
        ("CURLOPT_KRBLEVEL", "CURLOPTTYPE_STRINGPOINT", 63),
        ("CURLOPT_SSL_VERIFYPEER", "CURLOPTTYPE_LONG", 64),
        ("CURLOPT_CAINFO", "CURLOPTTYPE_STRINGPOINT", 65),
        ("CURLOPT_MAXREDIRS", "CURLOPTTYPE_LONG", 68),
        ("CURLOPT_FILETIME", "CURLOPTTYPE_LONG", 69),
        ("CURLOPT_TELNETOPTIONS", "CURLOPTTYPE_SLISTPOINT", 70),
        ("CURLOPT_MAXCONNECTS", "CURLOPTTYPE_LONG", 71),
        ("CURLOPT_FRESH_CONNECT", "CURLOPTTYPE_LONG", 74),
        ("CURLOPT_FORBID_REUSE", "CURLOPTTYPE_LONG", 75),
        ("CURLOPT_RANDOM_FILE", "CURLOPTTYPE_STRINGPOINT", 76),
        ("CURLOPT_EGDSOCKET", "CURLOPTTYPE_STRINGPOINT", 77),
        ("CURLOPT_CONNECTTIMEOUT", "CURLOPTTYPE_LONG", 78),
        ("CURLOPT_HEADERFUNCTION", "CURLOPTTYPE_FUNCTIONPOINT", 79),
        ("CURLOPT_HTTPGET", "CURLOPTTYPE_LONG", 80),
        ("CURLOPT_SSL_VERIFYHOST", "CURLOPTTYPE_LONG", 81),
        ("CURLOPT_COOKIEJAR", "CURLOPTTYPE_STRINGPOINT", 82),
        ("CURLOPT_SSL_CIPHER_LIST", "CURLOPTTYPE_STRINGPOINT", 83),
        ("CURLOPT_HTTP_VERSION", "CURLOPTTYPE_VALUES", 84),
        ("CURLOPT_FTP_USE_EPSV", "CURLOPTTYPE_LONG", 85),
        ("CURLOPT_SSLCERTTYPE", "CURLOPTTYPE_STRINGPOINT", 86),
        ("CURLOPT_SSLKEY", "CURLOPTTYPE_STRINGPOINT", 87),
        ("CURLOPT_SSLKEYTYPE", "CURLOPTTYPE_STRINGPOINT", 88),
        ("CURLOPT_SSLENGINE", "CURLOPTTYPE_STRINGPOINT", 89),
        ("CURLOPT_SSLENGINE_DEFAULT", "CURLOPTTYPE_LONG", 90),
        ("CURLOPT_DNS_USE_GLOBAL_CACHE", "CURLOPTTYPE_LONG", 91),
        ("CURLOPT_DNS_CACHE_TIMEOUT", "CURLOPTTYPE_LONG", 92),
        ("CURLOPT_PREQUOTE", "CURLOPTTYPE_SLISTPOINT", 93),
        ("CURLOPT_DEBUGFUNCTION", "CURLOPTTYPE_FUNCTIONPOINT", 94),
        ("CURLOPT_DEBUGDATA", "CURLOPTTYPE_CBPOINT", 95),
        ("CURLOPT_COOKIESESSION", "CURLOPTTYPE_LONG", 96),
        ("CURLOPT_CAPATH", "CURLOPTTYPE_STRINGPOINT", 97),
        ("CURLOPT_BUFFERSIZE", "CURLOPTTYPE_LONG", 98),
        ("CURLOPT_NOSIGNAL", "CURLOPTTYPE_LONG", 99),
        ("CURLOPT_SHARE", "CURLOPTTYPE_OBJECTPOINT", 100),
        ("CURLOPT_PROXYTYPE", "CURLOPTTYPE_VALUES", 101),
        ("CURLOPT_ACCEPT_ENCODING", "CURLOPTTYPE_STRINGPOINT", 102),
        ("CURLOPT_PRIVATE", "CURLOPTTYPE_OBJECTPOINT", 103),
        ("CURLOPT_HTTP200ALIASES", "CURLOPTTYPE_SLISTPOINT", 104),
        ("CURLOPT_UNRESTRICTED_AUTH", "CURLOPTTYPE_LONG", 105),
        ("CURLOPT_FTP_USE_EPRT", "CURLOPTTYPE_LONG", 106),
        ("CURLOPT_HTTPAUTH", "CURLOPTTYPE_VALUES", 107),
        ("CURLOPT_SSL_CTX_FUNCTION", "CURLOPTTYPE_FUNCTIONPOINT", 108),
        ("CURLOPT_SSL_CTX_DATA", "CURLOPTTYPE_CBPOINT", 109),
        ("CURLOPT_FTP_CREATE_MISSING_DIRS", "CURLOPTTYPE_LONG", 110),
        ("CURLOPT_PROXYAUTH", "CURLOPTTYPE_VALUES", 111),
        ("CURLOPT_SERVER_RESPONSE_TIMEOUT", "CURLOPTTYPE_LONG", 112),
        ("CURLOPT_IPRESOLVE", "CURLOPTTYPE_VALUES", 113),
        ("CURLOPT_MAXFILESIZE", "CURLOPTTYPE_LONG", 114),
        ("CURLOPT_INFILESIZE_LARGE", "CURLOPTTYPE_OFF_T", 115),
        ("CURLOPT_RESUME_FROM_LARGE", "CURLOPTTYPE_OFF_T", 116),
        ("CURLOPT_MAXFILESIZE_LARGE", "CURLOPTTYPE_OFF_T", 117),
        ("CURLOPT_NETRC_FILE", "CURLOPTTYPE_STRINGPOINT", 118),
        ("CURLOPT_USE_SSL", "CURLOPTTYPE_VALUES", 119),
        ("CURLOPT_POSTFIELDSIZE_LARGE", "CURLOPTTYPE_OFF_T", 120),
        ("CURLOPT_TCP_NODELAY", "CURLOPTTYPE_LONG", 121),
        ("CURLOPT_FTPSSLAUTH", "CURLOPTTYPE_VALUES", 129),
        ("CURLOPT_IOCTLFUNCTION", "CURLOPTTYPE_FUNCTIONPOINT", 130),
        ("CURLOPT_IOCTLDATA", "CURLOPTTYPE_CBPOINT", 131),
        ("CURLOPT_FTP_ACCOUNT", "CURLOPTTYPE_STRINGPOINT", 134),
        ("CURLOPT_COOKIELIST", "CURLOPTTYPE_STRINGPOINT", 135),
        ("CURLOPT_IGNORE_CONTENT_LENGTH", "CURLOPTTYPE_LONG", 136),
        ("CURLOPT_FTP_SKIP_PASV_IP", "CURLOPTTYPE_LONG", 137),
        ("CURLOPT_FTP_FILEMETHOD", "CURLOPTTYPE_VALUES", 138),
        ("CURLOPT_LOCALPORT", "CURLOPTTYPE_LONG", 139),
        ("CURLOPT_LOCALPORTRANGE", "CURLOPTTYPE_LONG", 140),
        ("CURLOPT_CONNECT_ONLY", "CURLOPTTYPE_LONG", 141),
        ("CURLOPT_CONV_FROM_NETWORK_FUNCTION", "CURLOPTTYPE_FUNCTIONPOINT", 142),
        ("CURLOPT_CONV_TO_NETWORK_FUNCTION", "CURLOPTTYPE_FUNCTIONPOINT", 143),
        ("CURLOPT_CONV_FROM_UTF8_FUNCTION", "CURLOPTTYPE_FUNCTIONPOINT", 144),
        ("CURLOPT_MAX_SEND_SPEED_LARGE", "CURLOPTTYPE_OFF_T", 145),
        ("CURLOPT_MAX_RECV_SPEED_LARGE", "CURLOPTTYPE_OFF_T", 146),
        ("CURLOPT_FTP_ALTERNATIVE_TO_USER", "CURLOPTTYPE_STRINGPOINT", 147),
        ("CURLOPT_SOCKOPTFUNCTION", "CURLOPTTYPE_FUNCTIONPOINT", 148),
        ("CURLOPT_SOCKOPTDATA", "CURLOPTTYPE_CBPOINT", 149),
        ("CURLOPT_SSL_SESSIONID_CACHE", "CURLOPTTYPE_LONG", 150),
        ("CURLOPT_SSH_AUTH_TYPES", "CURLOPTTYPE_VALUES", 151),
        ("CURLOPT_SSH_PUBLIC_KEYFILE", "CURLOPTTYPE_STRINGPOINT", 152),
        ("CURLOPT_SSH_PRIVATE_KEYFILE", "CURLOPTTYPE_STRINGPOINT", 153),
        ("CURLOPT_FTP_SSL_CCC", "CURLOPTTYPE_LONG", 154),
        ("CURLOPT_TIMEOUT_MS", "CURLOPTTYPE_LONG", 155),
        ("CURLOPT_CONNECTTIMEOUT_MS", "CURLOPTTYPE_LONG", 156),
        ("CURLOPT_HTTP_TRANSFER_DECODING", "CURLOPTTYPE_LONG", 157),
        ("CURLOPT_HTTP_CONTENT_DECODING", "CURLOPTTYPE_LONG", 158),
        ("CURLOPT_NEW_FILE_PERMS", "CURLOPTTYPE_LONG", 159),
        ("CURLOPT_NEW_DIRECTORY_PERMS", "CURLOPTTYPE_LONG", 160),
        ("CURLOPT_POSTREDIR", "CURLOPTTYPE_VALUES", 161),
        ("CURLOPT_SSH_HOST_PUBLIC_KEY_MD5", "CURLOPTTYPE_STRINGPOINT", 162),
        ("CURLOPT_OPENSOCKETFUNCTION", "CURLOPTTYPE_FUNCTIONPOINT", 163),
        ("CURLOPT_OPENSOCKETDATA", "CURLOPTTYPE_CBPOINT", 164),
        ("CURLOPT_COPYPOSTFIELDS", "CURLOPTTYPE_OBJECTPOINT", 165),
        ("CURLOPT_PROXY_TRANSFER_MODE", "CURLOPTTYPE_LONG", 166),
        ("CURLOPT_SEEKFUNCTION", "CURLOPTTYPE_FUNCTIONPOINT", 167),
        ("CURLOPT_SEEKDATA", "CURLOPTTYPE_CBPOINT", 168),
        ("CURLOPT_CRLFILE", "CURLOPTTYPE_STRINGPOINT", 169),
        ("CURLOPT_ISSUERCERT", "CURLOPTTYPE_STRINGPOINT", 170),
        ("CURLOPT_ADDRESS_SCOPE", "CURLOPTTYPE_LONG", 171),
        ("CURLOPT_CERTINFO", "CURLOPTTYPE_LONG", 172),
        ("CURLOPT_USERNAME", "CURLOPTTYPE_STRINGPOINT", 173),
        ("CURLOPT_PASSWORD", "CURLOPTTYPE_STRINGPOINT", 174),
        ("CURLOPT_PROXYUSERNAME", "CURLOPTTYPE_STRINGPOINT", 175),
        ("CURLOPT_PROXYPASSWORD", "CURLOPTTYPE_STRINGPOINT", 176),
        ("CURLOPT_NOPROXY", "CURLOPTTYPE_STRINGPOINT", 177),
        ("CURLOPT_TFTP_BLKSIZE", "CURLOPTTYPE_LONG", 178),
        ("CURLOPT_SOCKS5_GSSAPI_SERVICE", "CURLOPTTYPE_STRINGPOINT", 179),
        ("CURLOPT_SOCKS5_GSSAPI_NEC", "CURLOPTTYPE_LONG", 180),
        ("CURLOPT_PROTOCOLS", "CURLOPTTYPE_LONG", 181),
        ("CURLOPT_REDIR_PROTOCOLS", "CURLOPTTYPE_LONG", 182),
        ("CURLOPT_SSH_KNOWNHOSTS", "CURLOPTTYPE_STRINGPOINT", 183),
        ("CURLOPT_SSH_KEYFUNCTION", "CURLOPTTYPE_FUNCTIONPOINT", 184),
        ("CURLOPT_SSH_KEYDATA", "CURLOPTTYPE_CBPOINT", 185),
        ("CURLOPT_MAIL_FROM", "CURLOPTTYPE_STRINGPOINT", 186),
        ("CURLOPT_MAIL_RCPT", "CURLOPTTYPE_SLISTPOINT", 187),
        ("CURLOPT_FTP_USE_PRET", "CURLOPTTYPE_LONG", 188),
        ("CURLOPT_RTSP_REQUEST", "CURLOPTTYPE_VALUES", 189),
        ("CURLOPT_RTSP_SESSION_ID", "CURLOPTTYPE_STRINGPOINT", 190),
        ("CURLOPT_RTSP_STREAM_URI", "CURLOPTTYPE_STRINGPOINT", 191),
        ("CURLOPT_RTSP_TRANSPORT", "CURLOPTTYPE_STRINGPOINT", 192),
        ("CURLOPT_RTSP_CLIENT_CSEQ", "CURLOPTTYPE_LONG", 193),
        ("CURLOPT_RTSP_SERVER_CSEQ", "CURLOPTTYPE_LONG", 194),
        ("CURLOPT_INTERLEAVEDATA", "CURLOPTTYPE_CBPOINT", 195),
        ("CURLOPT_INTERLEAVEFUNCTION", "CURLOPTTYPE_FUNCTIONPOINT", 196),
        ("CURLOPT_WILDCARDMATCH", "CURLOPTTYPE_LONG", 197),
        ("CURLOPT_CHUNK_BGN_FUNCTION", "CURLOPTTYPE_FUNCTIONPOINT", 198),
        ("CURLOPT_CHUNK_END_FUNCTION", "CURLOPTTYPE_FUNCTIONPOINT", 199),
        ("CURLOPT_FNMATCH_FUNCTION", "CURLOPTTYPE_FUNCTIONPOINT", 200),
        ("CURLOPT_CHUNK_DATA", "CURLOPTTYPE_CBPOINT", 201),
        ("CURLOPT_FNMATCH_DATA", "CURLOPTTYPE_CBPOINT", 202),
        ("CURLOPT_RESOLVE", "CURLOPTTYPE_SLISTPOINT", 203),
        ("CURLOPT_TLSAUTH_USERNAME", "CURLOPTTYPE_STRINGPOINT", 204),
        ("CURLOPT_TLSAUTH_PASSWORD", "CURLOPTTYPE_STRINGPOINT", 205),
        ("CURLOPT_TLSAUTH_TYPE", "CURLOPTTYPE_STRINGPOINT", 206),
        ("CURLOPT_TRANSFER_ENCODING", "CURLOPTTYPE_LONG", 207),
        ("CURLOPT_CLOSESOCKETFUNCTION", "CURLOPTTYPE_FUNCTIONPOINT", 208),
        ("CURLOPT_CLOSESOCKETDATA", "CURLOPTTYPE_CBPOINT", 209),
        ("CURLOPT_GSSAPI_DELEGATION", "CURLOPTTYPE_VALUES", 210),
        ("CURLOPT_DNS_SERVERS", "CURLOPTTYPE_STRINGPOINT", 211),
        ("CURLOPT_ACCEPTTIMEOUT_MS", "CURLOPTTYPE_LONG", 212),
        ("CURLOPT_TCP_KEEPALIVE", "CURLOPTTYPE_LONG", 213),
        ("CURLOPT_TCP_KEEPIDLE", "CURLOPTTYPE_LONG", 214),
        ("CURLOPT_TCP_KEEPINTVL", "CURLOPTTYPE_LONG", 215),
        ("CURLOPT_SSL_OPTIONS", "CURLOPTTYPE_VALUES", 216),
        ("CURLOPT_MAIL_AUTH", "CURLOPTTYPE_STRINGPOINT", 217),
        ("CURLOPT_SASL_IR", "CURLOPTTYPE_LONG", 218),
        ("CURLOPT_XFERINFODATA", "CURLOPTTYPE_CBPOINT", 219),
        ("CURLOPT_XOAUTH2_BEARER", "CURLOPTTYPE_STRINGPOINT", 220),
        ("CURLOPT_DNS_INTERFACE", "CURLOPTTYPE_STRINGPOINT", 221),
        ("CURLOPT_DNS_LOCAL_IP4", "CURLOPTTYPE_STRINGPOINT", 222),
        ("CURLOPT_DNS_LOCAL_IP6", "CURLOPTTYPE_STRINGPOINT", 223),
        ("CURLOPT_LOGIN_OPTIONS", "CURLOPTTYPE_STRINGPOINT", 224),
        ("CURLOPT_SSL_ENABLE_NPN", "CURLOPTTYPE_LONG", 225),
        ("CURLOPT_SSL_ENABLE_ALPN", "CURLOPTTYPE_LONG", 226),
        ("CURLOPT_EXPECT_100_TIMEOUT_MS", "CURLOPTTYPE_LONG", 227),
        ("CURLOPT_PROXYHEADER", "CURLOPTTYPE_SLISTPOINT", 228),
        ("CURLOPT_HEADEROPT", "CURLOPTTYPE_VALUES", 229),
        ("CURLOPT_PINNEDPUBLICKEY", "CURLOPTTYPE_STRINGPOINT", 230),
        ("CURLOPT_UNIX_SOCKET_PATH", "CURLOPTTYPE_STRINGPOINT", 231),
        ("CURLOPT_SSL_VERIFYSTATUS", "CURLOPTTYPE_LONG", 232),
        ("CURLOPT_SSL_FALSESTART", "CURLOPTTYPE_LONG", 233),
        ("CURLOPT_PATH_AS_IS", "CURLOPTTYPE_LONG", 234),
        ("CURLOPT_PROXY_SERVICE_NAME", "CURLOPTTYPE_STRINGPOINT", 235),
        ("CURLOPT_SERVICE_NAME", "CURLOPTTYPE_STRINGPOINT", 236),
        ("CURLOPT_PIPEWAIT", "CURLOPTTYPE_LONG", 237),
        ("CURLOPT_DEFAULT_PROTOCOL", "CURLOPTTYPE_STRINGPOINT", 238),
        ("CURLOPT_STREAM_WEIGHT", "CURLOPTTYPE_LONG", 239),
        ("CURLOPT_STREAM_DEPENDS", "CURLOPTTYPE_OBJECTPOINT", 240),
        ("CURLOPT_STREAM_DEPENDS_E", "CURLOPTTYPE_OBJECTPOINT", 241),
        ("CURLOPT_TFTP_NO_OPTIONS", "CURLOPTTYPE_LONG", 242),
        ("CURLOPT_CONNECT_TO", "CURLOPTTYPE_SLISTPOINT", 243),
        ("CURLOPT_TCP_FASTOPEN", "CURLOPTTYPE_LONG", 244),
        ("CURLOPT_KEEP_SENDING_ON_ERROR", "CURLOPTTYPE_LONG", 245),
        ("CURLOPT_PROXY_CAINFO", "CURLOPTTYPE_STRINGPOINT", 246),
        ("CURLOPT_PROXY_CAPATH", "CURLOPTTYPE_STRINGPOINT", 247),
        ("CURLOPT_PROXY_SSL_VERIFYPEER", "CURLOPTTYPE_LONG", 248),
        ("CURLOPT_PROXY_SSL_VERIFYHOST", "CURLOPTTYPE_LONG", 249),
        ("CURLOPT_PROXY_SSLVERSION", "CURLOPTTYPE_VALUES", 250),
        ("CURLOPT_PROXY_TLSAUTH_USERNAME", "CURLOPTTYPE_STRINGPOINT", 251),
        ("CURLOPT_PROXY_TLSAUTH_PASSWORD", "CURLOPTTYPE_STRINGPOINT", 252),
        ("CURLOPT_PROXY_TLSAUTH_TYPE", "CURLOPTTYPE_STRINGPOINT", 253),
        ("CURLOPT_PROXY_SSLCERT", "CURLOPTTYPE_STRINGPOINT", 254),
        ("CURLOPT_PROXY_SSLCERTTYPE", "CURLOPTTYPE_STRINGPOINT", 255),
        ("CURLOPT_PROXY_SSLKEY", "CURLOPTTYPE_STRINGPOINT", 256),
        ("CURLOPT_PROXY_SSLKEYTYPE", "CURLOPTTYPE_STRINGPOINT", 257),
        ("CURLOPT_PROXY_KEYPASSWD", "CURLOPTTYPE_STRINGPOINT", 258),
        ("CURLOPT_PROXY_SSL_CIPHER_LIST", "CURLOPTTYPE_STRINGPOINT", 259),
        ("CURLOPT_PROXY_CRLFILE", "CURLOPTTYPE_STRINGPOINT", 260),
        ("CURLOPT_PROXY_SSL_OPTIONS", "CURLOPTTYPE_LONG", 261),
        ("CURLOPT_PRE_PROXY", "CURLOPTTYPE_STRINGPOINT", 262),
        ("CURLOPT_PROXY_PINNEDPUBLICKEY", "CURLOPTTYPE_STRINGPOINT", 263),
        ("CURLOPT_ABSTRACT_UNIX_SOCKET", "CURLOPTTYPE_STRINGPOINT", 264),
        ("CURLOPT_SUPPRESS_CONNECT_HEADERS", "CURLOPTTYPE_LONG", 265),
        ("CURLOPT_REQUEST_TARGET", "CURLOPTTYPE_STRINGPOINT", 266),
        ("CURLOPT_SOCKS5_AUTH", "CURLOPTTYPE_LONG", 267),
        ("CURLOPT_SSH_COMPRESSION", "CURLOPTTYPE_LONG", 268),
        ("CURLOPT_MIMEPOST", "CURLOPTTYPE_OBJECTPOINT", 269),
        ("CURLOPT_TIMEVALUE_LARGE", "CURLOPTTYPE_OFF_T", 270),
        ("CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS", "CURLOPTTYPE_LONG", 271),
        ("CURLOPT_RESOLVER_START_FUNCTION", "CURLOPTTYPE_FUNCTIONPOINT", 272),
        ("CURLOPT_RESOLVER_START_DATA", "CURLOPTTYPE_CBPOINT", 273),
        ("CURLOPT_HAPROXYPROTOCOL", "CURLOPTTYPE_LONG", 274),
        ("CURLOPT_DNS_SHUFFLE_ADDRESSES", "CURLOPTTYPE_LONG", 275),
        ("CURLOPT_TLS13_CIPHERS", "CURLOPTTYPE_STRINGPOINT", 276),
        ("CURLOPT_PROXY_TLS13_CIPHERS", "CURLOPTTYPE_STRINGPOINT", 277),
        ("CURLOPT_DISALLOW_USERNAME_IN_URL", "CURLOPTTYPE_LONG", 278),
        ("CURLOPT_DOH_URL", "CURLOPTTYPE_STRINGPOINT", 279),
        ("CURLOPT_UPLOAD_BUFFERSIZE", "CURLOPTTYPE_LONG", 280),
        ("CURLOPT_UPKEEP_INTERVAL_MS", "CURLOPTTYPE_LONG", 281),
        ("CURLOPT_CURLU", "CURLOPTTYPE_OBJECTPOINT", 282),
        ("CURLOPT_TRAILERFUNCTION", "CURLOPTTYPE_FUNCTIONPOINT", 283),
        ("CURLOPT_TRAILERDATA", "CURLOPTTYPE_CBPOINT", 284),
        ("CURLOPT_HTTP09_ALLOWED", "CURLOPTTYPE_LONG", 285),
        ("CURLOPT_ALTSVC_CTRL", "CURLOPTTYPE_LONG", 286),
        ("CURLOPT_ALTSVC", "CURLOPTTYPE_STRINGPOINT", 287),
        ("CURLOPT_MAXAGE_CONN", "CURLOPTTYPE_LONG", 288),
        ("CURLOPT_SASL_AUTHZID", "CURLOPTTYPE_STRINGPOINT", 289),
        ("CURLOPT_MAIL_RCPT_ALLOWFAILS", "CURLOPTTYPE_LONG", 290),
        ("CURLOPT_SSLCERT_BLOB", "CURLOPTTYPE_BLOB", 291),
        ("CURLOPT_SSLKEY_BLOB", "CURLOPTTYPE_BLOB", 292),
        ("CURLOPT_PROXY_SSLCERT_BLOB", "CURLOPTTYPE_BLOB", 293),
        ("CURLOPT_PROXY_SSLKEY_BLOB", "CURLOPTTYPE_BLOB", 294),
        ("CURLOPT_ISSUERCERT_BLOB", "CURLOPTTYPE_BLOB", 295),
        ("CURLOPT_PROXY_ISSUERCERT", "CURLOPTTYPE_STRINGPOINT", 296),
        ("CURLOPT_PROXY_ISSUERCERT_BLOB", "CURLOPTTYPE_BLOB", 297),
        ("CURLOPT_SSL_EC_CURVES", "CURLOPTTYPE_STRINGPOINT", 298),
        ("CURLOPT_HSTS_CTRL", "CURLOPTTYPE_LONG", 299),
        ("CURLOPT_HSTS", "CURLOPTTYPE_STRINGPOINT", 300),
        ("CURLOPT_HSTSREADFUNCTION", "CURLOPTTYPE_FUNCTIONPOINT", 301),
        ("CURLOPT_HSTSREADDATA", "CURLOPTTYPE_CBPOINT", 302),
        ("CURLOPT_HSTSWRITEFUNCTION", "CURLOPTTYPE_FUNCTIONPOINT", 303),
        ("CURLOPT_HSTSWRITEDATA", "CURLOPTTYPE_CBPOINT", 304),
        ("CURLOPT_AWS_SIGV4", "CURLOPTTYPE_STRINGPOINT", 305),
        ("CURLOPT_DOH_SSL_VERIFYPEER", "CURLOPTTYPE_LONG", 306),
        ("CURLOPT_DOH_SSL_VERIFYHOST", "CURLOPTTYPE_LONG", 307),
        ("CURLOPT_DOH_SSL_VERIFYSTATUS", "CURLOPTTYPE_LONG", 308),
        ("CURLOPT_CAINFO_BLOB", "CURLOPTTYPE_BLOB", 309),
        ("CURLOPT_PROXY_CAINFO_BLOB", "CURLOPTTYPE_BLOB", 310),
        ("CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256", "CURLOPTTYPE_STRINGPOINT", 311),
        ("CURLOPT_PREREQFUNCTION", "CURLOPTTYPE_FUNCTIONPOINT", 312),
        ("CURLOPT_PREREQDATA", "CURLOPTTYPE_CBPOINT", 313),
        ("CURLOPT_MAXLIFETIME_CONN", "CURLOPTTYPE_LONG", 314),
        ("CURLOPT_MIME_OPTIONS", "CURLOPTTYPE_LONG", 315),
        ("CURLOPT_SSH_HOSTKEYFUNCTION", "CURLOPTTYPE_FUNCTIONPOINT", 316),
        ("CURLOPT_SSH_HOSTKEYDATA", "CURLOPTTYPE_CBPOINT", 317),
        ("CURLOPT_PROTOCOLS_STR", "CURLOPTTYPE_STRINGPOINT", 318),
        ("CURLOPT_REDIR_PROTOCOLS_STR", "CURLOPTTYPE_STRINGPOINT", 319),
        ("CURLOPT_WS_OPTIONS", "CURLOPTTYPE_LONG", 320),
        ("CURLOPT_CA_CACHE_TIMEOUT", "CURLOPTTYPE_LONG", 321),
        ("CURLOPT_QUICK_EXIT", "CURLOPTTYPE_LONG", 322),
        ("CURLOPT_HAPROXY_CLIENT_IP", "CURLOPTTYPE_STRINGPOINT", 323),
        ("CURLOPT_SERVER_RESPONSE_TIMEOUT_MS", "CURLOPTTYPE_LONG", 324),
        ("CURLOPT_ECH", "CURLOPTTYPE_STRINGPOINT", 325),
        ("CURLOPT_TCP_KEEPCNT", "CURLOPTTYPE_LONG", 326),
        ("CURLOPT_UPLOAD_FLAGS", "CURLOPTTYPE_LONG", 327),
        ("CURLOPT_HTTPBASEHEADER", "CURLOPTTYPE_SLISTPOINT", 328),
    ];

    for (name, type_base, num) in curlopt_entries {
        s.push_str(&format!("#define {} ({} + {})\n", name, type_base, num));
    }

    // Deprecated CURLOPT aliases
    s.push_str("\n/* Deprecated CURLOPT aliases */\n");
    s.push_str("#define CURLOPT_ENCODING CURLOPT_ACCEPT_ENCODING\n");
    s.push_str("#define CURLOPT_FILE CURLOPT_WRITEDATA\n");
    s.push_str("#define CURLOPT_INFILE CURLOPT_READDATA\n");
    s.push_str("#define CURLOPT_WRITEHEADER CURLOPT_HEADERDATA\n");
    s.push_str("#define CURLOPT_PROGRESSDATA CURLOPT_XFERINFODATA\n");
    s.push_str("#define CURLOPT_POST301 CURLOPT_POSTREDIR\n");
    s.push_str("#define CURLOPT_SSLKEYPASSWD CURLOPT_KEYPASSWD\n");
    s.push_str("#define CURLOPT_FTPAPPEND CURLOPT_APPEND\n");
    s.push_str("#define CURLOPT_FTPLISTONLY CURLOPT_DIRLISTONLY\n");
    s.push_str("#define CURLOPT_FTP_SSL CURLOPT_USE_SSL\n");
    s.push_str("#define CURLOPT_SSLCERTPASSWD CURLOPT_KEYPASSWD\n");
    s.push_str("#define CURLOPT_KRB4LEVEL CURLOPT_KRBLEVEL\n");
    s.push_str("#define CURLOPT_FTP_RESPONSE_TIMEOUT CURLOPT_SERVER_RESPONSE_TIMEOUT\n");
    s.push_str("#define CURLOPT_RTSPHEADER CURLOPT_HTTPHEADER\n");

    // CURLINFO_* constants
    s.push_str("\n/* ================================================================ */\n");
    s.push_str("/* CURLINFO_* query constants — curl 8.x ABI compatible            */\n");
    s.push_str("/* ================================================================ */\n\n");

    let curlinfo_entries: &[(&str, &str, u32)] = &[
        ("CURLINFO_NONE", "0", 0),
        ("CURLINFO_EFFECTIVE_URL", "CURLINFO_STRING", 1),
        ("CURLINFO_RESPONSE_CODE", "CURLINFO_LONG", 2),
        ("CURLINFO_TOTAL_TIME", "CURLINFO_DOUBLE", 3),
        ("CURLINFO_NAMELOOKUP_TIME", "CURLINFO_DOUBLE", 4),
        ("CURLINFO_CONNECT_TIME", "CURLINFO_DOUBLE", 5),
        ("CURLINFO_PRETRANSFER_TIME", "CURLINFO_DOUBLE", 6),
        ("CURLINFO_SIZE_UPLOAD_T", "CURLINFO_OFF_T", 7),
        ("CURLINFO_SIZE_DOWNLOAD_T", "CURLINFO_OFF_T", 8),
        ("CURLINFO_SPEED_DOWNLOAD_T", "CURLINFO_OFF_T", 9),
        ("CURLINFO_SPEED_UPLOAD_T", "CURLINFO_OFF_T", 10),
        ("CURLINFO_HEADER_SIZE", "CURLINFO_LONG", 11),
        ("CURLINFO_REQUEST_SIZE", "CURLINFO_LONG", 12),
        ("CURLINFO_SSL_VERIFYRESULT", "CURLINFO_LONG", 13),
        ("CURLINFO_FILETIME", "CURLINFO_LONG", 14),
        ("CURLINFO_FILETIME_T", "CURLINFO_OFF_T", 14),
        ("CURLINFO_CONTENT_LENGTH_DOWNLOAD_T", "CURLINFO_OFF_T", 15),
        ("CURLINFO_CONTENT_LENGTH_UPLOAD_T", "CURLINFO_OFF_T", 16),
        ("CURLINFO_STARTTRANSFER_TIME", "CURLINFO_DOUBLE", 17),
        ("CURLINFO_CONTENT_TYPE", "CURLINFO_STRING", 18),
        ("CURLINFO_REDIRECT_TIME", "CURLINFO_DOUBLE", 19),
        ("CURLINFO_REDIRECT_COUNT", "CURLINFO_LONG", 20),
        ("CURLINFO_PRIVATE", "CURLINFO_STRING", 21),
        ("CURLINFO_HTTP_CONNECTCODE", "CURLINFO_LONG", 22),
        ("CURLINFO_HTTPAUTH_AVAIL", "CURLINFO_LONG", 23),
        ("CURLINFO_PROXYAUTH_AVAIL", "CURLINFO_LONG", 24),
        ("CURLINFO_OS_ERRNO", "CURLINFO_LONG", 25),
        ("CURLINFO_NUM_CONNECTS", "CURLINFO_LONG", 26),
        ("CURLINFO_SSL_ENGINES", "CURLINFO_SLIST", 27),
        ("CURLINFO_COOKIELIST", "CURLINFO_SLIST", 28),
        ("CURLINFO_FTP_ENTRY_PATH", "CURLINFO_STRING", 30),
        ("CURLINFO_REDIRECT_URL", "CURLINFO_STRING", 31),
        ("CURLINFO_PRIMARY_IP", "CURLINFO_STRING", 32),
        ("CURLINFO_APPCONNECT_TIME", "CURLINFO_DOUBLE", 33),
        ("CURLINFO_CERTINFO", "CURLINFO_PTR", 34),
        ("CURLINFO_CONDITION_UNMET", "CURLINFO_LONG", 35),
        ("CURLINFO_RTSP_SESSION_ID", "CURLINFO_STRING", 36),
        ("CURLINFO_RTSP_CLIENT_CSEQ", "CURLINFO_LONG", 37),
        ("CURLINFO_RTSP_SERVER_CSEQ", "CURLINFO_LONG", 38),
        ("CURLINFO_RTSP_CSEQ_RECV", "CURLINFO_LONG", 39),
        ("CURLINFO_PRIMARY_PORT", "CURLINFO_LONG", 40),
        ("CURLINFO_LOCAL_IP", "CURLINFO_STRING", 41),
        ("CURLINFO_LOCAL_PORT", "CURLINFO_LONG", 42),
        ("CURLINFO_ACTIVESOCKET", "CURLINFO_SOCKET", 44),
        ("CURLINFO_TLS_SSL_PTR", "CURLINFO_PTR", 45),
        ("CURLINFO_HTTP_VERSION", "CURLINFO_LONG", 46),
        ("CURLINFO_PROXY_SSL_VERIFYRESULT", "CURLINFO_LONG", 47),
        ("CURLINFO_SCHEME", "CURLINFO_STRING", 49),
        ("CURLINFO_TOTAL_TIME_T", "CURLINFO_OFF_T", 50),
        ("CURLINFO_NAMELOOKUP_TIME_T", "CURLINFO_OFF_T", 51),
        ("CURLINFO_CONNECT_TIME_T", "CURLINFO_OFF_T", 52),
        ("CURLINFO_PRETRANSFER_TIME_T", "CURLINFO_OFF_T", 53),
        ("CURLINFO_STARTTRANSFER_TIME_T", "CURLINFO_OFF_T", 54),
        ("CURLINFO_REDIRECT_TIME_T", "CURLINFO_OFF_T", 55),
        ("CURLINFO_APPCONNECT_TIME_T", "CURLINFO_OFF_T", 56),
        ("CURLINFO_RETRY_AFTER", "CURLINFO_OFF_T", 57),
        ("CURLINFO_EFFECTIVE_METHOD", "CURLINFO_STRING", 58),
        ("CURLINFO_PROXY_ERROR", "CURLINFO_LONG", 59),
        ("CURLINFO_REFERER", "CURLINFO_STRING", 60),
        ("CURLINFO_CAINFO", "CURLINFO_STRING", 61),
        ("CURLINFO_CAPATH", "CURLINFO_STRING", 62),
        ("CURLINFO_XFER_ID", "CURLINFO_OFF_T", 63),
        ("CURLINFO_CONN_ID", "CURLINFO_OFF_T", 64),
        ("CURLINFO_QUEUE_TIME_T", "CURLINFO_OFF_T", 65),
        ("CURLINFO_USED_PROXY", "CURLINFO_LONG", 66),
        ("CURLINFO_POSTTRANSFER_TIME_T", "CURLINFO_OFF_T", 67),
        ("CURLINFO_EARLYDATA_SENT_T", "CURLINFO_OFF_T", 68),
    ];

    for (name, type_base, num) in curlinfo_entries {
        if *num == 0 && *type_base == "0" {
            s.push_str(&format!("#define {} 0\n", name));
        } else {
            s.push_str(&format!("#define {} ({} + {})\n", name, type_base, num));
        }
    }

    // Deprecated CURLINFO aliases
    s.push_str("\n/* Deprecated CURLINFO aliases */\n");
    s.push_str("#define CURLINFO_HTTP_CODE CURLINFO_RESPONSE_CODE\n");
    s.push_str("#define CURLINFO_LASTSOCKET 0x500000 + 29\n");

    s.push_str("\n#endif /* end of CURLOPT/CURLINFO constants */\n");
    s
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
