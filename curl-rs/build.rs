//! Build script for `curl-rs` — generates the drop-in `curl-config` helper.
//!
//! # Why this exists (QA finding F7-CLI Issue 11 / AAP §0.5 curl-config parity)
//!
//! The C build ships `curl-config.in` at the project root and has `configure`
//! substitute its `@PLACEHOLDER@` tokens to emit an executable `curl-config`
//! script (also at the build root) that downstream consumers query for the
//! library's capabilities — most importantly `curl-config --features` and
//! `curl-config --protocols`. The curl 8.x checkpoint lists that equivalence as
//! in-scope, but the Rust workspace previously produced no `curl-config` at all.
//!
//! This script is the faithful Rust analog of that `configure` step: it READS
//! the committed `../curl-config.in` template (the C project's own oracle) and
//! substitutes the build-specific values, then writes the result next to the
//! freshly built `curl-rs` binary in the Cargo target profile directory
//! (e.g. `target/release/curl-config`). That is exactly where a drop-in
//! `curl`/`libcurl` install co-locates `curl` and `curl-config`, and exactly
//! where the QA pass looked for it.
//!
//! # Hard rules (mirroring `curl-rs-ffi/build.rs`)
//!
//! * **Writes only under `target/`.** The generated `curl-config` lands in the
//!   profile dir derived from `OUT_DIR`; `target/` is git-ignored, so the build
//!   never mutates the tracked source tree and stays fully reproducible. The
//!   committed `curl-config.in` template is the single authored artifact.
//! * **Best-effort, never fails the build.** A missing template or an
//!   unresolvable profile dir emits a `cargo:warning` and returns; it never
//!   breaks the zero-warnings rustc/clippy BUILD gate (the warning is a
//!   build-script note, not a compiler diagnostic).
//! * **Single-colon `cargo:` directives ONLY.** Workspace MSRV is 1.75
//!   (edition 2021); Cargo 1.75 understands only the single-colon
//!   `cargo:KEY=VALUE` build-script syntax.
//! * **Capability values are kept in lock-step with `curl_rs_lib::version`.**
//!   The feature/protocol token lists below MUST equal what `curl-rs --version`
//!   reports (the `EXPECTED_FEATURES` / `EXPECTED_PROTOCOLS` arrays in
//!   `curl-rs-lib/src/version.rs`, themselves pinned by that crate's unit
//!   tests). Drift is caught at test time by `curl-rs/tests/curl_config.rs`,
//!   which diffs `curl-config` output against `curl-rs --version`.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Build-specific capability values (the substitution inputs).
//
// These mirror the C `configure` substitutions for the curl-rs default build.
// `SUPPORT_*` MUST stay in sync with `curl_rs_lib::version` (see module docs).
// ---------------------------------------------------------------------------

/// Human-facing version string — `LIBCURL_VERSION` from `include/curl/curlver.h`
/// and the exact string `curl-rs --version` reports.
const CURL_VERSION: &str = "8.19.0-DEV";

/// Hexadecimal version number WITHOUT the `0x` prefix — the lower 6 hex digits
/// of `LIBCURL_VERSION_NUM` (`0x081300`) from `include/curl/curlver.h`, exactly
/// as C `curl-config --vernum` prints it.
const VERSION_NUM: &str = "081300";

/// The exclusive TLS backend (AAP §0.8.1) reported by `curl-config --ssl-backends`.
const SSL_BACKENDS: &str = "rustls";

/// Enabled feature names, in `sort -f` (case-insensitive) order — byte-identical
/// to `curl-rs --version`'s `Features:` line and to `EXPECTED_FEATURES` in
/// `curl-rs-lib/src/version.rs`. `curl-config --features` echoes these verbatim.
const SUPPORT_FEATURES: &[&str] = &[
    "alt-svc",
    "AsynchDNS",
    "brotli",
    "HSTS",
    "HTTP2",
    "HTTP3",
    "HTTPS-proxy",
    "IDN",
    "IPv6",
    "Largefile",
    "libz",
    "NTLM",
    "PSL",
    "SSL",
    "threadsafe",
    "UnixSockets",
    "zstd",
];

/// Enabled protocol scheme names in UPPERCASE, sorted — the curl-config
/// convention (C `configure` builds `SUPPORT_PROTOCOLS` uppercase and sorts it;
/// the lowercase variant feeds `curl --version`). This is the uppercase of
/// `EXPECTED_PROTOCOLS` in `curl-rs-lib/src/version.rs`. `curl-config
/// --protocols` echoes these one per line.
const SUPPORT_PROTOCOLS: &[&str] = &[
    "DICT", "FILE", "FTP", "FTPS", "GOPHER", "GOPHERS", "HTTP", "HTTPS", "IMAP", "IMAPS", "LDAP",
    "LDAPS", "MQTT", "MQTTS", "POP3", "POP3S", "RTSP", "SCP", "SFTP", "SMB", "SMBS", "SMTP", "SMTPS",
    "TELNET", "TFTP", "WS", "WSS",
];

fn main() {
    // -----------------------------------------------------------------------
    // Locate the committed template at the workspace root (parent of this
    // crate dir). Re-run only when the template or this script changes.
    // -----------------------------------------------------------------------
    let manifest_dir =
        env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is always set for build scripts");
    let workspace_root = PathBuf::from(&manifest_dir)
        .parent()
        .expect("curl-rs crate dir must have a parent (the workspace root)")
        .to_path_buf();
    let template_path = workspace_root.join("curl-config.in");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", template_path.display());

    // -----------------------------------------------------------------------
    // Expose the build target triple to the crate as `CURL_RS_OS` so the CLI's
    // `--version` line can report `curl <ver> (<target-triple>) libcurl/<ver>`
    // — the Rust analog of C's `CURL_OS`/`OS` define (`src/tool_version.h`).
    // `TARGET` is always set for build scripts; `rustc-env` makes it available
    // to `env!("CURL_RS_OS")` when compiling this crate (see operate.rs).
    // -----------------------------------------------------------------------
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=CURL_RS_OS={target}");

    // -----------------------------------------------------------------------
    // Read the template. Absence is non-fatal (best-effort): warn and stop so
    // the BUILD gate is never broken by a missing optional helper artifact.
    // -----------------------------------------------------------------------
    let template = match fs::read_to_string(&template_path) {
        Ok(text) => text,
        Err(err) => {
            println!(
                "cargo:warning=curl-config not generated: cannot read {}: {err}",
                template_path.display()
            );
            return;
        }
    };

    // -----------------------------------------------------------------------
    // Substitute every `@PLACEHOLDER@` token with its build value.
    // -----------------------------------------------------------------------
    let script = render_curl_config(&template);

    // -----------------------------------------------------------------------
    // Resolve the Cargo target profile directory from `OUT_DIR`.
    //
    // `OUT_DIR` is `<target>/[<triple>/]<profile>/build/<pkg>-<hash>/out`, so
    // the 3rd ancestor is always the `<profile>` directory that also holds the
    // compiled `curl-rs` binary — the correct co-location for `curl-config`.
    // -----------------------------------------------------------------------
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR is always set for build scripts");
    let profile_dir = Path::new(&out_dir).ancestors().nth(3).map(Path::to_path_buf);

    let Some(profile_dir) = profile_dir else {
        println!(
            "cargo:warning=curl-config not generated: could not resolve the target profile \
             directory from OUT_DIR={out_dir}"
        );
        return;
    };

    let dest = profile_dir.join("curl-config");
    if let Err(err) = fs::write(&dest, script.as_bytes()) {
        println!(
            "cargo:warning=curl-config not written to {}: {err}",
            dest.display()
        );
        return;
    }

    // Make the script executable so it can be invoked directly as
    // `./curl-config` / `target/<profile>/curl-config`, like the C build's
    // generated script. No-op on non-unix targets (the script is `#!/bin/sh`).
    make_executable(&dest);
}

/// Substitute the `curl-config.in` `@PLACEHOLDER@` tokens with this build's
/// values, faithfully reproducing what C `configure` emits.
///
/// Install-location placeholders use curl's conventional defaults
/// (`/usr/local` prefix); link/compile-flag placeholders are emitted empty
/// because the Rust `libcurl` carries its dependencies internally (the
/// `--cflags` / `--libs` / `--static-libs` queries remain structurally valid).
/// The capability placeholders (`@SUPPORT_FEATURES@`, `@SUPPORT_PROTOCOLS@`,
/// `@CURLVERSION@`, `@VERSIONNUM@`, `@SSL_BACKENDS@`) carry the real values.
fn render_curl_config(template: &str) -> String {
    let features = SUPPORT_FEATURES.join(" ");
    let protocols = SUPPORT_PROTOCOLS.join(" ");

    // (placeholder, value) pairs. `str::replace` substitutes ALL occurrences.
    let substitutions: &[(&str, &str)] = &[
        // Install layout (curl's conventional defaults).
        ("@prefix@", "/usr/local"),
        ("@exec_prefix@", "/usr/local"),
        ("@includedir@", "/usr/local/include"),
        ("@libdir@", "/usr/local/lib"),
        ("@libext@", "a"),
        // Toolchain / configure provenance.
        ("@CC@", "cc"),
        ("@CONFIGURE_OPTIONS@", ""),
        // Capabilities (the QA-relevant values).
        ("@CURLVERSION@", CURL_VERSION),
        ("@VERSIONNUM@", VERSION_NUM),
        ("@SSL_BACKENDS@", SSL_BACKENDS),
        ("@SUPPORT_FEATURES@", &features),
        ("@SUPPORT_PROTOCOLS@", &protocols),
        // Build flavor: the FFI crate yields both a cdylib and a staticlib.
        ("@ENABLE_SHARED@", "yes"),
        ("@ENABLE_STATIC@", "yes"),
        // Link/compile flags: empty — the Rust libcurl bundles its deps.
        ("@CURL_CA_BUNDLE@", ""),
        ("@LIBCURL_PC_CFLAGS@", ""),
        ("@LIBCURL_PC_LDFLAGS_PRIVATE@", ""),
        ("@LIBCURL_PC_LIBS_PRIVATE@", ""),
    ];

    let mut out = template.to_string();
    for (placeholder, value) in substitutions {
        out = out.replace(placeholder, value);
    }
    out
}

/// Set the owner/group/other execute bits (0o755) on `path` so the generated
/// `curl-config` is directly runnable. Unix-only; a no-op elsewhere.
#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(metadata) = fs::metadata(path) {
        let mut perms = metadata.permissions();
        perms.set_mode(0o755);
        let _ = fs::set_permissions(path, perms);
    }
}

/// Non-unix fallback: the `#!/bin/sh` script is not directly executable anyway.
#[cfg(not(unix))]
fn make_executable(_path: &Path) {}
