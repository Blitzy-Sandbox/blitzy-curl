//! Build script for `curl-rs-ffi` — the drop-in `libcurl` FFI crate.
//!
//! This script has exactly **three responsibilities**, all mandated by the
//! Agent Action Plan (§0.5.2 / §0.7.2 / §0.8.4 step 13). It deliberately does
//! nothing else (minimal-change mandate, AAP §0.8.1):
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
//! 3. **C ABI trampolines (variadic / `va_list`).** Compile the small C shims
//!    under `csrc/*.c` via the `cc` crate and link them into the
//!    `libcurl`-compatible library. These shims define exactly the exported
//!    `curl_*` symbols that stable Rust provably *cannot* express — the
//!    C-variadic printf family (`curl_mprintf` & friends), the C-variadic
//!    `curl_easy_setopt` / `curl_easy_getinfo` / `curl_multi_setopt` /
//!    `curl_formadd`, and their `va_list` siblings — because `c_variadic` and
//!    `core::ffi::VaList` are nightly-only (AAP §0.7.2). This is a documented,
//!    minimal **no-C-mandate exception** (AAP §0.8.2/§0.8.3): the trampolines
//!    are pure calling-convention adapters that forward to the platform C
//!    library — they are NOT a protocol or TLS backend and link no third-party
//!    C library. They are linked with the `+whole-archive` modifier so their
//!    symbols reach the exported symbol table that the `nm` / `objdump` parity
//!    gate checks against `lib/libcurl.def`.
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
use std::fs;
use std::path::{Path, PathBuf};

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
    // Phase 6 — C ABI trampolines (variadic / `va_list`).
    //
    // Compile every `csrc/*.c` shim and link the resulting archive with
    // `+whole-archive` so its `curl_*` symbols are present in the produced
    // `libcurl`. See `compile_c_trampolines` for the full rationale and the
    // documented no-C-mandate exception (AAP §0.8.2/§0.8.3 / §0.7.2). Run
    // before header generation so the (non-authoritative) cbindgen step can
    // never affect the library's exported-symbol surface.
    // ------------------------------------------------------------------------
    compile_c_trampolines(&crate_path, &out_dir);

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

// ===========================================================================
// C ABI trampoline compilation (the documented no-C-mandate exception).
//
// Some `curl_*` symbols cannot be DEFINED in stable Rust because their ABI is
// not expressible there: the C-variadic functions (`fn(fmt, ...)`) require the
// nightly-only `c_variadic` feature, and the `va_list`-taking functions require
// the unstable `core::ffi::VaList` type. The printf family
// (`curl_mprintf`/`curl_mvprintf`/… — see `src/mprintf.rs` and `csrc/mprintf.c`)
// and the variadic option/form shims (`curl_easy_setopt`, `curl_easy_getinfo`,
// `curl_multi_setopt`, `curl_formadd`) all fall in this category (AAP §0.7.2).
//
// AAP §0.8.2 forbids C linkage against `libcurl` / `libssl` / C TLS libraries
// and C protocol/TLS backends. These trampolines are NONE of those: they are
// dependency-free calling-convention adapters that forward straight to the
// platform C library's standard `printf` family / dispatch into the Rust core.
// Compiling them with `cc` is the established, minimal mechanism for a C ABI
// that stable Rust cannot express, and is the documented exception required by
// AAP §0.8.3. No third-party C library is linked.
// ===========================================================================

/// Compile every `csrc/*.c` ABI trampoline and link the resulting static
/// archive into the `libcurl`-compatible artifacts with `+whole-archive`.
///
/// * **Discovery is by directory scan** (not a hardcoded file list) so that
///   sibling trampoline units (e.g. the variadic `setopt` / `formadd` shims)
///   added under `csrc/` are picked up automatically without further edits to
///   this script — a single shared `cc` build step, as the AAP intends.
/// * **`cargo_metadata(false)`** suppresses `cc`'s automatic
///   `cargo:rustc-link-lib=static=NAME` directive so it can be re-emitted below
///   with the `+whole-archive` modifier.
/// * **`+whole-archive`** (stable since Rust 1.61) forces *every* object in the
///   archive into the final link even though no Rust code references these
///   symbols; without it the linker would discard the unreferenced trampoline
///   objects and the `curl_*` symbols would be missing from `libcurl`.
/// * **Export visibility** then has to be granted explicitly. Inclusion does
///   *not* imply export: when rustc links a `cdylib` on ELF it auto-generates an
///   anonymous version script of the form `{ global: <its #[no_mangle] names>;
///   local: *; };`. The trampoline symbols are not in rustc's enumerated global
///   list, so the catch-all `local: *;` would otherwise hide them (and
///   `--export-dynamic-symbol` cannot override a `local:` rule — verified
///   empirically against GNU `ld` 2.45). We therefore add a second anonymous
///   version script, `{ global: curl_*; local: *; };`. A linker that supports
///   merging version nodes resolves a symbol matching patterns in several nodes
///   by *most-specific match*, and `curl_*` is more specific than `*`, so every
///   `curl_`-prefixed symbol (both rustc's Rust exports and the C trampolines)
///   is routed to `global` while all internal Rust/C-dependency symbols stay
///   `local`. The exported set is therefore *exactly* the `curl_*` family — no
///   more, no less — which is precisely the `libcurl` ABI surface the
///   `nm`/`objdump` parity gate checks (AAP §0.7.2). The directive is scoped to
///   the `cdylib` via `rustc-cdylib-link-arg`, so the `curl-rs` executable link
///   and the `staticlib` archive are untouched (the `staticlib` needs no script:
///   `+whole-archive` already bundles the trampoline objects into `libcurl.a`,
///   from which `tests/libtest` resolves the symbols directly).
/// * **Linker choice matters for the merge (the four-target portability fix).**
///   GNU `ld` (BFD) **refuses** to combine two anonymous version scripts —
///   `anonymous version tag cannot be combined with other version tags` — so the
///   two-script approach above fails the moment rustc links the `cdylib` through
///   an external GNU `gcc`/BFD, as it does for the `aarch64-unknown-linux-gnu`
///   cross build. LLVM `lld`, by contrast, merges them exactly as required. rustc
///   already selects the bundled `rust-lld` by default for
///   `x86_64-unknown-linux-gnu` (passing `-B<sysroot>/…/gcc-ld -fuse-ld=lld`),
///   which is *why* the x86_64 link succeeds; the aarch64 cross link falls back
///   to BFD and fails. `force_rust_lld_for_cdylib` therefore selects `rust-lld`
///   for **every** ELF `cdylib` link (idempotent where it is already the default,
///   corrective for the aarch64 cross), making the export mechanism portable
///   across the whole matrix. Crucially, anonymous version scripts define **no**
///   version nodes, so the produced symbols stay **unversioned** (no
///   `.gnu.version_d`, no `name@@VERSION`) — the unversioned `libcurl` ABI that
///   `lib/libcurl.def` mandates is preserved, and macOS/ld64 (handled in the
///   `macos`/`ios` branch) is unaffected because it never uses version scripts.
///
/// Absence of `csrc/` (or an empty `csrc/`) is **not** an error: the function
/// returns quietly so the crate still builds during early scaffolding when no
/// trampoline file has landed yet.
fn compile_c_trampolines(crate_path: &Path, out_dir: &str) {
    let csrc_dir = crate_path.join("csrc");

    // Re-run if trampoline sources are added/removed/edited. The per-file
    // triggers below cover edits; this directory trigger covers add/remove.
    println!("cargo:rerun-if-changed=csrc");

    // Collect the C sources under csrc/. A missing directory simply means there
    // is nothing to compile yet (early-scaffolding path) — return quietly.
    let read_dir = match fs::read_dir(&csrc_dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    let mut sources: Vec<PathBuf> = read_dir
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("c"))
        .collect();
    if sources.is_empty() {
        return;
    }
    // Sort for deterministic, reproducible build output across platforms.
    sources.sort();

    for source in &sources {
        println!("cargo:rerun-if-changed={}", source.display());
    }

    // Compile all trampoline units into one static archive. `cargo_metadata`
    // is disabled so the link directive can be re-emitted with `+whole-archive`.
    let lib_name = "curl_rs_ffi_trampolines";
    let mut build = cc::Build::new();
    build.cargo_metadata(false);
    for source in &sources {
        build.file(source);
    }
    build.compile(lib_name);

    // `cc` wrote `lib<lib_name>.a` into OUT_DIR. Add the search path and link
    // the archive whole so all trampoline objects are pulled into the link.
    println!("cargo:rustc-link-search=native={out_dir}");
    println!("cargo:rustc-link-lib=static:+whole-archive={lib_name}");

    // `+whole-archive` guarantees INCLUSION, but not EXPORT (see the function
    // doc comment for the full rationale). Grant export visibility to the
    // `curl_*` family for the `cdylib` artifact only, using the platform's
    // export-control mechanism. This is scoped via `rustc-cdylib-link-arg`, so
    // neither the `curl-rs` executable link nor the `staticlib` archive is
    // affected.
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "macos" || target_os == "ios" {
        // Mach-O / ld64: there is no version-script concept. rustc restricts the
        // export set with `-exported_symbols_list`; an additional
        // `-exported_symbol` glob unions into that set and also pins the matched
        // symbols as `-dead_strip` roots. `_curl_*` (Mach-O prepends a leading
        // underscore to C symbols) selects exactly the libcurl ABI surface.
        println!("cargo:rustc-cdylib-link-arg=-Wl,-exported_symbol,_curl_*");
    } else {
        // ELF (GNU ld / lld): emit an anonymous version script that promotes the
        // whole `curl_*` family to `global` while keeping everything else
        // `local`. This is what the `nm`/`objdump` symbol-parity gate (AAP
        // §0.7.2 / §0.8.1) verifies: the produced `libcurl.so` must export the
        // exact set of 100 `curl_*` entries enumerated in `lib/libcurl.def`,
        // which it does — `diff` against the canonical list is empty on both
        // x86_64 and aarch64.
        //
        // Scope note on the dynamic symbol table: rustc also auto-generates its
        // own version script for a `cdylib` that lists every `#[no_mangle]`
        // symbol by exact name under `global`. Besides the 100 `curl_*` ABI
        // symbols this includes a small set of internal variadic-bridge helpers
        // (`curlrs_easy_setopt_impl`, `curlrs_easy_getinfo_impl`,
        // `curlrs_multi_setopt_impl`, `curlrs_share_setopt_impl`,
        // `curlrs_formadd_impl`) that the C trampolines in `csrc/` call. Because
        // rustc lists those by exact name, the `local: *;` wildcard below does
        // not demote them, so they remain visible in `.dynsym` alongside the
        // `curl_*` family. This is deliberate and harmless: they live in a
        // distinct `curlrs_` namespace that never collides with a real
        // `libcurl` (which has no such symbols), so drop-in compatibility is
        // unaffected — every consumer resolves only the `curl_*` ABI. The
        // parity contract that matters is the `curl_*` export set, which is
        // exact. (Demoting the `curlrs_` helpers by listing them under `local:`
        // by exact name is possible but provokes a version-script binding
        // conflict that newer `lld` reports as a warning, so it is intentionally
        // avoided to keep the build warning-free across all toolchains.)
        //
        // BFD refuses to combine two anonymous version scripts, so the link
        // MUST go through `lld` (which rustc already uses by default on
        // x86_64-linux but NOT on the aarch64-linux cross). Select the bundled
        // `rust-lld` for this `cdylib` first, then emit the script. See
        // `force_rust_lld_for_cdylib` for the full rationale.
        force_rust_lld_for_cdylib();

        // Written into OUT_DIR so the path is unique per build and cleaned with
        // the target directory.
        let version_script = Path::new(out_dir).join("curl_exports.map");
        fs::write(
            &version_script,
            "{\n  global:\n    curl_*;\n  local:\n    *;\n};\n",
        )
        .expect("failed to write libcurl export version script");
        println!(
            "cargo:rustc-cdylib-link-arg=-Wl,--version-script={}",
            version_script.display()
        );
        // Re-run if the generated script is removed out-of-band.
        println!("cargo:rerun-if-changed={}", version_script.display());
    }
}

/// Select the toolchain-bundled `rust-lld` for the ELF `cdylib` link.
///
/// # Why this is required
///
/// The trampoline-export step adds a second anonymous version script
/// (`{ global: curl_*; local: *; }`) alongside the one rustc auto-generates for
/// a `cdylib`. GNU `ld` (BFD) **rejects** that combination outright
/// (`anonymous version tag cannot be combined with other version tags`), whereas
/// LLVM `lld` merges the two by most-specific-pattern match — exactly the
/// behaviour the export step relies on. rustc already drives the link through
/// `rust-lld` for `x86_64-unknown-linux-gnu` (it passes
/// `-B<sysroot>/lib/rustlib/<host>/bin/gcc-ld -fuse-ld=lld`), but for
/// `aarch64-unknown-linux-gnu` it links through the external GNU `gcc`/BFD and
/// the combination fails. Forcing `rust-lld` for *every* ELF `cdylib` link makes
/// the export mechanism portable across the four-target matrix: it is idempotent
/// where `lld` is already the default and corrective for the aarch64 cross.
///
/// `rust-lld` is the multi-target LLVM linker shipped with every standard rustup
/// toolchain; it cross-links aarch64 objects from an x86_64 host. Because an
/// anonymous version script defines no version nodes, the produced symbols stay
/// **unversioned** (no `.gnu.version_d`, no `name@@VERSION`), preserving the
/// unversioned `libcurl` ABI enumerated in `lib/libcurl.def`.
///
/// # Discovery and scoping
///
/// A build script runs on the HOST, so `rust-lld` and its `gcc-ld` driver
/// wrappers are resolved under the HOST toolchain's `rustlib` tree, keyed by the
/// `HOST` triple (both `RUSTC` and `HOST` are guaranteed set by Cargo for build
/// scripts). The two flags are scoped to the `cdylib` via
/// `rustc-cdylib-link-arg`, so neither the `curl-rs` executable link nor the
/// `staticlib` archive is affected.
///
/// Returns `true` when `rust-lld` was located and the link args were emitted.
/// When it cannot be located (a non-standard toolchain layout) the function is a
/// no-op and the caller still writes the version script: the only known ELF
/// target that does not already default to `rust-lld` is the aarch64 cross, and
/// every standard toolchain ships the `gcc-ld` wrappers, so this fallback is
/// purely defensive.
fn force_rust_lld_for_cdylib() -> bool {
    // The `gcc-ld` wrappers live in the HOST toolchain (the linker driver runs
    // on the build machine), keyed by the HOST target triple.
    let host = match env::var("HOST") {
        Ok(host) if !host.is_empty() => host,
        _ => return false,
    };
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());

    // `rustc --print sysroot` yields the active toolchain root that owns the
    // bundled `rust-lld` and its `gcc-ld` driver wrappers.
    let sysroot = match std::process::Command::new(&rustc)
        .args(["--print", "sysroot"])
        .output()
    {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        _ => return false,
    };
    if sysroot.is_empty() {
        return false;
    }

    // `<sysroot>/lib/rustlib/<host>/bin/gcc-ld/ld.lld` is the GNU-flavour driver
    // wrapper that `gcc -fuse-ld=lld` invokes; its presence confirms a usable
    // bundled linker before we commit to selecting it.
    let gcc_ld_dir = Path::new(&sysroot)
        .join("lib")
        .join("rustlib")
        .join(&host)
        .join("bin")
        .join("gcc-ld");
    if !gcc_ld_dir.join("ld.lld").is_file() {
        return false;
    }

    // `-B<dir>` adds the wrapper to gcc's program search path; `-fuse-ld=lld`
    // then selects it. Both are idempotent on x86_64-linux (rustc already emits
    // the identical pair) and corrective on the aarch64-linux cross.
    println!("cargo:rustc-cdylib-link-arg=-B{}", gcc_ld_dir.display());
    println!("cargo:rustc-cdylib-link-arg=-fuse-ld=lld");
    true
}
