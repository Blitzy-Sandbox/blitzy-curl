// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Build script for curl-urlapi-rs, the Rust re-implementation of curl's URL
//! API.
//!
//! It has exactly three jobs and deliberately no others. There is no URL
//! parsing here, no raw-pointer or FFI code of any kind -- all of that is
//! confined to src/ffi.rs -- and nothing outside this directory is read or
//! written.
//!
//! JOB ONE, translate the C capability selection into Cargo configuration
//! flags. The C side gates internationalised-domain support in two steps, and
//! both steps are reproduced here rather than collapsed into one:
//!
//! ```text
//! lib/curl_setup.h:720-724   HAVE_LIBIDN2 && HAVE_IDN2_H &&
//!                            !USE_WIN32_IDN && !USE_APPLE_IDN
//!                            =>  USE_LIBIDN2
//! lib/idn.h:29-30            USE_LIBIDN2 || USE_WIN32_IDN ||
//!                            USE_APPLE_IDN
//!                            =>  USE_IDN
//! ```
//!
//! `have_idn` stands in for USE_IDN, while `idn_backend_libidn2` and
//! `idn_backend_pure` name the selected backend, so src/idn.rs can ask "is
//! support present at all" and "which backend" as separate questions instead
//! of re-deriving one from the other. With USE_IDN undefined the C code
//! degrades host_decode() and host_encode() to CURLUE_LACKS_IDN
//! (lib/urlapi.c:1334-1336), which is what the crate reproduces when
//! `have_idn` is absent. That branch is silent in C, so it is silent here
//! too: a configuration with no backend is a deliberate one, not something
//! to warn about.
//!
//! JOB TWO, emit the link directives the archive needs. A Rust staticlib does
//! not record its own dynamic dependencies, so they have to be named; for
//! this crate that is libidn2 and nothing else. Everything the finished
//! executable needs on top -- SSL, cryptography, compression, LDAP, threads,
//! the dynamic loader and the math library -- belongs on the link line in
//! GNUmakefile and scripts/, never here, because a directive emitted from a
//! build script is imposed on every consumer of the archive rather than on
//! the one link that actually needs it.
//!
//! JOB THREE, under the optional `genheader` feature only, regenerate
//! include/curl_urlapi_rs.h from the crate, so the committed mirror header
//! cannot drift away from the code it describes.
//!
//! Directive spelling: every directive below is emitted through one helper,
//! `cargo()`, and every one uses the legacy single-colon `cargo:` prefix.
//! The two spellings are never mixed. The modern `cargo::` form would be the
//! obvious choice on the pinned stable toolchain, but it is not available
//! here, and the reason is worth recording because it is not obvious:
//!
//! ```text
//! error: the `cargo::` syntax for build script output instructions was
//! added in Rust 1.77.0, but the minimum supported Rust version of
//! `curl-urlapi-rs v0.1.0` is 1.75.
//! ```
//!
//! Cargo compares the syntax against the package's own declared minimum, not
//! against the toolchain in use, so `rust-version = "1.75"` in Cargo.toml --
//! which is the minimum the technical specification declares and which is
//! deliberately not raised -- makes the double-colon form a hard error even
//! under a far newer Cargo. The single-colon form is accepted for every
//! directive used here, `rustc-check-cfg` included.

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The pkg-config module name of the C internationalised-domain library, and
/// the name the linker knows it by. lib/idn.c:33 includes <idn2.h> and calls
/// into this same library; binding it directly rather than substituting a
/// reimplementation is what makes bit-for-bit parity attainable, libidn2's
/// locale sensitivity included.
const LIBIDN2_MODULE: &str = "libidn2";
const LIBIDN2_LINK_NAME: &str = "idn2";

/// The oldest libidn2 this port claims parity against. lib/idn.c gates
/// IDN2_NONTRANSITIONAL on IDN2_VERSION_NUMBER >= 0x00140000 and checks the
/// runtime version with idn2_check_version(IDN2_VERSION), so an older
/// library quietly changes which flags reach idn2_lookup_ul() and what it
/// does with them. The reference measurements behind the parity claim were
/// taken against the 2.3 series.
const LIBIDN2_MIN_VERSION: &str = "2.0.0";

fn main() {
    let crate_dir = manifest_dir();

    // Which files this script's behaviour depends on. Emitting any rerun-if
    // directive replaces Cargo's default "re-run whenever anything in the
    // package changed", so the set has to be complete rather than
    // illustrative: cbindgen.toml is the generator configuration, and
    // src/ffi.rs and src/abi.rs hold the exported surface and the ABI
    // constants that the mirror header describes. build.rs itself needs no
    // entry, because changing it recompiles the script and a recompiled
    // script always re-runs.
    for relative in ["cbindgen.toml", "src/ffi.rs", "src/abi.rs"] {
        rerun_if_changed(&crate_dir.join(relative));
    }

    let idn_libidn2 = feature("IDN_LIBIDN2");
    let idn_pure = feature("IDN_PURE");
    let strerror = feature("STRERROR");
    let cfree = feature("CFREE");
    let scheme_table = feature("SCHEME_TABLE");
    let genheader = feature("GENHEADER");
    let capi = feature("CAPI");

    // Cargo features are additive by design, so a caller can ask for both
    // backends at once and the manifest cannot forbid it. Refuse the
    // combination here, exactly as lib/curl_setup.h:726-728 refuses
    // USE_LIBIDN2 alongside USE_WIN32_IDN or USE_APPLE_IDN: a hard build
    // failure, not a silent precedence rule. Quietly picking a winner would
    // leave it ambiguous which backend a parity run had actually measured,
    // and parity is claimed for one of them only. src/idn.rs rejects the
    // same pair at compile time, so the check survives a build that somehow
    // bypasses this script.
    if idn_libidn2 && idn_pure {
        panic!(
            "curl-urlapi-rs: the \"idn-libidn2\" and \"idn-pure\" features \
             are mutually exclusive; choose exactly one. \"idn-libidn2\" \
             binds the C library that lib/idn.c calls and is the only \
             backend the bit-for-bit parity claim covers, while \
             \"idn-pure\" substitutes the pure-Rust idna crate and diverges \
             as recorded in docs/KNOWN-DIVERGENCES.md. Either drop \
             \"idn-pure\", or select it with --no-default-features and add \
             back only the other features you need. This mirrors the \
             #error at lib/curl_setup.h:726-728."
        );
    }

    // Declare every custom cfg this script can emit, unconditionally and
    // whether or not it is then set. Testing a cfg that was never declared
    // makes rustc report the `unexpected_cfgs` lint, and this crate is held
    // to zero warnings; a cfg that is declared but not set is exactly how
    // src/idn.rs is meant to find the backend it was not built with.
    for name in ["have_idn", "idn_backend_libidn2", "idn_backend_pure"] {
        cargo(&format!("rustc-check-cfg=cfg({name})"));
    }

    // The two levels of the C gate, kept two levels apart.
    if idn_libidn2 || idn_pure {
        cargo("rustc-cfg=have_idn");
    }
    if idn_libidn2 {
        cargo("rustc-cfg=idn_backend_libidn2");
        link_libidn2();
    }
    if idn_pure {
        // Nothing to link: the backend is the pure-Rust idna crate, which
        // Cargo already resolves through the feature's dep:idna entry.
        cargo("rustc-cfg=idn_backend_pure");
    }

    #[cfg(feature = "genheader")]
    mirror_header::generate(&crate_dir);

    // A record of the configuration, in the build script's own captured
    // output at target/<profile>/build/curl-urlapi-rs-*/output. This is what
    // the remaining feature reads are for, and it is what makes the drop-in
    // configuration auditable after the fact: Mode A is
    // strerror/cfree/scheme-table all off, because libcurl already defines
    // curl_url_strerror(), curl_free() and Curl_get_scheme(), and Mode B is
    // all three on. `capi` distinguishes a `cargo cbuild` packaging run,
    // which a plain `cargo build` never switches on.
    note(&format!(
        "configuration: idn-libidn2={} idn-pure={} strerror={} cfree={} \
         scheme-table={} genheader={} capi={}",
        onoff(idn_libidn2),
        onoff(idn_pure),
        onoff(strerror),
        onoff(cfree),
        onoff(scheme_table),
        onoff(genheader),
        onoff(capi)
    ));
}

/// Emit one Cargo build-script directive.
///
/// The single-colon spelling is used here, and it is the only spelling this
/// script uses. See the note at the top of the file: the modern `cargo::`
/// form is rejected outright while Cargo.toml declares
/// `rust-version = "1.75"`, so this is not a stylistic choice.
fn cargo(directive: &str) {
    println!("cargo:{directive}");
}

/// Record an informational line in the build script's captured output. It
/// deliberately does not start with "cargo:", so Cargo keeps it as a note
/// instead of parsing it: an unrecognised `cargo::` line is a hard error.
fn note(message: &str) {
    println!("curl-urlapi-rs: {message}");
}

/// Emit a warning Cargo shows to whoever started the build. Reserved for
/// something a person can act on, so that it stays worth reading.
fn warn(message: &str) {
    cargo(&format!("warning={message}"));
}

/// Whether a Cargo feature is enabled, registering the script to re-run when
/// that changes.
///
/// Cargo upper-cases the feature name and turns every hyphen into an
/// underscore, so `scheme-table` arrives as CARGO_FEATURE_SCHEME_TABLE, and
/// it sets the variable only when the feature is on -- presence is the test,
/// not the value.
fn feature(name: &str) -> bool {
    let variable = format!("CARGO_FEATURE_{name}");
    cargo(&format!("rerun-if-env-changed={variable}"));
    env::var_os(&variable).is_some()
}

/// Render a flag for the configuration record.
fn onoff(enabled: bool) -> &'static str {
    if enabled {
        "on"
    } else {
        "off"
    }
}

/// The crate directory, which is where every path this script touches is
/// rooted. Nothing above it is ever read or written.
fn manifest_dir() -> PathBuf {
    PathBuf::from(cargo_env("CARGO_MANIFEST_DIR"))
}

/// Emit a rerun-if-changed directive for one absolute path.
fn rerun_if_changed(path: &Path) {
    cargo(&format!("rerun-if-changed={}", path.display()));
}

/// Read one of the variables Cargo always sets for a build script, and
/// register the script to re-run when it changes.
///
/// A missing variable means the script was not run by Cargo at all, which no
/// amount of defaulting can repair, so it fails with an actionable message
/// rather than with an unwrap.
fn cargo_env(name: &str) -> String {
    cargo(&format!("rerun-if-env-changed={name}"));
    match env::var(name) {
        Ok(value) => value,
        Err(_) => panic!(
            "curl-urlapi-rs: {name} is unset or is not valid UTF-8. Cargo \
             always sets it for a build script, so this script was not run \
             by Cargo. Build the crate with `cargo build` from the \
             rust-urlapi directory."
        ),
    }
}

/// Emit what is needed to link against the C internationalised-domain
/// library, and say something useful when it cannot be found.
///
/// Discovery is preferred to a hard-coded path, so pkg-config is asked where
/// the library lives. It is asked only for a host build: pkg-config reports
/// the host's own directories, which are the wrong answer for a cross build,
/// where the cross toolchain's own search path is the right one.
///
/// The link request itself is emitted whatever discovery concluded, because a
/// library sitting in the linker's default path with no .pc file installed
/// still links perfectly well. An absent library therefore degrades to a
/// warning naming it and how to install it, followed by a plain linker error
/// later, rather than to an obscure failure inside this script.
///
/// One consumer beyond the linker reads this directive: cargo-c copies it
/// into the Libs.private field of the pkg-config file it generates on the
/// `capi` path, so a C program built against that file inherits the same
/// dependency without having to know about it.
fn link_libidn2() {
    let host = cargo_env("HOST");
    let target = cargo_env("TARGET");

    if host == target {
        let tool = pkg_config_tool();
        match pkg_config(&tool, &["--exists", LIBIDN2_MODULE]) {
            None => note(&format!(
                "{tool} could not be run; relying on the linker's default \
                 search path for {LIBIDN2_MODULE}"
            )),
            Some(probe) if !probe.status.success() => warn(&format!(
                "{tool} cannot find {LIBIDN2_MODULE}. Install it (the Debian \
                 and Ubuntu package is libidn2-dev), or point \
                 PKG_CONFIG_PATH at its .pc file, or the link fails with \
                 `cannot find -l{LIBIDN2_LINK_NAME}`."
            )),
            Some(_) => describe_libidn2(&tool),
        }
    } else {
        note(&format!(
            "cross build ({host} to {target}); skipping the pkg-config \
             query for {LIBIDN2_MODULE}"
        ));
    }

    cargo(&format!("rustc-link-lib={LIBIDN2_LINK_NAME}"));
}

/// Record which libidn2 was found and emit its search directories.
fn describe_libidn2(tool: &str) {
    // The version floor is expressed as a module constraint rather than as
    // the dedicated version option, because pkg-config accepts both and this
    // form reads the way the requirement is stated. Existence has already
    // been established at this point, so a failure here means the library is
    // present but too old.
    let constraint = format!("{LIBIDN2_MODULE} >= {LIBIDN2_MIN_VERSION}");
    if !pkg_config_ok(tool, &["--exists", &constraint]) {
        warn(&format!(
            "the installed {LIBIDN2_MODULE} is older than \
             {LIBIDN2_MIN_VERSION}. lib/idn.c gates IDN2_NONTRANSITIONAL on \
             IDN2_VERSION_NUMBER >= 0x00140000 and checks the runtime \
             version with idn2_check_version(), so an older library changes \
             which flags reach the lookup and parity with the C \
             implementation is not claimed for it."
        ));
    }

    let modversion = pkg_config_value(tool, &["--modversion", LIBIDN2_MODULE]);
    if let Some(version) = modversion {
        note(&format!("{LIBIDN2_MODULE} {version} found by {tool}"));
    }

    // An empty -L list is the common case rather than a failure: a library
    // installed in the linker's default path needs no search directory of
    // its own, and libidn2 2.3.8 on a Debian-derived host reports exactly
    // nothing here.
    let search = pkg_config_value(tool, &["--libs-only-L", LIBIDN2_MODULE]);
    if let Some(flags) = search {
        for directory in flags
            .split_whitespace()
            .filter_map(|flag| flag.strip_prefix("-L"))
            .filter(|directory| !directory.is_empty())
        {
            cargo(&format!("rustc-link-search=native={directory}"));
        }
    }
}

/// The pkg-config program to run. PKG_CONFIG is the conventional way to name
/// a different one -- a cross build's <triple>-pkg-config, for instance -- so
/// it is honoured rather than hard-coding the name.
fn pkg_config_tool() -> String {
    cargo("rerun-if-env-changed=PKG_CONFIG");
    match env::var("PKG_CONFIG") {
        Ok(tool) if !tool.trim().is_empty() => tool,
        _ => String::from("pkg-config"),
    }
}

/// Run the pkg-config tool and capture its output, or return None when the
/// tool itself could not be executed at all. A missing pkg-config and an
/// unknown module are different problems that deserve different diagnostics,
/// which is why they are not collapsed into one boolean here. Both output
/// streams are captured so that pkg-config's own messages cannot masquerade
/// as this script's.
fn pkg_config(tool: &str, arguments: &[&str]) -> Option<Output> {
    Command::new(tool).args(arguments).output().ok()
}

/// Whether a pkg-config query succeeded.
fn pkg_config_ok(tool: &str, arguments: &[&str]) -> bool {
    matches!(pkg_config(tool, arguments), Some(o) if o.status.success())
}

/// The trimmed standard output of a successful pkg-config query, or None when
/// the query failed or had nothing to say.
fn pkg_config_value(tool: &str, arguments: &[&str]) -> Option<String> {
    let output = pkg_config(tool, arguments)?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Regeneration of the committed mirror header, compiled only when the
/// `genheader` feature is on.
///
/// The module boundary is what keeps the cbindgen import, and the two std
/// imports only this path needs, out of an ordinary build. That is the whole
/// point of cbindgen being an optional build-dependency: with the feature off
/// it is not built at all, and a plain `cargo build` therefore depends on no
/// code generator.
#[cfg(feature = "genheader")]
mod mirror_header {
    use std::fs;
    use std::io::ErrorKind;
    use std::path::Path;

    /// The mirror header, one directory down from the crate root. It mirrors
    /// include/curl/urlapi.h:34-149 and is a wholly separate file with a
    /// different name, directory and include guard, so it can neither shadow
    /// the real header nor be shadowed by it.
    const MIRROR_HEADER: &str = "curl_urlapi_rs.h";

    /// Regenerate include/curl_urlapi_rs.h from this crate.
    ///
    /// The output lands in the source tree rather than in OUT_DIR, which is
    /// the conventional destination for anything a build script produces, and
    /// that is deliberate: the mirror header is a *committed* artifact that
    /// standalone C consumers include by path, so it has to be where they
    /// look for it rather than buried in a build directory. Nothing outside
    /// this crate directory is written; include/curl/urlapi.h in particular
    /// is read-only and is never generated over, moved or shadowed.
    ///
    /// The write is idempotent and byte-stable. The bytes are produced in
    /// memory and compared with what is already on disk, and the file is
    /// touched only when they differ, so regenerating an unchanged crate
    /// leaves `git status` clean instead of dirtying the working tree on
    /// every build. When they do differ the file is rewritten and a warning
    /// points at it, because that difference is precisely the drift this
    /// feature exists to surface -- and because some of it is expected: five
    /// differences from the hand-authored header are cbindgen limitations
    /// rather than real drift, and cbindgen.toml and
    /// docs/KNOWN-DIVERGENCES.md both record them.
    pub fn generate(crate_dir: &Path) {
        // cbindgen parses the whole crate, so on this path the entire source
        // directory is an input -- wider than the three files an ordinary
        // build watches.
        super::rerun_if_changed(&crate_dir.join("src"));

        let config_path = crate_dir.join("cbindgen.toml");
        let header_path = crate_dir.join("include").join(MIRROR_HEADER);

        // Every configuration struct in cbindgen 0.29.4 denies unknown
        // fields, so a misspelled key here is a parse error rather than a
        // silently ignored line. Report the file it came from, since the
        // message alone does not.
        let config = match cbindgen::Config::from_file(&config_path) {
            Ok(config) => config,
            Err(error) => panic!(
                "curl-urlapi-rs: could not read {}: {error}",
                config_path.display()
            ),
        };

        let bindings = match cbindgen::Builder::new()
            .with_crate(crate_dir)
            .with_config(config)
            .generate()
        {
            Ok(bindings) => bindings,
            Err(error) => panic!(
                "curl-urlapi-rs: cbindgen could not generate the mirror \
                 header from this crate: {error}"
            ),
        };

        let mut generated = Vec::new();
        bindings.write(&mut generated);

        // A missing header is an ordinary first run; anything else going
        // wrong while reading it is not, and must not be mistaken for one.
        let existing = match fs::read(&header_path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(error) => panic!(
                "curl-urlapi-rs: could not read {}: {error}",
                header_path.display()
            ),
        };

        if existing.as_deref() == Some(generated.as_slice()) {
            super::note(&format!(
                "{} already matches the generated mirror; not rewritten",
                header_path.display()
            ));
            return;
        }

        if existing.is_some() {
            super::warn(&format!(
                "{} differed from the generated mirror and has been \
                 rewritten. Review the diff before committing: some \
                 differences are cbindgen limitations recorded in \
                 docs/KNOWN-DIVERGENCES.md rather than drift.",
                header_path.display()
            ));
        } else {
            super::note(&format!(
                "{} did not exist and has been generated",
                header_path.display()
            ));
        }

        if let Some(parent) = header_path.parent() {
            if let Err(error) = fs::create_dir_all(parent) {
                panic!(
                    "curl-urlapi-rs: could not create {}: {error}",
                    parent.display()
                );
            }
        }
        if let Err(error) = fs::write(&header_path, &generated) {
            panic!(
                "curl-urlapi-rs: could not write {}: {error}",
                header_path.display()
            );
        }
    }
}
