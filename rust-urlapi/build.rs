// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Build script for curl-urlapi-rs, the Rust re-implementation of curl's URL
//! API.
//!
//! It has exactly three jobs and deliberately no others. There is no URL
//! parsing here and no raw-pointer or FFI code of any kind; all of that is
//! confined to src/ffi.rs.
//!
//! What it touches outside this directory is worth stating, because "a build
//! script that reads nothing" would be the easier claim and it would be
//! false. It READS the installed libidn2 header, wherever pkg-config or the
//! IDN2_INCLUDE_ROOTS search below locates it, because the two version
//! constants lib/idn.c compares against live there and nothing else carries
//! them. It WRITES only OUT_DIR, the one directory Cargo gives a build script
//! to own, and under the off-by-default `genheader` feature that is where the
//! regenerated mirror header lands. It never writes into the source tree, and
//! `mirror_header::generate` below records why that has to stay true.
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
//! Three further conditions belong to the same job, and each is decided the
//! way the C decides it rather than by a Rust-side approximation of it:
//!
//! ```text
//! idn2.h:119,130            IDN2_VERSION, IDN2_VERSION_NUMBER
//!                           =>  CURL_URLAPI_IDN2_VERSION{,_NUMBER}
//! lib/idn.c:254             #if IDN2_VERSION_NUMBER >= 0x00140000
//!                           =>  cfg(idn2_nontransitional)
//! lib/idn.c:35              #if defined(_WIN32) && defined(UNICODE)
//!                           =>  cfg(windows) && cfg(win32_unicode)
//! CMakeLists.txt:1654-1655  HAVE_INET_PTON, HAVE_INET_NTOP
//!                           =>  cfg(have_inet_pton), cfg(have_inet_ntop)
//! ```
//!
//! The first two are read out of the installed `<idn2.h>` -- the same header
//! lib/idn.c:33 includes -- because the C's two decisions are made from its
//! constants and from nothing else, and a hard-coded pair would describe some
//! other installation. The third has no Rust counterpart for its second half,
//! `UNICODE` being a macro a C build defines, so it comes from an environment
//! variable whose default matches a default curl build. The fourth is a
//! compile-and-link probe per symbol, one for each, because nothing ties the
//! two answers together. [`idn2_header`], [`export_idn2_version`],
//! [`emit_win32_unicode`] and [`probe_address_conversions`] each set out their
//! own reasoning.
//!
//! JOB TWO, emit the link directives the archive needs. A Rust staticlib does
//! not record its own dynamic dependencies, so they have to be named; for
//! this crate that is libidn2 and nothing else. Everything the finished
//! executable needs on top -- SSL, cryptography, compression, LDAP, threads,
//! the dynamic loader and the math library -- belongs on the link line of
//! whoever links the executable, never here, because a directive emitted from
//! a build script is imposed on every consumer of the archive rather than on
//! the one link that actually needs it. GNUmakefile and scripts/ are to carry
//! those link lines; neither exists yet, so today they are written by hand.
//!
//! JOB THREE, under the optional `genheader` feature only, generate an ABI
//! mirror of include/curl_urlapi_rs.h from the crate and check the committed
//! header against it, so that header cannot drift away from the code it
//! describes. It is done through cbindgen's library API --
//! `cbindgen::Config::from_file` and `cbindgen::Builder` -- which Cargo.toml
//! declares as an optional build dependency with `default-features = false`.
//! Dropping cbindgen's defaults is what keeps that dependency affordable: the
//! defaults build its command-line front end and pull in clap and the whole
//! terminal-styling chain behind it, twelve packages this script never calls
//! into. With them off, the closure is 33 packages whose highest declared
//! `rust-version` is cbindgen's own 1.74, so an off-by-default generator does
//! not raise the 1.75 minimum of the code it generates from. Measured against
//! the committed Cargo.lock, not assumed. The mirror_header module below sets
//! out the mechanics, and the abi submodule inside it the comparison.
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
use std::fs;
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
///
/// Security: the heap-overflow fixed in libidn2 2.2.0, CVE-2019-12290,
/// affects the 2.0 and 2.1 series, which reach the very entry points this
/// crate calls. Accepting them would be accepting a known-vulnerable
/// provider, so the floor sits above the fix and a provider below it is a
/// hard configuration failure rather than a warning.
///
/// The version this crate then *requires at run time* is not this floor. It
/// is the exact version of the provider selected here, discovered below and
/// emitted as CURL_URLAPI_RS_IDN2_VERSION, which is what makes
/// src/idn.rs's idn2_check_version() call mean what lib/idn.c:252 means by
/// IDN2_VERSION: "at least as new as what I was built against".
const LIBIDN2_MIN_VERSION: &str = "2.2.0";

/// The Cargo release that stabilised the `rustc-check-cfg` build-script
/// directive, 1.80.0. An earlier Cargo answers the directive with a warning
/// per name and passes nothing to rustc, so the directive is emitted only
/// from this release onwards. See the call site for why the distinction is
/// worth making at all.
const CHECK_CFG_SINCE: (u32, u32, u32) = (1, 80, 0);

/// The header lib/idn.c:33 includes, and the file the two version constants
/// have to be read from. See [`idn2_header`] for why reading it is not
/// optional.
const IDN2_HEADER: &str = "idn2.h";

/// Where to look for that header once the explicit answers and pkg-config have
/// been exhausted. These are the roots a system package manager installs into
/// on the platforms this crate is built on, and pkg-config reports no `-I` for
/// the first of them precisely because it is already on the default search
/// path.
const IDN2_INCLUDE_ROOTS: &[&str] = &[
    "/usr/include",
    "/usr/local/include",
    "/opt/homebrew/include",
    "/usr/local/opt/libidn2/include",
];

/// The release that introduced `IDN2_NONTRANSITIONAL`, 0.20.0, in the packed
/// form `IDN2_VERSION_NUMBER` uses. This is the literal lib/idn.c:254 compares
/// against, reproduced rather than reinterpreted.
const IDN2_NONTRANSITIONAL_SINCE: u32 = 0x0014_0000;

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
    //
    // The directive was stabilised in Cargo 1.80, and an older Cargo answers
    // it with one "rustc-check-cfg requires -Zcheck-cfg flag" warning per
    // name -- seven warnings on exactly the toolchain Cargo.toml declares as
    // this crate's floor, which is the one configuration where a clean build
    // matters most. Skipping the directive there costs nothing, because that
    // Cargo passes no --check-cfg to rustc, so the lint it guards against
    // cannot fire.
    if cargo_supports_check_cfg() {
        for name in [
            "have_idn",
            "idn_backend_libidn2",
            "idn_backend_pure",
            "idn2_nontransitional",
            "win32_unicode",
            "have_inet_pton",
            "have_inet_ntop",
            "curl_bool_int",
            "curl_bool_enum",
        ] {
            cargo(&format!("rustc-check-cfg=cfg({name})"));
        }
    }

    probe_address_conversions();
    emit_curl_bool_abi();

    // The two levels of the C gate, kept two levels apart.
    if idn_libidn2 || idn_pure {
        cargo("rustc-cfg=have_idn");
    }
    if idn_libidn2 {
        cargo("rustc-cfg=idn_backend_libidn2");
        link_libidn2();
        export_idn2_version(&idn2_header());
        emit_win32_unicode();
    }
    // Drop-in mode reads libcurl's own scheme descriptors through a mirrored
    // structure, so the precondition that mirror rests on is checked rather
    // than assumed. The standalone table describes no C structure at all.
    if !scheme_table {
        check_scheme_layout_precondition(&crate_dir);
    }

    if idn_pure {
        // Nothing to link: the backend is the pure-Rust idna crate, which
        // Cargo already resolves through the feature's dep:idna entry.
        cargo("rustc-cfg=idn_backend_pure");
        announce_idn_pure_posture();
    }

    #[cfg(feature = "genheader")]
    mirror_header::generate(&crate_dir);

    // The drop-in artifact. Off unless asked for, because it post-processes a
    // finished archive and there is none during an ordinary build; see
    // `localize_dropin_archive` for why that means a second invocation.
    if let Some(archive) = env_path("CURL_URLAPI_DROPIN_ARCHIVE") {
        localize_dropin_archive(&archive, strerror, cfree);
    } else {
        // Registered even when unset, so that setting it re-runs this script
        // rather than being ignored because nothing else changed.
        cargo("rerun-if-env-changed=CURL_URLAPI_DROPIN_ARCHIVE");
    }

    // A record of the configuration, in the build script's own captured
    // output at target/<profile>/build/curl-urlapi-rs-*/output. This is what
    // the remaining feature reads are for, and it is what makes the drop-in
    // configuration auditable after the fact: Mode A is
    // strerror/cfree/scheme-table all off, because libcurl already defines
    // curl_url_strerror(), curl_free() and Curl_get_scheme(), and Mode B is
    // all three on.
    note(&format!(
        "configuration: idn-libidn2={} idn-pure={} strerror={} cfree={} \
         scheme-table={} genheader={}",
        onoff(idn_libidn2),
        onoff(idn_pure),
        onoff(strerror),
        onoff(cfree),
        onoff(scheme_table),
        onoff(genheader)
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
    println!("curl-urlapi-rs: {}", sanitize(message));
}

/// Emit a warning Cargo shows to whoever started the build. Reserved for
/// something a person can act on, so that it stays worth reading.
fn warn(message: &str) {
    cargo(&format!("warning={}", sanitize(message)));
}

/// Strip control characters from a diagnostic before it is printed.
///
/// Both diagnostic helpers above interpolate values this script did not
/// choose: PKG_CONFIG, pkg-config's own `--modversion` output, and the two
/// paths in the mirror-header check. Cargo parses the build script's standard
/// output line by line, and `warn` writes through the `cargo:warning=` prefix,
/// so a newline inside an interpolated value ends the warning and lets
/// whatever follows be read as a fresh directive -- an arbitrary
/// `rustc-link-arg`, for instance. A carriage return is nearly as bad for a
/// different reason: it can overwrite the line a reader has already seen.
///
/// This crosses no privilege boundary. Anyone able to set PKG_CONFIG can
/// already set RUSTFLAGS, CC or PATH and does not need this route. It is
/// filtered because a diagnostic should not be a control channel, not because
/// there is an attack to stop.
///
/// Every control character becomes a space rather than being deleted, so that
/// the message keeps its shape and a reader can see something was there.
/// Nothing else is touched: the printable text, non-ASCII included, is passed
/// through unchanged so that a path or a version string still reads as
/// itself. The correct handling at `describe_libidn2` is left as it is --
/// `split_whitespace` there provably drops newlines before any directive is
/// built from the pieces, which is the far more exposed path and is already
/// safe by construction.
fn sanitize(message: &str) -> String {
    message
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
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

/// Probe for the platform's `inet_pton` and `inet_ntop`, **separately**, and
/// emit one cfg for each.
///
/// This is the Rust spelling of two independent configure checks, and their
/// independence is the point. curl gates the two conversions on two different
/// macros, `HAVE_INET_PTON` at lib/curlx/inet_pton.h:28 and `HAVE_INET_NTOP`
/// at lib/curlx/inet_ntop.h:28, each of which selects between the platform's
/// function and curl's own Vixie-derived copy in that file. CMake decides
/// them with one `check_symbol_exists` per symbol, at CMakeLists.txt:1654 and
/// :1655, and nothing ties the two answers together: a platform may offer
/// either, both or neither. Collapsing them into a single condition -- a
/// target family, say -- would be a third policy that is neither of curl's.
///
/// The probe is a compile-and-link test, which is what the two configure
/// checks are: the symbol must be declared by the platform's own headers and
/// must resolve at link time. A failure therefore means "absent", exactly as
/// it does for configure, and the corresponding cfg is simply not emitted, so
/// src/inet.rs compiles curl's fallback for that one conversion.
///
/// # When there is no compiler
///
/// A build of a Rust crate does not otherwise need a C toolchain, and this
/// crate deliberately declares no `cc` build-dependency, so the probe has to
/// cope with finding none. That case is distinguished from a failed probe:
/// a compiler that cannot be executed at all leaves the answer unknown, and
/// unknown falls back to [`address_conversions_assumed`], with a note
/// recording that the assumption was used rather than a measurement.
fn probe_address_conversions() {
    let compiler = probe_compiler();
    for (symbol, flag) in [
        ("inet_pton", "have_inet_pton"),
        ("inet_ntop", "have_inet_ntop"),
    ] {
        let present = match compiler.as_deref() {
            Some(tool) => probe_symbol(tool, symbol),
            None => None,
        };
        let present = match present {
            Some(found) => found,
            None => {
                let assumed = address_conversions_assumed();
                note(&format!(
                    "could not probe for {symbol}; assuming it is {} on this \
                     target. Set CC to a working compiler to measure it \
                     instead.",
                    if assumed { "present" } else { "absent" }
                ));
                assumed
            }
        };
        if present {
            cargo(&format!("rustc-cfg={flag}"));
        } else {
            note(&format!(
                "{symbol} not found; src/inet.rs compiles curl's own \
                 implementation from lib/curlx/, which is the same choice the \
                 C build makes when its HAVE_ macro is undefined"
            ));
        }
    }
}

/// Whether to assume the platform pair exists when it cannot be measured.
///
/// Every target curl's own CI builds and that defines both macros is either a
/// Unix or a Windows target, so those are assumed present and everything else
/// absent. The assumption is conservative in the direction that matters: a
/// wrong "absent" compiles curl's own implementation, which is a documented
/// behavioural difference in two inputs recorded in src/inet.rs, whereas a
/// wrong "present" would fail to link.
fn address_conversions_assumed() -> bool {
    let family = env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default();
    family
        .split(',')
        .any(|name| name == "unix" || name == "windows")
}

/// The C compiler to probe with, honouring the conventional variables.
///
/// The per-target spellings come first, because a cross build sets those and
/// leaves CC pointing at the host's compiler; the order matches what the
/// wider ecosystem does with these names.
fn probe_compiler() -> Option<String> {
    let target = cargo_env("TARGET");
    let per_target = format!("CC_{}", target.replace('-', "_"));
    for name in [per_target.as_str(), "TARGET_CC", "CC"] {
        cargo(&format!("rerun-if-env-changed={name}"));
        if let Ok(value) = env::var(name) {
            if !value.trim().is_empty() {
                return Some(value);
            }
        }
    }
    Some(String::from("cc"))
}

/// Compile and link a program that needs `symbol`, and report what happened.
///
/// `Some(true)` when it built, `Some(false)` when the compiler ran and
/// rejected it, and `None` when the compiler could not be executed at all.
/// The distinction is what lets the caller tell "absent" from "unknown".
///
/// Taking the symbol's address is what forces both halves of the check: the
/// expression needs a declaration to compile and needs the definition to
/// link, which together are what `HAVE_INET_PTON` asserts.
fn probe_symbol(compiler: &str, symbol: &str) -> Option<bool> {
    let out_dir = PathBuf::from(cargo_env("OUT_DIR"));
    let source = out_dir.join(format!("probe_{symbol}.c"));
    let binary = out_dir.join(format!("probe_{symbol}.out"));
    let program = format!(
        "#ifdef _WIN32\n\
         #include <winsock2.h>\n\
         #include <ws2tcpip.h>\n\
         #else\n\
         #include <sys/types.h>\n\
         #include <sys/socket.h>\n\
         #include <netinet/in.h>\n\
         #include <arpa/inet.h>\n\
         #endif\n\
         int main(void)\n\
         {{\n\
           const void *probe = (const void *)&{symbol};\n\
           return probe == 0;\n\
         }}\n"
    );
    if std::fs::write(&source, program).is_err() {
        return None;
    }
    let outcome = Command::new(compiler)
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output();
    let status = match outcome {
        Ok(output) => output.status.success(),
        // The compiler itself could not be run, which is not the same as the
        // symbol being absent.
        Err(_) => return None,
    };
    // The artifacts are scratch; a failure to remove them is not a build
    // failure, so the results are deliberately discarded.
    let _ = std::fs::remove_file(&source);
    let _ = std::fs::remove_file(&binary);
    Some(status)
}

/// Locate the installed `<idn2.h>`, the header `lib/idn.c:33` includes.
///
/// Finding it is a requirement rather than a nicety, because two of the C
/// code's decisions are made from constants that header defines and from
/// nothing else: the version handed to `idn2_check_version()` at
/// lib/idn.c:252, and the `#if IDN2_VERSION_NUMBER >= 0x00140000` at
/// lib/idn.c:254 that decides whether `IDN2_NONTRANSITIONAL` is part of the
/// flag word. A hard-coded pair of values would answer both questions about
/// some other installation.
///
/// The search order puts the explicit answers first:
///
/// 1. `CURL_URLAPI_IDN2_H`, a full path to the header.
/// 2. `LIBIDN2_INCLUDE_DIR`, a directory that contains it.
/// 3. The `-I` directories pkg-config reports for the module, on a host build.
/// 4. The conventional include roots.
///
/// # Cross builds
///
/// Step 3 is skipped for a cross build, because pkg-config reports the host's
/// directories, and step 4 then reads the host's header. That is a real risk
/// -- a host at 2.3.8 and a target at 2.0.5 disagree about the flag word --
/// so it warns and names the override rather than doing it silently. Step 1 or
/// 2 avoids the guess entirely.
///
/// # Panics
///
/// When no header is found anywhere. libidn2 was asked for explicitly, by a
/// Cargo feature, and it cannot be honoured without its header; the C build
/// reaches the same conclusion through `HAVE_IDN2_H`, which
/// lib/curl_setup.h:720-724 requires before it will define `USE_LIBIDN2`. The
/// difference is only in what "not honoured" means: the C quietly builds
/// without internationalised-domain support, while an explicit feature request
/// here is a configuration error worth reporting.
fn idn2_header() -> PathBuf {
    if let Some(path) = env_path("CURL_URLAPI_IDN2_H") {
        if path.is_file() {
            return path;
        }
        panic!(
            "curl-urlapi-rs: CURL_URLAPI_IDN2_H is set to {} but that is not \
             a readable file. Point it at the {IDN2_HEADER} of the libidn2 \
             the crate will be linked against, or unset it to let this script \
             search.",
            path.display()
        );
    }

    let mut roots: Vec<PathBuf> = Vec::new();
    if let Some(directory) = env_path("LIBIDN2_INCLUDE_DIR") {
        roots.push(directory);
    }

    let host = cargo_env("HOST");
    let target = cargo_env("TARGET");
    let cross = host != target;
    if !cross {
        let tool = pkg_config_tool();
        if let Some(flags) = pkg_config_value(&tool, &["--cflags-only-I", LIBIDN2_MODULE]) {
            for directory in flags
                .split_whitespace()
                .filter_map(|flag| flag.strip_prefix("-I"))
                .filter(|directory| !directory.is_empty())
            {
                roots.push(PathBuf::from(directory));
            }
        }
    }

    // The conventional roots, which is where a library installed by a system
    // package manager puts its headers and where pkg-config reports no -I at
    // all: libidn2 2.3.8 on a Debian-derived host is exactly that case.
    for directory in IDN2_INCLUDE_ROOTS {
        roots.push(PathBuf::from(directory));
    }

    for root in &roots {
        let candidate = root.join(IDN2_HEADER);
        if candidate.is_file() {
            if cross && env_path("LIBIDN2_INCLUDE_DIR").is_none() {
                warn(&format!(
                    "cross build ({host} to {target}) is reading {} for the \
                     IDN2_VERSION and IDN2_VERSION_NUMBER constants. Those \
                     are the host's, and lib/idn.c:252-254 decides the \
                     version guard and the IDN2_NONTRANSITIONAL flag from \
                     them, so set CURL_URLAPI_IDN2_H or LIBIDN2_INCLUDE_DIR \
                     to the target's header instead.",
                    candidate.display()
                ));
            }
            return candidate;
        }
    }

    panic!(
        "curl-urlapi-rs: the \"idn-libidn2\" feature is enabled but \
         {IDN2_HEADER} was not found. It is needed for the IDN2_VERSION and \
         IDN2_VERSION_NUMBER constants that lib/idn.c:252-254 decides the \
         version guard and the flag word from, and no substitute for them is \
         correct. Install the library's development package (the Debian and \
         Ubuntu one is libidn2-dev), or set LIBIDN2_INCLUDE_DIR to the \
         directory holding {IDN2_HEADER}, or CURL_URLAPI_IDN2_H to the header \
         itself. Searched: {}. To build with no internationalised-domain \
         support at all, drop the feature: --no-default-features.",
        roots
            .iter()
            .map(|root| root.join(IDN2_HEADER).display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
}

/// Export the two version constants the C reads from `<idn2.h>`, and with them
/// the preprocessor decision they drive.
///
/// Three things leave this function, and the split between them is the point.
///
/// * `CURL_URLAPI_IDN2_VERSION` carries the version **string**, which
///   src/idn.rs hands to `idn2_check_version()` exactly as lib/idn.c:252 hands
///   it `IDN2_VERSION`. The guard's question is "is the runtime library at
///   least as new as the header this was compiled against", and it can only be
///   asked with the header's own answer.
/// * `CURL_URLAPI_IDN2_VERSION_NUMBER` carries the packed number, normalised
///   to eight hexadecimal digits. Nothing in the crate branches on it -- the
///   cfg below is what does -- but it is what makes the branch auditable, and
///   src/idn.rs asserts the two agree.
/// * `idn2_nontransitional` is the cfg standing in for
///   `#if IDN2_VERSION_NUMBER >= 0x00140000` at lib/idn.c:254. Evaluating the
///   comparison here, at build time, against the installed header is precisely
///   what the C preprocessor does; passing the number into Rust and comparing
///   it there would be a run-time test of a compile-time fact.
///
/// # Panics
///
/// When either macro is absent from the header, or the number cannot be read.
/// Both are documented parts of libidn2's public header
/// (`# define IDN2_VERSION "2.3.8"` and
/// `# define IDN2_VERSION_NUMBER 0x02030008` in 2.3.8), so their absence means
/// the file found is not that header, which is worth saying plainly rather
/// than defaulting around.
fn export_idn2_version(header: &Path) {
    // The constants change when the header changes, so the script has to run
    // again when it does.
    rerun_if_changed(header);

    let text = match std::fs::read_to_string(header) {
        Ok(text) => text,
        Err(error) => panic!(
            "curl-urlapi-rs: {} could not be read ({error}). It is needed for \
             the IDN2_VERSION and IDN2_VERSION_NUMBER constants.",
            header.display()
        ),
    };

    let version = match define_value(&text, "IDN2_VERSION") {
        Some(value) => unquote(&value).unwrap_or(value),
        None => panic!(
            "curl-urlapi-rs: {} defines no IDN2_VERSION, so it is not \
             libidn2's own header. Point CURL_URLAPI_IDN2_H at that header.",
            header.display()
        ),
    };
    let number_text = match define_value(&text, "IDN2_VERSION_NUMBER") {
        Some(value) => value,
        None => panic!(
            "curl-urlapi-rs: {} defines no IDN2_VERSION_NUMBER, so it is not \
             libidn2's own header. Point CURL_URLAPI_IDN2_H at that header.",
            header.display()
        ),
    };
    let number = match parse_c_integer(&number_text) {
        Some(number) => number,
        None => panic!(
            "curl-urlapi-rs: {} defines IDN2_VERSION_NUMBER as {number_text}, \
             which is not an integer this script can read. libidn2 writes it \
             as a hexadecimal literal, 0x02030008 in 2.3.8.",
            header.display()
        ),
    };

    // The security floor, checked against the version this artifact will
    // actually compile against rather than against a guess. Below it the
    // provider carries known vulnerabilities in the very entry points this
    // crate calls, so the configuration is refused rather than warned about.
    require_libidn2_floor(&version);

    cargo(&format!("rustc-env=CURL_URLAPI_IDN2_VERSION={version}"));
    cargo(&format!(
        "rustc-env=CURL_URLAPI_IDN2_VERSION_NUMBER=0x{number:08x}"
    ));

    // lib/idn.c:254. The literal is the C's own, not a rounded version of it:
    // 0x00140000 is libidn2 0.20.0, the release that introduced the flag.
    if number >= IDN2_NONTRANSITIONAL_SINCE {
        cargo("rustc-cfg=idn2_nontransitional");
    }

    note(&format!(
        "{} reports IDN2_VERSION {version} and IDN2_VERSION_NUMBER \
         0x{number:08x}; IDN2_NONTRANSITIONAL is {}",
        header.display(),
        if number >= IDN2_NONTRANSITIONAL_SINCE {
            "part of the flag word"
        } else {
            "not available"
        }
    ));
}

/// Emit the cfg that stands in for the C condition selecting the
/// byte-oriented lookup entry point.
///
/// lib/idn.c:35-41 is one two-part condition:
///
/// ```text
/// #if defined(_WIN32) && defined(UNICODE)
/// #define IDN2_LOOKUP(name, host, flags) idn2_lookup_u8(...)
/// #else
/// #define IDN2_LOOKUP(name, host, flags) idn2_lookup_ul(...)
/// #endif
/// ```
///
/// `_WIN32` is `cfg(windows)` and needs nothing from here. `UNICODE` has no
/// Rust counterpart at all: it is a macro curl's own build defines for its
/// wide-character variant and leaves undefined otherwise, so the answer has to
/// come from whoever is building. `CURL_URLAPI_WIN32_UNICODE` is that answer,
/// and the default -- unset, so `idn2_lookup_ul` -- is the default a curl
/// build has too.
///
/// Getting it wrong is not a link failure, which is why it is worth being
/// explicit about: both entry points exist in every libidn2. It is a
/// behavioural difference, and a subtle one. `idn2_lookup_ul` reads its input
/// in the encoding of the process locale and fails on non-ASCII input where
/// that encoding is not UTF-8; `idn2_lookup_u8` reads UTF-8 unconditionally
/// and has no locale sensitivity at all. Choosing the byte-oriented arm on a
/// build whose C half chose the locale-aware one would make the Rust succeed
/// where the C fails.
///
/// The cfg is emitted only for the libidn2 backend, which is the only reader,
/// and only for a Windows target, so that a value left set in an environment
/// cannot quietly change a Unix build.
fn emit_win32_unicode() {
    let requested = env_flag("CURL_URLAPI_WIN32_UNICODE");
    let windows = env::var("CARGO_CFG_TARGET_FAMILY")
        .unwrap_or_default()
        .split(',')
        .any(|name| name == "windows");

    if requested && windows {
        cargo("rustc-cfg=win32_unicode");
        note(
            "CURL_URLAPI_WIN32_UNICODE is set, so src/idn.rs takes the \
             idn2_lookup_u8 arm of lib/idn.c:35-41, as a UNICODE build of curl \
             does",
        );
    } else if requested {
        warn(
            "CURL_URLAPI_WIN32_UNICODE is set but the target is not Windows. \
             It stands in for the UNICODE macro in \
             `#if defined(_WIN32) && defined(UNICODE)` at lib/idn.c:35, so it \
             has no meaning here and is ignored.",
        );
    }
}

/// Emit the cfg that selects the C representation of curl's `bool`.
///
/// Two of the eight exported symbols take a `bool` parameter:
/// `Curl_is_absolute_url(url, buf, buflen, bool guess_scheme)` at
/// lib/urlapi.c:182-183 and `Curl_junkscan(url, urllen, bool allowspace)` at
/// L223. `bool` there is whatever `lib/curl_setup.h` made it, and it made it
/// one of three different things:
///
/// * `_Bool`, when `HAVE_STDBOOL_H` and `HAVE_BOOL_T` are both defined and
///   L848-L850 includes `<stdbool.h>`. One byte holding 0 or 1.
/// * `int`, from `typedef int bool` at L1007-L1012, taken on HP-UX when
///   `HAVE_BOOL_T` is absent.
/// * an enumeration, from `typedef enum { bool_false, bool_true } bool` at
///   L1020-L1024, taken on any other pre-C99 platform. A C enumeration whose
///   enumerators are all non-negative is `unsigned int` on the System V ABI
///   and `int` under MSVC; either way it is int-width, which is the property
///   the calling convention acts on.
///
/// The first is the overwhelmingly common case and is the default here, so an
/// ordinary build needs to set nothing. The other two exist because curl
/// supports them, and getting the choice wrong is not a link error: it is a
/// silent argument-width mismatch, so the callee reads whichever bits the
/// register or stack slot happens to hold beyond the byte it expected.
///
/// `CURL_URLAPI_CURL_BOOL` is how whoever is building says which one their
/// libcurl has, the same way `CURL_URLAPI_WIN32_UNICODE` stands in for a
/// macro Rust cannot see. Accepted values, case-insensitively and ignoring
/// surrounding space: `_Bool`, `bool` and `stdbool` for the first; `int` for
/// the second; `enum` for the third. Anything else is a hard error rather
/// than a silent fallback to the default, because a misspelling that quietly
/// selected the default would be exactly the mismatch this exists to prevent.
fn emit_curl_bool_abi() {
    let requested = match env_string("CURL_URLAPI_CURL_BOOL") {
        Some(value) => value,
        None => return,
    };

    match requested.to_ascii_lowercase().as_str() {
        "_bool" | "bool" | "stdbool" => note(
            "CURL_URLAPI_CURL_BOOL selects the _Bool representation of \
             lib/curl_setup.h:848-850, which is also the default",
        ),
        "int" => {
            cargo("rustc-cfg=curl_bool_int");
            note(
                "CURL_URLAPI_CURL_BOOL selects the `typedef int bool` \
                 representation of lib/curl_setup.h:1007-1012, so \
                 Curl_is_absolute_url and Curl_junkscan take a C int",
            );
        }
        "enum" => {
            cargo("rustc-cfg=curl_bool_enum");
            note(
                "CURL_URLAPI_CURL_BOOL selects the enumerated representation \
                 of lib/curl_setup.h:1020-1024, so Curl_is_absolute_url and \
                 Curl_junkscan take an int-width enumeration",
            );
        }
        other => panic!(
            "curl-urlapi-rs: CURL_URLAPI_CURL_BOOL is \"{other}\", which is \
             not one of the three representations lib/curl_setup.h can give \
             curl's `bool`. Use \"_Bool\" for the <stdbool.h> case at \
             lib/curl_setup.h:848-850, \"int\" for `typedef int bool` at \
             L1007-L1012, or \"enum\" for the enumeration at L1020-L1024. \
             Leave the variable unset for \"_Bool\", which is what every \
             platform with a C99 library selects."
        ),
    }
}

/// Read an environment variable as a trimmed string, registering the re-run.
///
/// Set-but-empty counts as unset, so a build system that always exports the
/// variable can leave it blank to mean "the default".
fn env_string(name: &str) -> Option<String> {
    cargo(&format!("rerun-if-env-changed={name}"));
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => Some(value.trim().to_owned()),
        _ => None,
    }
}

/// The complete set of global symbols the drop-in archive must define.
///
/// Not a selection and not a minimum: this is the whole set, and
/// [`localize_dropin_archive`] fails on anything missing from it and on
/// anything else being present. It was read off the object file this crate
/// replaces rather than recalled --
/// `ar x libcurl.a urlapi.c.o && nm -g --defined-only urlapi.c.o` -- and it is
/// eight names, not the six the public header declares.
///
/// The five public ones are declared at `include/curl/urlapi.h`:L113, L120,
/// L126, L133-L134 and L141-L142. The three `Curl_`-prefixed ones are declared
/// at `lib/urlapi-int.h`:L28-L33, an internal header, and real code inside
/// libcurl calls every one of them: `Curl_is_absolute_url` from `lib/http1.c`
/// L220, `lib/url.c` L1661 and `lib/http.c` L1177; `Curl_junkscan` from
/// `lib/doh.c` L1127; `Curl_url_set_authority` from `lib/http2.c` L739. An
/// archive exporting only the five public ones cannot replace `urlapi.c.o` in a
/// full libcurl link, which is why they are here.
///
/// Two names are deliberately absent and are added by
/// [`localize_dropin_archive`] only when their feature is on, because neither
/// is in `urlapi.c.o`: `curl_url_strerror` is defined at
/// `lib/strerror.c`:L420-L531 and `curl_free` at `lib/escape.c`:L189-L192, both
/// out of scope, so exporting either in drop-in mode would give the link a
/// duplicate definition.
const DROPIN_SYMBOLS: [&str; 8] = [
    "Curl_is_absolute_url",
    "Curl_junkscan",
    "Curl_url_set_authority",
    "curl_url",
    "curl_url_cleanup",
    "curl_url_dup",
    "curl_url_get",
    "curl_url_set",
];

/// Turn the Rust staticlib into the drop-in artifact: one relocatable object
/// whose only global symbols are the ones the C object file exported.
///
/// # The problem this solves
///
/// `crate-type = ["staticlib"]` produces an archive containing this crate's
/// code together with the whole of the Rust standard library, the allocator and
/// the unwinder, and every one of those carries global symbols. Measured on the
/// release build of this crate: **2413** distinct defined globals where
/// `urlapi.c.o` defines **8**. That is not a defect in the archive -- it is
/// what a staticlib is -- but it does not satisfy the Agent Action Plan's G1,
/// "exporting the complete symbol set that `lib/urlapi.o` exports and no
/// more", or its acceptance criterion A2.
///
/// # The mechanism
///
/// Three steps, and the plan already holds the technique in reserve at 0.3.2
/// for build systems that will not take an archive:
///
/// 1. `ld -r --whole-archive <archive> -o <whole>.o` links every member into
///    one relocatable object. `--whole-archive` matters: without it `ld` pulls
///    only the members something references, and nothing references anything
///    yet.
/// 2. `objcopy --keep-global-symbol=<name> ...` localizes every global except
///    the named ones. Localizing rather than deleting is the point -- the code
///    and its internal cross-references stay intact, they simply stop being
///    visible to a linker outside this object.
/// 3. `ar rcs <output> <object>` re-archives it, so the result drops into a
///    link line wherever the original archive did.
///
/// Then the check: `nm -g --defined-only` over the result must yield exactly
/// the expected set. Any name missing, and the drop-in cannot satisfy its
/// callers; any name extra, and it can collide with libcurl. Either fails.
///
/// # Why an environment variable rather than an ordinary build step
///
/// Cargo has no post-build hook. A build script runs *before* the crate is
/// compiled, so the archive it must post-process does not exist yet during the
/// build that produces it. The step is therefore an explicit second
/// invocation, run with the same feature flags as the build that produced the
/// archive so that the expected symbol set matches what was actually compiled:
///
/// ```text
/// cargo build --release --no-default-features --features idn-libidn2
/// CURL_URLAPI_DROPIN_ARCHIVE=target/release/libcurl_urlapi_rs.a \
///   cargo build --release --no-default-features --features idn-libidn2
/// ```
///
/// It is deterministic -- the same archive and the same feature set always
/// produce the same output and the same verdict -- and it writes only where it
/// is told, defaulting to a sibling of the input named
/// `libcurl_urlapi_rs_dropin.a`. `CURL_URLAPI_DROPIN_OUTPUT` overrides the
/// destination; `LD`, `OBJCOPY`, `AR` and `NM` override the tools, which is
/// what a cross build needs.
fn localize_dropin_archive(archive: &Path, strerror: bool, cfree: bool) {
    rerun_if_changed(archive);

    // The expected set follows the feature flags, because the two
    // standalone-only exports are real exports when their feature is on. A
    // localization pass run with different flags than the build it
    // post-processes is a mistake, and the comparison below is what catches
    // it: the symbol would show up as unexpected or as missing.
    let mut expected: Vec<String> = DROPIN_SYMBOLS.iter().map(|s| (*s).to_owned()).collect();
    if strerror {
        expected.push("curl_url_strerror".to_owned());
    }
    if cfree {
        expected.push("curl_free".to_owned());
    }
    expected.sort();

    if !archive.is_file() {
        panic!(
            "curl-urlapi-rs: CURL_URLAPI_DROPIN_ARCHIVE names {}, which is \
             not a file. Point it at the staticlib a finished build produced, \
             for example target/release/libcurl_urlapi_rs.a.",
            archive.display()
        );
    }

    let output = match env_path("CURL_URLAPI_DROPIN_OUTPUT") {
        Some(path) => path,
        None => archive.with_file_name("libcurl_urlapi_rs_dropin.a"),
    };
    if output == archive {
        panic!(
            "curl-urlapi-rs: CURL_URLAPI_DROPIN_OUTPUT and \
             CURL_URLAPI_DROPIN_ARCHIVE both name {}. The input archive is \
             never overwritten; choose a different destination.",
            output.display()
        );
    }

    let scratch = PathBuf::from(cargo_env("OUT_DIR")).join("curl_urlapi_rs_whole.o");
    let localized = PathBuf::from(cargo_env("OUT_DIR")).join("curl_urlapi_rs_dropin.o");

    // Step 1.
    run_tool(
        &tool("LD", "ld"),
        &[
            "-r".as_ref(),
            "--whole-archive".as_ref(),
            archive.as_os_str(),
            "-o".as_ref(),
            scratch.as_os_str(),
        ],
        "combine the archive into one relocatable object",
    );

    // Step 2.
    let mut arguments: Vec<std::ffi::OsString> = expected
        .iter()
        .map(|name| std::ffi::OsString::from(format!("--keep-global-symbol={name}")))
        .collect();
    arguments.push(scratch.clone().into_os_string());
    arguments.push(localized.clone().into_os_string());
    let arguments: Vec<&std::ffi::OsStr> = arguments.iter().map(AsRef::as_ref).collect();
    run_tool(
        &tool("OBJCOPY", "objcopy"),
        &arguments,
        "localize every symbol outside the drop-in ABI",
    );

    // Step 3. `ar` appends to an existing archive, so a stale output would
    // silently accumulate members; remove it first and let a genuine removal
    // failure surface as the `ar` failure it becomes.
    let _ = fs::remove_file(&output);
    run_tool(
        &tool("AR", "ar"),
        &["rcs".as_ref(), output.as_os_str(), localized.as_os_str()],
        "archive the localized object",
    );

    // The check. Both the object and the archive are inspected: the archive is
    // the artifact a link line names, and a difference between the two would
    // mean `ar` had put something else in it.
    let defined = defined_globals(&output);
    let missing: Vec<&String> = expected.iter().filter(|n| !defined.contains(*n)).collect();
    let unexpected: Vec<&String> = defined.iter().filter(|n| !expected.contains(n)).collect();
    if !missing.is_empty() || !unexpected.is_empty() {
        panic!(
            "curl-urlapi-rs: the drop-in archive {} does not define exactly \
             the expected symbol set. Expected {} names, found {}. Missing: \
             {:?}. Unexpected: {:?}. A missing name breaks the callers inside \
             libcurl; an unexpected one can collide with a definition libcurl \
             already has, which is why both are failures. If the unexpected \
             name is curl_url_strerror or curl_free, this pass was run with \
             different feature flags than the build that produced the \
             archive.",
            output.display(),
            expected.len(),
            defined.len(),
            missing,
            unexpected
        );
    }

    note(&format!(
        "drop-in archive {} defines exactly the {} expected global symbols: {}",
        output.display(),
        expected.len(),
        expected.join(" ")
    ));
}

/// The name of a binutils tool, overridable by the conventional variable.
fn tool(variable: &str, fallback: &str) -> String {
    match env_path(variable) {
        Some(path) => path.to_string_lossy().into_owned(),
        None => fallback.to_owned(),
    }
}

/// Run one tool, or fail the build saying which one and why it was being run.
fn run_tool(program: &str, arguments: &[&std::ffi::OsStr], purpose: &str) {
    let outcome = Command::new(program).args(arguments).output();
    let output = match outcome {
        Ok(output) => output,
        Err(error) => panic!(
            "curl-urlapi-rs: could not run {program} to {purpose}: {error}. \
             The drop-in archive needs GNU binutils; ld, objcopy, ar and nm \
             are overridable through the LD, OBJCOPY, AR and NM variables."
        ),
    };
    if !output.status.success() {
        panic!(
            "curl-urlapi-rs: {program} failed to {purpose}: {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
}

/// The sorted, deduplicated names `nm -g --defined-only` reports for a file.
///
/// The output format is `<value> <type> <name>` for a defined symbol, with
/// archive-member banner lines and blank lines in between, so a line is a
/// symbol only when it has three fields.
fn defined_globals(path: &Path) -> Vec<String> {
    let program = tool("NM", "nm");
    let outcome = Command::new(&program)
        .arg("-g")
        .arg("--defined-only")
        .arg(path)
        .output();
    let output = match outcome {
        Ok(output) if output.status.success() => output,
        Ok(output) => panic!(
            "curl-urlapi-rs: {program} failed to list the symbols of {}: {}\n{}",
            path.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(error) => panic!(
            "curl-urlapi-rs: could not run {program} to verify {}: {error}",
            path.display()
        ),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut names: Vec<String> = text
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            match fields.as_slice() {
                [_value, _kind, name] => Some((*name).to_owned()),
                _ => None,
            }
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Read an environment variable as a path, registering the re-run.
fn env_path(name: &str) -> Option<PathBuf> {
    cargo(&format!("rerun-if-env-changed={name}"));
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => Some(PathBuf::from(value.trim())),
        _ => None,
    }
}

/// Read an environment variable as a flag, registering the re-run.
///
/// Set-but-empty and the literal `0` both count as off, so that a build system
/// that always exports the variable can turn it off by value.
fn env_flag(name: &str) -> bool {
    cargo(&format!("rerun-if-env-changed={name}"));
    match env::var(name) {
        Ok(value) => {
            let value = value.trim();
            !value.is_empty() && value != "0"
        }
        Err(_) => false,
    }
}

/// The value of the first `#define <name> <value>` in a C header's text.
///
/// Deliberately small rather than a preprocessor: the two macros wanted here
/// are plain object-like defines of a literal, and libidn2 writes them one per
/// line. The leading `#` may be followed by spaces before `define`, which is
/// exactly how libidn2 2.3.8 writes them (`# define IDN2_VERSION "2.3.8"`), so
/// that form is handled. A trailing comment is trimmed, and the name must be
/// followed by whitespace so that `IDN2_VERSION` does not match
/// `IDN2_VERSION_NUMBER`.
fn define_value(text: &str, name: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix('#') else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix("define") else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix(name) else {
            continue;
        };
        // A macro name is one token: whatever follows it has to be
        // whitespace, or this is a longer name that merely starts the same way.
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        let value = match rest.find("/*") {
            Some(at) => rest.get(..at).unwrap_or(rest),
            None => rest,
        };
        let value = match value.find("//") {
            Some(at) => value.get(..at).unwrap_or(value),
            None => value,
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        return Some(value.to_owned());
    }
    None
}

/// Strip one pair of surrounding double quotes, if there is one.
fn unquote(value: &str) -> Option<String> {
    let inner = value.strip_prefix('"')?.strip_suffix('"')?;
    Some(inner.to_owned())
}

/// Read a C integer literal: hexadecimal with the `0x` prefix, or decimal.
///
/// Any `u`, `U`, `l` or `L` suffix is dropped, because C allows them and a
/// header is free to write one.
fn parse_c_integer(value: &str) -> Option<u32> {
    let value = value.trim().trim_end_matches(['u', 'U', 'l', 'L']);
    match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(digits) => u32::from_str_radix(digits, 16).ok(),
        None => value.parse::<u32>().ok(),
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

/// Check the one C-side precondition of the drop-in scheme mirror.
///
/// In drop-in mode the crate declares Curl_get_scheme() and reads three fields
/// of the descriptor it returns through a #[repr(C)] mirror of struct
/// Curl_scheme, lib/urldata.h:515-524. AAP 0.4.2.4 mandates exactly that. The
/// mirror itself lives in src/ffi.rs, with the rest of the crate's foreign
/// work -- the struct is CurlScheme there and its compile-time assertions are
/// the LAYOUT_PROOF block beneath it -- while src/scheme.rs receives an owned
/// copy of the three values and holds no raw pointer at all. Those assertions
/// can only check the Rust shape: no assertion compiled into the crate can
/// read lib/urldata.h, so the width of curl_prot_t is a precondition of the C
/// side rather than a checked property of it.
///
/// It is a load-bearing precondition. curl_prot_t is uint32_t only while
/// PROTO_TYPE_SMALL is defined, lib/urldata.h:81-88; without it the type
/// becomes curl_off_t, the protocol and family fields widen from 4 bytes to 8,
/// and flags and defport -- the two fields this crate actually reads -- shift
/// by eight bytes each. That does not fail to compile. It silently returns
/// another field's bytes as a default port. And it is not hypothetical:
/// lib/urldata.h:71 already defines CURLPROTO_WSS as ((curl_prot_t)1 << 31),
/// so bit 31 is taken and the header is one protocol away from the condition
/// its own comment at L81 describes.
///
/// So the precondition is checked here, against the header of the tree this
/// crate sits in -- which is the tree whose libcurl the drop-in link uses.
/// Reading the header is not the same as compiling it: doing that would need
/// libcurl's private build environment, curl_config.h included, which this
/// crate deliberately does not have. What the text can establish is exactly
/// the condition that decides the width, and that is what is established.
///
/// A header that cannot be found is a note rather than a failure. The crate is
/// buildable outside a curl checkout -- that is what standalone mode is for --
/// and refusing to build there would trade a real capability for a check that
/// has nothing to check.
fn check_scheme_layout_precondition(crate_dir: &Path) {
    // ../lib/urldata.h relative to the crate directory. Nothing is written,
    // and nothing outside the crate is otherwise touched.
    let header = match crate_dir.parent() {
        Some(repository) => repository.join("lib").join("urldata.h"),
        None => {
            note("the crate directory has no parent, so lib/urldata.h cannot be located");
            return;
        }
    };
    rerun_if_changed(&header);

    let text = match fs::read_to_string(&header) {
        Ok(text) => text,
        Err(error) => {
            note(&format!(
                "{} could not be read ({error}), so the 32-bit curl_prot_t \
                 precondition of the drop-in scheme mirror is unverified. It \
                 is recorded in docs/KNOWN-DIVERGENCES.md",
                header.display()
            ));
            return;
        }
    };

    let small = text.lines().map(str::trim).any(|line| {
        line.starts_with("#define") && line.split_whitespace().nth(1) == Some("PROTO_TYPE_SMALL")
    });
    let narrow = text
        .lines()
        .map(str::trim)
        .any(|line| line.starts_with("typedef uint32_t curl_prot_t"));

    if small && narrow {
        note(&format!(
            "{} defines PROTO_TYPE_SMALL and typedefs curl_prot_t as \
             uint32_t, so the struct Curl_scheme mirror in src/ffi.rs has \
             the layout it assumes",
            header.display()
        ));
        return;
    }

    panic!(
        "curl-urlapi-rs: {} no longer satisfies the layout precondition of \
         the drop-in scheme mirror. src/ffi.rs mirrors struct \
         Curl_scheme, lib/urldata.h:515-524, and locates its flags and \
         defport fields after two curl_prot_t members; that is correct only \
         while curl_prot_t is uint32_t, which lib/urldata.h:81-88 makes \
         conditional on PROTO_TYPE_SMALL. This build found PROTO_TYPE_SMALL \
         {} and the uint32_t typedef {}. Widening curl_prot_t shifts both \
         fields by eight bytes and does NOT fail to compile: it silently \
         returns another field's bytes as a scheme's default port. Either \
         widen the two mirrored fields in src/ffi.rs to match, or build \
         with --features scheme-table, which compiles this crate's own table \
         and describes no C structure at all. The precondition is recorded in \
         docs/KNOWN-DIVERGENCES.md.",
        header.display(),
        if small { "defined" } else { "MISSING" },
        if narrow { "present" } else { "MISSING" }
    );
}

/// Fail the configuration when the selected libidn2 is below
/// [`LIBIDN2_MIN_VERSION`].
///
/// A failure rather than a warning, because both reasons the floor exists are
/// reasons not to build: below 2.2.0 the provider carries the
/// CVE-2019-12290 heap overflow in the very entry points this crate calls,
/// and the flag set that reaches those entry points is not the one the parity
/// measurements were taken with. A warning on a build that then links anyway
/// leaves an artifact whose behaviour nobody has measured.
fn require_libidn2_floor(version: &str) {
    let floor = parse_version(LIBIDN2_MIN_VERSION).unwrap_or((2, 2, 0));
    match parse_version(version) {
        Some(_) if at_least(version, floor) => {}
        Some(_) => panic!(
            "curl-urlapi-rs: the selected {LIBIDN2_MODULE} is {version}, \
             which is older than the {LIBIDN2_MIN_VERSION} this crate \
             requires. Two reasons, either of which is enough. The \
             heap-overflow fixed in 2.2.0, CVE-2019-12290, reaches the \
             lookup entry points this crate calls. And lib/idn.c gates \
             IDN2_NONTRANSITIONAL on the compile-time version and checks the \
             runtime one with idn2_check_version(), so an older library \
             changes which flags reach the lookup and parity with the C \
             implementation is not claimed for it. Upgrade libidn2, or build \
             with --no-default-features --features idn-pure and read \
             docs/KNOWN-DIVERGENCES.md first."
        ),
        None => panic!(
            "curl-urlapi-rs: \"{version}\" is not a libidn2 version this \
             script can compare against {LIBIDN2_MIN_VERSION}. A version is \
             one to three dot-separated numbers, for instance 2.3.8. Fix \
             IDN2_VERSION in the installed idn2.h, or install a libidn2 \
             whose header spells its version the usual way."
        ),
    }
}

/// Split a version string into its first three numeric components.
///
/// Anything after a non-numeric character in a component ends the parse of
/// that component, which is how a suffixed version such as `2.3.8-rc1`
/// compares as 2.3.8. A component that is entirely non-numeric makes the
/// whole parse fail, so a malformed override is reported rather than read as
/// zero.
fn parse_version(version: &str) -> Option<(u32, u32, u32)> {
    let mut numbers = [0_u32; 3];
    let mut seen = 0_usize;
    for (index, component) in version.trim().split('.').enumerate() {
        if index >= numbers.len() {
            break;
        }
        let digits: String = component.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            return None;
        }
        let slot = numbers.get_mut(index)?;
        *slot = digits.parse().ok()?;
        seen = index.saturating_add(1);
    }
    if seen == 0 {
        return None;
    }
    let major = *numbers.first()?;
    let minor = *numbers.get(1)?;
    let patch = *numbers.get(2)?;
    Some((major, minor, patch))
}

/// Whether `version` is at least `floor`, comparing component by component.
fn at_least(version: &str, floor: (u32, u32, u32)) -> bool {
    match parse_version(version) {
        Some(parsed) => parsed >= floor,
        None => false,
    }
}

/// Whether the Cargo running this script understands `rustc-check-cfg`.
///
/// Cargo names its own executable in the CARGO variable for exactly this kind
/// of question, so the version comes from asking that binary rather than from
/// the toolchain that happens to be first on PATH -- under `cargo +1.75.0`
/// those are two different programs.
///
/// An indeterminate answer is treated as "supported", and the asymmetry is
/// deliberate. Emitting the directive to a Cargo that does not know it costs
/// an informational warning and nothing else; withholding it from a Cargo
/// that does know it makes rustc report `unexpected_cfgs` for every
/// `#[cfg(have_idn)]` in the crate, which is a real compiler warning against
/// a crate held to zero of them. So the cheaper mistake is the one made when
/// the version cannot be established.
fn cargo_supports_check_cfg() -> bool {
    let tool = match env::var("CARGO") {
        Ok(tool) if !tool.trim().is_empty() => tool,
        // Not run by Cargo, or run by one too old to say who it is. Either
        // way, emit and let the directive speak for itself.
        _ => return true,
    };
    let output = match Command::new(tool).arg("--version").output() {
        Ok(output) if output.status.success() => output,
        _ => return true,
    };
    // "cargo 1.80.0 (376290515 2024-07-16)": the second whitespace-separated
    // word, with anything after the patch number ignored by parse_version().
    let text = String::from_utf8_lossy(&output.stdout);
    match text.split_whitespace().nth(1) {
        Some(version) => at_least(version, CHECK_CFG_SINCE),
        None => true,
    }
}

/// Announce, loudly, that the pure-Rust backend sits outside the parity claim.
///
/// The backend diverges in ways no configuration closes: no transitional
/// retry, locale-independent conversion where `idn2_lookup_ul` is not,
/// different Unicode tables, and allocation through Rust's global allocator,
/// whose failure handler aborts the process where `curl_url_set()` is
/// documented to answer an allocation failure with `CURLUE_OUT_OF_MEMORY`.
///
/// This warns rather than refusing the build. `idn-pure` is one of the six
/// features the manifest offers, so selecting it deliberately is a supported
/// use of the manifest, and making it fail would turn a documented opt-in
/// into a broken one. A `cargo:warning` is shown on every build that selects
/// the backend, which is the loudest signal available short of refusing, and
/// the divergences are catalogued in docs/KNOWN-DIVERGENCES.md.
fn announce_idn_pure_posture() {
    warn(
        "the \"idn-pure\" backend is selected and is NOT covered by the \
         bit-for-bit IDN parity claim: no transitional retry, \
         locale-independent conversion, different Unicode tables, and an \
         allocation failure aborts instead of returning \
         CURLUE_OUT_OF_MEMORY. Use \"idn-libidn2\" for parity runs; every \
         divergence is recorded in docs/KNOWN-DIVERGENCES.md.",
    );
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
/// # Why this links the library rather than driving a program
///
/// cbindgen exists both as a crate and as a command-line tool. This uses the
/// crate, through `cbindgen::Config::from_file` and `cbindgen::Builder`, and
/// Cargo.toml names it under `[build-dependencies]` as
/// `cbindgen = { version = "0.29.4", optional = true, default-features =
/// false }`. Two reasons, in order of weight.
///
/// A build script that shells out to a tool depends on that tool being
/// installed, at the right version, on every machine that ever enables the
/// feature -- and fails late and confusingly when it is not. The library API
/// makes the version a lockfile entry instead, which is the same provenance
/// discipline every other dependency of this crate is held to.
///
/// The usual objection is the minimum toolchain, and `default-features =
/// false` is what answers it. cbindgen's defaults build its command-line front
/// end and drag in clap and the terminal-styling chain behind it -- anstream,
/// anstyle and its siblings, colorchoice, strsim, is_terminal_polyfill,
/// once_cell_polyfill, utf8parse -- twelve packages this script never calls
/// into, and the ones that reach for a newer compiler. With the defaults off
/// the closure is 33 packages and the highest `rust-version` any of them
/// declares is cbindgen's own 1.74, below the 1.75 Cargo.toml declares.
/// Verified against the committed Cargo.lock rather than assumed. So the
/// generator does not decide the minimum toolchain of the code it generates
/// from, which was the requirement all along.
///
/// The module boundary keeps the two std imports only this path needs out of
/// an ordinary build, and with the feature off nothing here is compiled at
/// all, so a plain `cargo build` neither runs nor pulls in a code generator.
#[cfg(feature = "genheader")]
mod mirror_header {
    use std::fs;
    use std::io::ErrorKind;
    use std::path::{Path, PathBuf};

    /// The mirror header, one directory down from the crate root. It mirrors
    /// include/curl/urlapi.h:34-149 and is a wholly separate file with a
    /// different name, directory and include guard, so it can neither shadow
    /// the real header nor be shadowed by it.
    const MIRROR_HEADER: &str = "curl_urlapi_rs.h";

    /// Generate the mirror header into OUT_DIR and fail the build on any
    /// drift from the committed include/curl_urlapi_rs.h.
    ///
    /// # This function does not write into the source tree, and must not
    ///
    /// The generated bytes land in OUT_DIR, which is the only directory a
    /// build script owns. include/curl_urlapi_rs.h is *tracked* and
    /// *hand-authored*, and cbindgen.toml states at its own top that the
    /// committed file stays authoritative; an earlier version of this
    /// function overwrote it, which meant an ordinary
    /// `cargo check --features genheader` destroyed a maintainer's edits with
    /// nothing but a warning to show for it. Two properties of the setup make
    /// that unavoidable rather than unlucky, and they are worth stating so
    /// that nobody restores the write:
    ///
    /// * cbindgen 0.29.4's output can never be byte-equal to the committed
    ///   header. cbindgen.toml records the four shape differences it cannot be
    ///   configured out of -- the `//` comments on the `extern "C"` wrapper
    ///   above all, which are not comments in C89 at all -- so the committed
    ///   header has to be hand-authored to stay C89-clean, and an
    ///   equality-guarded write therefore fires on *every* fresh checkout.
    /// * .gitignore cannot mitigate it, because the file is tracked. There is
    ///   no "ignore my own edits" for a build script.
    ///
    /// # WHY THE CRATE ROOT AND NOT THE CRATE
    ///
    /// The generator is pointed at src/lib.rs with `Builder::with_src`, not at
    /// the crate directory with `Builder::with_crate`. That is not a stylistic
    /// preference; it is what keeps this feature inside the 1.75 floor that
    /// Cargo.toml declares, and it must not be changed back.
    ///
    /// `Builder::generate` in cbindgen 0.29.4 branches on whether a library
    /// directory was supplied. With one, it calls `Cargo::load`, which shells
    /// out to `cargo metadata`; without one it parses the source files given
    /// to it and never invokes Cargo at all.
    ///
    /// `cargo metadata` resolves and parses the *whole* dependency graph,
    /// optional dependencies included, whether or not the current feature set
    /// reaches them. This crate's graph contains idna behind the opt-in
    /// idn-pure feature, and idna pulls idna_adapter, whose manifest declares
    /// edition 2024. Cargo 1.75 cannot parse that edition, so the subprocess
    /// exits non-zero and generation fails before it starts -- on a build that
    /// compiles none of those packages. Source mode never asks the question,
    /// so the optional high-floor graph stays out of the picture entirely.
    ///
    /// Nothing about the emitted bytes changes. Measured with cbindgen 0.29.4
    /// and this cbindgen.toml, `cbindgen --config cbindgen.toml src/lib.rs`
    /// and `cbindgen --config cbindgen.toml .` produce byte-identical output,
    /// because cbindgen's source parser follows the `mod` declarations out of
    /// the crate root and this configuration sets `parse.parse_deps = false`,
    /// so a dependency was never going to contribute a declaration in the
    /// first place. The one thing crate mode adds that source mode does not is
    /// the resolved package version, and nothing in cbindgen.toml asks for it.
    ///
    /// The alternative remedy -- re-pinning the lockfile to an older IDNA and
    /// internationalisation line so that Cargo 1.75 could parse it -- is
    /// deliberately not taken. AAP 0.5.1 records idna 1.1.0 and the
    /// idna_adapter 1.2.2 it resolves to, and 0.5.1.2 records the measured
    /// consequence: the idn-pure configuration's effective floor is 1.86, and
    /// that is a documented, deliberate exception. Changing the lock to work
    /// around a subprocess this function does not need would contradict the
    /// recorded dependency resolution to fix something the call site owns.
    ///
    /// It is also the only shape the check can safely take while
    /// `cargo cinstall` ships the same file as an install asset, per the
    /// `[package.metadata.capi.install.include]` block in Cargo.toml.
    ///
    /// # Why the comparison is semantic and why it is fatal
    ///
    /// Byte equality is unreachable, as above. An earlier version of this
    /// function therefore compared bytes and, on the inevitable difference,
    /// emitted a Cargo warning saying some of the difference was expected.
    /// That made the check worthless as a gate: the baseline output differed
    /// from the committed header by 357 unified-diff lines on a clean
    /// checkout, so a real ABI change produced exactly the same signal as the
    /// known cosmetic delta and nothing distinguished the two.
    ///
    /// So the comparison is made over a *normalized semantic surface* instead
    /// -- see [`surface`] for the model and for every normalization it
    /// applies, each with the proven reason it is cosmetic -- and any
    /// remaining difference panics. Panicking is the point: a build script
    /// panic fails `cargo build`, which is what turns this from a note into a
    /// gate. The committed header is still never written to; the failure says
    /// what differs and the human reconciles it, by changing the Rust items or
    /// this configuration, never by editing include/curl/urlapi.h.
    ///
    /// # What it compares, and what it reports
    ///
    /// * Surfaces equal: a note naming both paths, and a note if the bytes
    ///   happen to be equal too.
    /// * Surfaces different: a panic listing every entry present in one
    ///   surface and absent from the other, in both directions.
    /// * Committed header absent: a note saying where the generated copy is,
    ///   so it can be used as the starting point for the hand-authored file.
    ///   That is an ordinary state before the file has been authored and is
    ///   the one case that is not a failure.
    pub fn generate(crate_dir: &Path) {
        // cbindgen's source parser follows the `mod` declarations out of the
        // crate root, so on this path every file under src/ is an input --
        // wider than the three files an ordinary build watches.
        super::rerun_if_changed(&crate_dir.join("src"));

        let config_path = crate_dir.join("cbindgen.toml");
        let committed = crate_dir.join("include").join(MIRROR_HEADER);
        let generated_path = out_dir().join(MIRROR_HEADER);

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

        // Source mode, not crate mode, and the difference is the whole reason
        // this feature works on the toolchain Cargo.toml declares as the
        // floor. See the "WHY THE CRATE ROOT AND NOT THE CRATE" section of
        // this function's documentation.
        let root = crate_dir.join("src").join("lib.rs");
        let bindings = match cbindgen::Builder::new()
            .with_src(&root)
            .with_config(config)
            .generate()
        {
            Ok(bindings) => bindings,
            Err(error) => panic!(
                "curl-urlapi-rs: cbindgen could not generate the mirror \
                 header from {}: {error}",
                root.display()
            ),
        };

        let mut generated = Vec::new();
        bindings.write(&mut generated);

        // The one write this function performs, and it is inside OUT_DIR.
        // Cargo creates OUT_DIR before running the script, so no directory
        // has to be made here; the write is reported rather than ignored so
        // that a full disk cannot make the comparison below silently vacuous.
        if let Err(error) = fs::write(&generated_path, &generated) {
            panic!(
                "curl-urlapi-rs: could not write {}: {error}",
                generated_path.display()
            );
        }

        // A missing committed header is an ordinary state before it has been
        // authored; anything else going wrong while reading it is not, and
        // must not be mistaken for one.
        let existing = match fs::read(&committed) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(error) => panic!(
                "curl-urlapi-rs: could not read {}: {error}",
                committed.display()
            ),
        };

        let Some(bytes) = existing else {
            super::note(&format!(
                "{} does not exist; the generated mirror is in {} and can be \
                 used as the starting point for it",
                committed.display(),
                generated_path.display()
            ));
            return;
        };

        // Byte equality is not required and is not reachable, but if it ever
        // were reached the semantic comparison below would be vacuous, so say
        // so rather than let the note be misread.
        if bytes == generated {
            super::note(&format!(
                "{} is byte-equal to the generated mirror in {}",
                committed.display(),
                generated_path.display()
            ));
        }

        let committed_surface = surface::extract(&bytes, &committed.display().to_string());
        let generated_surface = surface::extract(&generated, &generated_path.display().to_string());

        // The gate. Anything the two surfaces disagree about is ABI drift by
        // construction: every difference the generator cannot avoid has
        // already been normalized away by `surface::extract`, and each of
        // those normalizations is justified in that module against the shape
        // of the two inputs. A difference surviving it is a real one.
        let missing = difference(&committed_surface, &generated_surface);
        let extra = difference(&generated_surface, &committed_surface);
        if !missing.is_empty() || !extra.is_empty() {
            panic!(
                "curl-urlapi-rs: the public surface of {} does not match the \
                 surface generated from this crate into {}. Nothing was \
                 modified. This is ABI drift, not a cosmetic difference: \
                 every difference cbindgen cannot avoid is normalized away \
                 before this comparison, and the normalizations are listed in \
                 build.rs `mod mirror_header::surface`. Reconcile by changing \
                 the Rust items in src/ffi.rs and src/abi.rs, or cbindgen.toml \
                 -- never by editing include/curl/urlapi.h, which is \
                 read-only.\n\
                 \n\
                 in the committed header but not generated from the crate \
                 ({} entries):\n{}\n\
                 generated from the crate but not in the committed header \
                 ({} entries):\n{}",
                committed.display(),
                generated_path.display(),
                missing.len(),
                bullets(&missing),
                extra.len(),
                bullets(&extra)
            );
        }

        super::note(&format!(
            "{} and the mirror generated into {} describe the same public \
             surface: {} entries, matched entry for entry",
            committed.display(),
            generated_path.display(),
            committed_surface.len()
        ));
    }

    /// Entries of `left` that do not appear in `right`, in `left` order.
    fn difference(left: &[String], right: &[String]) -> Vec<String> {
        left.iter()
            .filter(|entry| !right.contains(entry))
            .cloned()
            .collect()
    }

    /// One entry per line, indented, for a panic message.
    fn bullets(entries: &[String]) -> String {
        if entries.is_empty() {
            return "  (none)".to_string();
        }
        entries
            .iter()
            .map(|entry| format!("  {entry}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The normalized semantic surface of a C header, and nothing else.
    ///
    /// # What a surface is
    ///
    /// A sorted list of canonical one-line entries, exactly four kinds:
    ///
    /// * `const NAME = VALUE` -- one per object-like macro with a value and
    ///   one per enumerator, with the value evaluated to a decimal integer.
    ///   The committed header spells the 33 result codes and the 11 part
    ///   identifiers as C enumerators with implicit numbering and the 16 flags
    ///   as `#define NAME (1 << n)`; the generated header spells all 60 as
    ///   `#define NAME n`. Evaluating both to integers is what makes the two
    ///   spellings comparable, and it is also the only comparison that matters:
    ///   parity for those three sets is *positional*, so the number is the
    ///   contract and the spelling is not.
    /// * `scalar NAME` -- one per `typedef` of an integer type or of an
    ///   enumeration. `typedef enum { .. } CURLUcode;` and
    ///   `typedef int CURLUcode;` both reduce to `scalar CURLUcode`, because a
    ///   C enumeration whose enumerators all fit in `int` is compatible with
    ///   `int` on every platform curl supports, and the enumerators themselves
    ///   are already compared one by one as `const` entries.
    /// * `opaque NAME` -- one per `typedef struct TAG NAME;`. The tag is
    ///   dropped: `include/curl/urlapi.h`:L107 writes the tag `Curl_URL` and
    ///   cbindgen derives it from the Rust item name, but the type is
    ///   incomplete either way and is only ever used through a pointer, which
    ///   is precisely the property that makes this port possible. Nothing a C
    ///   caller can do depends on the tag.
    /// * `fn RET NAME ( P1 , P2 , .. )` -- one per function declaration, with
    ///   the return type and each parameter type tokenized and rejoined so
    ///   that spacing and pointer placement cannot matter.
    ///
    /// Anything that is none of those four -- a stray declaration, an unknown
    /// `typedef`, a valueless macro other than the two named below -- still
    /// becomes an entry, spelled verbatim, so that it cannot slip past the
    /// comparison by not fitting a category.
    ///
    /// # Every normalization, and why each one is cosmetic
    ///
    /// These are the whole list. Each was confirmed against the two actual
    /// inputs rather than assumed, and none of them can hide a change to a
    /// number, a name, a type or an arity.
    ///
    /// 1. **Comments.** `/* .. */` and `// ..` are removed before anything
    ///    else. The committed header carries the licence box, the per-value
    ///    `/* n */` ordinal comments and the descriptive block above each
    ///    declaration; cbindgen emits `/** .. */` doc comments in their place
    ///    and `// __cplusplus` / `// extern "C"` trailers, which are not
    ///    comments in C89 at all. No comment is part of the ABI.
    /// 2. **Whitespace and line breaks.** Collapsed to single spaces. The
    ///    generated header breaks `curl_url_get` and `curl_url_set` across
    ///    four lines each where the committed header uses two.
    /// 3. **The include guard.** `CURLINC_URLAPI_RS_H` is dropped. Both files
    ///    define it, so keeping it would be harmless, but it is not part of
    ///    the surface and dropping it says so.
    /// 4. **`CURL_EXTERN`.** Dropped both as a macro definition and as a
    ///    leading token on a declaration. It is linkage decoration: the
    ///    committed header self-resolves it because a standalone link has no
    ///    libcurl to define it, and cbindgen.toml's `[fn]` section
    ///    deliberately injects no prefix, since an undefined macro in front of
    ///    six declarations would not compile.
    /// 5. **The opaque tag.** As above under `opaque NAME`.
    /// 6. **The enumeration-versus-macro representation.** As above under
    ///    `const` and `scalar`. It is forced: `src/abi.rs` expresses the 60
    ///    values as explicit integer constants rather than as Rust
    ///    enumerations, because a Rust enumeration's discriminants could be
    ///    reordered by a later edit and the C numbering is positional. That is
    ///    the Agent Action Plan's transformation rule T2, so cbindgen has no
    ///    enumeration to emit and cannot be configured into emitting one.
    /// 7. **Parameter names.** Dropped. They are not part of the ABI. Two
    ///    differ and both are deliberate: `curl_url_dup`'s parameter is `in`
    ///    at `include/curl/urlapi.h`:L126, a Rust keyword, so `src/ffi.rs`
    ///    spells it `input`; and `curl_url_strerror`'s is unnamed at L149,
    ///    a cosmetic detail the committed mirror reproduces and Rust cannot.
    ///
    /// Nothing else is normalized. In particular no name, no numeric value, no
    /// return type, no parameter type, no parameter count and no
    /// `const` qualifier is touched, so a change to any of them fails the gate.
    mod surface {
        /// Extract the normalized semantic surface of `header`.
        ///
        /// `origin` names the file, for the panic messages a malformed input
        /// would otherwise make unattributable.
        pub fn extract(header: &[u8], origin: &str) -> Vec<String> {
            // Lossy rather than strict: both inputs are ASCII by
            // construction, and a stray byte must not turn a comparison into
            // a decode error whose message says nothing about the surface.
            let text = String::from_utf8_lossy(header);
            let text = strip_comments(&text);

            let mut entries = Vec::new();
            let mut declarations = String::new();
            for line in text.lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix('#') {
                    if let Some(entry) = macro_entry(rest.trim_start()) {
                        entries.push(entry);
                    }
                    // Every other preprocessor line -- the guard's `#ifndef`
                    // and `#endif`, the `__cplusplus` pair -- is structure
                    // rather than surface.
                    continue;
                }
                declarations.push(' ');
                declarations.push_str(line);
            }

            let (enums, rest) = take_enums(&declarations);
            entries.extend(enums);
            entries.extend(statements(&rest, origin));
            entries.sort();
            entries
        }

        /// Remove `/* .. */` and `// ..` comments, keeping line structure so
        /// that preprocessor lines can still be recognized afterwards.
        fn strip_comments(text: &str) -> String {
            let bytes = text.as_bytes();
            let mut out = String::with_capacity(text.len());
            let mut i = 0;
            while i < bytes.len() {
                let two = bytes.get(i..i.saturating_add(2));
                match two {
                    Some(b"/*") => {
                        // Skip to the closing delimiter, preserving newlines so
                        // that a comment spanning lines cannot glue two
                        // preprocessor lines together.
                        i = i.saturating_add(2);
                        while i < bytes.len() {
                            if bytes.get(i..i.saturating_add(2)) == Some(b"*/") {
                                i = i.saturating_add(2);
                                break;
                            }
                            if bytes.get(i) == Some(&b'\n') {
                                out.push('\n');
                            }
                            i = i.saturating_add(1);
                        }
                    }
                    Some(b"//") => {
                        while i < bytes.len() && bytes.get(i) != Some(&b'\n') {
                            i = i.saturating_add(1);
                        }
                    }
                    _ => {
                        out.push(char::from(bytes.get(i).copied().unwrap_or(b' ')));
                        i = i.saturating_add(1);
                    }
                }
            }
            out
        }

        /// The surface entry, if any, for the body of a preprocessor line.
        fn macro_entry(body: &str) -> Option<String> {
            let rest = body.strip_prefix("define")?;
            if !rest.starts_with(char::is_whitespace) {
                return None;
            }
            let mut parts = rest.trim().splitn(2, char::is_whitespace);
            let name = parts.next().unwrap_or_default().trim();
            if name.is_empty() || name.contains('(') {
                // A function-like macro is not part of this surface and
                // neither input has one; recorded verbatim so that one
                // appearing later cannot pass unnoticed.
                return Some(format!("macro {}", collapse(rest.trim())));
            }
            // Normalization 3 and 4: the include guard and the linkage
            // decoration are structure, not surface.
            if name == "CURLINC_URLAPI_RS_H" || name == "CURL_EXTERN" {
                return None;
            }
            let value = parts.next().unwrap_or_default().trim();
            match evaluate(value) {
                Some(number) => Some(format!("const {name} = {number}")),
                // A valueless or unevaluatable macro is still an entry, so it
                // cannot slip past by not being a number.
                None if value.is_empty() => Some(format!("macro {name}")),
                None => Some(format!("macro {name} = {}", collapse(value))),
            }
        }

        /// Evaluate the integer-constant spellings these two headers use: a
        /// decimal literal, or a left shift of one, either bare or in one
        /// layer of parentheses. Anything else is not a number here.
        fn evaluate(value: &str) -> Option<i64> {
            let value = value.trim();
            let value = value
                .strip_prefix('(')
                .and_then(|inner| inner.strip_suffix(')'))
                .unwrap_or(value)
                .trim();
            if let Some((left, right)) = value.split_once("<<") {
                let left: i64 = left.trim().parse().ok()?;
                let right: u32 = right.trim().parse().ok()?;
                return left.checked_shl(right);
            }
            value.parse().ok()
        }

        /// Pull every `typedef enum { .. } NAME;` out of `text`, returning its
        /// entries and the text with those blocks removed.
        ///
        /// One `scalar NAME` entry per block, plus one `const` entry per
        /// enumerator with C's implicit numbering applied: a bare enumerator
        /// takes the previous value plus one, starting from zero, and an
        /// explicit `= value` resets the sequence. That is normalization 6 in
        /// the module note, and it is what lets the committed header's
        /// enumerations be compared against the generated header's macros.
        fn take_enums(text: &str) -> (Vec<String>, String) {
            let mut entries = Vec::new();
            let mut rest = String::new();
            let mut remainder = text;
            while let Some(start) = remainder.find("typedef enum") {
                let (before, from_start) = remainder.split_at(start);
                rest.push_str(before);
                let Some(open) = from_start.find('{') else {
                    break;
                };
                let Some(close) = from_start.find('}') else {
                    break;
                };
                if close < open {
                    break;
                }
                let body = from_start.get(open.saturating_add(1)..close).unwrap_or("");
                let after = from_start.get(close.saturating_add(1)..).unwrap_or("");
                let Some(semicolon) = after.find(';') else {
                    break;
                };
                let name = collapse(after.get(..semicolon).unwrap_or(""));
                entries.push(format!("scalar {name}"));
                let mut next = 0i64;
                for member in body.split(',') {
                    let member = collapse(member);
                    if member.is_empty() {
                        continue;
                    }
                    let (member, value) = match member.split_once('=') {
                        Some((left, right)) => {
                            (collapse(left), evaluate(right).unwrap_or(i64::MIN))
                        }
                        None => (member, next),
                    };
                    entries.push(format!("const {member} = {value}"));
                    next = value.saturating_add(1);
                }
                remainder = after.get(semicolon.saturating_add(1)..).unwrap_or("");
            }
            rest.push_str(remainder);
            (entries, rest)
        }

        /// One entry per `;`-terminated declaration left in `text`.
        fn statements(text: &str, origin: &str) -> Vec<String> {
            // `extern "C" {` and its closing brace are structure. Removing the
            // opening form by name leaves only bare braces to drop, and no
            // declaration in this surface contains one.
            let text = text.replace("extern \"C\" {", " ");
            let mut entries = Vec::new();
            for statement in text.split(';') {
                let statement = collapse(&statement.replace('}', " "));
                if statement.is_empty() {
                    continue;
                }
                entries.push(match classify(&statement) {
                    Some(entry) => entry,
                    // Not a shape this surface knows. Recorded verbatim and
                    // attributed, so the comparison fails loudly rather than
                    // silently ignoring something new.
                    None => format!("unrecognized in {origin}: {statement}"),
                });
            }
            entries
        }

        /// Classify one collapsed declaration.
        fn classify(statement: &str) -> Option<String> {
            if let Some(rest) = statement.strip_prefix("typedef ") {
                return Some(typedef_entry(rest));
            }
            if statement.contains('(') {
                return function_entry(statement);
            }
            None
        }

        /// `typedef struct TAG NAME` becomes `opaque NAME`; a typedef of an
        /// integer type becomes `scalar NAME`; anything else is kept verbatim.
        fn typedef_entry(rest: &str) -> String {
            let tokens: Vec<&str> = rest.split_whitespace().collect();
            let (Some(first), Some(last)) = (tokens.first(), tokens.last()) else {
                return format!("typedef {rest}");
            };
            if *first == "struct" && tokens.len() == 3 {
                // Normalization 5: the tag is dropped.
                return format!("opaque {last}");
            }
            let integer = tokens
                .get(..tokens.len().saturating_sub(1))
                .unwrap_or_default()
                .iter()
                .all(|token| {
                    matches!(
                        *token,
                        "char" | "short" | "int" | "long" | "signed" | "unsigned"
                    )
                });
            if integer && tokens.len() >= 2 {
                // Normalization 6: `typedef int CURLUcode` and
                // `typedef enum { .. } CURLUcode` are the same scalar.
                return format!("scalar {last}");
            }
            format!("typedef {rest}")
        }

        /// `fn RET NAME ( P1 , P2 , .. )` for one function declaration.
        fn function_entry(statement: &str) -> Option<String> {
            // Normalization 4: the linkage decoration, when the header
            // carries it.
            let statement = statement.strip_prefix("CURL_EXTERN ").unwrap_or(statement);
            let open = statement.find('(')?;
            let close = statement.rfind(')')?;
            if close < open {
                return None;
            }
            let head = statement.get(..open)?.trim();
            let params = statement.get(open.saturating_add(1)..close)?;

            // The declarator's last token is the name, with any `*` of the
            // return type already split off by `tokenize`.
            let head_tokens = tokenize(head);
            let (name, return_type) = head_tokens.split_last()?;
            if name.is_empty() || !is_identifier(name) {
                return None;
            }

            let mut typed = Vec::new();
            for param in params.split(',') {
                typed.push(parameter_type(param));
            }
            Some(format!(
                "fn {} {} ( {} )",
                return_type.join(" "),
                name,
                typed.join(" , ")
            ))
        }

        /// The type of one parameter, with its name removed if it has one.
        ///
        /// Normalization 7. A parameter of two or more tokens whose last token
        /// is a plain identifier that is not a type keyword carries a name,
        /// and the name is dropped. A single-token parameter is a bare type --
        /// `void`, or the unnamed `CURLUcode` of `curl_url_strerror` -- and is
        /// kept whole.
        fn parameter_type(param: &str) -> String {
            let tokens = tokenize(param);
            let keep = match tokens.split_last() {
                Some((last, head)) if !head.is_empty() && is_identifier(last) => head.to_vec(),
                _ => tokens.clone(),
            };
            keep.join(" ")
        }

        /// Split on whitespace, then split every `*` into its own token, so
        /// that `char **part`, `char ** part` and `char * *part` are one
        /// spelling. That is normalization 2 applied to pointers.
        fn tokenize(text: &str) -> Vec<String> {
            let mut tokens = Vec::new();
            for word in text.split_whitespace() {
                let mut current = String::new();
                for character in word.chars() {
                    if character == '*' {
                        if !current.is_empty() {
                            tokens.push(current.clone());
                            current.clear();
                        }
                        tokens.push("*".to_string());
                    } else {
                        current.push(character);
                    }
                }
                if !current.is_empty() {
                    tokens.push(current);
                }
            }
            tokens
        }

        /// True for a C identifier that is not one of the type keywords these
        /// two headers use. Used only to tell a parameter name from a bare
        /// type, never to validate C.
        fn is_identifier(token: &str) -> bool {
            const KEYWORDS: [&str; 12] = [
                "void", "char", "short", "int", "long", "signed", "unsigned", "float", "double",
                "const", "struct", "enum",
            ];
            if KEYWORDS.contains(&token) {
                return false;
            }
            let mut characters = token.chars();
            match characters.next() {
                Some(first) if first.is_ascii_alphabetic() || first == '_' => {
                    characters.all(|c| c.is_ascii_alphanumeric() || c == '_')
                }
                _ => false,
            }
        }

        /// Whitespace runs to single spaces, ends trimmed.
        fn collapse(text: &str) -> String {
            text.split_whitespace().collect::<Vec<_>>().join(" ")
        }
    }

    /// The directory Cargo set aside for this build script's output.
    ///
    /// Read through the same helper the rest of the script uses, so a missing
    /// variable produces the one actionable message rather than an unwrap.
    fn out_dir() -> PathBuf {
        PathBuf::from(super::cargo_env("OUT_DIR"))
    }
}
