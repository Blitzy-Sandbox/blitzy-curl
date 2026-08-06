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
//! regenerated mirror header lands. It writes into the source tree only when
//! `CURL_URLAPI_WRITE_MIRROR_HEADER=1` asks it to install that regenerated
//! header, and `mirror_header::generate` below records why the default is to
//! compare rather than to write.
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
//!                           =>  the same comparison, in a const in
//!                               src/ffi.rs, over the number exported above
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
    // name in the list below -- on exactly the toolchain Cargo.toml declares
    // as this crate's floor, which is the one configuration where a clean
    // build matters most. Skipping the directive there costs nothing, because
    // that Cargo passes no --check-cfg to rustc, so the lint it guards
    // against cannot fire.
    if cargo_supports_check_cfg() {
        for name in [
            "have_idn",
            "idn_backend_libidn2",
            "idn_backend_pure",
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

    // Which artifact each scheme provider is allowed to serve, enforced by
    // the linker rather than asserted in prose.
    emit_shared_artifact_gate(scheme_table);

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
        localize_dropin_archive(&archive, strerror, cfree, scheme_table, idn_libidn2);
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
/// Two things leave this function, and the split between them is the point.
/// Both are read out of the same header, so they cannot describe two different
/// installations.
///
/// * `CURL_URLAPI_IDN2_VERSION` carries the version **string**, which
///   src/ffi.rs hands to `idn2_check_version()` exactly as lib/idn.c:252 hands
///   it `IDN2_VERSION`. The guard's question is "is the runtime library at
///   least as new as the header this was compiled against", and it can only be
///   asked with the header's own answer.
/// * `CURL_URLAPI_IDN2_VERSION_NUMBER` carries the packed number, normalised
///   to eight hexadecimal digits. This is what the crate branches on: src/ffi.rs
///   parses it into a `const` and compares it against `0x00140000` in a `const`
///   too, so `#if IDN2_VERSION_NUMBER >= 0x00140000` at lib/idn.c:254 stays a
///   compile-time test of a compile-time fact, decided from the installed
///   header exactly as the C preprocessor decides it.
///
/// One mechanism, deliberately. The comparison lives next to the flag word it
/// decides, and this script does not also emit a `cfg` standing for the same
/// answer: two switches over one fact are two switches that can disagree, and
/// the one nothing reads is the one that goes stale unnoticed. What this script
/// owes that comparison is the number, and a note recording which way it came
/// out on the machine that built the artifact.
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

    // lib/idn.c:254 is answered by src/ffi.rs, from the number just exported,
    // and not a second time here. What this script owes that comparison is the
    // number itself and a record of which way it came out; the literal below is
    // the C's own, not a rounded version of it: 0x00140000 is libidn2 0.20.0,
    // the release that introduced the flag.
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

/// The symbols the crate imports from libcurl in the drop-in configuration.
///
/// Declared at `lib/url.h` L76-L77, defined at `lib/url.c` L1469-L1541. They
/// must appear as **undefined** in a drop-in archive, because the whole point
/// of that configuration is that libcurl's own table answers every capability
/// question. An archive that lacks these references was built with
/// `scheme-table` on and is not a drop-in artifact, whatever its defined set
/// looks like after localization.
const SCHEME_PROVIDER_SYMBOLS: [&str; 2] = ["Curl_get_scheme", "Curl_getn_scheme"];
/// The libidn2 entry points `lib/idn.c` calls, which the default backend binds
/// directly and which must therefore appear as undefined under that backend
/// and not appear at all under any other.
///
/// The lookup entry point is deliberately absent from this list: `lib/idn.c`
/// L35-L41 chooses between `idn2_lookup_ul` and `idn2_lookup_u8` per platform,
/// so exactly one of the two is expected and
/// [`validate_raw_archive`] checks that separately.
const IDN2_PROVIDER_SYMBOLS: [&str; 3] =
    ["idn2_check_version", "idn2_free", "idn2_to_unicode_8z8z"];

/// The two spellings of the libidn2 lookup entry point, of which a libidn2
/// build imports exactly one. `lib/idn.c` L36-L37 selects the byte-oriented
/// form for Windows with wide characters and L39-L40 the locale-aware form
/// everywhere else.
const IDN2_LOOKUP_SYMBOLS: [&str; 2] = ["idn2_lookup_ul", "idn2_lookup_u8"];

/// Turn the Rust staticlib into the canonical drop-in artifact: one
/// relocatable object whose only global symbols are the ones the C object file
/// exported.
///
/// # The problem this solves
///
/// `crate-type = ["staticlib"]` produces an archive containing this crate's
/// code together with the whole of the Rust standard library, the allocator
/// and the unwinder, and every one of those carries global symbols. The count
/// runs into the thousands where `urlapi.c.o` defines **8**; the measured
/// figure moves with the toolchain, so this pass reports what it actually
/// found rather than repeating a literal that goes stale. That is not a defect
/// in the archive -- it is what a staticlib is -- but it does not satisfy the
/// Agent Action Plan's G1, "exporting the complete symbol set that
/// `lib/urlapi.o` exports and no more", or its acceptance criterion A2.
///
/// # Which artifact is canonical
///
/// **`libcurl_urlapi_rs_dropin.a`, the output of this pass, is the canonical
/// static deliverable.** Cargo's own `libcurl_urlapi_rs.a` is an *input* to
/// it and must never be presented as the drop-in: it fails A2 by thousands of
/// symbols. Everything downstream names the localized archive -- the parity
/// link line, the symbol comparison, and the archive a C consumer is given.
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
/// cargo rustc --release --no-default-features --features idn-libidn2 \
///   --lib --crate-type staticlib
/// CURL_URLAPI_DROPIN_ARCHIVE=target/release/libcurl_urlapi_rs.a \
///   cargo rustc --release --no-default-features --features idn-libidn2 \
///     --lib --crate-type staticlib
/// ```
///
/// It is deterministic -- the same archive and the same feature set always
/// produce the same output and the same verdict -- and it writes only where it
/// is told, defaulting to a sibling of the input named
/// `libcurl_urlapi_rs_dropin.a`. `CURL_URLAPI_DROPIN_OUTPUT` overrides the
/// destination; `LD`, `OBJCOPY`, `AR` and `NM` override the tools, which is
/// what a cross build needs.
///
/// # Why the second invocation cannot certify the wrong archive
///
/// Two invocations are two chances to disagree, and the environment variable
/// names a *path* rather than a build. Nothing stops somebody pointing a
/// drop-in localization at an archive built with different features, or at
/// yesterday's archive, and the first version of this pass would have accepted
/// both: it inspected the result *after* `objcopy`, by which point every
/// surplus global had already been localized away and every archive of the
/// right shape looked identical. A default-feature archive fed to a drop-in
/// invocation was certified as an eight-symbol drop-in artifact.
///
/// [`validate_raw_archive`] closes that by inspecting the **raw input**, and
/// it is deliberately two-sided:
///
/// * **Defined globals.** Every name the requested feature combination
///   implies must be defined, and the two feature-gated exports must be
///   defined if and only if their feature is on. A default-feature archive
///   defines `curl_url_strerror` and `curl_free`, so a drop-in invocation
///   rejects it here -- before `objcopy` can hide the evidence.
/// * **Undefined providers.** Every name the combination implies the archive
///   *imports* must be present as undefined, and every name it implies must be
///   absent must be absent. `Curl_get_scheme` and `Curl_getn_scheme` are
///   imported exactly when `scheme-table` is off; the libidn2 entry points
///   exactly under that backend. This is the direction that catches the
///   `scheme-table` mistake, which is otherwise silent: an archive carrying
///   the built-in table has no such references at all.
///
/// Staleness is a separate question from feature compatibility, and gets a
/// separate check: the archive must be no older than every file it was
/// supposedly built from. Finally the pass records a provenance file beside
/// the canonical artifact, so a certification can be compared with a later one
/// instead of being taken on trust.
///
/// A single orchestrated driver is still the right place for the two steps to
/// live, and `GNUmakefile` plus `scripts/build-rust.sh` are that driver. This
/// function's job is to make the coupling between the steps *checkable* rather
/// than assumed, because a driver can be bypassed and an environment variable
/// invites exactly that.
fn localize_dropin_archive(
    archive: &Path,
    strerror: bool,
    cfree: bool,
    scheme_table: bool,
    idn_libidn2: bool,
) {
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

    // Step 0, and the one that decides whether the rest means anything: prove
    // the raw input was built from this source tree with these features,
    // before `objcopy` gets a chance to make every archive look alike.
    let raw = validate_raw_archive(
        archive,
        &expected,
        strerror,
        cfree,
        scheme_table,
        idn_libidn2,
    );

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

    // The provenance record, beside the canonical artifact so that a later
    // certification can be compared with this one instead of being taken on
    // trust. Deliberately free of timestamps: the same input and the same
    // configuration must produce the same bytes here, or the record is no
    // longer evidence of anything.
    let provenance = format!(
        "curl-urlapi-rs drop-in artifact provenance\n\
         canonical-artifact: {}\n\
         built-from: {}\n\
         raw-content-tag: {:016x}\n\
         raw-defined-globals: {}\n\
         localized-content-tag: {:016x}\n\
         features: strerror={} cfree={} scheme-table={} idn-libidn2={}\n\
         target: {}\n\
         profile: {}\n\
         source-content-tag: {:016x}\n\
         exported-symbols: {}\n\
         imported-providers: {}\n",
        output.display(),
        archive.display(),
        raw.content_tag,
        raw.defined_count,
        content_tag(&output),
        onoff(strerror),
        onoff(cfree),
        onoff(scheme_table),
        onoff(idn_libidn2),
        cargo_env("TARGET"),
        cargo_env("PROFILE"),
        raw.source_tag,
        expected.join(" "),
        raw.providers.join(" ")
    );
    let record = output.with_extension("a.provenance");
    if let Err(error) = fs::write(&record, provenance.as_bytes()) {
        panic!(
            "curl-urlapi-rs: could not write the provenance record {}: \
             {error}. The record is part of the certification, so a failure \
             to write it fails the pass rather than being ignored.",
            record.display()
        );
    }

    note(&format!(
        "canonical drop-in archive {} defines exactly the {} expected global \
         symbols ({}), reduced from {} in the raw input; provenance recorded \
         in {}",
        output.display(),
        expected.len(),
        expected.join(" "),
        raw.defined_count,
        record.display()
    ));
}

/// What [`validate_raw_archive`] establishes about the raw input, carried
/// forward so the provenance record can state it rather than re-deriving it.
struct RawArchiveFacts {
    /// A change detector over the archive's bytes. See [`content_tag`].
    content_tag: u64,
    /// A change detector over the sources the archive was built from.
    source_tag: u64,
    /// How many distinct globals the raw archive defines. Reported rather than
    /// compared against a literal, because the figure moves with the
    /// toolchain.
    defined_count: usize,
    /// The provider symbols the archive was found to import, in the order
    /// checked.
    providers: Vec<String>,
}

/// Prove the raw archive was built from this source tree with these features.
///
/// Every check here is exact rather than probabilistic, and each one names the
/// mistake it exists to catch. The order is deliberate: symbol evidence first,
/// because it is the evidence `objcopy` destroys.
///
/// # Panics
///
/// On any disagreement, with a message naming the archive, the expectation and
/// the likely cause. A build script has no other way to stop a bad artifact
/// from being certified.
fn validate_raw_archive(
    archive: &Path,
    expected: &[String],
    strerror: bool,
    cfree: bool,
    scheme_table: bool,
    idn_libidn2: bool,
) -> RawArchiveFacts {
    let defined = defined_globals(archive);

    // 1. Every name this configuration must export has to be there. A missing
    //    one means the archive is not this crate, or is an older revision of
    //    it that predates the export.
    let missing: Vec<&String> = expected.iter().filter(|n| !defined.contains(*n)).collect();
    if !missing.is_empty() {
        panic!(
            "curl-urlapi-rs: the raw archive {} does not define {:?}, which \
             this feature combination requires. Either the archive is not a \
             build of this crate, or it predates those exports. Rebuild it \
             with the same flags as this invocation before localizing.",
            archive.display(),
            missing
        );
    }

    // 2. The two feature-gated exports have to be present exactly when their
    //    feature is on. THIS is the check that catches a default-feature
    //    archive handed to a drop-in invocation: it defines both, and after
    //    localization it would have looked like a clean eight-symbol drop-in.
    for (name, wanted) in [("curl_url_strerror", strerror), ("curl_free", cfree)] {
        let present = defined.iter().any(|n| n == name);
        if present != wanted {
            panic!(
                "curl-urlapi-rs: the raw archive {} {} {name}, but this \
                 invocation's features say it should {}. The archive was \
                 built with different features than this localization pass \
                 was given, so localizing it would certify the wrong build: \
                 curl_url_strerror comes from the \"strerror\" feature and \
                 curl_free from \"cfree\", and both must be off for a drop-in \
                 artifact because lib/strerror.c and lib/escape.c already \
                 define them. Rebuild the archive with exactly the flags used \
                 here.",
                archive.display(),
                if present {
                    "defines"
                } else {
                    "does not define"
                },
                if wanted { "be defined" } else { "be absent" }
            );
        }
    }

    // 3. No configuration of this crate defines libcurl's scheme lookup, so
    //    finding one means the archive is something else entirely.
    for name in SCHEME_PROVIDER_SYMBOLS {
        if defined.iter().any(|n| n == name) {
            panic!(
                "curl-urlapi-rs: the raw archive {} defines {name}. No \
                 configuration of this crate defines it -- lib/url.c does -- \
                 so this archive is not a build of this crate, and localizing \
                 it would put a duplicate definition on the drop-in link line.",
                archive.display()
            );
        }
    }

    // 4. The undefined side. What an archive imports is the half of its
    //    identity that survives nothing later in this pass, and it is the only
    //    evidence that distinguishes a drop-in build from a standalone one:
    //    the standalone table produces no scheme references at all, which is
    //    why leaving `scheme-table` on in a drop-in build is otherwise silent.
    let undefined = undefined_symbols(archive);
    let mut providers: Vec<String> = Vec::new();

    for name in SCHEME_PROVIDER_SYMBOLS {
        let present = undefined.iter().any(|n| n == name);
        if present != !scheme_table {
            panic!(
                "curl-urlapi-rs: the raw archive {} {} {name} as an undefined \
                 symbol, but this invocation has scheme-table {}. A drop-in \
                 archive MUST import libcurl's scheme lookup, and a \
                 standalone one MUST NOT; an archive built with scheme-table \
                 wrongly on links cleanly against libcurl and then answers \
                 capability questions from its own modelled table instead of \
                 the linked libcurl's, which no later check can detect. \
                 Rebuild the archive with exactly the flags used here.",
                archive.display(),
                if present { "carries" } else { "does not carry" },
                onoff(scheme_table)
            );
        }
        if present {
            providers.push(name.to_owned());
        }
    }

    for name in IDN2_PROVIDER_SYMBOLS {
        let present = undefined.iter().any(|n| n == name);
        if present != idn_libidn2 {
            panic!(
                "curl-urlapi-rs: the raw archive {} {} {name} as an undefined \
                 symbol, but this invocation has idn-libidn2 {}. The default \
                 IDN backend binds libidn2 directly and is the only one the \
                 bit-for-bit parity claim covers, so an archive built with a \
                 different backend must not be certified as this one. \
                 Rebuild the archive with exactly the flags used here.",
                archive.display(),
                if present { "carries" } else { "does not carry" },
                onoff(idn_libidn2)
            );
        }
        if present {
            providers.push(name.to_owned());
        }
    }

    // The lookup entry point is one of two spellings, chosen per platform at
    // lib/idn.c:35-41, so the requirement is "exactly one" rather than a
    // specific name. Neither, under the libidn2 backend, means the lookup path
    // was compiled out; both means two backends were somehow bound at once.
    let lookups: Vec<&str> = IDN2_LOOKUP_SYMBOLS
        .into_iter()
        .filter(|name| undefined.iter().any(|n| n == name))
        .collect();
    let wanted_lookups = usize::from(idn_libidn2);
    if lookups.len() != wanted_lookups {
        panic!(
            "curl-urlapi-rs: the raw archive {} imports {} of the two \
             libidn2 lookup entry points {:?}, and this invocation expects \
             exactly {wanted_lookups}. lib/idn.c:35-41 selects idn2_lookup_u8 \
             for Windows with wide characters and idn2_lookup_ul everywhere \
             else, so exactly one belongs in a libidn2 build and neither in \
             any other. Found: {lookups:?}.",
            archive.display(),
            lookups.len(),
            IDN2_LOOKUP_SYMBOLS
        );
    }
    for name in lookups {
        providers.push(name.to_owned());
    }

    // 5. Staleness, which is a different failure from feature incompatibility
    //    and needs its own check: an archive built from this configuration but
    //    from older sources passes every symbol test above. The comparison is
    //    against the newest input, so a single edited file is enough to fail
    //    it.
    let sources = source_inventory();
    let archive_time = modified_at(archive);
    for path in &sources {
        if modified_at(path) > archive_time {
            panic!(
                "curl-urlapi-rs: {} is newer than the raw archive {}, so the \
                 archive is stale and does not contain that edit. Rebuild it \
                 before localizing: a localization pass cannot tell a stale \
                 archive from a current one by its symbols alone, because \
                 the symbol set is the same.",
                path.display(),
                archive.display()
            );
        }
    }

    let source_tag = sources.iter().fold(0xcbf2_9ce4_8422_2325_u64, |tag, path| {
        let bytes = fs::read(path).unwrap_or_default();
        fnv1a(fnv1a(tag, path.to_string_lossy().as_bytes()), &bytes)
    });

    note(&format!(
        "raw archive {} accepted: defines all {} required globals out of {} \
         total, imports {:?}, and is no older than any of the {} source files \
         it was built from",
        archive.display(),
        expected.len(),
        defined.len(),
        providers,
        sources.len()
    ));

    RawArchiveFacts {
        content_tag: content_tag(archive),
        source_tag,
        defined_count: defined.len(),
        providers,
    }
}

/// Every file whose content can change what the archive contains, sorted so
/// that the fold over them is reproducible.
///
/// `Cargo.toml` and `build.rs` are here because they decide the feature set
/// and the configuration flags; `cbindgen.toml` is not, because it affects
/// only the generated header and never the compiled code.
fn source_inventory() -> Vec<PathBuf> {
    let crate_dir = manifest_dir();
    let mut paths = vec![crate_dir.join("Cargo.toml"), crate_dir.join("build.rs")];
    collect_rust_sources(&crate_dir.join("src"), &mut paths);
    paths.sort();
    paths
}

/// Append every `.rs` file under `directory`, recursively.
///
/// A directory that cannot be read is skipped rather than fatal: the caller
/// treats the inventory as "everything that could have contributed", and a
/// missing `src` directory is a failure the compiler reports far more clearly
/// than a build script could.
fn collect_rust_sources(directory: &Path, into: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, into);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            into.push(path);
        }
    }
}

/// The modification time of `path` as whole seconds since the epoch, or 0 when
/// it cannot be read.
///
/// Zero for an unreadable file is the conservative answer for the one caller:
/// it makes that file look old, so it never manufactures a staleness failure
/// out of a missing timestamp.
fn modified_at(path: &Path) -> u64 {
    fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |since| since.as_secs())
}

/// A change detector over a file's bytes.
///
/// FNV-1a, 64 bits. This is **not** a cryptographic digest and is not used as
/// one: its job is to let two provenance records be compared and to make an
/// accidental reuse of the wrong file visible, while the checks that actually
/// gate the certification -- the defined set, the imported provider set and
/// the staleness comparison -- are exact. Choosing it keeps the build script
/// free of a hashing dependency, which matters because the dependency
/// inventory is fixed.
fn content_tag(path: &Path) -> u64 {
    fnv1a(0xcbf2_9ce4_8422_2325, &fs::read(path).unwrap_or_default())
}

/// One FNV-1a round over `bytes`, folded into `tag`.
fn fnv1a(tag: u64, bytes: &[u8]) -> u64 {
    bytes.iter().fold(tag, |accumulator, byte| {
        (accumulator ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
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

/// The sorted, deduplicated names `nm -u` reports as undefined for a file.
///
/// The output format is `<spaces> <type> <name>` for an undefined symbol, so a
/// line is a symbol only when it has two fields. Archive-member banner lines
/// have one field and a trailing colon; blank lines have none. Weak undefined
/// references are reported with a lower-case type letter and are kept, because
/// the caller asks about names rather than about binding strength.
fn undefined_symbols(path: &Path) -> Vec<String> {
    let program = tool("NM", "nm");
    let outcome = Command::new(&program).arg("-u").arg(path).output();
    let output = match outcome {
        Ok(output) if output.status.success() => output,
        Ok(output) => panic!(
            "curl-urlapi-rs: {program} failed to list the undefined symbols \
             of {}: {}\n{}",
            path.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(error) => panic!(
            "curl-urlapi-rs: could not run {program} to inspect {}: {error}",
            path.display()
        ),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut names: Vec<String> = text
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            match fields.as_slice() {
                [_kind, name] => Some((*name).to_owned()),
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

/// The operating systems whose linker understands `-z defs`.
///
/// GNU ld, gold and LLD all accept it on an ELF target and all give it the
/// same meaning. Mach-O's linker has no such option -- the behaviour is its
/// default and its spelling is `-undefined error` -- and neither the MSVC
/// linker nor `wasm-ld` has an equivalent, so the gate is skipped rather than
/// guessed at on anything not listed here. Skipping loses the enforcement on
/// that target, which is why [`emit_shared_artifact_gate`] says so in the
/// build log instead of passing over it in silence.
const ELF_TARGET_OS: [&str; 11] = [
    "android",
    "dragonfly",
    "freebsd",
    "fuchsia",
    "haiku",
    "hurd",
    "illumos",
    "linux",
    "netbsd",
    "openbsd",
    "solaris",
];

/// Refuse to produce a shared object that carries an unresolved import.
///
/// # The defect this closes
///
/// `crate-type` in Cargo.toml is a property of the *package*, so every
/// configuration of this crate offers all three artifacts. The scheme
/// provider, by contrast, is a property of the *feature set*:
/// `src/scheme.rs` compiles the built-in table under `scheme-table` and
/// imports libcurl's own `Curl_get_scheme`/`Curl_getn_scheme` without it,
/// which is what the Agent Action Plan requires at 0.3.1.1, 0.4.2.4 and
/// 0.6.7 and is not negotiable.
///
/// Those two facts do not compose. In the drop-in configuration the archive
/// is exactly right -- the two names must appear as *undefined* in it, so
/// that the linker binds them to the `url.c.o` sitting in the same libcurl
/// archive -- while the shared object built from the same compilation is
/// wrong in a way nothing announced: `libcurl_urlapi_rs.so` came out with
/// `U Curl_get_scheme` and `U Curl_getn_scheme`, no `libcurl` in its NEEDED
/// list, and no prospect of ever resolving them, because both symbols are
/// hidden by libcurl's own visibility rules and so absent from a shared
/// libcurl's dynamic symbol table. Loading it fails, every time, at
/// `dlopen`.
///
/// # The strategy, stated as a rule
///
/// **A shared object is a deliverable only where the crate is
/// self-contained.** That is Mode B, the standalone configuration, whose
/// built-in scheme table needs nothing from libcurl and whose undefined set
/// is libc, libgcc and libidn2 -- every one of them a real NEEDED entry.
/// Mode A's deliverable is the archive, which is the only form a drop-in
/// replacement for `urlapi.c.o` is ever consumed in: it is linked *into*
/// libcurl, where `Curl_get_scheme` is a sibling object rather than a
/// foreign import.
///
/// This function turns that rule into something the build cannot get wrong.
/// `-z defs` -- `--no-undefined` under its other name -- makes the linker
/// refuse to produce a shared object with any unresolved strong reference,
/// so the Mode-A `.so` can no longer be built at all, and the Mode-B one is
/// proved closed on every build rather than on the occasions somebody
/// remembers to run `nm -D -u`. It is the acceptance gate, not a check that
/// stands beside one.
///
/// The directive is `rustc-cdylib-link-arg`, which Cargo applies to the
/// cdylib link and to nothing else, so the archive, the rlib, `cargo check`
/// and `cargo clippy` are untouched by it.
///
/// # Why the release profile and not every profile
///
/// Cargo builds *all* of a lib target's crate types whenever it builds the
/// lib target, and an integration test under `tests/` needs the lib target
/// built. Gating every profile would therefore make `cargo test` and
/// `cargo build` unusable in the drop-in configuration -- measured, not
/// supposed -- and the plan calls for five integration tests under
/// `rust-urlapi/tests/` that have to run in both configurations. So the gate
/// is scoped to the profile that produces **deliverables**, which is
/// `release`: it is the profile every documented build command names, and the
/// one `[profile.release]` in Cargo.toml exists to configure. `cargo test`
/// and `cargo test --lib` keep working in every configuration, and a debug
/// shared object -- which nobody ships -- is recorded in the build log rather
/// than refused.
///
/// # What a drop-in release build must therefore run
///
/// `cargo build --release` asks for all three artifacts at once and so fails
/// in the drop-in configuration on the cdylib it must not produce. Ask for
/// the archive by name instead:
///
/// ```text
/// cargo rustc --release --no-default-features --features idn-libidn2 \
///   --lib --crate-type staticlib
/// ```
///
/// `--crate-type` on `cargo rustc` has been stable since 1.64, well below
/// the 1.75 floor Cargo.toml declares.
fn emit_shared_artifact_gate(scheme_table: bool) {
    let target_os = cargo_env("CARGO_CFG_TARGET_OS");
    let profile = cargo_env("PROFILE");
    let provider = if scheme_table {
        "the built-in table in src/scheme.rs"
    } else {
        "libcurl's Curl_get_scheme, which only a static drop-in link supplies"
    };

    if !ELF_TARGET_OS.contains(&target_os.as_str()) {
        note(&format!(
            "target_os={target_os} has no -z defs equivalent, so the cdylib \
             link-closure gate is not applied here; the scheme provider is \
             {provider}"
        ));
        return;
    }

    if profile != "release" {
        note(&format!(
            "profile={profile} produces no deliverable, so the cdylib \
             link-closure gate is left off and `cargo test` keeps working; \
             the scheme provider is {provider}. A shared object built here in \
             the drop-in configuration carries unresolved libcurl-private \
             references and must not be installed -- see \
             docs/KNOWN-DIVERGENCES.md, \"Integration limitation: the shared \
             object exists in one configuration only\"."
        ));
        return;
    }

    cargo("rustc-cdylib-link-arg=-Wl,-z,defs");

    if scheme_table {
        note(&format!(
            "cdylib link-closure gate on (-Wl,-z,defs): the shared object is \
             a deliverable in this configuration and its scheme provider is \
             {provider}"
        ));
    } else {
        note(
            "cdylib link-closure gate on (-Wl,-z,defs): this is the drop-in \
             configuration, whose scheme provider is libcurl's own \
             Curl_get_scheme, so no self-contained shared object exists to \
             build and the release cdylib link is expected to fail. The \
             deliverable here is the archive: build it with `cargo rustc \
             --release --no-default-features --features idn-libidn2 --lib \
             --crate-type staticlib`, then localize it as described by \
             `localize_dropin_archive`.",
        );
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
    use std::fmt::Write as _;
    use std::fs;
    use std::io::ErrorKind;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    /// The committed mirror header, which this module regenerates byte for byte.
    ///
    /// It mirrors include/curl/urlapi.h:34-149 and is a wholly separate file
    /// with a different name, directory and include guard, so it can neither
    /// shadow the real header nor be shadowed by it.
    const MIRROR_HEADER: &str = "curl_urlapi_rs.h";

    /// cbindgen's own output, kept in OUT_DIR under its own name. It is the ABI
    /// *inventory* this module reads, never a deliverable, and keeping it means
    /// a drift report can point at the intermediate as well as at the result.
    const INVENTORY_HEADER: &str = "curl_urlapi_rs_cbindgen.h";

    /// The struct tag of the opaque handle, from include/curl/urlapi.h:107.
    ///
    /// This is the one part of a declaration that does not come from the
    /// inventory, and the reason is mechanical: cbindgen derives the tag from
    /// the Rust item name and has no setting for it, so the generated
    /// inventory writes `typedef struct CURLU CURLU;`. The tag is not ABI --
    /// the type is incomplete in both spellings and is only ever used through
    /// a pointer, which is the property that makes this whole port possible --
    /// while the typedef NAME beside it is taken from the inventory like
    /// everything else, so a rename there still fails the comparison.
    const HANDLE_TAG: &str = "Curl_URL";

    /// Set to 1 to update the committed header from the regenerated bytes.
    ///
    /// Unset, which is the default, regeneration only ever *compares*. That is
    /// deliberate: the committed header is tracked and hand-authored, and an
    /// earlier version of this module overwrote it during an ordinary
    /// `cargo check --features genheader`, destroying a maintainer's edits
    /// with nothing but a warning to show for it. Writing is now something a
    /// caller asks for by name.
    const WRITE_BACK: &str = "CURL_URLAPI_WRITE_MIRROR_HEADER";

    /// curl's line limit for C sources and headers, from .editorconfig.
    const LINE_LIMIT: usize = 79;

    /// The heading the result-code enumeration carries in the public header.
    const CODES_HEADING: &str = "/* the error codes for the URL API */";

    /// Everything above the first declaration: the include guard, the licence
    /// box, the explanatory prose, the CURL_EXTERN fallback and the opening of
    /// the `extern "C"` block.
    ///
    /// # Why the frame is transcribed here as well as committed
    ///
    /// No generator can derive prose. For the regenerated bytes to be
    /// comparable with the committed file *as a whole file* rather than as a
    /// projection of it, this module has to be able to produce the whole file,
    /// which means carrying the fixed text. The duplication is the price of an
    /// exact comparison, and the comparison is what keeps the two copies in
    /// step: edit one and the build fails until the other matches.
    ///
    /// Everything that is not fixed text -- every name, every value, every
    /// type, every arity, the declaration order and the alignment -- is derived
    /// from the inventory instead, which is the crate's real ABI as cbindgen
    /// reads it.
    const PREAMBLE: &str = r#"#ifndef CURLINC_URLAPI_RS_H
#define CURLINC_URLAPI_RS_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

/*
 * A one-for-one mirror of the public declarations in
 * include/curl/urlapi.h:34-149, provided for the standalone link mode, in
 * which no libcurl takes part and the real header is therefore not on the
 * include path. Everything from the CURLUcode enumeration down is
 * transcribed from that file verbatim, cosmetic details included, because a
 * mirror that improves on its original is no longer a mirror.
 *
 * This header neither shadows the real one nor can be shadowed by it: the
 * file name, the directory and the include guard opened above all differ
 * deliberately, so a shared guard can never make one of the two silently
 * vanish. Each link mode uses exactly one of them, and that is the
 * supported arrangement -- a translation unit including both is rejected,
 * because the two would declare the same enumerators and typedefs twice.
 * The CURL_EXTERN block below is guarded all the same, so that the macro
 * at least cannot collide in either include order.
 *
 * WHY THIS FILE HAS NO INCLUDE DIRECTIVE AT ALL
 *
 * include/curl/urlapi.h:27 includes "curl.h", and that is the only reason
 * it does so: "curl.h" is where it obtains CURL_EXTERN, the linkage
 * decoration its six declarations carry. That line is deliberately not
 * reproduced. A standalone link contains no libcurl, and drawing in the
 * whole of "curl.h" to obtain one macro would defeat the purpose of a
 * self-contained mirror. The decoration is resolved locally instead, by the
 * block below, which is guarded by ifndef so that a translation unit
 * including both this mirror and the real "curl.h" cannot redefine it, in
 * either include order.
 *
 * Nothing further is required. The six declarations close over CURLU,
 * CURLUcode, CURLUPart, char, void, unsigned int and const char * alone --
 * there is no size_t, no curl_off_t and no CURL anywhere in the surface --
 * so this file needs no header of its own and includes none.
 *
 * WHAT IS DELIBERATELY ABSENT
 *
 * curl_free() belongs to include/curl/curl.h:2735, not to urlapi.h, which
 * refers to it only in the prose below at its lines 130-131. A one-for-one
 * mirror therefore does not declare it, and a standalone consumer needing
 * it must obtain that prototype elsewhere.
 *
 * The three entry points declared at lib/urlapi-int.h:28-33 --
 * Curl_is_absolute_url, Curl_url_set_authority and Curl_junkscan -- are
 * exported by the production object file this crate replaces, and the crate
 * exports all three so that a drop-in link keeps working. They form no part
 * of the public contract, so they are absent here.
 *
 * Curl_parse_port is a different case and must not be lumped in with them.
 * Its declaration at lib/urlapi-int.h:36-37 sits inside the #ifdef UNITTESTS
 * block that spans lines 35 to 38, so it is a global only in a unit-test
 * build of libcurl and is NOT among the eight globals the production object
 * file defines. The crate therefore does
 * not export it either, deliberately: adding it would make the archive's
 * exported set larger than the object file's, which is the one property the
 * drop-in has to preserve. The consequence -- that tests/unit/unit1653.c
 * stays out of reach -- is recorded as constraint R2 rather than worked
 * around. dedotdotify, marked the same way at lib/urlapi.c:715, is in the
 * same position.
 *
 * curl_url_strerror() is declared below with an unnamed parameter, exactly
 * as at include/curl/urlapi.h:149, even though its manual page names one.
 * The omission is reproduced on purpose and must not be repaired;
 * ../docs/KNOWN-DIVERGENCES.md records it as finding FB5.
 */

#ifndef CURL_EXTERN
#ifdef CURL_STATICLIB
#define CURL_EXTERN
#elif defined(_WIN32)
#ifdef BUILDING_LIBCURL
#define CURL_EXTERN __declspec(dllexport)
#else
#define CURL_EXTERN __declspec(dllimport)
#endif
#else
#define CURL_EXTERN
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

"#;

    /// Everything below the last declaration: the close of the `extern "C"`
    /// block and the include guard.
    const EPILOGUE: &str = r#"
#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* CURLINC_URLAPI_RS_H */
"#;

    /// The trailing comment each behaviour flag carries in the public header,
    /// pre-split into the lines that header wraps it onto.
    ///
    /// The segments are data rather than something re-wrapped here on purpose:
    /// the wrap points are the public header's own, and re-deriving them would
    /// mean reproducing a decision somebody made by eye. What this module
    /// computes is the *alignment*, which is mechanical.
    const FLAG_COMMENTS: [(&str, &[&str]); 16] = [
        ("CURLU_DEFAULT_PORT", &["return default port number"]),
        (
            "CURLU_NO_DEFAULT_PORT",
            &[
                "act as if no port number was set,",
                "if the port number matches the",
                "default for the scheme",
            ],
        ),
        (
            "CURLU_DEFAULT_SCHEME",
            &["return default scheme if", "missing"],
        ),
        ("CURLU_NON_SUPPORT_SCHEME", &["allow non-supported scheme"]),
        ("CURLU_PATH_AS_IS", &["leave dot sequences"]),
        ("CURLU_DISALLOW_USER", &["no user+password allowed"]),
        ("CURLU_URLDECODE", &["URL decode on get"]),
        ("CURLU_URLENCODE", &["URL encode on set"]),
        ("CURLU_APPENDQUERY", &["append a form style part"]),
        ("CURLU_GUESS_SCHEME", &["legacy curl-style guessing"]),
        (
            "CURLU_NO_AUTHORITY",
            &["Allow empty authority when the", "scheme is unknown."],
        ),
        ("CURLU_ALLOW_SPACE", &["Allow spaces in the URL"]),
        ("CURLU_PUNYCODE", &["get the hostname in punycode"]),
        ("CURLU_PUNY2IDN", &["punycode => IDN conversion"]),
        (
            "CURLU_GET_EMPTY",
            &[
                "allow empty queries and fragments",
                "when extracting the URL or the",
                "components",
            ],
        ),
        ("CURLU_NO_GUESS_SCHEME", &["for get, do not accept a guess"]),
    ];

    /// The one part identifier that carries a note in the public header,
    /// include/curl/urlapi.h:81.
    const PART_ANNOTATIONS: [(&str, &str); 1] = [("CURLUPART_ZONEID", "added in 7.65.0")];

    /// The six public declarations in header order, each with the comment
    /// block that precedes it and the parameter names it uses.
    ///
    /// Parameter names are not ABI, and the public header's own choices are
    /// reproduced rather than the inventory's: cbindgen names them after the
    /// Rust parameters, so it writes `input` where the header writes `in` --
    /// which is a Rust keyword and cannot be spelled there -- and `code` where
    /// the header names nothing at all. That last one is finding FB5 in
    /// docs/KNOWN-DIVERGENCES.md and is reproduced deliberately: an empty
    /// string here means the parameter stays unnamed, exactly as at
    /// include/curl/urlapi.h:149.
    ///
    /// The ORDER is this table's, and the set has to match the inventory
    /// exactly -- a function in one and not the other fails before any byte is
    /// compared, with a message naming it.
    const FUNCTION_FRAME: [(&str, &str, &[&str]); 6] = [
        (
            "curl_url",
            r#"/*
 * curl_url() creates a new CURLU handle and returns a pointer to it.
 * Must be freed with curl_url_cleanup().
 */"#,
            &[],
        ),
        (
            "curl_url_cleanup",
            r#"/*
 * curl_url_cleanup() frees the CURLU handle and related resources used for
 * the URL parsing. It will not free strings previously returned with the URL
 * API.
 */"#,
            &["handle"],
        ),
        (
            "curl_url_dup",
            r#"/*
 * curl_url_dup() duplicates a CURLU handle and returns a new copy. The new
 * handle must also be freed with curl_url_cleanup().
 */"#,
            &["in"],
        ),
        (
            "curl_url_get",
            r#"/*
 * curl_url_get() extracts a specific part of the URL from a CURLU
 * handle. Returns error code. The returned pointer MUST be freed with
 * curl_free() afterwards.
 */"#,
            &["handle", "what", "part", "flags"],
        ),
        (
            "curl_url_set",
            r#"/*
 * curl_url_set() sets a specific part of the URL in a CURLU handle. Returns
 * error code. The passed in string will be copied. Passing a NULL instead of
 * a part string, clears that part.
 */"#,
            &["handle", "what", "part", "flags"],
        ),
        (
            "curl_url_strerror",
            r#"/*
 * curl_url_strerror() turns a CURLUcode value into the equivalent human
 * readable error string. This is useful for printing meaningful error
 * messages.
 */"#,
            &[""],
        ),
    ];

    /// Regenerate the mirror header and require it to equal the committed one
    /// byte for byte.
    ///
    /// # What "exact" means here, and why it is not a projection
    ///
    /// An earlier version of this module reduced both files to a set of
    /// canonical one-line entries and compared the sets. That comparison was
    /// deliberately blind to declaration *shape* -- enumeration versus macro,
    /// the struct tag, parameter names, comments, ordering, alignment -- and
    /// blindness is a liability in a file whose whole purpose is to be a
    /// one-for-one mirror. It also let the generated intermediate stay
    /// non-C89: cbindgen's `cpp_compat` wrapper writes `#endif // __cplusplus`,
    /// and `//` is not a comment in C89 at all.
    ///
    /// Both are closed. `cbindgen.toml` sets `cpp_compat = false`, so the
    /// inventory carries no `//` anywhere, and this module then *emits* the
    /// mirror rather than diffing against cbindgen's layout: it reads the
    /// inventory for the ABI -- constant names and values, typedef names and
    /// kinds, function return types, arities and parameter types -- and renders
    /// the public header's own shape from it, enumerations and aligned macros
    /// included. The result is compared with the committed file **byte for
    /// byte**, and any difference fails the build with the first differing line
    /// on both sides.
    ///
    /// # This function does not write into the source tree unless told to
    ///
    /// The generated bytes land in OUT_DIR, which is the only directory a build
    /// script owns. Setting `CURL_URLAPI_WRITE_MIRROR_HEADER=1` additionally
    /// updates the committed file, and that is the only path that writes to it.
    /// With the comparison now exact the write is a no-op on an unchanged
    /// crate, which is what makes regeneration idempotent: two runs in a row
    /// leave `git status --porcelain` clean for that path.
    ///
    /// # WHY THE CRATE ROOT AND NOT THE CRATE
    ///
    /// The generator is pointed at src/lib.rs with `Builder::with_src`, not at
    /// the crate directory with `Builder::with_crate`. That is not a stylistic
    /// preference; it is what keeps this feature inside the 1.75 floor that
    /// Cargo.toml declares. Crate mode makes cbindgen run `cargo metadata` and
    /// expand macros through the toolchain, which drags the whole dependency
    /// resolution of the package into a build script; source mode parses the
    /// module tree directly and needs none of it.
    pub(super) fn generate(crate_dir: &Path) {
        super::rerun_if_changed(&crate_dir.join("src"));
        super::cargo(&format!("rerun-if-env-changed={WRITE_BACK}"));

        let config_path = crate_dir.join("cbindgen.toml");
        let committed = crate_dir.join("include").join(MIRROR_HEADER);
        // The committed header is an INPUT to this step, because the step
        // compares against it. Without this the comparison would not re-run
        // when somebody edited the file, which is the one edit it exists to
        // catch -- measured, and it really did pass an edited header.
        super::rerun_if_changed(&committed);
        let inventory_path = out_dir().join(INVENTORY_HEADER);
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

        // Source mode, not crate mode. See "WHY THE CRATE ROOT AND NOT THE
        // CRATE" in this function's documentation.
        let root = crate_dir.join("src").join("lib.rs");
        let bindings = match cbindgen::Builder::new()
            .with_src(&root)
            .with_config(config)
            .generate()
        {
            Ok(bindings) => bindings,
            Err(error) => panic!(
                "curl-urlapi-rs: cbindgen could not generate the ABI \
                 inventory from {}: {error}",
                root.display()
            ),
        };

        let mut inventory = Vec::new();
        bindings.write(&mut inventory);
        write_out_dir(&inventory_path, &inventory);

        let abi = Abi::read(&inventory, &inventory_path);
        let mirror = abi.emit();
        write_out_dir(&generated_path, mirror.as_bytes());

        // A C89 syntax check of what was just emitted, when a compiler can be
        // found. The mirror is included by C programs in the standalone link
        // mode, and curl holds its headers to C89, so "compiles as C89" is
        // part of the contract rather than a nicety.
        check_c89(&generated_path);

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

        let identical = existing.as_deref() == Some(mirror.as_bytes());
        if identical {
            super::note(&format!(
                "{} is byte-for-byte what this crate's ABI regenerates: {} \
                 constants, {} typedefs and {} declarations, emitted into {}",
                committed.display(),
                abi.constants.len(),
                abi.typedef_count(),
                abi.functions.len(),
                generated_path.display()
            ));
            return;
        }

        if super::env_flag(WRITE_BACK) {
            if let Err(error) = fs::write(&committed, mirror.as_bytes()) {
                panic!(
                    "curl-urlapi-rs: could not update {}: {error}",
                    committed.display()
                );
            }
            super::warn(&format!(
                "{} updated from the regenerated mirror because {WRITE_BACK} \
                 is set. Review the diff before committing it: the file is \
                 tracked and hand-authored.",
                committed.display()
            ));
            return;
        }

        let Some(bytes) = existing else {
            super::note(&format!(
                "{} does not exist. The regenerated mirror is in {}; set \
                 {WRITE_BACK}=1 to install it there.",
                committed.display(),
                generated_path.display()
            ));
            return;
        };

        panic!(
            "curl-urlapi-rs: {} is not what this crate's ABI regenerates. \
             Nothing was modified. The regenerated bytes are in {}, and the \
             inventory they were read from is in {}.\n{}\n\
             Reconcile by changing the Rust items in src/ffi.rs and \
             src/abi.rs, or the frame in build.rs `mod mirror_header` -- never \
             by editing include/curl/urlapi.h, which is read-only. If the \
             regenerated bytes are the intended ones, rerun with \
             {WRITE_BACK}=1 to install them.",
            committed.display(),
            generated_path.display(),
            inventory_path.display(),
            first_difference(&bytes, mirror.as_bytes())
        );
    }

    /// Write into OUT_DIR, reporting a failure rather than ignoring it.
    ///
    /// Cargo creates OUT_DIR before running the script, so no directory has to
    /// be made here. The write is checked because a full disk would otherwise
    /// make the comparison that follows silently vacuous.
    fn write_out_dir(path: &Path, bytes: &[u8]) {
        if let Err(error) = fs::write(path, bytes) {
            panic!(
                "curl-urlapi-rs: could not write {}: {error}",
                path.display()
            );
        }
    }

    /// The first line at which two byte strings differ, rendered for a panic.
    ///
    /// Line-oriented rather than offset-oriented because the reader's next
    /// action is to look at that line in an editor. Trailing-newline-only
    /// differences have no differing line, so they are named explicitly instead
    /// of reported as "no difference".
    fn first_difference(left: &[u8], right: &[u8]) -> String {
        let left = String::from_utf8_lossy(left);
        let right = String::from_utf8_lossy(right);
        let mut lines = left.lines().zip(right.lines()).enumerate();
        if let Some((index, (l, r))) = lines.find(|(_, (l, r))| l != r) {
            return format!(
                "first difference at line {}:\n  committed:   {l}\n  regenerated: {r}",
                index.saturating_add(1)
            );
        }
        format!(
            "the lines agree, so the difference is in length or in trailing \
             bytes: committed {} bytes over {} lines, regenerated {} bytes \
             over {} lines",
            left.len(),
            left.lines().count(),
            right.len(),
            right.lines().count()
        )
    }

    /// Compile the emitted header as strict C89, when a compiler is available.
    ///
    /// An absent or unusable compiler is a note rather than a failure: the
    /// check is a bonus on top of the byte comparison, and a build script that
    /// insisted on a C compiler would make `cargo check --features genheader`
    /// depend on one.
    fn check_c89(header: &Path) {
        let Some(compiler) = super::probe_compiler() else {
            super::note("no C compiler found, so the C89 check was skipped");
            return;
        };
        let probe = out_dir().join("curl_urlapi_rs_c89_probe.c");
        let source = format!("#include \"{}\"\n", header.display());
        write_out_dir(&probe, source.as_bytes());

        let outcome = Command::new(&compiler)
            .args(["-std=c89", "-pedantic-errors", "-Wall", "-fsyntax-only"])
            .arg(&probe)
            .output();
        match outcome {
            Ok(output) if output.status.success() => super::note(&format!(
                "{} compiles as strict C89 with {compiler} \
                 -std=c89 -pedantic-errors -Wall",
                header.display()
            )),
            Ok(output) => panic!(
                "curl-urlapi-rs: the regenerated mirror {} is not valid \
                 strict C89. curl holds its headers to C89 and the standalone \
                 link mode includes this file from C, so this is a defect in \
                 what build.rs emits, not in the check.\n{}",
                header.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
            Err(error) => super::note(&format!(
                "{compiler} could not be run ({error}), so the C89 check was \
                 skipped"
            )),
        }
    }

    /// The directory Cargo set aside for this build script's output.
    ///
    /// Read through the same helper the rest of the script uses, so a missing
    /// variable produces the one actionable message rather than an unwrap.
    fn out_dir() -> PathBuf {
        PathBuf::from(super::cargo_env("OUT_DIR"))
    }

    /// A C type as a base spelling plus a pointer depth.
    ///
    /// Splitting the two is what lets the emitter place the star against the
    /// declarator the way the public header does -- `const CURLU *handle`,
    /// `char **part` -- from a description that says nothing about spacing.
    struct CType {
        /// The type without any `*`, with single spaces between its words.
        base: String,
        /// How many `*` the type carries.
        stars: usize,
    }

    impl CType {
        /// Read a declaration fragment as a type and, when there is one, the
        /// declarator name that followed it.
        ///
        /// The rule is C's own: after splitting `*` out as its own word, a
        /// trailing word is a declarator name exactly when something else
        /// precedes it. `void` alone is therefore a type and not a name, and
        /// `CURLUcode` alone -- the unnamed parameter at
        /// include/curl/urlapi.h:149 -- is read as a type too.
        fn parse(text: &str) -> (Self, String) {
            let spaced = text.replace('*', " * ");
            let mut words: Vec<&str> = spaced.split_whitespace().collect();
            let mut name = String::new();
            if words.len() > 1 {
                if let Some(last) = words.last() {
                    if *last != "*" {
                        name = (*last).to_owned();
                        words.pop();
                    }
                }
            }
            let stars = words.iter().filter(|word| **word == "*").count();
            let base = words
                .iter()
                .filter(|word| **word != "*")
                .copied()
                .collect::<Vec<&str>>()
                .join(" ");
            (Self { base, stars }, name)
        }

        /// The type followed by `name`, spaced the way the public header spaces
        /// it: one space after the base, then the stars against the name.
        ///
        /// With an empty name this renders the bare type, which is what an
        /// unnamed parameter needs.
        fn declare(&self, name: &str) -> String {
            let mut text = self.base.clone();
            if self.stars > 0 || !name.is_empty() {
                text.push(' ');
            }
            for _ in 0..self.stars {
                text.push('*');
            }
            text.push_str(name);
            text
        }
    }

    /// One function declaration, as the inventory describes it.
    struct CFunction {
        name: String,
        returns: CType,
        parameters: Vec<CType>,
    }

    /// The ABI the crate declares, read out of cbindgen's output.
    ///
    /// Everything the emitter varies comes from here, and nothing here comes
    /// from the committed header, which is what makes the byte comparison a
    /// real check rather than a tautology.
    struct Abi {
        /// Every object-like macro with an integer value, in file order.
        constants: Vec<(String, u32)>,
        /// The names of `typedef struct TAG NAME;` declarations.
        opaque: Vec<String>,
        /// The names of `typedef <integer type> NAME;` declarations.
        scalars: Vec<String>,
        /// Every function declaration, in file order.
        functions: Vec<CFunction>,
    }

    impl Abi {
        /// Read the inventory.
        ///
        /// The parse is deliberately narrow: comments and preprocessor lines
        /// are handled explicitly, and everything else is expected to be a
        /// `;`-terminated declaration. Anything that fits none of the shapes
        /// below fails the build rather than being skipped, because a silently
        /// ignored declaration is exactly the failure mode this rewrite exists
        /// to remove.
        fn read(bytes: &[u8], path: &Path) -> Self {
            let text = String::from_utf8_lossy(bytes);
            let mut constants = Vec::new();
            let mut declarations = String::new();

            for line in text.lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("#define ") {
                    let mut parts = rest.splitn(2, char::is_whitespace);
                    let name = parts.next().unwrap_or_default();
                    let value = parts.next().unwrap_or_default().trim();
                    // A macro with no value is CURL_EXTERN's fallback, which is
                    // frame rather than ABI. One with a value that is not an
                    // integer would be something this port does not declare.
                    if value.is_empty() || name.is_empty() {
                        continue;
                    }
                    if let Some(number) = integer(value) {
                        constants.push((name.to_owned(), number));
                    }
                    continue;
                }
                if line.starts_with('#') || line.is_empty() {
                    continue;
                }
                declarations.push(' ');
                declarations.push_str(line);
            }

            // Comments only ever appear as whole `/* ... */` runs in cbindgen's
            // output, and `//` cannot appear at all now that cpp_compat is off,
            // so removing the block form is the whole of the job.
            let declarations = strip_comments(&declarations);

            let mut opaque = Vec::new();
            let mut scalars = Vec::new();
            let mut functions = Vec::new();
            for statement in declarations.split(';') {
                let statement = statement.trim();
                if statement.is_empty() {
                    continue;
                }
                if let Some(rest) = statement.strip_prefix("typedef ") {
                    let words: Vec<&str> = rest.split_whitespace().collect();
                    match words.as_slice() {
                        ["struct", _tag, name] => opaque.push((*name).to_owned()),
                        [.., name] => scalars.push((*name).to_owned()),
                        [] => panic!(
                            "curl-urlapi-rs: {} contains an empty typedef",
                            path.display()
                        ),
                    }
                    continue;
                }
                functions.push(function(statement, path));
            }

            Self {
                constants,
                opaque,
                scalars,
                functions,
            }
        }

        /// How many typedefs the inventory holds, for the success note.
        fn typedef_count(&self) -> usize {
            self.opaque.len().saturating_add(self.scalars.len())
        }

        /// The constants whose names begin with `prefix`, in ascending value
        /// order, with any name that also matches `unless` left out.
        ///
        /// The grouping is by name prefix because that is what the public
        /// header groups by, and the order is by value because that is what
        /// positional parity means: `CURLUE_*` and `CURLUPART_*` are
        /// enumerators whose ordinals emerge from declaration order, so
        /// declaration order has to be the value order.
        fn group(&self, prefix: &str, unless: &[&str]) -> Vec<(String, u32)> {
            let mut group: Vec<(String, u32)> = self
                .constants
                .iter()
                .filter(|(name, _)| {
                    name.starts_with(prefix) && !unless.iter().any(|other| name.starts_with(other))
                })
                .cloned()
                .collect();
            group.sort_by_key(|(_, value)| *value);
            group
        }

        /// Render the whole mirror header.
        fn emit(&self) -> String {
            let codes = self.group("CURLUE_", &[]);
            let parts = self.group("CURLUPART_", &[]);
            let flags = self.group("CURLU_", &["CURLUE_", "CURLUPART_"]);

            let mut out = String::from(PREAMBLE);
            out.push_str(CODES_HEADING);
            out.push('\n');
            out.push_str(&self.enumeration(&codes, "CURLUcode", true));
            out.push('\n');
            out.push_str(&self.enumeration(&parts, "CURLUPart", false));
            out.push('\n');
            out.push_str(&macros(&flags));
            out.push('\n');
            let handle = match self.opaque.as_slice() {
                [name] => name,
                other => panic!(
                    "curl-urlapi-rs: the ABI inventory declares {} opaque \
                     typedefs and the mirror describes exactly one, the URL \
                     handle. Found: {other:?}.",
                    other.len()
                ),
            };
            let _ = writeln!(out, "typedef struct {HANDLE_TAG} {handle};");
            for (name, comment, names) in FUNCTION_FRAME {
                out.push('\n');
                out.push_str(comment);
                out.push('\n');
                out.push_str(&self.declaration(name, names));
            }
            out.push_str(EPILOGUE);
            out
        }

        /// Render one `typedef enum { .. } NAME;` block.
        ///
        /// `numbered` selects the result-code form, where every enumerator
        /// except the first and the sentinel carries its ordinal as an aligned
        /// comment. The part-identifier form carries no ordinals and one text
        /// annotation.
        fn enumeration(&self, entries: &[(String, u32)], typename: &str, numbered: bool) -> String {
            if !self.scalars.iter().any(|name| name == typename) {
                panic!(
                    "curl-urlapi-rs: the ABI inventory has no typedef named \
                     {typename}, which the mirror declares as an enumeration. \
                     Found: {:?}.",
                    self.scalars
                );
            }

            // Every line's declarator first, so the comment column can be the
            // longest of them. The public header aligns enumerator comments two
            // columns past the longest declarator; measured against
            // include/curl/urlapi.h, that is column 30.
            let last = entries.len().saturating_sub(1);
            let declarators: Vec<String> = entries
                .iter()
                .enumerate()
                .map(|(index, (name, _))| {
                    if index == last {
                        format!("  {name}")
                    } else {
                        format!("  {name},")
                    }
                })
                .collect();
            let commented = |index: usize| numbered && index != 0 && index != last;
            let column = declarators
                .iter()
                .enumerate()
                .filter(|(index, _)| commented(*index))
                .map(|(_, text)| text.len().saturating_add(2))
                .max()
                .unwrap_or(0);

            let mut out = String::from("typedef enum {\n");
            for (index, declarator) in declarators.iter().enumerate() {
                out.push_str(declarator);
                if commented(index) {
                    for _ in declarator.len()..column {
                        out.push(' ');
                    }
                    let value = entries.get(index).map_or(0, |(_, value)| *value);
                    let _ = write!(out, "/* {value} */");
                } else if let Some((_, note)) = PART_ANNOTATIONS
                    .iter()
                    .find(|(name, _)| entries.get(index).is_some_and(|(entry, _)| entry == name))
                {
                    let _ = write!(out, " /* {note} */");
                }
                out.push('\n');
            }
            let _ = writeln!(out, "}} {typename};");
            out
        }

        /// Render one function declaration, wrapped the way the public header
        /// wraps it.
        fn declaration(&self, name: &str, parameter_names: &[&str]) -> String {
            let Some(function) = self.functions.iter().find(|f| f.name == name) else {
                panic!(
                    "curl-urlapi-rs: the ABI inventory does not declare \
                     {name}, which the mirror does. Either src/ffi.rs stopped \
                     exporting it or cbindgen.toml excludes it."
                );
            };
            if function.parameters.len() != parameter_names.len().max(usize::from(false)) {
                // The `void` parameter list is one CType and no names, so the
                // arity comparison is against the names plus that one case.
                if !(parameter_names.is_empty() && function.parameters.len() == 1) {
                    panic!(
                        "curl-urlapi-rs: {name} takes {} parameters in the ABI \
                         inventory and the mirror names {}. A change of arity \
                         is an ABI break, not a formatting difference.",
                        function.parameters.len(),
                        parameter_names.len()
                    );
                }
            }

            let prefix = format!("CURL_EXTERN {}(", function.returns.declare(&function.name));
            let mut pieces: Vec<String> = Vec::new();
            for (index, parameter) in function.parameters.iter().enumerate() {
                let mut piece =
                    parameter.declare(parameter_names.get(index).copied().unwrap_or(""));
                if index.saturating_add(1) == function.parameters.len() {
                    piece.push_str(");");
                } else {
                    piece.push(',');
                }
                pieces.push(piece);
            }

            let mut out = String::new();
            let mut line = prefix.clone();
            for (index, piece) in pieces.iter().enumerate() {
                let separated = if index == 0 { 0 } else { 1 };
                if index > 0 && line.len().saturating_add(separated + piece.len()) > LINE_LIMIT {
                    out.push_str(&line);
                    out.push('\n');
                    line = " ".repeat(prefix.len());
                } else if index > 0 {
                    line.push(' ');
                }
                line.push_str(piece);
            }
            out.push_str(&line);
            out.push('\n');
            out
        }
    }

    /// Every function that is not one this mirror knows about is a defect, so
    /// the reverse check runs too.
    ///
    /// Called from [`Abi::read`] for each `;`-terminated statement that is not
    /// a typedef.
    fn function(statement: &str, path: &Path) -> CFunction {
        let statement = statement.trim().strip_prefix("CURL_EXTERN").map_or_else(
            || {
                panic!(
                    "curl-urlapi-rs: {} declares `{statement}` without the \
                     CURL_EXTERN decoration. Every public declaration carries \
                     it; cbindgen.toml sets it as the [fn] prefix.",
                    path.display()
                )
            },
            str::trim,
        );
        let Some(open) = statement.find('(') else {
            panic!(
                "curl-urlapi-rs: {} contains the declaration `{statement}`, \
                 which is not a function. The mirror describes six functions, \
                 two enumerations and one opaque handle and nothing else.",
                path.display()
            )
        };
        let Some(close) = statement.rfind(')') else {
            panic!(
                "curl-urlapi-rs: {} contains an unterminated parameter list in \
                 `{statement}`",
                path.display()
            )
        };
        let head = statement.get(..open).unwrap_or_default();
        let inner = statement
            .get(open.saturating_add(1)..close)
            .unwrap_or_default();
        let (returns, name) = CType::parse(head);
        if name.is_empty() {
            panic!(
                "curl-urlapi-rs: {} declares a function with no name in \
                 `{statement}`",
                path.display()
            );
        }
        let parameters = inner
            .split(',')
            .map(|parameter| CType::parse(parameter).0)
            .collect();
        CFunction {
            name,
            returns,
            parameters,
        }
    }

    /// Render the sixteen behaviour flags as aligned object-like macros.
    ///
    /// The public header aligns their comments one column past the longest
    /// declaration and indents a continuation three columns further, so that
    /// continuations line up with the comment text. Measured against
    /// include/curl/urlapi.h: columns 42 and 45.
    fn macros(entries: &[(String, u32)]) -> String {
        let declarations: Vec<String> = entries
            .iter()
            .map(|(name, value)| {
                let bit = value.trailing_zeros();
                if value.checked_shr(bit) == Some(1) {
                    format!("#define {name} (1 << {bit})")
                } else {
                    // Not a single bit, so not a flag. Rendered as itself so
                    // that the byte comparison reports it rather than this
                    // function guessing at an intent.
                    format!("#define {name} {value}")
                }
            })
            .collect();
        let column = declarations
            .iter()
            .map(|text| text.len().saturating_add(1))
            .max()
            .unwrap_or(0);
        let indent = column.saturating_add(3);

        let mut out = String::new();
        for (index, declaration) in declarations.iter().enumerate() {
            out.push_str(declaration);
            let name = entries.get(index).map(|(name, _)| name.as_str());
            let segments = FLAG_COMMENTS
                .iter()
                .find(|(flag, _)| Some(*flag) == name)
                .map(|(_, segments)| *segments)
                .unwrap_or(&[]);
            for _ in declaration.len()..column {
                out.push(' ');
            }
            for (line, segment) in segments.iter().enumerate() {
                if line == 0 {
                    out.push_str("/* ");
                } else {
                    out.push('\n');
                    for _ in 0..indent {
                        out.push(' ');
                    }
                }
                out.push_str(segment);
            }
            if !segments.is_empty() {
                out.push_str(" */");
            }
            out.push('\n');
        }
        out
    }

    /// Remove every `/* ... */` run from `text`.
    ///
    /// `//` is not handled and does not need to be: `cbindgen.toml` sets
    /// `cpp_compat = false` and `documentation = false`, so the inventory
    /// contains no line comments at all -- which is also why it is strict C89.
    fn strip_comments(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(open) = rest.find("/*") {
            out.push_str(rest.get(..open).unwrap_or_default());
            out.push(' ');
            let after = rest.get(open.saturating_add(2)..).unwrap_or_default();
            match after.find("*/") {
                Some(close) => rest = after.get(close.saturating_add(2)..).unwrap_or_default(),
                None => return out,
            }
        }
        out.push_str(rest);
        out
    }

    /// Read a C integer literal, including the `(1 << n)` form the flags use.
    fn integer(value: &str) -> Option<u32> {
        let value = value.trim();
        let inner = value
            .strip_prefix('(')
            .and_then(|rest| rest.strip_suffix(')'))
            .unwrap_or(value);
        if let Some((left, right)) = inner.split_once("<<") {
            let base = super::parse_c_integer(left.trim())?;
            let shift = super::parse_c_integer(right.trim())?;
            return base.checked_shl(shift);
        }
        super::parse_c_integer(inner)
    }
}
