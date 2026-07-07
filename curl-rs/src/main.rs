// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! # curl-rs — command-line entry point
//!
//! Rust rewrite of curl's `src/tool_main.c`. This is the binary crate of the three-crate
//! workspace; it drives the safe-Rust core (`curl-rs-lib`) from a `clap`-based command line
//! and runs on a **current-thread** Tokio runtime, matching curl 8.x's single-threaded CLI
//! model (AAP §0.3.2).
//!
//! At this foundation checkpoint the entry point establishes the runtime and the argument
//! parser and reproduces curl's version-banner and no-operand behavior exactly. The full
//! ~291-flag surface (derived 1:1 from `docs/cmdline-opts/`) and the transfer dispatch loop
//! are layered on in later checkpoints, in the build-order dependency sequence (AAP §0.7.3).
//! No command-line flag is invented here: only the built-in `--help` / `--version` that
//! `clap` provides are recognized, preserving the frozen curl flag contract.

// CLI sub-modules — language rewrites of curl's `src/*.c`, wired in as they are added.
mod terminal;

// Interactive no-echo password prompt (Rust rewrite of `src/tool_getpass.c`). Consumed by the
// argument- and operation-handling layer when a required password is not supplied on the command
// line (for example `-u user:` with an empty password, `--proxy-user`, or an SSH key passphrase).
mod getpass;

use clap::Parser;

/// First line of `--version` output, in curl's parity form
/// `curl-rs/<version> <backends>`. The backend list names the pure-Rust stack that replaces
/// curl's C libraries (rustls for TLS, flate2/brotli/zstd for content encoding, hyper for
/// HTTP/1.1+2, quinn for HTTP/3, russh for SSH). The version is inherited from the crate,
/// which in turn mirrors `LIBCURL_VERSION` via the workspace package version.
const VERSION_BANNER: &str = concat!(
    "curl-rs/",
    env!("CARGO_PKG_VERSION"),
    " rustls flate2 brotli zstd hyper quinn russh"
);

/// curl-rs command-line interface.
///
/// The full ~291-flag surface is added, one-to-one with `docs/cmdline-opts/`, in a later
/// checkpoint. At this foundation checkpoint the only option declared is curl's own
/// `-V` / `--version` flag; `clap` still provides the built-in `--help` handling and rejects
/// unrecognized arguments with the standard usage error (exit code 2), matching curl's
/// option-parsing contract.
///
/// `clap`'s automatic version flag is disabled (`disable_version_flag`) so the banner is
/// emitted verbatim: clap's built-in renderer prints `{name} {version}`, which would double
/// the program identity (`curl-rs curl-rs/…`). curl prints a single version line, so the flag
/// is declared explicitly here and handled in `main` to reproduce the AAP §0.6.3 form exactly.
#[derive(Debug, Parser)]
#[command(
    name = "curl-rs",
    about = "curl-rs - transfer data from or to a server",
    long_about = None,
    disable_help_subcommand = true,
    disable_version_flag = true
)]
struct Cli {
    /// Show version number and exit (curl's `-V` / `--version`).
    #[arg(short = 'V', long = "version")]
    version: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    // `clap` prints and exits (status 0) for `--help`, and rejects any unrecognized argument
    // with a usage error and exit code 2 — matching curl's parser.
    let cli = Cli::parse();

    // `-V` / `--version`: print the parity banner verbatim on stdout and exit 0, matching
    // curl's single-line version output (AAP §0.6.3). Rendering it here (rather than via
    // clap's `{name} {version}` renderer) keeps the output byte-exact.
    if cli.version {
        println!("{VERSION_BANNER}");
        std::process::exit(0);
    }

    // No URL operand means there is nothing to transfer. Mirror curl's behavior for an
    // argument-less invocation: print usage guidance on stderr and exit with status 2.
    eprintln!("curl-rs: try 'curl-rs --help' for more information");
    std::process::exit(2)
}
