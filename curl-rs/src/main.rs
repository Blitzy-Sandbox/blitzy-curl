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

// Command-line configuration model + argument parser (Rust rewrite of curl's
// `src/tool_getparam.c`, `src/tool_paramhlp.c`, and `src/tool_cfgable.c`). This is the
// foundational CLI module: it defines the `OperationConfig` / `GlobalConfig` / `State`
// configuration vocabulary, the `ParameterError` code set, and the full curl 8.x flag
// surface (parsed 1:1 from `docs/cmdline-opts/`). Every other CLI sub-module
// (`setopt`, `operate`, `parsecfg`, `var`, `writeout`, `urlglob`, `formparse`, `ipfs`,
// `filetime`, `xattr`, and the `callbacks/*` group) consumes the types it exports, so it
// is declared here at the crate root even though `main` does not yet drive it directly —
// the operation-dispatch wiring is layered on in a later checkpoint (AAP §0.7.3).
mod args;

// Interactive no-echo password prompt (Rust rewrite of `src/tool_getpass.c`). Consumed by the
// argument- and operation-handling layer when a required password is not supplied on the command
// line (for example `-u user:` with an empty password, `--proxy-user`, or an SSH key passphrase).
mod getpass;

// Extended-attribute metadata writer (Rust rewrite of `src/tool_xattr.c`). Consumed by the
// post-transfer path in the operation-handling layer (`operate.rs` / `callbacks/write.rs`) when
// the `--xattr` option is set, to record the origin URL, referrer, and MIME type on the
// downloaded output file.
mod xattr;

// URL globbing engine (Rust rewrite of `src/tool_urlglob.c`). Implements curl's own
// `{a,b}` / `[1-10]` URL-expansion mini-language (distinct from filesystem globbing). Consumed
// by the operation-dispatch layer (`operate.rs`) to expand a single command-line URL into the
// sequence of concrete transfers, and referenced from `args.rs`'s `State` (`urlglob`/`inglob`).
mod urlglob;
// `--parallel` aggregate progress meter and five-column byte formatter (Rust rewrite of
// `src/tool_progress.c`). Consumed by the parallel-transfer dispatch loop in `operate.rs`,
// which installs `progress_display::xferinfo_cb` on each easy handle and calls
// `ProgressMeter::progress_meter` between `curl_multi_poll` iterations to render the single
// aggregate status line. The single-transfer progress bar lives in `callbacks/progress.rs`
// (rewrite of `src/tool_cb_prg.c`), not here. Wired into dispatch in a later checkpoint
// (AAP §0.7.3).
mod progress_display;
// IPFS/IPNS gateway URL rewriting (Rust rewrite of `src/tool_ipfs.c`). Consumed by the
// option-application layer (`setopt.rs` / `operate.rs`, added in a later checkpoint) to rewrite
// an `ipfs://` / `ipns://` target URL into the gateway HTTP(S) URL before the transfer starts.
// Gated behind the default-on `ipfs` feature, mirroring curl's `#ifndef CURL_DISABLE_IPFS`
// (and the matching `#[cfg(feature = "ipfs")]` guard on `OperationConfig::ipfs_gateway`).
#[cfg(feature = "ipfs")]
mod ipfs;
// The `--write-out` / `-w` format engine (Rust rewrite of `src/tool_writeout.c`). Defines the
// shared variable catalogue (`WriteoutId` / `WriteoutVar` / `VARIABLES`) and the format-string
// interpreter (`our_writeout`). Consumed by the operation-handling layer after each transfer,
// and mutually referenced with `writeout_json` (which renders the `%{json}` / `%{header_json}`
// output over the same variable table).
mod writeout;

// The `%{json}` / `%{header_json}` emitters plus shared JSON string quoting (Rust rewrite of
// `src/tool_writeout_json.c`). Iterates `writeout::VARIABLES` in JSON mode; also exports
// `json_quoted` for the `--write-out` `:json` value function in `var.rs`.
mod writeout_json;
// File-time get/set plus portable local-time conversion (Rust rewrite of `src/tool_filetime.c`
// and `src/toolx/tool_time.c`). `getfiletime` feeds `-z` / `--time-cond` (translated by
// `setopt.rs` into `CURLOPT_TIMECONDITION` + `CURLOPT_TIMEVALUE`) and `setfiletime` is called
// by the post-transfer path (`operate.rs` / `callbacks/write.rs`) for `-R` / `--remote-time`,
// stamping the output file with the server-reported `CURLINFO_FILETIME`. Implemented entirely
// with safe `std::fs` (Rust 1.75) + `chrono`; contains no `unsafe`.
mod filetime;
// `-F` / `--form` multipart parser (Rust rewrite of `src/tool_formparse.c`). Parses one
// `-F`/`--form-string` argument into the CLI-side MIME tree (`args::ToolMime`) and later
// converts that tree into a `curl-rs-lib` mime object. Consumed by the argument layer (which
// installs `formparse::form_parser_hook` as the `args::FormParserHook`) and by the operation
// layer (`operate.rs` / `setopt.rs`), which calls `formparse::tool2curlmime` to build the body.
// Declared here at the crate root even though `main` does not yet drive it directly — the
// operation-dispatch wiring is layered on in a later checkpoint (AAP §0.7.3).
mod formparse;
// Config-file parser and default-config discovery (Rust rewrite of `src/tool_parsecfg.c` +
// `src/tool_findfile.c`). Reads `.curlrc` / `-K` files, tokenizes each directive with curl's
// exact grammar (comment/quoting/separator rules), and dispatches it to `args::getparameter`
// through the `args::ConfigParserHook` function pointer. The argument layer installs
// `parsecfg::config_parser_hook` (for `--config`/`-K`) and the operation layer drives the
// implicit default-`.curlrc` load via `parsecfg::find_config_file`; both are wired in the
// operation-dispatch checkpoint (AAP §0.7.3).
mod parsecfg;
// Easy-handle configuration and `--libcurl` C-source emission (Rust rewrite of
// `src/config2setopts.c` + `src/tool_setopt.c` + `src/tool_easysrc.c`). Translates a fully
// parsed `args::OperationConfig`/`GlobalConfig` into a `curl-rs-lib` easy handle via
// `setopt::config2setopts`, and — when `--libcurl` was given and the `libcurl-option` feature
// is enabled — records an equivalent standalone libcurl C program. Declared here at the crate
// root even though `main` does not yet drive it directly; the operation-dispatch layer
// (`operate.rs`) calls `config2setopts` in a later checkpoint (AAP §0.7.3).
mod setopt;

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
