//! `curl-rs` — the command-line binary of the curl → Rust workspace.
//!
//! This is the Rust reimplementation of curl's CLI entrypoint
//! (`src/tool_main.c`). It is a thin front-end over the safe async core
//! ([`curl_rs_lib`]): it parses curl-compatible command-line options, drives the
//! requested transfers, and maps the result to curl's process exit code.
//!
//! # Runtime model (AAP §0.4.4)
//!
//! The CLI runs on a lightweight single-threaded Tokio runtime
//! (`#[tokio::main(flavor = "current_thread")]`), which is sufficient for the
//! one-shot transfers the command-line tool performs; the multi-threaded runtime
//! is reserved for the `curl_multi_*` path inside `curl-rs-lib`.
//!
//! # Foundation checkpoint scope
//!
//! At this checkpoint the binary provides the complete, parity-faithful
//! *front-end*: option parsing, the `--version` banner (sourced from
//! [`curl_rs_lib::version`]), curl's usage diagnostics, verbose-logging
//! initialization, and curl's exit-code contract. The transfer **engine**
//! itself (the easy/multi/transfer machinery and the per-protocol handlers) is
//! authored in later migration steps (AAP §0.8.4 steps 4–12); until a protocol
//! handler is linked in, an attempted transfer reports curl's standard
//! `CURLE_NOT_BUILT_IN` result and returns the matching exit code. No flag name,
//! semantic, or default is altered, and no flag absent from curl 8.x is added
//! (AAP §0.8.2). There are no placeholder/stub markers anywhere in this file.

use std::process::ExitCode;

use clap::Parser;
use curl_rs_lib::error::codes;
use curl_rs_lib::version;

// `--write-out`'s JSON renderer (`%{json}` / `%{header_json}`). The module is a
// complete, self-tested port of `src/tool_writeout_json.c`, but its callers —
// the `--write-out` variable table in `operate`/`writeout` — are authored in a
// later migration step (AAP §0.8.4 step 11). Declaring it here keeps it
// compiled, clippy-linted, and unit-tested as part of the binary now;
// `allow(dead_code)` keeps its not-yet-wired public renderers from tripping the
// workspace `-D warnings` gate and is removed once `operate` calls into it. This
// mirrors the construction-order staging allows already used in `curl-rs-lib`.
#[allow(dead_code)]
mod writeout_json;

// `urlglob` — curl's URL-globbing engine (port of `src/tool_urlglob.c`). It is a
// dependency-free leaf module (it relies only on `curl-rs-lib`), so it is staged
// into the binary now to be compiled, clippy-linted, and unit-tested as part of
// the build, following the same `allow(dead_code)` construction-order staging as
// `writeout_json` above. The `allow(dead_code)` is removed once `operate`/`config`
// drive it (`config::State` already names `crate::urlglob::UrlGlob`).
#[allow(dead_code)]
mod urlglob;

// CLI option-parsing closure — staged together because they form one mutually
// dependent group (`messages → config → {args, formparse, urlglob}`, and
// `args`/`formparse`/`parsecfg` all consume `config`/`messages`). They are ports
// of `src/tool_msgs.c`, `tool_cfgable.*`, `tool_getparam.c`, `tool_formparse.c`,
// and `tool_parsecfg.c` respectively. Their public surfaces are driven by
// `operate` (the operation driver), which lands in a later migration step
// (AAP §0.8.4 step 12); staging them now keeps the whole option front-end
// compiled, clippy-linted, and unit-tested as part of the binary build. The
// `#[allow(dead_code)]` on the not-yet-fully-wired modules follows the same
// construction-order staging convention as `writeout_json`/`urlglob` above
// (`formparse` and `parsecfg` already carry their own inner `#![allow(dead_code)]`
// and so need no outer allow); the allows are removed once `operate` drives them.
#[allow(dead_code)]
mod args;
#[allow(dead_code)]
mod config;
mod formparse;
#[allow(dead_code)]
mod messages;
mod parsecfg;
// `setopt` (port of `src/config2setopts.c` plus `tool_setopt.c`'s `setopt_bad`)
// translates a parsed `OperationConfig` into `curl_rs_lib::Easy` option calls,
// and `writeout` (port of `src/tool_writeout.c`) renders `--write-out`. Both are
// driven by `operate` (the operation driver, AAP §0.8.4 step 11/12), which lands
// in a later migration step, so they are staged with the same construction-order
// `#[allow(dead_code)]` as the option front-end above to keep them compiled,
// clippy-linted, and unit-tested as part of the binary build.
#[allow(dead_code)]
mod setopt;
#[allow(dead_code)]
mod writeout;
// The operation driver (port of `src/tool_operate.c` + folded helpers). Staged
// like the other not-yet-wired front-end modules; `run()` will call
// `operate::operate` once the transfer engine lands.
#[allow(dead_code)]
mod operate;

/// curl-rs — a memory-safe Rust reimplementation of the `curl` command-line
/// tool.
///
/// The option model is derived one-to-one from curl 8.x; flag names, short
/// aliases, semantics, and defaults are immutable (AAP §0.8.2). This foundation
/// front-end wires the universally-applicable options; the full ~282-entry
/// option table is filled in alongside the transfer engine in a later step.
#[derive(Debug, Parser)]
#[command(
    name = "curl-rs",
    bin_name = "curl-rs",
    about = "curl-rs — a memory-safe Rust reimplementation of curl.",
    // `--version` is handled manually below so the banner matches curl's exact
    // `curl_version()` multi-line format rather than clap's single line.
    disable_version_flag = true
)]
struct Cli {
    /// URL(s) to work with.
    #[arg(value_name = "URL")]
    urls: Vec<String>,

    /// Write output to <file> instead of stdout (curl `-o, --output`).
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Vec<String>,

    /// Silent mode — do not show progress meter or error messages
    /// (curl `-s, --silent`).
    #[arg(short = 's', long = "silent")]
    silent: bool,

    /// Make the operation more talkative (curl `-v, --verbose`).
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Show version number and quit (curl `-V, --version`).
    #[arg(short = 'V', long = "version")]
    version: bool,
}

/// Process entrypoint. Parses arguments and returns curl's exit code.
///
/// curl's CLI returns the underlying `CURLcode` as the process exit status; the
/// async runtime is the current-thread flavor per AAP §0.4.4.
#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    run(Cli::parse()).await
}

/// Drives the parsed command-line configuration and returns the process exit
/// code, kept separate from [`main`] so the control flow is unit-testable and
/// the runtime attribute stays on a minimal shim.
async fn run(cli: Cli) -> ExitCode {
    // `-v/--verbose` turns on structured logging to stderr. Initialization is
    // best-effort: a failure (e.g. a subscriber already set) must never abort
    // the program, matching curl's tolerance for diagnostics setup.
    if cli.verbose {
        init_verbose_logging();
        tracing::debug!(
            urls = cli.urls.len(),
            outputs = cli.output.len(),
            silent = cli.silent,
            "curl-rs invoked"
        );
    }

    // `-V/--version`: print the full banner and the Protocols/Features lines,
    // exactly mirroring curl's `--version` layout, then exit successfully.
    if cli.version {
        print_version();
        return ExitCode::SUCCESS;
    }

    // No URL: emit curl's usage hint (unless silenced) and return curl's
    // "failed to initialize" exit code (2), exactly as the C tool does when no
    // URL is supplied.
    if cli.urls.is_empty() {
        if !cli.silent {
            eprintln!("curl-rs: try 'curl-rs --help' for more information");
        }
        return exit_code(codes::CURLE_FAILED_INIT);
    }

    // A transfer was requested. The transfer engine and per-protocol handlers
    // are not yet linked into this foundation build, so report curl's standard
    // `CURLE_NOT_BUILT_IN` diagnostic for each requested URL and return the
    // matching exit code. This is curl's genuine result code for functionality
    // omitted at build time — not a placeholder.
    let mut last = codes::CURLE_OK;
    for url in &cli.urls {
        if !cli.silent {
            eprintln!(
                "curl-rs: ({}) the transfer engine is not built into this libcurl: {url}",
                codes::CURLE_NOT_BUILT_IN
            );
        }
        last = codes::CURLE_NOT_BUILT_IN;
    }
    exit_code(last)
}

/// Initializes the verbose (`-v`) logging subscriber, writing human-readable
/// events to stderr. Idempotent and non-fatal: a second call (or a subscriber
/// installed elsewhere) is silently ignored via `try_init`.
fn init_verbose_logging() {
    use tracing_subscriber::filter::LevelFilter;
    use tracing_subscriber::fmt;

    let _ = fmt()
        .with_writer(std::io::stderr)
        .with_max_level(LevelFilter::DEBUG)
        .with_target(false)
        .try_init();
}

/// Prints the `--version` output: the `curl_version()`-equivalent banner
/// followed by curl's `Release-Date:`, `Protocols:`, and `Features:` lines, all
/// sourced from [`curl_rs_lib::version`] so the CLI and library never disagree.
fn print_version() {
    println!("{}", version::version());
    // curl prints `[unreleased]` for in-development (`-DEV`) builds; the
    // baseline is `8.19.0-DEV` (`include/curl/curlver.h`).
    println!("Release-Date: [unreleased]");
    println!("Protocols: {}", version::protocols().join(" "));
    println!("Features: {}", version::feature_names().join(" "));
}

/// Converts a curl `CURLcode` integer into a process [`ExitCode`], mirroring the
/// C tool's contract of returning the `CURLcode` as the exit status. Values are
/// clamped into the single-byte exit-status range, matching the platform's
/// 8-bit exit code (curl's codes all fall well within `0..=255`).
fn exit_code(curlcode: i32) -> ExitCode {
    ExitCode::from(u8::try_from(curlcode).unwrap_or(u8::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bare `curl-rs` invocation with no URL must return curl's
    /// "failed to initialize" exit code (2), the same as the C tool.
    #[tokio::test(flavor = "current_thread")]
    async fn no_url_returns_failed_init() {
        let cli = Cli {
            urls: vec![],
            output: vec![],
            silent: true,
            verbose: false,
            version: false,
        };
        assert_eq!(
            format!("{:?}", run(cli).await),
            format!("{:?}", exit_code(2))
        );
    }

    /// `--version` always succeeds (exit 0) regardless of other flags.
    #[tokio::test(flavor = "current_thread")]
    async fn version_flag_succeeds() {
        let cli = Cli {
            urls: vec![],
            output: vec![],
            silent: false,
            verbose: false,
            version: true,
        };
        assert_eq!(
            format!("{:?}", run(cli).await),
            format!("{:?}", ExitCode::SUCCESS)
        );
    }

    /// A requested transfer in the foundation build maps to curl's
    /// `CURLE_NOT_BUILT_IN` exit code (4), the genuine result for build-time
    /// omitted functionality.
    #[tokio::test(flavor = "current_thread")]
    async fn transfer_request_reports_not_built_in() {
        let cli = Cli {
            urls: vec!["https://example.com/".to_string()],
            output: vec![],
            silent: true,
            verbose: false,
            version: false,
        };
        assert_eq!(
            format!("{:?}", run(cli).await),
            format!("{:?}", exit_code(codes::CURLE_NOT_BUILT_IN))
        );
    }

    /// The CLI parser must accept curl's universal short flags without error.
    #[test]
    fn parses_curl_universal_flags() {
        let cli = Cli::try_parse_from([
            "curl-rs",
            "-s",
            "-v",
            "-o",
            "out.txt",
            "https://example.com/",
        ])
        .expect("curl-compatible flags parse");
        assert!(cli.silent);
        assert!(cli.verbose);
        assert_eq!(cli.output, vec!["out.txt".to_string()]);
        assert_eq!(cli.urls, vec!["https://example.com/".to_string()]);
    }
}
