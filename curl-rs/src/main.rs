// curl-rs — the command-line binary crate root and process entrypoint.
//
// SPDX-License-Identifier: curl
//
// This module is the Rust reimplementation of curl's CLI entrypoint. The
// original C sources are
//   Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// and are licensed under the curl license (https://curl.se/docs/copyright.html).
//
// It is the behavioral port of one C translation unit of the `src/` CLI tree:
//   * `src/tool_main.c` / `src/tool_main.h` — the process `main()`: stderr
//     initialization (`tool_init_stderr`), the standard-descriptor guard
//     (`main_checkfds`), the `SIGPIPE` disposition, global construction
//     (`globalconf_init` -> `curl_global_init`), the call to `operate()`, the
//     teardown (`globalconf_free` -> `curl_global_cleanup`), and the
//     `return (int)result;` exit-code contract.
//
// The Windows-only paths (`win32_init`, `--dump-module-paths`, `wmain` /
// `_UNICODE`, the trailing `fflush(NULL)`), the `__VMS` `vms_special_exit`, the
// `__AMIGA__` stack cookie, and the `CURL_MEMDEBUG` `memory_tracking_init` have
// no Rust analog and are intentionally omitted: Rust's standard library and
// ownership model subsume them (AAP §0.3.2; agent brief "OUT OF SCOPE").

#![forbid(unsafe_code)]

//! `curl-rs` — a memory-safe Rust reimplementation of the `curl` command-line
//! tool, and a drop-in replacement for it.
//!
//! As a **binary crate**, this file (`main.rs`) is the crate root: it has no
//! `lib.rs`. It declares the full CLI module tree and contains the process
//! [`main`] entrypoint. The binary is a thin, safe front-end over the
//! asynchronous core library [`curl_rs_lib`]; all of the transfer, protocol,
//! TLS, and option-setter machinery lives there, and **every `unsafe` block in
//! the workspace is confined to the separate `curl-rs-ffi` crate**. The
//! crate-level `#![forbid(unsafe_code)]` attribute above makes that guarantee
//! compiler-enforced for the entire CLI crate (AAP §0.7.1).
//!
//! # Relationship to `src/tool_main.c`
//!
//! [`run`] reproduces the control flow of curl's `main()` (`src/tool_main.c`,
//! the `#ifndef UNITTESTS` body) step for step:
//!
//! | curl `main()` (C)                        | `curl-rs` ([`run`] / [`main`])               |
//! |------------------------------------------|----------------------------------------------|
//! | `tool_init_stderr()`                     | `messages::init_stderr()`                    |
//! | `main_checkfds()`                        | documented no-op (see [`run`])               |
//! | `signal(SIGPIPE, SIG_IGN)`               | Rust std default (see [`run`])               |
//! | `globalconf_init()` (config + lib init)  | [`GlobalConfig::new`] + [`global_init`]      |
//! | `operate(argc, argv)`                    | [`operate`]`(&mut global, args).await`       |
//! | `globalconf_free()` (lib cleanup + free) | [`global_cleanup`] + `GlobalConfig::globalconf_free` |
//! | `return (int)result;`                    | [`std::process::exit`]`(code)`               |
//!
//! # Runtime model (AAP §0.4.4)
//!
//! The CLI runs on a lightweight **single-threaded** Tokio runtime
//! (`#[tokio::main(flavor = "current_thread")]`), which is sufficient for the
//! one-shot transfers a command-line invocation performs. The multi-threaded
//! runtime is reserved for the `curl_multi_*` path inside [`curl_rs_lib`] (used
//! only by `--parallel`), so this crate enables only Tokio's `rt` + `macros`
//! features.
//!
//! # Exit-code contract
//!
//! curl's CLI returns the underlying `CURLcode` as the process exit status
//! (`return (int)result;`). [`operate`] yields that numeric [`CurlCode`]
//! directly, and [`main`] delivers it verbatim via [`std::process::exit`] so
//! that distinct errors keep distinct codes — they are never collapsed by `?`
//! or by `anyhow`.

use std::ffi::OsString;
use std::io::Write as _;

use curl_rs_lib::error::codes;
use curl_rs_lib::{global_cleanup, global_init, CurlCode};

use crate::config::GlobalConfig;
use crate::operate::operate;

// -- CLI module tree ---------------------------------------------------------
//
// Every sibling source file plus the `callbacks/` subfolder is declared here so
// the binary crate is complete. Each module ports the curl `src/tool_*.c`
// translation unit named in its own header. With [`operate`] wired into [`run`]
// below, the diagnostics facility (`messages`) and the option / `--write-out`
// bridge (`setopt`, `writeout`, `writeout_json`) are fully exercised from
// `main`.
//
// Construction-order staging: a handful of modules expose items that become
// reachable only once the transfer-execution integration is in place (AAP
// §0.8.4 steps 11–13) — when `curl_rs_lib::Easy::perform` drives a real transfer
// and the core's Rust-native callback bridge invokes the CLI callbacks. The
// affected items are the per-transfer callback bodies (`callbacks`: the
// write/read/seek/header/progress/debug functions, which the transfer engine
// drives through `curl_rs_lib::transfer::{WriteCallbacks, ReadCallback}` — this
// CLI crate is `#![forbid(unsafe_code)]`, so it routes them Rust-natively rather
// than as C-ABI function pointers), curl's home / `.curlrc` / `.netrc` file
// finders (`operate`'s `findfile` / `checkhome`), some option-table helpers
// (`args`, `config`), and the glob-in-use query (`urlglob`). These items are
// part of the full CLI port; until the transfer drive reaches them they would
// trip the workspace `-D warnings` gate, so those five module declarations carry
// `#[allow(dead_code)]` to keep the not-yet-driven (never the *incomplete*) code
// compiled, clippy-linted, and unit-tested. (`formparse` and `parsecfg` carry
// their own inner `#![allow(dead_code)]`, so they need none here; `messages`,
// `setopt`, `writeout`, and `writeout_json` are fully live.) Each allow becomes
// unnecessary — and is dropped — once the transfer drive invokes that module.
#[allow(dead_code)]
mod args;
#[allow(dead_code)]
mod callbacks;
#[allow(dead_code)]
mod config;
mod formparse;
mod messages;
#[allow(dead_code)]
mod operate;
mod parsecfg;
mod setopt;
#[allow(dead_code)]
mod urlglob;
mod writeout;
mod writeout_json;

/// `CURL_GLOBAL_DEFAULT` — the `CURL_GLOBAL_*` bitmask curl's CLI passes to
/// `curl_global_init` (`src/tool_cfgable.c`: `globalconf_init` calls
/// `curl_global_init(CURL_GLOBAL_DEFAULT)`).
///
/// `CURL_GLOBAL_DEFAULT == CURL_GLOBAL_ALL == CURL_GLOBAL_SSL | CURL_GLOBAL_WIN32
/// == 3` (`include/curl/curl.h`). The canonical `CURL_GLOBAL_*` constants live
/// in the FFI crate (`curl-rs-ffi`), which this binary must **not** depend on:
/// the workspace dependency graph is strictly one-directional — the CLI and FFI
/// leaf crates depend only on `curl-rs-lib`, never on each other (AAP §0.4). The
/// value is therefore reproduced here as a private literal. [`global_init`]
/// accepts any bitmask (the rustls-based core has no per-flag subsystem to
/// toggle), so passing the canonical default keeps observable behavior
/// identical to curl's.
const CURL_GLOBAL_DEFAULT: i64 = 3;

/// Installs the process-wide [`tracing`] subscriber used for **internal library
/// diagnostics**, writing to `stderr`.
///
/// # Why this is silent by default
///
/// The user-facing `-v` / `--trace` / `--trace-ascii` output is **not** routed
/// through `tracing`: `callbacks::debug` writes those bytes directly to the
/// resolved trace stream because curl's regression suite diffs them
/// byte-for-byte, and `tracing`'s own framing (levels, spans, timestamps) would
/// corrupt that output (AAP §0.7.3, §0.8.2). This subscriber therefore exists
/// only so that internal diagnostic events emitted elsewhere in the workspace
/// have a sink, and it defaults to `LevelFilter::OFF` so it never pollutes the
/// `stderr` the suite inspects. A developer can opt in by setting `RUST_LOG`
/// (e.g. `RUST_LOG=debug`); the value is parsed as a `LevelFilter`.
///
/// Initialization is best-effort and non-fatal: a second call, or a subscriber
/// already installed by a test, is ignored via `try_init`, mirroring curl's
/// tolerance of diagnostics setup. `tracing-subscriber` is built here without
/// its `env-filter` feature, so the lightweight `LevelFilter` parse is used
/// rather than a full `EnvFilter` (which keeps the dependency set minimal).
fn init_tracing() {
    use tracing_subscriber::filter::LevelFilter;
    use tracing_subscriber::fmt;

    // Default OFF (no output) unless RUST_LOG names a level — this guarantees
    // curl's observable stderr is unaffected in normal use.
    let level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|raw| raw.parse::<LevelFilter>().ok())
        .unwrap_or(LevelFilter::OFF);

    // `with_target(false)` keeps any opted-in line free of module-path noise;
    // the writer is `stderr`, matching curl's diagnostic stream.
    let _ = fmt()
        .with_writer(std::io::stderr)
        .with_max_level(level)
        .with_target(false)
        .try_init();
}

/// Performs startup, drives [`operate`], tears down, and returns curl's numeric
/// [`CurlCode`] exit status.
///
/// Factored out of [`main`] so the control flow is independent of the
/// `#[tokio::main]` attribute and can be exercised by unit tests. This is the
/// Rust analog of the `#ifndef UNITTESTS` body of curl's `main()`
/// (`src/tool_main.c`); each step is annotated with its C counterpart.
async fn run(args: Vec<OsString>) -> CurlCode {
    // C: `tool_init_stderr()` — point the diagnostic stream at `stderr` before
    // anything can emit a warning or error.
    messages::init_stderr();

    // Internal-diagnostics sink (see `init_tracing`); silent unless `RUST_LOG`
    // is set, so curl's observable `stderr` is unaffected.
    init_tracing();

    // C: `main_checkfds()` ensures fds 0/1/2 are open by opening `/dev/null`
    // onto any closed standard descriptor, so the first sockets curl opens are
    // never mistaken for stdin/stdout/stderr. That trick manipulates raw
    // integer fds via `fcntl`/`pipe`, which cannot be done without `unsafe` —
    // and this crate is `#![forbid(unsafe_code)]`. Rust's standard library
    // already provides the `Stdin`/`Stdout`/`Stderr` handles regardless of the
    // OS fd state, so this is a deliberate, documented no-op rather than an
    // `unsafe` re-implementation.

    // C: `signal(SIGPIPE, SIG_IGN)`. The Rust standard library already installs
    // `SIG_IGN` for `SIGPIPE` during runtime startup (so a broken pipe surfaces
    // as a write error instead of terminating the process), which matches curl
    // exactly. No action — and no `unsafe` signal handling — is needed here.

    // C: `globalconf_init()` part 1 — allocate the global configuration with
    // curl's defaults and one initial operation block. This cannot fail.
    let mut global = GlobalConfig::new();

    // C: `globalconf_init()` part 2 — `curl_global_init(CURL_GLOBAL_DEFAULT)`.
    // "Call this before _any_ libcurl usage." On failure curl prints
    // "error initializing curl library" and returns without running a transfer.
    // `curl_rs_lib::global_init` is idempotent and currently infallible, but its
    // `Result` contract is honored so any future failure maps to curl's
    // `CURLE_FAILED_INIT` exactly as the C tool does.
    if global_init(CURL_GLOBAL_DEFAULT).is_err() {
        messages::errorf(&global, "error initializing curl library");
        return codes::CURLE_FAILED_INIT;
    }

    // C: `operate(argc, argv)` — the operation driver owns *all* of argument
    // parsing (including `--help` / `--version` / `.curlrc`), option
    // application, and the serial/parallel transfer loops, and returns curl's
    // numeric result code. `args` is the full argv (program name at index 0),
    // exactly as C passes `argv`.
    let result = operate(&mut global, args).await;

    // C: `globalconf_free()` — `curl_global_cleanup()` then release the CLI
    // configuration. The order mirrors curl (library teardown first). In Rust
    // the two are independent and the owned data also drops automatically, but
    // the explicit calls keep the C teardown call site one-to-one.
    global_cleanup();
    global.globalconf_free();

    result
}

/// Process entrypoint — the Rust analog of curl's `main()` (`src/tool_main.c`).
///
/// Runs on Tokio's current-thread runtime (AAP §0.4.4), collects the full argv
/// (via [`std::env::args_os`], preserving non-UTF-8 bytes the way curl tolerates
/// arbitrary argv), drives [`run`], flushes the standard streams, and exits with
/// curl's numeric result code.
#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Collect argv as `OsString`s: curl reads argv as raw C strings, and
    // `args_os` preserves bytes that are not valid UTF-8 (which `operate` then
    // converts losslessly for option parsing). Index 0 is the program name,
    // matching C's `argv[0]`.
    let args: Vec<OsString> = std::env::args_os().collect();

    let code: CurlCode = run(args).await;

    // C performs a final `fflush(NULL)` (under `_WIN32`); flush the standard
    // streams unconditionally here so no buffered output is lost before the
    // process exits via `process::exit` (which does not run destructors).
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();

    // C: `return (int)result;`. `process::exit` delivers the full integer code
    // as the process exit status (the OS masks it to 8 bits exactly as it does
    // for the C tool, and curl's codes all fall well within `0..=255`). All
    // meaningful teardown ran inside `run`, so bypassing destructor unwinding
    // here is safe and reproduces curl's contract precisely.
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an argv vector (program name first, as `operate` expects).
    fn argv(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
    }

    /// `--version` is an informational request: `operate` renders the version
    /// banner and returns `CURLE_OK` (0). The leading `-q` disables `.curlrc`
    /// so the result never depends on a config file in the test environment.
    #[tokio::test(flavor = "current_thread")]
    async fn version_request_exits_ok() {
        assert_eq!(
            run(argv(&["curl-rs", "-q", "--version"])).await,
            codes::CURLE_OK
        );
    }

    /// `--help` is likewise informational and exits successfully (0).
    #[tokio::test(flavor = "current_thread")]
    async fn help_request_exits_ok() {
        assert_eq!(
            run(argv(&["curl-rs", "-q", "--help"])).await,
            codes::CURLE_OK
        );
    }

    /// The local `CURL_GLOBAL_DEFAULT` literal equals curl's canonical
    /// `CURL_GLOBAL_ALL` (`CURL_GLOBAL_SSL | CURL_GLOBAL_WIN32 == 3`), keeping
    /// the value the CLI passes to `global_init` identical to curl's.
    #[test]
    fn global_default_matches_curl() {
        assert_eq!(CURL_GLOBAL_DEFAULT, 1 | 2);
    }
}
