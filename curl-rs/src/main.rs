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
// The `--variable` store and `{{name:func}}` expansion engine (Rust rewrite of `src/var.c`).
// Owns the higher-level `--variable`/`--expand-<opt>` semantics over the `args::ToolVar` store
// held in `GlobalConfig::variables`: `setvariable` parses one `--variable` definition
// (`name=text`, `name@file`, `%name` env import, `name[start-end]` byte range) and `varexpand`
// substitutes `{{name}}` / `{{name:func:func}}` templates (the `trim`/`json`/`url`/`b64`/`64dec`
// functions). The argument layer installs these as the `args::VariableSetterHook` /
// `args::VariableExpanderHook` function pointers; the wiring is performed by the
// operation-dispatch layer in a later checkpoint (AAP §0.7.3). `var.rs` reuses
// `writeout_json::json_quoted` for its `:json` function, exactly as curl's `src/var.c` includes
// `tool_writeout_json.h`.
mod var;
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

// libcurl-parity CLI callbacks (Rust rewrite of curl's `src/tool_cb_*.c`). Defines the
// `OutStruct`/`OutSink` output-sink model plus the write/read/header/progress/debug/seek/socket
// callbacks. Consumed by the operation-dispatch layer (`operate.rs`) and the option-application
// layer (`setopt.rs`).
mod callbacks;

// Transfer dispatch loop — serial and parallel (Rust rewrite of curl's `src/tool_operate.c`
// plus `tool_operhlp.c` / `tool_ssls.c` / `tool_helpers.c`, absorbing `tool_msgs.c` /
// `tool_stderr.c`). Drives every transfer, owns the per-transfer lifecycle and retry/etag
// logic, and hosts the redirect-aware `warnf`/`notef`/`errorf`/`helpf` diagnostics.
mod operate;

use std::ffi::OsString;

/// Process entry point — a faithful port of curl's `main` (`src/tool_main.c`). It sets up the
/// diagnostic stream, initializes the process-global configuration and its parser hooks, runs
/// the library's one-time init, dispatches to [`operate::operate`], and exits with the exact
/// [`CurlCode`](curl_rs_lib::CurlCode) the operation returned (exit-code parity, AAP §0.7.3).
///
/// Runs on a **current-thread** Tokio runtime to match curl 8.x's single-threaded CLI model
/// (AAP §0.3.2); the multi handle's own multi-thread executor (owned inside `curl-rs-lib`)
/// drives parallel transfers when `--parallel` is used.
#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Initialize the diagnostic stream to real stderr before any message can be emitted
    // (curl's very first call, `tool_init_stderr()`); `--stderr <file>` may redirect it later
    // once parsing discovers the flag (applied inside `operate`).
    operate::tool_init_stderr();

    // curl's `main_checkfds()` (reopen closed std fds to /dev/null), SIGPIPE ignore, and
    // `memory_tracking_init()` are intentionally not carried forward: the standard streams are
    // guaranteed open by the Rust runtime, SIGPIPE handling requires an `unsafe` libc call
    // (disallowed outside the FFI crate) and is moot without socket I/O, and allocation
    // tracking is subsumed by Rust ownership (AAP §0.5.2). Marked NOTE(parity).

    // Collect the full argument vector *including* argv[0]; `operate` mirrors curl's argc/argv
    // indexing (so `argv[1]` is the first real argument).
    let argv: Vec<OsString> = std::env::args_os().collect();

    // Initialize the process-global CLI configuration (curl's `globalconf_init`). Infallible
    // here — the operation chain, defaults, and empty stores are set by construction.
    let mut global = args::GlobalConfig::globalconf_init();

    // Wire the parser hooks that break the module-dependency cycle: `--config`/`-K` dispatches
    // through `parsecfg`, and `-F`/`--form` through `formparse`. (`--variable` / `--expand-`
    // have no wired backend at this checkpoint and are accepted as no-ops per the field
    // contract on `GlobalConfig`.)
    global.config_parser = Some(parsecfg::config_parser_hook);
    global.form_parser = Some(formparse::form_parser_hook);

    // Library one-time, process-wide initialization (curl's `curl_global_init`); paired with
    // `global_cleanup` below.
    curl_rs_lib::global_init();

    // Start the curl operation. `operate` owns argument parsing, the informational
    // short-circuits (`--help`/`--version`/…), the share, and the transfer dispatch loop; it
    // returns the process exit code.
    let result = operate::operate(&mut global, &argv).await;

    // Library teardown (curl's `curl_global_cleanup`). `global` — the operation chain, the
    // variable store, and any open streams — is released by RAII when it drops at scope end
    // (curl's `globalconf_free`).
    curl_rs_lib::global_cleanup();

    // curl returns `(int)result` from `main`; reproduce the exact exit code.
    std::process::exit(result.to_i32());
}
