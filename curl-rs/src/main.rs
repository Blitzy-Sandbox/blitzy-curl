// SPDX-License-Identifier: curl
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// Rust rewrite of curl's src/tool_main.c (curl-rs binary entrypoint).

//! # curl-rs — command-line entry point
//!
//! Language rewrite of curl 8.19.0-DEV's `src/tool_main.c` (the process entry point) with the
//! diagnostic-stream initialization of `src/tool_stderr.c` (`tool_init_stderr`) absorbed into
//! the startup sequence. This is the **binary crate root** of the three-crate workspace: it
//! drives the safe-Rust core (`curl-rs-lib`) from a `clap`-based command line and runs on a
//! **current-thread** Tokio runtime, matching curl 8.x's single-threaded CLI model
//! (AAP §0.3.2). The multi handle's own multi-thread executor lives inside `curl-rs-lib` and
//! powers parallel transfers when `--parallel` is used.
//!
//! ## Fidelity to `src/tool_main.c`
//!
//! `main` reproduces curl's startup sequence in order — diagnostic-stream init, the
//! standard-descriptor safety check (`main_checkfds`), `SIGPIPE` handling, one-time library
//! init, the transfer dispatch (`operate`), library teardown, and an exit status equal to the
//! returned [`CurlCode`](curl_rs_lib::CurlCode) integer (exit-code parity, AAP §0.7.1). The
//! platform- and build-specific steps that do not apply to the supported target set are
//! deliberately dropped: the Windows `--dump-module-paths` diagnostic and `win32_init`
//! (Windows is not a target platform, AAP §0.6.5) and `memory_tracking_init` (subsumed by
//! Rust's ownership model, AAP §0.5.2).
//!
//! ## Frozen flag contract
//!
//! No command-line flag is invented or altered here; the full curl 8.x flag surface is defined
//! 1:1 from `docs/cmdline-opts/` in [`args`], and the informational short-circuits
//! (`--help` / `--version` / `--manual` / …) are handled inside [`operate::operate`]. In
//! particular the `--version` banner text is owned by the library
//! ([`curl_rs_lib::version`]) so the CLI and the FFI `curl_version()` report the identical
//! string.

// ===========================================================================================
// Sibling module declarations.
//
// Because `curl-rs/Cargo.toml` sets `[[bin]] path = "src/main.rs"`, this file is the crate
// root and MUST declare every other module in the `curl-rs` crate (curl's `src/tool_*.c`
// language rewrites). They are declared here even where `main` does not drive them directly:
// the argument, option-application, and dispatch layers consume one another's exports, and the
// crate root is the single place their module tree is rooted.
// ===========================================================================================

// Command-line configuration model + argument parser (rewrite of `src/tool_getparam.c`,
// `src/tool_paramhlp.c`, `src/tool_cfgable.c`). Defines the `OperationConfig` / `GlobalConfig`
// / `State` vocabulary, the `ParameterError` set, the `Diag` diagnostic snapshot, and the full
// curl 8.x flag surface parsed 1:1 from `docs/cmdline-opts/`. Every other CLI sub-module
// consumes the types it exports.
mod args;

// Config-file parser and default-config discovery (rewrite of `src/tool_parsecfg.c` +
// `src/tool_findfile.c`). Reads `.curlrc` / `-K` files and dispatches each directive back to
// `args::getparameter` through the `args::ConfigParserHook`; `main` installs
// `parsecfg::config_parser_hook` below.
mod parsecfg;

// Transfer dispatch loop — serial and parallel (rewrite of `src/tool_operate.c` plus
// `tool_operhlp.c` / `tool_ssls.c` / `tool_helpers.c`, absorbing `tool_msgs.c` and
// `tool_stderr.c`). Owns argument parsing, the informational short-circuits, the redirectable
// `warnf`/`notef`/`errorf`/`helpf` diagnostics, and the per-transfer lifecycle. `main`
// delegates the whole operation to [`operate::operate`].
mod operate;

// Easy-handle configuration and `--libcurl` C-source emission (rewrite of
// `src/config2setopts.c` + `src/tool_setopt.c` + `src/tool_easysrc.c`). Translates a parsed
// `OperationConfig`/`GlobalConfig` into a `curl-rs-lib` easy handle; the `--libcurl` C-source
// machinery is gated behind the default-on `libcurl-option` feature. Driven by `operate`.
mod setopt;

// URL globbing engine (rewrite of `src/tool_urlglob.c`). Implements curl's own `{a,b}` /
// `[1-10]` URL-expansion mini-language (distinct from filesystem globbing). Consumed by
// `operate` to expand a command-line URL into concrete transfers.
mod urlglob;

// `-F` / `--form` multipart parser (rewrite of `src/tool_formparse.c`). Parses one
// `-F`/`--form-string` argument into the CLI-side MIME tree and later converts that tree into a
// `curl-rs-lib` mime object. `main` installs `formparse::form_parser_hook` below.
mod formparse;

// The `--variable` store and `{{name:func}}` expansion engine (rewrite of `src/var.c`). Owns
// the higher-level `--variable` / `--expand-<opt>` semantics over the `args::ToolVar` store:
// `setvariable` parses one `--variable` definition and `varexpand` substitutes
// `{{name}}` / `{{name:func:func}}` templates. `main` installs `var::setvariable` and
// `var::varexpand` as the `args::VariableSetterHook` / `args::VariableExpanderHook` below, so
// the argument layer can drive them while parsing.
mod var;

// The `--write-out` / `-w` format engine (rewrite of `src/tool_writeout.c`). Defines the shared
// variable catalogue and the format-string interpreter, applied after each transfer.
mod writeout;

// The `%{json}` / `%{header_json}` emitters plus shared JSON string quoting (rewrite of
// `src/tool_writeout_json.c`). Renders the write-out variable table in JSON mode and exports
// `json_quoted` for the `--variable` `:json` value function in `var.rs`.
mod writeout_json;

// `--parallel` aggregate progress meter and byte formatter (rewrite of `src/tool_progress.c`).
// Consumed by the parallel-transfer dispatch loop in `operate`. The single-transfer progress
// bar lives in `callbacks` (rewrite of `src/tool_cb_prg.c`), not here.
mod progress_display;

// Terminal-geometry and capability probing (rewrite of `src/terminal.c`). Provides the
// terminal width used for help/diagnostic wrapping; contains a narrow OS primitive.
mod terminal;

// Interactive no-echo password prompt (rewrite of `src/tool_getpass.c`). Consumed by the
// argument/operation layer when a required password is not supplied on the command line
// (for example `-u user:` with an empty password or an SSH key passphrase).
mod getpass;

// IPFS/IPNS gateway URL rewriting (rewrite of `src/tool_ipfs.c`). Gated behind the default-on
// `ipfs` feature, mirroring curl's `#ifndef CURL_DISABLE_IPFS` (and the matching
// `#[cfg(feature = "ipfs")]` guard on `OperationConfig::ipfs_gateway`); declaring the module
// under the same guard keeps a `--no-default-features` build (ipfs off) compiling cleanly.
#[cfg(feature = "ipfs")]
mod ipfs;

// File-time get/set plus portable local-time conversion (rewrite of `src/tool_filetime.c`).
// `getfiletime` feeds `-z` / `--time-cond`; `setfiletime` stamps the output file for
// `-R` / `--remote-time`. Implemented entirely with safe `std::fs` + `chrono`.
mod filetime;

// Extended-attribute metadata writer (rewrite of `src/tool_xattr.c`). Consumed by the
// post-transfer path when `--xattr` is set, to record the origin URL, referrer, and MIME type
// on the downloaded output file; contains a narrow OS primitive.
mod xattr;

// libcurl-parity CLI callbacks (rewrite of curl's `src/tool_cb_*.c`). Defines the output-sink
// model plus the write/read/header/progress/debug/seek/socket callbacks that mirror libcurl's
// C callback signatures. Consumed by `operate` and `setopt`.
mod callbacks;

use std::ffi::OsString;

/// Ensure the three standard file descriptors (stdin=0, stdout=1, stderr=2) are open before any
/// transfer begins — a faithful port of curl's `main_checkfds` (`src/tool_main.c`).
///
/// If one of the standard descriptors is closed at startup, the first network socket (or output
/// file) curl opens would be assigned that low descriptor number and would therefore *become*
/// stdin/stdout/stderr: a downloaded body, an upload source, or an error log could then be read
/// from or written to what the rest of the program (and the user's shell redirections) believe
/// is a standard stream. curl closes this hole by opening throwaway `pipe()` descriptors until
/// 0/1/2 are all occupied; per the AAP this port opens `/dev/null` onto each closed descriptor
/// instead, which provides the identical guarantee (the low descriptors are held by an inert
/// file) while keeping the reopen itself in safe `std::fs`.
///
/// Returns `true` on failure — a closed descriptor could not be reopened — matching the C
/// function's non-zero (error) return, which curl maps to `CURLE_FAILED_INIT`.
///
/// This is one of the AAP §0.6.2 "narrow OS-integration primitives" for which `unsafe` is
/// permitted outside the FFI crate: querying whether a raw descriptor is open genuinely
/// requires the `fcntl(fd, F_GETFD)` syscall. Each `unsafe` block is tightly scoped and carries
/// a `// SAFETY:` comment.
#[cfg(unix)]
fn main_checkfds() -> bool {
    use std::os::unix::io::IntoRawFd;

    // The three standard descriptors, lowest first. Repairing them in ascending order
    // guarantees that when a closed descriptor is reached, every lower descriptor is already
    // open, so `open("/dev/null")` — which returns the lowest free descriptor — lands exactly
    // on the descriptor being repaired.
    for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: `fcntl` with the `F_GETFD` command only reads the descriptor's close-on-exec
        // flag; it performs no allocation, writes to no memory, and cannot violate any Rust
        // invariant. `fd` is one of the three small standard-descriptor integer constants. The
        // call returns -1 (with errno `EBADF`) precisely when the descriptor is closed.
        let is_open = unsafe { libc::fcntl(fd, libc::F_GETFD) } != -1;
        if is_open {
            continue;
        }

        // The descriptor is closed: occupy it with an inert file so a later socket/file cannot
        // inherit it. Opening `/dev/null` itself is entirely safe `std::fs`.
        let dev_null = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
        {
            Ok(file) => file,
            // curl's `pipe()` failing here is its "out of file descriptors" condition.
            Err(_) => return true,
        };

        // Leak the descriptor so it remains open for the rest of the process, exactly as curl
        // leaves its `pipe()` descriptors open. `into_raw_fd` transfers ownership out of the
        // `File`, so the `File` destructor will not close it.
        let opened = dev_null.into_raw_fd();
        if opened != fd {
            // `/dev/null` did not land on the descriptor under repair (a lower descriptor was
            // unexpectedly free). Do not leave a standard descriptor pointing at the wrong
            // place: close the stray descriptor and report failure.
            //
            // SAFETY: `opened` is a descriptor this function has just obtained from a
            // successfully opened file and now exclusively owns — the `File` was consumed by
            // `into_raw_fd`, so there is no other owner and hence no aliasing and no double
            // close. `close` has no memory effects.
            unsafe {
                libc::close(opened);
            }
            return true;
        }
    }
    false
}

/// Non-Unix fallback for [`main_checkfds`]. The supported target set is Linux and macOS
/// (both Unix); Windows and the other legacy platforms are out of scope (AAP §0.6.5). On any
/// hypothetical non-Unix build the standard descriptors are guaranteed open by the runtime, so
/// the check is a no-op that always reports success.
#[cfg(not(unix))]
fn main_checkfds() -> bool {
    false
}

/// Process entry point — a faithful port of curl's `main` (`src/tool_main.c`).
///
/// Runs on a **current-thread** Tokio runtime to match curl 8.x's single-threaded CLI model
/// (AAP §0.3.2). The startup sequence mirrors the C `main`: initialize the diagnostic stream,
/// guarantee the standard descriptors are open, keep `SIGPIPE` ignored, install the structured
/// diagnostic subscriber, build the process-global configuration and wire its parser hooks, run
/// the library's one-time init, dispatch to [`operate::operate`], tear the library and
/// configuration down, and exit with the exact returned [`CurlCode`](curl_rs_lib::CurlCode)
/// integer.
#[tokio::main(flavor = "current_thread")]
async fn main() {
    // (1) Initialize the diagnostic stream to the real stderr before any message can be
    // emitted — curl's very first call, `tool_init_stderr()`. A later `--stderr <file>` may
    // redirect it once parsing discovers the flag (applied inside `operate`).
    operate::tool_init_stderr();

    // (2) The Windows `--dump-module-paths` diagnostic and `win32_init()` are not carried
    // forward: Windows is not a supported target platform (AAP §0.6.5).

    // (3) Guarantee stdin/stdout/stderr are open, reopening any closed one onto `/dev/null` so
    // a subsequent socket cannot masquerade as a standard stream (curl's `main_checkfds`). On
    // failure curl prints "out of file descriptors" and returns `CURLE_FAILED_INIT`; reproduce
    // both, including the literal `curl: ` error prefix, via the diagnostic helpers. Nothing
    // has been initialized yet (this is pre-`global_init`), so no teardown is required on this
    // path — exactly like the C `return CURLE_FAILED_INIT`.
    if main_checkfds() {
        operate::errorf(args::Diag::default(), "out of file descriptors");
        std::process::exit(curl_rs_lib::CurlCode::FailedInit.to_i32());
    }

    // (4) SIGPIPE: curl calls `signal(SIGPIPE, SIG_IGN)` so that writing to a peer that has
    // closed the connection yields an `EPIPE` error to handle rather than killing the process.
    // Rust's standard runtime already installs `SIG_IGN` for `SIGPIPE` at startup, which is the
    // identical behavior, so no explicit action is required here. curl's `memory_tracking_init`
    // is likewise dropped — allocation tracking is subsumed by Rust's ownership model
    // (AAP §0.5.2).

    // (5) Install the process's single `tracing` subscriber. `curl-rs-lib` emits its internal
    // diagnostics (SSH auth steps, the rustls cipher parser, and so on) through the `tracing`
    // facade; this subscriber renders those events to the diagnostic stream (stderr). The
    // filter is read from `RUST_LOG` and DEFAULTS TO `OFF`, so an ordinary invocation emits
    // nothing extra and curl 8.x's exact stderr output is preserved for downstream log scrapers
    // (AAP §0.7.3); setting e.g. `RUST_LOG=curl=trace` opts into the library's structured trace
    // vocabulary for debugging. curl's user-facing `--verbose`/`--trace` output is produced
    // separately by the debug callback (`callbacks`) writing through the CLI `Diag` sink and is
    // unaffected by this subscriber's level.
    let env_filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing_subscriber::filter::LevelFilter::OFF.into())
        .with_env_var("RUST_LOG")
        .from_env_lossy();
    // `try_init` returns `Err` only if a global subscriber has already been installed, which
    // cannot happen from this single entry point; ignore the result so it can never panic.
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(env_filter)
        .try_init();

    // (6a) Build the process-global CLI configuration (curl's `globalconf_init`). Infallible
    // here — the operation chain, defaults, and empty stores are established by construction.
    let mut global = args::GlobalConfig::globalconf_init();

    // (6b) Wire the parser hooks that break the module-dependency cycle, so the argument layer
    // can call back into the specialized parsers while it parses:
    //   * `--config` / `-K`      -> `parsecfg::config_parser_hook`
    //   * `-F` / `--form*`       -> `formparse::form_parser_hook`
    //   * `--variable`           -> `var::setvariable`   (stores the definition)
    //   * `--expand-<opt>`       -> `var::varexpand`     (expands `{{name}}` templates)
    // The `GlobalConfig` field contracts state these are `None` until `main` wires them; wiring
    // all four here is what makes `--variable` / `--expand-` functional (unset, they would be
    // accepted but silently do nothing — a parity gap).
    global.config_parser = Some(parsecfg::config_parser_hook);
    global.form_parser = Some(formparse::form_parser_hook);
    global.variable_setter = Some(var::setvariable);
    global.variable_expander = Some(var::varexpand);

    // (6c) Library one-time, process-wide initialization (curl's `curl_global_init`). No
    // library function is called before this point; paired with `global_cleanup` below.
    curl_rs_lib::global_init();

    // (7) Collect the full argument vector *including* `argv[0]`; `operate` mirrors curl's
    // argc/argv indexing, so `argv[1]` is the first real argument.
    let argv: Vec<OsString> = std::env::args_os().collect();

    // Start the curl operation. `operate` owns argument parsing, the informational
    // short-circuits (`--help` / `--version` / …), the share, and the transfer dispatch loop;
    // it returns the process exit code as a `CurlCode`.
    let result = operate::operate(&mut global, &argv).await;

    // (8) Library teardown (curl's `curl_global_cleanup`), then release the global
    // configuration (curl's `globalconf_free`). The explicit `drop` is required: the final
    // `std::process::exit` below terminates the process *without* running destructors, so
    // relying on scope-end RAII would skip any flush/close the configuration performs.
    curl_rs_lib::global_cleanup();
    drop(global);

    // (9) curl returns `(int)result` from `main`; reproduce the exact exit status. The OS
    // truncates the status to the low 8 bits identically to the C `return (int)result`, so the
    // shell observes the same exit code curl 8.x returns for the identical invocation
    // (exit-code parity, AAP §0.7.1).
    std::process::exit(result.to_i32());
}
