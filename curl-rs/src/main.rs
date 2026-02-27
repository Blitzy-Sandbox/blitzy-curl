// -----------------------------------------------------------------------
// curl-rs/src/main.rs — Tokio Current-Thread Binary Entrypoint
//
// Rust rewrite of `src/tool_main.c` and `src/tool_main.h` from
// curl 8.19.0-DEV.  This is the binary entry point for the curl-rs
// CLI tool.
//
// # Initialization Sequence
//
// The initialization order is critical and mirrors the C implementation
// exactly:
//
// 1. **stderr initialization** — `tool_init_stderr()` must be called
//    before any diagnostic output to set up the global stderr handle.
// 2. **Signal handling** — SIGPIPE is effectively ignored via Rust's
//    I/O error model.  All write sites handle `BrokenPipe` errors
//    gracefully, matching the C `signal(SIGPIPE, SIG_IGN)` behavior.
// 3. **Global configuration init** — `globalconf_init()` initializes
//    the underlying curl library and creates the root configuration
//    object.
// 4. **Operation execution** — `operate()` parses arguments, sets up
//    transfers, and executes serial/parallel operations.
// 5. **Cleanup** — `globalconf_free()` releases all resources.
// 6. **Exit** — Process exits with the CurlError integer code,
//    matching C `return (int)result`.
//
// # Async Runtime
//
// Per AAP Section 0.4.4, the CLI binary uses Tokio's current-thread
// flavor for single-threaded cooperative async execution suitable for
// sequential command-line operations.  The `--parallel` flag (if
// exercised) spawns concurrent transfers on the same thread using
// cooperative scheduling.
//
// # C Code Not Ported
//
// The following C-specific constructs from `tool_main.c` are
// intentionally omitted in the Rust rewrite:
//
// - `main_checkfds()` — ensures fd 0/1/2 are open.  Not needed in
//   Rust; the standard library handles missing descriptors gracefully
//   and network sockets are never aliased to stdin/stdout/stderr.
//
// - `memory_tracking_init()` — `CURL_MEMDEBUG`/`CURL_MEMLIMIT`
//   infrastructure for debugging C `malloc`/`free`.  Completely
//   replaced by Rust's ownership and borrowing model, which provides
//   compile-time memory safety without runtime tracking.
//
// - `_CRT_glob` (MinGW glob suppression) — not applicable; Rust's
//   `std::env::args()` returns arguments as-is without shell globbing.
//
// - `min_stack[]` (Amiga stack reservation) — Amiga is out of scope
//   for the Rust rewrite.
//
// - `vms_special_exit()` — VMS platform support is out of scope.
//
// - `GetLoadedModulePaths()` / `--dump-module-paths` — Windows-only
//   diagnostic; can be added in a future Windows-specific module.
//
// - `win32_init()` — Windows-specific Winsock initialization.  Tokio
//   handles Winsock initialization automatically on Windows.
//
// # Safety
//
// This module contains **zero** `unsafe` blocks.
//
// SPDX-License-Identifier: curl
// -----------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Module declarations — every module in the curl-rs binary crate.
//
// This list must include ALL modules that exist in this crate's `src/`
// directory.  The order matches the logical grouping used in the C
// source tree: argument parsing, callbacks, configuration, I/O helpers,
// protocol helpers, output formatting, and utilities.
// ---------------------------------------------------------------------------

mod args;
mod callbacks;
mod config;
mod dirhier;
mod filetime;
mod findfile;
mod formparse;
mod getpass;
mod help;
mod ipfs;
mod libinfo;
mod msgs;
mod operate;
mod operhlp;
mod paramhelp;
mod parsecfg;
mod progress_display;
mod setopt;
mod ssls;
mod stderr;
mod terminal;
mod urlglob;
mod util;
mod var;
mod writeout;
mod writeout_json;
mod xattr;

// ---------------------------------------------------------------------------
// Main entrypoint
// ---------------------------------------------------------------------------

/// Binary entrypoint for the curl-rs CLI tool.
///
/// Uses Tokio's current-thread runtime for single-threaded cooperative
/// async execution.  The initialization sequence, error handling, and
/// exit code semantics mirror `src/tool_main.c` exactly.
///
/// # Exit Codes
///
/// The process exit code is the integer value of the `CurlError` enum,
/// matching the C `return (int)result` behavior:
///
/// | Code | Meaning                            |
/// |------|------------------------------------|
/// |    0 | `CurlError::Ok` — success          |
/// |    2 | `CurlError::FailedInit`            |
/// |    6 | `CurlError::CouldntResolveHost`    |
/// |    7 | `CurlError::CouldntConnect`        |
/// |  ... | All other CURLcode integer values   |
///
/// # Panics
///
/// This function does not panic under normal operation.  All error
/// conditions are mapped to `CurlError` codes and propagated via the
/// process exit code.
#[tokio::main(flavor = "current_thread")]
async fn main() {
    // ------------------------------------------------------------------
    // Step 1: Initialize the global stderr handle.
    //
    // This MUST happen before any diagnostic output to ensure that
    // `tool_stderr_write()`, `errorf()`, `warnf()`, and all other
    // diagnostic functions have a valid output target.
    //
    // Matches C: `tool_init_stderr();` (line 148 of tool_main.c)
    // ------------------------------------------------------------------
    stderr::tool_init_stderr();

    // ------------------------------------------------------------------
    // Step 2: SIGPIPE handling (Unix only).
    //
    // The C implementation ignores SIGPIPE to prevent the process from
    // being terminated when writing to a broken pipe:
    //
    //   #if defined(HAVE_SIGNAL) && defined(SIGPIPE)
    //   (void)signal(SIGPIPE, SIG_IGN);
    //   #endif
    //
    // In Rust, this is handled by the I/O error model: all write
    // operations throughout this crate (via `tool_stderr_write()`,
    // `std::io::Write`, etc.) return `io::ErrorKind::BrokenPipe`
    // errors instead of raising SIGPIPE, and all write sites handle
    // these errors gracefully by ignoring them.  This provides
    // equivalent behavior to the C `signal(SIGPIPE, SIG_IGN)` without
    // requiring any `unsafe` code.
    //
    // Specifically:
    //   - `stderr::tool_stderr_write()` uses `let _ = write_all()`
    //     which silently ignores BrokenPipe errors.
    //   - All stdout writes in callbacks and output routines check
    //     for write errors and propagate them as CurlError codes.
    //   - Tokio's I/O runtime handles EPIPE at the socket layer.
    // ------------------------------------------------------------------

    // ------------------------------------------------------------------
    // Step 3: Initialize global configuration.
    //
    // `globalconf_init()` performs two critical operations:
    //   1. Calls `global_init()` to set up the TLS provider (rustls)
    //      and the tracing subscriber.
    //   2. Creates the root `GlobalConfig` with default values and
    //      queries library capability information.
    //
    // If initialization fails, the error code is propagated directly
    // to the process exit code — matching the C pattern where
    // `operate()` is only called on success:
    //
    //   result = globalconf_init();
    //   if(!result) {
    //       result = operate(argc, argv);
    //       globalconf_free();
    //   }
    //   return (int)result;
    //
    // Note: `errorf()` is NOT called on init failure because it
    // requires a `&GlobalConfig` reference that does not exist yet.
    // This matches the C behavior where the init failure path goes
    // straight to `return (int)result`.
    // ------------------------------------------------------------------
    let result = match config::globalconf_init() {
        Ok(mut global) => {
            // Step 4: Collect command-line arguments and run the main
            // operation dispatch.
            //
            // `std::env::args()` handles platform-specific encoding
            // including Windows wide-character arguments (replacing the
            // C `wmain`/`main` duality).  The collected `Vec<String>`
            // is passed to `operate()` which parses configuration files,
            // command-line flags, sets up transfers, and executes them
            // (serial or parallel).
            let args: Vec<String> = std::env::args().collect();
            let result = operate::operate(&args, &mut global).await;

            // Step 5: Global cleanup.
            //
            // Releases all resources held by the global configuration:
            // closes trace streams, clears operation configs, clears
            // variables, and calls `global_cleanup()` to tear down the
            // underlying library.
            //
            // Matches C: `globalconf_free();`
            config::globalconf_free(&mut global);

            result
        }
        Err(e) => {
            // `globalconf_init()` failed — the error IS the result.
            // Matches C: `result = globalconf_init();` where a non-zero
            // result skips `operate()` and falls through to
            // `return (int)result`.
            //
            // We write the error to stderr using `tool_stderr_write()`
            // directly because `msgs::errorf()` requires a `&GlobalConfig`
            // reference that does not exist when initialization itself
            // has failed.  The output format matches errorf()'s prefix:
            //   "curl: ({code}) {description}"
            stderr::tool_stderr_write(
                &format!("curl: ({}) {}\n", e as i32, e),
            );
            e
        }
    };

    // ------------------------------------------------------------------
    // Step 6: Flush output streams and exit with the result code.
    //
    // Explicit flush is required because `std::process::exit()` calls
    // libc `exit()` which terminates the process.  While libc `exit()`
    // flushes C stdio buffers, Rust's `BufWriter` and similar wrappers
    // require explicit flushing since `exit()` does not run Rust
    // destructors.
    //
    // On Windows, the C code calls `fflush(NULL)` to flush all open
    // streams.  We perform the equivalent on all platforms for safety.
    //
    // Matches C:
    //   #ifdef _WIN32
    //   fflush(NULL);
    //   #endif
    //   return (int)result;
    // ------------------------------------------------------------------
    {
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }
    stderr::tool_stderr_flush();

    // Exit with the CurlError integer value.
    //
    // The `as i32` cast maps the enum discriminant to the process exit
    // code, matching C: `return (int)result;`
    //
    // Examples:
    //   CurlError::Ok          → exit(0)
    //   CurlError::FailedInit  → exit(2)
    //   CurlError::CouldntConnect → exit(7)
    std::process::exit(result as i32);
}
