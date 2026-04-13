//! Transfer callback implementations for the curl-rs CLI tool.
//!
//! Each callback module provides functions compatible with curl-rs-lib's
//! `EasyHandle` callback registration API, rewritten from the C `tool_cb_*.c`
//! source files.
//!
//! # Callbacks
//!
//! - [`debug`] — Debug/verbose output callback (`--verbose`, `--trace`,
//!   `--trace-ascii`).  Implements `CURLOPT_DEBUGFUNCTION` with timestamp
//!   formatting, hex dump rendering, and the seven-element trace prefix array
//!   matching curl 8.x behavior.
//!
//! - [`header`] — HTTP header processing callback (`--dump-header`,
//!   `--etag-save`).  Implements `CURLOPT_HEADERFUNCTION`, provides
//!   [`HdrCbData`] for per-transfer callback state, and
//!   [`tool_write_headers`](header::tool_write_headers) for flushing buffered
//!   headers to an output stream.
//!
//! - [`progress`] — Transfer progress tracking callback (progress bar).
//!   Implements `CURLOPT_XFERINFOFUNCTION` with spinner animation for unknown
//!   totals and hash-bar rendering for known totals.  Provides
//!   [`ProgressData`] for progress state and
//!   [`progressbarinit`](progress::progressbarinit) for initialization.
//!
//! - [`read`] — Upload data read callback.  Implements
//!   `CURLOPT_READFUNCTION` with rate limiting, pause/resume support, and
//!   upload-size clamping.  Provides [`ReadResult`] for typed return values
//!   and [`tool_readbusy_cb`] for unpausing blocked reads.
//!
//! - [`seek`] — Upload stream seek callback (resume support).  Implements
//!   `CURLOPT_SEEKFUNCTION` for repositioning the input stream, with
//!   [`SeekResult`] mapping to `CURL_SEEKFUNC_*` integer return codes.
//!
//! - [`socket`] — Socket creation callback (MPTCP support).  Implements
//!   `CURLOPT_OPENSOCKETFUNCTION` for creating sockets with optional
//!   Multipath TCP on Linux, with automatic fallback to standard TCP.
//!
//! - [`write`] — Download data write callback (file output, CLOBBER
//!   policies).  Implements `CURLOPT_WRITEFUNCTION` handling file output
//!   with [`ClobberPolicy`] for overwrite semantics, lazy output file
//!   creation via [`tool_create_output_file`], and binary-to-terminal
//!   detection.
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks, per AAP Section 0.7.1.
//!
//! SPDX-License-Identifier: curl

// ---------------------------------------------------------------------------
// Submodule declarations
// ---------------------------------------------------------------------------

/// Debug/verbose output callback (`--verbose`, `--trace`, `--trace-ascii`).
pub mod debug;

/// HTTP header processing callback (`--dump-header`, `--etag-save`,
/// `--remote-header-name`).
pub mod header;

/// Transfer progress/xferinfo callback (progress bar, spinner).
pub mod progress;

/// Upload data read callback with pause/resume support.
pub mod read;

/// Upload stream seek callback for resumed transfers.
pub mod seek;

/// Socket creation callback with optional MPTCP support.
pub mod socket;

/// Download data write callback with file CLOBBER policies.
pub mod write;

// ---------------------------------------------------------------------------
// Public re-exports — Debug callback
// ---------------------------------------------------------------------------

/// Re-exported debug/verbose callback function.
///
/// Registered via `CURLOPT_DEBUGFUNCTION` to handle `--verbose`, `--trace`,
/// and `--trace-ascii` output with timestamp formatting, hex dump rendering,
/// and trace prefix arrays matching curl 8.x behavior.
pub use debug::tool_debug_cb;

// ---------------------------------------------------------------------------
// Public re-exports — Header callback
// ---------------------------------------------------------------------------

/// Re-exported header processing callback function.
///
/// Registered via `CURLOPT_HEADERFUNCTION` to process HTTP response headers
/// during transfers (dump headers, save ETags, resolve Content-Disposition
/// filenames, render styled output).
pub use header::tool_header_cb;

/// Per-transfer header callback state.
///
/// Tracks the output streams, buffered header list, and Content-Disposition
/// filename processing state across header callback invocations.
pub use header::HdrCbData;

/// Flush buffered headers to an output stream.
///
/// Called from the write callback after Content-Disposition filename
/// resolution completes, to replay any headers that were held back while
/// waiting for the final output filename.
pub use header::tool_write_headers;

// ---------------------------------------------------------------------------
// Public re-exports — Progress callback
// ---------------------------------------------------------------------------

/// Re-exported progress/xferinfo callback function.
///
/// Registered via `CURLOPT_XFERINFOFUNCTION` to display a hash-bar
/// percentage progress indicator (known totals) or a sine-wave spinner
/// animation (unknown totals) on stderr.
pub use progress::tool_progress_cb;

/// Progress callback state.
///
/// Tracks the transfer progress counters, terminal width, animation tick
/// state, and output stream for the progress bar renderer.
pub use progress::ProgressData;

/// Initialize a [`ProgressData`] instance from the operation configuration.
///
/// Sets the initial terminal width, resume offset, spinner seed, and
/// output stream.
pub use progress::progressbarinit;

// ---------------------------------------------------------------------------
// Public re-exports — Read callback
// ---------------------------------------------------------------------------

/// Re-exported upload data read callback function.
///
/// Registered via `CURLOPT_READFUNCTION` to read upload data from
/// files or stdin, with timeout enforcement, upload-size clamping,
/// and pause/resume support.
pub use read::tool_read_cb;

/// Readbusy recovery callback for paused uploads.
///
/// Registered as an `XFERINFOFUNCTION` when the read callback returns
/// `ReadResult::Pause`.  Performs a 1 ms anti-spin sleep and then
/// unpauses the transfer when the upload source becomes ready.
pub use read::tool_readbusy_cb;

/// Typed return value from the read callback.
///
/// Replaces the C convention of returning magic `size_t` constants
/// (`CURL_READFUNC_PAUSE`, `CURL_READFUNC_ABORT`, 0 for EOF) with
/// explicit enum variants for clarity and exhaustive matching.
pub use read::ReadResult;

// ---------------------------------------------------------------------------
// Public re-exports — Seek callback
// ---------------------------------------------------------------------------

/// Re-exported seek callback function for upload stream repositioning.
///
/// Registered via `CURLOPT_SEEKFUNCTION` to rewind or reposition the
/// upload data source during transfer retry and resume scenarios.
pub use seek::tool_seek_cb;

/// Result of a seek callback invocation.
///
/// Maps 1:1 to the C `CURL_SEEKFUNC_*` integer return codes:
/// `Ok` = 0, `Fail` = 1, `CantSeek` = 2.
pub use seek::SeekResult;

// ---------------------------------------------------------------------------
// Public re-exports — Socket callback
// ---------------------------------------------------------------------------

/// Re-exported socket creation callback with MPTCP support.
///
/// Registered via `CURLOPT_OPENSOCKETFUNCTION` to create sockets with
/// optional Multipath TCP (MPTCP, protocol 262) on Linux, falling back
/// to standard TCP when MPTCP is unavailable.
pub use socket::tool_socket_open_mptcp_cb;

// ---------------------------------------------------------------------------
// Public re-exports — Write callback
// ---------------------------------------------------------------------------

/// Re-exported download data write callback function.
///
/// Registered via `CURLOPT_WRITEFUNCTION` to write downloaded data to
/// the output file or stdout, with CLOBBER policy enforcement, binary
/// output detection, and transfer size limit checking.
pub use write::tool_write_cb;

/// Create or open the output file for a download transfer.
///
/// Handles `ClobberPolicy` semantics: exclusive file creation
/// (`create_new`) for race-free operation, numbered suffix renaming
/// (`.1` through `.100`), and direct overwrite for `Always` mode.
pub use write::tool_create_output_file;

/// File overwrite policy for output file creation.
///
/// Controls how `tool_create_output_file` handles an existing file at
/// the target output path:
///
/// - `Default` — same as `Always` unless `--no-clobber` is specified.
/// - `Never` — refuse to overwrite; fail with an error.
/// - `Rename` — rename the existing file with a numbered suffix before
///   writing to the original name.
/// - `Always` — overwrite unconditionally.
pub use write::ClobberPolicy;
