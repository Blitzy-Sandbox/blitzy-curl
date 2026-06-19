// curl-rs — CLI transfer callbacks (ports of curl's `src/tool_cb_*.c`).
//
// SPDX-License-Identifier: curl
//
// This module groups the Rust ports of curl's per-transfer callback translation
// units (`src/tool_cb_*.c`): the read, write, seek, header, progress, and debug
// callbacks the CLI registers on each `curl_rs_lib::Easy` handle. The original C
// sources are
//   Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// and are licensed under the curl license (https://curl.se/docs/copyright.html).

//! Per-transfer callbacks for the `curl-rs` CLI.
//!
//! Each submodule ports one of curl's `src/tool_cb_*.c` callback units — the
//! write/read/seek/progress callbacks and the `CURLOPT_DEBUGFUNCTION` trace
//! callback. Each callback is a memory-safe function that the integration layer
//! ([`crate::operate`]) wires to the corresponding `CURLOPT_*FUNCTION`/
//! `CURLOPT_*DATA` setter; together they implement curl's observable I/O
//! behavior (output, upload, resume, header capture, the progress meter, and
//! `--verbose`/`--trace` tracing).
//!
//! The current submodule set:
//!
//! * [`debug`] — the `CURLOPT_DEBUGFUNCTION` `-v`/`--trace`/`--trace-ascii`
//!   trace callback (`src/tool_cb_dbg.c`).
//! * [`progress`] — the `-#`/`--progress-bar` `CURLOPT_XFERINFOFUNCTION`
//!   callback; owns the [`ProgressData`] state that
//!   `crate::operate::PerTransfer` embeds (`src/tool_cb_prg.c`).
//! * [`read`] — the `CURLOPT_READFUNCTION` upload feeder + busy-read unpauser
//!   (`src/tool_cb_rea.c`).
//! * [`seek`] — the `CURLOPT_SEEKFUNCTION` resume/seek callback
//!   (`src/tool_cb_see.c`).
//! * [`write`] — the `CURLOPT_WRITEFUNCTION` body-write callback + output-file
//!   creation (`src/tool_cb_wrt.c`).
//!
//! # Construction-order staging
//!
//! These callbacks are authored ahead of the `operate` wiring that drives them
//! (AAP §0.8.4 step 11/12). The `mod callbacks;` declaration in `main.rs`
//! carries `#[allow(dead_code)]`, which propagates to this whole subtree so the
//! not-yet-wired public callbacks stay compiled, clippy-linted, and
//! unit-tested as part of the binary build without tripping the workspace
//! `-D warnings` gate; the allow is removed once `operate` registers every
//! callback.

pub mod debug;
pub mod progress;
pub mod read;
pub mod seek;
pub mod write;

// Re-export the progress bar's public surface so callers can use
// `crate::callbacks::ProgressData` / `progressbarinit` / `tool_progress_cb`
// without naming the submodule (the AAP specifies `ProgressData` is re-exported
// via this module and embedded as `PerTransfer.progressbar`).
//
// `ProgressData` is already consumed by `crate::operate::PerTransfer`; the
// remaining three (`progressbarinit`, `tool_progress_cb`, `ProgressOut`) are
// registered against the transfer engine only once the operation driver wires
// the callback in a later migration step (AAP §0.8.4 step 11/12). Until then
// they are intentionally unconsumed, so this single re-export carries a targeted
// `#[allow(unused_imports)]` — the same construction-order staging convention as
// the `#[allow(dead_code)]` on the not-yet-driven front-end modules in
// `main.rs`, keeping the zero-warnings (`-D warnings`) gate green without
// relaxing linting anywhere else in the module tree.
#[allow(unused_imports)]
pub use progress::{progressbarinit, tool_progress_cb, ProgressData, ProgressOut};
