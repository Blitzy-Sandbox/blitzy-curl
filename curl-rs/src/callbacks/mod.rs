// curl-rs — CLI transfer callbacks (ports of curl's `src/tool_cb_*.c`).
//
// SPDX-License-Identifier: curl
//
// This module groups the Rust ports of curl's per-transfer callback translation
// units (`src/tool_cb_*.c`): the write, read, seek, header, progress, and debug
// callbacks the CLI registers on each `curl_rs_lib::Easy` handle. The original C
// sources are
//   Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// and are licensed under the curl license (https://curl.se/docs/copyright.html).

//! Per-transfer callbacks for the `curl-rs` CLI.
//!
//! This is the **module root** for the CLI's libcurl-style callback layer — the
//! Rust analog of curl's `src/tool_cb_*.c` units. It is purely *organizational*:
//! it declares the six callback submodules so they become part of the crate and
//! re-exports the single shared type that a sibling module names by its short
//! path. All callback *behavior* lives in the submodules; this file adds no
//! logic, no new abstractions, and no `unsafe`.
//!
//! # Submodules
//!
//! Each submodule ports exactly one of curl's `src/tool_cb_*.c` callback units;
//! together they implement curl's observable per-transfer I/O behavior (output,
//! upload, resume, header capture, the progress meter, and `--verbose` /
//! `--trace` tracing). Every callback is a memory-safe function that the
//! integration layer ([`crate::operate`]) wires to the matching
//! `CURLOPT_*FUNCTION` / `CURLOPT_*DATA` setter, with the per-transfer record as
//! its userdata:
//!
//! * [`debug`] — the `CURLOPT_DEBUGFUNCTION` `-v` / `--trace` / `--trace-ascii`
//!   trace callback (`src/tool_cb_dbg.c`).
//! * [`header`] — the `CURLOPT_HEADERFUNCTION` header callback: `-D` /
//!   `--dump-header` file output, `-J` / `--remote-header-name`
//!   Content-Disposition filename derivation, `--etag-save` capture, and the
//!   styled / OSC-8-hyperlinked header echo (`src/tool_cb_hdr.c`).
//! * [`progress`] — the `-#` / `--progress-bar` `CURLOPT_XFERINFOFUNCTION`
//!   callback; owns the [`ProgressData`] state that `crate::operate`'s
//!   `PerTransfer` embeds as its `progressbar` field (`src/tool_cb_prg.c`).
//! * [`read`] — the `CURLOPT_READFUNCTION` upload feeder plus the busy-read
//!   unpauser (`src/tool_cb_rea.c`).
//! * [`seek`] — the `CURLOPT_SEEKFUNCTION` resume / seek callback
//!   (`src/tool_cb_see.c`).
//! * [`write`] — the `CURLOPT_WRITEFUNCTION` body-write callback plus
//!   output-file creation (`src/tool_cb_wrt.c`).
//!
//! curl's `src/tool_cb_soc.c` (the MPTCP / `CURLOPT_SOCKOPTFUNCTION` socket
//! helper) is deliberately **not** part of this set — it is not one of the six
//! per-transfer callback files. If sockopt behavior is ever required it belongs
//! with the option wiring in `crate::setopt`, not in this subtree.
//!
//! # Re-export surface
//!
//! The submodules are declared `pub`, so every callback and helper they expose
//! is already reachable by its full path (for example
//! `crate::callbacks::write::create_output_file` or
//! `crate::callbacks::progress::tool_progress_cb`). To keep the surface minimal
//! and warning-clean, this root re-exports only the one symbol that a sibling
//! module actually names by its short path: [`ProgressData`]. `crate::operate`
//! imports it as `crate::callbacks::ProgressData` and embeds it in its
//! `PerTransfer` record, so the re-export is genuinely consumed. Nothing else is
//! re-exported here — re-exporting an unconsumed item would be flagged as an
//! unused import and fail the workspace's `-D warnings` gate (re-export only
//! what is consumed).
//!
//! # Construction-order staging
//!
//! These callbacks are authored ahead of the `crate::operate` wiring that
//! registers them (AAP §0.8.4 step 12). The `mod callbacks;` declaration in
//! `main.rs` carries `#[allow(dead_code)]`, which covers this whole subtree so
//! the not-yet-registered public callbacks stay compiled, clippy-linted, and
//! unit-tested as part of the binary build without tripping `-D warnings`; that
//! allow is removed once `operate` registers every callback.

pub mod debug;
pub mod header;
pub mod progress;
pub mod read;
pub mod seek;
pub mod write;

// `crate::operate` names the progress-bar state by its short path
// (`use crate::callbacks::ProgressData;`) and embeds it as
// `PerTransfer.progressbar`, so it is re-exported here. This is the only
// callback symbol consumed by short path anywhere in the crate; every other
// public item in the submodules is reached through its full
// `crate::callbacks::<module>::<item>` path, so re-exporting any of them here
// would be an unused import and would fail the `-D warnings` gate.
pub use progress::ProgressData;
