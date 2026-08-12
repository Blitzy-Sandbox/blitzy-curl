// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: the blitzy-curl project contributors

//! Generated audits over this project's own configuration contracts.
//!
//! Three audits live here, each reading its contract from
//! `[workspace.metadata.curl]` in the root manifest and each emitting a report
//! whose failure count drives the process exit status:
//!
//! - [`lockfile`] — the resolved dependency graph: membership, exact pins, the
//!   committed `Cargo.lock`, and a mechanical re-derivation of the full pinned
//!   set. Every assertion rejects an empty graph and a zero match.
//! - [`comments`] — comment discipline in project-authored configuration files:
//!   labels, machine-read markers and `DL-####` pointers only.
//! - [`premise`] — baseline-premise deltas: each recorded difference between a
//!   plan premise and the pinned oracle, with line-pinned evidence.
//!
//! Rationale for every decision these audits enforce lives in
//! `refactor/docs/DECISION-LOG.md`; the identifiers referenced from here are
//! `DL-0031` through `DL-0037`.

#![forbid(unsafe_code)]

pub mod comments;
pub mod fs;
pub mod lockfile;
pub mod premise;
pub mod report;
pub mod workspace;
