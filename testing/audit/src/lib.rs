// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: the blitzy-curl project contributors

//! Generated audits over this project's own configuration contracts.
//!
//! Five audits live here, each reading its contract from
//! `[workspace.metadata.curl]` in the root manifest and each emitting a report
//! whose failure count drives the process exit status:
//!
//! - [`baseline`] — the frozen baseline identity: the tag, the tag object, the
//!   commit it peels to and the recorded state of the vendored worktree, with
//!   the tree digest recomputed from `original/` and compared against the
//!   record rather than against itself.
//! - [`lockfile`] — the resolved dependency graph: membership, exact pins, the
//!   committed `Cargo.lock`, and a mechanical re-derivation of the full pinned
//!   set. Every assertion rejects an empty graph and a zero match.
//! - [`comments`] — comment discipline in project-authored configuration files:
//!   labels, machine-read markers and `DL-####` pointers only.
//! - [`premise`] — baseline-premise deltas: each recorded difference between a
//!   plan premise and the pinned oracle, with line-pinned evidence.
//! - [`provenance`] — provenance ownership of the vendored tree: which crate
//!   owns each pinned-tag path, with every recorded metric re-measured from the
//!   oracle and every project-authored reference reconciled against the tree.
//!
//! Rationale for every decision these audits enforce lives in
//! `refactor/docs/DECISION-LOG.md`; the identifiers referenced from here are
//! `DL-0031` through `DL-0037`, `DL-0138` and `DL-0220` through `DL-0222`.

#![forbid(unsafe_code)]

pub mod baseline;
pub mod comments;
pub mod fs;
pub mod lockfile;
pub mod premise;
pub mod provenance;
pub mod report;
pub mod workspace;
