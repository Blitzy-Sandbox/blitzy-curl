// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: the blitzy-curl project contributors

//! Generated provenance, traceability, coverage and hazard registers.
//!
//! The generator enumerates every construct the vendored oracle carries,
//! resolves each one to the target that owns it, resolves every
//! project-authored file back to the oracle construct it derives from, and
//! renders four documents under `refactor/docs/`. A construct with no target,
//! a target with no construct, a locator that does not resolve, a verdict
//! outside the vocabulary and a pointer that does not resolve are each a
//! failing check, so coverage is a gate rather than a claim.
//!
//! Enumeration is always mechanical: the extraction rules run against
//! `original/` on every invocation and no recorded figure is read. Ownership
//! is declared, because a mapping from a C translation unit to a Rust crate is
//! a design decision no enumeration can produce.
//!
//! Rationale for every decision enforced here lives in
//! `refactor/docs/DECISION-LOG.md`; the identifiers referenced from here are
//! `DL-0110` and `DL-0111`.

#![forbid(unsafe_code)]

pub mod contract;
pub mod forward;
pub mod hazards;
pub mod oracle;
pub mod render;
pub mod reverse;

use curl_audit::fs::Files;
use curl_audit::report::Report;
use curl_audit::workspace::{AuditError, AuditResult, Workspace};

/// Everything the generator produced for one invocation.
pub struct Generated {
    /// Checks the generator ran, in order.
    pub report: Report,
    /// Rendered documents, keyed by repository-relative output path.
    pub documents: Vec<(String, String)>,
}

/// Runs every gate and renders every document.
///
/// The report is returned whole rather than short-circuited: a failing gate in
/// one direction must not hide the state of the other.
pub fn generate(workspace: &Workspace, files: &dyn Files) -> AuditResult<Generated> {
    let index = contract::Index::from_workspace(workspace)?;
    let ownership = contract::Ownership::load(files, index.ownership_data())?;
    let register = hazards::Register::load(files, index.hazard_data())?;
    let planned = contract::planned_crates(workspace)?;
    let present = contract::crates_present(workspace, files)?;
    let decisions = contract::decision_ids(files, index.decision_log())?;

    let mut report = Report::new("traceability");
    let survey = oracle::Survey::collect(files);
    let forward = forward::resolve(&survey, &ownership, &planned, &decisions, &mut report);
    let back = reverse::resolve(files, &ownership, &decisions, &mut report);
    let hazard_rows = register.resolve(files, &planned, &decisions, &mut report);

    let documents = render::documents(&index, &survey, &forward, &back, &hazard_rows, &present);
    report.assert(
        documents.len() == index.outputs().len(),
        "outputs-rendered",
        format!(
            "{} of {} declared output(s) rendered",
            documents.len(),
            index.outputs().len()
        ),
    );
    Ok(Generated { report, documents })
}

/// Compares rendered documents against the committed ones.
///
/// A missing file and a differing file are the same failure: the committed
/// document is not what the generator produces.
pub fn check(generated: &Generated, files: &dyn Files) -> Report {
    let mut report = Report::new("traceability/committed-documents");
    for (path, rendered) in &generated.documents {
        match files.read(path) {
            Some(committed) if committed == *rendered => report.pass(
                format!("committed/{path}"),
                format!("{} byte(s) match the generator", committed.len()),
            ),
            Some(committed) => report.fail(
                format!("committed/{path}"),
                format!(
                    "committed {} byte(s), generator produces {} byte(s)",
                    committed.len(),
                    rendered.len()
                ),
            ),
            None => report.fail(format!("committed/{path}"), "absent".to_owned()),
        }
    }
    if generated.documents.is_empty() {
        report.fail("committed-documents", "no document was rendered".to_owned());
    }
    report
}

/// Writes every rendered document, creating parent directories as needed.
pub fn emit(generated: &Generated, root: &std::path::Path) -> AuditResult<usize> {
    let mut written = 0_usize;
    for (path, rendered) in &generated.documents {
        let target = root.join(path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| AuditError::new(format!("{}: {error}", parent.display())))?;
        }
        std::fs::write(&target, rendered)
            .map_err(|error| AuditError::new(format!("{}: {error}", target.display())))?;
        written += 1;
    }
    Ok(written)
}
