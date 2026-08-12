// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: the blitzy-curl project contributors

//! Runs the three configuration-contract audits and exits non-zero on any
//! failing check.
//!
//! Invoked from the repository root, or with the root as the single argument.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use curl_audit::fs::RealFiles;
use curl_audit::report::Report;
use curl_audit::workspace::{AuditError, Workspace};
use curl_audit::{comments, lockfile, premise};

/// Absorbs one audit's report, or records the contract failure that stopped it.
///
/// Each audit is independent: a contract one audit cannot read is a failing
/// check of its own rather than a reason to hide the other two.
fn absorb(report: &mut Report, name: &str, outcome: Result<Report, AuditError>) {
    match outcome {
        Ok(audited) => report.absorb(audited),
        Err(error) => report.fail(format!("{name}/contract"), error.message().to_owned()),
    }
}

fn run() -> Result<Report, AuditError> {
    let start = match std::env::args().nth(1) {
        Some(argument) => std::path::PathBuf::from(argument),
        None => std::env::current_dir()
            .map_err(|error| AuditError::new(format!("current directory: {error}")))?,
    };
    let workspace = Workspace::discover(&start)?;
    let files = RealFiles::new(workspace.root());

    let mut report = Report::new(format!(
        "configuration contracts of {}",
        workspace.root().display()
    ));
    absorb(
        &mut report,
        "dependency-graph",
        lockfile::audit(&workspace, &files),
    );
    absorb(
        &mut report,
        "comment-discipline",
        comments::audit(&workspace, &files),
    );
    absorb(
        &mut report,
        "baseline-premise-deltas",
        premise::audit(&workspace, &files),
    );
    Ok(report)
}

fn main() -> ExitCode {
    match run() {
        Ok(report) => {
            print!("{}", report.render());
            if report.passed() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("curl-audit-config: {error}");
            ExitCode::FAILURE
        }
    }
}
