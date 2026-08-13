// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: the blitzy-curl project contributors

//! Generates the provenance, traceability, coverage and hazard registers, or
//! checks the committed ones against what the generator produces.
//!
//! Invoked from the repository root. `--check` compares instead of writing, and
//! is what continuous integration runs; without it the documents are written.
//! Either way every gate runs and a failing gate is a non-zero exit.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use curl_audit::fs::RealFiles;
use curl_audit::workspace::{AuditError, Workspace};
use curl_audit_traceability::{check, emit, generate};

/// What the invocation asked for.
enum Mode {
    /// Write every document.
    Emit,
    /// Compare every document against the tree.
    Check,
}

fn parse() -> Result<(Mode, std::path::PathBuf), AuditError> {
    let mut mode = Mode::Emit;
    let mut start: Option<std::path::PathBuf> = None;
    for argument in std::env::args().skip(1) {
        match argument.as_str() {
            "--check" => mode = Mode::Check,
            "--emit" => mode = Mode::Emit,
            other if other.starts_with("--") => {
                return Err(AuditError::new(format!("unknown argument {other}")));
            }
            other => start = Some(std::path::PathBuf::from(other)),
        }
    }
    let start = match start {
        Some(start) => start,
        None => std::env::current_dir()
            .map_err(|error| AuditError::new(format!("current directory: {error}")))?,
    };
    Ok((mode, start))
}

fn run() -> Result<bool, AuditError> {
    let (mode, start) = parse()?;
    let workspace = Workspace::discover(&start)?;
    let files = RealFiles::new(workspace.root());
    let generated = generate(&workspace, &files)?;

    let mut report = generated.report.clone();
    match mode {
        Mode::Check => report.absorb(check(&generated, &files)),
        Mode::Emit => {
            let written = emit(&generated, workspace.root())?;
            report.pass(
                "documents-written",
                format!("{written} document(s) written under the repository root"),
            );
        }
    }
    print!("{}", report.render());
    Ok(report.passed())
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("curl-audit-traceability: {error}");
            ExitCode::FAILURE
        }
    }
}
