// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: the blitzy-curl project contributors

//! Baseline-premise deltas: every recorded difference between a plan premise and
//! the pinned oracle.
//!
//! The plan's premises were derived from a development snapshot; the oracle is
//! the pinned release tag, and it is immutable. Where the two disagree, the
//! disagreement is recorded as a delta under
//! `[workspace.metadata.curl.baseline-premise-deltas]` and verified here: the
//! paths the plan expected are asserted absent, the paths the tag actually
//! carries are asserted present, and every claim carries a line-pinned locator
//! in the oracle. `DL-0033`, `DL-0034` and `DL-0035` record the deltas
//! themselves.

use toml::Value;

use crate::comments::decision_ids;
use crate::fs::Files;
use crate::report::Report;
use crate::workspace::{AuditError, AuditResult, Workspace};

/// A line-pinned citation into the oracle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Evidence {
    /// Repository-relative path of the cited file.
    pub path: String,
    /// One-based line number.
    pub line: usize,
    /// Text the cited line must contain.
    pub contains: String,
}

/// One recorded difference between a plan premise and the oracle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Delta {
    /// Key the delta is recorded under.
    pub name: String,
    /// Paths the plan expected that the pinned tag does not carry.
    pub absent_paths: Vec<String>,
    /// Paths the pinned tag carries instead, if any.
    pub present_paths: Vec<String>,
    /// Citations that establish the delta from the oracle itself.
    pub evidence: Vec<Evidence>,
    /// What the project delivers for this premise.
    pub delivered: String,
    /// Mapping class of the flag the premise named, or `none`.
    pub flag_contract: String,
    /// Decision-log row that carries the reasoning.
    pub decision: String,
}

/// The delta contract, read from the root manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Deltas {
    /// Path of the decision log every delta must cite.
    pub decision_log: String,
    /// Accepted values of a delta's `delivered` field.
    pub delivered_vocabulary: Vec<String>,
    /// Accepted values of a delta's `flag-contract` field.
    pub flag_contracts: Vec<String>,
    /// The deltas themselves, in key order.
    pub entries: Vec<Delta>,
}

fn string_field(
    table: &toml::map::Map<String, Value>,
    key: &str,
    name: &str,
) -> AuditResult<String> {
    table
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| AuditError::new(format!("baseline-premise-deltas.{name}.{key} missing")))
}

fn string_list(
    table: &toml::map::Map<String, Value>,
    key: &str,
    name: &str,
) -> AuditResult<Vec<String>> {
    match table.get(key) {
        None => Ok(Vec::new()),
        Some(value) => {
            let array = value.as_array().ok_or_else(|| {
                AuditError::new(format!(
                    "baseline-premise-deltas.{name}.{key} is not an array"
                ))
            })?;
            array
                .iter()
                .map(|entry| {
                    entry.as_str().map(str::to_owned).ok_or_else(|| {
                        AuditError::new(format!(
                            "baseline-premise-deltas.{name}.{key} holds a non-string"
                        ))
                    })
                })
                .collect()
        }
    }
}

impl Deltas {
    /// Reads the delta contract out of the root manifest.
    pub fn from_workspace(workspace: &Workspace) -> AuditResult<Self> {
        let decision_log = workspace
            .curl_value(&["comment-discipline", "decision-log"])
            .and_then(Value::as_str)
            .ok_or_else(|| AuditError::new("comment-discipline.decision-log missing"))?
            .to_owned();
        let delivered_vocabulary = workspace.string_array(&[
            "workspace",
            "metadata",
            "curl",
            "baseline-premise",
            "vocabulary",
        ])?;
        let flag_contracts = {
            let classes = workspace.table(&["workspace", "metadata", "curl", "flag-classes"])?;
            let mut names: Vec<String> = classes.keys().cloned().collect();
            names.push("none".to_owned());
            names
        };
        let table =
            workspace.table(&["workspace", "metadata", "curl", "baseline-premise-deltas"])?;
        let mut entries = Vec::with_capacity(table.len());
        for (name, value) in table {
            let entry = value.as_table().ok_or_else(|| {
                AuditError::new(format!("baseline-premise-deltas.{name} is not a table"))
            })?;
            let mut evidence = Vec::new();
            let citations = entry.get("evidence").and_then(Value::as_array);
            for citation in citations.into_iter().flatten() {
                let citation = citation.as_table().ok_or_else(|| {
                    AuditError::new(format!(
                        "baseline-premise-deltas.{name}.evidence holds a non-table"
                    ))
                })?;
                let line = citation
                    .get("line")
                    .and_then(Value::as_integer)
                    .ok_or_else(|| {
                        AuditError::new(format!(
                            "baseline-premise-deltas.{name}.evidence entry has no line"
                        ))
                    })?;
                let line = usize::try_from(line).map_err(|_| {
                    AuditError::new(format!(
                        "baseline-premise-deltas.{name}.evidence line is not a line number"
                    ))
                })?;
                evidence.push(Evidence {
                    path: string_field(citation, "path", name)?,
                    line,
                    contains: string_field(citation, "contains", name)?,
                });
            }
            entries.push(Delta {
                name: name.clone(),
                absent_paths: string_list(entry, "absent-paths", name)?,
                present_paths: string_list(entry, "present-paths", name)?,
                evidence,
                delivered: string_field(entry, "delivered", name)?,
                flag_contract: string_field(entry, "flag-contract", name)?,
                decision: string_field(entry, "decision", name)?,
            });
        }
        if delivered_vocabulary.is_empty() {
            return Err(AuditError::new("baseline-premise.vocabulary is empty"));
        }
        Ok(Self {
            decision_log,
            delivered_vocabulary,
            flag_contracts,
            entries,
        })
    }
}

/// Whether a file's `line`-th line contains `needle`.
#[must_use]
pub fn line_contains(contents: &str, line: usize, needle: &str) -> bool {
    line.checked_sub(1)
        .and_then(|index| contents.lines().nth(index))
        .is_some_and(|text| text.contains(needle))
}

/// Verifies every recorded delta against the checkout.
pub fn audit(workspace: &Workspace, files: &dyn Files) -> AuditResult<Report> {
    let deltas = Deltas::from_workspace(workspace)?;
    let mut report = Report::new("baseline-premise-deltas");
    let log = files
        .read(&deltas.decision_log)
        .ok_or_else(|| AuditError::new(format!("{} is missing", deltas.decision_log)))?;
    let defined = decision_ids(&log);

    report.assert(
        !deltas.entries.is_empty(),
        "deltas-recorded",
        format!("{} delta(s) recorded", deltas.entries.len()),
    );

    for delta in &deltas.entries {
        let name = &delta.name;
        report.assert(
            !delta.absent_paths.is_empty(),
            format!("{name}/names-an-absent-path"),
            format!("{} absent path(s) recorded", delta.absent_paths.len()),
        );
        report.assert(
            !delta.evidence.is_empty(),
            format!("{name}/is-evidenced"),
            format!("{} citation(s) recorded", delta.evidence.len()),
        );
        report.assert(
            defined.contains(&delta.decision),
            format!("{name}/decision-resolves"),
            format!("{} in {}", delta.decision, deltas.decision_log),
        );
        report.assert(
            deltas.delivered_vocabulary.contains(&delta.delivered),
            format!("{name}/delivered-in-vocabulary"),
            format!("delivered = {}", delta.delivered),
        );
        report.assert(
            deltas.flag_contracts.contains(&delta.flag_contract),
            format!("{name}/flag-contract-is-a-class"),
            format!("flag-contract = {}", delta.flag_contract),
        );

        let present: Vec<&String> = delta
            .absent_paths
            .iter()
            .filter(|path| files.exists(path))
            .collect();
        report.assert(
            present.is_empty(),
            format!("{name}/absent-paths-absent"),
            if present.is_empty() {
                format!("{} path(s) absent as recorded", delta.absent_paths.len())
            } else {
                format!(
                    "now present, so the delta is stale: {}",
                    present
                        .iter()
                        .map(|path| path.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            },
        );

        let missing: Vec<&String> = delta
            .present_paths
            .iter()
            .filter(|path| !files.exists(path))
            .collect();
        report.assert(
            missing.is_empty(),
            format!("{name}/present-paths-present"),
            if missing.is_empty() {
                format!("{} replacement path(s) present", delta.present_paths.len())
            } else {
                format!(
                    "missing: {}",
                    missing
                        .iter()
                        .map(|path| path.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            },
        );

        for citation in &delta.evidence {
            let held = files.read(&citation.path).is_some_and(|contents| {
                line_contains(&contents, citation.line, &citation.contains)
            });
            report.assert(
                held,
                format!("{name}/evidence/{}:{}", citation.path, citation.line),
                format!("contains \"{}\"", citation.contains),
            );
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::{Deltas, audit, line_contains};
    use crate::fs::MapFiles;
    use crate::workspace::Workspace;

    const ROOT_MANIFEST: &str = r#"
[workspace]
members = []

[workspace.metadata.curl.baseline-premise]
vocabulary = ["vendored-at-tag-path", "constants-and-symbols-only"]

[workspace.metadata.curl.comment-discipline]
decision-log = "refactor/docs/DECISION-LOG.md"

[workspace.metadata.curl.flag-classes]
capability = { becomes-cargo-feature = true }
accepted-and-inert = { becomes-cargo-feature = false }

[workspace.metadata.curl.baseline-premise-deltas.librtmp]
absent-paths = ["original/CMake/FindLibrtmp.cmake"]
present-paths = ["original/include/curl/curl.h"]
evidence = [{ path = "original/docs/DEPRECATE.md", line = 2, contains = "RTMP (removed in 8.20.0)" }]
delivered = "constants-and-symbols-only"
flag-contract = "accepted-and-inert"
decision = "DL-0035"
"#;

    fn workspace(manifest: &str, key: &str) -> Workspace {
        let directory = std::env::temp_dir().join(format!("curl-audit-tests/premise-{key}"));
        std::fs::create_dir_all(&directory).expect("fixture directory");
        std::fs::write(directory.join("Cargo.toml"), manifest).expect("fixture manifest");
        Workspace::load(&directory).expect("fixture workspace")
    }

    fn clean_files() -> MapFiles {
        MapFiles::new()
            .with("refactor/docs/DECISION-LOG.md", "| DL-0035 | row |\n")
            .with("original/include/curl/curl.h", "#define CURLPROTO_RTMP\n")
            .with(
                "original/docs/DEPRECATE.md",
                "## Past removals\n- RTMP (removed in 8.20.0)\n",
            )
    }

    #[test]
    fn line_contains_is_one_based_and_bounded() {
        let text = "alpha\nbeta\n";
        assert!(line_contains(text, 1, "alpha"));
        assert!(line_contains(text, 2, "beta"));
        assert!(!line_contains(text, 2, "alpha"));
        assert!(!line_contains(text, 3, "alpha"));
        assert!(!line_contains(text, 0, "alpha"));
    }

    #[test]
    fn a_fully_evidenced_delta_passes() {
        let workspace = workspace(ROOT_MANIFEST, "clean");
        let report = audit(&workspace, &clean_files()).expect("audit runs");
        assert!(report.passed(), "{}", report.render());
    }

    #[test]
    fn a_stale_delta_fails() {
        let workspace = workspace(ROOT_MANIFEST, "stale");
        let files = clean_files().with("original/CMake/FindLibrtmp.cmake", "");
        let report = audit(&workspace, &files).expect("audit runs");
        assert!(report.render().contains("FAIL librtmp/absent-paths-absent"));
        assert!(report.render().contains("stale"));
    }

    #[test]
    fn a_missing_replacement_fails() {
        let workspace = workspace(ROOT_MANIFEST, "missing");
        let files = MapFiles::new()
            .with("refactor/docs/DECISION-LOG.md", "| DL-0035 | row |\n")
            .with(
                "original/docs/DEPRECATE.md",
                "## Past removals\n- RTMP (removed in 8.20.0)\n",
            );
        let report = audit(&workspace, &files).expect("audit runs");
        assert!(
            report
                .render()
                .contains("FAIL librtmp/present-paths-present")
        );
    }

    #[test]
    fn evidence_that_no_longer_reads_as_recorded_fails() {
        let workspace = workspace(ROOT_MANIFEST, "evidence");
        let files = clean_files().with("original/docs/DEPRECATE.md", "## Past removals\n- SMB\n");
        let report = audit(&workspace, &files).expect("audit runs");
        assert!(
            report
                .render()
                .contains("FAIL librtmp/evidence/original/docs/DEPRECATE.md:2")
        );
    }

    #[test]
    fn an_unevidenced_or_unexplained_delta_fails() {
        let manifest = ROOT_MANIFEST
            .replace(
                "evidence = [{ path = \"original/docs/DEPRECATE.md\", line = 2, contains = \"RTMP (removed in 8.20.0)\" }]\n",
                "",
            )
            .replace("decision = \"DL-0035\"", "decision = \"DL-9999\"")
            .replace("delivered = \"constants-and-symbols-only\"", "delivered = \"invented\"")
            .replace("flag-contract = \"accepted-and-inert\"", "flag-contract = \"invented\"");
        let workspace = workspace(&manifest, "unevidenced");
        let report = audit(&workspace, &clean_files()).expect("audit runs");
        let rendered = report.render();
        assert!(rendered.contains("FAIL librtmp/is-evidenced"));
        assert!(rendered.contains("FAIL librtmp/decision-resolves"));
        assert!(rendered.contains("FAIL librtmp/delivered-in-vocabulary"));
        assert!(rendered.contains("FAIL librtmp/flag-contract-is-a-class"));
    }

    #[test]
    fn an_empty_delta_table_fails_and_a_broken_contract_errors() {
        let manifest = ROOT_MANIFEST
            .split("[workspace.metadata.curl.baseline-premise-deltas.librtmp]")
            .next()
            .expect("prefix")
            .to_owned()
            + "[workspace.metadata.curl.baseline-premise-deltas]\n";
        let empty = workspace(&manifest, "empty");
        let report = audit(&empty, &clean_files()).expect("audit runs");
        assert!(report.render().contains("FAIL deltas-recorded"));

        let broken_manifest = manifest.replace(
            "vocabulary = [\"vendored-at-tag-path\", \"constants-and-symbols-only\"]",
            "vocabulary = []",
        );
        let broken = workspace(&broken_manifest, "broken");
        assert!(Deltas::from_workspace(&broken).is_err());
    }
}
