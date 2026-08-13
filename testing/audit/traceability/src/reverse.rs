// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: the blitzy-curl project contributors

//! Reverse direction: every project-authored file resolved back to the oracle
//! construct it derives from, or to the decision that owns it outright.
//!
//! An enumerated file with no entry, an entry naming no enumerated file, a
//! derivation naming a path the oracle does not carry and a project-owned entry
//! with no resolving pointer are each a failing check.

use std::collections::{BTreeMap, BTreeSet};

use curl_audit::fs::Files;
use curl_audit::report::Report;

use crate::contract::Ownership;

/// Directories the enumeration does not enter.
///
/// The oracle is the forward direction's subject, build output is not tracked,
/// and the repository's own metadata is not authored by this project.
pub const SKIPPED: [&str; 3] = ["original", "target", ".git"];

/// One resolved reverse row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Row {
    /// Repository-relative path outside the oracle.
    pub path: String,
    /// Oracle paths it derives from, or the reason it has none.
    pub derivation: String,
    /// How it is accounted for: derived or project-owned.
    pub disposition: &'static str,
    /// Decision a project-owned file rests on.
    pub decision: String,
}

/// Every reverse row plus the gaps found while resolving them.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Reverse {
    /// Rows in path order.
    pub rows: Vec<Row>,
    /// Files or entries that resolved to nothing.
    pub gaps: Vec<String>,
}

/// Every project-authored file, enumerated from the checkout.
pub fn project_files(files: &dyn Files) -> Vec<String> {
    let mut found = Vec::new();
    let mut pending = vec![String::new()];
    while let Some(current) = pending.pop() {
        for name in files.list(&current) {
            if SKIPPED.contains(&name.as_str()) {
                continue;
            }
            let child = if current.is_empty() {
                name.clone()
            } else {
                format!("{current}/{name}")
            };
            if files.is_dir(&child) {
                pending.push(child);
            } else {
                found.push(child);
            }
        }
    }
    found.sort();
    found
}

/// Resolves every project-authored file and records a check per gate.
pub fn resolve(
    files: &dyn Files,
    ownership: &Ownership,
    decisions: &BTreeSet<String>,
    report: &mut Report,
) -> Reverse {
    let mut reverse = Reverse::default();
    let enumerated = project_files(files);
    report.assert(
        !enumerated.is_empty(),
        "reverse/enumerated",
        format!("{} project-authored file(s)", enumerated.len()),
    );

    let declared: BTreeMap<&str, &crate::contract::Reverse> = ownership
        .reverse
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    report.assert(
        declared.len() == ownership.reverse.len(),
        "reverse/entries-unique",
        format!(
            "{} entry(ies) for {} distinct path(s)",
            ownership.reverse.len(),
            declared.len()
        ),
    );

    let mut unmapped = Vec::new();
    for path in &enumerated {
        let Some(entry) = declared.get(path.as_str()) else {
            unmapped.push(path.clone());
            continue;
        };
        if entry.project_owned {
            if !decisions.contains(&entry.decision) {
                reverse
                    .gaps
                    .push(format!("{path}: project-owned with no resolving pointer"));
                continue;
            }
            reverse.rows.push(Row {
                path: path.clone(),
                derivation: "no oracle counterpart".to_owned(),
                disposition: "project-owned",
                decision: entry.decision.clone(),
            });
            continue;
        }
        if entry.derives_from.is_empty() {
            reverse
                .gaps
                .push(format!("{path}: neither derived nor project-owned"));
            continue;
        }
        let missing: Vec<&String> = entry
            .derives_from
            .iter()
            .filter(|source| !files.exists(source))
            .collect();
        if !missing.is_empty() {
            reverse.gaps.push(format!(
                "{path}: derives from absent {}",
                missing
                    .iter()
                    .map(|source| source.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            continue;
        }
        let outside: Vec<&String> = entry
            .derives_from
            .iter()
            .filter(|source| !source.starts_with("original/"))
            .collect();
        if !outside.is_empty() {
            reverse
                .gaps
                .push(format!("{path}: derivation is outside the oracle"));
            continue;
        }
        reverse.rows.push(Row {
            path: path.clone(),
            derivation: entry.derives_from.join(", "),
            disposition: "derived",
            decision: entry.decision.clone(),
        });
    }
    reverse.gaps.extend(
        unmapped
            .iter()
            .map(|path| format!("{path}: no reverse entry")),
    );
    report.assert(
        unmapped.is_empty(),
        "reverse/covers-every-file",
        if unmapped.is_empty() {
            format!("{} file(s) each carry one entry", enumerated.len())
        } else {
            format!("unmapped: {}", unmapped.join(", "))
        },
    );

    let present: BTreeSet<&str> = enumerated.iter().map(String::as_str).collect();
    let stale: Vec<&str> = declared
        .keys()
        .filter(|path| !present.contains(*path))
        .copied()
        .collect();
    report.assert(
        stale.is_empty(),
        "reverse/entries-exist",
        if stale.is_empty() {
            "every entry names an enumerated file".to_owned()
        } else {
            format!("stale: {}", stale.join(", "))
        },
    );

    report.assert(
        reverse.gaps.is_empty(),
        "reverse/no-gap",
        if reverse.gaps.is_empty() {
            format!("{} row(s), every file resolved", reverse.rows.len())
        } else {
            format!("{} gap(s): {}", reverse.gaps.len(), reverse.gaps.join("; "))
        },
    );
    reverse
        .rows
        .sort_by(|left, right| left.path.cmp(&right.path));
    reverse
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use curl_audit::fs::{MapFiles, RealFiles};
    use curl_audit::report::Report;

    use super::{project_files, resolve};
    use crate::contract::Ownership;

    const BASE: &str = r#"
schema = 1
[unit]
"http.c" = "curl-http1"
[[family]]
prefix = "CURL_"
owner = "curl-abi"
kind = "constant"
[[harness]]
path = "original/src/mkhelp.pl"
role = "help-text generator"
disposition = "replaced"
target = "curl-cli"
decision = "DL-0273"
"#;

    fn ownership(reverse: &str) -> Ownership {
        let text = format!("{BASE}{reverse}");
        let files = MapFiles::new().with("data/ownership.toml", &text);
        Ownership::load(&files, "data/ownership.toml").expect("fixture loads")
    }

    fn tree() -> MapFiles {
        MapFiles::new()
            .with("Cargo.toml", "")
            .with("original/configure.ac", "")
            .with("refactor/docs/DECISION-LOG.md", "")
            .with("target/debug/thing", "")
    }

    fn decisions() -> BTreeSet<String> {
        ["DL-0023"].into_iter().map(str::to_owned).collect()
    }

    #[test]
    fn the_oracle_and_build_output_are_not_enumerated() {
        let found = project_files(&tree());
        assert_eq!(
            found,
            vec![
                "Cargo.toml".to_owned(),
                "refactor/docs/DECISION-LOG.md".to_owned()
            ]
        );
        assert!(project_files(&MapFiles::new()).is_empty());
    }

    #[test]
    fn an_empty_directory_is_not_a_project_file() {
        let root = std::env::temp_dir().join("curl-audit-tests/reverse-empty-directory");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("refactor/docs")).expect("fixture directory");
        std::fs::create_dir_all(root.join("scratch/recordings")).expect("fixture directory");
        std::fs::write(root.join("refactor/docs/DECISION-LOG.md"), "").expect("fixture file");
        let found = project_files(&RealFiles::new(&root));
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(found, vec!["refactor/docs/DECISION-LOG.md".to_owned()]);
    }

    #[test]
    fn derived_and_project_owned_entries_both_resolve() {
        let owned = ownership(
            r#"
[[reverse]]
path = "Cargo.toml"
derives-from = ["original/configure.ac"]
[[reverse]]
path = "refactor/docs/DECISION-LOG.md"
project-owned = true
decision = "DL-0023"
"#,
        );
        let mut report = Report::new("test");
        let reverse = resolve(&tree(), &owned, &decisions(), &mut report);
        let rendered = report.render();
        assert!(rendered.contains("PASS reverse/no-gap"), "{rendered}");
        assert!(rendered.contains("PASS reverse/covers-every-file"));
        assert_eq!(reverse.rows.len(), 2);
        assert_eq!(reverse.rows[0].disposition, "derived");
        assert_eq!(reverse.rows[1].disposition, "project-owned");
    }

    #[test]
    fn an_unmapped_file_is_a_gap() {
        let owned = ownership(
            r#"
[[reverse]]
path = "Cargo.toml"
derives-from = ["original/configure.ac"]
"#,
        );
        let mut report = Report::new("test");
        let reverse = resolve(&tree(), &owned, &decisions(), &mut report);
        assert!(!reverse.gaps.is_empty());
        let rendered = report.render();
        assert!(rendered.contains("FAIL reverse/covers-every-file"));
        assert!(rendered.contains("DECISION-LOG.md"));
    }

    #[test]
    fn a_stale_entry_and_a_bad_derivation_both_fail() {
        let owned = ownership(
            r#"
[[reverse]]
path = "Cargo.toml"
derives-from = ["original/absent.ac"]
[[reverse]]
path = "refactor/docs/DECISION-LOG.md"
project-owned = true
decision = "DL-0023"
[[reverse]]
path = "gone.txt"
project-owned = true
decision = "DL-0023"
"#,
        );
        let mut report = Report::new("test");
        let _ = resolve(&tree(), &owned, &decisions(), &mut report);
        let rendered = report.render();
        assert!(
            rendered.contains("FAIL reverse/entries-exist"),
            "{rendered}"
        );
        assert!(rendered.contains("FAIL reverse/no-gap"));
        assert!(rendered.contains("absent.ac"));
    }

    #[test]
    fn a_project_owned_entry_needs_a_resolving_pointer() {
        let owned = ownership(
            r#"
[[reverse]]
path = "Cargo.toml"
project-owned = true
decision = "DL-9999"
[[reverse]]
path = "refactor/docs/DECISION-LOG.md"
project-owned = true
decision = "DL-0023"
"#,
        );
        let mut report = Report::new("test");
        let _ = resolve(&tree(), &owned, &decisions(), &mut report);
        assert!(report.render().contains("FAIL reverse/no-gap"));
    }
}
