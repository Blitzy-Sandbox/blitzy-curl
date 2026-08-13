// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: the blitzy-curl project contributors

//! The hazard register: one row per hazard the oracle carries, with the verdict
//! the port holds, the crate that owns it and the verification that proves it.
//!
//! The register carries no rationale. Each row points at the decision row that
//! holds the reasoning, and a pointer that does not resolve is a failing check.

use std::collections::{BTreeSet, HashSet};

use curl_audit::fs::Files;
use curl_audit::report::Report;
use curl_audit::workspace::{AuditError, AuditResult};
use toml::Value;

/// The verdicts a hazard may carry.
///
/// Three of them describe what the port does with a hazard it has. The fourth
/// exists for code the platform matrix excludes, which has no counterpart to
/// reproduce, substitute or diverge from.
pub const VERDICTS: [&str; 4] = ["reproduce", "substitute", "diverge", "not-ported"];

/// The states a compensating verification may be in.
pub const STATUSES: [&str; 2] = ["obligation", "verified"];

/// Owner value a `not-ported` hazard carries.
pub const NO_OWNER: &str = "none";

/// One hazard as declared.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hazard {
    /// Project identifier.
    pub id: String,
    /// Oracle path the hazard is in.
    pub path: String,
    /// Inclusive one-based line range.
    pub lines: (usize, usize),
    /// What the oracle observably does.
    pub behaviour: String,
    /// What the port does about it.
    pub verdict: String,
    /// Crate that owns it, or `none`.
    pub owner: String,
    /// Verification that proves the verdict.
    pub verification: String,
    /// Whether that verification is an obligation or a result.
    pub status: String,
    /// Decision row holding the reasoning.
    pub decision: String,
}

/// The declared register.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Register {
    /// Hazards in declaration order.
    pub hazards: Vec<Hazard>,
}

fn text<'a>(entry: &'a Value, key: &str, id: &str) -> AuditResult<&'a str> {
    entry
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| AuditError::new(format!("{id}: {key} missing")))
}

impl Register {
    /// Reads the register from `path`.
    pub fn load(files: &dyn Files, path: &str) -> AuditResult<Self> {
        let body = files
            .read(path)
            .ok_or_else(|| AuditError::new(format!("{path} is missing")))?;
        let value: Value =
            toml::from_str(&body).map_err(|error| AuditError::new(format!("{path}: {error}")))?;
        let entries = value
            .get("hazard")
            .and_then(Value::as_array)
            .ok_or_else(|| AuditError::new(format!("{path} declares no hazard")))?;
        let mut hazards = Vec::new();
        for entry in entries {
            let id = entry
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| AuditError::new(format!("{path}: a hazard has no id")))?;
            let range = entry
                .get("lines")
                .and_then(Value::as_array)
                .ok_or_else(|| AuditError::new(format!("{id}: lines missing")))?;
            let bound = |index: usize| -> AuditResult<usize> {
                range
                    .get(index)
                    .and_then(Value::as_integer)
                    .and_then(|line| usize::try_from(line).ok())
                    .ok_or_else(|| AuditError::new(format!("{id}: lines is not a range")))
            };
            hazards.push(Hazard {
                id: id.to_owned(),
                path: text(entry, "path", id)?.to_owned(),
                lines: (bound(0)?, bound(1)?),
                behaviour: text(entry, "behaviour", id)?.to_owned(),
                verdict: text(entry, "verdict", id)?.to_owned(),
                owner: text(entry, "owner", id)?.to_owned(),
                verification: text(entry, "verification", id)?.to_owned(),
                status: text(entry, "status", id)?.to_owned(),
                decision: text(entry, "decision", id)?.to_owned(),
            });
        }
        if hazards.is_empty() {
            return Err(AuditError::new(format!("{path} declares no hazard")));
        }
        Ok(Self { hazards })
    }

    /// Runs every register gate and returns the rows that passed them.
    pub fn resolve(
        &self,
        files: &dyn Files,
        planned: &BTreeSet<String>,
        decisions: &BTreeSet<String>,
        report: &mut Report,
    ) -> Vec<Hazard> {
        report.assert(
            !self.hazards.is_empty(),
            "hazard/declared",
            format!("{} hazard(s) declared", self.hazards.len()),
        );

        let mut identifiers: HashSet<&str> = HashSet::new();
        let mut duplicate = Vec::new();
        for hazard in &self.hazards {
            if !identifiers.insert(hazard.id.as_str()) {
                duplicate.push(hazard.id.clone());
            }
        }
        report.assert(
            duplicate.is_empty(),
            "hazard/identifiers-unique",
            if duplicate.is_empty() {
                format!("{} distinct identifier(s)", identifiers.len())
            } else {
                format!("duplicated: {}", duplicate.join(", "))
            },
        );

        let mut unresolved = Vec::new();
        for hazard in &self.hazards {
            match files.read(&hazard.path) {
                None => unresolved.push(format!("{}: {} is absent", hazard.id, hazard.path)),
                Some(body) => {
                    let lines = body.lines().count();
                    let (first, last) = hazard.lines;
                    if first == 0 || first > last || last > lines {
                        unresolved.push(format!(
                            "{}: {}:{}-{} outside a {}-line file",
                            hazard.id, hazard.path, first, last, lines
                        ));
                    }
                }
            }
        }
        report.assert(
            unresolved.is_empty(),
            "hazard/locators-resolve",
            if unresolved.is_empty() {
                format!("{} locator(s) inside the oracle", self.hazards.len())
            } else {
                format!("unresolved: {}", unresolved.join("; "))
            },
        );

        let outside: Vec<String> = self
            .hazards
            .iter()
            .filter(|hazard| !hazard.path.starts_with("original/"))
            .map(|hazard| hazard.id.clone())
            .collect();
        report.assert(
            outside.is_empty(),
            "hazard/locators-are-oracle-paths",
            if outside.is_empty() {
                "every locator names a path inside the oracle".to_owned()
            } else {
                format!("outside the oracle: {}", outside.join(", "))
            },
        );

        let bad_verdict: Vec<String> = self
            .hazards
            .iter()
            .filter(|hazard| !VERDICTS.contains(&hazard.verdict.as_str()))
            .map(|hazard| format!("{}: {}", hazard.id, hazard.verdict))
            .collect();
        report.assert(
            bad_verdict.is_empty(),
            "hazard/verdicts-in-vocabulary",
            if bad_verdict.is_empty() {
                format!("every verdict is one of {}", VERDICTS.join(", "))
            } else {
                format!("outside the vocabulary: {}", bad_verdict.join(", "))
            },
        );

        let bad_owner: Vec<String> = self
            .hazards
            .iter()
            .filter(|hazard| {
                if hazard.verdict == "not-ported" {
                    hazard.owner != NO_OWNER
                } else {
                    !planned.contains(&hazard.owner)
                }
            })
            .map(|hazard| format!("{}: {}", hazard.id, hazard.owner))
            .collect();
        report.assert(
            bad_owner.is_empty(),
            "hazard/owners-planned",
            if bad_owner.is_empty() {
                "every owner is a planned crate, and only an unported hazard has none".to_owned()
            } else {
                format!("bad owner: {}", bad_owner.join(", "))
            },
        );

        let unpointed: Vec<String> = self
            .hazards
            .iter()
            .filter(|hazard| !decisions.contains(&hazard.decision))
            .map(|hazard| format!("{}: {}", hazard.id, hazard.decision))
            .collect();
        report.assert(
            unpointed.is_empty(),
            "hazard/decisions-resolve",
            if unpointed.is_empty() {
                "every hazard points at a decision row that exists".to_owned()
            } else {
                format!("dangling: {}", unpointed.join(", "))
            },
        );

        let unverified: Vec<String> = self
            .hazards
            .iter()
            .filter(|hazard| {
                hazard.verification.trim().is_empty() || !STATUSES.contains(&hazard.status.as_str())
            })
            .map(|hazard| hazard.id.clone())
            .collect();
        report.assert(
            unverified.is_empty(),
            "hazard/verification-named",
            if unverified.is_empty() {
                format!(
                    "{} obligation(s) and {} result(s), each naming its verification",
                    self.hazards
                        .iter()
                        .filter(|hazard| hazard.status == "obligation")
                        .count(),
                    self.hazards
                        .iter()
                        .filter(|hazard| hazard.status == "verified")
                        .count()
                )
            } else {
                format!(
                    "no named verification or bad status: {}",
                    unverified.join(", ")
                )
            },
        );

        let unproven: Vec<String> = self
            .hazards
            .iter()
            .filter(|hazard| hazard.status == "verified" && !files.exists(&hazard.verification))
            .map(|hazard| hazard.id.clone())
            .collect();
        report.assert(
            unproven.is_empty(),
            "hazard/no-unproven-pass",
            if unproven.is_empty() {
                "no hazard claims a result without an artifact that exists".to_owned()
            } else {
                format!("claimed without an artifact: {}", unproven.join(", "))
            },
        );

        let unlisted: Vec<String> = self
            .hazards
            .iter()
            .filter(|hazard| {
                hazard.verdict == "diverge" && !hazard.verification.contains("allowlist")
            })
            .map(|hazard| hazard.id.clone())
            .collect();
        report.assert(
            unlisted.is_empty(),
            "hazard/divergences-name-the-allowlist",
            if unlisted.is_empty() {
                format!(
                    "{} divergence(s), each naming its allowlist entry",
                    self.hazards
                        .iter()
                        .filter(|hazard| hazard.verdict == "diverge")
                        .count()
                )
            } else {
                format!("no allowlist entry named: {}", unlisted.join(", "))
            },
        );

        self.hazards.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use curl_audit::fs::MapFiles;
    use curl_audit::report::Report;

    use super::Register;

    const GOOD: &str = r#"
schema = 1
[[hazard]]
id = "HZ-0001"
path = "original/lib/file.c"
lines = [1, 2]
behaviour = "A read error ends the body as end of data."
verdict = "reproduce"
owner = "curl-proto-file"
verification = "Equivalence test over a failing read."
status = "obligation"
decision = "DL-0113"
[[hazard]]
id = "HZ-0002"
path = "original/lib/file.c"
lines = [2, 3]
behaviour = "An indeterminate mode is read outside its guard."
verdict = "diverge"
owner = "curl-proto-file"
verification = "Fault-injected failure plus the divergence-allowlist entry."
status = "obligation"
decision = "DL-0113"
[[hazard]]
id = "HZ-0003"
path = "original/lib/setup-vms.h"
lines = [1, 1]
behaviour = "A non-void path can fall through."
verdict = "not-ported"
owner = "none"
verification = "Platform matrix excludes OpenVMS."
status = "obligation"
decision = "DL-0052"
"#;

    fn tree() -> MapFiles {
        MapFiles::new()
            .with("data/hazards.toml", GOOD)
            .with("original/lib/file.c", "a\nb\nc\n")
            .with("original/lib/setup-vms.h", "a\n")
    }

    fn planned() -> BTreeSet<String> {
        ["curl-proto-file"].into_iter().map(str::to_owned).collect()
    }

    fn decisions() -> BTreeSet<String> {
        ["DL-0052", "DL-0113"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn a_missing_or_empty_register_is_an_error() {
        assert!(Register::load(&MapFiles::new(), "data/hazards.toml").is_err());
        let files = MapFiles::new().with("data/hazards.toml", "schema = 1\n");
        assert!(Register::load(&files, "data/hazards.toml").is_err());
    }

    #[test]
    fn a_complete_register_passes_every_gate() {
        let files = tree();
        let register = Register::load(&files, "data/hazards.toml").expect("loads");
        let mut report = Report::new("test");
        let rows = register.resolve(&files, &planned(), &decisions(), &mut report);
        let rendered = report.render();
        assert_eq!(rows.len(), 3);
        assert!(report.passed(), "{rendered}");
        assert!(rendered.contains("PASS hazard/locators-resolve"));
        assert!(rendered.contains("PASS hazard/divergences-name-the-allowlist"));
    }

    #[test]
    fn a_locator_past_the_end_of_the_file_fails() {
        let text = GOOD.replace("lines = [1, 2]", "lines = [1, 99]");
        let files = tree().with("data/hazards.toml", &text);
        let register = Register::load(&files, "data/hazards.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = register.resolve(&files, &planned(), &decisions(), &mut report);
        assert!(report.render().contains("FAIL hazard/locators-resolve"));
    }

    #[test]
    fn a_verdict_outside_the_vocabulary_fails() {
        let text = GOOD.replace("verdict = \"reproduce\"", "verdict = \"ignore\"");
        let files = tree().with("data/hazards.toml", &text);
        let register = Register::load(&files, "data/hazards.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = register.resolve(&files, &planned(), &decisions(), &mut report);
        assert!(
            report
                .render()
                .contains("FAIL hazard/verdicts-in-vocabulary")
        );
    }

    #[test]
    fn a_divergence_with_no_allowlist_entry_fails() {
        let text = GOOD.replace(
            "verification = \"Fault-injected failure plus the divergence-allowlist entry.\"",
            "verification = \"Fault-injected failure.\"",
        );
        let files = tree().with("data/hazards.toml", &text);
        let register = Register::load(&files, "data/hazards.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = register.resolve(&files, &planned(), &decisions(), &mut report);
        assert!(
            report
                .render()
                .contains("FAIL hazard/divergences-name-the-allowlist")
        );
    }

    #[test]
    fn an_unplanned_owner_a_dangling_pointer_and_a_claimed_pass_all_fail() {
        let text = GOOD
            .replace("owner = \"curl-proto-file\"", "owner = \"curl-nowhere\"")
            .replace("decision = \"DL-0113\"", "decision = \"DL-9999\"")
            .replace("status = \"obligation\"", "status = \"verified\"");
        let files = tree().with("data/hazards.toml", &text);
        let register = Register::load(&files, "data/hazards.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = register.resolve(&files, &planned(), &decisions(), &mut report);
        let rendered = report.render();
        assert!(
            rendered.contains("FAIL hazard/owners-planned"),
            "{rendered}"
        );
        assert!(rendered.contains("FAIL hazard/decisions-resolve"));
        assert!(rendered.contains("FAIL hazard/no-unproven-pass"));
    }

    #[test]
    fn a_duplicate_identifier_fails() {
        let text = GOOD.replace("id = \"HZ-0002\"", "id = \"HZ-0001\"");
        let files = tree().with("data/hazards.toml", &text);
        let register = Register::load(&files, "data/hazards.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = register.resolve(&files, &planned(), &decisions(), &mut report);
        assert!(report.render().contains("FAIL hazard/identifiers-unique"));
    }
}
