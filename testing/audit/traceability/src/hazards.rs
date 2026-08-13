// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: the blitzy-curl project contributors

//! The hazard register: one row per hazard the oracle carries, with the verdict
//! the port holds, the crate that owns it and the verification that proves it.
//!
//! The register carries no rationale. Each row points at the decision row that
//! holds the reasoning, and a pointer that does not resolve is a failing check.
//!
//! Completeness is a gate rather than a claim, and it rests on two declarations
//! and one mechanical pass. Every path a row names must be declared reviewed,
//! and a reviewed path declares how many rows it carries, so a row that is
//! dropped fails instead of shrinking the register in silence. Over every
//! reviewed path the discovery pass then scans for the annotations upstream
//! itself writes where it knows a behaviour is sharp - `FIXME`, `TODO`, `XXX`,
//! `HACK`, `KLUDGE`, `WORKAROUND`, and the prose it uses for the same purpose -
//! and requires each site to fall inside a hazard row's line range or to carry
//! a written disposition. A disposition that names a line no longer carrying an
//! annotation fails too, so the inventory cannot go stale in either direction.
//!
//! `DL-0110` records the register, `DL-0225` the discovery gate.

use std::collections::{BTreeMap, BTreeSet, HashSet};

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

/// Annotation acronyms the discovery pass scans for.
///
/// These match whole words and match case, which is what keeps a URL query of
/// `xxx`, a header value of `XXXX` and the word "hack" in ordinary prose from
/// reading as an upstream annotation.
pub const ANNOTATION_MARKERS: [&str; 6] = ["FIXME", "HACK", "KLUDGE", "TODO", "WORKAROUND", "XXX"];

/// Annotation phrases the discovery pass scans for, ignoring case.
///
/// Upstream writes these where it knows a behaviour is sharp but has no acronym
/// for it, so they carry as much of the inventory as the acronyms do.
pub const ANNOTATION_PHRASES: [&str; 7] = [
    "cannot happen",
    "deliberate",
    "for now",
    "never happen",
    "on purpose",
    "should not happen",
    "silently",
];

/// Oracle directory holding upstream's maintenance tooling.
///
/// A hazard row under this root can be answered by refusing the script, so it is
/// the domain of the guard gate below; a row anywhere else in the oracle names a
/// construct the wrapper cannot refuse by name.
pub const TOOLING_ROOT: &str = "original/scripts/";

/// Shell variable the guarded-tooling inventory is assigned to.
///
/// The wrapper builds the inventory over one or more assignments, so the parse
/// reads every line that assigns this name and drops the accumulating reference.
pub const GUARD_VARIABLE: &str = "guarded_tooling";

/// Dispositions an annotation site may carry when no hazard row covers it.
pub const ANNOTATION_CLASSES: [&str; 4] = [
    "behaviour-elsewhere",
    "defensive-invariant",
    "diagnosed-outcome",
    "no-observable-outcome",
];

/// One oracle path whose hazard review is complete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reviewed {
    /// Repository-relative path inside the oracle.
    pub path: String,
    /// Number of hazard rows the path carries.
    pub hazards: usize,
    /// Decision the review rests on.
    pub decision: String,
}

/// One divergence-allowlist entry.
///
/// The locator, the behaviour and the owner of the divergence itself live in the
/// hazard row this entry answers, so an entry carries only what the allowlist
/// adds: the deterministic outcome the port holds instead, why that is accepted,
/// and who is accountable for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Divergence {
    /// Entry identifier, unique across the allowlist.
    pub id: String,
    /// Hazard whose `diverge` verdict this entry answers.
    pub hazard: String,
    /// Deterministic outcome the port holds instead of the oracle's.
    pub outcome: String,
    /// Why the divergence is accepted.
    pub rationale: String,
    /// Planned member accountable for it.
    pub owner: String,
    /// Decision the divergence rests on.
    pub decision: String,
}

/// One discovered annotation site that carries no hazard row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Annotation {
    /// Oracle path the site is in.
    pub path: String,
    /// One-based line of the annotated statement or comment.
    pub line: usize,
    /// Why no hazard row covers it.
    pub class: String,
    /// Written disposition.
    pub reason: String,
    /// Decision the disposition rests on.
    pub decision: String,
}

/// What the completeness gate observed, for the rendered register.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Coverage {
    /// Oracle paths declared reviewed.
    pub reviewed: usize,
    /// Annotation sites discovered over those paths.
    pub sites: usize,
    /// Sites a hazard row's line range already covers.
    pub covered: usize,
    /// Dispositions, in path then line order.
    pub dispositions: Vec<Annotation>,
}

/// Whether a line carries an upstream annotation.
///
/// An acronym matches only as a whole uppercase word; a phrase matches anywhere,
/// ignoring case.
#[must_use]
pub fn is_annotated(line: &str) -> bool {
    let lowered = line.to_lowercase();
    if ANNOTATION_PHRASES
        .iter()
        .any(|phrase| lowered.contains(phrase))
    {
        return true;
    }
    ANNOTATION_MARKERS.iter().any(|marker| {
        line.match_indices(marker).any(|(offset, _)| {
            let before = line[..offset].chars().next_back();
            let after = line[offset + marker.len()..].chars().next();
            let boundary = |character: Option<char>| {
                character.is_none_or(|value| !value.is_ascii_alphanumeric() && value != '_')
            };
            boundary(before) && boundary(after)
        })
    })
}

/// The guarded-tooling inventory a staging wrapper declares.
///
/// The wrapper names the oracle scripts it refuses to run in one shell variable,
/// built over as many assignments as it needs; the parse takes the words between
/// the first and last quote of each assignment and drops the accumulating
/// reference to the variable itself. Names come back sorted and unique, so the
/// gates below read as set comparisons.
#[must_use]
pub fn guarded_inventory(files: &dyn Files, path: &str) -> Vec<String> {
    let assignment = format!("{GUARD_VARIABLE}=");
    let mut names = BTreeSet::new();
    for line in files.read(path).unwrap_or_default().lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with(&assignment) {
            continue;
        }
        let Some(opening) = trimmed.find('"') else {
            continue;
        };
        let Some(closing) = trimmed.rfind('"') else {
            continue;
        };
        if closing <= opening {
            continue;
        }
        for word in trimmed[opening + 1..closing].split_whitespace() {
            if !word.starts_with('$') {
                names.insert(word.to_owned());
            }
        }
    }
    names.into_iter().collect()
}

/// Every annotated line of `path`, one-based, in order.
#[must_use]
pub fn annotated_lines(files: &dyn Files, path: &str) -> Vec<usize> {
    files.read(path).map_or_else(Vec::new, |body| {
        body.lines()
            .enumerate()
            .filter(|(_, line)| is_annotated(line))
            .map(|(index, _)| index + 1)
            .collect()
    })
}

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
    /// Oracle paths whose hazard review is complete.
    pub reviewed: Vec<Reviewed>,
    /// Dispositioned annotation sites.
    pub annotations: Vec<Annotation>,
    /// Divergence-allowlist entries.
    pub divergences: Vec<Divergence>,
    /// Annotation acronyms the register declares.
    pub markers: Vec<String>,
    /// Annotation phrases the register declares.
    pub phrases: Vec<String>,
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

        let list = |key: &str| -> AuditResult<Vec<String>> {
            value
                .get(key)
                .and_then(Value::as_array)
                .ok_or_else(|| AuditError::new(format!("{path}: {key} missing")))?
                .iter()
                .map(|entry| {
                    entry
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| AuditError::new(format!("{path}: {key} holds a non-string")))
                })
                .collect()
        };
        let markers = list("annotation-markers")?;
        let phrases = list("annotation-phrases")?;

        let mut reviewed = Vec::new();
        for entry in value
            .get("reviewed")
            .and_then(Value::as_array)
            .ok_or_else(|| AuditError::new(format!("{path} declares no reviewed path")))?
        {
            let reviewed_path = entry
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| AuditError::new(format!("{path}: a reviewed row has no path")))?;
            let hazards = entry
                .get("hazards")
                .and_then(Value::as_integer)
                .and_then(|count| usize::try_from(count).ok())
                .ok_or_else(|| {
                    AuditError::new(format!("{reviewed_path}: reviewed count missing"))
                })?;
            reviewed.push(Reviewed {
                path: reviewed_path.to_owned(),
                hazards,
                decision: text(entry, "decision", reviewed_path)?.to_owned(),
            });
        }

        let mut annotations = Vec::new();
        for entry in value
            .get("annotation")
            .and_then(Value::as_array)
            .map_or_else(Vec::new, |array| array.iter().collect())
        {
            let annotated = entry
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| AuditError::new(format!("{path}: an annotation has no path")))?;
            let line = entry
                .get("line")
                .and_then(Value::as_integer)
                .and_then(|line| usize::try_from(line).ok())
                .ok_or_else(|| AuditError::new(format!("{annotated}: annotation line missing")))?;
            annotations.push(Annotation {
                path: annotated.to_owned(),
                line,
                class: text(entry, "class", annotated)?.to_owned(),
                reason: text(entry, "reason", annotated)?.to_owned(),
                decision: text(entry, "decision", annotated)?.to_owned(),
            });
        }

        let mut divergences = Vec::new();
        for entry in value
            .get("divergence")
            .and_then(Value::as_array)
            .map_or_else(Vec::new, |array| array.iter().collect())
        {
            let id = entry
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| AuditError::new(format!("{path}: a divergence has no id")))?;
            divergences.push(Divergence {
                id: id.to_owned(),
                hazard: text(entry, "hazard", id)?.to_owned(),
                outcome: text(entry, "outcome", id)?.to_owned(),
                rationale: text(entry, "rationale", id)?.to_owned(),
                owner: text(entry, "owner", id)?.to_owned(),
                decision: text(entry, "decision", id)?.to_owned(),
            });
        }

        Ok(Self {
            hazards,
            reviewed,
            annotations,
            divergences,
            markers,
            phrases,
        })
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

        self.allowlist(planned, decisions, report);

        self.complete(files, decisions, report);
        self.hazards.clone()
    }

    /// Runs the divergence-allowlist gates in both directions.
    ///
    /// A `diverge` verdict without an entry and an entry without a `diverge`
    /// verdict are the same defect seen from two sides, and the earlier free-text
    /// search for the word "allowlist" could see neither.
    fn allowlist(
        &self,
        planned: &BTreeSet<String>,
        decisions: &BTreeSet<String>,
        report: &mut Report,
    ) {
        let diverging: BTreeMap<&str, &Hazard> = self
            .hazards
            .iter()
            .filter(|hazard| hazard.verdict == "diverge")
            .map(|hazard| (hazard.id.as_str(), hazard))
            .collect();

        let identifiers: BTreeSet<&str> = self
            .divergences
            .iter()
            .map(|entry| entry.id.as_str())
            .collect();
        report.assert(
            identifiers.len() == self.divergences.len() && !self.divergences.is_empty(),
            "divergence/identifiers-unique",
            format!(
                "{} entry/entries, {} distinct identifier(s)",
                self.divergences.len(),
                identifiers.len()
            ),
        );

        let mut answered: BTreeMap<&str, usize> = BTreeMap::new();
        for entry in &self.divergences {
            *answered.entry(entry.hazard.as_str()).or_default() += 1;
        }
        let unlisted: Vec<&str> = diverging
            .keys()
            .filter(|id| answered.get(*id).copied().unwrap_or(0) != 1)
            .copied()
            .collect();
        report.assert(
            unlisted.is_empty() && !diverging.is_empty(),
            "divergence/every-verdict-listed",
            if unlisted.is_empty() {
                format!(
                    "{} divergence(s), each carrying exactly one allowlist entry",
                    diverging.len()
                )
            } else {
                format!("no single entry answers: {}", unlisted.join(", "))
            },
        );

        let orphaned: Vec<String> = self
            .divergences
            .iter()
            .filter(|entry| !diverging.contains_key(entry.hazard.as_str()))
            .map(|entry| format!("{}: {}", entry.id, entry.hazard))
            .collect();
        report.assert(
            orphaned.is_empty(),
            "divergence/every-entry-answers-a-verdict",
            if orphaned.is_empty() {
                "every entry answers a hazard whose verdict is diverge".to_owned()
            } else {
                format!("answers no divergence: {}", orphaned.join(", "))
            },
        );

        let mismatched: Vec<String> = self
            .divergences
            .iter()
            .filter(|entry| {
                diverging
                    .get(entry.hazard.as_str())
                    .is_some_and(|hazard| hazard.owner != entry.owner)
            })
            .map(|entry| format!("{}: {}", entry.id, entry.owner))
            .collect();
        report.assert(
            mismatched.is_empty(),
            "divergence/owners-agree",
            if mismatched.is_empty() {
                "every entry names the owner its hazard row names".to_owned()
            } else {
                format!("owner disagrees with the row: {}", mismatched.join(", "))
            },
        );

        let unaccountable: Vec<String> = self
            .divergences
            .iter()
            .filter(|entry| {
                !planned.contains(&entry.owner)
                    || entry.outcome.trim().is_empty()
                    || entry.rationale.trim().is_empty()
                    || !decisions.contains(&entry.decision)
            })
            .map(|entry| entry.id.clone())
            .collect();
        report.assert(
            unaccountable.is_empty(),
            "divergence/entries-accountable",
            if unaccountable.is_empty() {
                "every entry names an outcome, a rationale, a planned owner and a decision"
                    .to_owned()
            } else {
                format!("incomplete: {}", unaccountable.join(", "))
            },
        );
    }

    /// What the discovery pass observed over the reviewed set.
    ///
    /// The rendered register carries these figures so a reader sees the
    /// denominator the gate used rather than a claim of completeness.
    #[must_use]
    pub fn coverage(&self, files: &dyn Files) -> Coverage {
        let mut ranges: BTreeMap<&str, Vec<(usize, usize)>> = BTreeMap::new();
        for hazard in &self.hazards {
            ranges
                .entry(hazard.path.as_str())
                .or_default()
                .push(hazard.lines);
        }
        let mut sites = 0_usize;
        let mut covered = 0_usize;
        for entry in &self.reviewed {
            let spans = ranges.get(entry.path.as_str());
            for line in annotated_lines(files, &entry.path) {
                sites += 1;
                if spans.is_some_and(|spans| {
                    spans
                        .iter()
                        .any(|(low, high)| *low <= line && line <= *high)
                }) {
                    covered += 1;
                }
            }
        }
        let mut dispositions = self.annotations.clone();
        dispositions.sort_by(|left, right| (&left.path, left.line).cmp(&(&right.path, right.line)));
        Coverage {
            reviewed: self.reviewed.len(),
            sites,
            covered,
            dispositions,
        }
    }

    /// Gates the staging wrapper's guarded-tooling inventory against the
    /// register, in both directions.
    ///
    /// A row that names the wrapper as its verification claims the wrapper keeps
    /// that oracle script off the project's invocation surface, so the inventory
    /// must carry the script the row names; and an entry the inventory carries
    /// that answers no row is a guard nobody accounted for. Rows outside the
    /// oracle's tooling directory are not in the domain: the guard matches a
    /// script by name and cannot refuse a translation unit or a harness module.
    /// `DL-0306` records the arrangement.
    pub fn guard(&self, files: &dyn Files, guard: &str, report: &mut Report) {
        let inventory = guarded_inventory(files, guard);
        report.assert(
            !inventory.is_empty(),
            "hazard/guarded-tooling-declared",
            if inventory.is_empty() {
                format!("{guard} declares no guarded entry")
            } else {
                format!(
                    "{} guarded entry/entries declared by {guard}",
                    inventory.len()
                )
            },
        );
        let declared: BTreeSet<&str> = inventory.iter().map(String::as_str).collect();

        let mut answered: BTreeSet<&str> = BTreeSet::new();
        let mut unguarded = Vec::new();
        let mut rows = 0_usize;
        for hazard in &self.hazards {
            if hazard.verification != guard || !hazard.path.starts_with(TOOLING_ROOT) {
                continue;
            }
            rows += 1;
            let script = hazard.path.rsplit('/').next().unwrap_or_default();
            if declared.contains(script) {
                answered.insert(script);
            } else {
                unguarded.push(format!("{}: {}", hazard.id, hazard.path));
            }
        }
        report.assert(
            unguarded.is_empty(),
            "hazard/guarded-tooling-covers-rows",
            if unguarded.is_empty() {
                format!("{rows} row(s) verified by the guard name a declared entry")
            } else {
                format!("not guarded: {}", unguarded.join(", "))
            },
        );

        let dead: Vec<&str> = declared
            .iter()
            .copied()
            .filter(|script| !answered.contains(script))
            .collect();
        report.assert(
            dead.is_empty(),
            "hazard/guarded-tooling-answered",
            if dead.is_empty() {
                format!(
                    "every one of {} guarded entry/entries answers a row",
                    declared.len()
                )
            } else {
                format!("answers no row: {}", dead.join(", "))
            },
        );
    }

    /// Runs the completeness gates: the reviewed set, the frozen per-path counts
    /// and the annotation inventory.
    ///
    /// Kept apart from [`Register::resolve`] so the discovery pass reads as the
    /// one gate it is rather than as another per-row check.
    fn complete(&self, files: &dyn Files, decisions: &BTreeSet<String>, report: &mut Report) {
        report.assert(
            self.markers == ANNOTATION_MARKERS && self.phrases == ANNOTATION_PHRASES,
            "hazard/annotation-vocabulary-declared",
            format!(
                "{} acronym(s) and {} phrase(s) declared and implemented",
                self.markers.len(),
                self.phrases.len()
            ),
        );

        let reviewed: BTreeMap<&str, &Reviewed> = self
            .reviewed
            .iter()
            .map(|entry| (entry.path.as_str(), entry))
            .collect();
        report.assert(
            reviewed.len() == self.reviewed.len() && !reviewed.is_empty(),
            "hazard/reviewed-paths-unique",
            format!("{} reviewed path(s)", self.reviewed.len()),
        );

        let missing: Vec<&str> = self
            .reviewed
            .iter()
            .filter(|entry| !files.exists(&entry.path))
            .map(|entry| entry.path.as_str())
            .collect();
        report.assert(
            missing.is_empty(),
            "hazard/reviewed-paths-exist",
            if missing.is_empty() {
                "every reviewed path is in the oracle".to_owned()
            } else {
                format!("absent: {}", missing.join(", "))
            },
        );

        let dangling: Vec<String> = self
            .reviewed
            .iter()
            .filter(|entry| !decisions.contains(&entry.decision))
            .map(|entry| format!("{}: {}", entry.path, entry.decision))
            .collect();
        report.assert(
            dangling.is_empty(),
            "hazard/reviewed-decisions-resolve",
            if dangling.is_empty() {
                "every reviewed path points at a decision row that exists".to_owned()
            } else {
                format!("dangling: {}", dangling.join(", "))
            },
        );

        let mut observed: BTreeMap<&str, usize> = BTreeMap::new();
        for hazard in &self.hazards {
            *observed.entry(hazard.path.as_str()).or_default() += 1;
        }
        let unreviewed: Vec<&str> = observed
            .keys()
            .filter(|path| !reviewed.contains_key(*path))
            .copied()
            .collect();
        report.assert(
            unreviewed.is_empty(),
            "hazard/paths-reviewed",
            if unreviewed.is_empty() {
                format!("every row names one of {} reviewed path(s)", reviewed.len())
            } else {
                format!("not declared reviewed: {}", unreviewed.join(", "))
            },
        );

        let drifted: Vec<String> = self
            .reviewed
            .iter()
            .filter(|entry| {
                observed.get(entry.path.as_str()).copied().unwrap_or(0) != entry.hazards
            })
            .map(|entry| {
                format!(
                    "{}: {} declared, {} present",
                    entry.path,
                    entry.hazards,
                    observed.get(entry.path.as_str()).copied().unwrap_or(0)
                )
            })
            .collect();
        report.assert(
            drifted.is_empty(),
            "hazard/reviewed-counts-frozen",
            if drifted.is_empty() {
                format!("{} row(s) across the reviewed set", self.hazards.len())
            } else {
                format!("count drift: {}", drifted.join("; "))
            },
        );

        let mut ranges: BTreeMap<&str, Vec<(usize, usize)>> = BTreeMap::new();
        for hazard in &self.hazards {
            ranges
                .entry(hazard.path.as_str())
                .or_default()
                .push(hazard.lines);
        }
        let mut dispositioned: BTreeSet<(&str, usize)> = BTreeSet::new();
        for annotation in &self.annotations {
            dispositioned.insert((annotation.path.as_str(), annotation.line));
        }

        let mut sites = 0_usize;
        let mut uncovered = Vec::new();
        for entry in &self.reviewed {
            let covered = ranges.get(entry.path.as_str());
            for line in annotated_lines(files, &entry.path) {
                sites += 1;
                let inside = covered.is_some_and(|spans| {
                    spans
                        .iter()
                        .any(|(low, high)| *low <= line && line <= *high)
                });
                if !inside && !dispositioned.contains(&(entry.path.as_str(), line)) {
                    uncovered.push(format!("{}:{line}", entry.path));
                }
            }
        }
        report.assert(
            uncovered.is_empty() && sites > 0,
            "hazard/annotations-accounted",
            if uncovered.is_empty() {
                format!(
                    "{sites} annotation site(s) over {} reviewed path(s), {} dispositioned",
                    self.reviewed.len(),
                    self.annotations.len()
                )
            } else {
                format!(
                    "{} site(s) with neither a row nor a disposition: {}",
                    uncovered.len(),
                    uncovered.join(", ")
                )
            },
        );

        let stale: Vec<String> = self
            .annotations
            .iter()
            .filter(|annotation| {
                !reviewed.contains_key(annotation.path.as_str())
                    || !annotated_lines(files, &annotation.path).contains(&annotation.line)
                    || ranges.get(annotation.path.as_str()).is_some_and(|spans| {
                        spans
                            .iter()
                            .any(|(low, high)| *low <= annotation.line && annotation.line <= *high)
                    })
            })
            .map(|annotation| format!("{}:{}", annotation.path, annotation.line))
            .collect();
        report.assert(
            stale.is_empty(),
            "hazard/dispositions-resolve",
            if stale.is_empty() {
                format!("{} disposition(s) name a live site", self.annotations.len())
            } else {
                format!("stale or redundant: {}", stale.join(", "))
            },
        );

        let malformed: Vec<String> = self
            .annotations
            .iter()
            .filter(|annotation| {
                !ANNOTATION_CLASSES.contains(&annotation.class.as_str())
                    || annotation.reason.trim().is_empty()
                    || !decisions.contains(&annotation.decision)
            })
            .map(|annotation| format!("{}:{}", annotation.path, annotation.line))
            .collect();
        report.assert(
            malformed.is_empty(),
            "hazard/dispositions-well-formed",
            if malformed.is_empty() {
                format!(
                    "every disposition carries one of {} class(es), a reason and a decision",
                    ANNOTATION_CLASSES.len()
                )
            } else {
                format!("malformed: {}", malformed.join(", "))
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use curl_audit::fs::MapFiles;
    use curl_audit::report::Report;

    use super::{Register, annotated_lines, guarded_inventory, is_annotated};

    const GOOD: &str = r#"
schema = 1
annotation-markers = ["FIXME", "HACK", "KLUDGE", "TODO", "WORKAROUND", "XXX"]
annotation-phrases = [
  "cannot happen",
  "deliberate",
  "for now",
  "never happen",
  "on purpose",
  "should not happen",
  "silently",
]
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

[[reviewed]]
path = "original/lib/file.c"
hazards = 2
decision = "DL-0225"

[[reviewed]]
path = "original/lib/setup-vms.h"
hazards = 1
decision = "DL-0225"

[[annotation]]
path = "original/lib/file.c"
line = 4
class = "defensive-invariant"
reason = "Guards a state the caller excludes."
decision = "DL-0225"

[[divergence]]
id = "DV-0001"
hazard = "HZ-0002"
outcome = "The guard answers not-a-directory rather than reading the buffer."
rationale = "Safe Rust cannot read an indeterminate value."
owner = "curl-proto-file"
decision = "DL-0113"
"#;

    fn tree() -> MapFiles {
        MapFiles::new()
            .with("data/hazards.toml", GOOD)
            .with("original/lib/file.c", "a\nb\nc\n/* should not happen */\n")
            .with("original/lib/setup-vms.h", "a\n")
    }

    fn planned() -> BTreeSet<String> {
        ["curl-proto-file"].into_iter().map(str::to_owned).collect()
    }

    fn decisions() -> BTreeSet<String> {
        ["DL-0052", "DL-0113", "DL-0225"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    /// Path the guarded-tooling fixtures use for the staging wrapper.
    const GUARD: &str = "testing/upstream-suite/baseline-bootstrap";

    /// A wrapper whose inventory is built over two assignments.
    const WRAPPER: &str =
        "#!/bin/sh\nguarded_tooling=\"tool.sh\"\nguarded_tooling=\"$guarded_tooling helper.pl\"\n";

    /// Two guarded oracle-tooling rows, and a wrapper carrying `inventory`.
    fn guarded_tree(inventory: &str) -> MapFiles {
        let rows = format!(
            "[[hazard]]
id = \"HZ-0004\"
path = \"original/scripts/tool.sh\"
lines = [1, 1]
behaviour = \"A caller-supplied name reaches a shell.\"
verdict = \"substitute\"
owner = \"upstream-suite\"
verification = \"{GUARD}\"
status = \"verified\"
decision = \"DL-0306\"

[[hazard]]
id = \"HZ-0005\"
path = \"original/scripts/helper.pl\"
lines = [1, 1]
behaviour = \"A temporary name is predictable.\"
verdict = \"substitute\"
owner = \"upstream-suite\"
verification = \"{GUARD}\"
status = \"verified\"
decision = \"DL-0306\"

[[reviewed]]
path = \"original/scripts/tool.sh\"
hazards = 1
decision = \"DL-0306\"

[[reviewed]]
path = \"original/scripts/helper.pl\"
hazards = 1
decision = \"DL-0306\"

"
        );
        let text = GOOD.replace("[[divergence]]", &format!("{rows}[[divergence]]"));
        tree()
            .with("data/hazards.toml", &text)
            .with("original/scripts/tool.sh", "#!/bin/sh\n")
            .with("original/scripts/helper.pl", "use strict;\n")
            .with(GUARD, inventory)
    }

    fn guarded_planned() -> BTreeSet<String> {
        ["curl-proto-file", "upstream-suite"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    fn guarded_decisions() -> BTreeSet<String> {
        ["DL-0052", "DL-0113", "DL-0225", "DL-0306"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    /// Runs both the per-row gates and the guard gate over one fixture.
    fn guarded_report(files: &MapFiles) -> String {
        let register = Register::load(files, "data/hazards.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = register.resolve(files, &guarded_planned(), &guarded_decisions(), &mut report);
        register.guard(files, GUARD, &mut report);
        report.render()
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
        assert!(rendered.contains("PASS divergence/every-verdict-listed"));
        assert!(rendered.contains("PASS divergence/every-entry-answers-a-verdict"));
        assert!(rendered.contains("PASS divergence/owners-agree"));
        assert!(rendered.contains("PASS divergence/entries-accountable"));
        assert!(rendered.contains("PASS divergence/identifiers-unique"));
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
        let text = GOOD
            .replace("id = \"DV-0001\"", "id = \"DV-0009\"")
            .replace("hazard = \"HZ-0002\"", "hazard = \"HZ-0001\"");
        let files = tree().with("data/hazards.toml", &text);
        let register = Register::load(&files, "data/hazards.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = register.resolve(&files, &planned(), &decisions(), &mut report);
        let rendered = report.render();
        assert!(
            rendered.contains("FAIL divergence/every-verdict-listed"),
            "{rendered}"
        );
        assert!(
            rendered.contains("FAIL divergence/every-entry-answers-a-verdict"),
            "{rendered}"
        );
    }

    #[test]
    fn a_row_that_merely_says_allowlist_no_longer_satisfies_the_gate() {
        let text = GOOD
            .replace(
                "[[divergence]]\nid = \"DV-0001\"\nhazard = \"HZ-0002\"\noutcome = \"The guard answers not-a-directory rather than reading the buffer.\"\nrationale = \"Safe Rust cannot read an indeterminate value.\"\nowner = \"curl-proto-file\"\ndecision = \"DL-0113\"\n",
                "",
            );
        let files = tree().with("data/hazards.toml", &text);
        let register = Register::load(&files, "data/hazards.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = register.resolve(&files, &planned(), &decisions(), &mut report);
        let rendered = report.render();
        assert!(
            rendered.contains("FAIL divergence/every-verdict-listed"),
            "{rendered}"
        );
        assert!(
            rendered.contains("FAIL divergence/identifiers-unique"),
            "{rendered}"
        );
    }

    #[test]
    fn a_duplicated_entry_identifier_fails() {
        let text = format!(
            "{GOOD}\n[[divergence]]\nid = \"DV-0001\"\nhazard = \"HZ-0002\"\noutcome = \"A second answer.\"\nrationale = \"Duplicated on purpose.\"\nowner = \"curl-proto-file\"\ndecision = \"DL-0113\"\n"
        );
        let files = tree().with("data/hazards.toml", &text);
        let register = Register::load(&files, "data/hazards.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = register.resolve(&files, &planned(), &decisions(), &mut report);
        let rendered = report.render();
        assert!(
            rendered.contains("FAIL divergence/identifiers-unique"),
            "{rendered}"
        );
        assert!(
            rendered.contains("FAIL divergence/every-verdict-listed"),
            "{rendered}"
        );
    }

    #[test]
    fn an_entry_disagreeing_with_its_row_about_the_owner_fails() {
        let text = GOOD.replace(
            "rationale = \"Safe Rust cannot read an indeterminate value.\"\nowner = \"curl-proto-file\"\ndecision = \"DL-0113\"",
            "rationale = \"Safe Rust cannot read an indeterminate value.\"\nowner = \"curl-dns\"\ndecision = \"DL-0113\"",
        );
        let files = tree().with("data/hazards.toml", &text);
        let register = Register::load(&files, "data/hazards.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = register.resolve(&files, &planned(), &decisions(), &mut report);
        let rendered = report.render();
        assert!(
            rendered.contains("FAIL divergence/owners-agree"),
            "{rendered}"
        );
    }

    #[test]
    fn an_entry_with_no_rationale_or_a_dangling_decision_fails() {
        let blank = GOOD.replace(
            "rationale = \"Safe Rust cannot read an indeterminate value.\"",
            "rationale = \"   \"",
        );
        let files = tree().with("data/hazards.toml", &blank);
        let register = Register::load(&files, "data/hazards.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = register.resolve(&files, &planned(), &decisions(), &mut report);
        assert!(
            report
                .render()
                .contains("FAIL divergence/entries-accountable"),
            "a blank rationale must fail"
        );

        let dangling = GOOD.replace(
            "rationale = \"Safe Rust cannot read an indeterminate value.\"\nowner = \"curl-proto-file\"\ndecision = \"DL-0113\"",
            "rationale = \"Safe Rust cannot read an indeterminate value.\"\nowner = \"curl-proto-file\"\ndecision = \"DL-9999\"",
        );
        let files = tree().with("data/hazards.toml", &dangling);
        let register = Register::load(&files, "data/hazards.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = register.resolve(&files, &planned(), &decisions(), &mut report);
        assert!(
            report
                .render()
                .contains("FAIL divergence/entries-accountable"),
            "a dangling decision must fail"
        );
    }

    #[test]
    fn an_entry_missing_a_field_is_a_load_error() {
        let text = GOOD.replace(
            "outcome = \"The guard answers not-a-directory rather than reading the buffer.\"\n",
            "",
        );
        let files = tree().with("data/hazards.toml", &text);
        assert!(Register::load(&files, "data/hazards.toml").is_err());
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
    fn the_annotation_inventory_accounts_for_every_discovered_site() {
        let files = tree();
        let register = Register::load(&files, "data/hazards.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = register.resolve(&files, &planned(), &decisions(), &mut report);
        let rendered = report.render();
        assert!(report.passed(), "{rendered}");
        assert!(rendered.contains("PASS hazard/annotation-vocabulary-declared"));
        assert!(rendered.contains("PASS hazard/reviewed-counts-frozen"));
        assert!(
            rendered.contains("PASS hazard/annotations-accounted"),
            "{rendered}"
        );
    }

    #[test]
    fn an_undispositioned_annotation_site_fails() {
        let files = tree().with("original/lib/setup-vms.h", "a\n/* HACK for the linker */\n");
        let register = Register::load(&files, "data/hazards.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = register.resolve(&files, &planned(), &decisions(), &mut report);
        let rendered = report.render();
        assert!(
            rendered.contains("FAIL hazard/annotations-accounted"),
            "{rendered}"
        );
        assert!(rendered.contains("original/lib/setup-vms.h:2"));
    }

    #[test]
    fn a_hazard_on_an_undeclared_path_fails() {
        let text = GOOD.replace(
            "[[reviewed]]\npath = \"original/lib/setup-vms.h\"\nhazards = 1\ndecision = \"DL-0225\"\n",
            "",
        );
        let files = tree().with("data/hazards.toml", &text);
        let register = Register::load(&files, "data/hazards.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = register.resolve(&files, &planned(), &decisions(), &mut report);
        let rendered = report.render();
        assert!(
            rendered.contains("FAIL hazard/paths-reviewed"),
            "{rendered}"
        );
    }

    #[test]
    fn a_dropped_row_fails_the_frozen_count() {
        let text = GOOD.replace("hazards = 2", "hazards = 3");
        let files = tree().with("data/hazards.toml", &text);
        let register = Register::load(&files, "data/hazards.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = register.resolve(&files, &planned(), &decisions(), &mut report);
        let rendered = report.render();
        assert!(
            rendered.contains("FAIL hazard/reviewed-counts-frozen"),
            "{rendered}"
        );
        assert!(rendered.contains("3 declared, 2 present"));
    }

    #[test]
    fn a_stale_or_malformed_disposition_fails() {
        let stale = GOOD.replace("line = 4", "line = 2");
        let files = tree().with("data/hazards.toml", &stale);
        let register = Register::load(&files, "data/hazards.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = register.resolve(&files, &planned(), &decisions(), &mut report);
        assert!(report.render().contains("FAIL hazard/dispositions-resolve"));

        let malformed = GOOD
            .replace("class = \"defensive-invariant\"", "class = \"looks-fine\"")
            .replace(
                "reason = \"Guards a state the caller excludes.\"",
                "reason = \" \"",
            );
        let files = tree().with("data/hazards.toml", &malformed);
        let register = Register::load(&files, "data/hazards.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = register.resolve(&files, &planned(), &decisions(), &mut report);
        assert!(
            report
                .render()
                .contains("FAIL hazard/dispositions-well-formed")
        );
    }

    #[test]
    fn a_declared_vocabulary_that_is_not_the_implemented_one_fails() {
        let text = GOOD.replace("\"WORKAROUND\", ", "");
        let files = tree().with("data/hazards.toml", &text);
        let register = Register::load(&files, "data/hazards.toml").expect("loads");
        let mut report = Report::new("test");
        let _ = register.resolve(&files, &planned(), &decisions(), &mut report);
        assert!(
            report
                .render()
                .contains("FAIL hazard/annotation-vocabulary-declared")
        );
    }

    #[test]
    fn annotation_matching_reads_words_and_phrases() {
        assert!(is_annotated("  /* FIXME: later */"));
        assert!(is_annotated("if(x) /* should NOT Happen */"));
        assert!(is_annotated("/* silently ignore the rest */"));
        assert!(!is_annotated("url = \"/hoge?fuga=xxx\""));
        assert!(!is_annotated("Authorization: XXXX header"));
        assert!(!is_annotated("/* workaround icc 9.1 */"));
        assert!(!is_annotated("plain code;"));
        assert!(annotated_lines(&MapFiles::new(), "missing").is_empty());
    }

    #[test]
    fn a_register_with_no_reviewed_path_is_an_error() {
        let text = GOOD.replace("[[reviewed]]", "[[unused]]");
        let files = tree().with("data/hazards.toml", &text);
        assert!(Register::load(&files, "data/hazards.toml").is_err());
        let text = GOOD.replace("annotation-markers", "markers");
        let files = tree().with("data/hazards.toml", &text);
        assert!(Register::load(&files, "data/hazards.toml").is_err());
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

    #[test]
    fn a_guarded_row_and_its_inventory_entry_pass_together() {
        let files = guarded_tree(WRAPPER);
        let rendered = guarded_report(&files);
        assert!(
            rendered.contains("PASS hazard/guarded-tooling-declared"),
            "{rendered}"
        );
        assert!(rendered.contains("PASS hazard/guarded-tooling-covers-rows"));
        assert!(rendered.contains("PASS hazard/guarded-tooling-answered"));
        assert!(!rendered.contains("FAIL"), "{rendered}");
        assert_eq!(
            guarded_inventory(&files, GUARD),
            vec!["helper.pl".to_owned(), "tool.sh".to_owned()]
        );
    }

    #[test]
    fn a_row_the_inventory_forgets_fails() {
        let files = guarded_tree("#!/bin/sh\nguarded_tooling=\"tool.sh\"\n");
        let rendered = guarded_report(&files);
        assert!(
            rendered.contains("FAIL hazard/guarded-tooling-covers-rows"),
            "{rendered}"
        );
        assert!(rendered.contains("original/scripts/helper.pl"));
        assert!(rendered.contains("PASS hazard/guarded-tooling-answered"));
    }

    #[test]
    fn an_inventory_entry_no_row_answers_fails() {
        let files = guarded_tree("#!/bin/sh\nguarded_tooling=\"tool.sh helper.pl spare.sh\"\n");
        let rendered = guarded_report(&files);
        assert!(
            rendered.contains("FAIL hazard/guarded-tooling-answered"),
            "{rendered}"
        );
        assert!(rendered.contains("spare.sh"));
        assert!(rendered.contains("PASS hazard/guarded-tooling-covers-rows"));
    }

    #[test]
    fn an_empty_or_absent_inventory_fails() {
        let files = guarded_tree("#!/bin/sh\n");
        let rendered = guarded_report(&files);
        assert!(
            rendered.contains("FAIL hazard/guarded-tooling-declared"),
            "{rendered}"
        );
        assert!(rendered.contains("FAIL hazard/guarded-tooling-covers-rows"));
        assert!(guarded_inventory(&MapFiles::new(), GUARD).is_empty());
    }

    #[test]
    fn a_row_outside_the_tooling_directory_is_not_in_the_guard_domain() {
        let text = GOOD.replace(
            "verification = \"Platform matrix excludes OpenVMS.\"",
            &format!("verification = \"{GUARD}\""),
        );
        let files = tree()
            .with("data/hazards.toml", &text)
            .with(GUARD, WRAPPER)
            .with("original/scripts/tool.sh", "#!/bin/sh\n");
        let register = Register::load(&files, "data/hazards.toml").expect("loads");
        let mut report = Report::new("test");
        register.guard(&files, GUARD, &mut report);
        let rendered = report.render();
        assert!(
            rendered.contains("FAIL hazard/guarded-tooling-answered"),
            "{rendered}"
        );
        assert!(rendered.contains("PASS hazard/guarded-tooling-covers-rows"));
        assert!(rendered.contains("0 row(s) verified by the guard"));
    }
}
