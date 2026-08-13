// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: the blitzy-curl project contributors

//! Provenance ownership of the vendored tree: which crate owns each pinned-tag
//! path, and whether the record still agrees with the tag.
//!
//! The catalog is `[workspace.metadata.curl.provenance]` in the root manifest.
//! Each `owners` entry names a vendored path, its kind, the planned member that
//! owns it, the decision row that reasons about it, the `Makefile.inc` line that
//! registers it, and metrics this module re-measures rather than trusts. Nothing
//! here reads a figure and reports it: every recorded number is the result of a
//! named extraction rule, and the rule is run against `original/` on each
//! invocation, so a record that has drifted from the oracle fails instead of
//! reading as coverage.
//!
//! Two closure rules carry the failure modes this audit exists for. A
//! translation unit whose sibling header the tag carries may not be catalogued
//! alone, and no entry may name a path that a baseline-premise delta records as
//! absent. A third check reconciles the other direction: every vendored `.c` or
//! `.h` path named anywhere in the declared record set must exist in the tree or
//! be a recorded absent path, so a stale reference cannot sit unnoticed in a
//! record that no longer matches the tag.
//!
//! `DL-0138` records the decisions this check enforces, `DL-0043` the
//! enumeration rule it applies, and `DL-0039` the trace registry it reconciles
//! filter names against.

use std::collections::{BTreeMap, BTreeSet};

use toml::Value;

use crate::comments::decision_ids;
use crate::fs::Files;
use crate::premise::line_contains;
use crate::report::Report;
use crate::workspace::{AuditError, AuditResult, Workspace};

/// Extraction rules this module implements, in the order they are declared.
///
/// The audit asserts that `provenance.extraction` names exactly these, so a
/// rule cannot be recorded that no code runs and no rule can run that the
/// manifest does not name.
pub const EXTRACTION_RULES: [&str; 7] = [
    "failf-calls",
    "filter-definition",
    "filter-registration",
    "function-definitions",
    "infof-calls",
    "trace-calls",
    "type-definitions",
];

/// Metric keys a translation-unit entry records, sorted.
pub const UNIT_METRICS: [&str; 4] = [
    "failf-calls",
    "function-definitions",
    "infof-calls",
    "trace-calls",
];

/// Metric keys a header entry records.
pub const HEADER_METRICS: [&str; 1] = ["type-definitions"];

/// Kind of catalogued path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// A `.c` translation unit, the provenance denominator's unit.
    Unit,
    /// A `.h` header, a traceability row rather than a compiled unit.
    Header,
}

impl Kind {
    /// The recorded spelling of this kind.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Unit => "translation-unit",
            Self::Header => "header",
        }
    }

    /// The file extension a path of this kind carries.
    #[must_use]
    pub fn extension(self) -> &'static str {
        match self {
            Self::Unit => "c",
            Self::Header => "h",
        }
    }

    /// The metric keys an entry of this kind records.
    #[must_use]
    pub fn metrics(self) -> &'static [&'static str] {
        match self {
            Self::Unit => &UNIT_METRICS,
            Self::Header => &HEADER_METRICS,
        }
    }

    /// The kind a recorded spelling names.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "translation-unit" => Some(Self::Unit),
            "header" => Some(Self::Header),
            _ => None,
        }
    }
}

/// One catalogued vendored path and the record made about it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Owner {
    /// Repository-relative path inside the vendored tree.
    pub path: String,
    /// Whether the path is a translation unit or a header.
    pub kind: Kind,
    /// Planned member that owns what the path declares or defines.
    pub crate_path: String,
    /// Decision-log row that carries the reasoning.
    pub decision: String,
    /// One-based line of the build manifest that registers the basename.
    pub manifest_line: usize,
    /// Recorded line count.
    pub lines: usize,
    /// Recorded metrics, keyed by the extraction rule that produces them.
    pub metrics: BTreeMap<String, usize>,
    /// Connection-filter object the path defines, when it defines one.
    pub filter: Option<String>,
}

impl Owner {
    /// The sibling header of a translation unit.
    #[must_use]
    pub fn sibling_header(&self) -> Option<String> {
        match self.kind {
            Kind::Unit => self.path.strip_suffix(".c").map(|stem| format!("{stem}.h")),
            Kind::Header => None,
        }
    }
}

/// The provenance catalog, read from the root manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Catalog {
    /// Path of the decision log every entry must cite.
    pub decision_log: String,
    /// Directories the vendored enumeration walks.
    pub enumeration_roots: Vec<String>,
    /// Build manifest of each enumeration root.
    pub manifests: BTreeMap<String, String>,
    /// Paths the catalog covers under each enumeration root.
    pub catalogued: BTreeMap<String, usize>,
    /// Translation unit holding the trace registry.
    pub trace_registry: String,
    /// Project-authored records reconciled against the tree.
    pub records: Vec<String>,
    /// Kind name to file extension, as recorded.
    pub kinds: BTreeMap<String, String>,
    /// Extraction rule name to its recorded description.
    pub extraction: BTreeMap<String, String>,
    /// The catalogued paths, in recorded order.
    pub owners: Vec<Owner>,
}

fn string_at(table: &toml::map::Map<String, Value>, key: &str) -> AuditResult<String> {
    table
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| AuditError::new(format!("provenance.{key} missing")))
}

fn count_at(table: &toml::map::Map<String, Value>, key: &str, path: &str) -> AuditResult<usize> {
    let value = table
        .get(key)
        .and_then(Value::as_integer)
        .ok_or_else(|| AuditError::new(format!("provenance.owners {path}: {key} missing")))?;
    usize::try_from(value)
        .map_err(|_| AuditError::new(format!("provenance.owners {path}: {key} is not a count")))
}

fn string_map(
    table: &toml::map::Map<String, Value>,
    key: &str,
) -> AuditResult<BTreeMap<String, String>> {
    let inner = table
        .get(key)
        .and_then(Value::as_table)
        .ok_or_else(|| AuditError::new(format!("provenance.{key} is not a table")))?;
    inner
        .iter()
        .map(|(name, value)| {
            value
                .as_str()
                .map(|text| (name.clone(), text.to_owned()))
                .ok_or_else(|| AuditError::new(format!("provenance.{key}.{name} is not a string")))
        })
        .collect()
}

/// Reads a root-keyed table of paths.
fn path_map(workspace: &Workspace, key: &str) -> AuditResult<BTreeMap<String, String>> {
    let table = workspace.table(&["workspace", "metadata", "curl", "provenance", key])?;
    let mut found = BTreeMap::new();
    for (root, value) in table {
        let path = value
            .as_str()
            .ok_or_else(|| AuditError::new(format!("provenance.{key}.{root} is not a path")))?;
        found.insert(root.clone(), path.to_owned());
    }
    if found.is_empty() {
        return Err(AuditError::new(format!("provenance.{key} is empty")));
    }
    Ok(found)
}

/// Reads a root-keyed table of counts.
fn count_map(workspace: &Workspace, key: &str) -> AuditResult<BTreeMap<String, usize>> {
    let table = workspace.table(&["workspace", "metadata", "curl", "provenance", key])?;
    let mut found = BTreeMap::new();
    for (root, value) in table {
        let count = value
            .as_integer()
            .and_then(|found| usize::try_from(found).ok())
            .ok_or_else(|| AuditError::new(format!("provenance.{key}.{root} is not a count")))?;
        found.insert(root.clone(), count);
    }
    if found.is_empty() {
        return Err(AuditError::new(format!("provenance.{key} is empty")));
    }
    Ok(found)
}

impl Catalog {
    /// Reads the catalog out of the root manifest.
    pub fn from_workspace(workspace: &Workspace) -> AuditResult<Self> {
        let decision_log = workspace
            .curl_value(&["comment-discipline", "decision-log"])
            .and_then(Value::as_str)
            .ok_or_else(|| AuditError::new("comment-discipline.decision-log missing"))?
            .to_owned();
        let table = workspace.table(&["workspace", "metadata", "curl", "provenance"])?;
        let enumeration_roots = workspace.string_array(&[
            "workspace",
            "metadata",
            "curl",
            "provenance",
            "enumeration-roots",
        ])?;
        let records =
            workspace.string_array(&["workspace", "metadata", "curl", "provenance", "records"])?;
        if enumeration_roots.is_empty() || records.is_empty() {
            return Err(AuditError::new(
                "provenance declares no enumeration root or no record",
            ));
        }
        let entries = table
            .get("owners")
            .and_then(Value::as_array)
            .ok_or_else(|| AuditError::new("provenance.owners is not an array"))?;
        let mut owners = Vec::with_capacity(entries.len());
        for entry in entries {
            let entry = entry
                .as_table()
                .ok_or_else(|| AuditError::new("provenance.owners holds a non-table"))?;
            let path = string_at(entry, "path")?;
            let kind_name = string_at(entry, "kind")?;
            let kind = Kind::parse(&kind_name).ok_or_else(|| {
                AuditError::new(format!(
                    "provenance.owners {path}: kind {kind_name} is not a kind"
                ))
            })?;
            let mut metrics = BTreeMap::new();
            for key in kind.metrics() {
                metrics.insert((*key).to_owned(), count_at(entry, key, &path)?);
            }
            let foreign: Vec<&str> = EXTRACTION_RULES
                .iter()
                .filter(|rule| !kind.metrics().contains(*rule) && entry.contains_key(**rule))
                .copied()
                .collect();
            if !foreign.is_empty() {
                return Err(AuditError::new(format!(
                    "provenance.owners {path}: {} does not apply to a {}",
                    foreign.join(", "),
                    kind.name()
                )));
            }
            owners.push(Owner {
                lines: count_at(entry, "lines", &path)?,
                manifest_line: count_at(entry, "manifest-line", &path)?,
                crate_path: string_at(entry, "crate")?,
                decision: string_at(entry, "decision")?,
                filter: entry
                    .get("filter")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                path,
                kind,
                metrics,
            });
        }
        Ok(Self {
            decision_log,
            enumeration_roots,
            manifests: path_map(workspace, "manifests")?,
            catalogued: count_map(workspace, "catalogued")?,
            trace_registry: string_at(table, "trace-registry")?,
            records,
            kinds: string_map(table, "kinds")?,
            extraction: string_map(table, "extraction")?,
            owners,
        })
    }
}

/// Number of lines in a file's contents.
#[must_use]
pub fn line_count(contents: &str) -> usize {
    contents.lines().count()
}

/// Function definitions, counted as an opening brace at column zero whose
/// preceding line ends in a closing parenthesis.
///
/// This is the shape every definition in the vendored sources takes, including
/// the multi-line parameter lists that a one-line pattern misses.
#[must_use]
pub fn function_definitions(contents: &str) -> usize {
    let lines: Vec<&str> = contents.lines().collect();
    lines
        .iter()
        .enumerate()
        .filter(|(index, line)| {
            line.starts_with('{')
                && index
                    .checked_sub(1)
                    .and_then(|previous| lines.get(previous))
                    .is_some_and(|previous| previous.trim_end().ends_with(')'))
        })
        .count()
}

/// Structure definitions, counted as `struct <name> {` at column zero.
#[must_use]
pub fn type_definitions(contents: &str) -> usize {
    contents
        .lines()
        .filter(|line| {
            let Some(rest) = line.strip_prefix("struct ") else {
                return false;
            };
            let name: String = rest
                .chars()
                .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
                .collect();
            !name.is_empty() && &rest[name.len()..] == " {"
        })
        .count()
}

/// Trace emissions, counted as `CURL_TRC_<NAME>(` occurrences.
#[must_use]
pub fn trace_calls(contents: &str) -> usize {
    let mut found = 0;
    let mut rest = contents;
    while let Some(offset) = rest.find("CURL_TRC_") {
        let tail = &rest[offset + "CURL_TRC_".len()..];
        let name: String = tail
            .chars()
            .take_while(|character| {
                character.is_ascii_uppercase() || character.is_ascii_digit() || *character == '_'
            })
            .collect();
        if tail[name.len()..].starts_with('(') {
            found += 1;
        }
        rest = tail;
    }
    found
}

/// Calls of `name`, counted at an identifier boundary so that a longer name
/// ending in `name` is not counted.
#[must_use]
pub fn word_calls(contents: &str, name: &str) -> usize {
    let needle = format!("{name}(");
    let mut found = 0;
    let mut consumed = 0;
    while let Some(offset) = contents[consumed..].find(needle.as_str()) {
        let start = consumed + offset;
        let boundary = contents[..start]
            .chars()
            .next_back()
            .is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_');
        if boundary {
            found += 1;
        }
        consumed = start + needle.len();
    }
    found
}

/// The metric an extraction rule yields for a file's contents.
///
/// Returns `None` for a rule that is not a counting rule, which is how the
/// filter rules are skipped without a special case at the call site.
#[must_use]
pub fn measure(rule: &str, contents: &str) -> Option<usize> {
    match rule {
        "function-definitions" => Some(function_definitions(contents)),
        "type-definitions" => Some(type_definitions(contents)),
        "trace-calls" => Some(trace_calls(contents)),
        "infof-calls" => Some(word_calls(contents, "infof")),
        "failf-calls" => Some(word_calls(contents, "failf")),
        _ => None,
    }
}

/// Every `.c` and `.h` path under `roots`, sorted.
///
/// This is the provenance denominator of `DL-0043`: the filesystem itself,
/// never a manifest, so a file no build system lists still enters the
/// enumeration and a file listed but absent cannot.
#[must_use]
pub fn enumerate(files: &dyn Files, roots: &[String]) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut pending: Vec<String> = roots.to_vec();
    while let Some(directory) = pending.pop() {
        for name in files.list(&directory) {
            let child = format!("{directory}/{name}");
            if files.is_dir(&child) {
                pending.push(child);
            } else if child.ends_with(".c") || child.ends_with(".h") {
                found.insert(child);
            }
        }
    }
    found
}

/// Vendored `.c` and `.h` paths a project-authored record names.
///
/// A locator such as `original/lib/hostip.c:368` yields the path without its
/// line suffix, and a brace list such as `original/lib/vssh/{a.c,b.c}` yields
/// nothing, since it names no single path.
#[must_use]
pub fn referenced_paths(text: &str, roots: &[String]) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for root in roots {
        let prefix = format!("{root}/");
        let mut consumed = 0;
        while let Some(offset) = text[consumed..].find(prefix.as_str()) {
            let start = consumed + offset;
            let run: String = text[start..]
                .chars()
                .take_while(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '/' | '-')
                })
                .collect();
            consumed = start + run.len().max(prefix.len());
            let candidate = run.trim_end_matches(['.', ',', ';', '/']);
            if candidate.ends_with(".c") || candidate.ends_with(".h") {
                found.insert(candidate.to_owned());
            }
        }
    }
    found
}

/// Paths that a baseline-premise delta records as absent from the pinned tag.
pub fn recorded_absent_paths(workspace: &Workspace) -> AuditResult<BTreeSet<String>> {
    let deltas = workspace.table(&["workspace", "metadata", "curl", "baseline-premise-deltas"])?;
    let mut absent = BTreeSet::new();
    for delta in deltas.values() {
        let Some(paths) = delta
            .as_table()
            .and_then(|table| table.get("absent-paths"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        absent.extend(paths.iter().filter_map(Value::as_str).map(str::to_owned));
    }
    Ok(absent)
}

/// Verifies the recorded catalog against the checkout.
pub fn audit(workspace: &Workspace, files: &dyn Files) -> AuditResult<Report> {
    let catalog = Catalog::from_workspace(workspace)?;
    let planned: BTreeSet<String> = workspace
        .string_array(&["workspace", "metadata", "curl", "required-members"])?
        .into_iter()
        .collect();
    let absent = recorded_absent_paths(workspace)?;
    let log = files
        .read(&catalog.decision_log)
        .ok_or_else(|| AuditError::new(format!("{} is missing", catalog.decision_log)))?;
    let defined = decision_ids(&log);

    let mut report = Report::new("provenance-owners");
    report.assert(
        !catalog.owners.is_empty(),
        "owners-recorded",
        format!("{} path(s) catalogued", catalog.owners.len()),
    );

    let declared_kinds: Vec<(String, String)> = catalog
        .kinds
        .iter()
        .map(|(name, extension)| (name.clone(), extension.clone()))
        .collect();
    let expected_kinds: Vec<(String, String)> = [Kind::Header, Kind::Unit]
        .iter()
        .map(|kind| (kind.name().to_owned(), kind.extension().to_owned()))
        .collect();
    report.assert(
        declared_kinds == expected_kinds,
        "kinds-declared",
        format!("{} kind(s) declared", declared_kinds.len()),
    );

    let declared_rules: Vec<&str> = catalog.extraction.keys().map(String::as_str).collect();
    report.assert(
        declared_rules == EXTRACTION_RULES,
        "extraction-rules-declared",
        format!(
            "{} of {} implemented rule(s) declared",
            declared_rules.len(),
            EXTRACTION_RULES.len()
        ),
    );

    let enumerated = enumerate(files, &catalog.enumeration_roots);
    report.assert(
        !enumerated.is_empty(),
        "enumeration-observed",
        format!(
            "{} vendored path(s) under {}",
            enumerated.len(),
            catalog.enumeration_roots.join(", ")
        ),
    );

    let outside: Vec<&String> = catalog
        .owners
        .iter()
        .map(|owner| &owner.path)
        .filter(|path| !enumerated.contains(*path))
        .collect();
    report.assert(
        outside.is_empty() && !enumerated.is_empty(),
        "owners-enumerated",
        if outside.is_empty() {
            format!(
                "{} of {} enumerated path(s) owned",
                catalog.owners.len(),
                enumerated.len()
            )
        } else {
            format!(
                "outside the enumeration: {}",
                outside
                    .iter()
                    .map(|path| path.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        },
    );

    let paths: Vec<&String> = catalog.owners.iter().map(|owner| &owner.path).collect();
    let unique: BTreeSet<&String> = paths.iter().copied().collect();
    let mut sorted = paths.clone();
    sorted.sort();
    report.assert(
        paths == sorted && unique.len() == paths.len(),
        "owners-sorted-and-unique",
        format!("{} entry/entries in path order", paths.len()),
    );

    let claimed_absent: Vec<&String> = catalog
        .owners
        .iter()
        .map(|owner| &owner.path)
        .filter(|path| absent.contains(*path))
        .collect();
    report.assert(
        claimed_absent.is_empty(),
        "owners-not-recorded-absent",
        if claimed_absent.is_empty() {
            format!("{} recorded absent path(s) unclaimed", absent.len())
        } else {
            format!(
                "recorded absent yet owned: {}",
                claimed_absent
                    .iter()
                    .map(|path| path.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        },
    );

    // One build manifest per enumeration root. A single manifest belonging to the
    // first root leaves every path under the second uncatalogable, because no
    // line of it registers a basename from the other tree.
    let roots: BTreeSet<&str> = catalog
        .enumeration_roots
        .iter()
        .map(String::as_str)
        .collect();
    let declared: BTreeSet<&str> = catalog.manifests.keys().map(String::as_str).collect();
    report.assert(
        roots == declared,
        "manifests-cover-every-root",
        if roots == declared {
            format!("{} root(s), each with its own build manifest", roots.len())
        } else {
            format!(
                "roots {} declare manifests {}",
                catalog.enumeration_roots.join(", "),
                catalog
                    .manifests
                    .keys()
                    .cloned()
                    .collect::<Vec<String>>()
                    .join(", ")
            )
        },
    );

    let mut manifests: BTreeMap<&str, String> = BTreeMap::new();
    let mut unreadable_manifests = Vec::new();
    for (root, path) in &catalog.manifests {
        match files.read(path) {
            Some(body) => {
                manifests.insert(root.as_str(), body);
            }
            None => unreadable_manifests.push(path.clone()),
        }
    }
    report.assert(
        unreadable_manifests.is_empty(),
        "manifests-readable",
        if unreadable_manifests.is_empty() {
            catalog
                .manifests
                .values()
                .cloned()
                .collect::<Vec<String>>()
                .join(", ")
        } else {
            format!("unreadable: {}", unreadable_manifests.join(", "))
        },
    );

    // The catalog covers the subset whose provenance is established, not every
    // enumerated path, and the size of that subset per root is frozen so growth
    // is a deliberate edit rather than a silent drift.
    let covered: BTreeSet<&str> = catalog.catalogued.keys().map(String::as_str).collect();
    report.assert(
        roots == covered,
        "coverage-declared",
        if roots == covered {
            format!(
                "{} root(s), each declaring its catalogued count",
                roots.len()
            )
        } else {
            format!(
                "roots {} declare coverage {}",
                catalog.enumeration_roots.join(", "),
                catalog
                    .catalogued
                    .keys()
                    .cloned()
                    .collect::<Vec<String>>()
                    .join(", ")
            )
        },
    );

    let mut measured: BTreeMap<&str, usize> = BTreeMap::new();
    for owner in &catalog.owners {
        if let Some(root) = catalog
            .enumeration_roots
            .iter()
            .find(|root| owner.path.starts_with(&format!("{root}/")))
        {
            *measured.entry(root.as_str()).or_default() += 1;
        }
    }
    let drift: Vec<String> = catalog
        .catalogued
        .iter()
        .filter(|(root, count)| measured.get(root.as_str()).copied().unwrap_or(0) != **count)
        .map(|(root, count)| {
            format!(
                "{root}: {count} declared, {} catalogued",
                measured.get(root.as_str()).copied().unwrap_or(0)
            )
        })
        .collect();
    report.assert(
        drift.is_empty(),
        "coverage-denominator",
        if drift.is_empty() {
            format!(
                "{} of {} enumerated path(s) catalogued: {}",
                catalog.owners.len(),
                enumerated.len(),
                catalog
                    .catalogued
                    .iter()
                    .map(|(root, count)| format!("{root} {count}"))
                    .collect::<Vec<String>>()
                    .join(", ")
            )
        } else {
            format!("count drift: {}", drift.join(", "))
        },
    );
    let registry = files.read(&catalog.trace_registry);
    report.assert(
        registry.is_some(),
        "trace-registry-readable",
        catalog.trace_registry.clone(),
    );

    for owner in &catalog.owners {
        audit_owner(
            &mut report,
            owner,
            &Context {
                files,
                planned: &planned,
                defined: &defined,
                manifest: catalog
                    .enumeration_roots
                    .iter()
                    .find(|root| owner.path.starts_with(&format!("{root}/")))
                    .and_then(|root| manifests.get(root.as_str()))
                    .map(String::as_str),
                registry: registry.as_deref(),
                catalogued: &unique,
            },
        );
    }

    let mut references = BTreeSet::new();
    let mut unreadable = Vec::new();
    for record in &catalog.records {
        match files.read(record) {
            Some(contents) => {
                references.extend(referenced_paths(&contents, &catalog.enumeration_roots));
            }
            None => unreadable.push(record.clone()),
        }
    }
    report.assert(
        unreadable.is_empty(),
        "records-readable",
        if unreadable.is_empty() {
            format!("{} record(s) read", catalog.records.len())
        } else {
            format!("unreadable: {}", unreadable.join(", "))
        },
    );
    let unaccounted: Vec<&String> = references
        .iter()
        .filter(|path| !files.exists(path) && !absent.contains(*path))
        .collect();
    report.assert(
        unaccounted.is_empty() && !references.is_empty(),
        "records-reconciled",
        if unaccounted.is_empty() {
            format!(
                "{} referenced vendored path(s) accounted for",
                references.len()
            )
        } else {
            format!(
                "named yet neither present nor recorded absent: {}",
                unaccounted
                    .iter()
                    .map(|path| path.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        },
    );
    Ok(report)
}

/// What one entry is checked against.
struct Context<'a> {
    files: &'a dyn Files,
    planned: &'a BTreeSet<String>,
    defined: &'a BTreeSet<String>,
    manifest: Option<&'a str>,
    registry: Option<&'a str>,
    catalogued: &'a BTreeSet<&'a String>,
}

/// Verifies one catalogued path.
fn audit_owner(report: &mut Report, owner: &Owner, context: &Context<'_>) {
    let path = &owner.path;
    let contents = context.files.read(path);
    report.assert(
        contents.is_some(),
        format!("owner/{path}/exists"),
        format!("{} at the pinned tag", owner.kind.name()),
    );
    report.assert(
        path.ends_with(&format!(".{}", owner.kind.extension())),
        format!("owner/{path}/kind"),
        owner.kind.name().to_owned(),
    );
    report.assert(
        context.planned.contains(&owner.crate_path),
        format!("owner/{path}/crate"),
        format!("owned by {}", owner.crate_path),
    );
    report.assert(
        context.defined.contains(&owner.decision),
        format!("owner/{path}/decision"),
        owner.decision.clone(),
    );

    let basename = path.rsplit('/').next().unwrap_or(path.as_str());
    let registered = context
        .manifest
        .is_some_and(|manifest| line_contains(manifest, owner.manifest_line, basename));
    report.assert(
        registered,
        format!("owner/{path}/registered"),
        format!("build manifest line {}", owner.manifest_line),
    );

    match &contents {
        None => report.fail(format!("owner/{path}/metrics"), "unreadable".to_owned()),
        Some(text) => {
            let mut observed = vec![("lines".to_owned(), owner.lines, line_count(text))];
            for (rule, recorded) in &owner.metrics {
                if let Some(value) = measure(rule, text) {
                    observed.push((rule.clone(), *recorded, value));
                }
            }
            let drifted: Vec<String> = observed
                .iter()
                .filter(|(_, recorded, measured)| recorded != measured)
                .map(|(rule, recorded, measured)| {
                    format!("{rule} recorded {recorded}, measured {measured}")
                })
                .collect();
            report.assert(
                drifted.is_empty() && observed.len() == owner.metrics.len() + 1,
                format!("owner/{path}/metrics"),
                if drifted.is_empty() {
                    observed
                        .iter()
                        .map(|(rule, _, measured)| format!("{rule} {measured}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                } else {
                    drifted.join("; ")
                },
            );
        }
    }

    if let Some(filter) = &owner.filter {
        let defined_here = contents
            .as_deref()
            .is_some_and(|text| text.contains(&format!("{filter} = {{")));
        let registered_there = context
            .registry
            .is_some_and(|registry| registry.contains(&format!("&{filter},")));
        report.assert(
            defined_here && registered_there,
            format!("owner/{path}/filter"),
            if defined_here && registered_there {
                format!("{filter} defined here and in the trace registry")
            } else if defined_here {
                format!("{filter} defined here, absent from the trace registry")
            } else {
                format!("{filter} not defined here")
            },
        );
    }

    if let Some(sibling) = owner.sibling_header()
        && context.files.exists(&sibling)
    {
        report.assert(
            context.catalogued.contains(&sibling),
            format!("owner/{path}/sibling-header"),
            format!("{sibling} catalogued"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Catalog, EXTRACTION_RULES, Kind, audit, enumerate, function_definitions, line_count,
        measure, referenced_paths, trace_calls, type_definitions, word_calls,
    };
    use crate::fs::MapFiles;
    use crate::workspace::Workspace;

    const UNIT: &str = "#include \"cf-dns.h\"\n\
                        struct cf_dns_ctx {\n  int a;\n};\n\
                        static void one(struct Curl_easy *data,\n\
                        \x20                  int sockindex)\n\
                        {\n  CURL_TRC_DNS(data, \"x\");\n  infof(data, \"y\");\n}\n\
                        struct Curl_cftype Curl_cft_dns = {\n  \"DNS\",\n};\n\
                        CURLcode two(void)\n{\n  failf(data, \"z\");\n  Curl_infof(data);\n  return 0;\n}\n";

    const HEADER: &str = "#include \"curl_setup.h\"\n\
                          struct Curl_creds {\n  const char *user;\n};\n\
                          struct other {\n  int b;\n};\n\
                          CURLcode Curl_creds_create(void);\n";

    const MANIFEST: &str = "LIB_CFILES = \\\n  cf-dns.c           \\\n  x.c\nLIB_HFILES = \\\n  cf-dns.h           \\\n  creds.h            \\\n";

    const REGISTRY: &str = "static struct trc_cft_def trc_cfts[] = {\n  { &Curl_cft_dns,            TRC_CT_NETWORK },\n};\n";

    const ROOT_MANIFEST: &str = r#"
[workspace]
members = ["testing/audit"]

[workspace.metadata.curl]
required-members = ["refactor/curl-core", "refactor/curl-types"]

[workspace.metadata.curl.comment-discipline]
decision-log = "refactor/docs/DECISION-LOG.md"

[workspace.metadata.curl.baseline-premise-deltas.librtmp]
absent-paths = ["original/lib/curl_rtmp.h"]

[workspace.metadata.curl.provenance]
enumeration-roots = ["original/lib"]
trace-registry = "original/lib/curl_trc.c"
records = ["refactor/docs/DECISION-LOG.md"]
kinds = { translation-unit = "c", header = "h" }

[workspace.metadata.curl.provenance.manifests]
"original/lib" = "original/lib/Makefile.inc"

[workspace.metadata.curl.provenance.catalogued]
"original/lib" = 3

[workspace.metadata.curl.provenance.extraction]
failf-calls = "failf"
filter-definition = "Curl_cft_<name> = {"
filter-registration = "&Curl_cft_<name>,"
function-definitions = "open-brace-at-column-zero-after-close-paren"
infof-calls = "infof"
trace-calls = "CURL_TRC_"
type-definitions = "struct-name-open-brace-at-column-zero"

[[workspace.metadata.curl.provenance.owners]]
path = "original/lib/cf-dns.c"
kind = "translation-unit"
crate = "refactor/curl-core"
decision = "DL-0139"
manifest-line = 2
lines = 19
function-definitions = 2
trace-calls = 1
infof-calls = 1
failf-calls = 1
filter = "Curl_cft_dns"

[[workspace.metadata.curl.provenance.owners]]
path = "original/lib/cf-dns.h"
kind = "header"
crate = "refactor/curl-core"
decision = "DL-0139"
manifest-line = 5
lines = 1
type-definitions = 0

[[workspace.metadata.curl.provenance.owners]]
path = "original/lib/creds.h"
kind = "header"
crate = "refactor/curl-types"
decision = "DL-0142"
manifest-line = 6
lines = 8
type-definitions = 2
"#;

    fn workspace(manifest: &str, key: &str) -> Workspace {
        let directory = std::env::temp_dir().join(format!("curl-audit-tests/provenance-{key}"));
        std::fs::create_dir_all(&directory).expect("fixture directory");
        std::fs::write(directory.join("Cargo.toml"), manifest).expect("fixture manifest");
        Workspace::load(&directory).expect("fixture workspace")
    }

    fn clean_files() -> MapFiles {
        MapFiles::new()
            .with(
                "refactor/docs/DECISION-LOG.md",
                "| DL-0139 | row |\n| DL-0142 | row over original/lib/cf-dns.c |\n",
            )
            .with("original/lib/cf-dns.c", UNIT)
            .with("original/lib/cf-dns.h", "extern struct Curl_cftype x;\n")
            .with("original/lib/creds.h", HEADER)
            .with("original/lib/Makefile.inc", MANIFEST)
            .with("original/lib/curl_trc.c", REGISTRY)
    }

    #[test]
    fn extraction_rules_measure_the_vendored_shapes() {
        assert_eq!(function_definitions(UNIT), 2);
        assert_eq!(trace_calls(UNIT), 1);
        assert_eq!(word_calls(UNIT, "infof"), 1);
        assert_eq!(word_calls(UNIT, "failf"), 1);
        assert_eq!(type_definitions(HEADER), 2);
        assert_eq!(line_count(HEADER), 8);
        assert_eq!(measure("trace-calls", UNIT), Some(1));
        assert_eq!(measure("filter-definition", UNIT), None);
    }

    #[test]
    fn counting_rules_reject_near_misses() {
        assert_eq!(function_definitions("void f(void)\n{\n}\n"), 1);
        assert_eq!(function_definitions("void f(void);\n{\n}\n"), 0);
        assert_eq!(function_definitions("void f(void)\n  {\n}\n"), 0);
        assert_eq!(type_definitions("struct a b;\nstruct  c {\n"), 0);
        assert_eq!(type_definitions("  struct a {\n"), 0);
        assert_eq!(trace_calls("CURL_TRC_M (x)\ncurl_trc_m(x)\n"), 0);
        assert_eq!(trace_calls("CURL_TRC_M(x) CURL_TRC_CF(y)\n"), 2);
        assert_eq!(word_calls("Curl_infof(x) infof(y) _infof(z)\n", "infof"), 1);
        assert_eq!(line_count(""), 0);
    }

    #[test]
    fn kinds_carry_their_own_extension_and_metrics() {
        assert_eq!(Kind::parse("translation-unit"), Some(Kind::Unit));
        assert_eq!(Kind::parse("header"), Some(Kind::Header));
        assert_eq!(Kind::parse("module"), None);
        assert_eq!(Kind::Unit.extension(), "c");
        assert_eq!(Kind::Header.metrics(), &["type-definitions"]);
        assert_eq!(Kind::Unit.metrics().len(), 4);
        assert_eq!(EXTRACTION_RULES.len(), 7);
    }

    #[test]
    fn enumeration_walks_the_tree_and_references_are_extracted() {
        let files = MapFiles::new()
            .with("original/lib/a.c", "")
            .with("original/lib/vtls/b.h", "")
            .with("original/lib/Makefile.inc", "")
            .with("original/src/c.c", "");
        let found = enumerate(&files, &["original/lib".to_owned()]);
        assert_eq!(
            found.into_iter().collect::<Vec<_>>(),
            vec![
                "original/lib/a.c".to_owned(),
                "original/lib/vtls/b.h".to_owned()
            ]
        );

        let text = "at `original/lib/hostip.c:368` and original/lib/file.c. plus \
                    `original/lib/vssh/{libssh.c,vssh.c}` and original/lib/Makefile.inc:154 \
                    and original/lib/vtls/vtls_config.h:32";
        let referenced = referenced_paths(text, &["original/lib".to_owned()]);
        assert_eq!(
            referenced.into_iter().collect::<Vec<_>>(),
            vec![
                "original/lib/file.c".to_owned(),
                "original/lib/hostip.c".to_owned(),
                "original/lib/vtls/vtls_config.h".to_owned(),
            ]
        );
    }

    #[test]
    fn a_fully_recorded_catalog_passes() {
        let workspace = workspace(ROOT_MANIFEST, "clean");
        let report = audit(&workspace, &clean_files()).expect("audit runs");
        assert!(report.passed(), "{}", report.render());
        let rendered = report.render();
        assert!(rendered.contains("PASS owners-recorded: 3 path(s) catalogued"));
        assert!(rendered.contains("PASS owners-enumerated: 3 of 4 enumerated path(s) owned"));
        assert!(rendered.contains("PASS owner/original/lib/cf-dns.c/filter"));
        assert!(rendered.contains("PASS owner/original/lib/cf-dns.c/sibling-header"));
        assert!(rendered.contains("PASS records-reconciled"));
    }

    #[test]
    fn a_drifted_metric_fails() {
        let workspace = workspace(
            &ROOT_MANIFEST.replace("trace-calls = 1", "trace-calls = 4"),
            "drift",
        );
        let report = audit(&workspace, &clean_files()).expect("audit runs");
        let rendered = report.render();
        assert!(rendered.contains("FAIL owner/original/lib/cf-dns.c/metrics"));
        assert!(rendered.contains("trace-calls recorded 4, measured 1"));
    }

    #[test]
    fn an_absent_or_unregistered_path_fails() {
        let workspace = workspace(ROOT_MANIFEST, "absent");
        let files = MapFiles::new()
            .with(
                "refactor/docs/DECISION-LOG.md",
                "| DL-0139 | row |\n| DL-0142 | row |\n",
            )
            .with("original/lib/cf-dns.h", "extern struct Curl_cftype x;\n")
            .with("original/lib/creds.h", HEADER)
            .with("original/lib/Makefile.inc", "LIB_CFILES = \\\n  other.c\n")
            .with("original/lib/curl_trc.c", REGISTRY);
        let report = audit(&workspace, &files).expect("audit runs");
        let rendered = report.render();
        assert!(rendered.contains("FAIL owner/original/lib/cf-dns.c/exists"));
        assert!(rendered.contains("FAIL owner/original/lib/cf-dns.c/metrics: unreadable"));
        assert!(rendered.contains("FAIL owner/original/lib/cf-dns.c/registered"));
        assert!(rendered.contains("FAIL owners-enumerated"));
        assert!(rendered.contains("FAIL owner/original/lib/cf-dns.c/filter"));
    }

    #[test]
    fn a_path_recorded_absent_may_not_be_owned() {
        let manifest = ROOT_MANIFEST.replace(
            "path = \"original/lib/creds.h\"",
            "path = \"original/lib/curl_rtmp.h\"",
        );
        let workspace = workspace(&manifest, "phantom");
        let files = clean_files().with("original/lib/curl_rtmp.h", HEADER);
        let report = audit(&workspace, &files).expect("audit runs");
        let rendered = report.render();
        assert!(rendered.contains("FAIL owners-not-recorded-absent"));
        assert!(rendered.contains("original/lib/curl_rtmp.h"));
    }

    #[test]
    fn an_uncatalogued_sibling_header_fails() {
        let manifest = ROOT_MANIFEST
            .split(
                "[[workspace.metadata.curl.provenance.owners]]\npath = \"original/lib/cf-dns.h\"",
            )
            .next()
            .expect("prefix")
            .to_owned();
        let workspace = workspace(&manifest, "sibling");
        let report = audit(&workspace, &clean_files()).expect("audit runs");
        assert!(
            report
                .render()
                .contains("FAIL owner/original/lib/cf-dns.c/sibling-header")
        );
    }

    #[test]
    fn an_unplanned_crate_or_dangling_decision_fails() {
        let manifest = ROOT_MANIFEST
            .replace("\"refactor/curl-types\"]", "\"refactor/curl-url\"]")
            .replace("decision = \"DL-0142\"", "decision = \"DL-9999\"");
        let workspace = workspace(&manifest, "unplanned");
        let report = audit(&workspace, &clean_files()).expect("audit runs");
        let rendered = report.render();
        assert!(rendered.contains("FAIL owner/original/lib/creds.h/crate"));
        assert!(rendered.contains("FAIL owner/original/lib/creds.h/decision"));
    }

    #[test]
    fn an_unsorted_or_duplicated_catalog_fails() {
        let manifest = ROOT_MANIFEST.replace(
            "path = \"original/lib/cf-dns.c\"",
            "path = \"original/lib/creds.h\"",
        );
        let workspace = workspace(&manifest, "unsorted");
        let report = audit(&workspace, &clean_files()).expect("audit runs");
        assert!(report.render().contains("FAIL owners-sorted-and-unique"));
    }

    #[test]
    fn a_stale_reference_in_a_record_fails() {
        let workspace = workspace(ROOT_MANIFEST, "stale-reference");
        let files = clean_files().with(
            "refactor/docs/DECISION-LOG.md",
            "| DL-0139 | row |\n| DL-0142 | names original/lib/gone.c |\n",
        );
        let report = audit(&workspace, &files).expect("audit runs");
        let rendered = report.render();
        assert!(rendered.contains("FAIL records-reconciled"));
        assert!(rendered.contains("original/lib/gone.c"));
    }

    #[test]
    fn a_broken_contract_errors_rather_than_passing() {
        let unknown_kind = workspace(
            &ROOT_MANIFEST.replace(
                "kind = \"header\"\ncrate = \"refactor/curl-types\"",
                "kind = \"module\"\ncrate = \"refactor/curl-types\"",
            ),
            "kind",
        );
        assert!(Catalog::from_workspace(&unknown_kind).is_err());

        let foreign = workspace(
            &ROOT_MANIFEST.replace(
                "type-definitions = 2\n",
                "type-definitions = 2\ntrace-calls = 9\n",
            ),
            "foreign",
        );
        assert!(Catalog::from_workspace(&foreign).is_err());

        let empty = workspace(
            &ROOT_MANIFEST.replace(
                "enumeration-roots = [\"original/lib\"]",
                "enumeration-roots = []",
            ),
            "empty",
        );
        assert!(Catalog::from_workspace(&empty).is_err());
    }

    #[test]
    fn every_enumeration_root_needs_its_own_manifest() {
        let manifest = ROOT_MANIFEST.replace(
            "enumeration-roots = [\"original/lib\"]",
            "enumeration-roots = [\"original/lib\", \"original/src\"]",
        );
        let workspace = workspace(&manifest, "root without a manifest");
        let report = audit(&workspace, &clean_files()).expect("audits");
        let rendered = report.render();
        assert!(
            rendered.contains("FAIL manifests-cover-every-root"),
            "{rendered}"
        );
        assert!(rendered.contains("FAIL coverage-declared"), "{rendered}");
    }

    #[test]
    fn an_unreadable_manifest_fails() {
        let manifest = ROOT_MANIFEST.replace(
            "\"original/lib\" = \"original/lib/Makefile.inc\"",
            "\"original/lib\" = \"original/lib/Makefile.absent\"",
        );
        let workspace = workspace(&manifest, "unreadable manifest");
        let report = audit(&workspace, &clean_files()).expect("audits");
        assert!(report.render().contains("FAIL manifests-readable"));
    }

    #[test]
    fn the_catalogued_count_is_frozen_per_root() {
        let manifest = ROOT_MANIFEST.replace("\"original/lib\" = 3", "\"original/lib\" = 9");
        let workspace = workspace(&manifest, "count drift");
        let report = audit(&workspace, &clean_files()).expect("audits");
        let rendered = report.render();
        assert!(rendered.contains("FAIL coverage-denominator"), "{rendered}");
        assert!(rendered.contains("9 declared"), "{rendered}");
    }

    #[test]
    fn a_declared_coverage_root_outside_the_enumeration_fails() {
        let manifest = ROOT_MANIFEST.replace(
            "[workspace.metadata.curl.provenance.catalogued]\n\"original/lib\" = 3",
            "[workspace.metadata.curl.provenance.catalogued]\n\"original/lib\" = 3\n\"original/docs\" = 0",
        );
        let workspace = workspace(&manifest, "stray coverage root");
        let report = audit(&workspace, &clean_files()).expect("audits");
        assert!(report.render().contains("FAIL coverage-declared"));
    }

    #[test]
    fn a_missing_manifest_table_is_a_load_error() {
        let manifest = ROOT_MANIFEST.replace(
            "[workspace.metadata.curl.provenance.manifests]\n\"original/lib\" = \"original/lib/Makefile.inc\"\n",
            "",
        );
        let workspace = workspace(&manifest, "no manifest table");
        assert!(audit(&workspace, &clean_files()).is_err());
    }

    #[test]
    fn a_complete_catalogue_passes_the_new_gates() {
        let workspace = workspace(ROOT_MANIFEST, "complete provenance");
        let report = audit(&workspace, &clean_files()).expect("audits");
        let rendered = report.render();
        assert!(
            rendered.contains("PASS manifests-cover-every-root"),
            "{rendered}"
        );
        assert!(rendered.contains("PASS manifests-readable"), "{rendered}");
        assert!(rendered.contains("PASS coverage-declared"), "{rendered}");
        assert!(rendered.contains("PASS coverage-denominator"), "{rendered}");
    }
}
