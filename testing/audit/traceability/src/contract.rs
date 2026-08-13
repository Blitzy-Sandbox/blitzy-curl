// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: the blitzy-curl project contributors

//! The declared inputs: the root-manifest index, the ownership map and the
//! planned crate set every owner must belong to.

use std::collections::{BTreeMap, BTreeSet};

use curl_audit::fs::Files;
use curl_audit::workspace::{AuditError, AuditResult, Workspace};
use toml::Value;

/// Where the generator finds its data and where it writes its documents.
///
/// The root manifest carries only this index; the bulk lives beside the
/// generator, which is what keeps the configuration contract a contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Index {
    ownership: String,
    hazards: String,
    observability: String,
    decision_log: String,
    tooling_guard: String,
    outputs: BTreeMap<String, String>,
}

impl Index {
    /// Reads `[workspace.metadata.curl.traceability]`.
    pub fn from_workspace(workspace: &Workspace) -> AuditResult<Self> {
        let path = ["workspace", "metadata", "curl", "traceability"];
        let table = workspace.table(&path)?;
        let text = |key: &str| -> AuditResult<String> {
            table
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| AuditError::new(format!("traceability.{key} missing")))
        };
        let outputs = table
            .get("outputs")
            .and_then(Value::as_table)
            .ok_or_else(|| AuditError::new("traceability.outputs missing"))?;
        let mut rendered = BTreeMap::new();
        for (name, value) in outputs {
            let target = value.as_str().ok_or_else(|| {
                AuditError::new(format!("traceability.outputs.{name} is not a path"))
            })?;
            rendered.insert(name.clone(), target.to_owned());
        }
        if rendered.is_empty() {
            return Err(AuditError::new("traceability.outputs declares no document"));
        }
        Ok(Self {
            ownership: text("ownership-data")?,
            hazards: text("hazard-data")?,
            observability: text("observability-data")?,
            decision_log: text("decision-log")?,
            tooling_guard: text("tooling-guard")?,
            outputs: rendered,
        })
    }

    /// Path of the ownership map.
    #[must_use]
    pub fn ownership_data(&self) -> &str {
        &self.ownership
    }

    /// Path of the hazard register.
    #[must_use]
    pub fn hazard_data(&self) -> &str {
        &self.hazards
    }

    /// Path of the observability contract.
    #[must_use]
    pub fn observability_data(&self) -> &str {
        &self.observability
    }

    /// Path of the decision log every pointer resolves in.
    #[must_use]
    pub fn decision_log(&self) -> &str {
        &self.decision_log
    }

    /// Path of the wrapper that guards the oracle's maintenance tooling.
    ///
    /// The hazard register names this path as the verification of every oracle
    /// script the wrapper refuses, and `DL-0306` records the arrangement.
    #[must_use]
    pub fn tooling_guard(&self) -> &str {
        &self.tooling_guard
    }

    /// Declared outputs, keyed by document name.
    #[must_use]
    pub fn outputs(&self) -> &BTreeMap<String, String> {
        &self.outputs
    }

    /// Output path of one document name.
    #[must_use]
    pub fn output(&self, name: &str) -> Option<&str> {
        self.outputs.get(name).map(String::as_str)
    }
}

/// A directory rule: the owner of every path under one prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rule {
    /// Repository-relative prefix, ending in a separator.
    pub prefix: String,
    /// Crate that owns everything under it.
    pub owner: String,
    /// Decision this assignment rests on.
    pub decision: String,
}

/// A path that carries no Rust module, with the reason it does not.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Exclusion {
    /// Repository-relative path inside the oracle.
    pub path: String,
    /// Why no module exists: a platform or a build-configuration disposition.
    pub disposition: String,
    /// Written justification.
    pub reason: String,
    /// Decision this exclusion rests on.
    pub decision: String,
}

/// An internal declaration with no definition and no caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Orphan {
    /// Header that declares it.
    pub path: String,
    /// One-based line of the declaration.
    pub line: usize,
    /// Declared name.
    pub symbol: String,
    /// The file-local definition that exists instead, if any.
    pub local_definition: String,
    /// Decision that classifies it.
    pub decision: String,
}

/// A definition upstream's own single-use whitelist names.
///
/// The inverse of an orphan declaration: the symbol is defined, and whether
/// anything can reach it is a measured property rather than a declared one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrphanDefinition {
    /// Whitelisted name.
    pub symbol: String,
    /// How the oracle reaches it, as declared.
    pub reach: String,
    /// What the port does about it.
    pub disposition: String,
    /// Decision that classifies it.
    pub decision: String,
}

/// A command-line option no dispatch arm names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SilentOption {
    /// Identifier the alias table maps the option to.
    pub identifier: String,
    /// What the tool does with the argument instead.
    pub outcome: String,
    /// What the port does about it.
    pub disposition: String,
    /// Decision that classifies it.
    pub decision: String,
}

/// Dispositions a generator, harness or configuration asset may carry.
///
/// `DL-0273` records what each one means and why the vocabulary is closed.
pub const HARNESS_DISPOSITIONS: [&str; 4] = [
    "build-input",
    "no-counterpart",
    "replaced",
    "source-reference",
];

/// One generator, harness or configuration asset and what answers for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Harness {
    /// Repository-relative path inside the oracle.
    pub path: String,
    /// What the asset is, in the oracle's own terms.
    pub role: String,
    /// How the project accounts for it, from [`HARNESS_DISPOSITIONS`].
    pub disposition: String,
    /// Target that answers for it, or `none` when nothing does.
    pub target: String,
    /// Decision the disposition rests on.
    pub decision: String,
}

/// A symbol-register family and the crate that must define it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Family {
    /// Name prefix; the longest match wins.
    pub prefix: String,
    /// Crate that owns the family.
    pub owner: String,
    /// What kind of construct the family holds.
    pub kind: String,
}

/// One project-authored file and what it derives from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reverse {
    /// Repository-relative path outside the oracle.
    pub path: String,
    /// Oracle paths this file derives from, empty when it is project-owned.
    pub derives_from: Vec<String>,
    /// Whether the file has no oracle counterpart.
    pub project_owned: bool,
    /// Decision a project-owned file rests on.
    pub decision: String,
}

/// The declared ownership map.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Ownership {
    /// Directory rules, longest prefix first.
    pub rules: Vec<Rule>,
    /// Per-path overrides applied before any rule.
    pub overrides: BTreeMap<String, String>,
    /// Owner of each translation unit basename under `original/lib`.
    pub units: BTreeMap<String, String>,
    /// Owner of each header basename under `original/lib` with no same-stem source.
    pub headers: BTreeMap<String, String>,
    /// Paths carrying no Rust module.
    pub exclusions: Vec<Exclusion>,
    /// Declarations with no definition and no caller.
    pub orphans: Vec<Orphan>,
    /// Definitions upstream's own single-use whitelist names.
    pub orphan_definitions: Vec<OrphanDefinition>,
    /// Options no dispatch arm names.
    pub silent_options: Vec<SilentOption>,
    /// Owner of each internal-surface case that includes no internal header.
    pub cases: BTreeMap<String, String>,
    /// Generator, harness and configuration assets.
    pub harness: Vec<Harness>,
    /// Symbol-register families.
    pub families: Vec<Family>,
    /// Target of each family the generator resolves without a per-row entry.
    pub targets: BTreeMap<String, String>,
    /// Decision behind each such target.
    pub decisions: BTreeMap<String, String>,
    /// Reverse-direction entries.
    pub reverse: Vec<Reverse>,
}

fn string_map(value: Option<&Value>, name: &str) -> AuditResult<BTreeMap<String, String>> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    let table = value
        .as_table()
        .ok_or_else(|| AuditError::new(format!("{name} is not a table")))?;
    let mut map = BTreeMap::new();
    for (key, entry) in table {
        let text = entry
            .as_str()
            .ok_or_else(|| AuditError::new(format!("{name}.{key} is not a string")))?;
        map.insert(key.clone(), text.to_owned());
    }
    Ok(map)
}

fn field<'a>(entry: &'a Value, key: &str, owner: &str) -> AuditResult<&'a str> {
    entry
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| AuditError::new(format!("{owner}: {key} missing")))
}

fn array<'a>(value: Option<&'a Value>, name: &str) -> AuditResult<&'a [Value]> {
    match value {
        None => Ok(&[]),
        Some(value) => value
            .as_array()
            .map(Vec::as_slice)
            .ok_or_else(|| AuditError::new(format!("{name} is not an array"))),
    }
}

impl Ownership {
    /// Reads the ownership map from `path`.
    pub fn load(files: &dyn Files, path: &str) -> AuditResult<Self> {
        let text = files
            .read(path)
            .ok_or_else(|| AuditError::new(format!("{path} is missing")))?;
        let value: Value =
            toml::from_str(&text).map_err(|error| AuditError::new(format!("{path}: {error}")))?;

        let mut rules = Vec::new();
        for entry in array(value.get("rule"), "rule")? {
            rules.push(Rule {
                prefix: field(entry, "prefix", "rule")?.to_owned(),
                owner: field(entry, "owner", "rule")?.to_owned(),
                decision: field(entry, "decision", "rule")?.to_owned(),
            });
        }
        rules.sort_by_key(|rule| std::cmp::Reverse(rule.prefix.len()));

        let mut overrides = BTreeMap::new();
        for entry in array(value.get("override"), "override")? {
            overrides.insert(
                field(entry, "path", "override")?.to_owned(),
                field(entry, "owner", "override")?.to_owned(),
            );
        }

        let mut exclusions = Vec::new();
        for entry in array(value.get("exclusion"), "exclusion")? {
            exclusions.push(Exclusion {
                path: field(entry, "path", "exclusion")?.to_owned(),
                disposition: field(entry, "disposition", "exclusion")?.to_owned(),
                reason: field(entry, "reason", "exclusion")?.to_owned(),
                decision: field(entry, "decision", "exclusion")?.to_owned(),
            });
        }

        let mut orphan_definitions = Vec::new();
        for entry in array(value.get("orphan-definition"), "orphan-definition")? {
            orphan_definitions.push(OrphanDefinition {
                symbol: field(entry, "symbol", "orphan-definition")?.to_owned(),
                reach: field(entry, "reach", "orphan-definition")?.to_owned(),
                disposition: field(entry, "disposition", "orphan-definition")?.to_owned(),
                decision: field(entry, "decision", "orphan-definition")?.to_owned(),
            });
        }

        let mut silent_options = Vec::new();
        for entry in array(value.get("silent-option"), "silent-option")? {
            silent_options.push(SilentOption {
                identifier: field(entry, "identifier", "silent-option")?.to_owned(),
                outcome: field(entry, "outcome", "silent-option")?.to_owned(),
                disposition: field(entry, "disposition", "silent-option")?.to_owned(),
                decision: field(entry, "decision", "silent-option")?.to_owned(),
            });
        }

        let mut orphans = Vec::new();
        for entry in array(value.get("orphan"), "orphan")? {
            let line = entry
                .get("line")
                .and_then(Value::as_integer)
                .and_then(|line| usize::try_from(line).ok())
                .ok_or_else(|| AuditError::new("orphan: line missing"))?;
            orphans.push(Orphan {
                path: field(entry, "path", "orphan")?.to_owned(),
                line,
                symbol: field(entry, "symbol", "orphan")?.to_owned(),
                local_definition: field(entry, "local-definition", "orphan")?.to_owned(),
                decision: field(entry, "decision", "orphan")?.to_owned(),
            });
        }

        let mut harness = Vec::new();
        for entry in array(value.get("harness"), "harness")? {
            let at = field(entry, "path", "harness")?;
            harness.push(Harness {
                path: at.to_owned(),
                role: field(entry, "role", at)?.to_owned(),
                disposition: field(entry, "disposition", at)?.to_owned(),
                target: field(entry, "target", at)?.to_owned(),
                decision: field(entry, "decision", at)?.to_owned(),
            });
        }

        let mut families = Vec::new();
        for entry in array(value.get("family"), "family")? {
            families.push(Family {
                prefix: field(entry, "prefix", "family")?.to_owned(),
                owner: field(entry, "owner", "family")?.to_owned(),
                kind: field(entry, "kind", "family")?.to_owned(),
            });
        }
        families.sort_by_key(|family| std::cmp::Reverse(family.prefix.len()));

        let mut reverse = Vec::new();
        for entry in array(value.get("reverse"), "reverse")? {
            let derives_from = match entry.get("derives-from") {
                None => Vec::new(),
                Some(list) => list
                    .as_array()
                    .ok_or_else(|| AuditError::new("reverse: derives-from is not an array"))?
                    .iter()
                    .map(|item| {
                        item.as_str().map(str::to_owned).ok_or_else(|| {
                            AuditError::new("reverse: derives-from entry is not a path")
                        })
                    })
                    .collect::<AuditResult<Vec<String>>>()?,
            };
            reverse.push(Reverse {
                path: field(entry, "path", "reverse")?.to_owned(),
                derives_from,
                project_owned: entry
                    .get("project-owned")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                decision: entry
                    .get("decision")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            });
        }

        let owned = Self {
            rules,
            overrides,
            units: string_map(value.get("unit"), "unit")?,
            headers: string_map(value.get("header"), "header")?,
            exclusions,
            orphans,
            orphan_definitions,
            silent_options,
            cases: string_map(value.get("case"), "case")?,
            harness,
            families,
            targets: string_map(value.get("target"), "target")?,
            decisions: string_map(value.get("decision"), "decision")?,
            reverse,
        };
        if owned.units.is_empty()
            || owned.families.is_empty()
            || owned.reverse.is_empty()
            || owned.harness.is_empty()
        {
            return Err(AuditError::new(format!(
                "{path}: declares no unit, family, harness or reverse entry"
            )));
        }
        Ok(owned)
    }

    /// Whether `path` is declared as carrying no Rust module.
    #[must_use]
    pub fn excluded(&self, path: &str) -> Option<&Exclusion> {
        self.exclusions
            .iter()
            .find(|exclusion| exclusion.path == path)
    }

    /// Whether `path` carries an explicit owner rather than a rule-derived one.
    ///
    /// An explicit entry beside an exclusion is a contradiction; a directory
    /// rule beside one is not, because the exclusion is the narrower statement.
    #[must_use]
    pub fn explicitly_owned(&self, path: &str) -> bool {
        if self.overrides.contains_key(path) {
            return true;
        }
        let name = path.rsplit('/').next().unwrap_or(path);
        path.strip_prefix("original/lib/")
            .is_some_and(|rest| !rest.contains('/'))
            && (self.units.contains_key(name) || self.headers.contains_key(name))
    }

    /// Owner of one oracle path, by override, then explicit entry, then
    /// same-stem inheritance, then directory rule.
    #[must_use]
    pub fn owner_of(&self, path: &str, siblings: &BTreeSet<String>) -> Option<String> {
        if let Some(owner) = self.overrides.get(path) {
            return Some(owner.clone());
        }
        let name = path.rsplit('/').next().unwrap_or(path);
        let top_level_lib = path
            .strip_prefix("original/lib/")
            .is_some_and(|rest| !rest.contains('/'));
        if top_level_lib {
            if let Some(owner) = self.units.get(name).or_else(|| self.headers.get(name)) {
                return Some(owner.clone());
            }
            if let Some(stem) = name.strip_suffix(".h") {
                let source = format!("original/lib/{stem}.c");
                if siblings.contains(&source) {
                    return self.owner_of(&source, siblings);
                }
            }
        }
        self.rules
            .iter()
            .find(|rule| path.starts_with(&rule.prefix))
            .map(|rule| rule.owner.clone())
    }

    /// Family of one register entry, longest declared prefix first.
    #[must_use]
    pub fn family_of(&self, symbol: &str) -> Option<&Family> {
        self.families
            .iter()
            .find(|family| symbol.starts_with(&family.prefix))
    }

    /// Declared target of a family the generator resolves wholesale.
    #[must_use]
    pub fn target_of(&self, family: &str) -> Option<(&str, &str)> {
        let target = self.targets.get(family)?;
        let decision = self.decisions.get(family)?;
        Some((target.as_str(), decision.as_str()))
    }
}

/// Crate names of every planned workspace member.
pub fn planned_crates(workspace: &Workspace) -> AuditResult<BTreeSet<String>> {
    let members = workspace.string_array(&["workspace", "metadata", "curl", "required-members"])?;
    let planned: BTreeSet<String> = members
        .iter()
        .filter_map(|member| member.rsplit('/').next())
        .map(str::to_owned)
        .collect();
    if planned.is_empty() {
        return Err(AuditError::new("required-members is empty"));
    }
    Ok(planned)
}

/// Whether each planned crate has a manifest in the tree yet.
///
/// This is what the rendered `Status` column reports, so a document can never
/// claim an implementation the checkout does not contain.
pub fn crates_present(
    workspace: &Workspace,
    files: &dyn Files,
) -> AuditResult<BTreeMap<String, bool>> {
    let members = workspace.string_array(&["workspace", "metadata", "curl", "required-members"])?;
    let mut present = BTreeMap::new();
    for member in members {
        let Some(name) = member.rsplit('/').next() else {
            continue;
        };
        present.insert(
            name.to_owned(),
            files.exists(&format!("{member}/Cargo.toml")),
        );
    }
    if present.is_empty() {
        return Err(AuditError::new("required-members is empty"));
    }
    Ok(present)
}

/// Identifiers the decision log defines.
pub fn decision_ids(files: &dyn Files, path: &str) -> AuditResult<BTreeSet<String>> {
    let log = files
        .read(path)
        .ok_or_else(|| AuditError::new(format!("{path} is missing")))?;
    let ids = curl_audit::comments::decision_ids(&log);
    if ids.is_empty() {
        return Err(AuditError::new(format!("{path} defines no decision row")));
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use curl_audit::fs::MapFiles;

    use super::{Ownership, planned_crates};

    const OWNERSHIP: &str = r#"
schema = 1
[[rule]]
prefix = "original/lib/curlx/"
owner = "curl-types"
decision = "DL-0003"
[[override]]
path = "original/lib/curlx/winapi.c"
owner = "curl-abi"
[unit]
"http.c" = "curl-http1"
[header]
"urldata.h" = "curl-core"
[[exclusion]]
path = "original/lib/amigaos.c"
disposition = "platform-outside-matrix"
reason = "outside the matrix"
decision = "DL-0043"
[[orphan]]
path = "original/lib/request.h"
line = 249
symbol = "Curl_req_set_upload_done"
local-definition = "original/lib/request.c:268"
decision = "DL-0112"
[case]
"unit1330.c" = "curl-alloc"
[[family]]
prefix = "CURL_"
owner = "curl-abi"
kind = "constant"
[[family]]
prefix = "CURLOPT_"
owner = "curl-core"
kind = "option"
[target]
cli-option = "curl-cli"
[decision]
cli-option = "DL-0026"
[[harness]]
path = "original/src/mkhelp.pl"
role = "help-text generator"
disposition = "replaced"
target = "curl-cli"
decision = "DL-0273"
[[reverse]]
path = "Cargo.toml"
derives-from = ["original/configure.ac"]
"#;

    fn ownership() -> Ownership {
        let files = MapFiles::new().with("data/ownership.toml", OWNERSHIP);
        Ownership::load(&files, "data/ownership.toml").expect("fixture loads")
    }

    #[test]
    fn a_missing_map_is_an_error() {
        let files = MapFiles::new();
        assert!(Ownership::load(&files, "data/ownership.toml").is_err());
    }

    #[test]
    fn an_empty_map_is_an_error() {
        let files = MapFiles::new().with("data/ownership.toml", "schema = 1\n");
        assert!(Ownership::load(&files, "data/ownership.toml").is_err());
    }

    #[test]
    fn owners_resolve_by_override_then_entry_then_stem_then_rule() {
        let owned = ownership();
        let siblings: BTreeSet<String> = ["original/lib/http.c".to_owned()].into_iter().collect();
        assert_eq!(
            owned
                .owner_of("original/lib/curlx/winapi.c", &siblings)
                .as_deref(),
            Some("curl-abi")
        );
        assert_eq!(
            owned.owner_of("original/lib/http.c", &siblings).as_deref(),
            Some("curl-http1")
        );
        assert_eq!(
            owned.owner_of("original/lib/http.h", &siblings).as_deref(),
            Some("curl-http1")
        );
        assert_eq!(
            owned
                .owner_of("original/lib/urldata.h", &siblings)
                .as_deref(),
            Some("curl-core")
        );
        assert_eq!(
            owned
                .owner_of("original/lib/curlx/base64.c", &siblings)
                .as_deref(),
            Some("curl-types")
        );
        assert_eq!(owned.owner_of("original/lib/nothing.c", &siblings), None);
    }

    #[test]
    fn harness_declarations_load_whole_or_not_at_all() {
        let owned = ownership();
        assert_eq!(owned.harness.len(), 1);
        let entry = &owned.harness[0];
        assert_eq!(entry.path, "original/src/mkhelp.pl");
        assert_eq!(entry.disposition, "replaced");
        assert_eq!(entry.target, "curl-cli");
        assert_eq!(entry.decision, "DL-0273");
        // A declaration missing any field is an error rather than a default.
        for field in ["role", "disposition", "target", "decision"] {
            let text = OWNERSHIP.replace(&format!("\n{field} = "), "\nunread = ");
            let files = MapFiles::new().with("data/ownership.toml", &text);
            assert!(
                Ownership::load(&files, "data/ownership.toml").is_err(),
                "{field} is required"
            );
        }
        // A map with no harness declaration at all is an error.
        let text = OWNERSHIP.replace("[[harness]]", "[[unread]]");
        let files = MapFiles::new().with("data/ownership.toml", &text);
        assert!(Ownership::load(&files, "data/ownership.toml").is_err());
    }

    #[test]
    fn families_match_the_longest_prefix() {
        let owned = ownership();
        assert_eq!(
            owned.family_of("CURLOPT_URL").map(|f| f.owner.as_str()),
            Some("curl-core")
        );
        assert_eq!(
            owned
                .family_of("CURL_LOCK_DATA_DNS")
                .map(|f| f.owner.as_str()),
            Some("curl-abi")
        );
        assert!(owned.family_of("SOMETHING_ELSE").is_none());
        assert_eq!(owned.target_of("cli-option"), Some(("curl-cli", "DL-0026")));
        assert_eq!(owned.target_of("absent"), None);
    }

    #[test]
    fn exclusions_and_orphans_are_read() {
        let owned = ownership();
        assert!(owned.excluded("original/lib/amigaos.c").is_some());
        assert!(owned.excluded("original/lib/http.c").is_none());
        assert_eq!(owned.orphans.len(), 1);
        assert_eq!(owned.orphans[0].line, 249);
        assert_eq!(owned.cases.len(), 1);
    }

    #[test]
    fn planned_crates_come_from_required_members() {
        let directory = std::env::temp_dir().join("curl-audit-tests/traceability-contract");
        std::fs::create_dir_all(&directory).expect("fixture directory");
        std::fs::write(
            directory.join("Cargo.toml"),
            "[workspace]\nmembers = []\n\n[workspace.metadata.curl]\nrequired-members = [\"refactor/curl-core\", \"testing/abi\"]\n",
        )
        .expect("fixture manifest");
        let workspace = curl_audit::workspace::Workspace::load(&directory).expect("workspace");
        let planned = planned_crates(&workspace).expect("planned");
        assert!(planned.contains("curl-core"));
        assert!(planned.contains("abi"));
    }
}
