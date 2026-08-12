// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: the blitzy-curl project contributors

//! The resolved dependency graph: membership, exact pins, the committed
//! `Cargo.lock`, and a mechanical re-derivation of the full pinned set.
//!
//! Every assertion here rejects an empty graph and a zero match, so no check
//! can report success by observing nothing. `DL-0031` records why membership is
//! the gate it is, and `DL-0036` records why the full-set assertions run against
//! a re-derived resolution rather than against the committed lockfile.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use toml::Value;

use crate::fs::Files;
use crate::report::Report;
use crate::workspace::{
    AuditError, AuditResult, LOCKFILE, MANIFEST, Workspace, declared_version, is_exact_pin,
};

/// Name of the probe package used to re-derive the full pinned resolution.
pub const PROBE_PACKAGE: &str = "curl-audit-pin-probe";

/// Directory, under the Cargo target directory, holding the probe workspace.
pub const PROBE_DIRECTORY: &str = "curl-audit/pin-probe";

/// One `[[package]]` record of a lockfile.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LockedPackage {
    /// Package name.
    pub name: String,
    /// Package version, exactly as the lockfile spells it.
    pub version: String,
}

/// The version core of a Cargo version, with any `+build` metadata removed.
///
/// Cargo writes build metadata into the lockfile - `toml 1.1.4+spec-1.1.0` -
/// while a requirement is written without it, and semver ignores it when
/// comparing, so every comparison here compares cores.
#[must_use]
pub fn version_core(version: &str) -> &str {
    version.split('+').next().unwrap_or(version)
}

/// Parses the `[[package]]` records of a lockfile.
pub fn parse_packages(lockfile: &str) -> AuditResult<Vec<LockedPackage>> {
    let document = toml::from_str::<Value>(lockfile)
        .map_err(|error| AuditError::new(format!("{LOCKFILE}: {error}")))?;
    let Some(entries) = document.get("package") else {
        return Ok(Vec::new());
    };
    let entries = entries
        .as_array()
        .ok_or_else(|| AuditError::new(format!("{LOCKFILE}: package is not an array")))?;
    let mut packages = Vec::with_capacity(entries.len());
    for entry in entries {
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| AuditError::new(format!("{LOCKFILE}: a package has no name")))?;
        let version = entry
            .get("version")
            .and_then(Value::as_str)
            .ok_or_else(|| AuditError::new(format!("{LOCKFILE}: {name} has no version")))?;
        packages.push(LockedPackage {
            name: name.to_owned(),
            version: version.to_owned(),
        });
    }
    Ok(packages)
}

/// The distinct version cores a named package appears at.
#[must_use]
pub fn versions_of<'a>(packages: &'a [LockedPackage], name: &str) -> BTreeSet<&'a str> {
    packages
        .iter()
        .filter(|package| package.name == name)
        .map(|package| version_core(&package.version))
        .collect()
}

/// The recorded invariants the resolved graph must satisfy.
///
/// Read from `[workspace.metadata.curl.resolved-invariants]`, which `[R1]`
/// freezes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invariants {
    /// Package whose distinct-version count is constrained.
    pub single_version_package: String,
    /// The permitted number of distinct versions of that package.
    pub distinct_versions: usize,
    /// The one crypto provider the graph may contain.
    pub crypto_provider: String,
    /// Packages that must not appear anywhere in the graph.
    pub absent: Vec<String>,
    /// Transitives recorded by name and version.
    pub recorded: BTreeMap<String, String>,
}

impl Invariants {
    /// Reads the invariants out of the root manifest.
    pub fn from_workspace(workspace: &Workspace) -> AuditResult<Self> {
        let table = workspace.table(&["workspace", "metadata", "curl", "resolved-invariants"])?;
        let read_string = |key: &str| -> AuditResult<String> {
            table
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| AuditError::new(format!("resolved-invariants.{key} missing")))
        };
        let single_version_package = read_string("single-version-package")?;
        let crypto_provider = read_string("crypto-provider")?;
        let distinct_versions = table
            .get("distinct-rustls-versions")
            .and_then(Value::as_integer)
            .ok_or_else(|| {
                AuditError::new("resolved-invariants.distinct-rustls-versions missing")
            })?;
        let distinct_versions = usize::try_from(distinct_versions).map_err(|_| {
            AuditError::new("resolved-invariants.distinct-rustls-versions is not a count")
        })?;
        let absent = workspace.string_array(&[
            "workspace",
            "metadata",
            "curl",
            "resolved-invariants",
            "absent-transitives",
        ])?;
        let recorded_table = table
            .get("recorded-transitives")
            .and_then(Value::as_table)
            .ok_or_else(|| AuditError::new("resolved-invariants.recorded-transitives missing"))?;
        let mut recorded = BTreeMap::new();
        for (name, version) in recorded_table {
            let version = version.as_str().ok_or_else(|| {
                AuditError::new(format!(
                    "recorded-transitives.{name} is not a version string"
                ))
            })?;
            recorded.insert(name.clone(), version.to_owned());
        }
        if absent.is_empty() || recorded.is_empty() {
            return Err(AuditError::new(
                "resolved-invariants records no absent transitive or no recorded transitive",
            ));
        }
        Ok(Self {
            single_version_package,
            distinct_versions,
            crypto_provider,
            absent,
            recorded,
        })
    }
}

/// Asserts the recorded invariants against a complete resolution.
///
/// A complete resolution is one that resolves every pin, so here a zero match
/// is a failure rather than a not-yet-applicable state.
#[must_use]
pub fn check_full_resolution(packages: &[LockedPackage], invariants: &Invariants) -> Report {
    let mut report = Report::new("resolved-invariants/full-pin-resolution");
    report.assert(
        !packages.is_empty(),
        "graph-not-empty",
        format!("{} packages resolved", packages.len()),
    );
    if packages.is_empty() {
        return report;
    }

    let tracked = versions_of(packages, &invariants.single_version_package);
    report.assert(
        tracked.len() == invariants.distinct_versions,
        "single-version-package",
        format!(
            "{} resolves to {} distinct version(s) [{}], recorded {}",
            invariants.single_version_package,
            tracked.len(),
            tracked.iter().copied().collect::<Vec<_>>().join(", "),
            invariants.distinct_versions
        ),
    );

    let provider = versions_of(packages, &invariants.crypto_provider);
    report.assert(
        provider.len() == 1,
        "crypto-provider",
        format!(
            "{} resolves to {} distinct version(s) [{}]",
            invariants.crypto_provider,
            provider.len(),
            provider.iter().copied().collect::<Vec<_>>().join(", ")
        ),
    );

    for name in &invariants.absent {
        let found = versions_of(packages, name);
        report.assert(
            found.is_empty(),
            format!("absent-transitive/{name}"),
            if found.is_empty() {
                "absent".to_owned()
            } else {
                format!(
                    "present at {}",
                    found.iter().copied().collect::<Vec<_>>().join(", ")
                )
            },
        );
    }

    for (name, recorded) in &invariants.recorded {
        let found = versions_of(packages, name);
        let matches = found.contains(&version_core(recorded));
        report.assert(
            matches,
            format!("recorded-transitive/{name}"),
            format!(
                "recorded {recorded}, resolved [{}]",
                found.iter().copied().collect::<Vec<_>>().join(", ")
            ),
        );
    }
    report
}

/// Asserts what the committed lockfile alone can carry.
///
/// The committed lockfile resolves exactly the dependencies the current members
/// declare, so it is a subset of the pinned set by construction (`DL-0036`).
/// The assertions therefore are: the graph is not empty, no banned package is in
/// it, the single-version package is never duplicated, and every pin the graph
/// does contain is honoured at its pinned version - with a failure if no pin at
/// all could be verified.
#[must_use]
pub fn check_committed_lock(
    packages: &[LockedPackage],
    invariants: &Invariants,
    pins: &BTreeMap<String, String>,
) -> Report {
    let mut report = Report::new("resolved-invariants/committed-lock");
    report.assert(
        !packages.is_empty(),
        "lock-not-empty",
        format!("{} packages locked", packages.len()),
    );
    if packages.is_empty() {
        return report;
    }

    for name in &invariants.absent {
        let found = versions_of(packages, name);
        report.assert(
            found.is_empty(),
            format!("absent-transitive/{name}"),
            if found.is_empty() {
                "absent".to_owned()
            } else {
                format!(
                    "present at {}",
                    found.iter().copied().collect::<Vec<_>>().join(", ")
                )
            },
        );
    }

    let tracked = versions_of(packages, &invariants.single_version_package);
    report.assert(
        tracked.len() <= invariants.distinct_versions,
        "single-version-package-not-duplicated",
        format!(
            "{} locked at {} distinct version(s), ceiling {}",
            invariants.single_version_package,
            tracked.len(),
            invariants.distinct_versions
        ),
    );

    let mut honoured = 0_usize;
    let mut violated = Vec::new();
    for (name, requirement) in pins {
        let found = versions_of(packages, name);
        if found.is_empty() {
            continue;
        }
        let pinned = version_core(requirement.trim_start_matches('='));
        if found.contains(&pinned) {
            honoured += 1;
        } else {
            violated.push(format!(
                "{name}: pinned {pinned}, locked [{}]",
                found.iter().copied().collect::<Vec<_>>().join(", ")
            ));
        }
    }
    report.assert(
        violated.is_empty(),
        "pins-honoured",
        if violated.is_empty() {
            format!("{honoured} pinned crate(s) present and at their pinned version")
        } else {
            violated.join("; ")
        },
    );
    report.assert(
        honoured > 0,
        "pins-verified-not-zero",
        format!("{honoured} pin(s) verified against the lock"),
    );
    report
}

/// Asserts that every `[workspace.dependencies]` entry is an exact pin.
#[must_use]
pub fn check_pins(pins: &BTreeMap<String, String>) -> Report {
    let mut report = Report::new("workspace-dependencies/exact-pins");
    report.assert(
        !pins.is_empty(),
        "pins-declared",
        format!("{} pinned crate(s)", pins.len()),
    );
    let loose: Vec<String> = pins
        .iter()
        .filter(|(_, requirement)| !is_exact_pin(requirement))
        .map(|(name, requirement)| format!("{name} = {requirement}"))
        .collect();
    report.assert(
        loose.is_empty(),
        "pins-exact",
        if loose.is_empty() {
            "every requirement is an exact =x.y.z pin".to_owned()
        } else {
            loose.join("; ")
        },
    );
    report
}

/// Reads `[workspace.dependencies]` as a name-to-requirement map.
pub fn pins_of(workspace: &Workspace) -> AuditResult<BTreeMap<String, String>> {
    let table = workspace.dependencies()?;
    let mut pins = BTreeMap::new();
    for (name, entry) in table {
        let requirement = declared_version(entry).ok_or_else(|| {
            AuditError::new(format!("workspace.dependencies.{name} declares no version"))
        })?;
        pins.insert(name.clone(), requirement.to_owned());
    }
    Ok(pins)
}

/// Asserts workspace membership against the frozen member inventory.
///
/// An empty member list is the failure this check exists for: it makes every
/// cargo invocation fail and leaves the lockfile unresolvable (`DL-0031`).
#[must_use]
pub fn check_membership(workspace: &Workspace, files: &dyn Files) -> Report {
    let mut report = Report::new("workspace-members");
    let members = match workspace.members() {
        Ok(members) => members,
        Err(error) => {
            report.fail("members-declared", error.message().to_owned());
            return report;
        }
    };
    report.assert(
        !members.is_empty(),
        "members-not-empty",
        format!("{} member(s) declared", members.len()),
    );

    let missing: Vec<&String> = members
        .iter()
        .filter(|member| !files.exists(&format!("{member}/{MANIFEST}")))
        .collect();
    report.assert(
        missing.is_empty(),
        "members-exist",
        if missing.is_empty() {
            format!("every member has a {MANIFEST}")
        } else {
            missing
                .iter()
                .map(|member| format!("{member}: no {MANIFEST}"))
                .collect::<Vec<_>>()
                .join("; ")
        },
    );

    let required =
        match workspace.string_array(&["workspace", "metadata", "curl", "required-members"]) {
            Ok(required) => required,
            Err(error) => {
                report.fail("required-members-declared", error.message().to_owned());
                return report;
            }
        };
    let required_set: BTreeSet<&String> = required.iter().collect();
    let unplanned: Vec<&String> = members
        .iter()
        .filter(|member| !required_set.contains(*member))
        .collect();
    report.assert(
        unplanned.is_empty(),
        "members-are-planned",
        if unplanned.is_empty() {
            format!(
                "every member is one of the {} planned members",
                required.len()
            )
        } else {
            unplanned
                .iter()
                .map(|member| format!("{member}: not in required-members"))
                .collect::<Vec<_>>()
                .join("; ")
        },
    );

    let member_set: BTreeSet<&String> = members.iter().collect();
    let orphans: Vec<&String> = required
        .iter()
        .filter(|candidate| {
            files.exists(&format!("{candidate}/{MANIFEST}")) && !member_set.contains(*candidate)
        })
        .collect();
    report.assert(
        orphans.is_empty(),
        "no-orphan-member",
        if orphans.is_empty() {
            "every planned member that exists is a workspace member".to_owned()
        } else {
            orphans
                .iter()
                .map(|member| format!("{member}: has a manifest but is not a member"))
                .collect::<Vec<_>>()
                .join("; ")
        },
    );
    report
}

/// Where the probe workspace is written.
#[must_use]
pub fn probe_directory(root: &Path) -> PathBuf {
    match std::env::var_os("CARGO_TARGET_DIR") {
        Some(target) => PathBuf::from(target).join(PROBE_DIRECTORY),
        None => root.join("target").join(PROBE_DIRECTORY),
    }
}

/// Renders the probe manifest that pulls in every pinned crate.
///
/// The probe declares its own `[workspace]` table so it is a standalone
/// workspace rather than a member of the one being audited, and it copies each
/// dependency entry verbatim so features and `default-features` - which change
/// resolution - are the ones the project declares.
pub fn probe_manifest(workspace: &Workspace) -> AuditResult<String> {
    let dependencies = workspace.dependencies()?;
    let mut manifest = Value::Table(toml::map::Map::new());
    let table = manifest
        .as_table_mut()
        .ok_or_else(|| AuditError::new("probe manifest is not a table"))?;

    let mut package = toml::map::Map::new();
    package.insert("name".to_owned(), Value::String(PROBE_PACKAGE.to_owned()));
    package.insert("version".to_owned(), Value::String("0.0.0".to_owned()));
    package.insert("edition".to_owned(), Value::String("2024".to_owned()));
    package.insert("publish".to_owned(), Value::Boolean(false));
    table.insert("package".to_owned(), Value::Table(package));

    let mut library = toml::map::Map::new();
    library.insert("name".to_owned(), Value::String("probe".to_owned()));
    library.insert("path".to_owned(), Value::String("probe.rs".to_owned()));
    table.insert("lib".to_owned(), Value::Table(library));

    table.insert(
        "dependencies".to_owned(),
        Value::Table(dependencies.clone()),
    );
    table.insert("workspace".to_owned(), Value::Table(toml::map::Map::new()));

    toml::to_string_pretty(&manifest)
        .map_err(|error| AuditError::new(format!("probe manifest: {error}")))
}

/// Re-derives the resolution of every pinned crate and returns its packages.
///
/// Cargo resolves exactly what the members of a workspace declare, so the only
/// way to observe the full pinned set is to resolve it (`DL-0036`). Resolution
/// is attempted offline first so a warmed registry cache needs no network, then
/// online.
pub fn derive_full_resolution(workspace: &Workspace) -> AuditResult<Vec<LockedPackage>> {
    let directory = probe_directory(workspace.root());
    std::fs::create_dir_all(&directory)
        .map_err(|error| AuditError::new(format!("{}: {error}", directory.display())))?;
    let manifest = probe_manifest(workspace)?;
    std::fs::write(directory.join(MANIFEST), manifest)
        .map_err(|error| AuditError::new(format!("{}: {error}", directory.display())))?;
    std::fs::write(directory.join("probe.rs"), "")
        .map_err(|error| AuditError::new(format!("{}: {error}", directory.display())))?;
    let lock = directory.join(LOCKFILE);
    if lock.exists() {
        std::fs::remove_file(&lock)
            .map_err(|error| AuditError::new(format!("{}: {error}", lock.display())))?;
    }

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let mut failures = Vec::new();
    for offline in [true, false] {
        let mut command = Command::new(&cargo);
        command
            .arg("generate-lockfile")
            .arg("--manifest-path")
            .arg(directory.join(MANIFEST));
        if offline {
            command.arg("--offline");
        }
        command.env_remove("CARGO_TARGET_DIR");
        match command.output() {
            Ok(output) if output.status.success() => {
                let text = std::fs::read_to_string(&lock)
                    .map_err(|error| AuditError::new(format!("{}: {error}", lock.display())))?;
                let mut packages = parse_packages(&text)?;
                packages.retain(|package| package.name != PROBE_PACKAGE);
                return Ok(packages);
            }
            Ok(output) => failures.push(format!(
                "{cargo} generate-lockfile{}: {}",
                if offline { " --offline" } else { "" },
                String::from_utf8_lossy(&output.stderr).trim()
            )),
            Err(error) => failures.push(format!("{cargo} generate-lockfile: {error}")),
        }
    }
    Err(AuditError::new(failures.join(" | ")))
}

/// Runs every dependency-graph audit against a checkout.
pub fn audit(workspace: &Workspace, files: &dyn Files) -> AuditResult<Report> {
    let mut report = Report::new("dependency-graph");
    let pins = pins_of(workspace)?;
    let invariants = Invariants::from_workspace(workspace)?;

    report.absorb(check_membership(workspace, files));
    report.absorb(check_pins(&pins));

    let lockfile = files
        .read(LOCKFILE)
        .ok_or_else(|| AuditError::new(format!("{LOCKFILE} is missing")))?;
    let locked = parse_packages(&lockfile)?;
    report.absorb(check_committed_lock(&locked, &invariants, &pins));

    let resolved = derive_full_resolution(workspace)?;
    report.absorb(check_full_resolution(&resolved, &invariants));
    Ok(report)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        Invariants, LockedPackage, check_committed_lock, check_full_resolution, check_membership,
        check_pins, parse_packages, probe_manifest, version_core, versions_of,
    };
    use crate::fs::MapFiles;
    use crate::workspace::Workspace;

    const ROOT_MANIFEST: &str = r#"
[workspace]
members = ["testing/audit"]

[workspace.dependencies]
toml = "=1.1.4"
rustls = { version = "=0.23.43", default-features = false, features = ["ring"] }

[workspace.metadata.curl]
required-members = ["testing/audit", "testing/abi"]

[workspace.metadata.curl.resolved-invariants]
single-version-package = "rustls"
distinct-rustls-versions = 1
crypto-provider = "ring"
absent-transitives = ["aws-lc-rs"]
recorded-transitives = { ring = "0.17.14", toml = "1.1.4" }
"#;

    fn workspace(key: &str) -> Workspace {
        // One fixture directory per test: these run in parallel, and a shared
        // path would let one test read another's half-written manifest.
        let directory = std::env::temp_dir().join(format!("curl-audit-tests/lockfile-{key}"));
        std::fs::create_dir_all(&directory).expect("fixture directory");
        std::fs::write(directory.join("Cargo.toml"), ROOT_MANIFEST).expect("fixture manifest");
        Workspace::load(&directory).expect("fixture workspace")
    }

    fn packages(pairs: &[(&str, &str)]) -> Vec<LockedPackage> {
        pairs
            .iter()
            .map(|(name, version)| LockedPackage {
                name: (*name).to_owned(),
                version: (*version).to_owned(),
            })
            .collect()
    }

    #[test]
    fn build_metadata_is_ignored_when_comparing() {
        assert_eq!(version_core("1.1.4+spec-1.1.0"), "1.1.4");
        assert_eq!(version_core("0.23.43"), "0.23.43");
    }

    #[test]
    fn an_empty_lockfile_parses_to_no_packages() {
        let empty = "# This file is automatically @generated by Cargo.\nversion = 4\n";
        assert!(parse_packages(empty).expect("parses").is_empty());
    }

    #[test]
    fn packages_and_versions_are_read() {
        let text = r#"
version = 4

[[package]]
name = "rustls"
version = "0.23.43"

[[package]]
name = "toml"
version = "1.1.4+spec-1.1.0"
"#;
        let parsed = parse_packages(text).expect("parses");
        assert_eq!(parsed.len(), 2);
        assert_eq!(versions_of(&parsed, "toml").len(), 1);
        assert!(versions_of(&parsed, "toml").contains("1.1.4"));
        assert!(versions_of(&parsed, "absent").is_empty());
    }

    #[test]
    fn a_malformed_lockfile_is_an_error() {
        assert!(parse_packages("package = 3").is_err());
        assert!(parse_packages("[[package]]\nversion = \"1.0.0\"").is_err());
        assert!(parse_packages("[[package]]\nname = \"x\"").is_err());
    }

    #[test]
    fn an_empty_graph_fails_both_lock_checks() {
        let invariants = Invariants::from_workspace(&workspace("empty-graph")).expect("invariants");
        let pins = BTreeMap::from([("toml".to_owned(), "=1.1.4".to_owned())]);
        let empty = check_committed_lock(&[], &invariants, &pins);
        assert!(!empty.passed());
        assert!(empty.render().contains("FAIL lock-not-empty"));
        let full = check_full_resolution(&[], &invariants);
        assert!(!full.passed());
        assert!(full.render().contains("FAIL graph-not-empty"));
    }

    #[test]
    fn zero_matches_fail_the_full_resolution_checks() {
        let invariants =
            Invariants::from_workspace(&workspace("zero-matches")).expect("invariants");
        // A graph with neither rustls nor ring nor the recorded transitives.
        let report = check_full_resolution(&packages(&[("serde", "1.0.229")]), &invariants);
        let rendered = report.render();
        assert!(rendered.contains("FAIL single-version-package"));
        assert!(rendered.contains("FAIL crypto-provider"));
        assert!(rendered.contains("FAIL recorded-transitive/ring"));
        assert!(rendered.contains("FAIL recorded-transitive/toml"));
        assert_eq!(report.failures(), 4);
    }

    #[test]
    fn a_complete_graph_passes_the_full_resolution_checks() {
        let invariants =
            Invariants::from_workspace(&workspace("complete-graph")).expect("invariants");
        let report = check_full_resolution(
            &packages(&[
                ("rustls", "0.23.43"),
                ("ring", "0.17.14"),
                ("toml", "1.1.4+spec-1.1.0"),
            ]),
            &invariants,
        );
        assert!(report.passed(), "{}", report.render());
    }

    #[test]
    fn duplication_and_banned_packages_fail() {
        let invariants = Invariants::from_workspace(&workspace("duplication")).expect("invariants");
        let report = check_full_resolution(
            &packages(&[
                ("rustls", "0.23.43"),
                ("rustls", "0.24.0"),
                ("ring", "0.17.14"),
                ("aws-lc-rs", "1.18.0"),
                ("toml", "1.1.4"),
            ]),
            &invariants,
        );
        let rendered = report.render();
        assert!(rendered.contains("FAIL single-version-package"));
        assert!(rendered.contains("FAIL absent-transitive/aws-lc-rs"));
    }

    #[test]
    fn committed_lock_honours_pins_and_tolerates_third_party_duplication() {
        let invariants =
            Invariants::from_workspace(&workspace("committed-lock")).expect("invariants");
        let pins = BTreeMap::from([
            ("toml".to_owned(), "=1.1.4".to_owned()),
            ("rustls".to_owned(), "=0.23.43".to_owned()),
        ]);
        // toml at the pinned version plus a third-party older copy: honoured.
        let report = check_committed_lock(
            &packages(&[("toml", "1.1.4+spec-1.1.0"), ("toml", "0.9.12+spec-1.1.0")]),
            &invariants,
            &pins,
        );
        assert!(report.passed(), "{}", report.render());

        // toml present but not at the pinned version: violated.
        let report = check_committed_lock(&packages(&[("toml", "1.1.3")]), &invariants, &pins);
        assert!(report.render().contains("FAIL pins-honoured"));

        // no pin observable at all: rejected rather than passed.
        let report = check_committed_lock(&packages(&[("serde", "1.0.229")]), &invariants, &pins);
        assert!(report.render().contains("FAIL pins-verified-not-zero"));
    }

    #[test]
    fn pin_shapes_are_checked() {
        let exact = BTreeMap::from([("toml".to_owned(), "=1.1.4".to_owned())]);
        assert!(check_pins(&exact).passed());
        let loose = BTreeMap::from([("toml".to_owned(), "^1.1.4".to_owned())]);
        assert!(check_pins(&loose).render().contains("FAIL pins-exact"));
        assert!(
            check_pins(&BTreeMap::new())
                .render()
                .contains("FAIL pins-declared")
        );
    }

    #[test]
    fn membership_is_checked_against_the_frozen_inventory() {
        let workspace = workspace("membership");
        let files = MapFiles::new()
            .with("testing/audit/Cargo.toml", "")
            .with("Cargo.lock", "version = 4\n");
        let report = check_membership(&workspace, &files);
        assert!(report.passed(), "{}", report.render());

        // A planned member that exists but is not a member is an orphan.
        let files = files.with("testing/abi/Cargo.toml", "");
        let report = check_membership(&workspace, &files);
        assert!(report.render().contains("FAIL no-orphan-member"));

        // A member without a manifest fails, and an empty list fails.
        let report = check_membership(&workspace, &MapFiles::new());
        assert!(report.render().contains("FAIL members-exist"));
    }

    #[test]
    fn an_empty_member_list_fails() {
        let directory = std::env::temp_dir().join("curl-audit-tests/lockfile-empty-members");
        std::fs::create_dir_all(&directory).expect("fixture directory");
        std::fs::write(
            directory.join("Cargo.toml"),
            ROOT_MANIFEST.replace("members = [\"testing/audit\"]", "members = []"),
        )
        .expect("fixture manifest");
        let workspace = Workspace::load(&directory).expect("fixture workspace");
        let report = check_membership(&workspace, &MapFiles::new());
        assert!(report.render().contains("FAIL members-not-empty"));
    }

    #[test]
    fn the_probe_manifest_copies_every_pin_verbatim() {
        let manifest = probe_manifest(&workspace("probe")).expect("probe manifest");
        assert!(manifest.contains("curl-audit-pin-probe"));
        assert!(manifest.contains("[workspace]"));
        assert!(manifest.contains("toml = \"=1.1.4\""));
        assert!(manifest.contains("default-features = false"));
        assert!(manifest.contains("\"ring\""));
        let reparsed = toml::from_str::<toml::Value>(&manifest).expect("probe manifest parses");
        assert!(reparsed.get("dependencies").is_some());
    }

    #[test]
    fn invariants_reject_an_incomplete_contract() {
        let directory = std::env::temp_dir().join("curl-audit-tests/lockfile-bad-invariants");
        std::fs::create_dir_all(&directory).expect("fixture directory");
        std::fs::write(
            directory.join("Cargo.toml"),
            "[workspace]\nmembers = []\n\n[workspace.metadata.curl.resolved-invariants]\nsingle-version-package = \"rustls\"\n",
        )
        .expect("fixture manifest");
        let workspace = Workspace::load(&directory).expect("fixture workspace");
        assert!(Invariants::from_workspace(&workspace).is_err());
    }
}
