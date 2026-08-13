// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: the blitzy-curl project contributors

//! Forward direction: every oracle construct resolved to the target that owns
//! it, or to a justified exclusion.
//!
//! A construct with neither is a gap, and a gap is a failing check.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use curl_audit::fs::Files;
use curl_audit::report::Report;

use crate::contract::Ownership;
use crate::oracle::Survey;

/// One resolved forward row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Row {
    /// Construct family this row belongs to.
    pub family: &'static str,
    /// Oracle construct: a path, a symbol or a flag name.
    pub source: String,
    /// What the construct is, in the family's own terms.
    pub detail: String,
    /// Target that owns it, or `none` when nothing does.
    pub target: String,
    /// How it is accounted for: owned, excluded or orphaned.
    pub disposition: String,
    /// Decision this row rests on, empty when the family needs none.
    pub decision: String,
}

/// Every forward row plus the gaps found while resolving them.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Forward {
    /// Rows in family then source order.
    pub rows: Vec<Row>,
    /// Sources that resolved to nothing.
    pub gaps: Vec<String>,
}

impl Forward {
    /// Rows of one family.
    #[must_use]
    pub fn family(&self, family: &str) -> Vec<&Row> {
        self.rows
            .iter()
            .filter(|row| row.family == family)
            .collect()
    }

    /// Rows whose disposition is an exclusion.
    #[must_use]
    pub fn excluded(&self) -> Vec<&Row> {
        self.rows
            .iter()
            .filter(|row| row.disposition.starts_with("excluded"))
            .collect()
    }
}

/// Symbols upstream's own single-use checker whitelists.
///
/// The whitelist is the mechanical denominator for the inverse orphan shape: it
/// is upstream's own record of definitions its checker would otherwise flag, so
/// it cannot drift from a list of ours because it is not a list of ours.
#[must_use]
pub fn single_use_whitelist(files: &dyn Files) -> BTreeSet<String> {
    let Some(text) = files.read("original/scripts/singleuse.pl") else {
        return BTreeSet::new();
    };
    let mut found = BTreeSet::new();
    let mut inside = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("my %wl") {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        if trimmed == ");" {
            break;
        }
        if let Some(name) = trimmed.strip_prefix('\'')
            && let Some(symbol) = name.split('\'').next()
        {
            found.insert(symbol.to_owned());
        }
    }
    found
}

/// How the oracle reaches one whitelisted definition.
///
/// Measured over the library sources rather than declared: a reference that is
/// neither the definition nor a prototype makes it `called`, a macro that
/// expands to it makes it `macro`, and neither makes it `unreachable`.
#[must_use]
pub fn reachability(files: &dyn Files, symbol: &str) -> String {
    let sources = crate::oracle::walk(files, "original/lib", ".c");
    let headers = crate::oracle::walk(files, "original/lib", ".h");
    let mut called = false;
    let mut macro_reached = false;
    for path in sources.iter().chain(headers.iter()) {
        let Some(text) = files.read(path) else {
            continue;
        };
        let source = path.ends_with(".c");
        for line in text.lines() {
            if !line.contains(symbol) {
                continue;
            }
            let trimmed = line.trim();
            if trimmed.starts_with("#define") {
                macro_reached = true;
                continue;
            }
            if !source {
                // A prototype is not a use.
                continue;
            }
            // A definition's signature line does not end in a semicolon and
            // carries only declarator tokens before the name. Everything else
            // that names the symbol is a use: a call, or an entry in a table of
            // function pointers.
            let head = trimmed
                .split_once(symbol)
                .map_or("", |(head, _)| head)
                .trim();
            let declarator = !trimmed.ends_with(';')
                && trimmed.contains(&format!("{symbol}("))
                && !head.is_empty()
                && head
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '_' || c == '*' || c == ' ' || c == '\t');
            if declarator {
                continue;
            }
            called = true;
        }
    }
    if called {
        "called".to_owned()
    } else if macro_reached {
        "macro".to_owned()
    } else {
        "unreachable".to_owned()
    }
}

/// How many whitelisted symbols have one measured reach.
fn count_reach(files: &dyn Files, whitelist: &BTreeSet<String>, reach: &str) -> usize {
    whitelist
        .iter()
        .filter(|symbol| reachability(files, symbol) == reach)
        .count()
}

/// Resolves the generator, harness and configuration assets.
///
/// Both directions are gates: an enumerated asset with no declaration is a gap,
/// and a declaration naming nothing enumerated is stale. `DL-0273` records the
/// family.
fn resolve_harness(
    survey: &Survey,
    ownership: &Ownership,
    planned: &BTreeSet<String>,
    decisions: &BTreeSet<String>,
    forward: &mut Forward,
    report: &mut Report,
) {
    report.assert(
        !survey.harness.is_empty(),
        "harness-asset/enumerated",
        format!(
            "{} asset(s) across {} root(s), {} registered by a build manifest",
            survey.harness.len(),
            crate::oracle::HARNESS_ROOTS.len(),
            survey
                .harness
                .iter()
                .filter(|asset| !asset.registration.is_empty())
                .count()
        ),
    );

    // A distribution word that names no file is recorded rather than dropped: it
    // is a build product the vendored build writes, not an import that failed.
    report.pass(
        "harness-asset/manifest-words-without-a-file",
        if survey.harness_absent.is_empty() {
            "every distribution word names a file".to_owned()
        } else {
            format!(
                "{} word(s) naming no file: {}",
                survey.harness_absent.len(),
                survey.harness_absent.join(", ")
            )
        },
    );

    let declared: BTreeMap<&str, &crate::contract::Harness> = ownership
        .harness
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    report.assert(
        declared.len() == ownership.harness.len(),
        "harness-asset/declarations-unique",
        format!(
            "{} declaration(s) for {} distinct path(s)",
            ownership.harness.len(),
            declared.len()
        ),
    );

    // A target is `none`, a planned member or a target the map already declares
    // for a whole family, which is what admits the compatibility front end.
    let known: BTreeSet<&str> = ownership
        .targets
        .values()
        .map(String::as_str)
        .chain(planned.iter().map(String::as_str))
        .collect();
    let mut undeclared = Vec::new();
    let mut unaccountable = Vec::new();
    for asset in &survey.harness {
        let Some(entry) = declared.get(asset.path.as_str()) else {
            undeclared.push(asset.path.clone());
            continue;
        };
        if !crate::contract::HARNESS_DISPOSITIONS.contains(&entry.disposition.as_str())
            || entry.role.trim().is_empty()
            || !decisions.contains(&entry.decision)
            || (entry.target != "none" && !known.contains(entry.target.as_str()))
        {
            unaccountable.push(asset.path.clone());
        }
        forward.rows.push(Row {
            family: "harness-asset",
            source: asset.path.clone(),
            detail: format!(
                "{}; registered {}",
                entry.role,
                if asset.registration.is_empty() {
                    "nowhere".to_owned()
                } else {
                    format!("`{}`", asset.registration)
                }
            ),
            target: entry.target.clone(),
            disposition: entry.disposition.clone(),
            decision: entry.decision.clone(),
        });
    }
    report.assert(
        undeclared.is_empty(),
        "harness-asset/declared",
        if undeclared.is_empty() {
            format!(
                "every enumerated asset carries a declaration, {} of them with no counterpart",
                ownership
                    .harness
                    .iter()
                    .filter(|entry| entry.target == "none")
                    .count()
            )
        } else {
            format!("no declaration: {}", undeclared.join(", "))
        },
    );
    forward.gaps.extend(undeclared);

    report.assert(
        unaccountable.is_empty(),
        "harness-asset/declarations-accountable",
        if unaccountable.is_empty() {
            format!(
                "every declaration names a role, one of {} disposition(s), a known target and a resolving pointer",
                crate::contract::HARNESS_DISPOSITIONS.len()
            )
        } else {
            format!("incomplete: {}", unaccountable.join(", "))
        },
    );
    forward.gaps.extend(unaccountable);

    let enumerated: BTreeSet<&str> = survey
        .harness
        .iter()
        .map(|asset| asset.path.as_str())
        .collect();
    let stale: Vec<&str> = declared
        .keys()
        .filter(|path| !enumerated.contains(*path))
        .copied()
        .collect();
    report.assert(
        stale.is_empty(),
        "harness-asset/declarations-enumerated",
        if stale.is_empty() {
            "every declaration names an enumerated asset".to_owned()
        } else {
            format!("declared and not enumerated: {}", stale.join(", "))
        },
    );
    forward
        .gaps
        .extend(stale.into_iter().map(|path| format!("{path}: stale")));
}

/// Resolves every family and records a check per gate.
#[allow(clippy::too_many_lines)] // One gate per family; splitting hides the set. DL-0111
pub fn resolve(
    files: &dyn Files,
    survey: &Survey,
    ownership: &Ownership,
    planned: &BTreeSet<String>,
    decisions: &BTreeSet<String>,
    report: &mut Report,
) -> Forward {
    let mut forward = Forward::default();
    let siblings = survey.paths();
    let mut owners_seen: BTreeSet<String> = BTreeSet::new();

    // Translation units and internal headers share one resolution rule.
    for (family, paths) in [
        ("translation-unit", &survey.units),
        ("internal-header", &survey.headers),
    ] {
        report.assert(
            !paths.is_empty(),
            format!("{family}/enumerated"),
            format!("{} enumerated from the oracle", paths.len()),
        );
        for path in paths {
            // An exclusion is the narrower statement, so it wins over a
            // directory rule; beside an explicit entry it is a contradiction.
            match ownership.excluded(path) {
                Some(_) if ownership.explicitly_owned(path) => forward
                    .gaps
                    .push(format!("{path}: explicitly owned and excluded")),
                Some(exclusion) => forward.rows.push(Row {
                    family,
                    source: path.clone(),
                    detail: exclusion.reason.clone(),
                    target: "none".to_owned(),
                    disposition: format!("excluded:{}", exclusion.disposition),
                    decision: exclusion.decision.clone(),
                }),
                None => match ownership.owner_of(path, &siblings) {
                    Some(owner) => {
                        owners_seen.insert(owner.clone());
                        forward.rows.push(Row {
                            family,
                            source: path.clone(),
                            detail: String::new(),
                            target: owner,
                            disposition: "owned".to_owned(),
                            decision: String::new(),
                        });
                    }
                    None => forward.gaps.push(format!("{path}: no owner declared")),
                },
            }
        }
    }

    // Every declared owner has to be a crate the project plans to build.
    let unplanned: Vec<&String> = owners_seen
        .iter()
        .filter(|owner| !planned.contains(*owner))
        .collect();
    report.assert(
        unplanned.is_empty() && !owners_seen.is_empty(),
        "owners-planned",
        if unplanned.is_empty() {
            format!(
                "{} distinct owner(s), all planned members",
                owners_seen.len()
            )
        } else {
            format!(
                "not planned members: {}",
                unplanned
                    .iter()
                    .map(|owner| owner.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        },
    );

    // A declared entry that names nothing in the oracle is stale.
    let enumerated: HashSet<&str> = survey
        .units
        .iter()
        .chain(survey.headers.iter())
        .map(String::as_str)
        .collect();
    let stale: Vec<String> = ownership
        .units
        .keys()
        .map(|name| format!("original/lib/{name}"))
        .chain(
            ownership
                .headers
                .keys()
                .map(|name| format!("original/lib/{name}")),
        )
        .chain(ownership.overrides.keys().cloned())
        .chain(
            ownership
                .exclusions
                .iter()
                .map(|exclusion| exclusion.path.clone()),
        )
        .filter(|path| !enumerated.contains(path.as_str()))
        .collect();
    report.assert(
        stale.is_empty(),
        "declared-entries-exist",
        if stale.is_empty() {
            "every declared entry names an enumerated path".to_owned()
        } else {
            format!("stale: {}", stale.join(", "))
        },
    );

    // Every exclusion carries a written justification and a resolving pointer.
    let unjustified: Vec<String> = ownership
        .exclusions
        .iter()
        .filter(|exclusion| {
            exclusion.reason.trim().is_empty()
                || exclusion.disposition.trim().is_empty()
                || !decisions.contains(&exclusion.decision)
        })
        .map(|exclusion| exclusion.path.clone())
        .collect();
    report.assert(
        unjustified.is_empty() && !ownership.exclusions.is_empty(),
        "exclusions-justified",
        if unjustified.is_empty() {
            format!(
                "{} exclusion(s), each with a disposition, a reason and a resolving pointer",
                ownership.exclusions.len()
            )
        } else {
            format!("unjustified: {}", unjustified.join(", "))
        },
    );

    // Public headers are inputs; their target is the crate whose declarations
    // are verified against them.
    let (public_target, public_decision) = ownership.target_of("public-header").unwrap_or(("", ""));
    report.assert(
        !survey.public_headers.is_empty() && !public_target.is_empty(),
        "public-header/enumerated",
        format!(
            "{} public header(s), target {}",
            survey.public_headers.len(),
            if public_target.is_empty() {
                "undeclared"
            } else {
                public_target
            }
        ),
    );
    for header in &survey.public_headers {
        forward.rows.push(Row {
            family: "public-header",
            source: header.clone(),
            detail: "immutable input, declarations verified against it".to_owned(),
            target: public_target.to_owned(),
            disposition: "verified".to_owned(),
            decision: public_decision.to_owned(),
        });
    }

    // Exported symbols: every name in the export list has to be declared.
    let (export_target, export_decision) =
        ownership.target_of("exported-symbol").unwrap_or(("", ""));
    report.assert(
        !survey.exports.is_empty() && !export_target.is_empty(),
        "exported-symbol/enumerated",
        format!("{} exported name(s)", survey.exports.len()),
    );
    let undeclared: Vec<&str> = survey
        .exports
        .iter()
        .filter(|export| export.headers.is_empty())
        .map(|export| export.name.as_str())
        .collect();
    report.assert(
        undeclared.is_empty(),
        "exported-symbol/declared",
        if undeclared.is_empty() {
            "every exported name is declared in a public header".to_owned()
        } else {
            format!("undeclared: {}", undeclared.join(", "))
        },
    );
    let variadic = survey
        .exports
        .iter()
        .filter(|export| export.variadic)
        .count();
    report.assert(
        variadic > 0,
        "exported-symbol/variadic-derived",
        format!("{variadic} name(s) variadic or taking an argument list"),
    );
    for export in &survey.exports {
        forward.rows.push(Row {
            family: "exported-symbol",
            source: export.name.clone(),
            detail: format!(
                "{} declared in {}",
                if export.variadic {
                    "C thunk"
                } else {
                    "Rust entry point"
                },
                if export.headers.is_empty() {
                    "no public header".to_owned()
                } else {
                    export.headers.join(", ")
                }
            ),
            target: export_target.to_owned(),
            disposition: if export.variadic {
                "c-thunk".to_owned()
            } else {
                "rust-entry".to_owned()
            },
            decision: export_decision.to_owned(),
        });
    }

    // Symbol register: every entry has to match a declared family.
    report.assert(
        !survey.register.is_empty(),
        "symbol-register/enumerated",
        format!("{} register entry(ies)", survey.register.len()),
    );
    let mut unfamiliar = Vec::new();
    for entry in &survey.register {
        match ownership.family_of(&entry.name) {
            Some(family) => {
                if !planned.contains(&family.owner) {
                    unfamiliar.push(format!(
                        "{}: owner {} not planned",
                        entry.name, family.owner
                    ));
                    continue;
                }
                let mut detail = format!("{} since {}", family.kind, entry.introduced);
                if !entry.deprecated.is_empty() {
                    detail.push_str(&format!(", deprecated {}", entry.deprecated));
                }
                if !entry.last.is_empty() {
                    detail.push_str(&format!(", last {}", entry.last));
                }
                forward.rows.push(Row {
                    family: "symbol-register",
                    source: entry.name.clone(),
                    detail,
                    target: family.owner.clone(),
                    disposition: "owned".to_owned(),
                    decision: String::new(),
                });
            }
            None => unfamiliar.push(format!("{}: no declared family", entry.name)),
        }
    }
    report.assert(
        unfamiliar.is_empty(),
        "symbol-register/families-cover",
        if unfamiliar.is_empty() {
            "every register entry matches a declared family with a planned owner".to_owned()
        } else {
            format!("unmatched: {}", unfamiliar.join("; "))
        },
    );
    forward.gaps.extend(unfamiliar);

    // Command-line options and output variables.
    let (cli_target, cli_decision) = ownership.target_of("cli-option").unwrap_or(("", ""));
    report.assert(
        !survey.cli_options.is_empty() && !cli_target.is_empty(),
        "cli-option/enumerated",
        format!("{} option(s)", survey.cli_options.len()),
    );
    let unidentified: Vec<&str> = survey
        .cli_options
        .iter()
        .filter(|option| option.identifier.is_empty())
        .map(|option| option.name.as_str())
        .collect();
    report.assert(
        unidentified.is_empty(),
        "cli-option/identified",
        if unidentified.is_empty() {
            "every option carries the identifier its table maps it to".to_owned()
        } else {
            format!("no identifier: {}", unidentified.join(", "))
        },
    );
    // A behavioural verdict per option, not a bare marker: the alias table and
    // the dispatch arms are separate lists and nothing upstream checks that they
    // agree, so an option can be accepted, have its argument consumed and then be
    // discarded with no diagnostic. Each undispatched option must be declared.
    let silent: BTreeMap<&str, &crate::contract::SilentOption> = ownership
        .silent_options
        .iter()
        .map(|entry| (entry.identifier.as_str(), entry))
        .collect();
    let mut undeclared = Vec::new();
    for option in &survey.cli_options {
        let (verdict, decision) = if option.dispatched {
            ("dispatched".to_owned(), cli_decision.to_owned())
        } else if option.deprecated {
            (
                "deprecated: warns and does nothing".to_owned(),
                cli_decision.to_owned(),
            )
        } else if let Some(entry) = silent.get(option.identifier.as_str()) {
            (entry.disposition.clone(), entry.decision.clone())
        } else {
            undeclared.push(format!("--{}", option.name));
            ("undeclared".to_owned(), cli_decision.to_owned())
        };
        forward.rows.push(Row {
            family: "cli-option",
            source: format!("--{}", option.name),
            detail: format!("{} · {}", option.identifier, option.descriptor),
            target: cli_target.to_owned(),
            disposition: verdict,
            decision,
        });
    }
    report.assert(
        undeclared.is_empty(),
        "cli-option/dispatch-accounted",
        if undeclared.is_empty() {
            format!(
                "{} dispatched, {} deprecated, {} declared without a dispatch arm",
                survey
                    .cli_options
                    .iter()
                    .filter(|option| option.dispatched)
                    .count(),
                survey
                    .cli_options
                    .iter()
                    .filter(|option| !option.dispatched && option.deprecated)
                    .count(),
                survey
                    .cli_options
                    .iter()
                    .filter(|option| {
                        !option.dispatched
                            && !option.deprecated
                            && silent.contains_key(option.identifier.as_str())
                    })
                    .count()
            )
        } else {
            format!(
                "no dispatch arm and no declaration: {}",
                undeclared.join(", ")
            )
        },
    );
    forward.gaps.extend(undeclared);

    let phantom: Vec<&str> = ownership
        .silent_options
        .iter()
        .filter(|entry| {
            !survey.cli_options.iter().any(|option| {
                option.identifier == entry.identifier && !option.dispatched && !option.deprecated
            })
        })
        .map(|entry| entry.identifier.as_str())
        .collect();
    report.assert(
        phantom.is_empty(),
        "cli-option/declarations-needed",
        if phantom.is_empty() {
            format!(
                "{} declaration(s), each answering an option with no dispatch arm",
                ownership.silent_options.len()
            )
        } else {
            format!(
                "declared and dispatched or deprecated: {}",
                phantom.join(", ")
            )
        },
    );

    let (var_target, var_decision) = ownership.target_of("writeout-variable").unwrap_or(("", ""));
    report.assert(
        !survey.writeout_variables.is_empty() && !var_target.is_empty(),
        "writeout-variable/enumerated",
        format!("{} variable(s)", survey.writeout_variables.len()),
    );
    for name in &survey.writeout_variables {
        forward.rows.push(Row {
            family: "writeout-variable",
            source: name.clone(),
            detail: "byte-frozen output surface".to_owned(),
            target: var_target.to_owned(),
            disposition: "owned".to_owned(),
            decision: var_decision.to_owned(),
        });
    }

    // Build flags: the compatibility front end accepts every one by name.
    let (flag_target, flag_decision) = ownership.target_of("build-flag").unwrap_or(("", ""));
    report.assert(
        !survey.build_flags.is_empty() && !flag_target.is_empty(),
        "build-flag/enumerated",
        format!("{} flag(s) and option(s)", survey.build_flags.len()),
    );
    for flag in &survey.build_flags {
        forward.rows.push(Row {
            family: "build-flag",
            source: flag.name.clone(),
            detail: flag.source.clone(),
            target: flag_target.to_owned(),
            disposition: "accepted-by-name".to_owned(),
            decision: flag_decision.to_owned(),
        });
    }

    // Internal-surface cases resolve through the internal headers they include.
    report.assert(
        !survey.cases.is_empty(),
        "internal-surface-case/enumerated",
        format!("{} case(s)", survey.cases.len()),
    );
    let mut unresolved_cases = Vec::new();
    for case in &survey.cases {
        let name = case.path.rsplit('/').next().unwrap_or(&case.path);
        let mut owners: BTreeSet<String> = BTreeSet::new();
        for include in &case.includes {
            let candidates = [
                format!("original/lib/{include}"),
                format!("original/src/{include}"),
            ];
            for candidate in candidates {
                if !siblings.contains(&candidate) {
                    continue;
                }
                if let Some(owner) = ownership.owner_of(&candidate, &siblings) {
                    owners.insert(owner);
                }
            }
        }
        if owners.is_empty()
            && let Some(owner) = ownership.cases.get(name)
        {
            owners.insert(owner.clone());
        }
        if owners.is_empty() {
            unresolved_cases.push(case.path.clone());
            continue;
        }
        forward.rows.push(Row {
            family: "internal-surface-case",
            source: case.path.clone(),
            detail: if case.includes.is_empty() {
                "declared owner; the case includes no internal header".to_owned()
            } else {
                case.includes.join(", ")
            },
            target: owners.into_iter().collect::<Vec<_>>().join(", "),
            disposition: "owned".to_owned(),
            decision: String::new(),
        });
    }
    report.assert(
        unresolved_cases.is_empty(),
        "internal-surface-case/resolved",
        if unresolved_cases.is_empty() {
            "every case resolves to at least one owner".to_owned()
        } else {
            format!("unresolved: {}", unresolved_cases.join(", "))
        },
    );
    forward.gaps.extend(unresolved_cases);

    // Generators, harness and configuration assets: the class that carries no
    // symbol, option or case number, so nothing else can enumerate it.
    resolve_harness(survey, ownership, planned, decisions, &mut forward, report);

    // Orphan declarations: declared, defined nowhere, called nowhere.
    report.assert(
        !ownership.orphans.is_empty(),
        "orphan/declared",
        format!("{} orphan declaration(s)", ownership.orphans.len()),
    );
    for orphan in &ownership.orphans {
        forward.rows.push(Row {
            family: "orphan-declaration",
            source: format!("{}:{}", orphan.path, orphan.line),
            detail: format!(
                "{} declared; file-local {} exists instead",
                orphan.symbol, orphan.local_definition
            ),
            target: "none".to_owned(),
            disposition: "orphan".to_owned(),
            decision: orphan.decision.clone(),
        });
    }

    // Orphan definitions: the inverse shape, taken from upstream's own single-use
    // whitelist rather than from a list of ours, and reachability measured rather
    // than assumed.
    let whitelist = single_use_whitelist(files);
    report.assert(
        !whitelist.is_empty(),
        "orphan-definition/whitelist-read",
        format!(
            "{} whitelisted symbol(s) from original/scripts/singleuse.pl",
            whitelist.len()
        ),
    );
    let declared: BTreeMap<&str, &crate::contract::OrphanDefinition> = ownership
        .orphan_definitions
        .iter()
        .map(|entry| (entry.symbol.as_str(), entry))
        .collect();
    let mut unaccounted = Vec::new();
    for symbol in &whitelist {
        let reach = reachability(files, symbol);
        match declared.get(symbol.as_str()) {
            Some(entry) => {
                forward.rows.push(Row {
                    family: "orphan-definition",
                    source: symbol.clone(),
                    detail: format!("reach: {reach}"),
                    target: "none".to_owned(),
                    disposition: entry.disposition.clone(),
                    decision: entry.decision.clone(),
                });
            }
            None => unaccounted.push(symbol.clone()),
        }
    }
    report.assert(
        unaccounted.is_empty(),
        "orphan-definition/whitelist-accounted",
        if unaccounted.is_empty() {
            format!(
                "{} whitelisted symbol(s), each carrying a disposition",
                whitelist.len()
            )
        } else {
            format!("no disposition: {}", unaccounted.join(", "))
        },
    );
    forward.gaps.extend(unaccounted);

    let stray: Vec<&str> = ownership
        .orphan_definitions
        .iter()
        .filter(|entry| !whitelist.contains(&entry.symbol))
        .map(|entry| entry.symbol.as_str())
        .collect();
    report.assert(
        stray.is_empty(),
        "orphan-definition/whitelist-sourced",
        if stray.is_empty() {
            "every disposition names a whitelisted symbol".to_owned()
        } else {
            format!("not in the upstream whitelist: {}", stray.join(", "))
        },
    );

    let misread: Vec<String> = ownership
        .orphan_definitions
        .iter()
        .filter(|entry| {
            whitelist.contains(&entry.symbol) && reachability(files, &entry.symbol) != entry.reach
        })
        .map(|entry| {
            format!(
                "{}: declared {}, measured {}",
                entry.symbol,
                entry.reach,
                reachability(files, &entry.symbol)
            )
        })
        .collect();
    report.assert(
        misread.is_empty(),
        "orphan-definition/reach-measured",
        if misread.is_empty() {
            format!(
                "{} unreachable, {} macro-reached, {} called",
                count_reach(files, &whitelist, "unreachable"),
                count_reach(files, &whitelist, "macro"),
                count_reach(files, &whitelist, "called")
            )
        } else {
            format!("reach disagrees: {}", misread.join("; "))
        },
    );

    report.assert(
        forward.gaps.is_empty(),
        "forward/no-gap",
        if forward.gaps.is_empty() {
            format!("{} row(s), every construct resolved", forward.rows.len())
        } else {
            format!("{} gap(s): {}", forward.gaps.len(), forward.gaps.join("; "))
        },
    );
    forward
        .rows
        .sort_by(|left, right| (left.family, &left.source).cmp(&(right.family, &right.source)));
    forward
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use curl_audit::fs::MapFiles;
    use curl_audit::report::Report;

    use super::{reachability, resolve, single_use_whitelist};
    use crate::contract::Ownership;
    use crate::oracle::Survey;

    const OWNERSHIP: &str = r#"
schema = 1
[[rule]]
prefix = "original/src/"
owner = "curl-cli"
decision = "DL-0026"
[unit]
"http.c" = "curl-http1"
"request.c" = "curl-core"
"sendf.c" = "curl-core"
[header]
"urldata.h" = "curl-core"
[[exclusion]]
path = "original/lib/amigaos.c"
disposition = "platform-outside-matrix"
reason = "outside the matrix"
decision = "DL-0043"
[[orphan]]
path = "original/lib/request.h"
line = 1
symbol = "Curl_req_set_upload_done"
local-definition = "original/lib/request.c:268"
decision = "DL-0112"
[[orphan-definition]]
symbol = "Curl_reached"
reach = "called"
disposition = "ported and called the same way"
decision = "DL-0112"
[[orphan-definition]]
symbol = "Curl_lonely"
reach = "unreachable"
disposition = "not ported: nothing can enter it"
decision = "DL-0112"
[[family]]
prefix = "CURLOPT_"
owner = "curl-core"
kind = "option"
[target]
public-header = "curl-abi"
exported-symbol = "curl-abi"
cli-option = "curl-cli"
writeout-variable = "curl-cli"
build-flag = "refactor/shim"
[decision]
public-header = "DL-0111"
exported-symbol = "DL-0007"
cli-option = "DL-0026"
writeout-variable = "DL-0026"
build-flag = "DL-0016"
[[harness]]
path = "original/src/mkhelp.pl"
role = "help-text generator"
disposition = "replaced"
target = "curl-cli"
decision = "DL-0026"
[[harness]]
path = "original/src/Makefile.am"
role = "build manifest"
disposition = "build-input"
target = "refactor/shim"
decision = "DL-0016"
[[harness]]
path = "original/src/.gitignore"
role = "repository metadata"
disposition = "no-counterpart"
target = "none"
decision = "DL-0026"
[[harness]]
path = "original/lib/libcurl.def"
role = "export list"
disposition = "build-input"
target = "refactor/shim"
decision = "DL-0016"
[[reverse]]
path = "Cargo.toml"
project-owned = true
decision = "DL-0026"
"#;

    fn oracle() -> MapFiles {
        MapFiles::new()
            .with("original/lib/http.c", "")
            .with("original/lib/amigaos.c", "")
            .with("original/lib/urldata.h", "")
            .with("original/lib/request.c", "")
            .with("original/lib/request.h", "x")
            .with(
                "original/lib/libcurl.def",
                "EXPORTS\ncurl_easy_setopt\n",
            )
            .with(
                "original/include/curl/easy.h",
                "CURL_EXTERN CURLcode curl_easy_setopt(CURL *h, CURLoption o, ...);\n",
            )
            .with(
                "original/docs/libcurl/symbols-in-versions",
                "CURLOPT_URL   7.1\n",
            )
            .with(
                "original/src/tool_getparam.c",
                "static const struct LongShort aliases[]= {\n  {\"alpn\", ARG_BOOL, ' ', C_ALPN},\n};\n  case C_ALPN:\n",
            )
            .with(
                "original/src/tool_writeout.c",
                "static const struct writeoutvar variables[] = {\n  { \"certs\", VAR_CERT, CURLINFO_NONE, writeString },\n};\n",
            )
            .with("original/configure.ac", "AC_ARG_WITH(openssl,\n")
            .with(
                "original/tests/unit/unit1300.c",
                "#include \"unitcheck.h\"\n#include \"urldata.h\"\n",
            )
            .with(
                "original/scripts/singleuse.pl",
                "my %wl = (\n    'Curl_reached' => 'internal api',\n    'Curl_lonely' => 'internal api',\n);\n",
            )
            .with(
                "original/lib/sendf.c",
                "void Curl_reached(int a)\n{\n}\nvoid Curl_lonely(int a)\n{\n}\nvoid caller(void)\n{\n  Curl_reached(1);\n}\n",
            )
            .with("original/lib/sendf.h", "void Curl_reached(int a);\nvoid Curl_lonely(int a);\n")
            .with("original/src/Makefile.am", "EXTRA_DIST = mkhelp.pl\n")
            .with("original/src/mkhelp.pl", "")
            .with("original/src/.gitignore", "")
    }

    fn ownership(text: &str, key: &str) -> Ownership {
        let files = MapFiles::new().with("data/ownership.toml", text);
        let _ = key;
        Ownership::load(&files, "data/ownership.toml").expect("fixture loads")
    }

    fn planned() -> BTreeSet<String> {
        [
            "curl-http1",
            "curl-core",
            "curl-abi",
            "curl-cli",
            "curl-types",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    fn decisions() -> BTreeSet<String> {
        [
            "DL-0007", "DL-0016", "DL-0026", "DL-0043", "DL-0111", "DL-0112",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    #[test]
    fn a_complete_map_resolves_every_construct() {
        let files = oracle();
        let survey = Survey::collect(&files);
        let owned = ownership(OWNERSHIP, "complete");
        let mut report = Report::new("test");
        let forward = resolve(
            &files,
            &survey,
            &owned,
            &planned(),
            &decisions(),
            &mut report,
        );
        let rendered = report.render();
        assert!(rendered.contains("PASS forward/no-gap"), "{rendered}");
        assert!(rendered.contains("PASS exported-symbol/declared"));
        assert!(rendered.contains("PASS exclusions-justified"));
        assert!(forward.gaps.is_empty());
        assert_eq!(forward.excluded().len(), 1);
        assert_eq!(forward.family("exported-symbol").len(), 1);
        assert_eq!(forward.family("exported-symbol")[0].disposition, "c-thunk");
        assert_eq!(forward.family("internal-surface-case").len(), 1);
        assert_eq!(forward.family("orphan-declaration").len(), 1);
        assert!(
            rendered.contains("PASS harness-asset/declared"),
            "{rendered}"
        );
        assert!(rendered.contains("PASS harness-asset/declarations-enumerated"));
        assert_eq!(forward.family("harness-asset").len(), 4);
        let asset = forward.family("harness-asset")[3];
        assert_eq!(asset.source, "original/src/mkhelp.pl");
        assert_eq!(asset.disposition, "replaced");
        assert_eq!(
            asset.detail,
            "help-text generator; registered `original/src/Makefile.am:1`"
        );
    }

    #[test]
    fn an_undeclared_asset_is_a_gap_and_a_stale_declaration_fails() {
        let files = oracle().with("original/tests/runtests.pl", "");
        let survey = Survey::collect(&files);
        let owned = ownership(OWNERSHIP, "asset");
        let mut report = Report::new("test");
        let forward = resolve(
            &files,
            &survey,
            &owned,
            &planned(),
            &decisions(),
            &mut report,
        );
        let rendered = report.render();
        assert!(
            rendered.contains("FAIL harness-asset/declared"),
            "{rendered}"
        );
        assert!(rendered.contains("runtests.pl"));
        assert!(
            forward
                .gaps
                .iter()
                .any(|gap| gap.contains("original/tests/runtests.pl"))
        );

        // The other direction: a declaration naming nothing enumerated.
        let text = OWNERSHIP.replace("original/src/mkhelp.pl", "original/src/gone.pl");
        let owned = ownership(&text, "stale-asset");
        let mut report = Report::new("test");
        let forward = resolve(
            &oracle(),
            &Survey::collect(&oracle()),
            &owned,
            &planned(),
            &decisions(),
            &mut report,
        );
        let rendered = report.render();
        assert!(
            rendered.contains("FAIL harness-asset/declarations-enumerated"),
            "{rendered}"
        );
        assert!(forward.gaps.iter().any(|gap| gap.contains("gone.pl")));
    }

    #[test]
    fn a_declaration_outside_the_disposition_vocabulary_fails() {
        let text = OWNERSHIP.replace("disposition = \"replaced\"", "disposition = \"invented\"");
        let files = oracle();
        let survey = Survey::collect(&files);
        let owned = ownership(&text, "vocabulary");
        let mut report = Report::new("test");
        let _ = resolve(
            &files,
            &survey,
            &owned,
            &planned(),
            &decisions(),
            &mut report,
        );
        let rendered = report.render();
        assert!(
            rendered.contains("FAIL harness-asset/declarations-accountable"),
            "{rendered}"
        );

        // An unknown target is the same defect seen from the other field.
        let text = OWNERSHIP.replace("target = \"curl-cli\"", "target = \"curl-nowhere\"");
        let owned = ownership(&text, "target");
        let mut report = Report::new("test");
        let _ = resolve(
            &files,
            &survey,
            &owned,
            &planned(),
            &decisions(),
            &mut report,
        );
        assert!(
            report
                .render()
                .contains("FAIL harness-asset/declarations-accountable")
        );
    }

    #[test]
    fn an_unowned_unit_is_a_gap() {
        let files = oracle().with("original/lib/newthing.c", "");
        let survey = Survey::collect(&files);
        let owned = ownership(OWNERSHIP, "gap");
        let mut report = Report::new("test");
        let forward = resolve(
            &files,
            &survey,
            &owned,
            &planned(),
            &decisions(),
            &mut report,
        );
        assert!(!forward.gaps.is_empty());
        let rendered = report.render();
        assert!(rendered.contains("FAIL forward/no-gap"));
        assert!(rendered.contains("newthing.c"));
    }

    #[test]
    fn an_unplanned_owner_fails() {
        let text = OWNERSHIP.replace("\"curl-http1\"", "\"curl-nowhere\"");
        let files = oracle();
        let survey = Survey::collect(&files);
        let owned = ownership(&text, "unplanned");
        let mut report = Report::new("test");
        let _ = resolve(
            &files,
            &survey,
            &owned,
            &planned(),
            &decisions(),
            &mut report,
        );
        let rendered = report.render();
        assert!(rendered.contains("FAIL owners-planned"), "{rendered}");
    }

    #[test]
    fn a_declared_entry_naming_nothing_is_stale() {
        let text = OWNERSHIP.replace(
            "[unit]\n\"http.c\" = \"curl-http1\"",
            "[unit]\n\"http.c\" = \"curl-http1\"\n\"gone.c\" = \"curl-types\"",
        );
        let files = oracle();
        let survey = Survey::collect(&files);
        let owned = ownership(&text, "stale");
        let mut report = Report::new("test");
        let _ = resolve(
            &files,
            &survey,
            &owned,
            &planned(),
            &decisions(),
            &mut report,
        );
        let rendered = report.render();
        assert!(
            rendered.contains("FAIL declared-entries-exist"),
            "{rendered}"
        );
        assert!(rendered.contains("gone.c"));
    }

    #[test]
    fn an_empty_oracle_fails_every_enumeration() {
        let files = MapFiles::new();
        let survey = Survey::collect(&files);
        let owned = ownership(OWNERSHIP, "empty");
        let mut report = Report::new("test");
        let _ = resolve(
            &files,
            &survey,
            &owned,
            &planned(),
            &decisions(),
            &mut report,
        );
        let rendered = report.render();
        assert!(rendered.contains("FAIL translation-unit/enumerated"));
        assert!(rendered.contains("FAIL symbol-register/enumerated"));
        assert!(rendered.contains("FAIL cli-option/enumerated"));
        assert!(rendered.contains("FAIL exported-symbol/variadic-derived"));
    }

    #[test]
    fn an_explicit_entry_beside_an_exclusion_is_a_contradiction() {
        let text = OWNERSHIP.replace(
            "[unit]\n\"http.c\" = \"curl-http1\"",
            "[unit]\n\"http.c\" = \"curl-http1\"\n\"amigaos.c\" = \"curl-core\"",
        );
        let files = oracle();
        let survey = Survey::collect(&files);
        let owned = ownership(&text, "contradiction");
        let mut report = Report::new("test");
        let forward = resolve(
            &files,
            &survey,
            &owned,
            &planned(),
            &decisions(),
            &mut report,
        );
        assert!(forward.excluded().is_empty());
        let rendered = report.render();
        assert!(rendered.contains("FAIL forward/no-gap"), "{rendered}");
        assert!(rendered.contains("explicitly owned and excluded"));
    }

    #[test]
    fn an_unresolving_exclusion_pointer_fails() {
        let text = OWNERSHIP.replace("decision = \"DL-0043\"", "decision = \"DL-9999\"");
        let files = oracle();
        let survey = Survey::collect(&files);
        let owned = ownership(&text, "pointer");
        let mut report = Report::new("test");
        let _ = resolve(
            &files,
            &survey,
            &owned,
            &planned(),
            &decisions(),
            &mut report,
        );
        assert!(report.render().contains("FAIL exclusions-justified"));
    }

    #[test]
    fn the_whitelist_is_read_from_upstreams_own_script() {
        let found = single_use_whitelist(&oracle());
        assert_eq!(found.len(), 2);
        assert!(found.contains("Curl_reached"));
        assert!(found.contains("Curl_lonely"));
        assert!(single_use_whitelist(&MapFiles::new()).is_empty());
    }

    #[test]
    fn reach_is_measured_rather_than_declared() {
        let files = oracle();
        assert_eq!(reachability(&files, "Curl_reached"), "called");
        assert_eq!(reachability(&files, "Curl_lonely"), "unreachable");
        let with_macro = files.clone().with(
            "original/lib/curl_trc.h",
            "#define CURL_TRC_LONELY Curl_lonely\n",
        );
        assert_eq!(reachability(&with_macro, "Curl_lonely"), "macro");
    }

    #[test]
    fn a_whitelisted_symbol_with_no_disposition_is_a_gap() {
        let text = OWNERSHIP.replace(
            "[[orphan-definition]]\nsymbol = \"Curl_lonely\"\nreach = \"unreachable\"\ndisposition = \"not ported: nothing can enter it\"\ndecision = \"DL-0112\"\n",
            "",
        );
        let files = oracle();
        let survey = Survey::collect(&files);
        let owned = ownership(&text, "no disposition");
        let mut report = Report::new("test");
        let forward = resolve(
            &files,
            &survey,
            &owned,
            &planned(),
            &decisions(),
            &mut report,
        );
        let rendered = report.render();
        assert!(
            rendered.contains("FAIL orphan-definition/whitelist-accounted"),
            "{rendered}"
        );
        assert!(forward.gaps.iter().any(|gap| gap == "Curl_lonely"));
    }

    #[test]
    fn a_disposition_outside_the_whitelist_fails() {
        let text = OWNERSHIP.replace("symbol = \"Curl_reached\"", "symbol = \"Curl_invented\"");
        let files = oracle();
        let survey = Survey::collect(&files);
        let owned = ownership(&text, "stray");
        let mut report = Report::new("test");
        let _ = resolve(
            &files,
            &survey,
            &owned,
            &planned(),
            &decisions(),
            &mut report,
        );
        assert!(
            report
                .render()
                .contains("FAIL orphan-definition/whitelist-sourced")
        );
    }

    #[test]
    fn a_declared_reach_that_disagrees_with_the_tree_fails() {
        let text = OWNERSHIP.replace(
            "symbol = \"Curl_lonely\"\nreach = \"unreachable\"",
            "symbol = \"Curl_lonely\"\nreach = \"called\"",
        );
        let files = oracle();
        let survey = Survey::collect(&files);
        let owned = ownership(&text, "wrong reach");
        let mut report = Report::new("test");
        let _ = resolve(
            &files,
            &survey,
            &owned,
            &planned(),
            &decisions(),
            &mut report,
        );
        assert!(
            report
                .render()
                .contains("FAIL orphan-definition/reach-measured")
        );
    }

    #[test]
    fn an_option_with_no_dispatch_arm_needs_a_declaration() {
        let files = oracle().with(
            "original/src/tool_getparam.c",
            "static const struct LongShort aliases[]= {\n  {\"alpn\", ARG_BOOL, ' ', C_ALPN},\n  {\"ghost\", ARG_STRG, ' ', C_GHOST},\n};\n  case C_ALPN:\n",
        );
        let survey = Survey::collect(&files);
        let owned = ownership(OWNERSHIP, "silent");
        let mut report = Report::new("test");
        let forward = resolve(
            &files,
            &survey,
            &owned,
            &planned(),
            &decisions(),
            &mut report,
        );
        let rendered = report.render();
        assert!(
            rendered.contains("FAIL cli-option/dispatch-accounted"),
            "{rendered}"
        );
        assert!(forward.gaps.iter().any(|gap| gap == "--ghost"));
    }

    #[test]
    fn a_declared_silent_option_that_is_dispatched_fails() {
        let text = format!(
            "{OWNERSHIP}\n[[silent-option]]\nidentifier = \"C_ALPN\"\noutcome = \"nothing\"\ndisposition = \"reproduce\"\ndecision = \"DL-0026\"\n"
        );
        let files = oracle();
        let survey = Survey::collect(&files);
        let owned = ownership(&text, "phantom");
        let mut report = Report::new("test");
        let _ = resolve(
            &files,
            &survey,
            &owned,
            &planned(),
            &decisions(),
            &mut report,
        );
        assert!(
            report
                .render()
                .contains("FAIL cli-option/declarations-needed")
        );
    }

    #[test]
    fn a_deprecated_option_carries_its_own_verdict() {
        let files = oracle().with(
            "original/src/tool_getparam.c",
            "static const struct LongShort aliases[]= {\n  {\"alpn\", ARG_BOOL, ' ', C_ALPN},\n  {\"sslv2\", ARG_NONE|ARG_DEPR, '2', C_SSLV2},\n};\n  case C_ALPN:\n",
        );
        let survey = Survey::collect(&files);
        let owned = ownership(OWNERSHIP, "deprecated");
        let mut report = Report::new("test");
        let forward = resolve(
            &files,
            &survey,
            &owned,
            &planned(),
            &decisions(),
            &mut report,
        );
        assert!(
            report
                .render()
                .contains("PASS cli-option/dispatch-accounted")
        );
        let row = forward
            .family("cli-option")
            .into_iter()
            .find(|row| row.source == "--sslv2")
            .expect("row");
        assert_eq!(row.disposition, "deprecated: warns and does nothing");
    }

    #[test]
    fn a_wrapped_alias_row_still_yields_its_identifier() {
        let files = oracle().with(
            "original/src/tool_getparam.c",
            "static const struct LongShort aliases[]= {\n  {\"alpn\", ARG_BOOL, ' ', C_ALPN},\n  {\"proxy-cert\", ARG_FILE|ARG_TLS|ARG_CLEAR, ' ',\n   C_PROXY_CERT},\n};\n  case C_ALPN:\n  case C_PROXY_CERT:\n",
        );
        let survey = Survey::collect(&files);
        let wrapped = survey
            .cli_options
            .iter()
            .find(|option| option.name == "proxy-cert")
            .expect("option");
        assert_eq!(wrapped.identifier, "C_PROXY_CERT");
        assert!(wrapped.dispatched);
        assert!(!wrapped.deprecated);
    }
}
