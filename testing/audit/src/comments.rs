// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: the blitzy-curl project contributors

//! Comment discipline in project-authored configuration files.
//!
//! A comment in one of the declared files may be a licence or copyright line, a
//! divider, a machine-read `KEY: value` marker, a `DL-####` or `[Rn]` pointer,
//! or a short label. Anything longer or more explanatory is rationale, which
//! belongs in `refactor/docs/DECISION-LOG.md` and nowhere else. `DL-0023` and
//! `DL-0032` record the decisions this check enforces.

use std::collections::BTreeSet;

use toml::Value;

use crate::fs::Files;
use crate::report::Report;
use crate::workspace::{AuditError, AuditResult, MANIFEST, Workspace};

/// What a single comment is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// A licence identifier or copyright line.
    Licence,
    /// A rule of dashes, equals signs or hashes.
    Divider,
    /// A `KEY: value` line a tool reads.
    Marker,
    /// Nothing but `DL-####` and `[Rn]` tags.
    Pointer,
    /// A short mechanical label.
    Label,
    /// Explanatory prose: a violation.
    Prose,
}

/// The comment-discipline contract, read from
/// `[workspace.metadata.curl.comment-discipline]`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Discipline {
    /// Path of the decision log every pointer must resolve in.
    pub decision_log: String,
    /// Files this check covers.
    pub files: Vec<String>,
    /// Most words a label may have.
    pub max_label_words: usize,
    /// Most characters a label may have, whitespace collapsed.
    pub max_label_chars: usize,
    /// Most consecutive label lines a comment block may have.
    pub max_block_lines: usize,
    /// Keys a `KEY: value` marker may use.
    pub marker_keys: Vec<String>,
    /// Phrases whose presence makes a comment rationale.
    pub banned_phrases: Vec<String>,
}

impl Discipline {
    /// Reads the contract out of the root manifest.
    pub fn from_workspace(workspace: &Workspace) -> AuditResult<Self> {
        let path = ["workspace", "metadata", "curl", "comment-discipline"];
        let table = workspace.table(&path)?;
        let count = |key: &str| -> AuditResult<usize> {
            let value = table
                .get(key)
                .and_then(Value::as_integer)
                .ok_or_else(|| AuditError::new(format!("comment-discipline.{key} missing")))?;
            usize::try_from(value)
                .map_err(|_| AuditError::new(format!("comment-discipline.{key} is not a count")))
        };
        let mut keyed = path.to_vec();
        keyed.push("files");
        let files = workspace.string_array(&keyed)?;
        let mut keyed = path.to_vec();
        keyed.push("marker-keys");
        let marker_keys = workspace.string_array(&keyed)?;
        let mut keyed = path.to_vec();
        keyed.push("banned-phrases");
        let banned_phrases = workspace.string_array(&keyed)?;
        let decision_log = table
            .get("decision-log")
            .and_then(Value::as_str)
            .ok_or_else(|| AuditError::new("comment-discipline.decision-log missing"))?
            .to_owned();
        if files.is_empty() || banned_phrases.is_empty() {
            return Err(AuditError::new(
                "comment-discipline covers no file or bans no phrase",
            ));
        }
        Ok(Self {
            decision_log,
            files,
            max_label_words: count("max-label-words")?,
            max_label_chars: count("max-label-chars")?,
            max_block_lines: count("max-block-lines")?,
            marker_keys,
            banned_phrases,
        })
    }
}

/// One comment that breaks the contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Violation {
    /// File the comment is in.
    pub file: String,
    /// One-based line number.
    pub line: usize,
    /// Why the comment is a violation.
    pub reason: String,
    /// The comment text, whitespace collapsed.
    pub text: String,
}

/// Collapses whitespace runs into single spaces and trims the ends.
#[must_use]
pub fn collapse(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The `DL-####` and `[Rn]` tags a text carries.
#[must_use]
pub fn tags(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let bytes: Vec<char> = text.chars().collect();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == 'D' && text[byte_offset(text, index)..].starts_with("DL-") {
            let digits: String = bytes
                .iter()
                .skip(index + 3)
                .take(4)
                .filter(|character| character.is_ascii_digit())
                .collect();
            if digits.len() == 4 {
                found.push(format!("DL-{digits}"));
                index += 7;
                continue;
            }
        }
        if bytes[index] == '[' {
            let rest = &text[byte_offset(text, index)..];
            if let Some(end) = rest.find(']') {
                let inner = &rest[1..end];
                if inner.len() >= 2
                    && inner.starts_with('R')
                    && inner[1..]
                        .chars()
                        .all(|character| character.is_ascii_digit())
                {
                    found.push(format!("[{inner}]"));
                    index += inner.chars().count() + 2;
                    continue;
                }
            }
        }
        index += 1;
    }
    found
}

/// Byte offset of the character at `index`.
fn byte_offset(text: &str, index: usize) -> usize {
    text.char_indices()
        .nth(index)
        .map_or(text.len(), |(offset, _)| offset)
}

/// Words that end a phrase only when it continues on another line.
const CONTINUATIONS: [&str; 16] = [
    "and", "or", "but", "the", "a", "an", "of", "to", "for", "with", "that", "which", "is", "are",
    "its", "their",
];

/// Classifies one comment's text.
#[must_use]
pub fn classify(text: &str, discipline: &Discipline) -> Kind {
    let collapsed = collapse(text);
    if collapsed.is_empty() {
        return Kind::Divider;
    }
    if collapsed.starts_with("SPDX-") || collapsed.contains("Copyright (C)") {
        return Kind::Licence;
    }
    if collapsed
        .chars()
        .all(|character| matches!(character, '-' | '=' | '#' | ' ' | '.'))
    {
        return Kind::Divider;
    }
    if let Some((key, _)) = collapsed.split_once(": ")
        && discipline.marker_keys.iter().any(|allowed| allowed == key)
    {
        return Kind::Marker;
    }

    let found = tags(&collapsed);
    let mut residue = collapsed.clone();
    for tag in &found {
        residue = residue.replace(tag, " ");
    }
    let residue = collapse(&residue);
    if !found.is_empty() && (residue.is_empty() || residue.chars().all(|c| c == ';' || c == ',')) {
        return Kind::Pointer;
    }

    let lowered = collapsed.to_lowercase();
    if discipline
        .banned_phrases
        .iter()
        .any(|phrase| lowered.contains(&phrase.to_lowercase()))
    {
        return Kind::Prose;
    }
    let words: Vec<&str> = residue.split_whitespace().collect();
    if words.len() > discipline.max_label_words
        || residue.chars().count() > discipline.max_label_chars
    {
        return Kind::Prose;
    }
    if residue.ends_with(',') {
        return Kind::Prose;
    }
    if let Some(last) = words.last() {
        let trimmed = last.trim_end_matches([',', ';', ':']).to_lowercase();
        if CONTINUATIONS.contains(&trimmed.as_str()) {
            return Kind::Prose;
        }
    }
    Kind::Label
}

/// One comment found in a file.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Comment {
    line: usize,
    text: String,
    own_line: bool,
}

/// Extracts the comments of a `#`-commented configuration file.
///
/// A `#` inside a quoted string is not a comment, so quoting is tracked; both
/// whole-line comments and trailing comments are returned.
fn comments_of(contents: &str) -> Vec<Comment> {
    let mut found = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let trimmed = line.trim_start();
        if let Some(text) = trimmed.strip_prefix('#') {
            found.push(Comment {
                line: index + 1,
                text: text.to_owned(),
                own_line: true,
            });
            continue;
        }
        let mut quote: Option<char> = None;
        let mut escaped = false;
        for (offset, character) in line.char_indices() {
            match quote {
                Some(active) => {
                    if escaped {
                        escaped = false;
                    } else if character == '\\' && active == '"' {
                        escaped = true;
                    } else if character == active {
                        quote = None;
                    }
                }
                None => match character {
                    '"' | '\'' => quote = Some(character),
                    '#' => {
                        found.push(Comment {
                            line: index + 1,
                            text: line[offset + 1..].to_owned(),
                            own_line: false,
                        });
                        break;
                    }
                    _ => {}
                },
            }
        }
    }
    found
}

/// Scans one file's contents and returns every violation.
#[must_use]
pub fn scan(file: &str, contents: &str, discipline: &Discipline) -> Vec<Violation> {
    let mut violations = Vec::new();
    let mut label_run = 0_usize;
    let mut previous_line = 0_usize;
    for comment in comments_of(contents) {
        let kind = classify(&comment.text, discipline);
        let collapsed = collapse(&comment.text);
        if !comment.own_line && !matches!(kind, Kind::Pointer | Kind::Licence | Kind::Marker) {
            violations.push(Violation {
                file: file.to_owned(),
                line: comment.line,
                reason: "trailing comment must be a DL-#### or [Rn] pointer".to_owned(),
                text: collapsed.clone(),
            });
            continue;
        }
        match kind {
            Kind::Prose => {
                violations.push(Violation {
                    file: file.to_owned(),
                    line: comment.line,
                    reason: "rationale belongs in the decision log".to_owned(),
                    text: collapsed,
                });
                label_run = 0;
            }
            Kind::Label => {
                if comment.line == previous_line + 1 {
                    label_run += 1;
                } else {
                    label_run = 1;
                }
                if label_run > discipline.max_block_lines {
                    violations.push(Violation {
                        file: file.to_owned(),
                        line: comment.line,
                        reason: format!(
                            "comment block longer than {} label line(s)",
                            discipline.max_block_lines
                        ),
                        text: collapsed,
                    });
                }
            }
            Kind::Licence | Kind::Divider | Kind::Marker | Kind::Pointer => label_run = 0,
        }
        previous_line = comment.line;
    }
    violations
}

/// The row identifiers a decision log defines.
#[must_use]
pub fn decision_ids(decision_log: &str) -> BTreeSet<String> {
    decision_log
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            let rest = trimmed.strip_prefix("| ")?;
            let id: String = rest.chars().take(7).collect();
            (id.starts_with("DL-") && id[3..].chars().all(|c| c.is_ascii_digit())).then_some(id)
        })
        .collect()
}

/// Every `DL-####` identifier a text references.
#[must_use]
pub fn referenced_ids(contents: &str) -> BTreeSet<String> {
    tags(contents)
        .into_iter()
        .filter(|tag| tag.starts_with("DL-"))
        .collect()
}

/// Runs the comment-discipline audit against a checkout.
pub fn audit(workspace: &Workspace, files: &dyn Files) -> AuditResult<Report> {
    let discipline = Discipline::from_workspace(workspace)?;
    let mut report = Report::new("comment-discipline");

    let log = files
        .read(&discipline.decision_log)
        .ok_or_else(|| AuditError::new(format!("{} is missing", discipline.decision_log)))?;
    let defined = decision_ids(&log);
    report.assert(
        !defined.is_empty(),
        "decision-log-has-rows",
        format!("{} decision row(s)", defined.len()),
    );

    let mut scanned = 0_usize;
    for file in &discipline.files {
        let Some(contents) = files.read(file) else {
            report.fail(
                format!("declared-file/{file}"),
                "declared but missing".to_owned(),
            );
            continue;
        };
        scanned += 1;
        let violations = scan(file, &contents, &discipline);
        report.assert(
            violations.is_empty(),
            format!("comments/{file}"),
            if violations.is_empty() {
                "every comment is a licence line, divider, marker, pointer or label".to_owned()
            } else {
                violations
                    .iter()
                    .map(|violation| {
                        format!(
                            "{}:{}: {} - \"{}\"",
                            violation.file, violation.line, violation.reason, violation.text
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("; ")
            },
        );
        let dangling: Vec<String> = referenced_ids(&contents)
            .into_iter()
            .filter(|id| !defined.contains(id))
            .collect();
        report.assert(
            dangling.is_empty(),
            format!("pointers/{file}"),
            if dangling.is_empty() {
                "every DL-#### pointer resolves".to_owned()
            } else {
                format!("dangling: {}", dangling.join(", "))
            },
        );
    }
    report.assert(
        scanned == discipline.files.len() && scanned > 0,
        "declared-files-read",
        format!(
            "{scanned} of {} declared file(s) read",
            discipline.files.len()
        ),
    );

    let declared: BTreeSet<&String> = discipline.files.iter().collect();
    let mut candidates: Vec<String> = files
        .list("")
        .into_iter()
        .filter(|name| name.ends_with(".toml") || name == ".gitignore")
        .collect();
    for member in workspace.members()? {
        candidates.push(format!("{member}/{MANIFEST}"));
    }
    let uncovered: Vec<String> = candidates
        .into_iter()
        .filter(|candidate| !declared.contains(candidate) && candidate != "Cargo.lock")
        .collect();
    report.assert(
        uncovered.is_empty(),
        "declared-files-complete",
        if uncovered.is_empty() {
            "every project-authored configuration file is declared".to_owned()
        } else {
            format!("undeclared: {}", uncovered.join(", "))
        },
    );
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::{
        Discipline, Kind, audit, classify, collapse, decision_ids, referenced_ids, scan, tags,
    };
    use crate::fs::MapFiles;
    use crate::workspace::Workspace;

    const ROOT_MANIFEST: &str = r#"
[workspace]
members = ["testing/audit"]

[workspace.metadata.curl.comment-discipline]
decision-log = "refactor/docs/DECISION-LOG.md"
files = ["Cargo.toml", "testing/audit/Cargo.toml"]
max-label-words = 10
max-label-chars = 76
max-block-lines = 2
marker-keys = ["MIRI-TOOLCHAIN"]
banned-phrases = ["because", "rather than"]
"#;

    fn workspace(manifest: &str, key: &str) -> Workspace {
        // One fixture directory per test: these run in parallel, and a shared
        // path would let one test read another's half-written manifest.
        let directory = std::env::temp_dir().join(format!("curl-audit-tests/comments-{key}"));
        std::fs::create_dir_all(&directory).expect("fixture directory");
        std::fs::write(directory.join("Cargo.toml"), manifest).expect("fixture manifest");
        Workspace::load(&directory).expect("fixture workspace")
    }

    fn discipline(key: &str) -> Discipline {
        Discipline::from_workspace(&workspace(ROOT_MANIFEST, key)).expect("fixture discipline")
    }

    #[test]
    fn collapse_normalises_whitespace() {
        assert_eq!(collapse("  a   b  "), "a b");
        assert_eq!(collapse("\t"), "");
    }

    #[test]
    fn tags_are_extracted() {
        assert_eq!(tags("see DL-0026 and [R12]"), vec!["DL-0026", "[R12]"]);
        assert!(tags("DL-12 [Rx] [R]").is_empty());
        assert_eq!(referenced_ids("DL-0001 DL-0001 [R1]").len(), 1);
    }

    #[test]
    fn classification_covers_every_kind() {
        let discipline = discipline("classify");
        assert_eq!(
            classify(" SPDX-License-Identifier: curl", &discipline),
            Kind::Licence
        );
        assert_eq!(
            classify(" Copyright (C) Daniel Stenberg", &discipline),
            Kind::Licence
        );
        assert_eq!(classify(" -------------", &discipline), Kind::Divider);
        assert_eq!(classify("", &discipline), Kind::Divider);
        assert_eq!(
            classify(" MIRI-TOOLCHAIN: nightly-2026-08-11", &discipline),
            Kind::Marker
        );
        assert_eq!(classify(" DL-0026", &discipline), Kind::Pointer);
        assert_eq!(classify(" DL-0026 [R1]", &discipline), Kind::Pointer);
        assert_eq!(
            classify(" Dependency pins. DL-0009", &discipline),
            Kind::Label
        );
        assert_eq!(
            classify(
                " Deny, not forbid, because an inner allow is an error.",
                &discipline
            ),
            Kind::Prose
        );
        assert_eq!(
            classify(" Pinned rather than floating.", &discipline),
            Kind::Prose
        );
        assert_eq!(
            classify(
                " A label that runs on well past the ten word ceiling this contract sets.",
                &discipline
            ),
            Kind::Prose
        );
        assert_eq!(
            classify(" Sole membership mechanism and", &discipline),
            Kind::Prose
        );
        assert_eq!(
            classify(" Members carry the lints,", &discipline),
            Kind::Prose
        );
        // An unlisted `KEY: value` line is judged as a label, so it is held to
        // the label ceilings that a listed marker key is exempt from.
        assert_eq!(
            classify(" NOT-A-MARKER: some value", &discipline),
            Kind::Label
        );
        assert_eq!(
            classify(
                " NOT-A-MARKER: a value long enough to run past the label ceiling here",
                &discipline
            ),
            Kind::Prose
        );
        assert_eq!(
            classify(
                " MIRI-TOOLCHAIN: a marker value is exempt from the label ceilings entirely",
                &discipline
            ),
            Kind::Marker
        );
    }

    #[test]
    fn scanning_reports_prose_and_long_blocks() {
        let discipline = discipline("scan");
        let clean =
            "# SPDX-License-Identifier: curl\n# Dependency pins. DL-0009\nkey = 1 # DL-0026\n";
        assert!(scan("Cargo.toml", clean, &discipline).is_empty());

        let prose = "# This exists because a competent engineer could differ.\n";
        let violations = scan("Cargo.toml", prose, &discipline);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].line, 1);
        assert!(violations[0].reason.contains("decision log"));

        let long_block =
            "# First label. DL-0001\n# Second label. DL-0002\n# Third label. DL-0003\n";
        let violations = scan("Cargo.toml", long_block, &discipline);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].line, 3);
        assert!(violations[0].reason.contains("longer than 2"));
    }

    #[test]
    fn trailing_comments_must_be_pointers() {
        let discipline = discipline("trailing");
        let violations = scan(
            "Cargo.toml",
            "key = 1 # keeps the graph small\n",
            &discipline,
        );
        assert_eq!(violations.len(), 1);
        assert!(violations[0].reason.contains("trailing comment"));
        assert!(scan("Cargo.toml", "key = 1 # DL-0009\n", &discipline).is_empty());
    }

    #[test]
    fn a_hash_inside_a_string_is_not_a_comment() {
        let discipline = discipline("string-hash");
        assert!(
            scan(
                "Cargo.toml",
                "value = \"a # b that is long enough to be prose if read as a comment\"\n",
                &discipline
            )
            .is_empty()
        );
    }

    #[test]
    fn decision_ids_are_read_from_table_rows() {
        let log = "| ID | Decision |\n|---|---|\n| DL-0001 | first |\n| DL-0030 | last |\n";
        let ids = decision_ids(log);
        assert_eq!(ids.len(), 2);
        assert!(ids.contains("DL-0001"));
        assert!(decision_ids("no rows here").is_empty());
    }

    #[test]
    fn the_audit_reports_dangling_pointers_and_undeclared_files() {
        let workspace = workspace(ROOT_MANIFEST, "audit-dangling");

        let files = MapFiles::new()
            .with("refactor/docs/DECISION-LOG.md", "| DL-0026 | row |\n")
            .with("Cargo.toml", "# Pins. DL-0026\n")
            .with("testing/audit/Cargo.toml", "# Audit crate. DL-0999\n")
            .with("rust-toolchain.toml", "# Toolchain pin. DL-0026\n");
        let report = audit(&workspace, &files).expect("audit runs");
        let rendered = report.render();
        assert!(rendered.contains("FAIL pointers/testing/audit/Cargo.toml"));
        assert!(rendered.contains("DL-0999"));
        assert!(rendered.contains("FAIL declared-files-complete"));
        assert!(rendered.contains("rust-toolchain.toml"));
    }

    #[test]
    fn the_audit_passes_a_clean_checkout() {
        let workspace = workspace(ROOT_MANIFEST, "audit-clean");
        let files = MapFiles::new()
            .with("refactor/docs/DECISION-LOG.md", "| DL-0026 | row |\n")
            .with("Cargo.toml", "# Pins. DL-0026\n")
            .with("testing/audit/Cargo.toml", "# Audit crate. DL-0026\n");
        let report = audit(&workspace, &files).expect("audit runs");
        assert!(report.passed(), "{}", report.render());
    }
}
