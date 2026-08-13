// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: the blitzy-curl project contributors

//! Frozen baseline identity: the record of what the oracle is, and whether the
//! tree on disk is still that.
//!
//! `BASELINE.toml` carries the upstream tag, the tag object, the commit it peels
//! to, the release archive digest, the import commit, and the frozen state of
//! the vendored worktree: one digest over the mode, the content and the path of
//! every regular file, plus the file and executable counts the digest covers.
//! This module recomputes that digest from the tree on every invocation and
//! compares it against the record. Nothing here reads a recorded figure and
//! reports it.
//!
//! Two failure modes drive the design. A wrong committed oracle passes any check
//! that compares the tree only against itself, so the comparison target is the
//! frozen record. And a write into the oracle after the import commit is a rule
//! violation whether or not the bytes it wrote were identical, so the digest
//! covers modes as well as content and the recorded write-target set is asserted
//! empty.
//!
//! `DL-0220` records the manifest, `DL-0221` the digest algorithm and `DL-0222`
//! the read-only verification method.

use std::collections::BTreeSet;

use sha2::{Digest as _, Sha256};
use toml::Value;

use crate::fs::{EXECUTABLE_MODE, Entry, Files};
use crate::report::Report;
use crate::workspace::{AuditError, AuditResult, Workspace};

/// File name of the frozen baseline manifest.
pub const MANIFEST: &str = "BASELINE.toml";

/// The only digest algorithm this module implements.
///
/// The recorded spelling is asserted rather than assumed, so a record naming an
/// algorithm no code runs fails instead of reading as verified.
pub const DIGEST_ALGORITHM: &str = "sha256-mode-content-path-lines";

/// The algorithm the recorded git-index digest names.
pub const INDEX_DIGEST_ALGORITHM: &str = "sha256-of-git-ls-files-s";

/// The verification method the project holds for the oracle.
pub const VERIFICATION_METHOD: &str = "read-only-compare-in-scratch";

/// The frozen record, as declared.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Baseline {
    /// Upstream tag name.
    pub tag: String,
    /// Annotated tag object identifier.
    pub tag_object: String,
    /// Commit the tag peels to.
    pub tag_commit: String,
    /// Release archive digest.
    pub archive_sha256: String,
    /// Commit that placed the oracle in this repository.
    pub import_commit: String,
    /// Repository-relative root of the vendored tree.
    pub root: String,
    /// Frozen content and mode digest of that tree.
    pub digest: String,
    /// Algorithm the digest was computed with.
    pub digest_algorithm: String,
    /// Algorithm the recorded index digest was computed with.
    pub index_digest_algorithm: String,
    /// Number of regular files the digest covers.
    pub files: usize,
    /// Number of those files carrying the executable bit.
    pub executable_files: usize,
    /// Number of symlinks the record permits.
    pub symlinks: usize,
    /// Verification method the project holds.
    pub method: String,
    /// Paths any project-authored script may write inside the oracle.
    pub write_targets: Vec<String>,
    /// Script that stages the oracle for a baseline build.
    pub bootstrap: String,
}

fn text(table: &toml::map::Map<String, Value>, path: &[&str], key: &str) -> AuditResult<String> {
    table
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| AuditError::new(format!("{MANIFEST}: {}.{key} missing", path.join("."))))
}

fn count(table: &toml::map::Map<String, Value>, path: &[&str], key: &str) -> AuditResult<usize> {
    let value = table
        .get(key)
        .and_then(Value::as_integer)
        .ok_or_else(|| AuditError::new(format!("{MANIFEST}: {}.{key} missing", path.join("."))))?;
    usize::try_from(value).map_err(|_| {
        AuditError::new(format!(
            "{MANIFEST}: {}.{key} is not a count",
            path.join(".")
        ))
    })
}

fn section<'a>(value: &'a Value, name: &str) -> AuditResult<&'a toml::map::Map<String, Value>> {
    value
        .get(name)
        .and_then(Value::as_table)
        .ok_or_else(|| AuditError::new(format!("{MANIFEST}: no [{name}] table")))
}

impl Baseline {
    /// Reads the frozen record out of `BASELINE.toml`.
    pub fn load(files: &dyn Files) -> AuditResult<Self> {
        let body = files
            .read(MANIFEST)
            .ok_or_else(|| AuditError::new(format!("{MANIFEST} is missing")))?;
        let value: Value = toml::from_str(&body)
            .map_err(|error| AuditError::new(format!("{MANIFEST}: {error}")))?;
        let tag = section(&value, "tag")?;
        let import = section(&value, "import")?;
        let worktree = section(&value, "worktree")?;
        let verification = section(&value, "verification")?;
        let write_targets = verification
            .get("write-targets")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                AuditError::new(format!("{MANIFEST}: verification.write-targets missing"))
            })?
            .iter()
            .map(|entry| {
                entry.as_str().map(str::to_owned).ok_or_else(|| {
                    AuditError::new(format!("{MANIFEST}: a write target is not a path"))
                })
            })
            .collect::<AuditResult<Vec<String>>>()?;
        Ok(Self {
            tag: text(tag, &["tag"], "name")?,
            tag_object: text(tag, &["tag"], "object")?,
            tag_commit: text(tag, &["tag"], "commit")?,
            archive_sha256: text(tag, &["tag"], "archive-sha256")?,
            import_commit: text(import, &["import"], "commit")?,
            root: text(import, &["import"], "root")?,
            digest: text(worktree, &["worktree"], "digest")?,
            digest_algorithm: text(worktree, &["worktree"], "digest-algorithm")?,
            index_digest_algorithm: text(worktree, &["worktree"], "index-digest-algorithm")?,
            files: count(worktree, &["worktree"], "files")?,
            executable_files: count(worktree, &["worktree"], "executable-files")?,
            symlinks: count(worktree, &["worktree"], "symlinks")?,
            method: text(verification, &["verification"], "method")?,
            write_targets,
            bootstrap: text(verification, &["verification"], "bootstrap")?,
        })
    }
}

/// Hexadecimal sha256 of `bytes`.
#[must_use]
pub fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// The one line an entry contributes to the tree digest.
///
/// Mode, content digest and path, in that order, one line each. The path is
/// last so a name can hold any byte a filesystem allows without shifting the
/// fields before it.
#[must_use]
pub fn digest_line(entry: &Entry) -> String {
    format!(
        "{} {} {}\n",
        entry.mode,
        hex_sha256(&entry.bytes),
        entry.path
    )
}

/// The digest of a tree, and the counts it covers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Measured {
    /// Hexadecimal digest over every entry's line, in path order.
    pub digest: String,
    /// Number of regular files hashed.
    pub files: usize,
    /// Number of those carrying the executable bit.
    pub executable_files: usize,
}

/// Recomputes the frozen digest of the tree rooted at `root`.
#[must_use]
pub fn measure(files: &dyn Files, root: &str) -> Measured {
    let entries = files.walk(root);
    let mut hasher = Sha256::new();
    let mut executable = 0_usize;
    for entry in &entries {
        if entry.mode == EXECUTABLE_MODE {
            executable += 1;
        }
        hasher.update(digest_line(entry).as_bytes());
    }
    Measured {
        digest: hex::encode(hasher.finalize()),
        files: entries.len(),
        executable_files: executable,
    }
}

/// Whether a hexadecimal identifier is a full-length object name.
fn is_object_id(value: &str) -> bool {
    value.len() == 40
        && value
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
}

/// Whether a hexadecimal identifier is a sha256 digest.
fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
}

/// Runs the baseline-identity audit against a checkout.
///
/// Every check compares the tree against the frozen record. The record itself is
/// checked for shape first, so a truncated identifier cannot pass as an identity.
pub fn audit(workspace: &Workspace, files: &dyn Files) -> AuditResult<Report> {
    let baseline = Baseline::load(files)?;
    let mut report = Report::new("baseline-identity");

    let declared = workspace
        .curl_value(&["baseline-manifest"])
        .and_then(Value::as_str)
        .unwrap_or_default();
    report.assert(
        declared == MANIFEST,
        "manifest-declared",
        if declared.is_empty() {
            "the root manifest names no baseline manifest".to_owned()
        } else {
            format!("the root manifest reads {declared}")
        },
    );

    let recorded_tag = workspace
        .curl_value(&["baseline-tag"])
        .and_then(Value::as_str)
        .unwrap_or_default();
    report.assert(
        !recorded_tag.is_empty() && recorded_tag == baseline.tag,
        "tag-agrees",
        format!(
            "{MANIFEST} {} against manifest {recorded_tag}",
            baseline.tag
        ),
    );

    let shaped: Vec<&str> = [
        ("tag.object", baseline.tag_object.as_str()),
        ("tag.commit", baseline.tag_commit.as_str()),
        ("import.commit", baseline.import_commit.as_str()),
    ]
    .into_iter()
    .filter(|(_, value)| !is_object_id(value))
    .map(|(name, _)| name)
    .collect();
    report.assert(
        shaped.is_empty(),
        "identities-well-formed",
        if shaped.is_empty() {
            "the tag object, its commit and the import commit are full object names".to_owned()
        } else {
            format!("not an object name: {}", shaped.join(", "))
        },
    );

    report.assert(
        is_sha256(&baseline.archive_sha256) && is_sha256(&baseline.digest),
        "digests-well-formed",
        "the archive digest and the tree digest are sha256 values".to_owned(),
    );

    report.assert(
        baseline.digest_algorithm == DIGEST_ALGORITHM
            && baseline.index_digest_algorithm == INDEX_DIGEST_ALGORITHM,
        "algorithms-implemented",
        format!(
            "{} over the tree, {} over the index",
            baseline.digest_algorithm, baseline.index_digest_algorithm
        ),
    );

    let measured = measure(files, &baseline.root);
    report.assert(
        measured.files > 0 && measured.files == baseline.files,
        "worktree-file-count",
        format!(
            "{} file(s) under {}, {} recorded",
            measured.files, baseline.root, baseline.files
        ),
    );
    report.assert(
        measured.executable_files == baseline.executable_files,
        "worktree-mode-count",
        format!(
            "{} executable file(s), {} recorded",
            measured.executable_files, baseline.executable_files
        ),
    );
    report.assert(
        measured.files > 0 && measured.digest == baseline.digest,
        "worktree-digest",
        if measured.digest == baseline.digest {
            format!("{} unchanged at {}", baseline.root, measured.digest)
        } else {
            format!(
                "{} measures {}, {MANIFEST} records {}",
                baseline.root, measured.digest, baseline.digest
            )
        },
    );

    report.assert(
        baseline.symlinks == 0,
        "no-symlink-permitted",
        format!("{} symlink(s) recorded", baseline.symlinks),
    );

    report.assert(
        baseline.method == VERIFICATION_METHOD && baseline.write_targets.is_empty(),
        "oracle-not-a-write-target",
        if baseline.write_targets.is_empty() {
            format!("verification is {}", baseline.method)
        } else {
            format!("write target(s): {}", baseline.write_targets.join(", "))
        },
    );

    let prefix = format!("{}/", baseline.root);
    match files.read(&baseline.bootstrap) {
        None => report.fail(
            "bootstrap-readable",
            format!("{} is missing", baseline.bootstrap),
        ),
        Some(script) => {
            report.pass("bootstrap-readable", format!("{} read", baseline.bootstrap));
            let writes = oracle_write_sites(&script, &prefix);
            report.assert(
                writes.is_empty(),
                "bootstrap-writes-no-oracle-path",
                if writes.is_empty() {
                    format!(
                        "no write command in {} targets {prefix}",
                        baseline.bootstrap
                    )
                } else {
                    format!("writes into the oracle: {}", writes.join("; "))
                },
            );
            report.assert(
                script.contains(MANIFEST),
                "bootstrap-reads-the-record",
                format!("{} reads {MANIFEST}", baseline.bootstrap),
            );
        }
    }

    Ok(report)
}

/// Commands whose last operand is the one they write.
const LAST_OPERAND_COMMANDS: [&str; 4] = ["cp", "mv", "install", "ln"];

/// Commands that write every operand they are given.
const EVERY_OPERAND_COMMANDS: [&str; 6] = ["rm", "rmdir", "mkdir", "tee", "chmod", "truncate"];

/// The operands one command segment would write to.
///
/// A copy writes its final operand and reads the rest; a removal, a mode change
/// and a `tee` write all of theirs; a redirection writes the word the arrow
/// points at. Reading only the operands a command writes is what lets the
/// bootstrap copy *out of* the oracle while a copy *into* it still fails.
#[must_use]
pub fn written_operands(segment: &str) -> Vec<String> {
    let mut written = Vec::new();
    let mut operands: Vec<&str> = Vec::new();
    let mut command: Option<&str> = None;
    let mut tokens = segment
        .split_whitespace()
        .map(|token| token.trim_matches(['(', ')', '{', '}']))
        .filter(|token| !token.is_empty())
        .peekable();
    while let Some(token) = tokens.next() {
        if let Some((_, target)) = token.rsplit_once('>') {
            let target = if target.is_empty() {
                tokens.next().unwrap_or_default()
            } else {
                target
            };
            written.push(unquote(target));
            continue;
        }
        if command.is_none() {
            command = Some(token);
            continue;
        }
        if token == "--" || token.starts_with('-') {
            continue;
        }
        operands.push(token);
    }
    let Some(command) = command else {
        return written;
    };
    if LAST_OPERAND_COMMANDS.contains(&command) {
        if let Some(last) = operands.last() {
            written.push(unquote(last));
        }
    } else if EVERY_OPERAND_COMMANDS.contains(&command) {
        written.extend(operands.iter().map(|operand| unquote(operand)));
    }
    written
}

/// Strips the quoting a shell word may carry.
fn unquote(word: &str) -> String {
    word.trim_matches(['"', '\'']).to_owned()
}

/// Lines of a script that would write a path inside the oracle.
///
/// The scan reads the code of each line, splits it into command segments, and
/// examines only the operands each segment writes. A comment is not code, so a
/// line that mentions the oracle in prose is not a write.
#[must_use]
pub fn oracle_write_sites(script: &str, prefix: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (index, line) in script.lines().enumerate() {
        let code = line.split_once('#').map_or(line, |(before, _)| before);
        let trimmed = code.trim();
        if trimmed.is_empty() {
            continue;
        }
        let writes_oracle = trimmed
            .split(['|', ';', '&'])
            .flat_map(written_operands)
            .any(|operand| operand.starts_with(prefix) || operand == prefix.trim_end_matches('/'));
        if writes_oracle {
            found.push(format!("line {}: {trimmed}", index + 1));
        }
    }
    found
}

/// Every path a text names inside the oracle, for a caller that needs the set.
#[must_use]
pub fn named_oracle_paths(text: &str, prefix: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut consumed = 0;
    while let Some(offset) = text[consumed..].find(prefix) {
        let start = consumed + offset;
        let run: String = text[start..]
            .chars()
            .take_while(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '/' | '-')
            })
            .collect();
        consumed = start + run.len().max(prefix.len());
        found.insert(run.trim_end_matches(['.', ',', ';', '/']).to_owned());
    }
    found
}

#[cfg(test)]
mod tests {
    use super::{
        Baseline, DIGEST_ALGORITHM, audit, digest_line, hex_sha256, measure, named_oracle_paths,
        oracle_write_sites, written_operands,
    };
    use crate::fs::{Entry, Files, MapFiles, PLAIN_MODE};
    use crate::workspace::Workspace;

    const BOOTSTRAP: &str = "#!/bin/sh\n# reads BASELINE.toml\nstaging=target/baseline\ncp -a -- \"$oracle/.\" \"$staging/\"\n";

    fn record(digest: &str, files: usize, executable: usize) -> String {
        format!(
            r#"
schema = 1

[tag]
name = "curl-8_21_0"
object = "3f00a2f6fa97f7721b65606954aac979dcb6caac"
commit = "68720b4837284335b2d63cb358f8f6ce65f5bc55"
archive-sha256 = "aa1b66a70eace83dc624508745646c08ae561de512ab403adffb93ac87fc72e6"

[import]
commit = "972192ded6bc909246dcf9f3852f30060e71e2cc"
root = "original"

[worktree]
digest = "{digest}"
digest-algorithm = "{DIGEST_ALGORITHM}"
files = {files}
executable-files = {executable}
symlinks = 0
index-digest = "9132ac7957eb7f62c87372521b54bb29d76b91c690434d8692730f623a01ee9b"
index-digest-algorithm = "sha256-of-git-ls-files-s"

[verification]
method = "read-only-compare-in-scratch"
write-targets = []
bootstrap = "testing/upstream-suite/baseline-bootstrap"
"#
        )
    }

    fn oracle() -> MapFiles {
        MapFiles::new()
            .with("original/lib/easy.c", "body\n")
            .with_executable("original/scripts/run.sh", "#!/bin/sh\n")
    }

    fn tree(digest: &str, files: usize, executable: usize) -> MapFiles {
        oracle()
            .with("BASELINE.toml", &record(digest, files, executable))
            .with("testing/upstream-suite/baseline-bootstrap", BOOTSTRAP)
    }

    fn workspace(manifest: &str, key: &str) -> Workspace {
        let directory = std::env::temp_dir().join(format!("curl-audit-baseline-{key}"));
        std::fs::create_dir_all(&directory).expect("fixture directory");
        std::fs::write(directory.join("Cargo.toml"), manifest).expect("fixture manifest");
        Workspace::load(&directory).expect("fixture workspace")
    }

    const ROOT_MANIFEST: &str = "[workspace]\nmembers = []\n\n[workspace.metadata.curl]\nbaseline-manifest = \"BASELINE.toml\"\nbaseline-tag = \"curl-8_21_0\"\n";

    fn measured_digest() -> String {
        measure(&oracle(), "original").digest
    }

    #[test]
    fn a_line_carries_mode_then_content_then_path() {
        let entry = Entry {
            path: "original/lib/easy.c".to_owned(),
            mode: PLAIN_MODE,
            bytes: b"body\n".to_vec(),
        };
        assert_eq!(
            digest_line(&entry),
            format!("100644 {} original/lib/easy.c\n", hex_sha256(b"body\n"))
        );
    }

    #[test]
    fn the_measured_tree_matches_the_frozen_record() {
        let digest = measured_digest();
        let files = tree(&digest, 2, 1);
        let report = audit(&workspace(ROOT_MANIFEST, "match"), &files).expect("record loads");
        let rendered = report.render();
        assert!(report.passed(), "{rendered}");
        assert!(rendered.contains("PASS worktree-digest"));
        assert!(rendered.contains("PASS worktree-mode-count"));
    }

    #[test]
    fn a_changed_byte_fails_the_digest() {
        let digest = measured_digest();
        let files = tree(&digest, 2, 1).with("original/lib/easy.c", "body!\n");
        let report = audit(&workspace(ROOT_MANIFEST, "byte"), &files).expect("record loads");
        assert!(report.render().contains("FAIL worktree-digest"));
    }

    #[test]
    fn a_changed_mode_fails_the_digest_and_the_mode_count() {
        let digest = measured_digest();
        let files = tree(&digest, 2, 1).with_executable("original/lib/easy.c", "body\n");
        let rendered = audit(&workspace(ROOT_MANIFEST, "mode"), &files)
            .expect("record loads")
            .render();
        assert!(rendered.contains("FAIL worktree-digest"), "{rendered}");
        assert!(rendered.contains("FAIL worktree-mode-count"));
    }

    #[test]
    fn an_extra_file_fails_the_count() {
        let digest = measured_digest();
        let files = tree(&digest, 2, 1).with("original/lib/new.c", "");
        let rendered = audit(&workspace(ROOT_MANIFEST, "extra"), &files)
            .expect("record loads")
            .render();
        assert!(rendered.contains("FAIL worktree-file-count"), "{rendered}");
    }

    #[test]
    fn an_empty_tree_is_not_a_pass() {
        let record = record(&measured_digest(), 0, 0);
        let files = MapFiles::new()
            .with("BASELINE.toml", &record)
            .with("testing/upstream-suite/baseline-bootstrap", BOOTSTRAP);
        let rendered = audit(&workspace(ROOT_MANIFEST, "empty"), &files)
            .expect("record loads")
            .render();
        assert!(rendered.contains("FAIL worktree-file-count"), "{rendered}");
        assert!(rendered.contains("FAIL worktree-digest"));
    }

    #[test]
    fn a_manifest_that_names_no_record_and_a_tag_that_disagrees_both_fail() {
        let digest = measured_digest();
        let files = tree(&digest, 2, 1);
        let manifest = "[workspace]\nmembers = []\n\n[workspace.metadata.curl]\nbaseline-tag = \"curl-8_20_0\"\n";
        let rendered = audit(&workspace(manifest, "disagree"), &files)
            .expect("record loads")
            .render();
        assert!(rendered.contains("FAIL manifest-declared"), "{rendered}");
        assert!(rendered.contains("FAIL tag-agrees"));
    }

    #[test]
    fn a_truncated_identity_and_a_foreign_algorithm_both_fail() {
        let digest = measured_digest();
        let body = record(&digest, 2, 1)
            .replace("3f00a2f6fa97f7721b65606954aac979dcb6caac", "3f00a2f6")
            .replace(DIGEST_ALGORITHM, "blake3-of-something");
        let files = tree(&digest, 2, 1).with("BASELINE.toml", &body);
        let rendered = audit(&workspace(ROOT_MANIFEST, "truncated"), &files)
            .expect("record loads")
            .render();
        assert!(
            rendered.contains("FAIL identities-well-formed"),
            "{rendered}"
        );
        assert!(rendered.contains("FAIL algorithms-implemented"));
    }

    #[test]
    fn a_recorded_write_target_fails() {
        let digest = measured_digest();
        let body = record(&digest, 2, 1)
            .replace("write-targets = []", "write-targets = [\"original/lib\"]");
        let files = tree(&digest, 2, 1).with("BASELINE.toml", &body);
        let rendered = audit(&workspace(ROOT_MANIFEST, "target"), &files)
            .expect("record loads")
            .render();
        assert!(
            rendered.contains("FAIL oracle-not-a-write-target"),
            "{rendered}"
        );
    }

    #[test]
    fn a_bootstrap_that_writes_into_the_oracle_fails() {
        let digest = measured_digest();
        let files = tree(&digest, 2, 1).with(
            "testing/upstream-suite/baseline-bootstrap",
            "#!/bin/sh\n# BASELINE.toml\ncp -a -- \"$staging/.\" \"original/lib/\"\n",
        );
        let rendered = audit(&workspace(ROOT_MANIFEST, "bootstrap"), &files)
            .expect("record loads")
            .render();
        assert!(
            rendered.contains("FAIL bootstrap-writes-no-oracle-path"),
            "{rendered}"
        );
    }

    #[test]
    fn a_missing_record_and_a_missing_bootstrap_are_errors() {
        assert!(Baseline::load(&MapFiles::new()).is_err());
        let files = MapFiles::new().with("BASELINE.toml", "schema = 1\n");
        assert!(Baseline::load(&files).is_err());
        let digest = measured_digest();
        let without = oracle().with("BASELINE.toml", &record(&digest, 2, 1));
        let rendered = audit(&workspace(ROOT_MANIFEST, "nobootstrap"), &without)
            .expect("record loads")
            .render();
        assert!(rendered.contains("FAIL bootstrap-readable"), "{rendered}");
    }

    #[test]
    fn write_site_detection_reads_only_written_operands() {
        assert_eq!(
            oracle_write_sites("cp a original/b\n", "original/").len(),
            1
        );
        assert_eq!(
            oracle_write_sites("cp -a -- x \"original/lib\"\n", "original/").len(),
            1
        );
        assert_eq!(
            oracle_write_sites("echo x > original/b\n", "original/").len(),
            1
        );
        assert_eq!(
            oracle_write_sites("echo x >original/b\n", "original/").len(),
            1
        );
        assert_eq!(
            oracle_write_sites("rm -rf -- original\n", "original/").len(),
            1
        );
        assert_eq!(
            oracle_write_sites("chmod 644 original/lib/easy.c\n", "original/").len(),
            1
        );
        assert!(
            oracle_write_sites("cp -a -- original/. target/baseline/\n", "original/").is_empty()
        );
        assert!(oracle_write_sites("find original -type f | sort\n", "original/").is_empty());
        assert!(oracle_write_sites("# cp a original/b\n", "original/").is_empty());
        assert!(oracle_write_sites("\n   \n", "original/").is_empty());
        assert!(written_operands("").is_empty());
    }

    #[test]
    fn named_paths_are_collected_once_each() {
        let named = named_oracle_paths(
            "see original/lib/easy.c and original/lib/easy.c.",
            "original/",
        );
        assert_eq!(named.len(), 1);
        assert!(named.contains("original/lib/easy.c"));
    }

    #[test]
    fn the_walk_reports_modes_and_order() {
        let entries = oracle().walk("original");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "original/lib/easy.c");
        assert_eq!(entries[1].mode, "100755");
    }
}
