// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: the blitzy-curl project contributors

//! Repository-relative file access, injectable so audits are testable without
//! touching a real tree.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The two modes a tracked file carries.
///
/// Git records one permission bit and no more, so a mode is the executable one
/// or the plain one. A recorded mode is part of the frozen baseline state, which
/// is why it is a value the digest covers rather than a detail left to the
/// filesystem.
pub const EXECUTABLE_MODE: &str = "100755";

/// Mode of a tracked file that carries no executable bit.
pub const PLAIN_MODE: &str = "100644";

/// One regular file of a tree, with the state a content digest covers.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Entry {
    /// Repository-relative path, separated by forward slashes.
    pub path: String,
    /// Recorded mode: [`EXECUTABLE_MODE`] or [`PLAIN_MODE`].
    pub mode: &'static str,
    /// Raw bytes of the file.
    pub bytes: Vec<u8>,
}

/// Read-only view of repository-relative paths.
///
/// Every path an audit names is relative to the repository root, so an audit
/// never builds an absolute path itself and never reaches outside the tree.
pub trait Files {
    /// Whether `path` names an existing file or directory.
    fn exists(&self, path: &str) -> bool;

    /// Whether `path` names a directory.
    fn is_dir(&self, path: &str) -> bool;

    /// Contents of `path`, or `None` when it is absent or unreadable.
    fn read(&self, path: &str) -> Option<String>;

    /// Names of the entries directly inside the repository-relative directory
    /// `path`, sorted. An absent or unreadable directory lists as empty.
    fn list(&self, path: &str) -> Vec<String>;

    /// Every regular file under `root`, recursively, in path order.
    ///
    /// A symlink is not a regular file and is not returned, so a view that
    /// carries one reports a count the digest cannot account for. An absent
    /// root walks as empty, which the caller reports as a failing check rather
    /// than as an empty tree.
    fn walk(&self, root: &str) -> Vec<Entry>;
}

/// [`Files`] over a real repository checkout.
#[derive(Clone, Debug)]
pub struct RealFiles {
    root: PathBuf,
}

impl RealFiles {
    /// Views the checkout rooted at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The repository root this view resolves against.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Absolute path of a repository-relative `path`.
    #[must_use]
    pub fn absolute(&self, path: &str) -> PathBuf {
        self.root.join(path)
    }
}

impl Files for RealFiles {
    fn exists(&self, path: &str) -> bool {
        self.absolute(path).exists()
    }

    fn is_dir(&self, path: &str) -> bool {
        self.absolute(path).is_dir()
    }

    fn read(&self, path: &str) -> Option<String> {
        std::fs::read_to_string(self.absolute(path)).ok()
    }

    fn list(&self, path: &str) -> Vec<String> {
        let directory = if path.is_empty() {
            self.root.clone()
        } else {
            self.absolute(path)
        };
        let Ok(entries) = std::fs::read_dir(directory) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn walk(&self, root: &str) -> Vec<Entry> {
        let mut found = Vec::new();
        let mut pending = vec![root.to_owned()];
        while let Some(current) = pending.pop() {
            for name in self.list(&current) {
                let path = if current.is_empty() {
                    name
                } else {
                    format!("{current}/{name}")
                };
                let absolute = self.absolute(&path);
                let Ok(metadata) = std::fs::symlink_metadata(&absolute) else {
                    continue;
                };
                if metadata.is_dir() {
                    pending.push(path);
                    continue;
                }
                if !metadata.is_file() {
                    continue;
                }
                let Ok(bytes) = std::fs::read(&absolute) else {
                    continue;
                };
                found.push(Entry {
                    path,
                    mode: mode_of(&metadata),
                    bytes,
                });
            }
        }
        found.sort();
        found
    }
}

/// The recorded mode of a file's metadata.
#[cfg(unix)]
fn mode_of(metadata: &std::fs::Metadata) -> &'static str {
    use std::os::unix::fs::PermissionsExt as _;
    if metadata.permissions().mode() & 0o111 == 0 {
        PLAIN_MODE
    } else {
        EXECUTABLE_MODE
    }
}

/// The recorded mode of a file's metadata.
#[cfg(not(unix))]
fn mode_of(_metadata: &std::fs::Metadata) -> &'static str {
    PLAIN_MODE
}

/// [`Files`] over an in-memory map, for tests.
#[derive(Clone, Debug, Default)]
pub struct MapFiles {
    entries: BTreeMap<String, String>,
    executable: BTreeSet<String>,
}

impl MapFiles {
    /// An empty view.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a file with contents.
    #[must_use]
    pub fn with(mut self, path: &str, contents: &str) -> Self {
        self.entries.insert(path.to_owned(), contents.to_owned());
        self
    }

    /// Adds a file whose recorded mode carries the executable bit.
    #[must_use]
    pub fn with_executable(mut self, path: &str, contents: &str) -> Self {
        self.executable.insert(path.to_owned());
        self.with(path, contents)
    }
}

impl Files for MapFiles {
    fn exists(&self, path: &str) -> bool {
        self.entries.contains_key(path)
    }

    fn is_dir(&self, path: &str) -> bool {
        let prefix = format!("{path}/");
        self.entries.keys().any(|key| key.starts_with(&prefix))
    }

    fn read(&self, path: &str) -> Option<String> {
        self.entries.get(path).cloned()
    }

    fn list(&self, path: &str) -> Vec<String> {
        let prefix = if path.is_empty() {
            String::new()
        } else {
            format!("{path}/")
        };
        let mut names: BTreeSet<String> = BTreeSet::new();
        for key in self.entries.keys() {
            let Some(rest) = key.strip_prefix(prefix.as_str()) else {
                continue;
            };
            let name = rest.split('/').next().unwrap_or(rest);
            if !name.is_empty() {
                names.insert(name.to_owned());
            }
        }
        names.into_iter().collect()
    }

    fn walk(&self, root: &str) -> Vec<Entry> {
        let prefix = if root.is_empty() {
            String::new()
        } else {
            format!("{root}/")
        };
        let mut found: Vec<Entry> = self
            .entries
            .iter()
            .filter(|(path, _)| path.starts_with(prefix.as_str()))
            .map(|(path, contents)| Entry {
                path: path.clone(),
                mode: if self.executable.contains(path) {
                    EXECUTABLE_MODE
                } else {
                    PLAIN_MODE
                },
                bytes: contents.as_bytes().to_vec(),
            })
            .collect();
        found.sort();
        found
    }
}

#[cfg(test)]
mod tests {
    use super::{Files, MapFiles, RealFiles};

    #[test]
    fn map_files_answers_exists_and_read() {
        let files = MapFiles::new().with("a/b.txt", "body");
        assert!(files.exists("a/b.txt"));
        assert!(!files.exists("a/c.txt"));
        assert_eq!(files.read("a/b.txt").as_deref(), Some("body"));
        assert_eq!(files.read("a/c.txt"), None);
    }

    #[test]
    fn map_files_tell_files_from_directories() {
        let files = MapFiles::new().with("a/b.txt", "body");
        assert!(files.is_dir("a"));
        assert!(!files.is_dir("a/b.txt"));
        assert!(!files.is_dir("missing"));
    }

    #[test]
    fn map_files_lists_one_level() {
        let files = MapFiles::new()
            .with("Cargo.toml", "")
            .with("a/b.txt", "")
            .with("a/c/d.txt", "");
        assert_eq!(
            files.list(""),
            vec!["Cargo.toml".to_owned(), "a".to_owned()]
        );
        assert_eq!(files.list("a"), vec!["b.txt".to_owned(), "c".to_owned()]);
        assert!(files.list("missing").is_empty());
    }

    #[test]
    fn real_files_resolves_against_its_root() {
        let files = RealFiles::new("/tmp/does-not-exist-curl-audit");
        assert_eq!(
            files.root().to_string_lossy(),
            "/tmp/does-not-exist-curl-audit"
        );
        assert_eq!(
            files.absolute("x/y").to_string_lossy(),
            "/tmp/does-not-exist-curl-audit/x/y"
        );
        assert!(!files.exists("x/y"));
        assert!(!files.is_dir("x/y"));
        assert_eq!(files.read("x/y"), None);
    }
}
