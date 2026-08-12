// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: the blitzy-curl project contributors

//! Repository-relative file access, injectable so audits are testable without
//! touching a real tree.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Read-only view of repository-relative paths.
///
/// Every path an audit names is relative to the repository root, so an audit
/// never builds an absolute path itself and never reaches outside the tree.
pub trait Files {
    /// Whether `path` names an existing file or directory.
    fn exists(&self, path: &str) -> bool;

    /// Contents of `path`, or `None` when it is absent or unreadable.
    fn read(&self, path: &str) -> Option<String>;

    /// Names of the entries directly inside the repository-relative directory
    /// `path`, sorted. An absent or unreadable directory lists as empty.
    fn list(&self, path: &str) -> Vec<String>;
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
}

/// [`Files`] over an in-memory map, for tests.
#[derive(Clone, Debug, Default)]
pub struct MapFiles {
    entries: BTreeMap<String, String>,
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
}

impl Files for MapFiles {
    fn exists(&self, path: &str) -> bool {
        self.entries.contains_key(path)
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
        assert_eq!(files.read("x/y"), None);
    }
}
