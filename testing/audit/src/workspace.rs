// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: the blitzy-curl project contributors

//! The root workspace manifest and the project contract it carries under
//! `[workspace.metadata.curl]`.

use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

use toml::Value;

/// Anything that stops an audit from reading its contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditError(String);

impl AuditError {
    /// Wraps a message.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    /// The message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for AuditError {}

/// Result of an operation that reads a contract.
pub type AuditResult<T> = Result<T, AuditError>;

/// File name of a Cargo manifest.
pub const MANIFEST: &str = "Cargo.toml";

/// File name of the committed lockfile.
pub const LOCKFILE: &str = "Cargo.lock";

/// The root manifest of the workspace, parsed.
#[derive(Clone, Debug)]
pub struct Workspace {
    root: PathBuf,
    manifest: Value,
}

impl Workspace {
    /// Loads the root manifest of the workspace rooted at `root`.
    pub fn load(root: impl Into<PathBuf>) -> AuditResult<Self> {
        let root = root.into();
        let path = root.join(MANIFEST);
        let text = std::fs::read_to_string(&path)
            .map_err(|error| AuditError::new(format!("{}: {error}", path.display())))?;
        let manifest = toml::from_str::<Value>(&text)
            .map_err(|error| AuditError::new(format!("{}: {error}", path.display())))?;
        if manifest.get("workspace").is_none() {
            return Err(AuditError::new(format!(
                "{}: no [workspace] table",
                path.display()
            )));
        }
        Ok(Self { root, manifest })
    }

    /// Walks up from `start` to the first directory whose manifest declares a
    /// `[workspace]` table, and loads it.
    pub fn discover(start: impl AsRef<Path>) -> AuditResult<Self> {
        let start = start.as_ref();
        let mut current = Some(start);
        while let Some(directory) = current {
            if directory.join(MANIFEST).is_file()
                && let Ok(workspace) = Self::load(directory)
            {
                return Ok(workspace);
            }
            current = directory.parent();
        }
        Err(AuditError::new(format!(
            "no workspace root at or above {}",
            start.display()
        )))
    }

    /// The repository root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The parsed root manifest.
    #[must_use]
    pub fn manifest(&self) -> &Value {
        &self.manifest
    }

    /// The value at a dotted path of table keys, if present.
    #[must_use]
    pub fn value(&self, path: &[&str]) -> Option<&Value> {
        let mut current = &self.manifest;
        for key in path {
            current = current.get(key)?;
        }
        Some(current)
    }

    /// The table at a dotted path of table keys.
    pub fn table(&self, path: &[&str]) -> AuditResult<&toml::map::Map<String, Value>> {
        self.value(path)
            .and_then(Value::as_table)
            .ok_or_else(|| AuditError::new(format!("missing table [{}]", path.join("."))))
    }

    /// The string array at a dotted path of table keys.
    pub fn string_array(&self, path: &[&str]) -> AuditResult<Vec<String>> {
        let array = self
            .value(path)
            .and_then(Value::as_array)
            .ok_or_else(|| AuditError::new(format!("missing array {}", path.join("."))))?;
        array
            .iter()
            .map(|entry| {
                entry.as_str().map(str::to_owned).ok_or_else(|| {
                    AuditError::new(format!("{}: entry is not a string", path.join(".")))
                })
            })
            .collect()
    }

    /// `[workspace].members`.
    pub fn members(&self) -> AuditResult<Vec<String>> {
        self.string_array(&["workspace", "members"])
    }

    /// `[workspace.dependencies]`, one entry per pinned crate.
    pub fn dependencies(&self) -> AuditResult<&toml::map::Map<String, Value>> {
        self.table(&["workspace", "dependencies"])
    }

    /// `[workspace.metadata.curl]`, the project contract.
    pub fn curl_metadata(&self) -> AuditResult<&toml::map::Map<String, Value>> {
        self.table(&["workspace", "metadata", "curl"])
    }

    /// The value at a dotted path under `[workspace.metadata.curl]`.
    #[must_use]
    pub fn curl_value(&self, path: &[&str]) -> Option<&Value> {
        let mut keys = vec!["workspace", "metadata", "curl"];
        keys.extend_from_slice(path);
        self.value(&keys)
    }
}

/// The version requirement a `[workspace.dependencies]` entry declares.
///
/// An entry is either a bare version string or a table carrying `version`.
#[must_use]
pub fn declared_version(entry: &Value) -> Option<&str> {
    match entry {
        Value::String(version) => Some(version.as_str()),
        Value::Table(table) => table.get("version").and_then(Value::as_str),
        _ => None,
    }
}

/// Whether a requirement is an exact `=x.y.z` pin.
///
/// Exactness is what `[R1]` freezes and what `DL-0009` and `DL-0010` assert
/// against; caret, tilde, wildcard and comparison requirements are all
/// rejected.
#[must_use]
pub fn is_exact_pin(requirement: &str) -> bool {
    let Some(version) = requirement.strip_prefix('=') else {
        return false;
    };
    let version = version.trim();
    if version.is_empty() || version.contains(['*', ',', ' ', '^', '~', '>', '<']) {
        return false;
    }
    let components: Vec<&str> = version.split('.').collect();
    components.len() == 3
        && components
            .iter()
            .all(|component| !component.is_empty() && component.chars().all(char::is_numeric))
}

#[cfg(test)]
mod tests {
    use super::{AuditError, Workspace, declared_version, is_exact_pin};
    use toml::Value;

    fn manifest() -> Value {
        let text = r#"
[workspace]
members = ["testing/audit"]

[workspace.dependencies]
toml = "=1.1.4"
serde = { version = "=1.0.229", features = ["derive"] }

[workspace.metadata.curl]
msrv = "1.97.1"
"#
        .to_owned();
        toml::from_str::<Value>(&text).expect("fixture parses")
    }

    #[test]
    fn exact_pins_are_recognised() {
        assert!(is_exact_pin("=1.1.4"));
        assert!(is_exact_pin("=0.0.8"));
        assert!(!is_exact_pin("1.1.4"));
        assert!(!is_exact_pin("^1.1.4"));
        assert!(!is_exact_pin("~1.1.4"));
        assert!(!is_exact_pin("=1.1"));
        assert!(!is_exact_pin("=1.1.*"));
        assert!(!is_exact_pin(">=1.1.4"));
        assert!(!is_exact_pin("="));
        assert!(!is_exact_pin("=1.1.4-beta"));
    }

    #[test]
    fn declared_version_reads_both_shapes() {
        let value = manifest();
        let dependencies = value
            .get("workspace")
            .and_then(|workspace| workspace.get("dependencies"))
            .and_then(Value::as_table)
            .expect("fixture has dependencies");
        assert_eq!(declared_version(&dependencies["toml"]), Some("=1.1.4"));
        assert_eq!(declared_version(&dependencies["serde"]), Some("=1.0.229"));
        assert_eq!(declared_version(&Value::Integer(1)), None);
    }

    #[test]
    fn navigation_reports_missing_tables() {
        let error = AuditError::new("boom");
        assert_eq!(error.message(), "boom");
        assert_eq!(error.to_string(), "boom");
        let missing = Workspace::discover("/proc/self/cwd/definitely-not-a-workspace-here");
        assert!(missing.is_err());
    }
}
