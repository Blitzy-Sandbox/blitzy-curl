// curl-rs/src/dirhier.rs — Directory Hierarchy Creation
//
// Rust rewrite of src/tool_dirhie.c and src/tool_dirhie.h from curl 8.19.0-DEV.
// Creates directory hierarchies for the `--create-dirs` CLI option, ensuring
// that all parent directories exist before writing output files.
//
// The C implementation walks path components one at a time, calling mkdir()
// for each intermediate directory. The Rust version delegates to
// `std::fs::create_dir_all()` which provides equivalent recursive creation
// with proper handling of already-existing directories and cross-platform
// path separator semantics.
//
// SPDX-License-Identifier: curl

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

/// Extracts the directory portion from a full file path.
///
/// Given a file path such as `"dir1/dir2/file.txt"`, this function returns
/// `Some("dir1/dir2")` — i.e. everything except the final filename component.
/// If the path contains no directory component (e.g. a bare filename like
/// `"file.txt"`), or if the path is empty, it returns `None`.
///
/// This function uses [`std::path::Path::parent`] for cross-platform path
/// handling, correctly interpreting both `/` (Unix) and `\` (Windows) path
/// separators without any `unsafe` code.
///
/// # Examples
///
/// ```
/// use curl_rs::dirhier::dir_from_path;
///
/// assert_eq!(dir_from_path("dir1/dir2/file.txt"), Some("dir1/dir2"));
/// assert_eq!(dir_from_path("file.txt"), None);
/// assert_eq!(dir_from_path(""), None);
/// assert_eq!(dir_from_path("/file.txt"), Some("/"));
/// assert_eq!(dir_from_path("/a/b/c/d.tar.gz"), Some("/a/b/c"));
/// ```
///
/// # Platform Behavior
///
/// On Windows, backslash-separated paths are handled correctly:
/// - `"C:\\Users\\name\\file.txt"` → `Some("C:\\Users\\name")`
/// - `"dir\\file.txt"` → `Some("dir")`
pub fn dir_from_path(path: &str) -> Option<&str> {
    // Empty paths have no directory component.
    if path.is_empty() {
        return None;
    }

    let p = Path::new(path);

    // Path::parent() returns:
    //   - Some("dir") for "dir/file.txt"
    //   - Some("/")    for "/file.txt"
    //   - Some("")     for "file.txt"  (no directory component)
    //   - None         for "" or "/"   (root/empty has no parent)
    match p.parent() {
        Some(parent) => {
            // Convert back to &str. Since our input is valid UTF-8 (&str),
            // the parent (a sub-slice of the same path) is always valid UTF-8.
            let parent_str = parent.to_str()?;
            if parent_str.is_empty() {
                // An empty parent means the file is in the current directory
                // (e.g. "file.txt") — no directories need to be created.
                None
            } else {
                Some(parent_str)
            }
        }
        None => None,
    }
}

/// Creates the directory hierarchy needed for the given output file path.
///
/// This is the Rust equivalent of curl's `--create-dirs` behavior: given a
/// full file path (e.g. `"dir1/dir2/file.txt"`), it creates all intermediate
/// directories (`dir1/`, `dir1/dir2/`) so that the file can be written. The
/// file itself is **not** created.
///
/// Internally this uses [`std::fs::create_dir_all`], which:
/// - Creates all missing intermediate directories (like `mkdir -p`).
/// - Returns `Ok(())` if the directory already exists.
/// - Handles cross-platform path separators via [`std::path::Path`].
///
/// # Arguments
///
/// * `path` — The full output file path. Only the directory portion (everything
///   before the last path component) is created. If the path has no directory
///   component (e.g. `"file.txt"` with no slashes), the function returns
///   `Ok(())` immediately since there is nothing to create.
///
/// # Returns
///
/// * `Ok(())` — The directories were created successfully, or they already
///   existed, or the path had no directory component.
/// * `Err(...)` — Directory creation failed. The error includes human-readable
///   context describing which directory could not be created and the underlying
///   OS error (e.g. permission denied, read-only filesystem, disk full).
///
/// # Examples
///
/// ```no_run
/// use curl_rs::dirhier::create_dir_hierarchy;
///
/// // Creates "output/subdir/" then the file can be written there.
/// create_dir_hierarchy("output/subdir/data.json").unwrap();
///
/// // No directory component — nothing to create, returns Ok(()).
/// create_dir_hierarchy("data.json").unwrap();
/// ```
///
/// # Errors
///
/// Returns an error with context if `std::fs::create_dir_all` fails, which
/// can happen when:
/// - The process lacks permission to create a directory in the path.
/// - The filesystem is read-only.
/// - The disk is full or the quota has been exceeded.
/// - A path component exists but is not a directory (e.g. a file blocks the
///   path).
pub fn create_dir_hierarchy(path: &str) -> Result<()> {
    if let Some(dir) = dir_from_path(path) {
        fs::create_dir_all(dir).with_context(|| {
            format!("failed to create directory hierarchy '{}'", dir)
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // dir_from_path tests
    // -----------------------------------------------------------------------

    #[test]
    fn dir_from_path_with_nested_dirs() {
        assert_eq!(dir_from_path("a/b/c/file.txt"), Some("a/b/c"));
    }

    #[test]
    fn dir_from_path_single_dir() {
        assert_eq!(dir_from_path("dir/file.txt"), Some("dir"));
    }

    #[test]
    fn dir_from_path_no_dir() {
        assert_eq!(dir_from_path("file.txt"), None);
    }

    #[test]
    fn dir_from_path_empty() {
        assert_eq!(dir_from_path(""), None);
    }

    #[test]
    fn dir_from_path_root_file() {
        assert_eq!(dir_from_path("/file.txt"), Some("/"));
    }

    #[test]
    fn dir_from_path_deep_nesting() {
        assert_eq!(
            dir_from_path("/a/b/c/d/e/f.tar.gz"),
            Some("/a/b/c/d/e")
        );
    }

    #[test]
    fn dir_from_path_relative_dot() {
        // "./file.txt" has parent "."
        assert_eq!(dir_from_path("./file.txt"), Some("."));
    }

    #[test]
    fn dir_from_path_dotdot() {
        assert_eq!(dir_from_path("../dir/file.txt"), Some("../dir"));
    }

    // -----------------------------------------------------------------------
    // create_dir_hierarchy tests
    // -----------------------------------------------------------------------

    #[test]
    fn create_hierarchy_no_dir_component() {
        // No directory portion — should succeed immediately.
        assert!(create_dir_hierarchy("file.txt").is_ok());
    }

    #[test]
    fn create_hierarchy_empty_path() {
        // Empty path — should succeed immediately.
        assert!(create_dir_hierarchy("").is_ok());
    }

    #[test]
    fn create_hierarchy_creates_nested_dirs() {
        let tmp = tempdir_for_test("create_nested");
        let file_path = format!("{}/a/b/c/output.txt", tmp);
        assert!(create_dir_hierarchy(&file_path).is_ok());
        assert!(Path::new(&format!("{}/a/b/c", tmp)).is_dir());
    }

    #[test]
    fn create_hierarchy_existing_dir() {
        let tmp = tempdir_for_test("existing_dir");
        let dir_path = format!("{}/existing", tmp);
        fs::create_dir_all(&dir_path).unwrap();
        let file_path = format!("{}/existing/file.txt", tmp);
        // Should succeed even though the directory already exists.
        assert!(create_dir_hierarchy(&file_path).is_ok());
    }

    #[test]
    fn create_hierarchy_relative_path() {
        // Use a unique subdirectory under the current directory.
        let unique = format!(
            "blitzy_dirhier_test_{}",
            std::process::id()
        );
        let file_path = format!("{}/sub/deep/file.dat", unique);
        let result = create_dir_hierarchy(&file_path);
        // Clean up regardless of outcome.
        let _ = fs::remove_dir_all(&unique);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Test helper: create a temporary directory with a predictable prefix
    // -----------------------------------------------------------------------

    fn tempdir_for_test(name: &str) -> String {
        let dir = format!(
            "/tmp/blitzy_dirhier_test_{}_{}",
            name,
            std::process::id()
        );
        // Ensure a clean slate.
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("failed to create test temp dir");
        dir
    }
}
