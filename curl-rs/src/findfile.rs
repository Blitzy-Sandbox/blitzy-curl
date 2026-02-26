//! Config/Certificate File Discovery
//!
//! Rust rewrite of `src/tool_findfile.c` and `src/tool_findfile.h`.
//! Implements file discovery logic for configuration files (`.curlrc`),
//! certificate bundles (CA cert), and other support files.
//!
//! The search path precedence matches curl 8.x exactly, including the
//! mutable `dotscore` state machine that controls XDG\_CONFIG\_HOME
//! interaction with the `.config/` fallback directories.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Returns the value of an environment variable only if it is set and non-empty.
///
/// Empty-string values are treated as unset, matching the curl 8.x C behavior
/// where `curl_getenv` returns non-NULL but the code explicitly checks `home[0]`.
fn get_nonempty_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.is_empty())
}

/// Checks whether a file (or directory) exists at the given path.
///
/// Uses `fs::metadata()` as a safe replacement for the C `open(O_RDONLY)`/`close()`
/// pattern used in `checkhome()`.  Unlike `Path::exists()`, `metadata()` does not
/// follow the unstable `try_exists` path and is available on MSRV 1.75.
fn file_exists(path: &Path) -> bool {
    fs::metadata(path).is_ok()
}

/// Checks for the existence of a file in a directory, optionally trying both the
/// dot-prefixed and underscore-prefixed name variants (Windows `_curlrc` behavior).
///
/// This mirrors the C `checkhome()` function:
///
/// * When `try_underscore` is `false`, simply checks `{dir}/{fname}`.
/// * When `try_underscore` is `true`, the first character of `fname` is stripped
///   and re-prefixed with `'.'` then `'_'`, producing two candidate paths:
///   `{dir}/.{rest}` and `{dir}/_{rest}`.
///
/// The two-prefix behavior is used on Windows (where `dotscore == 2`) so that
/// both `.curlrc` and `_curlrc` are tried.
fn check_home(dir: &Path, fname: &str, try_underscore: bool) -> Option<PathBuf> {
    if try_underscore && fname.len() > 1 {
        // The C code iterates over pref[] = {'.', '_'} and builds
        // "{home}/{pref[i]}{fname[1:]}".
        let rest = &fname[1..]; // skip the first character (always '.')
        for prefix_char in ['.', '_'] {
            let prefixed = format!("{}{}", prefix_char, rest);
            let candidate = dir.join(&prefixed);
            if file_exists(&candidate) {
                return Some(candidate);
            }
        }
    } else {
        let candidate = dir.join(fname);
        if file_exists(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// A search-location entry mirroring the C `struct finder` and the static
/// `conf_list[]` array in `tool_findfile.c`.
///
/// Each entry specifies:
/// * An environment variable whose value is the base directory.
/// * An optional sub-path to append (e.g. `".config"`).
/// * Whether the leading dot should be stripped from the filename
///   (`without_dot`), which also interacts with the mutable `dotscore` state.
struct FinderEntry {
    env_var: &'static str,
    append: Option<&'static str>,
    without_dot: bool,
}

/// Builds the ordered search configuration list matching the C `conf_list[]`.
///
/// The order is critical — it determines search precedence and the `dotscore`
/// state transitions that disable subsequent `without_dot` entries once
/// `XDG_CONFIG_HOME` has been processed.
fn build_conf_list() -> Vec<FinderEntry> {
    let mut list = vec![
        FinderEntry {
            env_var: "CURL_HOME",
            append: None,
            without_dot: false,
        },
        FinderEntry {
            env_var: "XDG_CONFIG_HOME",
            append: None,
            without_dot: true,
        },
        FinderEntry {
            env_var: "HOME",
            append: None,
            without_dot: false,
        },
    ];

    // Windows-specific locations (mirrors C `#ifdef _WIN32` block)
    #[cfg(windows)]
    {
        list.push(FinderEntry {
            env_var: "USERPROFILE",
            append: None,
            without_dot: false,
        });
        list.push(FinderEntry {
            env_var: "APPDATA",
            append: None,
            without_dot: false,
        });
        list.push(FinderEntry {
            env_var: "USERPROFILE",
            append: Some("Application Data"),
            without_dot: false,
        });
    }

    // Fallback `.config/` directories — these are only used when
    // `XDG_CONFIG_HOME` was *not* set (dotscore is still > 0).
    list.push(FinderEntry {
        env_var: "CURL_HOME",
        append: Some(".config"),
        without_dot: true,
    });
    list.push(FinderEntry {
        env_var: "HOME",
        append: Some(".config"),
        without_dot: true,
    });

    list
}

/// Returns the standard system CA certificate bundle paths for the current platform.
///
/// On Linux these follow the well-known distribution conventions; on macOS the
/// OpenSSL-compatible PEM path is checked; on other Unix systems a small
/// superset of common paths is tried.
fn system_ca_bundle_paths() -> Vec<&'static str> {
    let mut paths = Vec::new();

    #[cfg(target_os = "linux")]
    {
        paths.extend_from_slice(&[
            "/etc/ssl/certs/ca-certificates.crt", // Debian / Ubuntu
            "/etc/pki/tls/certs/ca-bundle.crt",   // RHEL / CentOS / Fedora
            "/usr/share/ssl/certs/ca-bundle.crt",  // Older RHEL
            "/etc/ssl/certs/ca-bundle.crt",        // openSUSE
            "/etc/pki/tls/cacert.pem",             // OpenELEC
            "/etc/ssl/cert.pem",                   // Alpine Linux
        ]);
    }

    #[cfg(target_os = "macos")]
    {
        paths.extend_from_slice(&[
            "/etc/ssl/cert.pem",
            "/usr/local/etc/openssl/cert.pem",
        ]);
    }

    // Other Unix-like systems (FreeBSD, OpenBSD, NetBSD, etc.)
    #[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
    {
        paths.extend_from_slice(&[
            "/etc/ssl/cert.pem",
            "/etc/ssl/certs/ca-certificates.crt",
            "/usr/local/share/certs/ca-root-nss.crt", // FreeBSD
            "/etc/pki/tls/certs/ca-bundle.crt",
        ]);
    }

    // Windows: no system PEM paths (uses the Windows certificate store).
    // The Vec stays empty; the caller falls back to the beside-executable check.

    paths
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Searches through a list of directories for the named file.
///
/// For each directory in `dirs`, the directory is joined with `filename` and
/// the resulting path is checked for existence via `fs::metadata()`.
/// The first existing match is returned.
///
/// # Arguments
///
/// * `filename` — The name of the file to search for.
/// * `dirs`     — An ordered slice of directories to search through.
///
/// # Returns
///
/// `Some(PathBuf)` containing the full path of the first match, or `None` if the
/// file was not found in any of the provided directories.
///
/// # Examples
///
/// ```rust,no_run
/// use std::path::PathBuf;
/// # use curl_rs::findfile::findfile;
/// let dirs = vec![PathBuf::from("/etc"), PathBuf::from("/usr/local/etc")];
/// if let Some(path) = findfile("known_hosts", &dirs) {
///     println!("Found: {}", path.display());
/// }
/// ```
pub fn findfile(filename: &str, dirs: &[PathBuf]) -> Option<PathBuf> {
    if filename.is_empty() {
        return None;
    }
    for dir in dirs {
        let candidate = dir.join(filename);
        if file_exists(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Discovers the user's home directory using platform-appropriate methods.
///
/// # Search Order
///
/// **Unix / macOS:**
/// 1. `HOME` environment variable.
///
/// **Windows:**
/// 1. `USERPROFILE` environment variable.
/// 2. `APPDATA` environment variable.
/// 3. `HOME` environment variable.
///
/// Empty-string values are treated as unset.
///
/// # Returns
///
/// `Some(PathBuf)` containing the home directory, or `None` if no home
/// directory could be determined from the environment.
pub fn get_home_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        get_nonempty_env("USERPROFILE")
            .or_else(|| get_nonempty_env("APPDATA"))
            .or_else(|| get_nonempty_env("HOME"))
            .map(PathBuf::from)
    } else {
        // Unix, macOS, and any other platform.
        get_nonempty_env("HOME").map(PathBuf::from)
    }
}

/// Finds the `.curlrc` configuration file following curl 8.x search precedence.
///
/// This function replicates the C `findfile(".curlrc", CURLRC_DOTSCORE)` behavior
/// exactly, including the mutable `dotscore` state machine that:
///
/// * Starts at 1 (Unix) or 2 (Windows).
/// * Is reset to 0 when the first `without_dot` entry is processed, preventing
///   subsequent `without_dot` entries from being evaluated.
/// * Controls whether the underscore-prefixed variant (`_curlrc`) is tried
///   alongside the dot-prefixed variant (`.curlrc`) — Windows only.
///
/// # Search Order (Unix, `dotscore = 1`)
///
/// 1. `$CURL_HOME/.curlrc`
/// 2. `$XDG_CONFIG_HOME/curlrc` (if set; disables subsequent without-dot entries)
/// 3. `$HOME/.curlrc`
/// 4. `$CURL_HOME/.config/curlrc` (only if XDG\_CONFIG\_HOME was *not* set)
/// 5. `$HOME/.config/curlrc` (only if step 4 did not reset dotscore)
///
/// # Search Order (Windows, `dotscore = 2`)
///
/// 1. `$CURL_HOME/.curlrc` then `$CURL_HOME/_curlrc`
/// 2. `$XDG_CONFIG_HOME/curlrc` (if set; disables underscore variants)
/// 3. `$HOME/.curlrc` (+ `_curlrc` if XDG not set)
/// 4. `$USERPROFILE/.curlrc` (+ `_curlrc` if XDG not set)
/// 5. `$APPDATA/.curlrc` (+ `_curlrc` if XDG not set)
/// 6. `$USERPROFILE\Application Data/.curlrc` (+ `_curlrc` if XDG not set)
/// 7. `$CURL_HOME/.config/curlrc` (only if XDG not set)
/// 8. `$HOME/.config/curlrc` (only if step 7 did not reset dotscore)
/// 9. Beside executable: `_curlrc`
///
/// # Returns
///
/// `Some(PathBuf)` containing the full path to the `.curlrc` file if found,
/// `None` if no configuration file was found in any search location.
pub fn find_curlrc() -> Option<PathBuf> {
    let fname = ".curlrc";

    // dotscore = 2 on Windows (try underscore-prefixed variant too).
    // dotscore = 1 on Unix    (regular .curlrc check only).
    let mut dotscore: i32 = if cfg!(windows) { 2 } else { 1 };

    let conf_list = build_conf_list();

    for entry in &conf_list {
        if let Some(env_val) = get_nonempty_env(entry.env_var) {
            // Build the base directory, optionally appending a sub-path.
            // The C code uses string concatenation (`curl_maprintf("%s%s", …)`);
            // we use `Path::join` which handles platform separators.
            let home = match entry.append {
                Some(suffix) => PathBuf::from(&env_val).join(suffix),
                None => PathBuf::from(&env_val),
            };

            // Handle `without_dot` entries: strip the leading dot from the
            // filename and disable dotscore for all subsequent entries.
            let (filename, try_underscore) = if entry.without_dot {
                if dotscore == 0 {
                    // dotscore already disabled — skip this entry.
                    // Matches the C `continue` after `if(!dotscore)`.
                    continue;
                }
                // Consume the dotscore: strip leading dot and disable.
                dotscore = 0;
                (&fname[1..], false) // "curlrc", never try underscore variant
            } else {
                // Normal entry — `checkhome(home, fname, dotscore ? dotscore-1 : 0)`.
                // `dotscore - 1 > 0` means try underscore variant (Windows w/ dotscore=2).
                let try_us = if dotscore > 0 {
                    dotscore - 1 > 0
                } else {
                    false
                };
                (fname, try_us)
            };

            if let Some(path) = check_home(&home, filename, try_underscore) {
                return Some(path);
            }
        }
    }

    // Windows: also check beside the executable for `_curlrc`.
    #[cfg(windows)]
    {
        if let Ok(exe_path) = env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let candidate = exe_dir.join("_curlrc");
                if file_exists(&candidate) {
                    return Some(candidate);
                }
            }
        }
    }

    None
}

/// Finds the CA certificate bundle file.
///
/// The function first checks the `CURL_CA_BUNDLE` environment variable, then
/// falls back to well-known system locations that vary by platform.
///
/// # Search Order
///
/// 1. `$CURL_CA_BUNDLE` environment variable (highest priority).
/// 2. Platform-specific system paths:
///    * **Linux:** Debian/Ubuntu, RHEL/CentOS, openSUSE, Alpine paths.
///    * **macOS:** `/etc/ssl/cert.pem`, Homebrew OpenSSL path.
///    * **Other Unix:** common BSD and generic Unix paths.
///    * **Windows:** bundled `curl-ca-bundle.crt` beside the executable.
///
/// # Returns
///
/// `Some(PathBuf)` containing the path to the CA bundle if found,
/// `None` if no certificate bundle could be located.
pub fn find_ca_bundle() -> Option<PathBuf> {
    // 1. CURL_CA_BUNDLE environment variable takes highest priority.
    if let Some(path_str) = get_nonempty_env("CURL_CA_BUNDLE") {
        let path = PathBuf::from(&path_str);
        if file_exists(&path) {
            return Some(path);
        }
    }

    // 2. Platform-specific system locations.
    for system_path in system_ca_bundle_paths() {
        let path = PathBuf::from(system_path);
        if file_exists(&path) {
            return Some(path);
        }
    }

    // 3. Windows: check for a bundled CA file beside the executable.
    #[cfg(windows)]
    {
        if let Ok(exe_path) = env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let candidate = exe_dir.join("curl-ca-bundle.crt");
                if file_exists(&candidate) {
                    return Some(candidate);
                }
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};

    /// Helper: create a temporary directory and return its path.
    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("curl_rs_findfile_test_{}", name));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    /// Helper: clean up a temporary directory.
    fn cleanup(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_findfile_basic() {
        let dir = temp_dir("findfile_basic");
        let file_path = dir.join("testfile.txt");
        File::create(&file_path).expect("create test file");

        let dirs = vec![dir.clone()];
        let result = findfile("testfile.txt", &dirs);
        assert_eq!(result, Some(file_path));

        cleanup(&dir);
    }

    #[test]
    fn test_findfile_not_found() {
        let dir = temp_dir("findfile_notfound");
        let _ = fs::create_dir_all(&dir);

        let dirs = vec![dir.clone()];
        let result = findfile("nonexistent.txt", &dirs);
        assert_eq!(result, None);

        cleanup(&dir);
    }

    #[test]
    fn test_findfile_empty_filename() {
        let dirs = vec![PathBuf::from("/tmp")];
        assert_eq!(findfile("", &dirs), None);
    }

    #[test]
    fn test_findfile_empty_dirs() {
        assert_eq!(findfile("anything.txt", &[]), None);
    }

    #[test]
    fn test_findfile_first_match_wins() {
        let dir1 = temp_dir("findfile_first_1");
        let dir2 = temp_dir("findfile_first_2");
        let file1 = dir1.join("target.txt");
        let file2 = dir2.join("target.txt");
        File::create(&file1).expect("create file1");
        File::create(&file2).expect("create file2");

        let dirs = vec![dir1.clone(), dir2.clone()];
        let result = findfile("target.txt", &dirs);
        assert_eq!(result, Some(file1));

        cleanup(&dir1);
        cleanup(&dir2);
    }

    #[test]
    fn test_get_home_dir_from_env() {
        // This test depends on the HOME / USERPROFILE env var being set,
        // which is true in virtually all CI and development environments.
        let home = get_home_dir();
        // We can't assert a specific value, but if HOME is set it should return Some.
        if cfg!(windows) {
            // Windows: at least one of USERPROFILE/APPDATA/HOME should be set.
            // In CI it almost always is.
        } else if env::var("HOME").is_ok() {
            assert!(home.is_some(), "HOME is set but get_home_dir returned None");
        }
    }

    #[test]
    fn test_file_exists_positive() {
        let dir = temp_dir("file_exists_pos");
        let file = dir.join("exists.txt");
        File::create(&file).expect("create");
        assert!(file_exists(&file));
        cleanup(&dir);
    }

    #[test]
    fn test_file_exists_negative() {
        assert!(!file_exists(Path::new("/nonexistent_path_1234567890")));
    }

    #[test]
    fn test_check_home_plain() {
        let dir = temp_dir("check_home_plain");
        let file = dir.join(".curlrc");
        File::create(&file).expect("create");

        let result = check_home(&dir, ".curlrc", false);
        assert_eq!(result, Some(file));

        cleanup(&dir);
    }

    #[test]
    fn test_check_home_underscore() {
        let dir = temp_dir("check_home_us");
        // Only create the underscore variant — the dot variant does not exist.
        let file = dir.join("_curlrc");
        File::create(&file).expect("create");

        let result = check_home(&dir, ".curlrc", true);
        assert_eq!(result, Some(file));

        cleanup(&dir);
    }

    #[test]
    fn test_check_home_dot_before_underscore() {
        let dir = temp_dir("check_home_dot_first");
        let dot_file = dir.join(".curlrc");
        let us_file = dir.join("_curlrc");
        File::create(&dot_file).expect("create dot");
        File::create(&us_file).expect("create underscore");

        // When both exist, the dot-prefixed variant wins (tried first).
        let result = check_home(&dir, ".curlrc", true);
        assert_eq!(result, Some(dot_file));

        cleanup(&dir);
    }
}
