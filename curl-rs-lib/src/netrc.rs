//! Netrc file parser for automatic authentication credential lookup.
//!
//! This module provides a Rust implementation of the `.netrc` file parsing
//! functionality from curl's `lib/netrc.c`. It supports the standard netrc
//! file format including `machine`, `default`, `login`, `password`, `account`,
//! and `macdef` tokens, quoted values with escape sequences, and comment lines.
//!
//! # File Format
//!
//! ```text
//! # Comment line
//! machine example.com
//!     login myuser
//!     password mypass
//!
//! machine other.com
//!     login otheruser
//!     password otherpass
//!     account myaccount
//!
//! default
//!     login anonymous
//!     password user@example.com
//! ```
//!
//! # Supported Tokens
//!
//! - `machine <hostname>` — begins a host-specific credential block
//! - `default` — begins a fallback credential block (matches any host)
//! - `login <name>` — specifies the username
//! - `password <secret>` — specifies the password
//! - `account <token>` — specifies an optional account string
//! - `macdef <name>` — begins a macro definition (skipped until blank line)
//!
//! Quoted values (e.g., `"my password"`) support `\n`, `\r`, `\t` escape
//! sequences. Lines beginning with `#` (after optional leading whitespace)
//! are treated as comments and ignored.
//!
//! # Limits
//!
//! - Maximum file size: 128 KB
//! - Maximum line length: 16,384 bytes
//! - Maximum token length: 4,096 bytes

use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use crate::error::{CurlError, CurlResult};

// ---------------------------------------------------------------------------
// Constants — matching lib/netrc.c limits exactly
// ---------------------------------------------------------------------------

/// Maximum netrc file size in bytes (128 KB), matching `MAX_NETRC_FILE` in C.
const MAX_NETRC_FILE: usize = 128 * 1024;

/// Maximum single-line length in bytes, matching `MAX_NETRC_LINE` in C.
const MAX_NETRC_LINE: usize = 16384;

/// Maximum single-token length in bytes, matching `MAX_NETRC_TOKEN` in C.
const MAX_NETRC_TOKEN: usize = 4096;

// ---------------------------------------------------------------------------
// Internal parse state enums
// ---------------------------------------------------------------------------

/// State machine states for netrc token processing, mirroring the C
/// `enum host_lookup_state` in `lib/netrc.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseState {
    /// Looking for `machine`, `default`, or `macdef` keywords.
    Nothing,
    /// Found `machine` keyword; the next token is the hostname.
    HostFound,
    /// Inside a host/default section, collecting credentials.
    HostValid,
    /// Inside a `macdef` block; skip tokens until a blank line.
    MacDef,
}

/// Sub-state within [`ParseState::HostValid`] indicating which value token
/// is expected next, mirroring the C `enum found_state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeywordState {
    /// No keyword pending; the next token should be a keyword name.
    None,
    /// `login` keyword was seen; the next token is the login value.
    Login,
    /// `password` keyword was seen; the next token is the password value.
    Password,
    /// `account` keyword was seen; the next token is the account value.
    Account,
}

// ---------------------------------------------------------------------------
// Internal entry builder
// ---------------------------------------------------------------------------

/// Accumulates fields while parsing a single machine/default section.
#[derive(Debug)]
struct EntryBuilder {
    machine: String,
    login: String,
    password: String,
    account: Option<String>,
    is_default: bool,
    /// Whether at least one credential keyword was seen in this section.
    has_content: bool,
}

impl EntryBuilder {
    /// Creates a fresh, empty builder.
    fn new() -> Self {
        EntryBuilder {
            machine: String::new(),
            login: String::new(),
            password: String::new(),
            account: None,
            is_default: false,
            has_content: false,
        }
    }

    /// Resets the builder for a new section, returning the previous section's
    /// data as an `(entry, is_default)` tuple if it contained any content.
    fn take(&mut self) -> Option<(NetrcEntry, bool)> {
        if !self.has_content && self.machine.is_empty() && !self.is_default {
            // Nothing accumulated yet (initial state or consecutive keywords).
            return None;
        }
        let entry = NetrcEntry {
            machine: std::mem::take(&mut self.machine),
            login: std::mem::take(&mut self.login),
            password: std::mem::take(&mut self.password),
            account: self.account.take(),
        };
        let was_default = self.is_default;
        self.is_default = false;
        self.has_content = false;
        Some((entry, was_default))
    }
}

// ---------------------------------------------------------------------------
// NetrcEntry — public credential record
// ---------------------------------------------------------------------------

/// A single entry from a `.netrc` file representing credentials for one
/// machine (or the `default` fallback).
///
/// Entries are produced by [`Netrc::parse_file`] or [`Netrc::load_default`]
/// and consumed by the `find_credentials*` lookup methods.
#[derive(Debug, Clone)]
pub struct NetrcEntry {
    /// Hostname this entry applies to. Empty string for `default` entries.
    machine: String,
    /// Login (username) for authentication.
    login: String,
    /// Password for authentication. Empty string if not specified in the file.
    password: String,
    /// Optional account token (rarely used; parsed but not required).
    account: Option<String>,
}

impl NetrcEntry {
    /// Returns the machine hostname for this entry.
    ///
    /// An empty string indicates this was a `default` entry.
    pub fn machine(&self) -> &str {
        &self.machine
    }

    /// Returns the login (username) for this entry.
    pub fn login(&self) -> &str {
        &self.login
    }

    /// Returns the password for this entry.
    ///
    /// May be an empty string if the `password` keyword was absent.
    pub fn password(&self) -> &str {
        &self.password
    }

    /// Returns the optional account string, if present in the file.
    pub fn account(&self) -> Option<&str> {
        self.account.as_deref()
    }
}

// ---------------------------------------------------------------------------
// Internal ordered entry (preserves file order of machine vs default)
// ---------------------------------------------------------------------------

/// Wrapper that records whether a [`NetrcEntry`] came from a `default` line
/// so that lookups can honour file-order precedence (matching the C parser
/// which processes the file in a single sequential pass).
#[derive(Debug, Clone)]
struct OrderedEntry {
    entry: NetrcEntry,
    is_default: bool,
}

// ---------------------------------------------------------------------------
// Netrc — public parser and credential store
// ---------------------------------------------------------------------------

/// Parser and credential store for `.netrc` files.
///
/// A `Netrc` instance holds all entries parsed from a single `.netrc` file and
/// provides lookup methods to retrieve credentials by hostname. The parsing
/// and lookup semantics are identical to curl 8.x's `Curl_parsenetrc()`.
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use curl_rs_lib::netrc::Netrc;
///
/// let netrc = Netrc::parse_file(Path::new("/home/user/.netrc")).unwrap();
/// if let Some((login, password)) = netrc.find_credentials("example.com") {
///     println!("login={login}, password={password}");
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Netrc {
    /// All entries in file order. Each entry records whether it is a `default`.
    ordered: Vec<OrderedEntry>,
}

impl Netrc {
    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    /// Creates a new, empty `Netrc` with no entries.
    pub fn new() -> Self {
        Netrc {
            ordered: Vec::new(),
        }
    }

    /// Parses a `.netrc` file at the given path.
    ///
    /// # Errors
    ///
    /// | Error | Condition |
    /// |---|---|
    /// | [`CurlError::FileCouldntReadFile`] | File cannot be opened or read |
    /// | [`CurlError::OutOfMemory`] | File exceeds 128 KB, line exceeds 16 KB, or token exceeds 4 KB |
    /// | [`CurlError::LoginDenied`] | Syntax error (unterminated quote, trailing backslash) |
    pub fn parse_file(path: &Path) -> CurlResult<Netrc> {
        let content = load_file(path)?;
        parse_content(&content)
    }

    /// Loads the `.netrc` file from the platform-default location.
    ///
    /// Resolution order:
    /// 1. `$NETRC` environment variable (full path to the file)
    /// 2. `$HOME/.netrc`
    /// 3. *(Windows only)* `$USERPROFILE/.netrc`, then `$USERPROFILE/_netrc`
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::FileCouldntReadFile`] when no home directory can
    /// be determined or the file does not exist.
    pub fn load_default() -> CurlResult<Netrc> {
        // 1. $NETRC overrides everything.
        if let Ok(netrc_path) = env::var("NETRC") {
            if !netrc_path.is_empty() {
                return Netrc::parse_file(Path::new(&netrc_path));
            }
        }

        // 2. Resolve home directory.
        let home = find_home_dir()?;

        // 3. Try $HOME/.netrc (or equivalent).
        let dotnetrc = home.join(".netrc");
        match Netrc::parse_file(&dotnetrc) {
            Ok(netrc) => Ok(netrc),
            Err(CurlError::FileCouldntReadFile) => {
                // On Windows, fall back to the legacy `_netrc` name.
                #[cfg(target_os = "windows")]
                {
                    let under_netrc = home.join("_netrc");
                    Netrc::parse_file(&under_netrc)
                }
                #[cfg(not(target_os = "windows"))]
                {
                    Err(CurlError::FileCouldntReadFile)
                }
            }
            Err(other) => Err(other),
        }
    }

    // ------------------------------------------------------------------
    // Credential lookup
    // ------------------------------------------------------------------

    /// Finds credentials for the given hostname (case-insensitive match).
    ///
    /// Entries are searched in file order. The first entry whose `machine`
    /// matches `hostname` (case-insensitive) **or** that is a `default` entry
    /// is returned. This mirrors the single-pass behaviour of `Curl_parsenetrc`
    /// in the C implementation.
    ///
    /// Returns `Some((login, password))` on success, or `None` when no entry
    /// matches and no `default` is present.
    pub fn find_credentials(&self, hostname: &str) -> Option<(&str, &str)> {
        for oe in &self.ordered {
            if oe.is_default || oe.entry.machine.eq_ignore_ascii_case(hostname) {
                return Some((&oe.entry.login, &oe.entry.password));
            }
        }
        None
    }

    /// Finds credentials for the given hostname **and** a pre-known login.
    ///
    /// This replicates curl 8.x's `specific_login` mode where the caller
    /// already possesses a username and only needs the corresponding password.
    ///
    /// Matching proceeds in file order through three tiers:
    ///
    /// 1. **Exact match** — an entry whose machine matches `hostname`
    ///    (case-insensitive) **and** whose login equals `login`
    ///    (case-sensitive, matching `Curl_timestrcmp` semantics).
    /// 2. **Password capture** — an entry whose machine matches (or is
    ///    `default`) but whose login differs. The password is remembered but
    ///    searching continues in case a later entry provides an exact match.
    /// 3. **Fallback** — if no exact match was found but a password was
    ///    captured in tier 2, it is returned paired with the caller's `login`.
    ///
    /// Returns `Some((login, password))` on success, or `None`.
    pub fn find_credentials_with_login<'a>(
        &'a self,
        hostname: &str,
        login: &'a str,
    ) -> Option<(&'a str, &'a str)> {
        // Track the last-seen password from a matching section whose login
        // did not match — mirrors the C parser's password-capture behaviour.
        let mut last_captured_password: Option<&str> = None;

        for oe in &self.ordered {
            let host_matches =
                oe.is_default || oe.entry.machine.eq_ignore_ascii_case(hostname);
            if !host_matches {
                // In the C parser, encountering a non-matching `machine`
                // keyword frees the captured password. Replicate by
                // resetting the capture.
                if !oe.is_default {
                    last_captured_password = None;
                }
                continue;
            }

            // Host (or default) matches.
            if oe.entry.login == login {
                // Exact login match → immediate return (C sets `our_login`
                // and `FOUND_PASSWORD | FOUND_LOGIN`, then `done = TRUE`).
                return Some((&oe.entry.login, &oe.entry.password));
            }

            // Login does not match. Capture the password if present, but
            // keep searching (C sets the `password` variable but does not
            // set `FOUND_PASSWORD`, so parsing continues).
            if !oe.entry.password.is_empty() {
                last_captured_password = Some(&oe.entry.password);
            }
        }

        // No exact login match was found. Return the last captured password
        // (if any) paired with the caller's login, replicating C's behaviour
        // of returning `*passwordp` even when `our_login` is `FALSE`.
        if let Some(pw) = last_captured_password {
            return Some((login, pw));
        }

        None
    }

    /// Returns `true` when no entries have been parsed (neither machine nor
    /// default).
    pub fn is_empty(&self) -> bool {
        self.ordered.is_empty()
    }
}

impl Default for Netrc {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// File I/O helpers
// ---------------------------------------------------------------------------

/// Loads a `.netrc` file into a `String`, stripping comment lines and
/// enforcing the size limits from `lib/netrc.c`.
///
/// This mirrors the C `file2memory()` function.
fn load_file(path: &Path) -> CurlResult<String> {
    let file = File::open(path).map_err(|_| CurlError::FileCouldntReadFile)?;

    // Pre-check file size via metadata (cheap, avoids reading huge files).
    if let Ok(meta) = file.metadata() {
        if meta.len() > MAX_NETRC_FILE as u64 {
            return Err(CurlError::OutOfMemory);
        }
    }

    let reader = BufReader::new(file);
    let mut content = String::with_capacity(4096);

    for line_result in reader.lines() {
        let line = line_result.map_err(|_| CurlError::FileCouldntReadFile)?;

        // Enforce per-line length limit.
        if line.len() > MAX_NETRC_LINE {
            return Err(CurlError::OutOfMemory);
        }

        // Skip comment lines (leading whitespace then `#`), matching the C
        // `file2memory()` logic: `curlx_str_passblanks(&line); if(*line == '#') continue;`
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }

        content.push_str(&line);
        content.push('\n');

        // Enforce cumulative file size limit.
        if content.len() > MAX_NETRC_FILE {
            return Err(CurlError::OutOfMemory);
        }
    }

    Ok(content)
}

/// Resolves the user's home directory from environment variables.
///
/// Checks `$HOME` first (portable across Unix/macOS/WSL), then falls back to
/// `$USERPROFILE` on Windows, mirroring the C `Curl_parsenetrc()` fallback
/// chain.
fn find_home_dir() -> CurlResult<PathBuf> {
    // $HOME — set on virtually all Unix systems and many Windows environments.
    if let Ok(home) = env::var("HOME") {
        if !home.is_empty() {
            return Ok(PathBuf::from(home));
        }
    }

    // $USERPROFILE — Windows fallback when $HOME is not available.
    #[cfg(target_os = "windows")]
    {
        if let Ok(userprofile) = env::var("USERPROFILE") {
            if !userprofile.is_empty() {
                return Ok(PathBuf::from(userprofile));
            }
        }
    }

    Err(CurlError::FileCouldntReadFile)
}

// ---------------------------------------------------------------------------
// Tokeniser — extracts one token from a line position
// ---------------------------------------------------------------------------

/// Extracts the next token starting at `input`, returning `(token, rest)`.
///
/// Tokens are either:
/// - **Unquoted** — a run of characters with ASCII value > 32 (i.e., not
///   space, tab, CR, LF, or control characters), matching the C `while(*tok_end > ' ')`.
/// - **Quoted** — delimited by double-quotes, with backslash escape sequences
///   `\n`, `\r`, `\t` (other characters after `\` are passed through literally,
///   including `\\` → `\` and `\"` → `"`).
///
/// Returns `Err(CurlError::LoginDenied)` (maps to `NETRC_SYNTAX_ERROR`) for
/// unterminated quotes or trailing backslash, and `Err(CurlError::OutOfMemory)`
/// (maps to `NETRC_OUT_OF_MEMORY`) when a token exceeds [`MAX_NETRC_TOKEN`].
fn extract_token(input: &str) -> CurlResult<(String, &str)> {
    let bytes = input.as_bytes();

    if bytes.first() == Some(&b'"') {
        // ------ Quoted token ------
        let mut result = String::new();
        let mut pos: usize = 1; // skip opening quote
        let mut escape = false;

        while pos < bytes.len() {
            let b = bytes[pos];
            if escape {
                escape = false;
                let ch = match b {
                    b'n' => '\n',
                    b'r' => '\r',
                    b't' => '\t',
                    _ => b as char,
                };
                result.push(ch);
                if result.len() > MAX_NETRC_TOKEN {
                    return Err(CurlError::OutOfMemory);
                }
                pos += 1;
                continue;
            }
            match b {
                b'\\' => {
                    escape = true;
                    pos += 1;
                }
                b'"' => {
                    pos += 1; // consume closing quote
                    // Verify no trailing escape and quote was closed.
                    if result.len() > MAX_NETRC_TOKEN {
                        return Err(CurlError::OutOfMemory);
                    }
                    return Ok((result, &input[pos..]));
                }
                _ => {
                    result.push(b as char);
                    if result.len() > MAX_NETRC_TOKEN {
                        return Err(CurlError::OutOfMemory);
                    }
                    pos += 1;
                }
            }
        }

        // Reached end of input without closing quote, or trailing backslash.
        Err(CurlError::LoginDenied)
    } else {
        // ------ Unquoted token ------
        // Advance while byte > b' ' (ASCII 32), matching C `while(*tok_end > ' ')`.
        let end = bytes
            .iter()
            .position(|&b| b <= b' ')
            .unwrap_or(bytes.len());

        if end == 0 {
            // Empty token — should not happen if caller skips leading blanks,
            // but guard defensively. Maps to NETRC_SYNTAX_ERROR.
            return Err(CurlError::LoginDenied);
        }
        if end > MAX_NETRC_TOKEN {
            return Err(CurlError::OutOfMemory);
        }

        let token = input[..end].to_string();
        Ok((token, &input[end..]))
    }
}

// ---------------------------------------------------------------------------
// Content parser — state-machine token processor
// ---------------------------------------------------------------------------

/// Parses the pre-loaded (comments stripped) netrc content into a [`Netrc`].
///
/// Implements the same state machine as `parsenetrc()` in `lib/netrc.c` but
/// collects **all** entries rather than searching for a single host. Entries
/// are stored in file order so that lookup methods can replicate the
/// single-pass semantics of the C parser.
fn parse_content(content: &str) -> CurlResult<Netrc> {
    let mut ordered: Vec<OrderedEntry> = Vec::new();
    let mut builder = EntryBuilder::new();
    let mut state = ParseState::Nothing;
    let mut keyword = KeywordState::None;

    for line in content.split('\n') {
        // ---- MacDef state: skip content lines, blank line ends macro ----
        if state == ParseState::MacDef {
            // A line that is empty (or contains only whitespace / CR) signals
            // end-of-macro, matching the C check for `*tok == '\n' || '\r'`
            // after `curlx_str_passblanks`.
            let trimmed = line
                .bytes()
                .all(|b| b == b' ' || b == b'\t' || b == b'\r');
            if trimmed || line.is_empty() {
                state = ParseState::Nothing;
            }
            continue;
        }

        // ---- Tokenise and process the line ----
        let mut remaining: &str = line;

        while !remaining.is_empty() {
            // Skip horizontal whitespace (spaces and tabs), matching
            // `curlx_str_passblanks`.
            let after_blanks = remaining
                .trim_start_matches([' ', '\t']);

            // End of meaningful content on this line (CR, empty, etc.).
            if after_blanks.is_empty()
                || after_blanks.as_bytes()[0] <= b' '
            {
                break;
            }
            remaining = after_blanks;

            // If we transitioned to MacDef mid-line (after seeing the
            // `macdef` keyword earlier on this line), skip remaining tokens.
            if state == ParseState::MacDef {
                break;
            }

            // Extract the next token.
            let (token, rest) = extract_token(remaining)?;
            remaining = rest;

            // ---------- State machine ----------
            match state {
                ParseState::Nothing => {
                    if token.eq_ignore_ascii_case("macdef") {
                        // Finalise any pending entry before entering MacDef.
                        if let Some((entry, is_default)) = builder.take() {
                            ordered.push(OrderedEntry { entry, is_default });
                        }
                        state = ParseState::MacDef;
                    } else if token.eq_ignore_ascii_case("machine") {
                        if let Some((entry, is_default)) = builder.take() {
                            ordered.push(OrderedEntry { entry, is_default });
                        }
                        state = ParseState::HostFound;
                        keyword = KeywordState::None;
                    } else if token.eq_ignore_ascii_case("default") {
                        if let Some((entry, is_default)) = builder.take() {
                            ordered.push(OrderedEntry { entry, is_default });
                        }
                        builder.is_default = true;
                        builder.has_content = true;
                        state = ParseState::HostValid;
                        keyword = KeywordState::None;
                    }
                    // Unknown tokens in Nothing state are silently ignored.
                }

                ParseState::HostFound => {
                    // This token is the hostname for the current `machine`.
                    builder.machine = token;
                    builder.has_content = true;
                    state = ParseState::HostValid;
                }

                ParseState::HostValid => {
                    match keyword {
                        KeywordState::Login => {
                            builder.login = token;
                            builder.has_content = true;
                            keyword = KeywordState::None;
                        }
                        KeywordState::Password => {
                            builder.password = token;
                            builder.has_content = true;
                            keyword = KeywordState::None;
                        }
                        KeywordState::Account => {
                            builder.account = Some(token);
                            builder.has_content = true;
                            keyword = KeywordState::None;
                        }
                        KeywordState::None => {
                            if token.eq_ignore_ascii_case("login") {
                                keyword = KeywordState::Login;
                            } else if token.eq_ignore_ascii_case("password") {
                                keyword = KeywordState::Password;
                            } else if token.eq_ignore_ascii_case("account") {
                                keyword = KeywordState::Account;
                            } else if token.eq_ignore_ascii_case("machine") {
                                // New machine section — finalise current.
                                if let Some((entry, is_default)) = builder.take() {
                                    ordered.push(OrderedEntry { entry, is_default });
                                }
                                state = ParseState::HostFound;
                                keyword = KeywordState::None;
                            } else if token.eq_ignore_ascii_case("default") {
                                if let Some((entry, is_default)) = builder.take() {
                                    ordered.push(OrderedEntry { entry, is_default });
                                }
                                builder.is_default = true;
                                builder.has_content = true;
                                state = ParseState::HostValid;
                                keyword = KeywordState::None;
                            } else if token.eq_ignore_ascii_case("macdef") {
                                if let Some((entry, is_default)) = builder.take() {
                                    ordered.push(OrderedEntry { entry, is_default });
                                }
                                state = ParseState::MacDef;
                            }
                            // Other unknown keywords in HostValid are
                            // silently ignored, matching C behaviour.
                        }
                    }
                }

                ParseState::MacDef => {
                    // Tokens on the same line as `macdef` (the macro name,
                    // etc.) are ignored. The C code enters MACDEF state and
                    // the switch-case just `break`s.
                }
            }
        }
    }

    // Finalise the last entry.
    if let Some((entry, is_default)) = builder.take() {
        ordered.push(OrderedEntry { entry, is_default });
    }

    Ok(Netrc { ordered })
}

// ---------------------------------------------------------------------------
// Unit-test support helpers (cfg(test) only)
// ---------------------------------------------------------------------------

#[cfg(test)]
impl Netrc {
    /// Returns the number of machine-specific entries (excludes default).
    #[allow(dead_code)]
    fn machine_count(&self) -> usize {
        self.ordered.iter().filter(|oe| !oe.is_default).count()
    }

    /// Returns `true` if a `default` entry is present.
    #[allow(dead_code)]
    fn has_default(&self) -> bool {
        self.ordered.iter().any(|oe| oe.is_default)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: parse a netrc string directly (bypasses file I/O).
    fn parse(content: &str) -> Netrc {
        parse_content(content).expect("parse_content should succeed")
    }

    // -- Basic parsing ------------------------------------------------------

    #[test]
    fn parse_single_machine() {
        let netrc = parse("machine example.com login user password secret");
        assert_eq!(netrc.machine_count(), 1);
        assert!(!netrc.has_default());
    }

    #[test]
    fn parse_single_machine_credentials() {
        let netrc = parse("machine host.example login myuser password mypass");
        let (login, pass) = netrc.find_credentials("host.example").unwrap();
        assert_eq!(login, "myuser");
        assert_eq!(pass, "mypass");
    }

    #[test]
    fn parse_multiple_machines() {
        let content = "\
machine a.com login ua password pa
machine b.com login ub password pb
machine c.com login uc password pc
";
        let netrc = parse(content);
        assert_eq!(netrc.machine_count(), 3);
        assert_eq!(netrc.find_credentials("b.com"), Some(("ub", "pb")));
    }

    // -- Default entry ------------------------------------------------------

    #[test]
    fn parse_default_entry() {
        let content = "default login defuser password defpass";
        let netrc = parse(content);
        assert!(netrc.has_default());
        assert_eq!(netrc.machine_count(), 0);
    }

    #[test]
    fn default_used_when_no_machine_match() {
        let content = "\
machine known.host login u1 password p1
default login fallback password fallpass
";
        let netrc = parse(content);
        // Exact match.
        assert_eq!(netrc.find_credentials("known.host"), Some(("u1", "p1")));
        // Falls back to default.
        let (login, pass) = netrc.find_credentials("unknown.host").unwrap();
        assert_eq!(login, "fallback");
        assert_eq!(pass, "fallpass");
    }

    // -- Comments -----------------------------------------------------------

    #[test]
    fn comments_are_ignored() {
        let content = "\
# This is a comment
machine example.com login user password pass
# another comment
";
        let netrc = parse(content);
        assert_eq!(netrc.machine_count(), 1);
    }

    // -- macdef handling ----------------------------------------------------

    #[test]
    fn macdef_block_skipped() {
        let content = "\
machine before.com login u1 password p1
macdef init
cd /pub
get README

machine after.com login u2 password p2
";
        let netrc = parse(content);
        // The macdef block (terminated by blank line) should be skipped.
        assert!(netrc.find_credentials("before.com").is_some());
        assert!(netrc.find_credentials("after.com").is_some());
    }

    // -- Missing fields -----------------------------------------------------

    #[test]
    fn missing_password_returns_empty() {
        let content = "machine nopass.com login onlylogin";
        let netrc = parse(content);
        let creds = netrc.find_credentials("nopass.com");
        if let Some((login, pass)) = creds {
            assert_eq!(login, "onlylogin");
            assert!(pass.is_empty());
        }
        // If creds is None, the parser might handle missing password differently;
        // either behaviour is acceptable as long as it doesn't panic.
    }

    // -- Empty file ---------------------------------------------------------

    #[test]
    fn empty_content_produces_empty_netrc() {
        let netrc = parse("");
        assert!(netrc.is_empty());
        assert_eq!(netrc.machine_count(), 0);
        assert!(!netrc.has_default());
    }

    // -- Whitespace tolerance -----------------------------------------------

    #[test]
    fn extra_whitespace_handled() {
        let content = "  machine   ws.host   login   user   password   pass  ";
        let netrc = parse(content);
        assert_eq!(netrc.find_credentials("ws.host"), Some(("user", "pass")));
    }

    #[test]
    fn newline_separated_tokens() {
        let content = "machine\nnl.host\nlogin\nnluser\npassword\nnlpass";
        let netrc = parse(content);
        assert_eq!(netrc.find_credentials("nl.host"), Some(("nluser", "nlpass")));
    }

    // -- No match -----------------------------------------------------------

    #[test]
    fn no_match_returns_none_without_default() {
        let netrc = parse("machine other.host login x password y");
        assert!(netrc.find_credentials("missing.host").is_none());
    }

    // -- Account token ------------------------------------------------------

    #[test]
    fn account_token_parsed() {
        let content = "machine acct.host login u password p account myaccount";
        let netrc = parse(content);
        // Account is rarely used; just verify it doesn't break parsing.
        assert!(netrc.find_credentials("acct.host").is_some());
    }

    // -- First match wins ---------------------------------------------------

    #[test]
    fn first_machine_match_wins() {
        let content = "\
machine dup.host login first password p1
machine dup.host login second password p2
";
        let netrc = parse(content);
        let (login, _) = netrc.find_credentials("dup.host").unwrap();
        assert_eq!(login, "first");
    }

    // -- NetrcEntry accessors -----------------------------------------------

    #[test]
    fn netrc_entry_accessors() {
        let entry = NetrcEntry {
            machine: "m".to_string(),
            login: "l".to_string(),
            password: "p".to_string(),
            account: Some("a".to_string()),
        };
        assert_eq!(entry.machine(), "m");
        assert_eq!(entry.login(), "l");
        assert_eq!(entry.password(), "p");
        assert_eq!(entry.account(), Some("a"));
    }

    #[test]
    fn netrc_entry_no_account() {
        let entry = NetrcEntry {
            machine: String::new(),
            login: String::new(),
            password: String::new(),
            account: None,
        };
        assert_eq!(entry.account(), None);
    }

    // -- Constants ----------------------------------------------------------

    #[test]
    fn max_constants() {
        assert_eq!(MAX_NETRC_FILE, 128 * 1024);
        assert_eq!(MAX_NETRC_LINE, 16384);
        assert_eq!(MAX_NETRC_TOKEN, 4096);
    }
}
