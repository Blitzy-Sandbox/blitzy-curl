//! `.netrc` credential-file support — a memory-safe Rust port of libcurl's
//! `lib/netrc.c` / `lib/netrc.h`.
//!
//! This module locates and parses a `.netrc` file (the path given by
//! `CURLOPT_NETRC_FILE`, the `NETRC` environment variable, or `$HOME/.netrc`)
//! and resolves the `login`/`password` for a requested host when
//! `CURLOPT_NETRC` is enabled. It is consumed by the option layer
//! (`crate::setopt` / `crate::easy`) and by credential resolution before
//! authentication (`crate::transfer` / `crate::protocols`); it is also reached
//! by the CLI (`curl-rs`) through the libcurl path.
//!
//! # Behavioral oracle
//!
//! The behavior here is a faithful reproduction of curl 8.x's `lib/netrc.c`
//! (`Curl_parsenetrc` / `Curl_netrc_init` / `Curl_netrc_cleanup`). It is *not* a
//! line-by-line transliteration of the C, but every externally observable
//! behavior is preserved exactly, because `.netrc` handling is part of curl's
//! behavioral contract (AAP §0.8.2) and the curl regression suite exercises it
//! unmodified (e.g. `tests/unit/unit1304.c`, `tests/data/test755`). In
//! particular this module reproduces:
//!
//! * the tokenizer for `machine <name>`, `default`, `login <user>`,
//!   `password <pass>`, and `macdef <name> … <blank line>` macro blocks
//!   (macro bodies are *skipped*, never interpreted), including quoted-string
//!   tokens (`\n`, `\r`, `\t`, `\"`, `\\` escapes) and full-line `#` comments;
//! * the host-matching rules — an exact (ASCII case-insensitive) `machine`
//!   match, falling back to a `default` block — and the existing-login-hint
//!   semantics (when a username is already set, curl matches `machine` + that
//!   `login`, discarding a password collected under a non-matching login);
//! * the `CURL_NETRC_OPTIONAL` / `CURL_NETRC_REQUIRED` / `CURL_NETRC_IGNORED`
//!   mode handling exactly as `lib/url.c:override_login` applies it;
//! * the file-location resolution order — explicit file, then `$NETRC`, then
//!   `$HOME/.netrc` (with the legacy `_netrc` fallback on Windows).
//!
//! ## The `account` keyword
//!
//! curl 8.19's `lib/netrc.c` does **not** recognize the `account` keyword in
//! its credential resolver — `account` and its value are ignored as unknown
//! tokens. To preserve byte-exact parity, [`lookup`] (the credential resolver)
//! likewise ignores it, so [`NetrcEntry::account`] is always `None` in lookup
//! results. The richer [`parse`] model *does* capture `account` for callers
//! that want to inspect a parsed file, using a deferred-capture rule that
//! provably never alters `login`/`password` resolution (an `account` value is
//! recorded only when the following token is not itself a structural keyword —
//! exactly the positions curl ignores anyway).
//!
//! ## Environment variables
//!
//! Only curl's *existing* environment variables are honored — `NETRC` and
//! `HOME` (plus `USERPROFILE` on Windows) — consistent with the
//! environment-passthrough rule (AAP §0.8.3). Honoring `$NETRC` is required for
//! parity with `tests/data/test755`, which sets `NETRC` and invokes `--netrc`.
//! No new environment variables are introduced.
//!
//! # Memory safety
//!
//! This module contains **zero** `unsafe` and compiles cleanly under the
//! crate-root `#![forbid(unsafe_code)]`. All file and environment access goes
//! through `std::fs`, `std::io`, and `std::env`; the C original's manual
//! `malloc`/`free` and `dynbuf` bookkeeping are replaced by owned `String`s and
//! `Vec`s with deterministic `Drop`.

use crate::error::{CurlError, Result};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// A resolved set of `.netrc` credentials for a host.
///
/// Mirrors the credential triple a `.netrc` `machine`/`default` block can
/// supply. Any field may be absent:
///
/// * `login` — the username (`login <user>`), or the caller-supplied login hint
///   when [`lookup`] was given one and the host matched.
/// * `password` — the password (`password <pass>`). curl yields an empty string
///   (`Some(String::new())`) rather than `None` when a matching `login` was
///   found but no `password` was present, matching `lib/netrc.c`'s
///   "success without a password" rule.
/// * `account` — the `account <acct>` value. Always `None` from [`lookup`]
///   (curl's resolver does not consult it); populated by [`parse`]'s model.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetrcEntry {
    /// The login/username for the matched entry, if any.
    pub login: Option<String>,
    /// The password for the matched entry, if any. May be an empty string when
    /// a login matched but no password was specified (see the type docs).
    pub password: Option<String>,
    /// The `account` value for the matched entry, if any. Always `None` from
    /// [`lookup`]; see the module-level note on the `account` keyword.
    pub account: Option<String>,
}

impl NetrcEntry {
    /// Returns `true` when no credential field is populated.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.login.is_none() && self.password.is_none() && self.account.is_none()
    }
}

/// The `.netrc` consultation mode, equivalent to curl's `enum
/// CURL_NETRC_OPTION` (`CURLOPT_NETRC`).
///
/// The integer values match the C macros exactly so the FFI/option layers can
/// round-trip the `long` option value through [`from_long`](Self::from_long) /
/// [`as_long`](Self::as_long):
///
/// * `CURL_NETRC_IGNORED  = 0` → [`Ignored`](Self::Ignored)
/// * `CURL_NETRC_OPTIONAL = 1` → [`Optional`](Self::Optional)
/// * `CURL_NETRC_REQUIRED = 2` → [`Required`](Self::Required)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurlNetrcOption {
    /// `CURL_NETRC_IGNORED` (0) — the `.netrc` file is never read. This is
    /// curl's default.
    Ignored,
    /// `CURL_NETRC_OPTIONAL` (1) — a `user:password` in the URL is preferred;
    /// the `.netrc` is consulted only as a fallback and missing/absent entries
    /// are not an error.
    Optional,
    /// `CURL_NETRC_REQUIRED` (2) — a `user:password` in the URL is ignored in
    /// favor of the `.netrc`; a missing file or a syntax error is a hard error.
    Required,
}

impl CurlNetrcOption {
    /// Returns the C integer value (`CURL_NETRC_*`) for this mode.
    #[must_use]
    pub const fn as_long(self) -> i64 {
        match self {
            CurlNetrcOption::Ignored => 0,
            CurlNetrcOption::Optional => 1,
            CurlNetrcOption::Required => 2,
        }
    }

    /// Maps a C `long` option value to a mode, returning `None` for any value
    /// outside the defined `CURL_NETRC_*` range (`0..=2`). curl rejects such
    /// values with `CURLE_BAD_FUNCTION_ARGUMENT` at the option layer.
    #[must_use]
    pub const fn from_long(value: i64) -> Option<Self> {
        match value {
            0 => Some(CurlNetrcOption::Ignored),
            1 => Some(CurlNetrcOption::Optional),
            2 => Some(CurlNetrcOption::Required),
            _ => None,
        }
    }
}

impl Default for CurlNetrcOption {
    /// `CURL_NETRC_IGNORED` — the curl default (the `.netrc` is not consulted
    /// unless `CURLOPT_NETRC` is explicitly enabled).
    fn default() -> Self {
        CurlNetrcOption::Ignored
    }
}

/// A single lexical unit produced by the tokenizer.
///
/// `EmptyLine` marks the points where curl's scanner observes a newline at the
/// top of its token loop. Its only semantic effect is to terminate a `macdef`
/// macro block (curl ends a macro at a blank line); in every other state it is
/// a no-op. Marking these points lets the resolver and model-builder reproduce
/// curl's macro-skipping exactly without re-deriving its pointer arithmetic.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Lexeme {
    /// A whitespace-delimited (or quoted) token.
    Word(String),
    /// A newline observed with no pending token — terminates a `macdef` block.
    EmptyLine,
}

/// ASCII case-insensitive token comparison, matching curl's `curl_strequal`
/// (used for keyword recognition and host matching).
fn ci_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Converts a raw token byte slice to an owned `String`.
///
/// `.netrc` files are byte-oriented in curl; credentials are almost always
/// ASCII/UTF-8. Invalid UTF-8 is replaced with the Unicode replacement
/// character (lossless for all ASCII/UTF-8 inputs, which covers every realistic
/// `.netrc` and the entire curl test suite).
fn bytes_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Normalizes raw file bytes into curl's in-memory line buffer, reproducing
/// `lib/netrc.c:file2memory` together with `Curl_get_line`.
///
/// For each line, in order: a trailing `\r` (CR / CRLF text-mode) is dropped,
/// leading blanks (space and tab — `ISBLANK`) are stripped, full-line comments
/// (first non-blank byte `#`) are removed entirely, and the surviving content
/// is emitted followed by a single `\n`. Every emitted line therefore ends with
/// exactly one `\n`, exactly as curl's `Curl_get_line` guarantees (it appends a
/// trailing newline at EOF). Blank lines survive as a bare `\n`, which the
/// scanner needs in order to terminate `macdef` blocks.
fn load(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 1);
    let len = content.len();
    let mut start = 0;
    while start < len {
        // Slice off the next physical line (excluding the '\n' terminator).
        let (line_end, next) = match content[start..].iter().position(|&b| b == b'\n') {
            Some(pos) => (start + pos, start + pos + 1),
            None => (len, len),
        };
        let mut line = &content[start..line_end];

        // Drop a trailing CR so a CRLF (or lone CR) line ending behaves like the
        // C runtime's text-mode read and never yields a stray control byte.
        if let Some((&b'\r', rest)) = line.split_last() {
            line = rest;
        }

        // Strip leading blanks (passblanks) before the comment test, mirroring
        // file2memory which advances past blanks and then adds the line.
        let mut ls = 0;
        while ls < line.len() && (line[ls] == b' ' || line[ls] == b'\t') {
            ls += 1;
        }
        let line = &line[ls..];

        // Full-line comment: first non-blank byte is '#'. Dropped entirely (it
        // leaves behind no blank line, exactly like the C `continue`).
        if line.first() == Some(&b'#') {
            start = next;
            continue;
        }

        // Truncate the line at the first embedded NUL byte, reproducing C
        // `file2memory` (lib/netrc.c L91): it appends each read line to the file
        // buffer with `curlx_dyn_add(filebuf, line)`, a C-string append that
        // stops at the first '\0'. A `.netrc` containing an embedded NUL — e.g.
        // `password<NUL> hello` — therefore truncates at the NUL, so the
        // `password` keyword is left with no following value and resolves to an
        // empty password (oracle: tests/data/test792, test793). Without this the
        // tokenizer (which treats NUL as a token terminator, byte <= ' ') would
        // skip the NUL and wrongly read `hello` as the password.
        let line = match line.iter().position(|&b| b == 0) {
            Some(nul) => &line[..nul],
            None => line,
        };

        out.extend_from_slice(line);
        out.push(b'\n');
        start = next;
    }
    out
}

/// Tokenizes the normalized line buffer into a stream of [`Lexeme`]s,
/// reproducing the token-scanning half of `lib/netrc.c:parsenetrc`.
///
/// Tokens are separated by blanks (space/tab) and newlines. An unquoted token
/// is a maximal run of bytes greater than `' '` (`0x20`); a zero-length token
/// (a stray control byte such as an embedded `\r`) is a syntax error, exactly
/// as curl's `if(!len)` check. A quoted token begins with `"` and supports the
/// `\n`/`\r`/`\t` escapes plus `\<other>` (which yields `<other>`, so `\"` is a
/// literal quote and `\\` a literal backslash); an unterminated quote or a
/// trailing backslash is a syntax error.
///
/// After each token curl advances by exactly one terminator byte
/// (`tok = ++tok_end`). Reproducing that single-byte skip is what makes an
/// end-of-line newline (consumed as a token's terminator, so the next line
/// flows on) distinct from a newline observed at the top of the loop (emitted
/// as [`Lexeme::EmptyLine`], the only thing that ends a `macdef`).
///
/// Returns `Err(())` on a syntax error (curl's `NETRC_SYNTAX_ERROR`).
fn lex(buf: &[u8]) -> core::result::Result<Vec<Lexeme>, ()> {
    let mut lexemes = Vec::new();
    let len = buf.len();
    let mut i = 0;

    loop {
        // passblanks: skip spaces and tabs only (never newline).
        while i < len && (buf[i] == b' ' || buf[i] == b'\t') {
            i += 1;
        }
        if i >= len {
            break;
        }

        let c = buf[i];
        if c == b'\n' {
            // A newline reached at the top of the loop: an empty line (or a line
            // whose only remaining content was trailing blanks). This is the
            // sole macdef terminator.
            lexemes.push(Lexeme::EmptyLine);
            i += 1;
            continue;
        }

        if c == b'"' {
            // Quoted token.
            let mut tok: Vec<u8> = Vec::new();
            i += 1; // consume the leading quote
            let mut escape = false;
            let mut endquote = false;
            while i < len {
                let mut s = buf[i];
                if escape {
                    escape = false;
                    match s {
                        b'n' => s = b'\n',
                        b'r' => s = b'\r',
                        b't' => s = b'\t',
                        _ => {}
                    }
                } else if s == b'\\' {
                    escape = true;
                    i += 1;
                    continue;
                } else if s == b'"' {
                    i += 1; // consume the closing quote
                    endquote = true;
                    break;
                }
                tok.push(s);
                i += 1;
            }
            if escape || !endquote {
                // Trailing backslash or unterminated quote: syntax error.
                return Err(());
            }
            lexemes.push(Lexeme::Word(bytes_to_string(&tok)));
            // tok = ++tok_end: skip one byte past the closing quote.
            i += 1;
        } else {
            // Unquoted token: a run of bytes strictly greater than ' '.
            let tstart = i;
            while i < len && buf[i] > b' ' {
                i += 1;
            }
            if i == tstart {
                // Zero-length token (a control byte <= ' ' that is not a blank
                // or newline): syntax error, matching curl's `if(!len)`.
                return Err(());
            }
            lexemes.push(Lexeme::Word(bytes_to_string(&buf[tstart..i])));
            // tok = ++tok_end: skip the single terminator byte.
            i += 1;
        }
    }

    Ok(lexemes)
}

// Found-bit flags, matching `lib/netrc.c`'s `FOUND_LOGIN` / `FOUND_PASSWORD`.
const FOUND_LOGIN: u8 = 1;
const FOUND_PASSWORD: u8 = 2;

/// Resolves credentials for `host` from a tokenized `.netrc`, a faithful port
/// of the state machine in `lib/netrc.c:parsenetrc`.
///
/// `login_hint` is the existing username (curl's `*loginp`): when present and
/// non-empty the search is "specific" — only a `password` collected under a
/// `login` that exactly (byte-for-byte, case-sensitively) matches the hint is
/// accepted, and the returned `login` is the hint itself. When absent/empty the
/// first matching block's `login` and `password` are taken. Per the documented
/// contract in `lib/netrc.h` ("if `(*loginp)[0] = 0`, search generally"), an
/// empty hint is treated as no hint.
///
/// Returns `Some(entry)` when the host (or a `default` block) matched and
/// yielded usable credentials (curl's `NETRC_OK`), or `None` when there was no
/// matching entry (`NETRC_NO_MATCH`). An `NETRC_OK` result whose `login` and
/// `password` are both absent (e.g. a bare `default`) is downgraded to `None`,
/// exactly as curl downgrades it to `NETRC_NO_MATCH`. The `account` field of
/// the returned entry is always `None` (curl's resolver does not consult it).
fn resolve_netrc(lexemes: &[Lexeme], host: &str, login_hint: Option<&str>) -> Option<NetrcEntry> {
    // specific_login mirrors curl's `!!login`, but per the netrc.h contract an
    // empty login means "search generally", so we treat it as no hint.
    let specific = matches!(login_hint, Some(h) if !h.is_empty());

    #[derive(PartialEq, Eq, Clone, Copy)]
    enum State {
        Nothing,
        HostFound,
        HostValid,
        Macdef,
    }
    #[derive(PartialEq, Eq, Clone, Copy)]
    enum Keyword {
        None,
        Login,
        Password,
    }

    let mut state = State::Nothing;
    let mut keyword = Keyword::None;
    let mut found: u8 = 0;
    let mut our_login = false;
    let mut done = false;
    // `retcode_ok` is curl's `retcode == NETRC_OK`: set the moment a host or a
    // `default` block matches.
    let mut retcode_ok = false;

    // `login` starts as the hint for a specific search (and is never reassigned
    // in that case, matching curl which leaves `*loginp` untouched); otherwise
    // it is filled from the file.
    let mut login: Option<String> = if specific {
        login_hint.map(str::to_string)
    } else {
        None
    };
    let mut password: Option<String> = None;

    for lex in lexemes {
        if done {
            break;
        }
        let tok = match lex {
            Lexeme::EmptyLine => {
                // The only effect of a blank line is to end a macro definition.
                if state == State::Macdef {
                    state = State::Nothing;
                }
                continue;
            }
            Lexeme::Word(w) => w.as_str(),
        };

        match state {
            State::Nothing => {
                if ci_eq(tok, "macdef") {
                    // A macro definition: its body is skipped until a blank line.
                    state = State::Macdef;
                } else if ci_eq(tok, "machine") {
                    state = State::HostFound;
                    keyword = Keyword::None;
                    found = 0;
                    our_login = false;
                    password = None;
                    if !specific {
                        login = None;
                    }
                } else if ci_eq(tok, "default") {
                    state = State::HostValid;
                    retcode_ok = true;
                }
                // Any other token in NOTHING is ignored.
            }
            State::Macdef => {
                // Tokens inside a macro body are skipped (the body ends at the
                // next blank line, handled by `Lexeme::EmptyLine`).
            }
            State::HostFound => {
                if ci_eq(host, tok) {
                    // This is our host.
                    state = State::HostValid;
                    retcode_ok = true;
                } else {
                    // Not our host; skip until the next machine/default.
                    state = State::Nothing;
                }
            }
            State::HostValid => {
                if keyword == Keyword::Login {
                    if specific {
                        // Constant-time-equivalent comparison is unnecessary for
                        // behavior; the boolean result is what curl uses.
                        our_login = login.as_deref() == Some(tok);
                    } else {
                        our_login = true;
                        login = Some(tok.to_string());
                    }
                    found |= FOUND_LOGIN;
                    keyword = Keyword::None;
                } else if keyword == Keyword::Password {
                    password = Some(tok.to_string());
                    if !specific || our_login {
                        found |= FOUND_PASSWORD;
                    }
                    keyword = Keyword::None;
                } else if ci_eq(tok, "login") {
                    keyword = Keyword::Login;
                } else if ci_eq(tok, "password") {
                    keyword = Keyword::Password;
                } else if ci_eq(tok, "machine") {
                    // A new machine block. If we already have a usable password
                    // we are done; otherwise reset and look for the next host.
                    if found & FOUND_PASSWORD != 0 {
                        done = true;
                    } else {
                        state = State::HostFound;
                        keyword = Keyword::None;
                        found = 0;
                        our_login = false;
                        password = None;
                        if !specific {
                            login = None;
                        }
                    }
                } else if ci_eq(tok, "default") {
                    // `default` stays valid; it resets the password (and the
                    // login for a general search) but not the found/our_login
                    // bookkeeping, matching curl.
                    state = State::HostValid;
                    retcode_ok = true;
                    password = None;
                    if !specific {
                        login = None;
                    }
                }
                // Any other token (including `account` and its value) is ignored.

                if !done && found == (FOUND_LOGIN | FOUND_PASSWORD) && our_login {
                    done = true;
                }
            }
        }
    }

    // `out:` fix-ups from curl. Only meaningful when a host/default matched.
    if retcode_ok {
        if password.is_none() && our_login {
            // Success without an explicit password: yield a blank password.
            password = Some(String::new());
        } else if login.is_none() && password.is_none() {
            // A matched block (e.g. a bare `default`) with no credentials is
            // treated as no match.
            retcode_ok = false;
        }
    }

    if retcode_ok {
        Some(NetrcEntry {
            login,
            password,
            account: None,
        })
    } else {
        None
    }
}

/// The outcome of consulting a single `.netrc` file, mirroring the `NETRCcode`
/// cases reachable in safe Rust (`NETRC_OUT_OF_MEMORY` cannot occur — Rust
/// aborts on allocation failure rather than returning).
enum Outcome {
    /// `NETRC_OK` — the host (or a `default`) matched and produced credentials.
    Found(NetrcEntry),
    /// `NETRC_NO_MATCH` — the file parsed but had no matching entry.
    NoMatch,
    /// `NETRC_FILE_MISSING` — the file does not exist or could not be opened.
    FileMissing,
    /// `NETRC_SYNTAX_ERROR` — the file contained a malformed token.
    SyntaxError,
}

/// Reads, tokenizes, and resolves a single `.netrc` file for `host`.
///
/// Any failure to open/read the file maps to [`Outcome::FileMissing`], matching
/// curl's `file2memory`, which treats a `NULL` `fopen` result (for any reason)
/// as `NETRC_FILE_MISSING`.
fn lookup_file(path: &Path, host: &str, login_hint: Option<&str>) -> Outcome {
    let content = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(_) => return Outcome::FileMissing,
    };
    let filebuf = load(&content);
    let lexemes = match lex(&filebuf) {
        Ok(lexemes) => lexemes,
        Err(()) => return Outcome::SyntaxError,
    };
    match resolve_netrc(&lexemes, host, login_hint) {
        Some(entry) => Outcome::Found(entry),
        None => Outcome::NoMatch,
    }
}

/// Looks up credentials for `host` in the `.netrc` file at `file`.
///
/// This is the direct equivalent of curl's `Curl_parsenetrc` for an explicit
/// file path. `login_hint` is an existing username to match (see
/// [`resolve_netrc`] for the exact hint semantics); pass `None` to take the
/// first matching block's login.
///
/// Returns:
/// * `Ok(Some(entry))` — the host (or a `default` block) matched
///   (`NETRC_OK`). The entry's `password` may be an empty string when a login
///   matched but no password was given, and `None` when (for a specific hint)
///   the host matched but the login did not.
/// * `Ok(None)` — the file was read but contained no matching entry
///   (`NETRC_NO_MATCH`).
/// * `Err(CurlError::ReadError)` — the file does not exist / could not be read
///   (`NETRC_FILE_MISSING`) or contained a malformed token
///   (`NETRC_SYNTAX_ERROR`). This matches the `CURLE_READ_ERROR` that
///   `lib/url.c:override_login` raises for a `.netrc` error. Callers that need
///   `CURL_NETRC_OPTIONAL`-style "missing is fine" semantics should use
///   [`resolve`], which applies the mode rules.
pub fn lookup(file: &Path, host: &str, login_hint: Option<&str>) -> Result<Option<NetrcEntry>> {
    match lookup_file(file, host, login_hint) {
        Outcome::Found(entry) => Ok(Some(entry)),
        Outcome::NoMatch => Ok(None),
        Outcome::FileMissing | Outcome::SyntaxError => Err(CurlError::ReadError),
    }
}

/// Returns the user's home directory from the environment, honoring only curl's
/// existing variables.
///
/// On all platforms `HOME` is consulted first (empty is treated as unset). On
/// Windows, `USERPROFILE` is the fallback, matching `Curl_parsenetrc`. curl's
/// additional `getpwuid` fallback is intentionally omitted: it requires
/// `unsafe`/libc, which is forbidden here, and the environment-passthrough rule
/// (AAP §0.8.3) mandates resolving the home directory via `HOME`.
fn home_dir() -> Option<PathBuf> {
    let home = env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    #[cfg(windows)]
    {
        home.or_else(|| {
            env::var_os("USERPROFILE")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        })
    }
    #[cfg(not(windows))]
    {
        home
    }
}

/// Pure file-path resolution, decoupled from the process environment for
/// testability. Implements curl's order: an explicit file wins; otherwise the
/// `NETRC` environment value (used verbatim, even when empty, exactly as
/// `curl_getenv("NETRC")`); otherwise `<home>/.netrc`.
fn resolve_path(
    explicit: Option<&Path>,
    netrc_env: Option<OsString>,
    home: Option<PathBuf>,
) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.to_path_buf());
    }
    if let Some(env_value) = netrc_env {
        return Some(PathBuf::from(env_value));
    }
    home.map(|h| h.join(".netrc"))
}

/// Resolves the `.netrc` file path curl would use, given an optional explicit
/// path (`CURLOPT_NETRC_FILE`).
///
/// Resolution order (matching `Curl_parsenetrc`):
/// 1. the explicit path, if provided;
/// 2. the `NETRC` environment variable, if set (required for parity with
///    `tests/data/test755`, which sets `NETRC` and runs `--netrc`);
/// 3. `$HOME/.netrc` (with `USERPROFILE` as the home fallback on Windows).
///
/// Returns `None` only when no path can be determined (no explicit path, no
/// `NETRC`, and no home directory) — curl's `NETRC_FILE_MISSING` "no home
/// directory" case. The legacy Windows `_netrc` fallback is applied by
/// [`resolve`], which is where curl applies it (only after a missing `.netrc`).
#[must_use]
pub fn find_file(explicit: Option<&Path>) -> Option<PathBuf> {
    resolve_path(explicit, env::var_os("NETRC"), home_dir())
}

/// Resolves `.netrc` credentials for `host` honoring a [`CurlNetrcOption`]
/// mode, reproducing the `.netrc` portion of `lib/url.c:override_login`.
///
/// `explicit_file` is the `CURLOPT_NETRC_FILE` value (or `None` to use the
/// environment/home default). `login_hint` is any existing username.
///
/// Behavior by mode:
/// * [`Ignored`](CurlNetrcOption::Ignored) — the file is never read;
///   `Ok(None)`.
/// * [`Optional`](CurlNetrcOption::Optional) — a missing file, a syntax error,
///   or no matching entry all yield `Ok(None)` ("using defaults"); never an
///   error.
/// * [`Required`](CurlNetrcOption::Required) — no matching entry yields
///   `Ok(None)`, but a missing file or a syntax error is
///   `Err(CurlError::ReadError)` (curl's `CURLE_READ_ERROR`).
///
/// Note: the protocol-specific control-character check that
/// `override_login` performs on the resolved credentials is intentionally left
/// to the caller (it depends on the connection's protocol flags, not on
/// `.netrc` parsing).
pub fn resolve(
    option: CurlNetrcOption,
    explicit_file: Option<&Path>,
    host: &str,
    login_hint: Option<&str>,
) -> Result<Option<NetrcEntry>> {
    if option == CurlNetrcOption::Ignored {
        return Ok(None);
    }
    let optional = option == CurlNetrcOption::Optional;

    let primary = match find_file(explicit_file) {
        Some(path) => path,
        None => {
            // No file could be located (curl's "no home directory" →
            // NETRC_FILE_MISSING).
            return if optional {
                Ok(None)
            } else {
                Err(CurlError::ReadError)
            };
        }
    };

    let outcome = lookup_file(&primary, host, login_hint);

    // Windows-only legacy fallback: when the default `.netrc` is missing, curl
    // retries `<home>/_netrc`. Only applies to the pure default path (no
    // explicit file and no `NETRC` override). Implemented as cfg-gated
    // shadowing so the binding needs no `mut` on non-Windows targets (where the
    // fallback is compiled out) — keeping `clippy -D warnings` clean everywhere.
    #[cfg(windows)]
    let outcome = if matches!(outcome, Outcome::FileMissing)
        && explicit_file.is_none()
        && env::var_os("NETRC").is_none()
    {
        match home_dir() {
            Some(home) => lookup_file(&home.join("_netrc"), host, login_hint),
            None => outcome,
        }
    } else {
        outcome
    };

    match outcome {
        Outcome::Found(entry) => Ok(Some(entry)),
        // NETRC_NO_MATCH is benign in every mode.
        Outcome::NoMatch => Ok(None),
        // Missing file / syntax error: benign only when optional.
        Outcome::FileMissing | Outcome::SyntaxError => {
            if optional {
                Ok(None)
            } else {
                Err(CurlError::ReadError)
            }
        }
    }
}

/// A single parsed `machine` or `default` block from a `.netrc` file.
///
/// Part of the [`Netrc`] inspection model produced by [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetrcMachine {
    /// The host name from a `machine <name>` block, or `None` for a `default`
    /// block.
    pub name: Option<String>,
    /// The credentials accumulated within the block (last value wins for a
    /// repeated keyword, matching curl).
    pub entry: NetrcEntry,
}

/// A parsed `.netrc` file: an ordered list of `machine`/`default` blocks.
///
/// Produced by [`parse`]. The [`machines`](Self::machines) accessor exposes the
/// blocks for inspection (this is where the `account` keyword is surfaced),
/// while [`lookup`](Self::lookup) performs credential resolution that is
/// byte-for-byte identical to the free [`lookup`] function — both run the same
/// faithful resolver over the file's token stream, so they never disagree.
#[derive(Debug, Clone)]
pub struct Netrc {
    machines: Vec<NetrcMachine>,
    // Retained so `lookup` can run the authoritative resolver rather than
    // re-deriving credential resolution from the (lossy) block model.
    lexemes: Vec<Lexeme>,
}

impl Netrc {
    /// The parsed `machine`/`default` blocks, in file order.
    #[must_use]
    pub fn machines(&self) -> &[NetrcMachine] {
        &self.machines
    }

    /// Resolves credentials for `host` exactly as the free [`lookup`] function
    /// does (same resolver, same token stream), honoring an optional
    /// `login_hint`. Returns `None` when there is no matching entry. The
    /// returned entry's `account` is always `None`; inspect
    /// [`machines`](Self::machines) for `account` values.
    #[must_use]
    pub fn lookup(&self, host: &str, login_hint: Option<&str>) -> Option<NetrcEntry> {
        resolve_netrc(&self.lexemes, host, login_hint)
    }
}

/// `true` if `tok` is one of the structural keywords curl acts on inside a host
/// block. Used by [`build_machines`] for parity-safe deferred `account`
/// capture.
fn is_structural_keyword(tok: &str) -> bool {
    ci_eq(tok, "login")
        || ci_eq(tok, "password")
        || ci_eq(tok, "machine")
        || ci_eq(tok, "default")
        || ci_eq(tok, "account")
}

/// Builds the inspection model (ordered `machine`/`default` blocks) from a
/// token stream.
///
/// Block delimiting (`machine`/`default`/`macdef`) follows curl's state
/// machine. `account` is captured with a deferred rule that provably never
/// changes `login`/`password`: an `account` keyword is remembered, and its
/// following token is recorded as the account value *only* if that token is not
/// itself a structural keyword (precisely the tokens curl ignores anyway). If
/// the following token is structural, it is processed normally — identical to
/// curl, which never recognizes `account` at all.
fn build_machines(lexemes: &[Lexeme]) -> Vec<NetrcMachine> {
    #[derive(PartialEq, Eq, Clone, Copy)]
    enum State {
        Nothing,
        HostFound,
        HostValid,
        Macdef,
    }
    #[derive(PartialEq, Eq, Clone, Copy)]
    enum Keyword {
        None,
        Login,
        Password,
    }

    let mut machines: Vec<NetrcMachine> = Vec::new();
    let mut cur: Option<NetrcMachine> = None;
    let mut state = State::Nothing;
    let mut keyword = Keyword::None;
    let mut pending_account = false;

    // Push the in-progress block (if any) to the output list.
    fn flush(machines: &mut Vec<NetrcMachine>, cur: &mut Option<NetrcMachine>) {
        if let Some(machine) = cur.take() {
            machines.push(machine);
        }
    }

    for lex in lexemes {
        let tok = match lex {
            Lexeme::EmptyLine => {
                if state == State::Macdef {
                    state = State::Nothing;
                }
                pending_account = false;
                continue;
            }
            Lexeme::Word(w) => w.as_str(),
        };

        match state {
            State::Nothing => {
                if ci_eq(tok, "macdef") {
                    state = State::Macdef;
                } else if ci_eq(tok, "machine") {
                    flush(&mut machines, &mut cur);
                    state = State::HostFound;
                    keyword = Keyword::None;
                    pending_account = false;
                } else if ci_eq(tok, "default") {
                    flush(&mut machines, &mut cur);
                    cur = Some(NetrcMachine {
                        name: None,
                        entry: NetrcEntry::default(),
                    });
                    state = State::HostValid;
                    keyword = Keyword::None;
                    pending_account = false;
                }
            }
            State::Macdef => { /* macro body: skipped */ }
            State::HostFound => {
                // This token is the machine name.
                cur = Some(NetrcMachine {
                    name: Some(tok.to_string()),
                    entry: NetrcEntry::default(),
                });
                state = State::HostValid;
                keyword = Keyword::None;
                pending_account = false;
            }
            State::HostValid => {
                // Deferred, parity-safe `account` capture.
                if keyword == Keyword::None && pending_account {
                    pending_account = false;
                    if !is_structural_keyword(tok) {
                        if let Some(machine) = cur.as_mut() {
                            machine.entry.account = Some(tok.to_string());
                        }
                        continue;
                    }
                    // Structural keyword: fall through and process normally.
                }

                if keyword == Keyword::Login {
                    if let Some(machine) = cur.as_mut() {
                        machine.entry.login = Some(tok.to_string());
                    }
                    keyword = Keyword::None;
                } else if keyword == Keyword::Password {
                    if let Some(machine) = cur.as_mut() {
                        machine.entry.password = Some(tok.to_string());
                    }
                    keyword = Keyword::None;
                } else if ci_eq(tok, "login") {
                    keyword = Keyword::Login;
                } else if ci_eq(tok, "password") {
                    keyword = Keyword::Password;
                } else if ci_eq(tok, "account") {
                    pending_account = true;
                } else if ci_eq(tok, "machine") {
                    flush(&mut machines, &mut cur);
                    state = State::HostFound;
                    keyword = Keyword::None;
                    pending_account = false;
                } else if ci_eq(tok, "default") {
                    flush(&mut machines, &mut cur);
                    cur = Some(NetrcMachine {
                        name: None,
                        entry: NetrcEntry::default(),
                    });
                    state = State::HostValid;
                    keyword = Keyword::None;
                    pending_account = false;
                }
                // Any other token is ignored.
            }
        }
    }

    flush(&mut machines, &mut cur);
    machines
}

/// Parses raw `.netrc` bytes into the [`Netrc`] inspection model.
///
/// Returns `Err(CurlError::ReadError)` on a malformed token
/// (`NETRC_SYNTAX_ERROR`).
fn parse_bytes(content: &[u8]) -> Result<Netrc> {
    let filebuf = load(content);
    let lexemes = lex(&filebuf).map_err(|()| CurlError::ReadError)?;
    let machines = build_machines(&lexemes);
    Ok(Netrc { machines, lexemes })
}

/// Parses a `.netrc` file from any byte source into the [`Netrc`] model.
///
/// The reader is consumed to end. This tokenizes the full `.netrc` grammar
/// (`machine`/`default`/`login`/`password`/`account`/`macdef`, quoted tokens,
/// and full-line comments); use [`Netrc::lookup`] to resolve credentials or
/// [`Netrc::machines`] to inspect the parsed blocks.
///
/// Returns `Err` if the reader fails (mapped from [`std::io::Error`]) or the
/// content has a syntax error (`CurlError::ReadError`).
pub fn parse<R: Read>(mut reader: R) -> Result<Netrc> {
    let mut content = Vec::new();
    reader.read_to_end(&mut content)?;
    parse_bytes(&content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// The exact fixture used by curl's `tests/unit/unit1304.c` /
    /// `tests/data/test1304`. Every assertion below mirrors a `fail_unless` /
    /// `abort_unless` from that unit test, making it the parity oracle.
    const FIXTURE: &str = "machine example.com login admin password passwd\n\
                           machine curl.example.com login none password none\n";

    /// A self-cleaning temporary `.netrc` file for the file-based tests. Files
    /// live in the OS temp dir (never the repository) and are removed on drop
    /// (even on panic).
    struct TempNetrc(PathBuf);

    impl TempNetrc {
        fn new(content: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let mut path = std::env::temp_dir();
            path.push(format!(
                "blitzy_adhoc_test_netrc_{}_{}.netrc",
                std::process::id(),
                n
            ));
            std::fs::write(&path, content).unwrap();
            TempNetrc(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
        /// A path guaranteed not to exist (for the file-missing cases).
        fn missing() -> PathBuf {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let mut path = std::env::temp_dir();
            path.push(format!(
                "blitzy_adhoc_test_netrc_missing_{}_{}.netrc",
                std::process::id(),
                n
            ));
            let _ = std::fs::remove_file(&path);
            path
        }
    }

    impl Drop for TempNetrc {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn fixture() -> Netrc {
        parse_bytes(FIXTURE.as_bytes()).expect("fixture parses")
    }

    // ---- curl unit1304 parity cases -------------------------------------

    #[test]
    fn u1304_nonexistent_host_no_login() {
        // Host not found, no login hint => NETRC_NO_MATCH (None).
        assert_eq!(fixture().lookup("test.example.com", None), None);
    }

    #[test]
    fn u1304_nonexistent_login_existing_host() {
        // Host found, specific login "me" not present => OK but no password.
        let entry = fixture()
            .lookup("example.com", Some("me"))
            .expect("host found => Some");
        assert_eq!(entry.password, None, "password must be absent");
    }

    #[test]
    fn u1304_nonexistent_login_and_host() {
        assert_eq!(fixture().lookup("test.example.com", Some("me")), None);
    }

    #[test]
    fn u1304_login_substring_does_not_match() {
        // "admi" is a substring of "admin" but must not match.
        let entry = fixture()
            .lookup("example.com", Some("admi"))
            .expect("host found => Some");
        assert_eq!(entry.password, None);
    }

    #[test]
    fn u1304_login_superstring_does_not_match() {
        // "adminn" is a superstring of "admin" but must not match.
        let entry = fixture()
            .lookup("example.com", Some("adminn"))
            .expect("host found => Some");
        assert_eq!(entry.password, None);
    }

    #[test]
    fn u1304_first_host_no_login_hint() {
        // login==NULL: take the block's own login + password.
        let entry = fixture().lookup("example.com", None).expect("found");
        assert_eq!(entry.login.as_deref(), Some("admin"));
        assert_eq!(entry.password.as_deref(), Some("passwd"));
    }

    #[test]
    fn u1304_second_host_no_login_hint() {
        let entry = fixture().lookup("curl.example.com", None).expect("found");
        assert_eq!(entry.login.as_deref(), Some("none"));
        assert_eq!(entry.password.as_deref(), Some("none"));
    }

    #[test]
    fn u1304_free_lookup_matches_model_lookup() {
        // The free `lookup(file, ...)` must agree with `Netrc::lookup` exactly.
        let tf = TempNetrc::new(FIXTURE);
        let model = fixture();
        for (host, hint) in [
            ("example.com", None),
            ("example.com", Some("me")),
            ("example.com", Some("admin")),
            ("curl.example.com", None),
            ("test.example.com", None),
        ] {
            let free = lookup(tf.path(), host, hint).expect("no error");
            let modeled = model.lookup(host, hint);
            assert_eq!(free, modeled, "host={host} hint={hint:?}");
        }
    }

    // ---- tokenizer behavior --------------------------------------------

    #[test]
    fn full_line_comments_are_ignored() {
        let netrc =
            parse_bytes(b"# a comment\n  # indented comment\nmachine x login u password p\n")
                .unwrap();
        let entry = netrc.lookup("x", None).expect("found");
        assert_eq!(entry.login.as_deref(), Some("u"));
        assert_eq!(entry.password.as_deref(), Some("p"));
    }

    #[test]
    fn hash_inside_token_is_not_a_comment() {
        // '#' only starts a comment as the first non-blank byte of a line.
        let netrc = parse_bytes(b"machine x login u password pa#ss\n").unwrap();
        assert_eq!(
            netrc.lookup("x", None).unwrap().password.as_deref(),
            Some("pa#ss")
        );
    }

    #[test]
    fn quoted_tokens_with_spaces_and_escapes() {
        // login "u ser", password "p\"a\\b\tc"
        let content = "machine x login \"u ser\" password \"p\\\"a\\\\b\\tc\"\n";
        let netrc = parse_bytes(content.as_bytes()).unwrap();
        let entry = netrc.lookup("x", None).expect("found");
        assert_eq!(entry.login.as_deref(), Some("u ser"));
        assert_eq!(entry.password.as_deref(), Some("p\"a\\b\tc"));
    }

    #[test]
    fn macdef_body_is_skipped() {
        // The macro body must not be parsed as machine/login/password tokens.
        let content = "macdef init\n\
                       machine bogus login bad password bad\n\
                       \n\
                       machine x login u password p\n";
        let netrc = parse_bytes(content.as_bytes()).unwrap();
        // "bogus" was inside the macro body, so it must not resolve.
        assert_eq!(netrc.lookup("bogus", None), None);
        let entry = netrc.lookup("x", None).expect("found after macro");
        assert_eq!(entry.login.as_deref(), Some("u"));
        assert_eq!(entry.password.as_deref(), Some("p"));
    }

    #[test]
    fn unterminated_quote_is_syntax_error() {
        assert!(parse_bytes(b"machine x login \"unterminated\n").is_err());
        let tf = TempNetrc::new("machine x login \"unterminated\n");
        assert!(matches!(
            lookup(tf.path(), "x", None),
            Err(CurlError::ReadError)
        ));
    }

    #[test]
    fn trailing_backslash_in_quote_is_syntax_error() {
        // Quote closes but the final in-quote byte is a dangling escape.
        assert!(parse_bytes(b"machine x login \"abc\\\n").is_err());
    }

    // ---- host / keyword matching ---------------------------------------

    #[test]
    fn host_and_keywords_are_case_insensitive() {
        let netrc = parse_bytes(b"MACHINE Example.COM LOGIN admin PASSWORD secret\n").unwrap();
        let entry = netrc.lookup("example.com", None).expect("found");
        assert_eq!(entry.login.as_deref(), Some("admin"));
        assert_eq!(entry.password.as_deref(), Some("secret"));
    }

    #[test]
    fn default_block_is_fallback() {
        let content = "machine a login la password pa\n\
                       default login ld password pd\n";
        let netrc = parse_bytes(content.as_bytes()).unwrap();
        // Specific machine still wins.
        let a = netrc.lookup("a", None).expect("found a");
        assert_eq!(a.login.as_deref(), Some("la"));
        assert_eq!(a.password.as_deref(), Some("pa"));
        // Unknown host falls back to default.
        let other = netrc.lookup("unknown.example", None).expect("default");
        assert_eq!(other.login.as_deref(), Some("ld"));
        assert_eq!(other.password.as_deref(), Some("pd"));
    }

    #[test]
    fn bare_default_without_credentials_is_no_match() {
        let netrc = parse_bytes(b"default\n").unwrap();
        assert_eq!(netrc.lookup("anything", None), None);
    }

    #[test]
    fn login_without_password_yields_blank_password() {
        // curl's "success without a password" rule: last block, login matched,
        // no password => blank password string.
        let netrc = parse_bytes(b"machine x login u\n").unwrap();
        let entry = netrc.lookup("x", None).expect("found");
        assert_eq!(entry.login.as_deref(), Some("u"));
        assert_eq!(entry.password.as_deref(), Some(""));
    }

    #[test]
    fn specific_login_matches_when_present() {
        let netrc =
            parse_bytes(b"machine x login alice password apw\nmachine x login bob password bpw\n")
                .unwrap();
        // Hint "bob" should pick bob's password from the second block.
        let entry = netrc.lookup("x", Some("bob")).expect("found");
        assert_eq!(entry.password.as_deref(), Some("bpw"));
    }

    // ---- account keyword (model only) ----------------------------------

    #[test]
    fn account_captured_in_model_not_in_lookup() {
        let netrc = parse_bytes(b"machine x login u account acct password p\n").unwrap();
        // Model surfaces account.
        let m = &netrc.machines()[0];
        assert_eq!(m.name.as_deref(), Some("x"));
        assert_eq!(m.entry.login.as_deref(), Some("u"));
        assert_eq!(m.entry.password.as_deref(), Some("p"));
        assert_eq!(m.entry.account.as_deref(), Some("acct"));
        // Lookup ignores account (curl parity) but still resolves login/password.
        let entry = netrc.lookup("x", None).expect("found");
        assert_eq!(entry.login.as_deref(), Some("u"));
        assert_eq!(entry.password.as_deref(), Some("p"));
        assert_eq!(entry.account, None);
    }

    #[test]
    fn account_followed_by_keyword_does_not_swallow_it() {
        // Parity-safe deferred capture: `account` immediately before `password`
        // must not consume the `password` keyword as the account value.
        let netrc = parse_bytes(b"machine x login u account password p\n").unwrap();
        let m = &netrc.machines()[0];
        assert_eq!(m.entry.password.as_deref(), Some("p"));
        // The account value was the structural keyword's slot, so account stays
        // unset — identical to curl, which ignores `account` entirely.
        assert_eq!(m.entry.account, None);
    }

    // ---- file path resolution ------------------------------------------

    #[test]
    fn resolve_path_prefers_explicit() {
        let explicit = Path::new("/tmp/explicit.netrc");
        let got = resolve_path(
            Some(explicit),
            Some(OsString::from("/env/netrc")),
            Some(PathBuf::from("/home/user")),
        );
        assert_eq!(got, Some(PathBuf::from("/tmp/explicit.netrc")));
    }

    #[test]
    fn resolve_path_uses_netrc_env_when_no_explicit() {
        let got = resolve_path(
            None,
            Some(OsString::from("/env/netrc")),
            Some(PathBuf::from("/home/user")),
        );
        assert_eq!(got, Some(PathBuf::from("/env/netrc")));
    }

    #[test]
    fn resolve_path_falls_back_to_home_dotnetrc() {
        let got = resolve_path(None, None, Some(PathBuf::from("/home/user")));
        assert_eq!(got, Some(PathBuf::from("/home/user/.netrc")));
    }

    #[test]
    fn resolve_path_none_when_nothing_available() {
        assert_eq!(resolve_path(None, None, None), None);
    }

    // ---- mode handling (resolve) ---------------------------------------

    #[test]
    fn mode_ignored_never_reads_file() {
        // Even a missing explicit file must not error in IGNORED mode.
        let missing = TempNetrc::missing();
        assert_eq!(
            resolve(CurlNetrcOption::Ignored, Some(&missing), "x", None).unwrap(),
            None
        );
    }

    #[test]
    fn mode_required_missing_file_errors() {
        let missing = TempNetrc::missing();
        assert!(matches!(
            resolve(CurlNetrcOption::Required, Some(&missing), "x", None),
            Err(CurlError::ReadError)
        ));
    }

    #[test]
    fn mode_optional_missing_file_is_ok_none() {
        let missing = TempNetrc::missing();
        assert_eq!(
            resolve(CurlNetrcOption::Optional, Some(&missing), "x", None).unwrap(),
            None
        );
    }

    #[test]
    fn mode_required_match_returns_credentials() {
        let tf = TempNetrc::new(FIXTURE);
        let entry = resolve(
            CurlNetrcOption::Required,
            Some(tf.path()),
            "example.com",
            None,
        )
        .unwrap()
        .expect("match");
        assert_eq!(entry.login.as_deref(), Some("admin"));
        assert_eq!(entry.password.as_deref(), Some("passwd"));
    }

    #[test]
    fn mode_required_no_match_is_ok_none() {
        let tf = TempNetrc::new(FIXTURE);
        assert_eq!(
            resolve(
                CurlNetrcOption::Required,
                Some(tf.path()),
                "absent.example",
                None
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn mode_optional_syntax_error_is_ok_none_but_required_errors() {
        let bad = TempNetrc::new("machine x login \"oops\n");
        assert_eq!(
            resolve(CurlNetrcOption::Optional, Some(bad.path()), "x", None).unwrap(),
            None
        );
        assert!(matches!(
            resolve(CurlNetrcOption::Required, Some(bad.path()), "x", None),
            Err(CurlError::ReadError)
        ));
    }

    // ---- lookup file errors --------------------------------------------

    #[test]
    fn lookup_missing_file_is_error() {
        let missing = TempNetrc::missing();
        assert!(matches!(
            lookup(&missing, "x", None),
            Err(CurlError::ReadError)
        ));
    }

    #[test]
    fn lookup_no_match_is_ok_none() {
        let tf = TempNetrc::new(FIXTURE);
        assert_eq!(lookup(tf.path(), "absent.example", None).unwrap(), None);
    }

    // ---- small types ----------------------------------------------------

    #[test]
    fn netrc_option_long_roundtrip() {
        for (mode, value) in [
            (CurlNetrcOption::Ignored, 0),
            (CurlNetrcOption::Optional, 1),
            (CurlNetrcOption::Required, 2),
        ] {
            assert_eq!(mode.as_long(), value);
            assert_eq!(CurlNetrcOption::from_long(value), Some(mode));
        }
        assert_eq!(CurlNetrcOption::from_long(3), None);
        assert_eq!(CurlNetrcOption::from_long(-1), None);
        assert_eq!(CurlNetrcOption::default(), CurlNetrcOption::Ignored);
    }

    #[test]
    fn netrc_entry_is_empty() {
        assert!(NetrcEntry::default().is_empty());
        assert!(!NetrcEntry {
            login: Some("u".into()),
            ..Default::default()
        }
        .is_empty());
    }

    #[test]
    fn parse_from_reader() {
        // `parse` accepts any Read source.
        let netrc = parse(FIXTURE.as_bytes()).unwrap();
        assert_eq!(netrc.machines().len(), 2);
        assert_eq!(netrc.machines()[0].name.as_deref(), Some("example.com"));
    }

    #[test]
    fn empty_file_is_no_match() {
        let netrc = parse_bytes(b"").unwrap();
        assert_eq!(netrc.lookup("anything", None), None);
        assert!(netrc.machines().is_empty());
    }

    #[test]
    fn crlf_line_endings_are_handled() {
        let netrc = parse_bytes(b"machine x login u password p\r\n").unwrap();
        let entry = netrc.lookup("x", None).expect("found");
        assert_eq!(entry.login.as_deref(), Some("u"));
        assert_eq!(entry.password.as_deref(), Some("p"));
    }
}
