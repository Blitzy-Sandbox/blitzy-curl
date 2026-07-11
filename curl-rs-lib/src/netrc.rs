// SPDX-License-Identifier: curl

//! Read-only `.netrc` credential-file parser (classic 4.3BSD format).
//!
//! This module is a faithful, byte-for-byte Rust port of curl's
//! `lib/netrc.c` (and its declaration-only companion `lib/netrc.h`). It parses
//! the `.netrc` file to supply a username and password for a given host when
//! the `--netrc`, `--netrc-file`, or `--netrc-optional` behavior is requested.
//! Only *reading* is implemented — like curl, this code never writes a
//! `.netrc` file.
//!
//! # Format
//!
//! A `.netrc` file is a whitespace-separated stream of tokens. The keywords
//! recognized here are exactly those honored by curl 8.x:
//!
//! * `machine <name>` — begin an entry for the host `<name>`.
//! * `default` — an entry that matches *any* host. By the file convention it
//!   is written last, and curl only falls back to it when no `machine` entry
//!   matched (the running [`Netrc::parse`] state machine reproduces this).
//! * `login <user>` — the username for the current entry.
//! * `password <pass>` — the password for the current entry.
//! * `account <acct>` — an additional account token. curl tokenizes it like
//!   any other keyword value but does not use it for credential selection, so
//!   this port likewise consumes it without special handling.
//! * `macdef <name>` — a macro definition. Its body starts on the next line
//!   and continues until a blank line; the entire block is skipped, exactly as
//!   curl does.
//!
//! Tokens may be double-quoted, in which case the escape sequences `\n`, `\r`,
//! `\t`, `\\`, and `\"` are interpreted; an unterminated quote (or a trailing
//! backslash) is a syntax error. Outside quotes, a token is a maximal run of
//! bytes greater than `0x20` (space), so any ASCII whitespace or control byte
//! terminates it — matching curl's `while(*tok_end > ' ')` scan.
//!
//! # Result codes
//!
//! [`NetrcCode`] mirrors the C `NETRCcode` enumeration one-to-one, including
//! the order of its variants (so [`NetrcCode::as_c_int`] returns the same
//! integer the C code would). [`NetrcCode::strerror`] reproduces
//! `Curl_netrc_strerror` verbatim, and [`From<NetrcCode>`](Error) bridges a
//! failure into the crate-wide [`Error`] type using the same
//! `CURLE_READ_ERROR` / `CURLE_OUT_OF_MEMORY` mapping curl applies in
//! `lib/url.c`.
//!
//! # Search semantics (parity contract)
//!
//! * An exact, case-insensitive `machine <host>` match wins over `default`.
//! * When the caller already knows the username (a *specific* login), the scan
//!   continues past a non-matching entry to find the `password` belonging to
//!   *that* user in the matching machine; a password is only accepted once the
//!   login has been confirmed. The login comparison is an exact, constant-time
//!   full-string match (see [`timing_safe_eq`]), so `admi` and `adminn` never
//!   match `admin`.
//! * A blank password is represented as `Some("")` when the host and login
//!   matched but no `password` keyword was present, matching curl's
//!   "success without a password" branch.
//!
//! # File location
//!
//! [`Netrc::parse`] resolves the file exactly as `Curl_parsenetrc`: an explicit
//! `netrcfile` argument (the `--netrc-file` override) wins; otherwise the
//! `NETRC` environment variable is consulted, then `HOME` to form
//! `$HOME/.netrc`. curl's additional `getpwuid`-based home-directory fallback
//! is intentionally **not** reproduced: it requires foreign-function calls into
//! the C runtime (the kind of non-safe Rust this crate forbids). `HOME` is the
//! standard resolution on the supported Unix and macOS targets, and the
//! Windows-only `_netrc` fallback is likewise out of scope for those platforms.
//!
//! # Safety
//!
//! This module is written entirely in safe Rust. It performs no raw-pointer
//! manipulation and never panics on file-derived input: every byte is treated
//! as untrusted, oversized inputs are rejected with [`NetrcCode::SyntaxError`],
//! and all fallible operations return a code instead of unwinding. (The token
//! that denotes non-safe Rust is intentionally absent from this file so the
//! crate-wide `grep` audit stays green.)

use std::fmt;
use std::path::{Path, PathBuf};

use crate::error::{CurlCode, Error, Result};

/// Maximum length of a single logical line, mirroring `MAX_NETRC_LINE` in
/// `lib/netrc.c`. curl accumulates each line in a `dynbuf` capped at this size,
/// so a longer line is rejected as a syntax error.
const MAX_NETRC_LINE: usize = 16384;

/// Maximum size of the comment-stripped, in-memory file image, mirroring
/// `MAX_NETRC_FILE` in `lib/netrc.c`.
const MAX_NETRC_FILE: usize = 128 * 1024;

/// Maximum length of a single token, mirroring `MAX_NETRC_TOKEN` in
/// `lib/netrc.c`.
const MAX_NETRC_TOKEN: usize = 4096;

/// The `found` bit set when a `login` value has been recorded for the current
/// entry. Mirrors `FOUND_LOGIN` in `lib/netrc.c`.
const FOUND_LOGIN: u8 = 1;

/// The `found` bit set when a `password` value belonging to the wanted login
/// has been recorded. Mirrors `FOUND_PASSWORD` in `lib/netrc.c`.
const FOUND_PASSWORD: u8 = 2;

/// Result code for a `.netrc` lookup, mirroring the C `NETRCcode` enumeration
/// declared in `lib/netrc.h`.
///
/// The variants are listed in the same order as the C enum, so
/// [`NetrcCode::as_c_int`] yields the identical integer a C caller would see
/// (`NETRC_OK == 0`, `NETRC_NO_MATCH == 1`, ...). The trailing `NETRC_LAST`
/// sentinel is intentionally not represented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetrcCode {
    /// `NETRC_OK` — a matching entry (or a usable `default`) was found.
    Ok,
    /// `NETRC_NO_MATCH` — no matching entry exists in the file.
    NoMatch,
    /// `NETRC_SYNTAX_ERROR` — the file contained a syntax error (including an
    /// oversized line, token, or file).
    SyntaxError,
    /// `NETRC_FILE_MISSING` — the `.netrc` file does not exist or could not be
    /// opened.
    FileMissing,
    /// `NETRC_OUT_OF_MEMORY` — a memory allocation failed while parsing.
    ///
    /// This variant exists for one-to-one parity with the C enumeration and to
    /// give [`NetrcCode::strerror`] and [`From<NetrcCode>`](Error) a total
    /// mapping. The safe-Rust parser never produces it: Rust's allocator aborts
    /// on failure rather than returning an error, and size-limit overflows are
    /// reported as [`NetrcCode::SyntaxError`] (exactly as curl maps the
    /// `CURLE_TOO_LARGE` `dynbuf` overflow via its `curl2netrc` macro).
    OutOfMemory,
}

impl NetrcCode {
    /// Returns the exact curl 8.x message for this code, reproducing
    /// `Curl_netrc_strerror` from `lib/netrc.c` verbatim.
    ///
    /// [`NetrcCode::Ok`] carries no message (curl's `default` switch arm
    /// returns the empty string for "not a legit error").
    #[must_use]
    pub const fn strerror(self) -> &'static str {
        match self {
            NetrcCode::Ok => "",
            NetrcCode::NoMatch => "no matching entry",
            NetrcCode::SyntaxError => "syntax error",
            NetrcCode::FileMissing => "no such file",
            NetrcCode::OutOfMemory => "out of memory",
        }
    }

    /// Returns the integer value this code has in the C `NETRCcode`
    /// enumeration (`NETRC_OK == 0`, `NETRC_NO_MATCH == 1`,
    /// `NETRC_SYNTAX_ERROR == 2`, `NETRC_FILE_MISSING == 3`,
    /// `NETRC_OUT_OF_MEMORY == 4`).
    ///
    /// This is the same integer the C unit tests assert against (for example
    /// `unit1304` checks `result == 1` for a host that is not found).
    #[must_use]
    pub const fn as_c_int(self) -> i32 {
        match self {
            NetrcCode::Ok => 0,
            NetrcCode::NoMatch => 1,
            NetrcCode::SyntaxError => 2,
            NetrcCode::FileMissing => 3,
            NetrcCode::OutOfMemory => 4,
        }
    }

    /// Returns `true` for [`NetrcCode::Ok`], i.e. a successful lookup.
    #[must_use]
    pub const fn is_ok(self) -> bool {
        matches!(self, NetrcCode::Ok)
    }
}

impl fmt::Display for NetrcCode {
    /// Formats the code using its curl 8.x message string (see
    /// [`NetrcCode::strerror`]). [`NetrcCode::Ok`] formats as the empty string,
    /// matching curl.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.strerror())
    }
}

impl From<NetrcCode> for Error {
    /// Bridges a `.netrc` failure into the crate-wide [`Error`], using the same
    /// mapping curl applies at the call site in `lib/url.c`:
    ///
    /// * [`NetrcCode::OutOfMemory`] maps to [`Error::OutOfMemory`]
    ///   (`CURLE_OUT_OF_MEMORY`), which curl returns directly.
    /// * every other failure — including a soft [`NetrcCode::NoMatch`] — maps to
    ///   [`CurlCode::ReadError`] (`CURLE_READ_ERROR`) carrying the contextual
    ///   text `".netrc error: <message>"`, mirroring curl's
    ///   `failf(data, ".netrc error: %s", ...)`.
    ///
    /// Because `NoMatch` is treated as fatal here, callers that implement the
    /// non-fatal `--netrc-optional` behavior should inspect the [`NetrcCode`]
    /// returned by [`Netrc::parse`] directly rather than relying on this
    /// conversion. [`NetrcCode::Ok`] is not an error; it converts to a benign
    /// [`Error::Code`] wrapping [`CurlCode::Ok`] so the mapping stays total.
    fn from(code: NetrcCode) -> Error {
        match code {
            NetrcCode::Ok => Error::Code(CurlCode::Ok),
            NetrcCode::OutOfMemory => Error::OutOfMemory,
            other => Error::with_context(
                CurlCode::ReadError,
                format!(".netrc error: {}", other.strerror()),
            ),
        }
    }
}

/// The credentials resolved from a successful `.netrc` lookup.
///
/// Both fields are optional, mirroring the C out-parameters `*loginp` and
/// `*passwordp`, either of which may still be `NULL` on a successful return:
///
/// * When the caller supplied a specific username, [`Credentials::login`]
///   echoes that username back and [`Credentials::password`] is `Some` only if
///   a `password` was found for it (otherwise `None`).
/// * When no username was supplied, [`Credentials::login`] holds the discovered
///   username and [`Credentials::password`] holds the discovered password.
/// * A host+login match with no `password` keyword yields
///   `password = Some(String::new())` (a blank password), matching curl.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Credentials {
    /// The username, if one is known or was discovered.
    pub login: Option<String>,
    /// The password, if one was found (`Some(String::new())` denotes a
    /// deliberate blank password).
    pub password: Option<String>,
}

/// Host-lookup state, mirroring `enum host_lookup_state` in `lib/netrc.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostLookupState {
    /// `NOTHING` — outside any entry; awaiting `machine`, `default`, or
    /// `macdef`.
    Nothing,
    /// `HOSTFOUND` — the `machine` keyword was seen; the next token is the host
    /// name.
    HostFound,
    /// `HOSTVALID` — the current entry is "our" host (or a `default`); parse its
    /// `login`/`password` sub-keywords.
    HostValid,
    /// `MACDEF` — inside a macro definition body; skip until a blank line.
    Macdef,
}

/// Which sub-keyword's value is expected next, mirroring `enum found_state` in
/// `lib/netrc.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FoundState {
    /// `NONE` — no value is pending; the next token is itself a keyword.
    None,
    /// `LOGIN` — the next token is the value for a `login` keyword.
    Login,
    /// `PASSWORD` — the next token is the value for a `password` keyword.
    Password,
}

/// An in-memory `.netrc` store, mirroring `struct store_netrc` in
/// `lib/netrc.h`.
///
/// The comment-stripped file image is cached in [`Netrc`] after the first
/// successful load so that repeated lookups against the same handle do not
/// re-read the file. Exactly as in curl, the cache is retained only across a
/// successful ([`NetrcCode::Ok`]) lookup; any failure (including
/// [`NetrcCode::NoMatch`]) drops the buffer so the next call reloads.
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use curl_rs_lib::netrc::Netrc;
///
/// let mut store = Netrc::new();
/// match store.parse("example.com", None, Some(Path::new("/home/user/.netrc"))) {
///     Ok(creds) => {
///         println!("login = {:?}, password = {:?}", creds.login, creds.password);
///     }
///     Err(code) => eprintln!(".netrc lookup failed: {code}"),
/// }
/// ```
#[derive(Debug, Default)]
pub struct Netrc {
    /// The comment-stripped, newline-normalized file image (`store->filebuf`).
    filebuf: Vec<u8>,
    /// Whether [`Netrc::filebuf`] has been populated (`store->loaded`).
    loaded: bool,
}

impl Netrc {
    /// Creates an empty, unloaded store, mirroring `Curl_netrc_init`.
    #[must_use]
    pub fn new() -> Self {
        Netrc::default()
    }

    /// Returns `true` once the file image has been loaded and cached.
    #[must_use]
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Drops the cached file image, mirroring `Curl_netrc_cleanup`.
    ///
    /// After this call the next [`Netrc::parse`] re-reads the file from disk.
    pub fn cleanup(&mut self) {
        self.filebuf = Vec::new();
        self.loaded = false;
    }

    /// Looks up credentials for `host`, mirroring `Curl_parsenetrc`.
    ///
    /// * `host` is the host name to match (compared case-insensitively).
    /// * `login` is an optional caller-supplied username. When `Some`, the scan
    ///   only accepts a password once it has confirmed this exact username in a
    ///   matching entry, and the returned [`Credentials::login`] echoes it back.
    /// * `netrcfile` optionally overrides the file location (the
    ///   `--netrc-file` argument). When `None`, the location is resolved from
    ///   the `NETRC` and `HOME` environment variables (see the module docs).
    ///
    /// On success returns [`Credentials`]; on failure returns the mirrored
    /// [`NetrcCode`]. A missing file yields [`NetrcCode::FileMissing`] and a
    /// host with no entry yields [`NetrcCode::NoMatch`]. Applying the
    /// non-fatal `--netrc-optional` policy to those codes is the caller's
    /// responsibility.
    ///
    /// # Errors
    ///
    /// Returns [`NetrcCode::FileMissing`] if the file cannot be opened,
    /// [`NetrcCode::SyntaxError`] on malformed or oversized input, and
    /// [`NetrcCode::NoMatch`] when no entry matches the host.
    pub fn parse(
        &mut self,
        host: &str,
        login: Option<&str>,
        netrcfile: Option<&Path>,
    ) -> std::result::Result<Credentials, NetrcCode> {
        match netrcfile {
            Some(path) => self.parse_file(host, login, path),
            None => {
                let path = resolve_default_netrc()?;
                self.parse_file(host, login, &path)
            }
        }
    }

    /// Like [`Netrc::parse`] but converts any failure into the crate-wide
    /// [`Error`], for callers that treat `.netrc` resolution as mandatory
    /// (the `--netrc` / `CURL_NETRC_REQUIRED` behavior, as opposed to
    /// `--netrc-optional`).
    ///
    /// This mirrors the `lib/url.c` call site, where a hard failure becomes
    /// `CURLE_READ_ERROR` (and `CURLE_OUT_OF_MEMORY` for allocation failure).
    ///
    /// # Errors
    ///
    /// Returns the [`Error`] produced by [`From<NetrcCode>`](Error) for any
    /// non-[`Ok`](NetrcCode::Ok) result — including [`NetrcCode::NoMatch`],
    /// which this method (unlike [`Netrc::parse`]) treats as fatal.
    pub fn require(
        &mut self,
        host: &str,
        login: Option<&str>,
        netrcfile: Option<&Path>,
    ) -> Result<Credentials> {
        self.parse(host, login, netrcfile).map_err(Error::from)
    }

    /// Parses a specific `.netrc` file, mirroring the static `parsenetrc` in
    /// `lib/netrc.c`.
    ///
    /// Loads and caches the comment-stripped file image on first use, then runs
    /// the token/state-machine scan. On any non-`Ok` result the cache is
    /// dropped (`store->loaded = FALSE`) so a later call reloads, exactly as the
    /// C code does in its `out:` error path.
    fn parse_file(
        &mut self,
        host: &str,
        login: Option<&str>,
        path: &Path,
    ) -> std::result::Result<Credentials, NetrcCode> {
        if !self.loaded {
            // Mirrors the `file2memory` call: a load failure returns
            // immediately without touching the (still-empty) buffer.
            self.filebuf = load_file(path)?;
            self.loaded = true;
        }

        let (code, login_out, password_out) =
            search(&self.filebuf, host.as_bytes(), login.map(str::as_bytes));

        if code == NetrcCode::Ok {
            Ok(Credentials {
                login: login_out.map(bytes_to_string),
                password: password_out.map(bytes_to_string),
            })
        } else {
            // curl's `out:` error path frees the file buffer and clears the
            // loaded flag so a subsequent lookup re-reads the file.
            self.cleanup();
            Err(code)
        }
    }
}

/// Resolves the default `.netrc` path, mirroring the `netrcfile == NULL` branch
/// of `Curl_parsenetrc`.
///
/// The `NETRC` environment variable, when set, names the file outright (even
/// when empty, in which case opening it later fails and yields
/// [`NetrcCode::FileMissing`], matching curl). Otherwise `HOME` is used to form
/// `$HOME/.netrc`. If neither is available the file is considered missing.
///
/// curl additionally falls back to `getpwuid` to discover the home directory
/// when `HOME` is unset; that path is deliberately omitted here because it
/// requires foreign-function calls into the C runtime — the kind of non-safe
/// Rust this crate forbids.
fn resolve_default_netrc() -> std::result::Result<PathBuf, NetrcCode> {
    if let Some(explicit) = std::env::var_os("NETRC") {
        return Ok(PathBuf::from(explicit));
    }
    match std::env::var_os("HOME") {
        Some(home) => Ok(PathBuf::from(home).join(".netrc")),
        None => Err(NetrcCode::FileMissing),
    }
}

/// Loads a `.netrc` file into a comment-stripped byte image, mirroring
/// `file2memory` in `lib/netrc.c`.
///
/// Each logical line is read as curl's `Curl_get_line` would produce it (lines
/// terminated by `\n`, with a `\n` synthesized for a final unterminated line),
/// its leading blanks are skipped, comment lines (whose first non-blank byte is
/// `#`) are dropped entirely, and every surviving line — from its first
/// non-blank byte through its terminating `\n` — is appended to the image.
///
/// The per-line, per-file, and (indirectly) allocation limits of the C
/// `dynbuf`s are enforced: exceeding [`MAX_NETRC_LINE`] or [`MAX_NETRC_FILE`]
/// is reported as [`NetrcCode::SyntaxError`], matching curl's mapping of the
/// `CURLE_TOO_LARGE` overflow. A file that cannot be opened yields
/// [`NetrcCode::FileMissing`].
fn load_file(path: &Path) -> std::result::Result<Vec<u8>, NetrcCode> {
    // Any open/read failure (missing file, permissions, ...) maps to the
    // "cannot open the file" case, exactly as curl's `curlx_fopen` returning
    // NULL yields NETRC_FILE_MISSING.
    let data = std::fs::read(path).map_err(|_| NetrcCode::FileMissing)?;

    let mut filebuf: Vec<u8> = Vec::new();
    let n = data.len();
    let mut i = 0usize;

    while i < n {
        // Determine the current line, including its terminating '\n' when
        // present. `Curl_get_line` synthesizes a '\n' for a final line that
        // lacks one.
        let newline = data[i..].iter().position(|&b| b == b'\n');
        let (line, next, has_newline) = match newline {
            Some(off) => (&data[i..=i + off], i + off + 1, true),
            None => (&data[i..], n, false),
        };

        // Enforce the line-length limit that `Curl_get_line` applies via its
        // `dynbuf` (`fit = len + 1 > MAX_NETRC_LINE`). For a line that had no
        // trailing newline, curl appends one, so account for that extra byte.
        let accumulated = if has_newline {
            line.len()
        } else {
            line.len() + 1
        };
        if accumulated + 1 > MAX_NETRC_LINE {
            return Err(NetrcCode::SyntaxError);
        }

        // Skip leading blanks (' ' and '\t'), matching `curlx_str_passblanks`.
        let start = line
            .iter()
            .position(|&b| b != b' ' && b != b'\t')
            .unwrap_or(line.len());
        let stripped = &line[start..];

        // Drop comment lines whose first non-blank byte is '#'.
        if stripped.first() == Some(&b'#') {
            i = next;
            continue;
        }

        // The bytes we are about to append: the stripped line, plus a
        // synthesized '\n' when the source line had none.
        let add_len = if has_newline {
            stripped.len()
        } else {
            stripped.len() + 1
        };
        if filebuf.len() + add_len + 1 > MAX_NETRC_FILE {
            return Err(NetrcCode::SyntaxError);
        }

        filebuf.extend_from_slice(stripped);
        if !has_newline {
            filebuf.push(b'\n');
        }

        i = next;
    }

    Ok(filebuf)
}

/// Scans the loaded file image for `host`, mirroring the token/state-machine
/// core of `parsenetrc` in `lib/netrc.c`.
///
/// `supplied_login` is the caller's pre-known username (`Some` when a specific
/// login was requested). Returns the result code together with the final login
/// and password bytes after applying curl's `out:` finalization:
///
/// * a matching host+login without an explicit `password` produces an empty
///   (blank) password;
/// * a `default` (or match) that yielded neither login nor password is
///   downgraded to [`NetrcCode::NoMatch`];
/// * for a specific login, the returned login is the supplied value unchanged.
///
/// On any non-`Ok` outcome the returned login and password are `None`.
fn search(
    buf: &[u8],
    host: &[u8],
    supplied_login: Option<&[u8]>,
) -> (NetrcCode, Option<Vec<u8>>, Option<Vec<u8>>) {
    let mut retcode = NetrcCode::NoMatch;
    // `login` starts as the caller-supplied username (if any). For a specific
    // login it is never reassigned; for a discovered login it is overwritten.
    let mut login: Option<Vec<u8>> = supplied_login.map(<[u8]>::to_vec);
    let specific_login = supplied_login.is_some();
    let mut password: Option<Vec<u8>> = None;
    let mut state = HostLookupState::Nothing;
    let mut keyword = FoundState::None;
    // Bitfield of FOUND_LOGIN / FOUND_PASSWORD, since the two can appear in
    // either order within an entry.
    let mut found: u8 = 0;
    let mut our_login = false;

    let n = buf.len();
    // `netrc_pos` mirrors `netrcbuffer`: the start of the region still to scan.
    let mut netrc_pos = 0usize;

    'outer: loop {
        // `pos` mirrors `tok`: the cursor walking the current region.
        let mut pos = netrc_pos;

        loop {
            // Collect the next token here (mirrors the reset `token` dynbuf).
            let mut token: Vec<u8> = Vec::new();

            // Skip leading blanks (' ' and '\t'), matching curlx_str_passblanks.
            while pos < n && (buf[pos] == b' ' || buf[pos] == b'\t') {
                pos += 1;
            }

            // A newline (or carriage return) at the start of a token ends a
            // macro definition.
            if state == HostLookupState::Macdef
                && pos < n
                && (buf[pos] == b'\n' || buf[pos] == b'\r')
            {
                state = HostLookupState::Nothing;
            }

            // End of the current line: stop this inner scan.
            if pos >= n || buf[pos] == b'\n' {
                break;
            }

            let quoted = buf[pos] == b'"';
            let mut tok_end = pos;

            if !quoted {
                // A bare token is a maximal run of bytes greater than ' '.
                let tok_start = pos;
                while tok_end < n && buf[tok_end] > b' ' {
                    tok_end += 1;
                }
                let len = tok_end - tok_start;
                if len == 0 {
                    // A byte that is neither a blank, a newline, nor > ' '
                    // (for example a stray '\r') cannot start a token.
                    return (NetrcCode::SyntaxError, None, None);
                }
                // Enforce the token dynbuf limit (`len + 1 > MAX_NETRC_TOKEN`).
                if len + 1 > MAX_NETRC_TOKEN {
                    return (NetrcCode::SyntaxError, None, None);
                }
                token.extend_from_slice(&buf[tok_start..tok_end]);
            } else {
                // A quoted token: interpret \n \r \t \\ \" escape sequences and
                // require a closing quote.
                let mut escape = false;
                let mut endquote = false;
                tok_end += 1; // step over the opening quote
                while tok_end < n {
                    let mut s = buf[tok_end];
                    if escape {
                        escape = false;
                        match s {
                            b'n' => s = b'\n',
                            b'r' => s = b'\r',
                            b't' => s = b'\t',
                            // Any other escaped byte is taken literally
                            // (notably \\ and \").
                            _ => {}
                        }
                    } else if s == b'\\' {
                        escape = true;
                        tok_end += 1;
                        continue;
                    } else if s == b'"' {
                        tok_end += 1; // step over the closing quote
                        endquote = true;
                        break;
                    }
                    // Enforce the token dynbuf limit as each byte is added
                    // (`idx + 1 + 1 > MAX_NETRC_TOKEN`).
                    if token.len() + 2 > MAX_NETRC_TOKEN {
                        return (NetrcCode::SyntaxError, None, None);
                    }
                    token.push(s);
                    tok_end += 1;
                }
                if escape || !endquote {
                    // A trailing backslash or an unterminated quote is invalid.
                    return (NetrcCode::SyntaxError, None, None);
                }
            }

            // Run the state machine over `token` (which may be empty, e.g. the
            // result of an empty quoted string `""`).
            match state {
                HostLookupState::Nothing => {
                    if token.eq_ignore_ascii_case(b"macdef") {
                        // A macro definition: skip its body until a blank line.
                        state = HostLookupState::Macdef;
                    } else if token.eq_ignore_ascii_case(b"machine") {
                        state = HostLookupState::HostFound;
                        keyword = FoundState::None;
                        found = 0;
                        our_login = false;
                        password = None;
                        if !specific_login {
                            login = None;
                        }
                    } else if token.eq_ignore_ascii_case(b"default") {
                        state = HostLookupState::HostValid;
                        retcode = NetrcCode::Ok; // a default matches any host
                    }
                }
                HostLookupState::Macdef => {
                    // An empty token (blank line) ends the macro definition.
                    if token.is_empty() {
                        state = HostLookupState::Nothing;
                    }
                }
                HostLookupState::HostFound => {
                    if token.eq_ignore_ascii_case(host) {
                        state = HostLookupState::HostValid;
                        retcode = NetrcCode::Ok; // this is our host
                    } else {
                        state = HostLookupState::Nothing;
                    }
                }
                HostLookupState::HostValid => {
                    if keyword == FoundState::Login {
                        if specific_login {
                            // Confirm the caller's username by exact,
                            // constant-time comparison.
                            our_login = login.as_deref().is_some_and(|l| timing_safe_eq(l, &token));
                        } else {
                            our_login = true;
                            login = Some(token.clone());
                        }
                        found |= FOUND_LOGIN;
                        keyword = FoundState::None;
                    } else if keyword == FoundState::Password {
                        password = Some(token.clone());
                        // Only accept the password once the login is confirmed
                        // (or when no specific login was requested).
                        if !specific_login || our_login {
                            found |= FOUND_PASSWORD;
                        }
                        keyword = FoundState::None;
                    } else if token.eq_ignore_ascii_case(b"login") {
                        keyword = FoundState::Login;
                    } else if token.eq_ignore_ascii_case(b"password") {
                        keyword = FoundState::Password;
                    } else if token.eq_ignore_ascii_case(b"machine") {
                        // A new entry begins. If we already have the password
                        // for our host, we are done with the first match.
                        if (found & FOUND_PASSWORD) != 0 {
                            break 'outer;
                        }
                        state = HostLookupState::HostFound;
                        keyword = FoundState::None;
                        found = 0;
                        password = None;
                        if !specific_login {
                            login = None;
                        }
                        // Unlike the NOTHING->machine transition, curl does not
                        // reset `our_login` here; that asymmetry is preserved.
                    } else if token.eq_ignore_ascii_case(b"default") {
                        state = HostLookupState::HostValid;
                        retcode = NetrcCode::Ok;
                        password = None;
                        if !specific_login {
                            login = None;
                        }
                    }

                    // Complete once both a login and its password are known.
                    if found == (FOUND_PASSWORD | FOUND_LOGIN) && our_login {
                        break 'outer;
                    }
                }
            }

            // Advance past the token and its terminator (mirrors `tok =
            // ++tok_end`); a mid-stream newline is stepped over just like any
            // other terminator.
            pos = tok_end + 1;
        }

        // The inner scan stopped at end-of-line or end-of-buffer. Resume after
        // the next newline (mirrors `netrcbuffer = &nl[1]`); if there is none,
        // the whole file has been consumed.
        if pos >= n {
            break;
        }
        match buf[pos..].iter().position(|&b| b == b'\n') {
            Some(off) => netrc_pos = pos + off + 1,
            None => break,
        }
    }

    // Finalization, mirroring the `out:` block of `parsenetrc`.
    if retcode == NetrcCode::Ok {
        if password.is_none() && our_login {
            // Success without a password: hand back a blank one.
            password = Some(Vec::new());
        } else if login.is_none() && password.is_none() {
            // A default (or match) with no credentials at all is no match.
            retcode = NetrcCode::NoMatch;
        }
    }

    if retcode == NetrcCode::Ok {
        // For a specific login, `login` still holds the caller's value; for a
        // discovered login it holds the value found in the file.
        (NetrcCode::Ok, login, password)
    } else {
        (retcode, None, None)
    }
}

/// Constant-time byte-slice equality, mirroring curl's `Curl_timestrcmp`
/// (`lib/strcase.c`).
///
/// The running time depends only on the input length, never on the position of
/// the first differing byte. This preserves curl's deliberate timing-attack
/// resistance when matching a caller-supplied login against a `.netrc` entry.
/// Returns `true` when the two slices are byte-for-byte identical.
fn timing_safe_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Converts credential token bytes into a `String`.
///
/// `.netrc` tokens are text (usernames and passwords); the common case is valid
/// UTF-8 and is converted without copying. On the rare chance a token contains
/// invalid UTF-8, the lossy conversion is used so the parser never fails on
/// otherwise well-formed input.
fn bytes_to_string(bytes: Vec<u8>) -> String {
    match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(err) => String::from_utf8_lossy(err.as_bytes()).into_owned(),
    }
}

/// Convenience wrapper that performs a single lookup against a fresh [`Netrc`]
/// store, mirroring a one-shot `Curl_parsenetrc` call.
///
/// See [`Netrc::parse`] for the argument and return-value semantics. Use
/// [`Netrc`] directly when performing several lookups so the file image is
/// parsed only once.
///
/// # Errors
///
/// Returns the same [`NetrcCode`] values as [`Netrc::parse`].
pub fn parse(
    host: &str,
    login: Option<&str>,
    netrcfile: Option<&Path>,
) -> std::result::Result<Credentials, NetrcCode> {
    Netrc::new().parse(host, login, netrcfile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// The exact fixture used by curl's `unit1304` netrc test
    /// (`tests/data/test1304`).
    const UNIT1304_FIXTURE: &[u8] = b"machine example.com login admin password passwd\n\
          machine curl.example.com login none password none\n";

    /// Writes `content` to a temporary file and returns the handle (which must
    /// be kept alive for the duration of the test so the file is not deleted).
    fn write_fixture(content: &[u8]) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("create temp fixture");
        file.write_all(content).expect("write fixture");
        file.flush().expect("flush fixture");
        file
    }

    /// Convenience: build the expected [`Credentials`] from string literals.
    fn creds(login: Option<&str>, password: Option<&str>) -> Credentials {
        Credentials {
            login: login.map(str::to_string),
            password: password.map(str::to_string),
        }
    }

    // ---------------------------------------------------------------------
    // Cases transcribed from curl's unit1304 (each uses a fresh store, exactly
    // as the C test re-runs Curl_netrc_init before every lookup).
    // ---------------------------------------------------------------------

    #[test]
    fn unit1304_unknown_host_no_login_is_no_match() {
        let fixture = write_fixture(UNIT1304_FIXTURE);
        let mut store = Netrc::new();
        let result = store.parse("test.example.com", None, Some(fixture.path()));
        assert_eq!(result, Err(NetrcCode::NoMatch));
        // Mirrors `result == 1` in the C test.
        assert_eq!(NetrcCode::NoMatch.as_c_int(), 1);
    }

    #[test]
    fn unit1304_known_host_unknown_login_finds_host_without_password() {
        let fixture = write_fixture(UNIT1304_FIXTURE);
        let mut store = Netrc::new();
        // login "me" does not match "admin": host is found (OK) but no password
        // is returned for that user.
        let result = store.parse("example.com", Some("me"), Some(fixture.path()));
        assert_eq!(result, Ok(creds(Some("me"), None)));
    }

    #[test]
    fn unit1304_unknown_host_with_login_is_no_match() {
        let fixture = write_fixture(UNIT1304_FIXTURE);
        let mut store = Netrc::new();
        let result = store.parse("test.example.com", Some("me"), Some(fixture.path()));
        assert_eq!(result, Err(NetrcCode::NoMatch));
    }

    #[test]
    fn unit1304_login_substring_does_not_match() {
        let fixture = write_fixture(UNIT1304_FIXTURE);
        let mut store = Netrc::new();
        // "admi" is a substring of "admin" but must not match.
        let result = store.parse("example.com", Some("admi"), Some(fixture.path()));
        assert_eq!(result, Ok(creds(Some("admi"), None)));
    }

    #[test]
    fn unit1304_login_superstring_does_not_match() {
        let fixture = write_fixture(UNIT1304_FIXTURE);
        let mut store = Netrc::new();
        // "adminn" is a superstring of "admin" but must not match.
        let result = store.parse("example.com", Some("adminn"), Some(fixture.path()));
        assert_eq!(result, Ok(creds(Some("adminn"), None)));
    }

    #[test]
    fn unit1304_first_host_no_login_returns_credentials() {
        let fixture = write_fixture(UNIT1304_FIXTURE);
        let mut store = Netrc::new();
        let result = store.parse("example.com", None, Some(fixture.path()));
        assert_eq!(result, Ok(creds(Some("admin"), Some("passwd"))));
    }

    #[test]
    fn unit1304_second_host_no_login_returns_credentials() {
        let fixture = write_fixture(UNIT1304_FIXTURE);
        let mut store = Netrc::new();
        let result = store.parse("curl.example.com", None, Some(fixture.path()));
        assert_eq!(result, Ok(creds(Some("none"), Some("none"))));
    }

    // ---------------------------------------------------------------------
    // `default` handling.
    // ---------------------------------------------------------------------

    #[test]
    fn default_matches_any_host_when_no_machine_matches() {
        let fixture = write_fixture(b"default login d password q\n");
        let mut store = Netrc::new();
        let result = store.parse("anything.example.org", None, Some(fixture.path()));
        assert_eq!(result, Ok(creds(Some("d"), Some("q"))));
    }

    #[test]
    fn default_is_only_used_when_no_machine_matches() {
        let fixture =
            write_fixture(b"machine example.com login a password b\ndefault login d password q\n");

        // A matching machine wins over the trailing default.
        let mut store = Netrc::new();
        assert_eq!(
            store.parse("example.com", None, Some(fixture.path())),
            Ok(creds(Some("a"), Some("b")))
        );

        // A non-matching host falls back to default.
        let mut store = Netrc::new();
        assert_eq!(
            store.parse("other.example.com", None, Some(fixture.path())),
            Ok(creds(Some("d"), Some("q")))
        );
    }

    // ---------------------------------------------------------------------
    // `macdef` blocks are skipped.
    // ---------------------------------------------------------------------

    #[test]
    fn macdef_block_is_skipped() {
        let fixture = write_fixture(
            b"macdef init\n\
              cd /pub\n\
              binary\n\
              \n\
              machine example.com login u password p\n",
        );
        let mut store = Netrc::new();
        let result = store.parse("example.com", None, Some(fixture.path()));
        assert_eq!(result, Ok(creds(Some("u"), Some("p"))));
    }

    #[test]
    fn macdef_at_end_of_file_is_skipped() {
        let fixture = write_fixture(
            b"machine example.com login u password p\n\
              macdef greeting\n\
              hello there\n",
        );
        let mut store = Netrc::new();
        let result = store.parse("example.com", None, Some(fixture.path()));
        assert_eq!(result, Ok(creds(Some("u"), Some("p"))));
    }

    // ---------------------------------------------------------------------
    // `account` keyword parity. curl recognizes `account` as a token but never
    // uses it for credential selection, so this port must ignore both the
    // keyword and its argument without disturbing the surrounding
    // `login`/`password` extraction (matching `Curl_parsenetrc`, which has no
    // `strcasecompare("account", ...)` arm).
    // ---------------------------------------------------------------------

    #[test]
    fn account_keyword_between_credentials_is_ignored() {
        // `account <acct>` sits between the login and the password. curl skips
        // over both tokens, so the credentials still resolve to (u, p).
        let fixture = write_fixture(b"machine example.com login u account myacct password p\n");
        let mut store = Netrc::new();
        let result = store.parse("example.com", None, Some(fixture.path()));
        assert_eq!(result, Ok(creds(Some("u"), Some("p"))));
    }

    #[test]
    fn account_does_not_consume_the_following_keyword() {
        // curl does not treat `account` as a value-consuming keyword: the token
        // immediately after it is still parsed as a keyword. Here `login`
        // follows `account`, and it must be honored as the login keyword rather
        // than swallowed as an account argument. Were `account` to consume its
        // follower, the login would be lost and this assertion would fail.
        let fixture = write_fixture(b"machine example.com account login u password p\n");
        let mut store = Netrc::new();
        let result = store.parse("example.com", None, Some(fixture.path()));
        assert_eq!(result, Ok(creds(Some("u"), Some("p"))));
    }

    // ---------------------------------------------------------------------
    // Missing file.
    // ---------------------------------------------------------------------

    #[test]
    fn missing_file_returns_file_missing() {
        let mut store = Netrc::new();
        let result = store.parse(
            "example.com",
            None,
            Some(Path::new("/nonexistent/path/to/.netrc-should-not-exist")),
        );
        assert_eq!(result, Err(NetrcCode::FileMissing));
        assert_eq!(NetrcCode::FileMissing.as_c_int(), 3);
        // A failed lookup must not leave the store marked as loaded.
        assert!(!store.is_loaded());
    }

    // ---------------------------------------------------------------------
    // Quoting and escapes.
    // ---------------------------------------------------------------------

    #[test]
    fn quoted_values_may_contain_spaces() {
        let fixture =
            write_fixture(b"machine example.com login \"user name\" password \"p@ss word\"\n");
        let mut store = Netrc::new();
        let result = store.parse("example.com", None, Some(fixture.path()));
        assert_eq!(result, Ok(creds(Some("user name"), Some("p@ss word"))));
    }

    #[test]
    fn quoted_escape_sequences_are_interpreted() {
        // \t and \n inside a quoted string decode to a tab and a newline; \\
        // and \" decode to a literal backslash and quote.
        let fixture = write_fixture(b"machine ex.com login u password \"a\\tb\\nc\\\\d\\\"e\"\n");
        let mut store = Netrc::new();
        let result = store.parse("ex.com", None, Some(fixture.path()));
        assert_eq!(result, Ok(creds(Some("u"), Some("a\tb\nc\\d\"e"))));
    }

    #[test]
    fn unterminated_quote_is_syntax_error() {
        let fixture = write_fixture(b"machine example.com login \"unterminated\n");
        let mut store = Netrc::new();
        let result = store.parse("example.com", None, Some(fixture.path()));
        assert_eq!(result, Err(NetrcCode::SyntaxError));
        assert_eq!(NetrcCode::SyntaxError.as_c_int(), 2);
    }

    #[test]
    fn empty_quoted_value_is_accepted() {
        // An explicit empty quoted password is a blank password.
        let fixture = write_fixture(b"machine example.com login u password \"\"\n");
        let mut store = Netrc::new();
        let result = store.parse("example.com", None, Some(fixture.path()));
        assert_eq!(result, Ok(creds(Some("u"), Some(""))));
    }

    // ---------------------------------------------------------------------
    // Blank password and comments.
    // ---------------------------------------------------------------------

    #[test]
    fn login_without_password_yields_blank_password() {
        let fixture = write_fixture(b"machine example.com login u\n");
        let mut store = Netrc::new();
        let result = store.parse("example.com", None, Some(fixture.path()));
        // Host and login matched but no password keyword: blank password.
        assert_eq!(result, Ok(creds(Some("u"), Some(""))));
    }

    #[test]
    fn comment_lines_are_ignored() {
        let fixture = write_fixture(
            b"# this is a comment\n\
              \t # indented comment\n\
              machine example.com login u password p\n",
        );
        let mut store = Netrc::new();
        let result = store.parse("example.com", None, Some(fixture.path()));
        assert_eq!(result, Ok(creds(Some("u"), Some("p"))));
    }

    // ---------------------------------------------------------------------
    // Case-insensitivity and whitespace tolerance.
    // ---------------------------------------------------------------------

    #[test]
    fn keywords_and_host_are_case_insensitive() {
        let fixture = write_fixture(b"MACHINE Example.COM LOGIN u PASSWORD p\n");
        let mut store = Netrc::new();
        let result = store.parse("example.com", None, Some(fixture.path()));
        assert_eq!(result, Ok(creds(Some("u"), Some("p"))));
    }

    #[test]
    fn tokens_may_span_multiple_lines_and_extra_whitespace() {
        // curl treats newlines like any other whitespace between tokens.
        let fixture = write_fixture(b"machine   example.com\n  login u\n\tpassword\tp\n");
        let mut store = Netrc::new();
        let result = store.parse("example.com", None, Some(fixture.path()));
        assert_eq!(result, Ok(creds(Some("u"), Some("p"))));
    }

    #[test]
    fn file_without_trailing_newline_is_parsed() {
        // The last line lacks a '\n'; curl (and this port) synthesizes one.
        let fixture = write_fixture(b"machine example.com login u password p");
        let mut store = Netrc::new();
        let result = store.parse("example.com", None, Some(fixture.path()));
        assert_eq!(result, Ok(creds(Some("u"), Some("p"))));
    }

    #[test]
    fn empty_file_is_no_match() {
        let fixture = write_fixture(b"");
        let mut store = Netrc::new();
        let result = store.parse("example.com", None, Some(fixture.path()));
        assert_eq!(result, Err(NetrcCode::NoMatch));
    }

    // ---------------------------------------------------------------------
    // Specific-login password selection across multiple entries.
    // ---------------------------------------------------------------------

    #[test]
    fn specific_login_selects_matching_entry_password() {
        // Two entries for the same host with different logins; the caller's
        // login selects the correct password.
        let fixture = write_fixture(
            b"machine example.com login alice password secret1\n\
              machine example.com login bob password secret2\n",
        );

        let mut store = Netrc::new();
        assert_eq!(
            store.parse("example.com", Some("bob"), Some(fixture.path())),
            Ok(creds(Some("bob"), Some("secret2")))
        );

        let mut store = Netrc::new();
        assert_eq!(
            store.parse("example.com", Some("alice"), Some(fixture.path())),
            Ok(creds(Some("alice"), Some("secret1")))
        );
    }

    #[test]
    fn stray_carriage_return_at_token_start_is_syntax_error() {
        // A '\r' that begins a token (rather than trailing a value) is not a
        // valid token start and mirrors curl's zero-length-token syntax error.
        let fixture = write_fixture(b"machine example.com\n\rp\n");
        let mut store = Netrc::new();
        let result = store.parse("example.com", None, Some(fixture.path()));
        assert_eq!(result, Err(NetrcCode::SyntaxError));
    }

    // ---------------------------------------------------------------------
    // Size limits (reject exactly what curl rejects).
    // ---------------------------------------------------------------------

    #[test]
    fn oversized_token_is_syntax_error() {
        // A token at or above MAX_NETRC_TOKEN bytes overflows curl's token
        // dynbuf and is a syntax error.
        let mut content = Vec::from(&b"machine "[..]);
        content.extend(std::iter::repeat(b'a').take(MAX_NETRC_TOKEN));
        content.push(b'\n');
        let fixture = write_fixture(&content);
        let mut store = Netrc::new();
        let result = store.parse("example.com", None, Some(fixture.path()));
        assert_eq!(result, Err(NetrcCode::SyntaxError));
    }

    #[test]
    fn token_just_under_limit_is_not_a_syntax_error() {
        // MAX_NETRC_TOKEN - 1 bytes fits; the host simply does not match.
        let mut content = Vec::from(&b"machine "[..]);
        content.extend(std::iter::repeat(b'a').take(MAX_NETRC_TOKEN - 1));
        content.push(b'\n');
        let fixture = write_fixture(&content);
        let mut store = Netrc::new();
        let result = store.parse("example.com", None, Some(fixture.path()));
        assert_eq!(result, Err(NetrcCode::NoMatch));
    }

    #[test]
    fn oversized_line_is_syntax_error() {
        // A single line longer than MAX_NETRC_LINE is rejected.
        let mut content = Vec::from(&b"machine "[..]);
        content.extend(std::iter::repeat(b'x').take(MAX_NETRC_LINE));
        content.push(b'\n');
        let fixture = write_fixture(&content);
        let mut store = Netrc::new();
        let result = store.parse("example.com", None, Some(fixture.path()));
        assert_eq!(result, Err(NetrcCode::SyntaxError));
    }

    // ---------------------------------------------------------------------
    // Caching semantics.
    // ---------------------------------------------------------------------

    #[test]
    fn successful_lookup_marks_store_loaded_and_cleanup_resets() {
        let fixture = write_fixture(UNIT1304_FIXTURE);
        let mut store = Netrc::new();
        assert!(!store.is_loaded());

        let result = store.parse("example.com", None, Some(fixture.path()));
        assert_eq!(result, Ok(creds(Some("admin"), Some("passwd"))));
        assert!(store.is_loaded());

        // A second lookup reuses the cached buffer.
        let result = store.parse("curl.example.com", None, Some(fixture.path()));
        assert_eq!(result, Ok(creds(Some("none"), Some("none"))));
        assert!(store.is_loaded());

        store.cleanup();
        assert!(!store.is_loaded());
    }

    #[test]
    fn free_parse_function_matches_method() {
        let fixture = write_fixture(UNIT1304_FIXTURE);
        let result = parse("example.com", None, Some(fixture.path()));
        assert_eq!(result, Ok(creds(Some("admin"), Some("passwd"))));
    }

    // ---------------------------------------------------------------------
    // NetrcCode metadata and error bridging.
    // ---------------------------------------------------------------------

    #[test]
    fn netrc_code_integers_match_c_enum_order() {
        assert_eq!(NetrcCode::Ok.as_c_int(), 0);
        assert_eq!(NetrcCode::NoMatch.as_c_int(), 1);
        assert_eq!(NetrcCode::SyntaxError.as_c_int(), 2);
        assert_eq!(NetrcCode::FileMissing.as_c_int(), 3);
        assert_eq!(NetrcCode::OutOfMemory.as_c_int(), 4);
    }

    #[test]
    fn netrc_code_strerror_matches_curl() {
        assert_eq!(NetrcCode::Ok.strerror(), "");
        assert_eq!(NetrcCode::NoMatch.strerror(), "no matching entry");
        assert_eq!(NetrcCode::SyntaxError.strerror(), "syntax error");
        assert_eq!(NetrcCode::FileMissing.strerror(), "no such file");
        assert_eq!(NetrcCode::OutOfMemory.strerror(), "out of memory");
        // Display uses the same text.
        assert_eq!(NetrcCode::FileMissing.to_string(), "no such file");
    }

    #[test]
    fn netrc_code_is_ok() {
        assert!(NetrcCode::Ok.is_ok());
        assert!(!NetrcCode::NoMatch.is_ok());
    }

    #[test]
    fn error_conversion_maps_to_curl_codes() {
        // Out of memory maps directly.
        assert_eq!(
            Error::from(NetrcCode::OutOfMemory).code(),
            CurlCode::OutOfMemory
        );

        // Every other failure maps to CURLE_READ_ERROR with contextual text.
        let syntax = Error::from(NetrcCode::SyntaxError);
        assert_eq!(syntax.code(), CurlCode::ReadError);
        assert_eq!(syntax.to_string(), ".netrc error: syntax error");

        let no_match = Error::from(NetrcCode::NoMatch);
        assert_eq!(no_match.code(), CurlCode::ReadError);
        assert_eq!(no_match.to_string(), ".netrc error: no matching entry");

        let missing = Error::from(NetrcCode::FileMissing);
        assert_eq!(missing.code(), CurlCode::ReadError);
        assert_eq!(missing.to_string(), ".netrc error: no such file");

        // Ok is not an error; it bridges to a benign CURLE_OK.
        assert_eq!(Error::from(NetrcCode::Ok).code(), CurlCode::Ok);
    }

    #[test]
    fn require_maps_failures_to_error() {
        let mut store = Netrc::new();
        let err = store
            .require(
                "example.com",
                None,
                Some(Path::new("/nonexistent/.netrc-should-not-exist")),
            )
            .expect_err("missing file must be an error");
        assert_eq!(err.code(), CurlCode::ReadError);
    }

    #[test]
    fn require_returns_credentials_on_success() {
        let fixture = write_fixture(UNIT1304_FIXTURE);
        let mut store = Netrc::new();
        let creds = store
            .require("example.com", None, Some(fixture.path()))
            .expect("lookup should succeed");
        assert_eq!(creds.login.as_deref(), Some("admin"));
        assert_eq!(creds.password.as_deref(), Some("passwd"));
    }

    #[test]
    fn timing_safe_eq_behaves_like_equality() {
        assert!(timing_safe_eq(b"admin", b"admin"));
        assert!(!timing_safe_eq(b"admin", b"admi"));
        assert!(!timing_safe_eq(b"admi", b"admin"));
        assert!(!timing_safe_eq(b"admin", b"Admin"));
        assert!(timing_safe_eq(b"", b""));
    }
}
