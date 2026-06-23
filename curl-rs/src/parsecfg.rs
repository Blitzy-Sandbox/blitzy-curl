//! curl configuration-file parser for the `curl-rs` CLI (`-K`/`--config`,
//! and the implicit `~/.curlrc`).
//!
//! This module is the Rust reimplementation of curl's `src/tool_parsecfg.c`
//! (and its header `src/tool_parsecfg.h`). It reads a curl *config file* — the
//! file named by `-K`/`--config`, or the default per-user `.curlrc` — parsing
//! its **one-option-per-line** syntax (with quoting, escaping, comments, and
//! `:`/`=` separators) and dispatching each directive through the *exact same*
//! option machinery as the command line, [`crate::args::get_parameter`].
//!
//! # Behavioral parity (AAP §0.8.2)
//!
//! The config-file grammar and its error mapping must match curl byte-for-byte
//! so that an existing `.curlrc` behaves identically under `curl-rs`. This port
//! reproduces every observable detail of `tool_parsecfg.c`:
//!
//! * **Separators (`ISSEP`)** — a bare colon or equals sign acts as the
//!   option/parameter separator *only* when the option token has **no** leading
//!   dash. So `data: x` and `data = x` split on the `:`/`=`, while `--data=x`
//!   keeps the `=` as part of the option token (the inline value is then split
//!   off by [`crate::args::get_parameter`] itself). See [`split_line`].
//! * **Quoting / escaping (`unslashquote`)** — a double-quoted parameter
//!   unescapes `\t`, `\n`, `\r`, `\v`; any other `\x` yields the literal `x`
//!   (the backslash is dropped); the parameter ends at the first unescaped `"`.
//! * **Comments / blank lines** — a line whose first non-blank column is `#`,
//!   and any blank line, is skipped (`my_get_line`).
//! * **`--next`** — when [`crate::args::get_parameter`] reports
//!   [`ParameterError::NextOperation`] *and* the current operation already has a
//!   URL, a fresh [`crate::config::OperationConfig`] is started via
//!   [`crate::config::GlobalConfig::add_operation`]; otherwise `--next` is
//!   silently ignored (this matches `tool_parsecfg.c`, and differs from the
//!   command-line driver which errors on a leading `--next`).
//! * **Error mapping** — an unknown option becomes
//!   [`ParameterError::ConfigOptionUnknown`] (not the plain
//!   [`ParameterError::OptionUnknown`] the command line uses), a leftover
//!   unused parameter becomes [`ParameterError::GotExtraParameter`], a quoting
//!   failure becomes [`ParameterError::BadUse`], and a file read failure becomes
//!   [`ParameterError::ReadError`]. The informational/control-flow codes
//!   (`--help`, `--version`, …) are not treated as errors. The diagnostic text
//!   is produced by [`crate::args::param2text`], emitted via
//!   [`crate::messages::errorf`], exactly as curl does.
//!
//! # Recursion
//!
//! A `-K`/`--config` directive *inside* a config file recurses back through
//! [`crate::args::get_parameter`]; the recursion-depth guard
//! ([`CONFIG_MAX_LEVELS`]) lives in that option handler (`opt_file`), which
//! decrements `max_recursive` and refuses to descend past zero. [`parseconfig`]
//! therefore simply forwards the received `max_recursive` to every
//! `get_parameter` call and performs no depth check of its own.
//!
//! # Constraints
//!
//! * No `unsafe` (`#![forbid(unsafe_code)]`).
//! * Depends on `curl_rs_lib` only (never `curl-rs-ffi`); the only crates used
//!   here are `std` and the sibling CLI modules `args`, `config`, `messages`.

#![forbid(unsafe_code)]
// The CLI is assembled file-by-file; `parseconfig` is already driven by
// `args::opt_file` (`-K`/`--config`), but [`CONFIG_MAX_LEVELS`] is consumed by
// `operate.rs` (the implicit `.curlrc` load), which lands in a later migration
// step. `allow(dead_code)` keeps the not-yet-wired public constant from tripping
// the workspace `-D warnings` gate, mirroring the construction-staging
// convention used by the other CLI modules. It is removed once `operate.rs`
// references the constant.
#![allow(dead_code)]

use std::fs::File;
use std::io::{self, BufRead, BufReader};

use crate::args::{get_parameter, param2text, ParameterError};
use crate::config::GlobalConfig;
use crate::messages::{errorf, warnf};

/// The maximum number of nested `-K`/`--config` levels curl will follow
/// (`CONFIG_MAX_LEVELS`, `src/tool_parsecfg.h`).
///
/// The top-level CLI driver seeds the first [`parseconfig`] call (and the
/// implicit `.curlrc` load in `operate.rs`) with this value; each nested
/// `--config` inside a file decrements it in `args::opt_file`, which refuses to
/// recurse once it would go negative.
pub const CONFIG_MAX_LEVELS: i32 = 5;

/// The maximum length of a single config-file line — and of a single quoted
/// parameter — in bytes (`MAX_CONFIG_LINE_LENGTH`, `src/tool_cfgable.h`,
/// `10 * 1024 * 1024`, i.e. 10 MiB, since curl 8.2.0). Exceeding it is treated
/// as a read error (for an over-long line) or [`ParameterError::BadUse`] (for an
/// over-long quoted parameter), matching curl's dynamic-buffer cap.
const MAX_CONFIG_LINE_LENGTH: usize = 10 * 1024 * 1024;

/// `ISBLANK` — curl treats only space and horizontal tab as "blank".
#[inline]
fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// `ISSPACE` — curl's whitespace set (the C `isspace` class): space, tab, line
/// feed, vertical tab, form feed, and carriage return. Used to terminate an
/// unquoted parameter so a trailing `\r` from a CRLF line ending also stops it.
#[inline]
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// `ISSEP(x, dash)` — a colon or equals sign is acknowledged as an
/// option/parameter separator *only* when the option token was **not** written
/// with a leading dash (`#define ISSEP(x, dash) (!(dash) && ...)`).
#[inline]
fn is_sep(b: u8, dashed: bool) -> bool {
    !dashed && (b == b'=' || b == b':')
}

/// Copy a double-quoted parameter, unescaping backslash-quoted characters, and
/// stop at the first non-backslash-quoted double-quote (or end of input).
///
/// Port of `unslashquote` (`src/tool_parsecfg.c`). `s` is the slice that begins
/// immediately *after* the opening quote. The escape rules are curl's exactly:
///
/// * `\t` → tab, `\n` → line feed, `\r` → carriage return, `\v` → vertical tab.
/// * `\\` → backslash and `\"` → double quote (the "literal char" default).
/// * any other `\x` → the literal `x` (the backslash is dropped).
/// * a trailing backslash (`\` at end of input) is dropped and ends the scan.
///
/// Processing is byte-oriented (as in C). Because non-escape bytes — including
/// every continuation byte of a multi-byte UTF-8 sequence — are copied
/// verbatim, and an escape only ever consumes the backslash plus one following
/// byte, valid UTF-8 input always yields valid UTF-8 output.
///
/// # Errors
/// Returns [`ParameterError::BadUse`] if the unquoted result would exceed
/// [`MAX_CONFIG_LINE_LENGTH`] (curl's dynamic buffer reports the same overflow
/// as a parameter error).
fn unslashquote(s: &str) -> Result<String, ParameterError> {
    let bytes = s.as_bytes();
    let n = bytes.len();
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let mut i = 0usize;

    while i < n && bytes[i] != b'"' {
        if bytes[i] == b'\\' {
            // Step past the backslash to inspect the escaped byte.
            i += 1;
            if i >= n {
                // C `case '\0': continue;` — a trailing backslash terminates
                // the scan (the next loop test would see the NUL terminator).
                break;
            }
            let escaped = bytes[i];
            let decoded = match escaped {
                b't' => b'\t',
                b'n' => b'\n',
                b'r' => b'\r',
                b'v' => 0x0b,
                // default: emit the literal character after the backslash
                other => other,
            };
            out.push(decoded);
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }

        if out.len() > MAX_CONFIG_LINE_LENGTH {
            // curl's `curlx_dyn_addn` rejects growth beyond the cap; the caller
            // maps that to PARAM_BAD_USE.
            return Err(ParameterError::BadUse);
        }
    }

    // Non-escape bytes (incl. UTF-8 continuation bytes) are copied verbatim, so
    // valid UTF-8 input yields valid UTF-8 output; the fallback keeps us safe.
    Ok(String::from_utf8(out)
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()))
}

/// Read one raw line from `input`, returning it without the trailing newline.
///
/// Port of `get_line` (`src/tool_parsecfg.c`). A line ends at the next `\n`
/// (which is stripped) or at end of file; a final line with no trailing newline
/// is returned as-is. Mirroring curl, only the `\n` is removed — a `\r` from a
/// CRLF ending is **kept** (the parameter scanner stops on it via [`is_space`]).
///
/// Returns [`None`] at clean end of file (nothing left to read). On a read
/// failure, or when a single line exceeds [`MAX_CONFIG_LINE_LENGTH`], `*error`
/// is set to `true` and [`None`] is returned, which the caller maps to
/// [`ParameterError::ReadError`].
fn get_line(input: &mut dyn BufRead, error: &mut bool) -> Option<String> {
    let mut buf: Vec<u8> = Vec::new();
    match input.read_until(b'\n', &mut buf) {
        // Clean EOF with no pending bytes: signal end of iteration.
        Ok(0) => None,
        Ok(_) => {
            if buf.len() > MAX_CONFIG_LINE_LENGTH {
                // Over-long line: curl's dynamic buffer reports a read error.
                *error = true;
                return None;
            }
            // Drop a single trailing '\n' (keep any preceding '\r', as curl does).
            if buf.last() == Some(&b'\n') {
                buf.pop();
            }
            // Config files are UTF-8/ASCII text; the CLI option surface is
            // `&str`, so decode here. Invalid byte sequences are extremely rare
            // and are replaced rather than aborting, consistent with the
            // crate-wide UTF-8 assumption.
            Some(
                String::from_utf8(buf)
                    .unwrap_or_else(|e| String::from_utf8_lossy(&e.into_bytes()).into_owned()),
            )
        }
        Err(_) => {
            *error = true;
            None
        }
    }
}

/// Read the next *significant* config line, skipping blank lines and lines whose
/// first non-blank column is `#`.
///
/// Port of `my_get_line` (`src/tool_parsecfg.c`). The returned line is the
/// original text (leading blanks preserved): curl does *not* left-trim the
/// option keyword, so an indented option line parses with an empty keyword — a
/// quirk this port faithfully reproduces. Leading blanks are consulted *only*
/// to decide whether the line is a comment or empty.
///
/// Returns [`None`] at end of file or on a read error (with `*error` set by
/// [`get_line`]).
fn my_get_line(input: &mut dyn BufRead, error: &mut bool) -> Option<String> {
    loop {
        let line = get_line(input, error)?;
        // Skip leading space/tab (the `ISBLANK` set) purely to classify the
        // line; this consults leading blanks without mutating the returned text.
        let trimmed = line.trim_start_matches([' ', '\t']);
        if trimmed.is_empty() || trimmed.starts_with('#') {
            // Blank line or a `#` comment in the first non-blank column: skip it.
            continue;
        }
        return Some(line);
    }
}

/// The result of splitting one config-file line into an option keyword and its
/// (optional) parameter, plus the two warnings curl emits while doing so.
///
/// The warning flags are returned (rather than emitted inside the splitter) so
/// the split logic stays pure and unit-testable; [`parseconfig`] formats and
/// emits them with the file name and line number, exactly as curl's `warnf`
/// calls do.
struct SplitLine {
    /// The option keyword (e.g. `silent`, `--data`, `-O`, or `data=x` with the
    /// inline value still attached for a dashed token). May be empty for an
    /// indented line — see [`my_get_line`].
    option: String,
    /// The parameter value. [`None`] means *no* parameter was present (so
    /// [`crate::args::get_parameter`] can still enforce a required argument);
    /// `Some("")` means an explicitly empty quoted parameter (`""`).
    param: Option<String>,
    /// `true` when an unquoted parameter began with a single quote — curl warns
    /// that double quotes were probably intended.
    warn_single_quote: bool,
    /// `true` when an unquoted parameter was followed by more non-comment data
    /// (unquoted internal whitespace) — curl warns about possible side effects.
    warn_unquoted_whitespace: bool,
}

/// Split one config-file line into `(option, param)` and detect the two
/// quoting-related warnings.
///
/// Port of the per-line scanning loop in `parseconfig` (`src/tool_parsecfg.c`).
/// The algorithm matches curl's pointer walk byte-for-byte:
///
/// 1. The option keyword starts at column 0 (leading blanks are **not**
///    skipped). `dashed` records whether it begins with `-`, which disables the
///    `:`/`=` separators for the rest of the line (`ISSEP`).
/// 2. The keyword runs until the first blank or — for a dash-less token — the
///    first `:`/`=`. That terminator byte is consumed, then all following blanks
///    and separators are skipped.
/// 3. If the parameter begins with `"`, it is a quoted parameter parsed by
///    [`unslashquote`] (always yielding `Some`, even for an empty `""`).
///    Otherwise the parameter runs to the next whitespace; a leading single
///    quote, or trailing non-comment data after internal whitespace, raises the
///    corresponding warning. An empty unquoted parameter becomes [`None`].
///
/// # Errors
/// Propagates [`ParameterError::BadUse`] from [`unslashquote`] (an over-long
/// quoted parameter).
fn split_line(line: &str) -> Result<SplitLine, ParameterError> {
    let bytes = line.as_bytes();
    let n = bytes.len();

    // The option keyword starts with a dash?  (C `dashed_option = option[0] ==
    // '-'`; an empty line yields `false`, matching `'\0' != '-'`.)
    let dashed = n > 0 && bytes[0] == b'-';

    // Walk to the end of the option keyword: stop at a blank or, for a dash-less
    // token, at a `:`/`=` separator.
    let mut i = 0usize;
    while i < n && !is_blank(bytes[i]) && !is_sep(bytes[i], dashed) {
        i += 1;
    }
    // `i` rests on the first ASCII delimiter (or `n`), a valid UTF-8 boundary.
    let option = line[..i].to_string();

    // Consume the single terminator byte (C `*line++ = '\0'`), then skip every
    // following blank and separator (C `while(ISBLANK || ISSEP) line++`).
    if i < n {
        i += 1;
    }
    while i < n && (is_blank(bytes[i]) || is_sep(bytes[i], dashed)) {
        i += 1;
    }

    let mut warn_single_quote = false;
    let mut warn_unquoted_whitespace = false;
    let param: Option<String>;

    if i < n && bytes[i] == b'"' {
        // Quoted parameter: skip the opening quote and unescape the body. A
        // quoted parameter is always present, even when empty (`param = "" `).
        i += 1;
        param = Some(unslashquote(&line[i..])?);
    } else {
        if i < n && bytes[i] == b'\'' {
            // Leading single quote on an unquoted parameter: probably a mistake.
            warn_single_quote = true;
        }
        let start = i;
        // The parameter runs to the next whitespace (stops on CRLF too).
        while i < n && !is_space(bytes[i]) {
            i += 1;
        }
        let token = &line[start..i];

        if i < n {
            // There was trailing whitespace after the token. Skip past it and
            // the run of blanks, then look at what follows to decide whether to
            // warn about unquoted internal whitespace.
            i += 1;
            while i < n && is_blank(bytes[i]) {
                i += 1;
            }
            if i < n {
                match bytes[i] {
                    // End of line, a bare CR/LF, or a comment: no warning.
                    b'\r' | b'\n' | b'#' => {}
                    // Anything else is more data the user probably meant to quote.
                    _ => warn_unquoted_whitespace = true,
                }
            }
        }

        // An empty unquoted parameter is reported as absent so a required
        // argument is still detected by `get_parameter` (C `if(!*param) param =
        // NULL`).
        param = if token.is_empty() {
            None
        } else {
            Some(token.to_string())
        };
    }

    Ok(SplitLine {
        option,
        param,
        warn_single_quote,
        warn_unquoted_whitespace,
    })
}

/// Locate the default per-user `.curlrc`, returning its full path if a readable
/// one is found.
///
/// Port of `findfile(".curlrc", CURLRC_DOTSCORE)` (`src/tool_findfile.c`) for
/// the platforms this workspace targets (Linux and macOS). curl searches a
/// fixed list of environment-rooted locations, in order, returning the first
/// file it can open for reading:
///
/// 1. `$CURL_HOME/.curlrc`
/// 2. `$XDG_CONFIG_HOME/curlrc` (no leading dot)
/// 3. `$HOME/.curlrc`
///
/// On Unix `CURLRC_DOTSCORE` is `1`, and curl's `findfile` zeroes its internal
/// "dotscore" flag the first time it consults an `XDG`-style entry — which, as a
/// side effect, makes the subsequent `$CURL_HOME/.config` and `$HOME/.config`
/// list entries unreachable. This port therefore reproduces exactly the three
/// reachable Unix locations above. An environment variable set to the empty
/// string is skipped, as in curl.
///
/// curl's final `getpwuid`-based fallback (used only when none of the above
/// environment variables are set) is intentionally not reproduced: it requires
/// a C `passwd` lookup unavailable to this crate's permitted dependencies, and
/// `$HOME` is set in every practical and test environment, so the search above
/// is faithful wherever the fallback would matter.
fn find_default_curlrc() -> Option<String> {
    // Delegate to the canonical `findfile` finder table (`src/tool_findfile.c`
    // `conf_list`), which is the exact port C uses for the default `.curlrc`
    // (`parseconfig(NULL, …)` → `findfile(".curlrc", CURLRC_DOTSCORE)`).
    //
    // This deliberately replaces an earlier, narrower home-only search that
    // only probed `$CURL_HOME/.curlrc`, `$XDG_CONFIG_HOME/curlrc`, and
    // `$HOME/.curlrc`. That search was missing the `.config`-suffixed finder
    // entries — `$CURL_HOME/.config/curlrc` and `$HOME/.config/curlrc` — so a
    // user who keeps their config under the XDG `.config` directory pointed to
    // by `CURL_HOME` (but with `XDG_CONFIG_HOME` unset) would never have their
    // `.curlrc` located. (Regression oracle: tests/data/test436 — "Find
    // .curlrc in .config/curlrc via CURL_HOME".)
    //
    // `CURLRC_DOTSCORE` is `2` on Windows (also probe the `_curlrc` variant)
    // and `1` elsewhere (`src/tool_findfile.h`).
    #[cfg(windows)]
    const CURLRC_DOTSCORE: i32 = 2;
    #[cfg(not(windows))]
    const CURLRC_DOTSCORE: i32 = 1;

    crate::operate::findfile(".curlrc", CURLRC_DOTSCORE)
}

/// Parse a curl configuration file, dispatching each directive through the same
/// option machinery as the command line ([`crate::args::get_parameter`]).
///
/// Port of `parseconfig` (`src/tool_parsecfg.c`). This is the entry point for
/// both the `-K`/`--config` option (`filename = Some(path)`) and the implicit
/// per-user `.curlrc` (`filename = None`), and it also reads the config from
/// standard input when `filename = Some("-")`.
///
/// # Parameters
/// * `global` — the CLI state mutated as directives are applied; the "current"
///   operation ([`GlobalConfig::current`](crate::config::GlobalConfig)) is the
///   block being filled, and `--next` starts a new one.
/// * `filename` — `None` loads the default `~/.curlrc`; `Some("-")` reads from
///   standard input; `Some(path)` opens that file.
/// * `max_recursive` — the remaining nested-`--config` budget, forwarded
///   verbatim to every [`get_parameter`] call. The depth guard itself lives in
///   the `--config` option handler (`args::opt_file`), which decrements this and
///   refuses to descend past zero, so this function performs no check of its own
///   (see [`CONFIG_MAX_LEVELS`]).
///
/// # Returns
/// On success, `Ok(Some(resolved_path))` — the path actually read (the resolved
/// `.curlrc`, the given file path, or `"-"` for standard input) — which the
/// caller uses for curl's `Read config file from '…'` notice.
///
/// # Errors
/// * [`ParameterError::ReadError`] — the file could not be opened or a read
///   failed mid-stream. For a *named* file (or stdin) that cannot be opened or
///   read, curl's `cannot read config from '…'` message is emitted; for a
///   *missing default* `.curlrc` (`filename = None`) the error is returned
///   silently, as a missing `.curlrc` is normal and the caller ignores it.
/// * [`ParameterError::BadUse`] — a malformed quoted parameter (`unslashquote`).
/// * [`ParameterError::ConfigOptionUnknown`] — an unknown option (curl remaps
///   the command line's [`ParameterError::OptionUnknown`] to this config-file
///   code).
/// * [`ParameterError::GotExtraParameter`] — a non-empty parameter the option
///   did not consume.
/// * Any other non-informational [`ParameterError`] surfaced by
///   [`get_parameter`] for the offending directive.
///
/// The informational/control-flow codes (`--help`, `--version`, `--manual`,
/// `--engines`, `--ca-native`'s embed request) are *not* errors here: curl logs
/// nothing for them in a config file and simply continues to the next line.
pub fn parseconfig(
    global: &mut GlobalConfig,
    filename: Option<&str>,
    max_recursive: i32,
) -> Result<Option<String>, ParameterError> {
    // Resolve `filename` to an open, buffered reader plus the name used both for
    // diagnostics and as the resolved-path return value. This mirrors the file
    // selection at the top of the C `parseconfig`:
    //   * None        → the default ~/.curlrc (via `find_default_curlrc`),
    //   * Some("-")   → standard input,
    //   * Some(path)  → that file.
    let (mut reader, resolved_name): (Box<dyn BufRead>, String) = match filename {
        None => match find_default_curlrc() {
            Some(path) => match File::open(&path) {
                Ok(f) => (Box::new(BufReader::new(f)), path),
                // Found but no longer openable (a race after the probe): curl
                // returns a read error here with no message (an early return,
                // before the post-loop "cannot read config" notice).
                Err(_) => return Err(ParameterError::ReadError),
            },
            // No default config file exists: a read error with no message and no
            // resolved path. The caller (operate) treats this as "no .curlrc",
            // which is the normal case.
            None => return Err(ParameterError::ReadError),
        },
        Some("-") => (Box::new(BufReader::new(io::stdin())), "-".to_string()),
        Some(path) => match File::open(path) {
            Ok(f) => (Box::new(BufReader::new(f)), path.to_string()),
            Err(_) => {
                // A named file that cannot be opened: emit curl's message and
                // fail with a read error (see tests/data/test411).
                errorf(global, &format!("cannot read config from '{path}'"));
                return Err(ParameterError::ReadError);
            }
        },
    };

    // `display_name` is the name shown in per-line diagnostics. For standard
    // input it begins as "-" (so warnings read "-:N …") and is switched to
    // "<stdin>" the moment an error is reported — exactly as curl reassigns its
    // `filename` pointer inside the error branch, after which the loop ends.
    let mut display_name = resolved_name.clone();

    let mut err: Result<(), ParameterError> = Ok(());
    let mut lineno: i32 = 0;
    // `get_parameter` resets this at entry; declared once (as in C) so the
    // "extra parameter" check below sees the value the dispatch left behind.
    let mut usedarg = false;
    // Set by `get_line`/`my_get_line` on an I/O failure (or an over-long line).
    let mut fileerror = false;

    // Read significant lines until EOF, a read error, or a parse error. The
    // `err.is_ok()` guard reproduces the C `while(!err && my_get_line(...))`.
    while err.is_ok() {
        let line = match my_get_line(&mut *reader, &mut fileerror) {
            Some(l) => l,
            None => break, // clean EOF, or a read error captured in `fileerror`
        };
        lineno += 1;

        // Split the line into an option keyword and its optional parameter,
        // along with the two quoting warnings. A quoting failure (over-long
        // quoted parameter) maps to BadUse and ends the scan, as in C.
        let (option, param, warn_single_quote, warn_unquoted_whitespace) = match split_line(&line) {
            Ok(s) => (
                s.option,
                s.param,
                s.warn_single_quote,
                s.warn_unquoted_whitespace,
            ),
            Err(e) => {
                err = Err(e);
                break;
            }
        };

        // Emit the quoting warnings (before dispatch, as curl does). The message
        // text is curl's verbatim.
        if warn_single_quote {
            warnf(
                global,
                &format!(
                    "{display_name}:{lineno} Option '{option}' uses argument with leading \
                     single quote. It is probably a mistake. Consider double quotes."
                ),
            );
        }
        if warn_unquoted_whitespace {
            warnf(
                global,
                &format!(
                    "{display_name}:{lineno} Option '{option}' uses argument with unquoted \
                     whitespace. This may cause side-effects. Consider double quotes."
                ),
            );
        }

        // Dispatch through the shared option machinery so config-file options
        // and command-line options are semantically identical.
        let mut res = get_parameter(
            global,
            &option,
            param.as_deref(),
            &mut usedarg,
            max_recursive,
        );

        // A non-empty parameter that the option did not consume is "extra".
        // (A quoted-empty `""` is present but empty and so is *not* extra,
        // matching the C `param && *param` test.)
        if res.is_ok() && param.as_deref().is_some_and(|p| !p.is_empty()) && !usedarg {
            res = Err(ParameterError::GotExtraParameter);
        }

        // `--next` begins a new operation block, but only once the current block
        // already has a URL; with no URL it is silently ignored here (unlike the
        // command-line driver, which errors). NextOperation is not treated as an
        // error by the branch below.
        if matches!(res, Err(ParameterError::NextOperation)) {
            let idx = global.current;
            let has_url = global.operations[idx]
                .url_list
                .first()
                .is_some_and(|g| g.url.is_some());
            if has_url {
                global.add_operation();
            }
        }

        if let Err(e) = res {
            if e != ParameterError::NextOperation {
                // Report stdin diagnostics against "<stdin>" from here on.
                if display_name == "-" {
                    display_name = "<stdin>".to_string();
                }
                // The informational/control-flow codes are not errors in a
                // config file: log nothing and keep parsing the next line.
                if !e.is_informational() {
                    let reason = param2text(e);
                    errorf(
                        global,
                        &format!("{display_name}:{lineno} config file option '{option}' {reason}"),
                    );
                    // An unknown option in a config file is reported with the
                    // config-specific code.
                    err = Err(if e == ParameterError::OptionUnknown {
                        ParameterError::ConfigOptionUnknown
                    } else {
                        e
                    });
                }
            }
        }
    }

    // A read failure during the loop overrides everything with a read error and
    // emits curl's "cannot read config" notice (the named-file open failure was
    // already handled, with its own message, during resolution above).
    if fileerror {
        err = Err(ParameterError::ReadError);
        errorf(
            global,
            &format!("cannot read config from '{resolved_name}'"),
        );
    }

    // On success, hand back the resolved path (curl's `*resolved`); on failure,
    // propagate the error and yield no path.
    err.map(|()| Some(resolved_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tempfile::tempdir;

    // -----------------------------------------------------------------------
    // unslashquote — escape parity with curl's `unslashquote`.
    //
    // The argument is the slice that begins immediately *after* the opening
    // quote, so a trailing `"` byte is the (unescaped) closing quote.
    // -----------------------------------------------------------------------

    #[test]
    fn unslashquote_stops_at_closing_quote() {
        assert_eq!(unslashquote("hello\"").unwrap(), "hello");
        // Anything after the closing quote is ignored.
        assert_eq!(unslashquote("hi\" trailing").unwrap(), "hi");
    }

    #[test]
    fn unslashquote_named_escapes() {
        // \t \n \r \v unescape to their control characters.
        assert_eq!(unslashquote("a\\tb\"").unwrap(), "a\tb");
        assert_eq!(unslashquote("x\\ny\"").unwrap(), "x\ny");
        assert_eq!(unslashquote("p\\rq\"").unwrap(), "p\rq");
        assert_eq!(unslashquote("u\\vw\"").unwrap(), "u\u{0b}w");
    }

    #[test]
    fn unslashquote_literal_after_backslash() {
        // Any other \x yields the literal x (the backslash is dropped).
        assert_eq!(unslashquote("a\\zb\"").unwrap(), "azb");
        // \\ → one backslash, \" → one double quote (the "literal char" default).
        assert_eq!(unslashquote("\\\\\"").unwrap(), "\\");
        assert_eq!(unslashquote("q\\\"r\"").unwrap(), "q\"r");
    }

    #[test]
    fn unslashquote_unterminated_and_empty() {
        // No closing quote: consume to end of input.
        assert_eq!(unslashquote("noquote").unwrap(), "noquote");
        // Empty body (immediate closing quote) and empty input.
        assert_eq!(unslashquote("\"").unwrap(), "");
        assert_eq!(unslashquote("").unwrap(), "");
        // A trailing backslash is dropped and ends the scan.
        assert_eq!(unslashquote("ab\\").unwrap(), "ab");
    }

    // -----------------------------------------------------------------------
    // split_line — option/parameter separation, ISSEP, quoting, warnings.
    // -----------------------------------------------------------------------

    fn split(line: &str) -> SplitLine {
        split_line(line).expect("split_line should not fail for these inputs")
    }

    #[test]
    fn split_bare_boolean_has_no_param() {
        let s = split("silent");
        assert_eq!(s.option, "silent");
        assert_eq!(s.param, None);
        assert!(!s.warn_single_quote && !s.warn_unquoted_whitespace);
    }

    #[test]
    fn split_dashless_colon_and_equals_separators() {
        // For a dash-less token, ':' and '=' act as the separator.
        let c = split("url: http://x/");
        assert_eq!(c.option, "url");
        assert_eq!(c.param.as_deref(), Some("http://x/"));

        let e = split("url = http://x/");
        assert_eq!(e.option, "url");
        assert_eq!(e.param.as_deref(), Some("http://x/"));
    }

    #[test]
    fn split_dashed_token_keeps_equals_inline() {
        // ISSEP is disabled for a dashed token, so `--data=x` keeps the `=` as
        // part of the option (get_parameter then splits the inline value).
        let s = split("--data=x");
        assert_eq!(s.option, "--data=x");
        assert_eq!(s.param, None);

        // A dashed token with a `:` likewise keeps the colon in the option.
        let c = split("--url:y");
        assert_eq!(c.option, "--url:y");
        assert_eq!(c.param, None);
    }

    #[test]
    fn split_dashed_with_space_separated_param() {
        let long = split("--data x");
        assert_eq!(long.option, "--data");
        assert_eq!(long.param.as_deref(), Some("x"));

        let short = split("-o value");
        assert_eq!(short.option, "-o");
        assert_eq!(short.param.as_deref(), Some("value"));
    }

    #[test]
    fn split_quoted_param() {
        let s = split("data \"a b\"");
        assert_eq!(s.option, "data");
        assert_eq!(s.param.as_deref(), Some("a b"));
        assert!(!s.warn_single_quote && !s.warn_unquoted_whitespace);
    }

    #[test]
    fn split_quoted_empty_is_present_but_empty() {
        // A quoted empty parameter is *present* (Some("")), unlike an unquoted
        // empty parameter which is absent (None).
        let q = split("foo \"\"");
        assert_eq!(q.option, "foo");
        assert_eq!(q.param.as_deref(), Some(""));

        let u = split("foo");
        assert_eq!(u.param, None);
    }

    #[test]
    fn split_single_quote_warns() {
        let s = split("foo 'bar");
        assert_eq!(s.option, "foo");
        assert_eq!(s.param.as_deref(), Some("'bar"));
        assert!(s.warn_single_quote);
        assert!(!s.warn_unquoted_whitespace);
    }

    #[test]
    fn split_unquoted_whitespace_warns() {
        // Trailing non-comment data after the parameter → unquoted-whitespace.
        let s = split("foo bar baz");
        assert_eq!(s.option, "foo");
        assert_eq!(s.param.as_deref(), Some("bar"));
        assert!(s.warn_unquoted_whitespace);
        assert!(!s.warn_single_quote);
    }

    #[test]
    fn split_trailing_comment_does_not_warn() {
        // A comment after the parameter is fine (no unquoted-whitespace warning).
        let s = split("foo bar # comment");
        assert_eq!(s.option, "foo");
        assert_eq!(s.param.as_deref(), Some("bar"));
        assert!(!s.warn_unquoted_whitespace);
    }

    #[test]
    fn split_does_not_left_trim_option_keyword() {
        // curl does NOT trim leading blanks from the option keyword: an indented
        // option line parses with an *empty* keyword (which get_parameter then
        // rejects as unknown). This quirk is reproduced faithfully.
        let s = split("   silent");
        assert_eq!(s.option, "");
        assert_eq!(s.param.as_deref(), Some("silent"));
    }

    // -----------------------------------------------------------------------
    // get_line / my_get_line — line reading, newline trimming, comment/blank
    // skipping.
    // -----------------------------------------------------------------------

    #[test]
    fn get_line_trims_lf_keeps_cr_and_signals_eof() {
        let mut err = false;
        let mut input = Cursor::new(b"hello\nworld\n".as_slice());
        assert_eq!(get_line(&mut input, &mut err).as_deref(), Some("hello"));
        assert_eq!(get_line(&mut input, &mut err).as_deref(), Some("world"));
        assert_eq!(get_line(&mut input, &mut err), None);
        assert!(!err, "clean EOF must not set the error flag");

        // A final line without a trailing newline is returned as-is.
        let mut input2 = Cursor::new(b"noeol".as_slice());
        assert_eq!(get_line(&mut input2, &mut err).as_deref(), Some("noeol"));
        assert_eq!(get_line(&mut input2, &mut err), None);

        // Only the '\n' is dropped; a '\r' from a CRLF ending is kept.
        let mut input3 = Cursor::new(b"a\r\nb\r\n".as_slice());
        assert_eq!(get_line(&mut input3, &mut err).as_deref(), Some("a\r"));
        assert_eq!(get_line(&mut input3, &mut err).as_deref(), Some("b\r"));
    }

    #[test]
    fn my_get_line_skips_blank_and_comment_lines() {
        let mut err = false;
        let mut input = Cursor::new(b"\n# comment\nsilent\n".as_slice());
        assert_eq!(my_get_line(&mut input, &mut err).as_deref(), Some("silent"));
        assert_eq!(my_get_line(&mut input, &mut err), None);
        assert!(!err);
    }

    #[test]
    fn my_get_line_indented_comment_is_skipped_indented_option_is_not() {
        let mut err = false;
        // An indented '#' is a comment (first non-blank column is '#').
        let mut input = Cursor::new(b"   # indented comment\noption\n".as_slice());
        assert_eq!(my_get_line(&mut input, &mut err).as_deref(), Some("option"));

        // An indented option line is *not* a comment: it is returned verbatim,
        // with its leading blanks intact (consumed only by split_line, where it
        // yields the empty-keyword quirk above).
        let mut input2 = Cursor::new(b"   silent\n".as_slice());
        assert_eq!(
            my_get_line(&mut input2, &mut err).as_deref(),
            Some("   silent")
        );
    }

    // -----------------------------------------------------------------------
    // find_default_curlrc — home-directory search precedence.
    //
    // Restores the three relevant environment variables on drop so the test is
    // self-contained. No other test in this crate touches these variables.
    // -----------------------------------------------------------------------

    struct EnvGuard {
        vars: Vec<(&'static str, Option<String>)>,
    }

    impl EnvGuard {
        fn capture(keys: &[&'static str]) -> Self {
            let vars = keys.iter().map(|&k| (k, std::env::var(k).ok())).collect();
            EnvGuard { vars }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in &self.vars {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    #[test]
    fn default_curlrc_resolution_precedence() {
        let _guard = EnvGuard::capture(&["CURL_HOME", "XDG_CONFIG_HOME", "HOME"]);

        // Case 1: $HOME/.curlrc when CURL_HOME and XDG_CONFIG_HOME are unset.
        let home = tempdir().unwrap();
        std::fs::write(home.path().join(".curlrc"), b"# test\n").unwrap();
        std::env::remove_var("CURL_HOME");
        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::set_var("HOME", home.path());
        let found = find_default_curlrc().expect("should resolve $HOME/.curlrc");
        assert!(found.ends_with(".curlrc"));
        assert!(std::path::Path::new(&found).is_file());
        assert!(found.contains(home.path().to_str().unwrap()));

        // Case 2: $CURL_HOME/.curlrc takes precedence over $HOME/.curlrc.
        let curl_home = tempdir().unwrap();
        std::fs::write(curl_home.path().join(".curlrc"), b"# test\n").unwrap();
        std::env::set_var("CURL_HOME", curl_home.path());
        let found2 = find_default_curlrc().expect("should resolve $CURL_HOME/.curlrc");
        assert!(found2.contains(curl_home.path().to_str().unwrap()));
        assert!(!found2.contains(home.path().to_str().unwrap()));

        // Case 3: $XDG_CONFIG_HOME/curlrc (no leading dot) outranks $HOME, but
        // not $CURL_HOME — so clear CURL_HOME first.
        std::env::remove_var("CURL_HOME");
        let xdg = tempdir().unwrap();
        std::fs::write(xdg.path().join("curlrc"), b"# test\n").unwrap();
        std::env::set_var("XDG_CONFIG_HOME", xdg.path());
        let found3 = find_default_curlrc().expect("should resolve $XDG_CONFIG_HOME/curlrc");
        assert!(found3.ends_with("curlrc"));
        assert!(found3.contains(xdg.path().to_str().unwrap()));

        // Case 4: nothing resolvable → None.
        std::env::remove_var("CURL_HOME");
        std::env::remove_var("XDG_CONFIG_HOME");
        let empty_home = tempdir().unwrap(); // contains no .curlrc
        std::env::set_var("HOME", empty_home.path());
        assert_eq!(find_default_curlrc(), None);
    }

    // -----------------------------------------------------------------------
    // parseconfig — end-to-end behavior over the shared option machinery.
    // -----------------------------------------------------------------------

    /// Write `contents` to a fresh temp file and return both the live `TempDir`
    /// (kept to delay cleanup) and the file path as a `String`.
    fn write_config(contents: &[u8]) -> (tempfile::TempDir, String) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("curlrc");
        std::fs::write(&path, contents).unwrap();
        let path_str = path.to_str().unwrap().to_string();
        (dir, path_str)
    }

    #[test]
    fn parseconfig_missing_named_file_is_read_error() {
        let mut g = GlobalConfig::new();
        let res = parseconfig(
            &mut g,
            Some("/no/such/curl_rs_config_file_4f8a3c"),
            CONFIG_MAX_LEVELS,
        );
        assert!(matches!(res, Err(ParameterError::ReadError)), "got {res:?}");
    }

    #[test]
    fn parseconfig_records_url_and_returns_resolved_path() {
        let (_dir, path) = write_config(b"url = http://example.com/\n");
        let mut g = GlobalConfig::new();
        let res = parseconfig(&mut g, Some(&path), CONFIG_MAX_LEVELS);
        assert!(res.is_ok(), "parseconfig failed: {res:?}");
        assert_eq!(res.unwrap().as_deref(), Some(path.as_str()));

        let idx = g.current;
        let url = g.operations[idx]
            .url_list
            .first()
            .and_then(|u| u.url.clone());
        assert!(
            url.as_deref().is_some_and(|u| u.contains("example.com")),
            "URL was not recorded: {url:?}"
        );
    }

    #[test]
    fn parseconfig_next_starts_new_operation_when_url_present() {
        let (_dir, path) =
            write_config(b"url = http://a.example/\n--next\nurl = http://b.example/\n");
        let mut g = GlobalConfig::new();
        let before = g.operations.len();
        let res = parseconfig(&mut g, Some(&path), CONFIG_MAX_LEVELS);
        assert!(res.is_ok(), "parseconfig failed: {res:?}");
        assert_eq!(
            g.operations.len(),
            before + 1,
            "--next after a URL should start exactly one new operation"
        );
    }

    #[test]
    fn parseconfig_next_without_url_is_silently_ignored() {
        // In a config file (unlike the command line), a leading `--next` with no
        // URL yet is silently ignored — it is not an error.
        let (_dir, path) = write_config(b"--next\nsilent\n");
        let mut g = GlobalConfig::new();
        let before = g.operations.len();
        let res = parseconfig(&mut g, Some(&path), CONFIG_MAX_LEVELS);
        assert!(
            res.is_ok(),
            "parseconfig should ignore a URL-less --next: {res:?}"
        );
        assert_eq!(
            g.operations.len(),
            before,
            "no new operation should be added"
        );
    }

    #[test]
    fn parseconfig_unknown_option_maps_to_config_unknown() {
        let (_dir, path) = write_config(b"this-is-not-a-real-option value\n");
        let mut g = GlobalConfig::new();
        let res = parseconfig(&mut g, Some(&path), CONFIG_MAX_LEVELS);
        assert!(
            matches!(res, Err(ParameterError::ConfigOptionUnknown)),
            "unknown config option should map to ConfigOptionUnknown, got {res:?}"
        );
    }

    #[test]
    fn parseconfig_extra_parameter_on_boolean() {
        // A boolean option handed a non-empty parameter it does not consume is
        // reported as an extra parameter.
        let (_dir, path) = write_config(b"silent extrastuff\n");
        let mut g = GlobalConfig::new();
        let res = parseconfig(&mut g, Some(&path), CONFIG_MAX_LEVELS);
        assert!(
            matches!(res, Err(ParameterError::GotExtraParameter)),
            "got {res:?}"
        );
    }

    #[test]
    fn parseconfig_skips_comments_and_blank_lines() {
        // Comments and blank lines are ignored; the real option still applies.
        let (_dir, path) =
            write_config(b"# a comment\n\n   # indented comment\nurl = http://ok.example/\n");
        let mut g = GlobalConfig::new();
        let res = parseconfig(&mut g, Some(&path), CONFIG_MAX_LEVELS);
        assert!(res.is_ok(), "parseconfig failed: {res:?}");
        let idx = g.current;
        assert!(
            g.operations[idx]
                .url_list
                .first()
                .and_then(|u| u.url.as_deref())
                .is_some_and(|u| u.contains("ok.example")),
            "URL after comments/blank lines was not recorded"
        );
    }
}
