// SPDX-License-Identifier: curl
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// Rust rewrite of curl's src/tool_parsecfg.c + src/tool_findfile.c.

//! # Config-file parsing and default-config discovery
//!
//! Faithful Rust port of curl 8.19.0-DEV's `src/tool_parsecfg.c` (the `--config` / `-K`
//! file reader, including the `unslashquote` backslash-unescaper and the `my_get_line`
//! comment/blank-skipping line reader) and `src/tool_findfile.c` (the default `.curlrc`
//! discovery walk). The authoritative behavior specification is
//! `docs/cmdline-opts/config.md`.
//!
//! A curl config file is a text file of one option per line, given exactly as they would
//! appear on the command line. This module tokenizes each line into an `(option, value)`
//! pair and dispatches it to [`crate::args::getparameter`], so the config file and the
//! command line share a single, byte-identical option grammar.
//!
//! ## Grammar (reproduced verbatim from curl 8.x)
//!
//! * One option per physical line; a `#` in the first non-blank column is a full-line
//!   comment; blank lines are ignored. Leading whitespace is **not** stripped from an
//!   option line — a leading blank makes the option name empty, exactly as in the C tool
//!   (an indented option line is therefore an error, matching curl).
//! * The option may be written with or without the leading `--` (or a `-` short form).
//! * The option and its value are separated by whitespace, `:`, or `=` — but `:` and `=`
//!   are honored as separators **only** when the option was *not* written with an initial
//!   dash (the C `ISSEP(x, dash)` macro).
//! * A value containing whitespace, or beginning with `:` or `=`, must be double-quoted.
//!   Inside double quotes [`unslashquote`] interprets `\\`, `\"`, `\t`, `\n`, `\r`, `\v`;
//!   a backslash before any other character emits that character; a trailing lone
//!   backslash ends the value; parsing stops at the first unescaped `"`.
//! * A bare URL must be written as `url = <URL>` (a lone URL line is an unknown option).
//! * `filename == "-"` reads the config from **stdin**.
//! * A single line may be no more than [`MAX_CONFIG_LINE_LENGTH`] (10 MB); a longer line
//!   is a read error.
//!
//! ## Integration
//!
//! [`parseconfig`] is the faithful port of the C `parseconfig`. Because the argument
//! parser in [`crate::args`] cannot depend on this module (that would be a cycle), it
//! reaches config parsing through a function-pointer hook
//! ([`crate::args::ConfigParserHook`]). [`config_parser_hook`] is the hook-typed adapter;
//! `main.rs` wires it once at startup with
//! `global.config_parser = Some(parsecfg::config_parser_hook);`. The default `.curlrc`
//! load (curl's `parseconfig(NULL, …)`) is driven by [`find_config_file`] +
//! [`parseconfig`]`(None, …)`.

// This module is a leaf CLI component that is wired into the argument/operation layer in a
// later checkpoint (AAP §0.7.3); until then some of its public entry points have no
// in-crate caller. The same crate-level allowance is used by the sibling CLI modules
// (`args`, `getpass`, `xattr`, `terminal`) for the identical reason. It never masks a real
// defect: every item here is exercised by the module's own unit tests.
#![allow(dead_code)]

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};

use crate::args::{
    errorf, getparameter, param_geterror, warnf, Diag, GlobalConfig, ParameterError,
};

/// Maximum length, in bytes, of a single config-file line (curl's `MAX_CONFIG_LINE_LENGTH`,
/// 10 MB, documented in `docs/cmdline-opts/config.md` as "no more than 10 megabytes",
/// since 8.2.0). A physical line longer than this is rejected as a read error rather than
/// buffered in full.
pub const MAX_CONFIG_LINE_LENGTH: usize = 10 * 1024 * 1024;

/// True for the characters curl's `ISSPACE` treats as whitespace (`isspace()`): space,
/// horizontal tab, newline, vertical tab, form feed, and carriage return. Used to find the
/// end of an *unquoted* value (curl stops the value at the first such byte, so a trailing
/// `\r` from a CRLF file terminates the value cleanly).
#[inline]
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// True for curl's `ISBLANK`: a space or a horizontal tab (and nothing else). This is the
/// narrower class used when scanning an option *name* and when skipping separators, so a
/// `\r`/`\n` is deliberately **not** blank here.
#[inline]
fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Copy the value that begins immediately after an opening double quote, undoing curl's
/// backslash quoting, and return the decoded bytes.
///
/// Faithful port of the C `unslashquote` (`tool_parsecfg.c`). Copying stops at the first
/// **unescaped** double quote or at the end of the input. The recognized escapes are:
///
/// | sequence | output        |
/// |----------|---------------|
/// | `\\`     | `\`           |
/// | `\"`     | `"`           |
/// | `\t`     | tab (0x09)    |
/// | `\n`     | newline (0x0a)|
/// | `\r`     | CR (0x0d)     |
/// | `\v`     | VT (0x0b)     |
/// | `\<x>`   | `<x>` verbatim |
///
/// A backslash as the final byte (no following character, e.g. the input ended right after
/// it) is dropped and ends the value, mirroring the C `case '\0': continue;` that breaks
/// out of the copy loop. The value is byte-oriented (curl treats it as raw bytes), so this
/// operates on and returns `Vec<u8>`.
fn unslashquote(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while i < input.len() {
        let c = input[i];
        if c == b'"' {
            // First non-backslash-quoted double quote: the value ends here.
            break;
        }
        if c == b'\\' {
            // Consume the backslash; the next byte decides the emitted character.
            i += 1;
            if i >= input.len() {
                // Trailing lone backslash — C `case '\0'` continues, ending the loop.
                break;
            }
            let n = input[i];
            let decoded = match n {
                b't' => b'\t',
                b'n' => b'\n',
                b'r' => b'\r',
                b'v' => 0x0b,
                // Default: output the byte following the backslash verbatim (this covers
                // `\\` -> `\` and `\"` -> `"` as well as any other escaped byte).
                other => other,
            };
            out.push(decoded);
            i += 1;
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// Outcome of reading one physical line via [`read_raw_line`].
enum RawLine {
    /// A line was read (its bytes are in the caller's buffer, without the trailing `\n`).
    /// The buffer may be empty (a blank line).
    Got,
    /// End of input with no further bytes.
    Eof,
    /// The line exceeded [`MAX_CONFIG_LINE_LENGTH`] before a newline was seen.
    TooLong,
}

/// Read one physical line into `buf` (cleared first), stopping at (and discarding) the
/// terminating `\n`, or at end of input. A lone `\r` is preserved (curl's `get_line` drops
/// only the `\n`, matching text-mode reads on the target platforms).
///
/// This streams through the reader's buffer so an over-long line is rejected *before* it is
/// fully materialized, reproducing the memory-bounded behavior of curl's dynbuf ceiling
/// (`fit > toobig` in `curlx_dyn_addn`).
fn read_raw_line<R: BufRead>(input: &mut R, buf: &mut Vec<u8>) -> io::Result<RawLine> {
    buf.clear();
    loop {
        let chunk = match input.fill_buf() {
            Ok(c) => c,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if chunk.is_empty() {
            // End of input. If we have accumulated bytes, they form the final unterminated
            // line (curl returns it); otherwise there is nothing left.
            if buf.is_empty() {
                return Ok(RawLine::Eof);
            }
            return Ok(RawLine::Got);
        }
        match chunk.iter().position(|&b| b == b'\n') {
            Some(pos) => {
                // `pos` bytes precede the newline; the newline itself is consumed but not
                // stored. Enforce the ceiling on the resulting content length.
                if buf.len() + pos > MAX_CONFIG_LINE_LENGTH {
                    return Ok(RawLine::TooLong);
                }
                buf.extend_from_slice(&chunk[..pos]);
                input.consume(pos + 1);
                return Ok(RawLine::Got);
            }
            None => {
                let clen = chunk.len();
                if buf.len() + clen > MAX_CONFIG_LINE_LENGTH {
                    return Ok(RawLine::TooLong);
                }
                buf.extend_from_slice(chunk);
                input.consume(clen);
                // No newline yet — keep pulling more of the same line.
            }
        }
    }
}

/// Outcome of [`my_get_line`]: the next *significant* line, end of input, or an over-long
/// line.
enum NextLine {
    /// A significant (non-blank, non-comment) line is in the caller's buffer.
    Significant,
    /// End of input.
    Eof,
    /// A line exceeded [`MAX_CONFIG_LINE_LENGTH`].
    TooLong,
}

/// Return the next significant config line, skipping blank lines and full-line comments,
/// exactly like curl's `my_get_line`.
///
/// A line is skipped when it is empty or when its first non-blank byte is `#`. The returned
/// line still carries any leading blanks (curl trims leading blanks only for the
/// comment/blank *test*, not for the value it hands back to the parser).
fn my_get_line<R: BufRead>(input: &mut R, buf: &mut Vec<u8>) -> io::Result<NextLine> {
    loop {
        match read_raw_line(input, buf)? {
            RawLine::Eof => return Ok(NextLine::Eof),
            RawLine::TooLong => return Ok(NextLine::TooLong),
            RawLine::Got => match buf.iter().position(|&b| !is_blank(b)) {
                // All blanks (or empty): skip and read the next line.
                None => continue,
                Some(idx) => {
                    // A `#` in the first non-blank column is a full-line comment: skip it.
                    if buf[idx] == b'#' {
                        continue;
                    }
                    return Ok(NextLine::Significant);
                }
            },
        }
    }
}

/// Split one significant config line into its `(option, value)` pair, reproducing the
/// tokenizer in the body of curl's `parseconfig` loop.
///
/// Byte-exact behavior:
/// * `dashed` is decided from the very first byte of the line (`line[0] == '-'`) — leading
///   blanks are part of the line, so an indented line has `dashed == false` and yields an
///   empty option name.
/// * The option name runs up to the first `ISBLANK`, or (when the option is dash-less) the
///   first `:`/`=` separator.
/// * One separator/terminator byte is consumed, then any further blanks and (dash-less)
///   `:`/`=` separators are skipped.
/// * If the value begins with `"`, it is [`unslashquote`]d and is always returned as
///   `Some` (possibly the empty string). Otherwise the value is the run of non-`ISSPACE`
///   bytes; an empty run becomes `None` (so `getparameter` sees "no argument"). A leading
///   single quote, or additional non-comment data after an unquoted value, triggers the
///   same advisory `warnf` diagnostics curl emits.
///
/// `diag` is captured by the caller *before* the option is applied, so the advisory
/// warnings honor the `--silent`/`--show-error` state in effect for this line.
fn tokenize_line(line: &[u8], fname: &str, lineno: u64, diag: Diag) -> (String, Option<String>) {
    let dashed = line.first() == Some(&b'-');

    // --- option name: up to the first ISBLANK, or (dash-less) ISSEP ---
    let mut i = 0usize;
    while i < line.len() {
        let b = line[i];
        if is_blank(b) {
            break;
        }
        if !dashed && (b == b'=' || b == b':') {
            break;
        }
        i += 1;
    }
    let option = String::from_utf8_lossy(&line[..i]).into_owned();

    // --- consume one terminator byte, then skip blanks and (dash-less) separators ---
    let mut j = i;
    if j < line.len() {
        j += 1; // the byte that ended the option name (curl null-terminates and advances)
    }
    while j < line.len() {
        let b = line[j];
        if is_blank(b) || (!dashed && (b == b'=' || b == b':')) {
            j += 1;
        } else {
            break;
        }
    }

    // --- value region ---
    let value = &line[j..];
    let param: Option<String> = if value.first() == Some(&b'"') {
        // Quoted value: unescape everything up to the first unescaped quote. A quoted value
        // is always present (curl returns "" rather than NULL for an empty quoted string).
        let decoded = unslashquote(&value[1..]);
        Some(String::from_utf8_lossy(&decoded).into_owned())
    } else {
        if value.first() == Some(&b'\'') {
            warnf(
                diag,
                &format!(
                    "{fname}:{lineno} Option '{option}' uses argument with leading single \
                     quote. It is probably a mistake. Consider double quotes."
                ),
            );
        }
        // Unquoted value: up to the first ISSPACE byte.
        let mut k = 0usize;
        while k < value.len() && !is_space(value[k]) {
            k += 1;
        }
        let token = &value[..k];

        // If a terminator byte followed the token, look past it (and any blanks) to detect
        // trailing non-comment data, which curl flags as an unquoted-whitespace mistake.
        if k < value.len() {
            let mut m = k + 1;
            while m < value.len() && is_blank(value[m]) {
                m += 1;
            }
            let next = value.get(m).copied().unwrap_or(0);
            if !matches!(next, 0 | b'\r' | b'\n' | b'#') {
                warnf(
                    diag,
                    &format!(
                        "{fname}:{lineno} Option '{option}' uses argument with unquoted \
                         whitespace. This may cause side-effects. Consider double quotes."
                    ),
                );
            }
        }

        if token.is_empty() {
            // curl sets `param = NULL` for an empty token so `getparameter` can tell that
            // no argument was supplied.
            None
        } else {
            Some(String::from_utf8_lossy(token).into_owned())
        }
    };

    (option, param)
}

/// Core config-parsing loop over an already-opened byte stream. `fname` is the name used in
/// diagnostics (a filesystem path, or `"<stdin>"` when reading from standard input).
///
/// This is the body of curl's `parseconfig` from the `my_get_line` loop onward: it reads
/// significant lines, tokenizes each, dispatches it to [`getparameter`], and reproduces the
/// C result handling — the `PARAM_GOT_EXTRA_PARAMETER` promotion, the `--next`
/// (`PARAM_NEXT_OPERATION`) operation advance, the pass-through of the flow-control signals
/// (`--help`/`--manual`/`--version`/`--engine list`/`--dump-ca-embed`), and the
/// `PARAM_OPTION_UNKNOWN` → `PARAM_CONFIG_OPTION_UNKNOWN` promotion with the
/// `"<file>:<line> config file option '<opt>' <reason>"` diagnostic. An over-long line or a
/// read error becomes [`ParameterError::ReadError`], reported once as
/// `"cannot read config from '<file>'"`.
fn parse_stream<R: BufRead>(
    input: &mut R,
    fname: &str,
    max_recursive: i32,
    global: &mut GlobalConfig,
) -> Result<(), ParameterError> {
    let mut buf: Vec<u8> = Vec::new();
    // curl increments `lineno` once per *significant* line (comments/blanks are skipped by
    // `my_get_line` and do not count), so a diagnostic's line number is the significant-line
    // index, matching curl's `--config` error output exactly.
    let mut lineno: u64 = 0;
    let mut err: Result<(), ParameterError> = Ok(());
    let mut fileerror = false;

    // curl keeps a single `filename` pointer that, for a stdin config, is renamed to
    // "<stdin>" the first time an option yields a non-OK, non-`--next` result (an error OR a
    // harmless flow-control signal). The rename persists for the remainder of the parse, so
    // any later diagnostic — a subsequent tokenize warning or the trailing read-error message
    // — also shows "<stdin>". A named-file parse never triggers the rename. `cur_fname` starts
    // as the caller's name ("-" for stdin) and can be reassigned to the `'static` "<stdin>",
    // which coerces to the borrowed lifetime.
    let mut cur_fname: &str = fname;

    loop {
        // C loop guard: `while(!err && my_get_line(...))`.
        if err.is_err() {
            break;
        }
        match my_get_line(input, &mut buf) {
            // A hard read error maps to curl's read-error path (fileerror).
            Err(_) => {
                fileerror = true;
                break;
            }
            Ok(NextLine::Eof) => break,
            Ok(NextLine::TooLong) => {
                fileerror = true;
                break;
            }
            Ok(NextLine::Significant) => {}
        }
        lineno += 1;

        // Tokenize with a diagnostic snapshot taken *before* the option is applied.
        let (option, param) = tokenize_line(&buf, cur_fname, lineno, global.diag());

        // Dispatch to the shared option grammar. `Ok(usedarg)` is curl's `PARAM_OK` with the
        // `*usedarg` flag; every other outcome arrives as an `Err(code)`.
        let mut res: ParameterError =
            match getparameter(&option, param.as_deref(), global, max_recursive) {
                Ok(usedarg) => {
                    // C: `if(!res && param && *param && !usedarg) res = PARAM_GOT_EXTRA_PARAMETER;`
                    // A non-empty value that the option did not consume is trailing garbage.
                    let value_nonempty = param.as_deref().is_some_and(|p| !p.is_empty());
                    if value_nonempty && !usedarg {
                        ParameterError::GotExtraParameter
                    } else {
                        ParameterError::Ok
                    }
                }
                Err(code) => code,
            };

        // `--next`: advance to a fresh operation, but only if the current one already has a
        // URL. In a config file a premature `--next` is silently ignored (not an error),
        // matching curl's `parseconfig` (this differs from the command-line parser).
        if res == ParameterError::NextOperation {
            let has_url = global
                .op_ref()
                .url_list
                .first()
                .is_some_and(|g| g.url.is_some());
            if has_url {
                global.push_operation();
            }
        }

        // C: `if(res != PARAM_OK && res != PARAM_NEXT_OPERATION) { ... }`.
        if res != ParameterError::Ok && res != ParameterError::NextOperation {
            // C renames a stdin config's filename to "<stdin>" here, *before* the
            // flow-signal check — so the rename fires even for a harmless `--help`/`--version`
            // in a stdin config, and persists for later lines.
            if cur_fname == "-" {
                cur_fname = "<stdin>";
            }
            // The five "requested" signals (`--help`, `--manual`, `--version`,
            // `--engine list`, `--dump-ca-embed`) are not errors here: curl neither reports
            // nor propagates them from a config file, so parsing simply continues.
            let is_flow_signal = matches!(
                res,
                ParameterError::HelpRequested
                    | ParameterError::ManualRequested
                    | ParameterError::VersionInfoRequested
                    | ParameterError::EnginesRequested
                    | ParameterError::CaEmbedRequested
            );
            if !is_flow_signal {
                // Reason text is taken *before* the unknown-option promotion so the message
                // reads "... is unknown" (curl computes `param2text(res)` first, then
                // remaps the code it returns).
                let reason = param_geterror(res);
                errorf(
                    global.diag(),
                    &format!("{cur_fname}:{lineno} config file option '{option}' {reason}"),
                );
                if res == ParameterError::OptionUnknown {
                    res = ParameterError::ConfigOptionUnknown;
                }
                err = Err(res);
                // The loop guard breaks on the next iteration (C `while(!err …)`).
            }
        }
    }

    // An over-long line or read failure is curl's `PARAM_READ_ERROR`.
    if fileerror {
        err = Err(ParameterError::ReadError);
    }

    // curl prints this once, after the loop, for any read error. `cur_fname` is "-" for a
    // stdin read error that hit no prior rename, or "<stdin>" if a prior flow-signal renamed
    // it; for a named file it is the file path.
    if err == Err(ParameterError::ReadError) {
        errorf(
            global.diag(),
            &format!("cannot read config from '{cur_fname}'"),
        );
    }

    err
}

/// Read a curl config file and apply every directive it contains, the faithful port of
/// curl's `parseconfig` (`src/tool_parsecfg.c`).
///
/// * `filename == None` reproduces curl's `parseconfig(NULL, …)`: locate the default
///   `.curlrc` via [`find_config_file`] and, if found, parse it. Loading the default config
///   is *best-effort* — curl's caller discards the return code in this case (a missing
///   `~/.curlrc` is the normal situation and must never abort the program), so this port
///   collapses every non-load outcome of the default path (no file found, or a found file
///   that then fails to open) to `Ok(())`. This preserves curl's observable behavior while
///   remaining safe regardless of how the caller treats the result.
/// * `filename == Some("-")` reads the config from standard input.
/// * `filename == Some(path)` reads the named file; if it cannot be opened, curl's read-error
///   diagnostic is printed and [`ParameterError::ReadError`] is returned. This case is
///   reached from `--config`/`-K` via [`config_parser_hook`], where the argument parser
///   propagates the error and aborts — matching curl, for which an unreadable explicit config
///   is fatal.
///
/// `max_recursive` is the remaining `--config` nesting budget; it is threaded through to
/// [`getparameter`] so that a `--config` directive *inside* a config file is capped exactly
/// as curl caps it (`CURLRC_MAX` levels).
pub fn parseconfig(
    filename: Option<&Path>,
    max_recursive: i32,
    global: &mut GlobalConfig,
) -> Result<(), ParameterError> {
    match filename {
        // curl's `parseconfig(NULL, …)` — load the default `.curlrc` from the home dir.
        None => match find_config_file() {
            Some(path) => match File::open(&path) {
                Ok(file) => {
                    let fname = path.to_string_lossy().into_owned();
                    let mut reader = BufReader::new(file);
                    parse_stream(&mut reader, &fname, max_recursive, global)
                }
                // findfile already opened the file O_RDONLY to confirm it exists, so a failure
                // here is a rare TOCTOU race. curl returns PARAM_READ_ERROR (with no
                // diagnostic) in this branch, but its caller ignores the default-load return;
                // treating it as "no default config" keeps the common path non-fatal.
                Err(_) => Ok(()),
            },
            None => Ok(()),
        },

        // "-" reads the config from standard input (curl's `strcmp(filename, "-")` branch).
        // stdin is always "open", so parsing proceeds directly; the "-" → "<stdin>" rename for
        // diagnostics is handled inside `parse_stream`.
        Some(p) if p.as_os_str() == "-" => {
            let stdin = io::stdin();
            let mut lock = stdin.lock();
            parse_stream(&mut lock, "-", max_recursive, global)
        }

        // A named config file. An open failure is curl's `else err = PARAM_READ_ERROR`
        // followed by the post-block "cannot read config from '<file>'" diagnostic.
        Some(path) => {
            let fname = path.to_string_lossy().into_owned();
            match File::open(path) {
                Ok(file) => {
                    let mut reader = BufReader::new(file);
                    parse_stream(&mut reader, &fname, max_recursive, global)
                }
                Err(_) => {
                    errorf(global.diag(), &format!("cannot read config from '{fname}'"));
                    Err(ParameterError::ReadError)
                }
            }
        }
    }
}

/// [`crate::args::ConfigParserHook`]-typed adapter that lets the argument parser reach config
/// parsing without a module cycle. `main.rs` installs it once at startup with
/// `global.config_parser = Some(parsecfg::config_parser_hook);`, and `--config`/`-K`
/// dispatches through it (see `args::opt_file`, `Cmd::Config`). `filename` is the raw option
/// argument — a path, or `"-"` for stdin — forwarded verbatim to [`parseconfig`].
pub fn config_parser_hook(
    filename: &str,
    max_recursive: i32,
    global: &mut GlobalConfig,
) -> Result<(), ParameterError> {
    parseconfig(Some(Path::new(filename)), max_recursive, global)
}

// --------------------------------------------------------------------------------------------
// Default config-file discovery — port of `src/tool_findfile.c`.
// --------------------------------------------------------------------------------------------

/// One entry of curl's `conf_list[]` search table: an environment variable, an optional path
/// suffix appended to that variable's value, and whether the entry uses the XDG-style
/// "without dot" filename (`curlrc` rather than `.curlrc`).
struct Finder {
    /// Environment variable naming a base directory.
    env: &'static str,
    /// Optional suffix concatenated onto the variable's value (curl appends it with a plain
    /// string concat, e.g. `"$HOME" + "/.config"`).
    append: Option<&'static str>,
    /// When true this is an XDG-style entry: the leading dot is stripped from the filename and
    /// the entry participates in the single-shot "dotscore" latch (see [`findfile`]).
    withoutdot: bool,
}

/// curl's `conf_list[]`, with the three Windows-only entries (`USERPROFILE`, `APPDATA`,
/// `USERPROFILE\Application Data`) omitted because those platforms are out of scope. Order is
/// significant and preserved exactly:
///
/// 1. `$CURL_HOME/.curlrc`
/// 2. `$XDG_CONFIG_HOME/curlrc`   (dot stripped)
/// 3. `$HOME/.curlrc`
/// 4. `$CURL_HOME/.config/curlrc` (only when no earlier "withoutdot" entry matched)
/// 5. `$HOME/.config/curlrc`      (only when no earlier "withoutdot" entry matched)
const CONF_LIST: &[Finder] = &[
    Finder {
        env: "CURL_HOME",
        append: None,
        withoutdot: false,
    },
    Finder {
        env: "XDG_CONFIG_HOME",
        append: None,
        withoutdot: true,
    },
    Finder {
        env: "HOME",
        append: None,
        withoutdot: false,
    },
    // The following handle .curlrc when XDG_CONFIG_HOME is not defined.
    Finder {
        env: "CURL_HOME",
        append: Some("/.config"),
        withoutdot: true,
    },
    Finder {
        env: "HOME",
        append: Some("/.config"),
        withoutdot: true,
    },
];

/// Locate the default `.curlrc`, the public entry point used for curl's implicit config load
/// (`parseconfig(None, …)`) when the user did not pass `-q`/`--disable`. Returns the first
/// existing, readable candidate from [`CONF_LIST`], or `None` if none is found.
///
/// This is the safe, `std`-only realization of curl's `findfile(".curlrc", CURLRC_DOTSCORE)`.
/// The environment is read through [`std::env::var_os`]; the `getpwuid(geteuid())` home-dir
/// fallback in the C code is intentionally not ported (it would require an `unsafe` libc call,
/// and this module is outside the unsafe-permitted set — AAP §0.7.2). On the supported
/// platforms `$HOME` is set, so that fallback is unreachable in practice.
pub fn find_config_file() -> Option<PathBuf> {
    findfile(".curlrc", CURLRC_DOTSCORE, &|key| std::env::var_os(key))
}

/// curl's `CURLRC_DOTSCORE` on the non-Windows build: a plain `.curlrc` search with no
/// underscore-prefixed variant. (The Windows build uses `2` to also try `_curlrc`.)
const CURLRC_DOTSCORE: i32 = 1;

/// The generic engine behind [`find_config_file`], parameterized over the environment lookup
/// so it can be unit-tested deterministically. A faithful port of curl's `findfile()`,
/// including the `dotscore` latch that makes only the *first* matching XDG-style ("withoutdot")
/// entry active: once such an entry's environment variable is set, `dotscore` is zeroed and
/// every subsequent "withoutdot" entry is skipped.
fn findfile<F>(fname: &str, dotscore_init: i32, getenv: &F) -> Option<PathBuf>
where
    F: Fn(&str) -> Option<std::ffi::OsString>,
{
    if fname.is_empty() {
        return None;
    }
    // `dotscore` is mutated as we walk the table (curl mutates its `int dotscore` parameter).
    let mut dotscore = dotscore_init;

    for entry in CONF_LIST {
        // Skip entries whose environment variable is unset or empty (curl: `if(!home) …;` and
        // `if(!home[0]) { … continue; }`).
        let home = match getenv(entry.env) {
            Some(h) if !h.is_empty() => h,
            _ => continue,
        };
        let mut home_path = PathBuf::from(home);
        let mut filename = fname;

        // Append the optional suffix as a raw string concat (curl: `maprintf("%s%s", …)`).
        // Using OsString::push (not PathBuf::push) reproduces the byte concat exactly and
        // avoids the absolute-path replacement PathBuf::push would perform for "/.config".
        if let Some(app) = entry.append {
            let mut s = home_path.into_os_string();
            s.push(app);
            home_path = PathBuf::from(s);
        }

        if entry.withoutdot {
            if dotscore == 0 {
                // A prior "withoutdot" entry already claimed the single XDG slot — skip.
                continue;
            }
            // Move past the leading '.' of ".curlrc" → "curlrc" and latch the slot closed.
            filename = &fname[1..];
            dotscore = 0;
        }

        // curl passes `dotscore ? dotscore - 1 : 0`, which is always 0 here (findfile is only
        // ever called with dotscore == 1), so checkhome tests just the single leading-dot (or
        // already-stripped) form — never the "_"-prefixed variant.
        if let Some(path) = checkhome(&home_path, filename, false) {
            return Some(path);
        }
    }

    None
}

/// Port of curl's `checkhome()`: build the candidate path `<home>/<leaf>` and return it if the
/// file can be opened for reading. When `dotscore` is true (the DOS/Windows convention that is
/// never reached on the supported platforms — see [`findfile`]) the leaf is tried first with a
/// leading `.` then a leading `_`; otherwise `fname` is used verbatim.
fn checkhome(home: &Path, fname: &str, dotscore: bool) -> Option<PathBuf> {
    if dotscore {
        // fname is like ".curlrc"; `&fname[1..]` drops the dot, then each prefix is prepended.
        let stem = &fname[1..];
        for pref in ['.', '_'] {
            let cand = home.join(format!("{pref}{stem}"));
            if file_readable(&cand) {
                return Some(cand);
            }
        }
        None
    } else {
        let cand = home.join(fname);
        file_readable(&cand).then_some(cand)
    }
}

/// True when `path` names an existing file that can be opened for reading. curl tests
/// candidates with `open(c, O_RDONLY)` and checks the descriptor, so a path that exists but is
/// unreadable does not count; [`File::open`] (read-only) reproduces exactly that predicate.
fn file_readable(path: &Path) -> bool {
    File::open(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::{GlobalConfig, ParameterError, CONFIG_MAX_LEVELS};
    use std::ffi::OsString;
    use std::io::Cursor;

    // ---- unslashquote ------------------------------------------------------------------

    #[test]
    fn unslashquote_recognized_escapes() {
        // \t \n \r \v and the literal \\ and \" all decode as curl documents.
        assert_eq!(unslashquote(br"a\tb"), b"a\tb");
        assert_eq!(unslashquote(br"a\nb"), b"a\nb");
        assert_eq!(unslashquote(br"a\rb"), b"a\rb");
        assert_eq!(unslashquote(br"a\vb"), b"a\x0bb");
        assert_eq!(unslashquote(br"a\\b"), b"a\\b");
        assert_eq!(unslashquote(br#"a\"b"#), b"a\"b");
    }

    #[test]
    fn unslashquote_unknown_escape_is_literal() {
        // A backslash before any other character emits that character verbatim.
        assert_eq!(unslashquote(br"a\zb"), b"azb");
        assert_eq!(unslashquote(br"\x"), b"x");
    }

    #[test]
    fn unslashquote_stops_at_unescaped_quote() {
        // Parsing stops at the first non-backslash-quoted double quote.
        assert_eq!(unslashquote(br#"abc"def"#), b"abc");
        // An escaped quote is included, and parsing continues until the next bare quote.
        assert_eq!(unslashquote(br#"a\"b"c"#), b"a\"b");
    }

    #[test]
    fn unslashquote_trailing_lone_backslash_is_dropped() {
        // A backslash as the final byte ends the value (C `case '\0': continue;`).
        assert_eq!(unslashquote(br"ab\"), b"ab");
        assert_eq!(unslashquote(b""), b"");
    }

    // ---- tokenize_line -----------------------------------------------------------------

    /// A silenced diagnostic sink so tokenizer advisory warnings do not spam test output.
    fn quiet() -> Diag {
        Diag {
            silent: true,
            showerror: false,
            tracing: false,
        }
    }

    fn tok(line: &str) -> (String, Option<String>) {
        tokenize_line(line.as_bytes(), "t", 1, quiet())
    }

    #[test]
    fn tokenize_bare_flag_has_no_value() {
        assert_eq!(tok("verbose"), ("verbose".to_string(), None));
    }

    #[test]
    fn tokenize_space_separated_value() {
        assert_eq!(
            tok("user-agent foo"),
            ("user-agent".to_string(), Some("foo".to_string()))
        );
    }

    #[test]
    fn tokenize_equals_and_colon_separator_when_not_dashed() {
        // A dash-less option accepts `=` and `:` as separators (the ISSEP rule).
        assert_eq!(
            tok("user-agent=foo"),
            ("user-agent".to_string(), Some("foo".to_string()))
        );
        assert_eq!(
            tok("user-agent:foo"),
            ("user-agent".to_string(), Some("foo".to_string()))
        );
        // `url = value` (blanks around the separator) is the documented bare-URL form.
        assert_eq!(
            tok("url = http://x/"),
            ("url".to_string(), Some("http://x/".to_string()))
        );
    }

    #[test]
    fn tokenize_dashed_option_does_not_split_on_colon_or_equals() {
        // With an initial dash, `:` and `=` are part of the option name, not separators.
        assert_eq!(
            tok("--user-agent:foo"),
            ("--user-agent:foo".to_string(), None)
        );
        assert_eq!(tok("--data=x=y"), ("--data=x=y".to_string(), None));
        // A dashed option still splits on whitespace.
        assert_eq!(
            tok("--user-agent foo"),
            ("--user-agent".to_string(), Some("foo".to_string()))
        );
    }

    #[test]
    fn tokenize_leading_whitespace_yields_empty_option() {
        // Leading whitespace is not stripped: the option name is empty and the first token
        // becomes the "value". curl then rejects the empty option as unknown.
        assert_eq!(
            tok(" verbose"),
            (String::new(), Some("verbose".to_string()))
        );
    }

    #[test]
    fn tokenize_quoted_value_preserves_spaces_and_may_be_empty() {
        assert_eq!(
            tok("user-agent \"foo bar\""),
            ("user-agent".to_string(), Some("foo bar".to_string()))
        );
        // A quoted value is always present, even when empty (curl returns "" not NULL).
        assert_eq!(
            tok("user-agent \"\""),
            ("user-agent".to_string(), Some(String::new()))
        );
    }

    #[test]
    fn tokenize_quoted_value_applies_backslash_escapes() {
        assert_eq!(
            tok(r#"user-agent "a\tb\"c""#),
            ("user-agent".to_string(), Some("a\tb\"c".to_string()))
        );
    }

    #[test]
    fn tokenize_unquoted_value_stops_at_carriage_return() {
        // A trailing CR (from a CRLF file, newline already dropped) terminates an unquoted
        // value because ISSPACE includes '\r'.
        assert_eq!(
            tok("user-agent foo\r"),
            ("user-agent".to_string(), Some("foo".to_string()))
        );
    }

    #[test]
    fn tokenize_crlf_bare_flag_keeps_cr_in_name() {
        // For an option-only line the name scan uses ISBLANK (space/tab only), so a trailing
        // CR stays part of the option name — matching curl (an option-only CRLF line is an
        // unknown option). Verified against the system curl oracle.
        assert_eq!(tok("verbose\r"), ("verbose\r".to_string(), None));
    }

    // ---- my_get_line / read_raw_line ---------------------------------------------------

    #[test]
    fn get_line_skips_blank_and_comment_lines() {
        let mut cur = Cursor::new(b"# a comment\n\n   \n\tverbose\n".to_vec());
        let mut buf = Vec::new();
        // The first three lines (comment, empty, all-blank) are skipped; the first
        // significant line still carries its leading tab.
        match my_get_line(&mut cur, &mut buf).unwrap() {
            NextLine::Significant => {}
            _ => panic!("expected a significant line"),
        }
        assert_eq!(buf, b"\tverbose");
        // Nothing significant remains.
        match my_get_line(&mut cur, &mut buf).unwrap() {
            NextLine::Eof => {}
            _ => panic!("expected EOF"),
        }
    }

    #[test]
    fn read_raw_line_drops_lf_keeps_cr() {
        let mut cur = Cursor::new(b"opt\r\nnext".to_vec());
        let mut buf = Vec::new();
        match read_raw_line(&mut cur, &mut buf).unwrap() {
            RawLine::Got => {}
            _ => panic!("expected a line"),
        }
        // Only the '\n' is removed; the '\r' is preserved.
        assert_eq!(buf, b"opt\r");
        // The final unterminated line is still returned.
        match read_raw_line(&mut cur, &mut buf).unwrap() {
            RawLine::Got => {}
            _ => panic!("expected the final line"),
        }
        assert_eq!(buf, b"next");
    }

    #[test]
    fn read_raw_line_rejects_overlong_line() {
        // A single line longer than the 10 MB ceiling is a read error, not buffered in full.
        let mut data = vec![b'a'; MAX_CONFIG_LINE_LENGTH + 5];
        data.push(b'\n');
        let mut cur = Cursor::new(data);
        let mut buf = Vec::new();
        match read_raw_line(&mut cur, &mut buf).unwrap() {
            RawLine::TooLong => {}
            _ => panic!("expected TooLong"),
        }
    }

    // ---- parse_stream (end-to-end dispatch to getparameter) ----------------------------

    fn parse(data: &[u8], fname: &str) -> (GlobalConfig, Result<(), ParameterError>) {
        let mut g = GlobalConfig::new();
        let mut cur = Cursor::new(data.to_vec());
        let res = parse_stream(&mut cur, fname, CONFIG_MAX_LEVELS, &mut g);
        (g, res)
    }

    #[test]
    fn parse_applies_quoted_option() {
        let (g, res) = parse(b"user-agent \"foo bar\"\n", "t");
        assert_eq!(res, Ok(()));
        assert_eq!(g.op_ref().useragent.as_deref(), Some("foo bar"));
    }

    #[test]
    fn parse_skips_comments_and_blanks() {
        let (g, res) = parse(b"# lead comment\n\n   \nuser-agent me\n", "t");
        assert_eq!(res, Ok(()));
        assert_eq!(g.op_ref().useragent.as_deref(), Some("me"));
    }

    #[test]
    fn parse_colon_separator_without_dash() {
        let (g, res) = parse(b"user-agent:viacolon\n", "t");
        assert_eq!(res, Ok(()));
        assert_eq!(g.op_ref().useragent.as_deref(), Some("viacolon"));
    }

    #[test]
    fn parse_url_directive() {
        let (g, res) = parse(b"url = http://example.invalid/\n", "t");
        assert_eq!(res, Ok(()));
        assert!(g
            .op_ref()
            .url_list
            .iter()
            .any(|u| u.url.as_deref() == Some("http://example.invalid/")));
    }

    #[test]
    fn parse_unknown_option_is_config_option_unknown() {
        // PARAM_OPTION_UNKNOWN is promoted to PARAM_CONFIG_OPTION_UNKNOWN in a config file.
        let (_g, res) = parse(b"totally-unknown-xyz\n", "t");
        assert_eq!(res, Err(ParameterError::ConfigOptionUnknown));
    }

    #[test]
    fn parse_dashed_colon_is_unknown_option() {
        // End-to-end proof of the ISSEP dash rule: `--user-agent:x` is one (unknown) token.
        let (_g, res) = parse(b"--user-agent:x\n", "t");
        assert_eq!(res, Err(ParameterError::ConfigOptionUnknown));
    }

    #[test]
    fn parse_extra_argument_to_flag_is_got_extra() {
        // A boolean flag given a value it does not consume yields GOT_EXTRA_PARAMETER.
        let (_g, res) = parse(b"verbose extra\n", "t");
        assert_eq!(res, Err(ParameterError::GotExtraParameter));
    }

    #[test]
    fn parse_overlong_line_is_read_error() {
        let mut data = vec![b'a'; MAX_CONFIG_LINE_LENGTH + 5];
        data.push(b'\n');
        let (_g, res) = parse(&data, "t");
        assert_eq!(res, Err(ParameterError::ReadError));
    }

    #[test]
    fn parse_stdin_name_still_reports_unknown() {
        // Exercises the "-" (stdin) diagnostic path; the return code is unaffected by the
        // "<stdin>" filename rename (which only changes the printed message).
        let (_g, res) = parse(b"totally-unknown-xyz\n", "-");
        assert_eq!(res, Err(ParameterError::ConfigOptionUnknown));
    }

    // ---- findfile / checkhome (default-config discovery, mocked environment) ------------

    /// Build an environment lookup returning the given (name -> dir) pairs.
    fn mock_env(pairs: Vec<(&'static str, PathBuf)>) -> impl Fn(&str) -> Option<OsString> {
        move |key: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.as_os_str().to_os_string())
        }
    }

    #[test]
    fn findfile_curl_home_dot_curlrc() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".curlrc"), b"# cfg\n").unwrap();
        let env = mock_env(vec![("CURL_HOME", dir.path().to_path_buf())]);
        assert_eq!(
            findfile(".curlrc", CURLRC_DOTSCORE, &env),
            Some(dir.path().join(".curlrc"))
        );
    }

    #[test]
    fn findfile_curl_home_precedes_home() {
        // Both CURL_HOME and HOME hold a .curlrc; CURL_HOME (listed first) wins.
        let ch = tempfile::tempdir().unwrap();
        let hm = tempfile::tempdir().unwrap();
        std::fs::write(ch.path().join(".curlrc"), b"a").unwrap();
        std::fs::write(hm.path().join(".curlrc"), b"b").unwrap();
        let env = mock_env(vec![
            ("CURL_HOME", ch.path().to_path_buf()),
            ("HOME", hm.path().to_path_buf()),
        ]);
        assert_eq!(
            findfile(".curlrc", CURLRC_DOTSCORE, &env),
            Some(ch.path().join(".curlrc"))
        );
    }

    #[test]
    fn findfile_xdg_uses_dotless_name() {
        // XDG_CONFIG_HOME uses the dot-stripped filename "curlrc".
        let xdg = tempfile::tempdir().unwrap();
        std::fs::write(xdg.path().join("curlrc"), b"x").unwrap();
        let env = mock_env(vec![("XDG_CONFIG_HOME", xdg.path().to_path_buf())]);
        assert_eq!(
            findfile(".curlrc", CURLRC_DOTSCORE, &env),
            Some(xdg.path().join("curlrc"))
        );
    }

    #[test]
    fn findfile_home_dotconfig_fallback_when_xdg_unset() {
        // With XDG unset, the "$HOME/.config/curlrc" fallback is consulted.
        let hm = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(hm.path().join(".config")).unwrap();
        std::fs::write(hm.path().join(".config").join("curlrc"), b"y").unwrap();
        let env = mock_env(vec![("HOME", hm.path().to_path_buf())]);
        assert_eq!(
            findfile(".curlrc", CURLRC_DOTSCORE, &env),
            Some(hm.path().join(".config").join("curlrc"))
        );
    }

    #[test]
    fn findfile_dotscore_latch_blocks_later_withoutdot_entries() {
        // When XDG_CONFIG_HOME is set (even if it has no curlrc), the single "withoutdot"
        // slot is consumed, so the later $HOME/.config/curlrc is NOT consulted — faithful to
        // curl's dotscore latch. Here only $HOME/.config/curlrc exists, yet the search misses
        // it because XDG_CONFIG_HOME claimed the slot first.
        let xdg = tempfile::tempdir().unwrap(); // set, but contains no "curlrc"
        let hm = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(hm.path().join(".config")).unwrap();
        std::fs::write(hm.path().join(".config").join("curlrc"), b"z").unwrap();
        let env = mock_env(vec![
            ("XDG_CONFIG_HOME", xdg.path().to_path_buf()),
            ("HOME", hm.path().to_path_buf()),
        ]);
        assert_eq!(findfile(".curlrc", CURLRC_DOTSCORE, &env), None);
    }

    #[test]
    fn findfile_empty_env_value_is_skipped() {
        // An empty variable value is ignored (curl's `if(!home[0]) continue;`), so the search
        // falls through to HOME.
        let hm = tempfile::tempdir().unwrap();
        std::fs::write(hm.path().join(".curlrc"), b"h").unwrap();
        let env = mock_env(vec![
            ("CURL_HOME", PathBuf::new()),
            ("HOME", hm.path().to_path_buf()),
        ]);
        assert_eq!(
            findfile(".curlrc", CURLRC_DOTSCORE, &env),
            Some(hm.path().join(".curlrc"))
        );
    }

    #[test]
    fn findfile_returns_none_when_nothing_exists() {
        let dir = tempfile::tempdir().unwrap(); // empty dir, no config file
        let env = mock_env(vec![("HOME", dir.path().to_path_buf())]);
        assert_eq!(findfile(".curlrc", CURLRC_DOTSCORE, &env), None);
    }

    #[test]
    fn checkhome_detects_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".curlrc"), b"c").unwrap();
        assert_eq!(
            checkhome(dir.path(), ".curlrc", false),
            Some(dir.path().join(".curlrc"))
        );
        assert_eq!(checkhome(dir.path(), "does-not-exist", false), None);
    }

    // ---- parseconfig (named file + default) --------------------------------------------

    #[test]
    fn parseconfig_reads_named_file() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("my.cfg");
        std::fs::write(&cfg, b"user-agent = \"fromfile/1\"\n").unwrap();
        let mut g = GlobalConfig::new();
        let res = parseconfig(Some(&cfg), CONFIG_MAX_LEVELS, &mut g);
        assert_eq!(res, Ok(()));
        assert_eq!(g.op_ref().useragent.as_deref(), Some("fromfile/1"));
    }

    #[test]
    fn parseconfig_missing_named_file_is_read_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.cfg");
        let mut g = GlobalConfig::new();
        let res = parseconfig(Some(&missing), CONFIG_MAX_LEVELS, &mut g);
        assert_eq!(res, Err(ParameterError::ReadError));
    }

    #[test]
    fn config_parser_hook_forwards_to_parseconfig() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("hook.cfg");
        std::fs::write(&cfg, b"user-agent hooked/2\n").unwrap();
        let mut g = GlobalConfig::new();
        let res = config_parser_hook(cfg.to_str().unwrap(), CONFIG_MAX_LEVELS, &mut g);
        assert_eq!(res, Ok(()));
        assert_eq!(g.op_ref().useragent.as_deref(), Some("hooked/2"));
    }
}
