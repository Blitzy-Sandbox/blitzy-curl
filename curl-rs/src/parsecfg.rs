// -----------------------------------------------------------------------
// curl-rs/src/parsecfg.rs — .curlrc Config File Parser
//
// Rust rewrite of src/tool_parsecfg.c and src/tool_parsecfg.h from
// curl 8.19.0-DEV.
//
// Parses `.curlrc` configuration files, extracting option/parameter
// pairs and dispatching them through the argument parser.  Supports:
//
//   - Default config file discovery via `find_curlrc()`
//   - Explicit file path or stdin (`"-"`)
//   - Comment lines (starting with `#`)
//   - Blank line skipping
//   - Double-quoted parameters with backslash escape sequences
//   - Bare (non-dashed) option names with `=` / `:` separators
//   - Dashed option names (single `-` or `--`) where `=` / `:` are
//     NOT treated as separators (ISSEP rule)
//   - `--no-` prefix negation for boolean options
//   - Recursive `--config` / `-K` includes with depth limiting
//   - Warnings for single-quoted parameters and unquoted whitespace
//
// Zero `unsafe` blocks.
//
// SPDX-License-Identifier: curl
// -----------------------------------------------------------------------

use std::fs::File;
use std::io::{self, BufRead, BufReader};

use anyhow::{bail, Context, Result};

use crate::args::{
    findlongopt, findshortopt, getparameter, param2text, CmdlineOption,
    LongShort, ParameterError, ParameterResult,
};
use crate::config::{GlobalConfig, OperationConfig};
use crate::findfile::find_curlrc;
use crate::msgs::{errorf, warnf};

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

/// Maximum nesting depth for recursive `--config` / `-K` includes.
///
/// Matches the C `#define CONFIG_MAX_LEVELS 5` in `src/tool_parsecfg.h`.
/// Prevents infinite recursion when config files reference each other.
pub const CONFIG_MAX_LEVELS: usize = 5;

// ---------------------------------------------------------------------------
// Private constants
// ---------------------------------------------------------------------------

/// Maximum length of a single configuration file line (10 MiB).
///
/// Matches the C `MAX_CONFIG_LINE_LENGTH` constant used by `curlx_dyn_init`
/// inside the config parser.  Lines exceeding this limit are rejected to
/// prevent unbounded memory allocation from malicious or corrupt files.
const MAX_CONFIG_LINE_LENGTH: usize = 10 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Private helpers: character classification
// ---------------------------------------------------------------------------

/// Returns `true` if the character is a blank (space or horizontal tab).
///
/// Matches the C `ISBLANK()` macro semantics: only ASCII space (0x20) and
/// horizontal tab (0x09) are considered blank.
#[inline]
fn is_blank(c: char) -> bool {
    c == ' ' || c == '\t'
}

/// Returns `true` if the character is a separator (colon or equals),
/// but **only** when the option was NOT specified with a leading dash.
///
/// This directly implements the C macro:
/// ```c
/// #define ISSEP(x, dash) (!(dash) && (((x) == '=') || ((x) == ':')))
/// ```
///
/// The rule ensures that for dashed options (e.g., `--header`), the `:`
/// and `=` characters are NOT treated as option/parameter separators,
/// allowing values like `--header "Content-Type: text/html"` to be
/// parsed correctly in config files.
#[inline]
fn is_sep(c: char, dashed: bool) -> bool {
    !dashed && (c == '=' || c == ':')
}

/// Returns `true` if the character is any whitespace (space, tab, CR, LF).
///
/// Matches the C `ISSPACE()` macro: recognises space, tab, carriage
/// return, newline, vertical tab, and form feed.
#[inline]
fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n' | '\x0B' | '\x0C')
}

// ---------------------------------------------------------------------------
// Argument type extraction — duplicated from args.rs private constants
// ---------------------------------------------------------------------------

/// Bitmask for extracting the base argument type from `LongShort::desc_flags`.
const ARG_TYPEMASK: u32 = 0x0F;

/// Argument takes a string value.
const ARG_STRG: u32 = 2;

/// Argument takes a filename value.
const ARG_FILE: u32 = 3;

/// Returns `true` if the option described by `desc_flags` consumes a
/// parameter (i.e., is of type `ARG_STRG` or `ARG_FILE`).
///
/// Used to implement the `usedarg` tracking from the C config parser:
/// if a parameter was provided on the config line but the matched option
/// does not consume parameters, `PARAM_GOT_EXTRA_PARAMETER` is reported.
#[inline]
fn option_consumes_param(desc_flags: u32) -> bool {
    let base = desc_flags & ARG_TYPEMASK;
    base == ARG_STRG || base == ARG_FILE
}

// ---------------------------------------------------------------------------
// Line reader: my_get_line
// ---------------------------------------------------------------------------

/// Reads the next meaningful line from a config file reader.
///
/// Skips blank lines and comment lines (where the first non-blank
/// character is `#`).  Returns `Ok(None)` on EOF.  The returned line
/// has leading whitespace trimmed and trailing CR/LF removed.
///
/// This is the Rust equivalent of the C `my_get_line()` function in
/// `src/tool_parsecfg.c`, which internally calls `get_line()` to handle
/// buffered reading and line assembly.
///
/// # Errors
///
/// Returns `io::Error` if the underlying reader encounters an I/O error
/// or if a line exceeds [`MAX_CONFIG_LINE_LENGTH`].
fn my_get_line(reader: &mut dyn BufRead) -> io::Result<Option<String>> {
    let mut raw = String::new();

    loop {
        raw.clear();
        let bytes_read = reader.read_line(&mut raw)?;
        if bytes_read == 0 {
            // EOF — no more lines.
            return Ok(None);
        }

        // Enforce maximum line length to prevent unbounded allocation
        // from malicious or corrupt config files.
        if raw.len() > MAX_CONFIG_LINE_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "config file line exceeds maximum length",
            ));
        }

        // Strip trailing newline characters (LF, CRLF).
        let trimmed_end = raw.trim_end_matches(['\n', '\r']);

        // Skip completely empty lines (after newline stripping).
        if trimmed_end.is_empty() {
            continue;
        }

        // Trim leading whitespace (spaces and tabs only, matching C ISBLANK).
        let trimmed = trimmed_end.trim_start_matches(|c: char| is_blank(c));

        // Skip blank-only lines.
        if trimmed.is_empty() {
            continue;
        }

        // A line with `#` in the first non-blank column is a comment.
        if trimmed.starts_with('#') {
            continue;
        }

        return Ok(Some(trimmed.to_string()));
    }
}

// ---------------------------------------------------------------------------
// Quoting/unescaping: unslash_quote
// ---------------------------------------------------------------------------

/// Processes a double-quoted parameter string, handling backslash escape
/// sequences and stopping at the first unescaped double-quote character
/// or the end of the input string.
///
/// Recognised escape sequences:
/// - `\t` → horizontal tab (0x09)
/// - `\n` → newline (0x0A)
/// - `\r` → carriage return (0x0D)
/// - `\v` → vertical tab (0x0B)
/// - `\X` → literal `X` for any other character `X`
/// - `\` at end of string → terminates processing (C `continue` on `\0`)
///
/// This is the Rust equivalent of the C `unslashquote()` static function
/// in `src/tool_parsecfg.c`.
///
/// # Arguments
///
/// * `input` — The portion of the config line **after** the opening
///   double-quote character.  The function reads up to and including
///   the closing double-quote or end of string.
///
/// # Returns
///
/// The unescaped string content between the quotes.
fn unslash_quote(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars();

    while let Some(c) = chars.next() {
        if c == '"' {
            // Stop at the first unescaped double-quote.
            break;
        }

        if c == '\\' {
            // Backslash escape — look at the next character.
            match chars.next() {
                None => {
                    // Backslash at end of string — break out of loop.
                    // Matches C: `case '\0': continue;` which breaks the while.
                    break;
                }
                Some('t') => result.push('\t'),
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('v') => result.push('\x0B'),
                Some(other) => result.push(other),
            }
        } else {
            result.push(c);
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Option name processing
// ---------------------------------------------------------------------------

/// Strips leading dashes from an option name and detects the `no-`
/// negation prefix for boolean options.
///
/// # Returns
///
/// A tuple of `(clean_name, is_negated)` where:
/// - `clean_name` is the option name with leading `--` or `-` removed.
/// - `is_negated` is `true` if the option was prefixed with `--no-` and
///   the base name (without `no-`) resolves to a known option.
///
/// The function first attempts to look up the full name (with `no-` if
/// present).  If the full name is found in the alias table, `is_negated`
/// is `false` because options like `--no-alpn` are canonical names, not
/// negations.  Only if the full name is NOT found does it try stripping
/// `no-` and looking up the base name.
fn prepare_option(raw_option: &str) -> (String, bool) {
    // Strip leading dashes: -- or -
    let stripped = if let Some(rest) = raw_option.strip_prefix("--") {
        rest
    } else if let Some(rest) = raw_option.strip_prefix('-') {
        rest
    } else {
        raw_option
    };

    // For single-character options, no negation handling needed.
    if stripped.len() <= 1 {
        return (stripped.to_string(), false);
    }

    // Try exact lookup first — handles canonical names like `no-alpn`.
    if findlongopt(stripped).is_some() {
        return (stripped.to_string(), false);
    }

    // If the name starts with `no-`, try stripping it for boolean negation.
    if let Some(base_name) = stripped.strip_prefix("no-") {
        if !base_name.is_empty() && findlongopt(base_name).is_some() {
            return (base_name.to_string(), true);
        }
    }

    // Option not found — return as-is; getparameter will report the error.
    (stripped.to_string(), false)
}

/// Looks up an option name (already stripped of dashes) in the alias
/// tables and returns the matching `LongShort` entry if found.
///
/// Single-character names are looked up as short options; multi-character
/// names are looked up as long options.
fn lookup_option(clean_name: &str) -> Option<&'static LongShort> {
    if clean_name.len() == 1 {
        findshortopt(clean_name.chars().next().unwrap_or('\0'))
    } else {
        findlongopt(clean_name)
    }
}

// ---------------------------------------------------------------------------
// Public API: parseconfig
// ---------------------------------------------------------------------------

/// Parses a `.curlrc` configuration file, applying each option/parameter
/// pair to the current operation configuration via `getparameter()`.
///
/// This is the public entry point — the Rust equivalent of the C
/// `parseconfig()` function in `src/tool_parsecfg.c`.
///
/// # Arguments
///
/// * `path` — Path to the config file.
///   - `None` → load the default `.curlrc` from the user's home directory
///     (via [`find_curlrc()`]).  If no default config is found, the
///     function returns `Ok(())` silently.
///   - `Some("-")` → read from standard input.
///   - `Some(path)` → open and read the specified file.
///
/// * `global` — Mutable reference to the global configuration.  The
///   parser modifies `global.configs` when `--next` (`PARAM_NEXT_OPERATION`)
///   is encountered, and passes `global` to `getparameter()` for option
///   dispatch and warning/error output.
///
/// # Errors
///
/// Returns an error if:
/// - The specified config file cannot be opened.
/// - An I/O error occurs while reading the file.
/// - A config file option is invalid and produces a non-help error.
/// - The recursion depth limit ([`CONFIG_MAX_LEVELS`]) is exceeded.
///
/// # Config File Format
///
/// Each line is one of:
/// - A comment: first non-blank character is `#`
/// - An option without dashes: `option_name = value` or `option_name: value`
/// - An option with dashes: `--long-option value` or `-X value`
/// - An option with a double-quoted value: `option "value with spaces"`
///
/// The ISSEP rule: `:` and `=` are treated as separators **only** when
/// the option name does NOT start with a dash.
pub fn parseconfig(path: Option<&str>, global: &mut GlobalConfig) -> Result<()> {
    parseconfig_inner(path, global, CONFIG_MAX_LEVELS)
}

// ---------------------------------------------------------------------------
// Internal recursive implementation
// ---------------------------------------------------------------------------

/// Internal config parser with depth tracking for recursion limiting.
///
/// This function implements the full parsing logic.  The public
/// [`parseconfig()`] function delegates to this with the initial depth
/// set to [`CONFIG_MAX_LEVELS`].
///
/// # Arguments
///
/// * `path`   — Config file path (same semantics as [`parseconfig()`]).
/// * `global` — Global configuration.
/// * `depth`  — Remaining recursion depth.  Decremented on each
///   recursive `--config` include.  When it reaches 0, further includes
///   are rejected.
fn parseconfig_inner(
    path: Option<&str>,
    global: &mut GlobalConfig,
    depth: usize,
) -> Result<()> {
    // ------------------------------------------------------------------
    // Phase 1: Open the config file (or stdin)
    // ------------------------------------------------------------------

    // `filename` is used for diagnostic messages throughout the parser.
    let filename: String;
    let reader: Box<dyn BufRead>;

    match path {
        None => {
            // NULL / None → load default .curlrc from home directory.
            // If no default config file is found, return silently.
            match find_curlrc() {
                Some(curlrc_path) => {
                    let path_str = curlrc_path.to_string_lossy().to_string();
                    match File::open(&curlrc_path) {
                        Ok(f) => {
                            filename = path_str;
                            reader = Box::new(BufReader::new(f));
                        }
                        Err(_) => {
                            // File was found by find_curlrc but cannot be opened
                            // (permissions or race condition).  The C code returns
                            // PARAM_READ_ERROR here without printing a message when
                            // filename is the default curlrc.
                            errorf(
                                global,
                                &format!("cannot read config from '{}'", path_str),
                            );
                            bail!("cannot read config from '{}'", path_str);
                        }
                    }
                }
                None => {
                    // No default config file found — not an error.
                    return Ok(());
                }
            }
        }

        Some("-") => {
            // Read from standard input.
            filename = "-".to_string();
            reader = Box::new(BufReader::new(io::stdin()));
        }

        Some(path_str) => {
            // Explicit file path.
            match File::open(path_str) {
                Ok(f) => {
                    filename = path_str.to_string();
                    reader = Box::new(BufReader::new(f));
                }
                Err(_) => {
                    errorf(
                        global,
                        &format!("cannot read config from '{}'", path_str),
                    );
                    bail!("cannot read config from '{}'", path_str);
                }
            }
        }
    }

    // Ensure at least one OperationConfig exists in the global config
    // chain before we start dispatching options.
    if global.configs.is_empty() {
        global.configs.push(OperationConfig::new());
    }

    // ------------------------------------------------------------------
    // Phase 2: Read and parse config lines
    // ------------------------------------------------------------------

    let mut reader = reader;
    let mut lineno: u32 = 0;

    loop {
        // Read the next meaningful line (skipping blanks and comments).
        let line = match my_get_line(&mut *reader) {
            Ok(Some(l)) => l,
            Ok(None) => break, // EOF
            Err(e) => {
                // I/O error or line-length violation.
                errorf(
                    global,
                    &format!("cannot read config from '{}'", filename),
                );
                return Err(e).context(format!(
                    "error reading config file '{}'",
                    filename
                ));
            }
        };

        lineno += 1;

        // ---- Extract the option keyword ----
        //
        // The option keyword starts at the beginning of the line (after
        // leading whitespace was already trimmed by my_get_line).
        //
        // `dashed_option` determines whether `:` and `=` act as
        // separators (ISSEP rule).
        let dashed_option = line.starts_with('-');

        // Scan forward to find the end of the option name.
        // Stop at the first blank, separator (ISSEP), or end of string.
        let mut option_end = line.len();
        for (i, c) in line.char_indices() {
            if is_blank(c) || is_sep(c, dashed_option) {
                option_end = i;
                break;
            }
        }

        let option_raw = &line[..option_end];
        if option_raw.is_empty() {
            continue;
        }

        // ---- Skip past separators and blanks to find the parameter ----
        let rest = &line[option_end..];
        let mut param_offset = 0;
        for (i, c) in rest.char_indices() {
            if !is_blank(c) && !is_sep(c, dashed_option) {
                param_offset = i;
                break;
            }
            // If we consumed the entire rest without finding a non-sep
            // character, param_offset stays beyond the end.
            param_offset = i + c.len_utf8();
        }
        let param_start_abs = option_end + param_offset;

        // ---- Parse the parameter ----
        let param: Option<String>;
        if param_start_abs >= line.len() {
            // No parameter on this line.
            param = None;
        } else {
            let param_region = &line[param_start_abs..];

            if let Some(quoted_content) = param_region.strip_prefix('"') {
                // Double-quoted parameter: perform quote/unescape dance.
                let unquoted = unslash_quote(quoted_content);
                // An empty quoted string ("") is a valid (empty) parameter.
                // The C code sets `param = curlx_dyn_ptr(&pbuf)` which
                // points to "" in this case.  We represent it as Some("").
                param = Some(unquoted);
            } else {
                // Unquoted parameter.

                // Warn if the parameter starts with a single quote.
                if param_region.starts_with('\'') {
                    warnf(
                        global,
                        &format!(
                            "{}:{} Option '{}' uses argument with leading \
                             single quote. It is probably a mistake. \
                             Consider double quotes.",
                            filename, lineno, option_raw
                        ),
                    );
                }

                // The parameter extends to the first whitespace character
                // (or end of string).  Matches C: `while(*line && !ISSPACE(*line))`.
                let param_end = param_region
                    .find(|c: char| is_space(c))
                    .unwrap_or(param_region.len());

                let param_value = &param_region[..param_end];

                // Check for trailing data after the parameter (unquoted
                // whitespace warning).
                if param_end < param_region.len() {
                    let after_param = &param_region[param_end..];
                    // Skip past the whitespace character itself, then
                    // skip remaining blanks to see if there is more data.
                    let trailing = if after_param.len() > 1 {
                        after_param[1..].trim_start_matches(|c: char| is_blank(c))
                    } else {
                        ""
                    };

                    // If trailing data is non-empty and not a comment,
                    // CR, or LF, emit a warning.
                    if !trailing.is_empty() {
                        let first_trailing = trailing.chars().next().unwrap_or('\0');
                        if first_trailing != '\0'
                            && first_trailing != '\r'
                            && first_trailing != '\n'
                            && first_trailing != '#'
                        {
                            warnf(
                                global,
                                &format!(
                                    "{}:{} Option '{}' uses argument with \
                                     unquoted whitespace. This may cause \
                                     side-effects. Consider double quotes.",
                                    filename, lineno, option_raw
                                ),
                            );
                        }
                    }
                }

                // Empty unquoted parameter → None (so getparameter can
                // detect missing required parameters).
                if param_value.is_empty() {
                    param = None;
                } else {
                    param = Some(param_value.to_string());
                }
            }
        }

        // ---- Prepare the option name for dispatch ----
        let (clean_option, is_negated) = prepare_option(option_raw);

        // ---- Handle --config / -K recursion ----
        //
        // In the C code, `getparameter()` handles `--config` internally
        // by recursively calling `parseconfig()`.  In the Rust code,
        // `getparameter()` does NOT handle `--config` (it's a no-op).
        // We handle it here instead.
        let alias = lookup_option(&clean_option);
        if let Some(a) = alias {
            if a.cmd == CmdlineOption::Config {
                if let Some(ref p) = param {
                    if depth == 0 {
                        errorf(
                            global,
                            &format!(
                                "{}:{} exceeded maximum config file \
                                 recursion depth ({})",
                                filename, lineno, CONFIG_MAX_LEVELS
                            ),
                        );
                        bail!(
                            "exceeded maximum config file recursion \
                             depth ({}) at {}:{}",
                            CONFIG_MAX_LEVELS,
                            filename,
                            lineno
                        );
                    }
                    // Recursive include — depth is decremented.
                    parseconfig_inner(Some(p.as_str()), global, depth - 1)?;
                }
                // Whether the parameter was provided or not, we're done
                // with this line.  (Missing parameter for --config is not
                // an error in the C config parser — it's silently ignored.)
                continue;
            }
        }

        // ---- Determine if the option type consumes a parameter ----
        //
        // Used to implement the C `usedarg` tracking: if a parameter was
        // present on the line but the option does not consume parameters,
        // we report PARAM_GOT_EXTRA_PARAMETER.
        let used_arg = alias
            .map(|a| option_consumes_param(a.desc_flags))
            .unwrap_or(false);

        // ---- Call getparameter ----
        //
        // Temporarily pop the last OperationConfig out of the Vec to
        // satisfy the borrow checker: `getparameter` needs `&mut
        // OperationConfig` and `&mut GlobalConfig` simultaneously,
        // but the config lives inside GlobalConfig.configs.
        //
        // This is the same pattern used by `parse_args` in args.rs.
        let mut config = global
            .configs
            .pop()
            .expect("configs Vec must not be empty during config parsing");

        let result = getparameter(
            &clean_option,
            param.as_deref(),
            is_negated,
            &mut config,
            global,
        );

        // Push the config back before processing the result.
        global.configs.push(config);

        // ---- Check for unconsumed parameter (PARAM_GOT_EXTRA_PARAMETER) ----
        if matches!(result, ParameterResult::Ok)
            && param.is_some()
            && !param.as_deref().unwrap_or("").is_empty()
            && !used_arg
        {
            let display_fname = if filename == "-" {
                "<stdin>"
            } else {
                &filename
            };
            let reason = param2text(&ParameterError::GotExtraParameter);
            errorf(
                global,
                &format!(
                    "{}:{} config file option '{}' {}",
                    display_fname, lineno, option_raw, reason
                ),
            );
            bail!(
                "{}:{} config file option '{}' {}",
                display_fname,
                lineno,
                option_raw,
                reason
            );
        }

        // ---- Handle the getparameter result ----
        match result {
            ParameterResult::Ok => {
                // Success — continue to the next line.
            }

            ParameterResult::NextOperation => {
                // `--next` / PARAM_NEXT_OPERATION: allocate a new
                // OperationConfig and append it to the chain, but only
                // if the current config actually has URLs.
                //
                // Matches the C logic:
                //   if(config->url_list && config->url_list->url) {
                //       config->next = config_alloc();
                //       global->last = config->next;
                //       ...
                //   }
                let last_idx = global.configs.len() - 1;
                let has_urls = global.configs[last_idx]
                    .url_list
                    .iter()
                    .any(|g| g.url.is_some());
                if has_urls {
                    global.configs.push(OperationConfig::new());
                    global.current = global.configs.len() - 1;
                }
            }

            ParameterResult::Help
            | ParameterResult::Manual
            | ParameterResult::Version
            | ParameterResult::EngineList
            | ParameterResult::CaBundleDump => {
                // These are informational requests, not errors.
                // In the C code, these do NOT set `err` and the parsing
                // loop continues.  The informational state is recorded
                // elsewhere (e.g., in global flags) and acted upon by
                // the calling code after config parsing completes.
            }

            ParameterResult::Error(ref e) => {
                // Real error from getparameter.
                let display_fname = if filename == "-" {
                    "<stdin>"
                } else {
                    &filename
                };
                let reason = param2text(e);
                errorf(
                    global,
                    &format!(
                        "{}:{} config file option '{}' {}",
                        display_fname, lineno, option_raw, reason
                    ),
                );
                bail!(
                    "{}:{} config file option '{}' {}",
                    display_fname,
                    lineno,
                    option_raw,
                    reason
                );
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- my_get_line tests ----

    #[test]
    fn test_my_get_line_skips_blank_lines() {
        let input = b"\n\n  \n\t\nhello\n";
        let mut reader = io::Cursor::new(input);
        let result = my_get_line(&mut reader).unwrap();
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn test_my_get_line_skips_comments() {
        let input = b"# this is a comment\n  # indented comment\nactual-line\n";
        let mut reader = io::Cursor::new(input);
        let result = my_get_line(&mut reader).unwrap();
        assert_eq!(result, Some("actual-line".to_string()));
    }

    #[test]
    fn test_my_get_line_trims_leading_whitespace() {
        let input = b"   --verbose\n";
        let mut reader = io::Cursor::new(input);
        let result = my_get_line(&mut reader).unwrap();
        assert_eq!(result, Some("--verbose".to_string()));
    }

    #[test]
    fn test_my_get_line_strips_trailing_crlf() {
        let input = b"option\r\n";
        let mut reader = io::Cursor::new(input);
        let result = my_get_line(&mut reader).unwrap();
        assert_eq!(result, Some("option".to_string()));
    }

    #[test]
    fn test_my_get_line_returns_none_on_eof() {
        let input = b"";
        let mut reader = io::Cursor::new(input);
        let result = my_get_line(&mut reader).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_my_get_line_eof_after_blanks_and_comments() {
        let input = b"\n# comment\n  \n";
        let mut reader = io::Cursor::new(input);
        let result = my_get_line(&mut reader).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_my_get_line_multiple_lines() {
        let input = b"# comment\nfirst\nsecond\n";
        let mut reader = io::Cursor::new(input);

        let l1 = my_get_line(&mut reader).unwrap();
        assert_eq!(l1, Some("first".to_string()));

        let l2 = my_get_line(&mut reader).unwrap();
        assert_eq!(l2, Some("second".to_string()));

        let l3 = my_get_line(&mut reader).unwrap();
        assert_eq!(l3, None);
    }

    // ---- unslash_quote tests ----

    #[test]
    fn test_unslash_quote_basic() {
        assert_eq!(unslash_quote("hello world\""), "hello world");
    }

    #[test]
    fn test_unslash_quote_tab_escape() {
        assert_eq!(unslash_quote("a\\tb\""), "a\tb");
    }

    #[test]
    fn test_unslash_quote_newline_escape() {
        assert_eq!(unslash_quote("a\\nb\""), "a\nb");
    }

    #[test]
    fn test_unslash_quote_carriage_return_escape() {
        assert_eq!(unslash_quote("a\\rb\""), "a\rb");
    }

    #[test]
    fn test_unslash_quote_vertical_tab_escape() {
        assert_eq!(unslash_quote("a\\vb\""), "a\x0Bb");
    }

    #[test]
    fn test_unslash_quote_literal_escape() {
        // \X for non-special X → literal X
        assert_eq!(unslash_quote("a\\xb\""), "axb");
    }

    #[test]
    fn test_unslash_quote_escaped_backslash() {
        assert_eq!(unslash_quote("a\\\\b\""), "a\\b");
    }

    #[test]
    fn test_unslash_quote_escaped_quote() {
        assert_eq!(unslash_quote("a\\\"b\""), "a\"b");
    }

    #[test]
    fn test_unslash_quote_no_closing_quote() {
        // No closing quote — process to end of string.
        assert_eq!(unslash_quote("hello world"), "hello world");
    }

    #[test]
    fn test_unslash_quote_empty_string() {
        assert_eq!(unslash_quote("\""), "");
    }

    #[test]
    fn test_unslash_quote_backslash_at_end() {
        // Trailing backslash — C `case '\0': continue;` breaks the loop.
        assert_eq!(unslash_quote("abc\\"), "abc");
    }

    // ---- is_sep / ISSEP tests ----

    #[test]
    fn test_issep_colon_no_dash() {
        assert!(is_sep(':', false));
    }

    #[test]
    fn test_issep_equals_no_dash() {
        assert!(is_sep('=', false));
    }

    #[test]
    fn test_issep_colon_with_dash() {
        // Dashed options: colon is NOT a separator.
        assert!(!is_sep(':', true));
    }

    #[test]
    fn test_issep_equals_with_dash() {
        // Dashed options: equals is NOT a separator.
        assert!(!is_sep('=', true));
    }

    #[test]
    fn test_issep_space_never_sep() {
        assert!(!is_sep(' ', false));
        assert!(!is_sep(' ', true));
    }

    // ---- prepare_option tests ----

    #[test]
    fn test_prepare_option_bare_name() {
        let (name, negated) = prepare_option("verbose");
        assert_eq!(name, "verbose");
        assert!(!negated);
    }

    #[test]
    fn test_prepare_option_single_dash() {
        let (name, negated) = prepare_option("-v");
        assert_eq!(name, "v");
        assert!(!negated);
    }

    #[test]
    fn test_prepare_option_double_dash() {
        let (name, negated) = prepare_option("--verbose");
        assert_eq!(name, "verbose");
        assert!(!negated);
    }

    // ---- option_consumes_param tests ----

    #[test]
    fn test_option_consumes_param_strg() {
        assert!(option_consumes_param(ARG_STRG));
    }

    #[test]
    fn test_option_consumes_param_file() {
        assert!(option_consumes_param(ARG_FILE));
    }

    #[test]
    fn test_option_consumes_param_bool() {
        assert!(!option_consumes_param(1)); // ARG_BOOL
    }

    #[test]
    fn test_option_consumes_param_none() {
        assert!(!option_consumes_param(0)); // ARG_NONE
    }

    // ---- CONFIG_MAX_LEVELS constant ----

    #[test]
    fn test_config_max_levels_value() {
        assert_eq!(CONFIG_MAX_LEVELS, 5);
    }

    // ---- Integration tests using parseconfig ----

    /// Helper: create a GlobalConfig for tests.  Returns `None` if
    /// the library init fails (should not happen in a normal test
    /// environment).
    fn make_global() -> Option<crate::config::GlobalConfig> {
        crate::config::globalconf_init().ok()
    }

    #[test]
    fn test_parseconfig_nonexistent_file() {
        let mut global = match make_global() {
            Some(g) => g,
            None => return,
        };
        let result = parseconfig(
            Some("/tmp/nonexistent_curlrc_parsecfg_test_12345"),
            &mut global,
        );
        assert!(result.is_err(), "should error on nonexistent file");
    }

    #[test]
    fn test_parseconfig_none_path_no_error() {
        let mut global = match make_global() {
            Some(g) => g,
            None => return,
        };
        // None path = default curlrc.  If none exists, should return Ok.
        let result = parseconfig(None, &mut global);
        assert!(
            result.is_ok(),
            "parseconfig(None) should not error: {:?}",
            result
        );
    }

    #[test]
    fn test_parseconfig_comments_and_blanks() {
        let mut global = match make_global() {
            Some(g) => g,
            None => return,
        };

        let tmpdir =
            std::env::temp_dir().join("curl_rs_parsecfg_test_comments");
        let _ = std::fs::create_dir_all(&tmpdir);
        let config_path = tmpdir.join("test.curlrc");
        std::fs::write(
            &config_path,
            "# Comment line\n\n  # Indented comment\n\n--silent\n",
        )
        .unwrap();

        let path_str = config_path.to_string_lossy().to_string();
        let result = parseconfig(Some(&path_str), &mut global);

        let _ = std::fs::remove_dir_all(&tmpdir);
        assert!(
            result.is_ok(),
            "config with comments and --silent should parse OK: {:?}",
            result
        );
    }

    #[test]
    fn test_parseconfig_quoted_user_agent() {
        let mut global = match make_global() {
            Some(g) => g,
            None => return,
        };

        let tmpdir =
            std::env::temp_dir().join("curl_rs_parsecfg_test_quoted");
        let _ = std::fs::create_dir_all(&tmpdir);
        let config_path = tmpdir.join("test.curlrc");
        std::fs::write(
            &config_path,
            "--user-agent \"my curl agent/1.0\"\n",
        )
        .unwrap();

        let path_str = config_path.to_string_lossy().to_string();
        let result = parseconfig(Some(&path_str), &mut global);

        let _ = std::fs::remove_dir_all(&tmpdir);
        assert!(
            result.is_ok(),
            "quoted param should parse OK: {:?}",
            result
        );

        let last_idx = global.configs.len() - 1;
        assert_eq!(
            global.configs[last_idx].useragent.as_deref(),
            Some("my curl agent/1.0")
        );
    }

    #[test]
    fn test_parseconfig_equals_separator() {
        let mut global = match make_global() {
            Some(g) => g,
            None => return,
        };

        let tmpdir =
            std::env::temp_dir().join("curl_rs_parsecfg_test_equals");
        let _ = std::fs::create_dir_all(&tmpdir);
        let config_path = tmpdir.join("test.curlrc");
        // Bare option name with = separator (ISSEP rule)
        std::fs::write(
            &config_path,
            "user-agent = TestAgent/2.0\n",
        )
        .unwrap();

        let path_str = config_path.to_string_lossy().to_string();
        let result = parseconfig(Some(&path_str), &mut global);

        let _ = std::fs::remove_dir_all(&tmpdir);
        assert!(
            result.is_ok(),
            "equals separator should parse OK: {:?}",
            result
        );

        let last_idx = global.configs.len() - 1;
        assert_eq!(
            global.configs[last_idx].useragent.as_deref(),
            Some("TestAgent/2.0")
        );
    }

    #[test]
    fn test_parseconfig_colon_separator() {
        let mut global = match make_global() {
            Some(g) => g,
            None => return,
        };

        let tmpdir =
            std::env::temp_dir().join("curl_rs_parsecfg_test_colon");
        let _ = std::fs::create_dir_all(&tmpdir);
        let config_path = tmpdir.join("test.curlrc");
        std::fs::write(
            &config_path,
            "user-agent: ColonAgent/3.0\n",
        )
        .unwrap();

        let path_str = config_path.to_string_lossy().to_string();
        let result = parseconfig(Some(&path_str), &mut global);

        let _ = std::fs::remove_dir_all(&tmpdir);
        assert!(
            result.is_ok(),
            "colon separator should parse OK: {:?}",
            result
        );

        let last_idx = global.configs.len() - 1;
        assert_eq!(
            global.configs[last_idx].useragent.as_deref(),
            Some("ColonAgent/3.0")
        );
    }

    #[test]
    fn test_parseconfig_silent_boolean_option() {
        let mut global = match make_global() {
            Some(g) => g,
            None => return,
        };

        let tmpdir =
            std::env::temp_dir().join("curl_rs_parsecfg_test_silent");
        let _ = std::fs::create_dir_all(&tmpdir);
        let config_path = tmpdir.join("test.curlrc");
        std::fs::write(&config_path, "--silent\n").unwrap();

        let path_str = config_path.to_string_lossy().to_string();
        let result = parseconfig(Some(&path_str), &mut global);

        let _ = std::fs::remove_dir_all(&tmpdir);
        assert!(
            result.is_ok(),
            "boolean option should parse OK: {:?}",
            result
        );

        // --silent should have set the global.silent flag
        assert!(
            global.silent,
            "global.silent should be true after --silent"
        );
    }

    #[test]
    fn test_parseconfig_multiple_options() {
        let mut global = match make_global() {
            Some(g) => g,
            None => return,
        };

        let tmpdir =
            std::env::temp_dir().join("curl_rs_parsecfg_test_multi");
        let _ = std::fs::create_dir_all(&tmpdir);
        let config_path = tmpdir.join("test.curlrc");
        std::fs::write(
            &config_path,
            "# Config file\n\
             --silent\n\
             --user-agent \"multi-test/1.0\"\n\
             --compressed\n",
        )
        .unwrap();

        let path_str = config_path.to_string_lossy().to_string();
        let result = parseconfig(Some(&path_str), &mut global);

        let _ = std::fs::remove_dir_all(&tmpdir);
        assert!(
            result.is_ok(),
            "multiple options should parse OK: {:?}",
            result
        );

        assert!(global.silent);
        let last_idx = global.configs.len() - 1;
        assert_eq!(
            global.configs[last_idx].useragent.as_deref(),
            Some("multi-test/1.0")
        );
    }

    #[test]
    fn test_parseconfig_escape_sequences_in_quotes() {
        let mut global = match make_global() {
            Some(g) => g,
            None => return,
        };

        let tmpdir =
            std::env::temp_dir().join("curl_rs_parsecfg_test_escape");
        let _ = std::fs::create_dir_all(&tmpdir);
        let config_path = tmpdir.join("test.curlrc");
        std::fs::write(
            &config_path,
            "--user-agent \"agent\\twith\\ntabs\"\n",
        )
        .unwrap();

        let path_str = config_path.to_string_lossy().to_string();
        let result = parseconfig(Some(&path_str), &mut global);

        let _ = std::fs::remove_dir_all(&tmpdir);
        assert!(
            result.is_ok(),
            "escaped quotes should parse OK: {:?}",
            result
        );

        let last_idx = global.configs.len() - 1;
        assert_eq!(
            global.configs[last_idx].useragent.as_deref(),
            Some("agent\twith\ntabs")
        );
    }

    #[test]
    fn test_parseconfig_empty_config_file() {
        let mut global = match make_global() {
            Some(g) => g,
            None => return,
        };

        let tmpdir =
            std::env::temp_dir().join("curl_rs_parsecfg_test_empty");
        let _ = std::fs::create_dir_all(&tmpdir);
        let config_path = tmpdir.join("test.curlrc");
        std::fs::write(&config_path, "").unwrap();

        let path_str = config_path.to_string_lossy().to_string();
        let result = parseconfig(Some(&path_str), &mut global);

        let _ = std::fs::remove_dir_all(&tmpdir);
        assert!(result.is_ok(), "empty file should parse OK: {:?}", result);
    }

    #[test]
    fn test_parseconfig_config_recursion() {
        let mut global = match make_global() {
            Some(g) => g,
            None => return,
        };

        let tmpdir =
            std::env::temp_dir().join("curl_rs_parsecfg_test_recurse");
        let _ = std::fs::create_dir_all(&tmpdir);

        // Create inner config
        let inner_path = tmpdir.join("inner.curlrc");
        std::fs::write(&inner_path, "--silent\n").unwrap();

        // Create outer config that includes inner
        let outer_path = tmpdir.join("outer.curlrc");
        let inner_str = inner_path.to_string_lossy().to_string();
        std::fs::write(
            &outer_path,
            format!("--config \"{}\"\n", inner_str),
        )
        .unwrap();

        let outer_str = outer_path.to_string_lossy().to_string();
        let result = parseconfig(Some(&outer_str), &mut global);

        let _ = std::fs::remove_dir_all(&tmpdir);
        assert!(
            result.is_ok(),
            "recursive config should parse OK: {:?}",
            result
        );
        assert!(global.silent, "inner config --silent should apply");
    }
}
