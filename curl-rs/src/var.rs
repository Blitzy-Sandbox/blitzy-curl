// -----------------------------------------------------------------------
// curl-rs/src/var.rs — Variable Expansion for --variable
//
// Rust rewrite of src/var.c and src/var.h from curl 8.19.0-DEV.
//
// Implements the `--variable` flag: variable storage, lookup,
// transformation functions (`:trim`, `:json`, `:url`, `:b64`, `:64dec`),
// and `{{name}}` placeholder expansion.
//
// # Source Mapping
//
// | Rust function        | C origin                           |
// |----------------------|------------------------------------|
// | `var_cleanup`        | `varcleanup()` in `var.c:37`       |
// | `var_content`        | `varcontent()` in `var.c:48`        |
// | `var_func`           | `varfunc()` in `var.c:75`           |
// | `varexpand`          | `varexpand()` in `var.c:206`        |
// | `add_variable`       | `addvariable()` in `var.c:342`      |
// | `set_variable`       | `setvariable()` in `var.c:372`      |
//
// Zero `unsafe` blocks.
//
// SPDX-License-Identifier: curl
// -----------------------------------------------------------------------

use std::env;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use percent_encoding::{percent_encode, AsciiSet, NON_ALPHANUMERIC};

use crate::config::{GlobalConfig, ToolVar};
use crate::msgs;
use crate::paramhelp::file2memory_range;
use crate::writeout_json::json_quoted;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum size of expanded content (10 MB).
///
/// Matches the C `#define MAX_EXPAND_CONTENT 10000000` in `src/var.c`.
const MAX_EXPAND_CONTENT: usize = 10_000_000;

/// Maximum length of a variable name buffer.
///
/// Matches the C `#define MAX_VAR_LEN 128` in `src/var.c`.
/// The maximum allowed name length is `MAX_VAR_LEN - 1` (127 characters)
/// because the C code uses `nlen >= MAX_VAR_LEN` for the length check.
const MAX_VAR_LEN: usize = 128;

/// URL percent-encoding set matching `curl_easy_escape` behavior.
///
/// Encodes all bytes except RFC 3986 unreserved characters:
/// `ALPHA / DIGIT / "-" / "." / "_" / "~"`
///
/// The `NON_ALPHANUMERIC` base set encodes everything except `A-Za-z0-9`.
/// Removing `-`, `.`, `_`, `~` from the set means those characters pass
/// through unencoded, matching the unreserved character set exactly.
/// Output uses uppercase hex digits (`%2F` not `%2f`), matching curl 8.x.
const CURL_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

// ---------------------------------------------------------------------------
// Variable cleanup
// ---------------------------------------------------------------------------

/// Clears all user-defined variables and releases their memory.
///
/// Rust equivalent of C `varcleanup()` in `src/var.c` lines 37–46.
///
/// In the C implementation, this walks a linked list and frees each node
/// via `curlx_free`.  In Rust, `Vec::clear()` drops all elements and
/// reclaims memory automatically via ownership semantics.
///
/// # Arguments
///
/// * `vars` — The variable list to clear (typically `global.variables`).
pub fn var_cleanup(vars: &mut Vec<ToolVar>) {
    vars.clear();
}

// ---------------------------------------------------------------------------
// Variable lookup (internal)
// ---------------------------------------------------------------------------

/// Looks up a variable by name and returns its content as a byte slice.
///
/// Rust equivalent of C `varcontent()` in `src/var.c` lines 48–58.
///
/// The C implementation walks a linked list comparing names by length
/// and `strncmp`.  The Rust version uses `Vec::iter().find()` with
/// string equality, which is functionally equivalent.
///
/// # Arguments
///
/// * `vars` — The variable list to search.
/// * `name` — The variable name to look up.
///
/// # Returns
///
/// `Some(&[u8])` with the variable's content if found, `None` otherwise.
fn var_content<'a>(vars: &'a [ToolVar], name: &str) -> Option<&'a [u8]> {
    vars.iter()
        .find(|v| v.name == name)
        .map(|v| v.content.as_slice())
}

// ---------------------------------------------------------------------------
// Transformation functions
// ---------------------------------------------------------------------------

/// Applies a chain of colon-separated transformation functions to variable
/// content.
///
/// Rust equivalent of C `varfunc()` in `src/var.c` lines 75–204.
///
/// # Supported Functions
///
/// | Name    | Description                                          |
/// |---------|------------------------------------------------------|
/// | `trim`  | Strip leading/trailing ASCII whitespace               |
/// | `json`  | JSON-escape the content (`writeout_json::json_quoted`)|
/// | `url`   | URL percent-encode (RFC 3986 unreserved chars exempt) |
/// | `b64`   | Base64-encode the content                             |
/// | `64dec` | Base64-decode (fallback to `[64dec-fail]` on error)   |
///
/// Functions are applied left-to-right in the order specified.
/// For example, `:trim:json:b64` first trims whitespace, then
/// JSON-escapes, then Base64-encodes the result.
///
/// # Arguments
///
/// * `global`    — Global config for diagnostic output (`errorf`).
/// * `content`   — The variable content to transform.
/// * `functions` — The function chain string (e.g., `:trim:json:b64`).
///
/// # Returns
///
/// The transformed content as a byte vector, or an error if an unknown
/// function is encountered.
fn var_func(
    global: &GlobalConfig,
    content: &[u8],
    functions: &str,
) -> Result<Vec<u8>> {
    let mut current = content.to_vec();
    let func_bytes = functions.as_bytes();
    let mut pos: usize = 0;

    // The function chain string starts with a colon and may contain
    // multiple colon-separated function names.  Process left-to-right.
    //
    // C equivalent: `while(*f && !err) { if(*f == '}') break; f++; ... }`
    while pos < func_bytes.len() {
        // Stop at closing brace (safety — our caller strips it, but
        // defend against it appearing anyway).
        if func_bytes[pos] == b'}' {
            break;
        }

        // Skip the leading colon separator between functions.
        if func_bytes[pos] == b':' {
            pos += 1;
        }

        if pos >= func_bytes.len() {
            break;
        }

        // Extract the function name: everything until the next ':' or end.
        let func_start = pos;
        while pos < func_bytes.len()
            && func_bytes[pos] != b':'
            && func_bytes[pos] != b'}'
        {
            pos += 1;
        }

        let func_name = &functions[func_start..pos];

        match func_name {
            "trim" => {
                // Strip leading and trailing ASCII whitespace.
                // Matches C: skip ISSPACE from front and back.
                if !current.is_empty() {
                    let start = current
                        .iter()
                        .position(|b| !b.is_ascii_whitespace())
                        .unwrap_or(current.len());
                    let end = current
                        .iter()
                        .rposition(|b| !b.is_ascii_whitespace())
                        .map(|p| p + 1)
                        .unwrap_or(start);
                    current = current[start..end].to_vec();
                }
            }
            "json" => {
                // JSON-escape the content via writeout_json::json_quoted.
                // Matches C: `jsonquoted(c, clen, out, FALSE)`
                if !current.is_empty() {
                    let s = String::from_utf8_lossy(&current);
                    let escaped = json_quoted(&s, false);
                    current = escaped.into_bytes();
                } else {
                    current = Vec::new();
                }
            }
            "url" => {
                // URL percent-encode matching curl_easy_escape behavior.
                // Encodes all bytes except RFC 3986 unreserved characters
                // using uppercase hex (%XX) sequences.
                if !current.is_empty() {
                    let encoded =
                        percent_encode(&current, CURL_ENCODE_SET).to_string();
                    current = encoded.into_bytes();
                } else {
                    current = Vec::new();
                }
            }
            "b64" => {
                // Base64-encode the content.
                // Matches C: `curlx_base64_encode(c, clen, &enc, &elen)`
                if !current.is_empty() {
                    let encoded = STANDARD.encode(&current);
                    current = encoded.into_bytes();
                } else {
                    current = Vec::new();
                }
            }
            "64dec" => {
                // Base64-decode the content.  On failure, produce the
                // literal string "[64dec-fail]" instead of returning an
                // error — matching the C fallback behavior.
                if !current.is_empty() {
                    match STANDARD.decode(&current) {
                        Ok(decoded) => {
                            current = decoded;
                        }
                        Err(_) => {
                            current = b"[64dec-fail]".to_vec();
                        }
                    }
                } else {
                    current = Vec::new();
                }
            }
            _ => {
                // Unknown function — report error and bail.
                // Matches C: `errorf("unknown variable function in
                // '%.*s'", ...); err = PARAM_EXPAND_ERROR;`
                msgs::errorf(
                    global,
                    &format!(
                        "unknown variable function in '{}'",
                        functions
                    ),
                );
                bail!(
                    "unknown variable function in '{}'",
                    functions
                );
            }
        }
    }

    Ok(current)
}

// ---------------------------------------------------------------------------
// Variable expansion
// ---------------------------------------------------------------------------

/// Expands `{{NAME}}` and `{{NAME:func1:func2}}` placeholders in input.
///
/// Rust equivalent of C `varexpand()` in `src/var.c` lines 206–335.
///
/// # Placeholder Syntax
///
/// * `{{name}}` — substitute the variable's value
/// * `{{name:func1:func2}}` — substitute with a transformation chain
/// * `\{{` — literal `{{` (backslash escape)
///
/// # Variable Name Rules
///
/// * Only `[A-Za-z0-9_]` characters allowed
/// * Maximum length: 127 characters (`MAX_VAR_LEN - 1`)
/// * Empty or overlong names are rejected (inserted as-is with warning)
///
/// # Behavior Details
///
/// * Variables not found → replaced with empty string
/// * Invalid placeholder syntax → inserted as-is with a warning
/// * Embedded null bytes in variable values → error
/// * Escape sequences are only resolved when at least one variable
///   substitution occurs; otherwise the original string is returned.
///   This matches the C behavior where the output buffer is freed
///   when no replacements were made.
///
/// # Arguments
///
/// * `global` — Global configuration (provides variables and diagnostic
///   settings for `warnf`/`errorf`).
/// * `input`  — The input string containing placeholders to expand.
///
/// # Returns
///
/// A tuple `(expanded_string, was_any_replacement_made)`:
/// * If at least one variable was substituted: the fully expanded string
///   with all placeholders resolved, and `true`.
/// * If no variable was substituted: a clone of the original `input`
///   string, and `false`.
pub fn varexpand(
    global: &GlobalConfig,
    input: &str,
) -> Result<(String, bool)> {
    let mut out = String::new();
    let mut added = false;
    let mut line: &str = input;

    while let Some(idx) = line.find("{{") {

        // Check for backslash escape: `\{{` produces literal `{{`.
        // Matches C: `if((envp > line) && envp[-1] == '\\')`
        if idx > 0 && line.as_bytes()[idx - 1] == b'\\' {
            // Insert text up to this point, minus the backslash.
            out.push_str(&line[..idx - 1]);
            // Output literal `{{`.
            out.push_str("{{");
            // Advance past `{{`.
            line = &line[idx + 2..];
            continue;
        }

        // Everything after `{{`.
        let after_open = &line[idx + 2..];

        // Look for the closing `}}`.
        let close_offset = match after_open.find("}}") {
            Some(co) => co,
            None => {
                // Unmatched braces — warn and stop processing.
                // Matches C: `warnf("missing close '}}' in '%s'", input);`
                msgs::warnf(
                    global,
                    &format!("missing close '}}}}' in '{}'", input),
                );
                break;
            }
        };

        // The inner content between `{{` and `}}`.
        let inner = &after_open[..close_offset];

        // Separate variable name from optional function chain.
        // A colon within the inner text starts the function chain.
        let (name, func_str) = match inner.find(':') {
            Some(colon_pos) => {
                (&inner[..colon_pos], Some(&inner[colon_pos..]))
            }
            None => (inner, None),
        };

        let nlen = name.len();

        // Position one past the closing `}}` relative to the start of
        // `line`.  Used for "insert as-is" fallback paths.
        let end_pos = idx + 2 + close_offset + 2;

        if nlen == 0 || nlen >= MAX_VAR_LEN {
            // Bad name length — insert the full text as-is (including
            // the `{{...}}`), then continue scanning.
            // Matches C: `warnf("bad variable name length '%s'", input);`
            msgs::warnf(
                global,
                &format!("bad variable name length '{}'", input),
            );
            out.push_str(&line[..end_pos]);
            line = &line[end_pos..];
            continue;
        }

        // Validate name characters: only alphanumeric and underscore.
        // Matches C: `for(i=0; ISALNUM(name[i])||name[i]=='_'; i++)`
        let name_valid = name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_');

        if !name_valid {
            // Bad characters in name — insert as-is.
            // Matches C: `warnf("bad variable name: %s", name);`
            msgs::warnf(
                global,
                &format!("bad variable name: {}", name),
            );
            out.push_str(&line[..end_pos]);
            line = &line[end_pos..];
            continue;
        }

        // --- Valid variable reference: process it ---

        // Insert text before the `{{` placeholder.
        out.push_str(&line[..idx]);

        // Look up the variable content.
        let var_value = var_content(&global.variables, name);
        let mut val_bytes: Vec<u8> = match var_value {
            Some(v) => v.to_vec(),
            None => Vec::new(),
        };

        // Apply transformation functions if a function chain is present.
        if let Some(funcs) = func_str {
            val_bytes = var_func(global, &val_bytes, funcs)?;
        }

        let val_len = val_bytes.len();

        // Reject embedded null bytes in the variable value.
        // Matches C: `memchr(value, '\0', vlen)` check.
        if val_len > 0 && val_bytes.contains(&0) {
            msgs::errorf(global, "variable contains null byte");
            bail!("variable contains null byte");
        }

        // Guard against unbounded output growth.
        if out.len() + val_len > MAX_EXPAND_CONTENT {
            bail!(
                "variable expansion exceeds maximum size ({})",
                MAX_EXPAND_CONTENT
            );
        }

        // Insert the (possibly transformed) variable value.
        if val_len > 0 {
            let val_str = String::from_utf8_lossy(&val_bytes);
            out.push_str(&val_str);
        }

        // Mark that at least one variable substitution occurred.
        added = true;

        // Advance past the closing `}}`.
        line = &after_open[close_offset + 2..];
    }

    if added {
        // Append the remaining suffix text after the last placeholder.
        // Matches C: `if(added && *line) curlx_dyn_add(out, line);`
        if !line.is_empty() {
            out.push_str(line);
        }
        Ok((out, true))
    } else {
        // No variable substitutions — return the original input as-is.
        // Matches C: `if(!added) curlx_dyn_free(out);` — the output
        // buffer is discarded and the caller uses the original string.
        Ok((input.to_string(), false))
    }
}

// ---------------------------------------------------------------------------
// Variable addition
// ---------------------------------------------------------------------------

/// Adds or overwrites a variable in the global variable list.
///
/// Rust equivalent of C `addvariable()` in `src/var.c` lines 342–370.
///
/// If a variable with the same name already exists, it is overwritten
/// and a diagnostic note is emitted via `notef`.  In the C implementation,
/// the old variable is shadowed by prepending the new one to the linked
/// list.  In Rust, the old entry is removed via `Vec::retain` and the
/// new entry is appended.
///
/// # Arguments
///
/// * `global`  — Global configuration (for `notef` and `variables` access).
/// * `name`    — The variable name.
/// * `content` — The variable content (binary-safe).
pub fn add_variable(
    global: &mut GlobalConfig,
    name: &str,
    content: Vec<u8>,
) {
    // Check for an existing variable with the same name and build the
    // overwrite notification message *before* mutating the vector.
    // The `format!` produces an owned String, so the immutable borrow
    // on `global.variables` is released before we call `notef`.
    let overwrite_msg: Option<String> = global
        .variables
        .iter()
        .find(|v| v.name == name)
        .map(|v| format!("Overwriting variable '{}'", v.name));

    // Emit note if overwriting an existing variable.
    // Matches C: `notef("Overwriting variable '%s'", check->name);`
    if let Some(msg) = overwrite_msg {
        msgs::notef(global, &msg);
    }

    // Remove the old variable (if any) and add the new one.
    global.variables.retain(|v| v.name != name);
    global.variables.push(ToolVar {
        name: name.to_string(),
        content,
    });
}

// ---------------------------------------------------------------------------
// Internal helper: parse_leading_number
// ---------------------------------------------------------------------------

/// Parses a leading decimal integer from a string slice.
///
/// Returns the parsed number and the remaining unparsed portion.
///
/// Used internally by [`set_variable`] to parse the `[start-end]` byte
/// range specifiers.  Matches the C `curlx_str_number` behavior.
///
/// # Errors
///
/// Returns `Err` if no leading digits are found or the number overflows.
fn parse_leading_number(s: &str) -> Result<(i64, &str)> {
    let digit_end = s
        .bytes()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(s.len());

    if digit_end == 0 {
        bail!("Bad --variable range syntax: expected number");
    }

    let num: i64 = s[..digit_end]
        .parse()
        .context("Bad --variable range number")?;

    Ok((num, &s[digit_end..]))
}

// ---------------------------------------------------------------------------
// Variable assignment (--variable parsing)
// ---------------------------------------------------------------------------

/// Parses a `--variable` assignment string and stores the result.
///
/// Rust equivalent of C `setvariable()` in `src/var.c` lines 372–492.
///
/// # Supported Formats
///
/// | Format                     | Description                              |
/// |----------------------------|------------------------------------------|
/// | `name=value`               | Literal string assignment                |
/// | `%env_name`                | Import value from environment variable   |
/// | `%env_name=default`        | Import with fallback default value       |
/// | `name@filename`            | Read content from file                   |
/// | `name@-`                   | Read content from stdin                  |
/// | `name[start-end]=value`    | Literal with byte-range slicing          |
/// | `name[start-]@filename`    | File import with byte-range slicing      |
///
/// # Environment Variable Import
///
/// When the assignment starts with `%`, the name is used to look up an
/// environment variable via `std::env::var()`.  If the variable is not
/// set and no fallback (`=default`) is provided, an error is returned.
/// If the variable is not set but a fallback is provided, the fallback
/// value is used instead.
///
/// # Byte Range
///
/// The optional `[start-end]` specifier selects a byte range from the
/// content source (file, literal, or env value fallback).  `start` and
/// `end` are 0-based inclusive byte offsets.  Omitting `end` means
/// "to the end of the content".
///
/// # Arguments
///
/// * `global`     — Global configuration (for variables, diagnostics).
/// * `assignment` — The raw `--variable` argument string.
///
/// # Returns
///
/// `Ok(())` on success, `Err` on fatal errors (read failures, bad syntax
/// that cannot be recovered from).  Non-fatal issues (bad names, bad
/// syntax that can be skipped) emit a warning and return `Ok(())`.
pub fn set_variable(
    global: &mut GlobalConfig,
    assignment: &str,
) -> Result<()> {
    let mut line: &str = assignment;
    let mut content: Option<Vec<u8>> = None;
    let mut import = false;
    let mut start_offset: i64 = 0;
    let mut end_offset: i64 = i64::MAX;

    // ---------------------------------------------------------------
    // Step 1: Check for environment variable import prefix `%`.
    // Matches C: `if(*input == '%') { import = TRUE; line++; }`
    // ---------------------------------------------------------------
    if line.starts_with('%') {
        import = true;
        line = &line[1..];
    }

    // ---------------------------------------------------------------
    // Step 2: Parse variable name (alphanumeric + underscore).
    // Matches C: `while(ISALNUM(*line) || *line == '_') line++;`
    // ---------------------------------------------------------------
    let name_end = line
        .bytes()
        .position(|b| !b.is_ascii_alphanumeric() && b != b'_')
        .unwrap_or(line.len());
    let name = &line[..name_end];
    let nlen = name.len();
    line = &line[name_end..];

    if nlen == 0 || nlen >= MAX_VAR_LEN {
        // Matches C: `warnf("Bad variable name length (%zd), skipping", nlen);`
        msgs::warnf(
            global,
            &format!("Bad variable name length ({}), skipping", nlen),
        );
        return Ok(());
    }

    // ---------------------------------------------------------------
    // Step 3: Handle environment variable import.
    // Matches C import block in `setvariable()`.
    // ---------------------------------------------------------------
    if import {
        // Use std::env::var which supports empty-string values (unlike
        // C curl_getenv which wraps getenv).
        match env::var(name) {
            Ok(val) => {
                content = Some(val.into_bytes());
            }
            Err(_) => {
                if line.is_empty() {
                    // No fallback action and no env variable — fail.
                    // Matches C: `errorf("Variable '%s' import fail,
                    // not set", name);`
                    msgs::errorf(
                        global,
                        &format!(
                            "Variable '{}' import fail, not set",
                            name
                        ),
                    );
                    bail!(
                        "Variable '{}' import fail, not set",
                        name
                    );
                }
                // Env var not set but fallback exists — fall through
                // to content determination below.
            }
        }
    }

    // ---------------------------------------------------------------
    // Step 4: Parse optional byte range `[start-end]`.
    // Matches C: `if(*line == '[' && ISDIGIT(line[1])) { ... }`
    // ---------------------------------------------------------------
    if line.starts_with('[')
        && line.len() > 1
        && line.as_bytes()[1].is_ascii_digit()
    {
        let rest = &line[1..]; // skip '['

        // Parse start number.
        let (start_num, after_start) = parse_leading_number(rest)
            .context("Bad --variable range syntax")?;
        start_offset = start_num;

        // Expect '-' separator.
        if !after_start.starts_with('-') {
            bail!("Bad --variable range syntax");
        }
        let after_dash = &after_start[1..]; // skip '-'

        // Check for immediate ']' (means end = max) or parse end number.
        if let Some(rest_after_bracket) = after_dash.strip_prefix(']') {
            // Range is [start-] — end stays at i64::MAX.
            line = rest_after_bracket;
        } else {
            let (end_num, after_end) = parse_leading_number(after_dash)
                .context("Bad --variable range syntax")?;
            end_offset = end_num;
            if let Some(rest) = after_end.strip_prefix(']') {
                line = rest;
            } else {
                bail!("Bad --variable range syntax");
            }
        }

        if start_offset > end_offset {
            bail!("Bad --variable range syntax");
        }
    }

    // ---------------------------------------------------------------
    // Step 5: Determine content source.
    // Priority: env import > file import > literal > bad syntax.
    // Matches C: `if(content); else if('@') ...; else if('=') ...;`
    // ---------------------------------------------------------------
    if content.is_some() {
        // Content already set from environment variable import — use it.
        // The `@` and `=` branches below are skipped.
    } else if let Some(filename) = line.strip_prefix('@') {
        // File import: read content from a file or stdin.
        let use_stdin = filename == "-";

        if use_stdin {
            let data =
                file2memory_range("-", start_offset, end_offset)
                    .context(
                        "Failed to read from stdin for variable",
                    )?;
            content = Some(data);
        } else {
            let data =
                file2memory_range(filename, start_offset, end_offset)
                    .with_context(|| {
                        format!("Failed to open {}", filename)
                    })?;
            content = Some(data);
        }
    } else if let Some(value_str) = line.strip_prefix('=') {
        // Literal assignment.
        let value_bytes = value_str.as_bytes();
        let clen = value_bytes.len();

        // Apply byte range to the literal value if a range was specified.
        if start_offset > 0 || end_offset != i64::MAX {
            if start_offset >= clen as i64 {
                // Start is past the end of the value — empty content.
                content = Some(Vec::new());
            } else {
                let actual_start = start_offset as usize;
                // Clamp end to the last byte of the value.
                let actual_end = if end_offset >= clen as i64 {
                    clen - 1
                } else {
                    end_offset as usize
                };
                let slice_len = actual_end - actual_start + 1;
                content = Some(
                    value_bytes[actual_start..actual_start + slice_len]
                        .to_vec(),
                );
            }
        } else {
            content = Some(value_bytes.to_vec());
        }
    } else if content.is_none() {
        // No valid assignment syntax found — skip with warning.
        // Matches C: `warnf("Bad --variable syntax, skipping: %s", input);`
        msgs::warnf(
            global,
            &format!(
                "Bad --variable syntax, skipping: {}",
                assignment
            ),
        );
        return Ok(());
    }

    // ---------------------------------------------------------------
    // Step 6: Store the variable.
    // ---------------------------------------------------------------
    let final_content = content.unwrap_or_default();
    let name_owned = name.to_string();

    // Check for overwrite and compose the notification message before
    // mutating the vector.  The `format!` creates an owned String so
    // the immutable borrow on `global.variables` is released.
    let overwrite_msg: Option<String> = global
        .variables
        .iter()
        .find(|v| v.name == name_owned)
        .map(|v| format!("Overwriting variable '{}'", v.name));

    if let Some(msg) = overwrite_msg {
        msgs::notef(global, &msg);
    }

    global.variables.retain(|v| v.name != name_owned);
    global.variables.push(ToolVar {
        name: name_owned,
        content: final_content,
    });

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        GlobalConfig, OperationConfig, TerminalState,
        TraceType, TransferState, PARALLEL_DEFAULT,
    };
    use crate::libinfo::LibCurlInfo;

    /// Helper to create a minimal `GlobalConfig` for testing.
    ///
    /// All diagnostic outputs are suppressed by default (`silent = true`),
    /// and all optional fields are set to their zero/empty defaults.
    fn test_global() -> GlobalConfig {
        GlobalConfig {
            state: TransferState::new(),
            trace_dump: None,
            trace_stream: None,
            libcurl: None,
            ssl_sessions: None,
            variables: Vec::new(),
            configs: vec![OperationConfig::new()],
            current: 0,
            ms_per_transfer: 0,
            tracetype: TraceType::None,
            progressmode: 0,
            parallel_host: 0,
            parallel_max: PARALLEL_DEFAULT,
            verbosity: 0,
            parallel: false,
            parallel_connect: false,
            fail_early: false,
            styled_output: false,
            trace_fopened: false,
            tracetime: false,
            traceids: false,
            showerror: false,
            silent: true,
            noprogress: true,
            isatty: false,
            trace_set: false,
            libcurl_info: LibCurlInfo::default(),
            term: TerminalState::new(),
            libcurl_version: None,
        }
    }

    // -- var_cleanup tests --

    #[test]
    fn test_var_cleanup_clears_all() {
        let mut vars = vec![
            ToolVar {
                name: "a".to_string(),
                content: b"1".to_vec(),
            },
            ToolVar {
                name: "b".to_string(),
                content: b"2".to_vec(),
            },
        ];
        var_cleanup(&mut vars);
        assert!(vars.is_empty());
    }

    #[test]
    fn test_var_cleanup_empty() {
        let mut vars: Vec<ToolVar> = Vec::new();
        var_cleanup(&mut vars);
        assert!(vars.is_empty());
    }

    // -- var_content tests --

    #[test]
    fn test_var_content_found() {
        let vars = vec![ToolVar {
            name: "foo".to_string(),
            content: b"bar".to_vec(),
        }];
        assert_eq!(var_content(&vars, "foo"), Some(b"bar".as_slice()));
    }

    #[test]
    fn test_var_content_not_found() {
        let vars = vec![ToolVar {
            name: "foo".to_string(),
            content: b"bar".to_vec(),
        }];
        assert_eq!(var_content(&vars, "baz"), None);
    }

    #[test]
    fn test_var_content_empty_list() {
        let vars: Vec<ToolVar> = Vec::new();
        assert_eq!(var_content(&vars, "anything"), None);
    }

    // -- var_func tests --

    #[test]
    fn test_var_func_trim() {
        let global = test_global();
        let result =
            var_func(&global, b"  hello world  ", ":trim").unwrap();
        assert_eq!(result, b"hello world");
    }

    #[test]
    fn test_var_func_trim_all_whitespace() {
        let global = test_global();
        let result = var_func(&global, b"   \t\n  ", ":trim").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_var_func_trim_empty() {
        let global = test_global();
        let result = var_func(&global, b"", ":trim").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_var_func_json() {
        let global = test_global();
        let result =
            var_func(&global, b"hello \"world\"", ":json").unwrap();
        let s = String::from_utf8(result).unwrap();
        assert!(s.contains("hello"));
        assert!(s.contains("world"));
        // The quotes should be escaped
        assert!(s.contains("\\\""));
    }

    #[test]
    fn test_var_func_url() {
        let global = test_global();
        let result =
            var_func(&global, b"hello world/test", ":url").unwrap();
        let s = String::from_utf8(result).unwrap();
        // Space → %20, slash → %2F
        assert!(s.contains("%20"));
        assert!(s.contains("%2F"));
        assert!(s.contains("hello"));
    }

    #[test]
    fn test_var_func_url_unreserved() {
        let global = test_global();
        // RFC 3986 unreserved: A-Za-z0-9 - . _ ~
        let result =
            var_func(&global, b"abc-._~XYZ09", ":url").unwrap();
        assert_eq!(result, b"abc-._~XYZ09");
    }

    #[test]
    fn test_var_func_b64_encode() {
        let global = test_global();
        let result = var_func(&global, b"hello", ":b64").unwrap();
        assert_eq!(result, b"aGVsbG8=");
    }

    #[test]
    fn test_var_func_64dec() {
        let global = test_global();
        let result =
            var_func(&global, b"aGVsbG8=", ":64dec").unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_var_func_64dec_invalid() {
        let global = test_global();
        let result =
            var_func(&global, b"not-valid-base64!!!", ":64dec").unwrap();
        assert_eq!(result, b"[64dec-fail]");
    }

    #[test]
    fn test_var_func_chain() {
        let global = test_global();
        // trim then b64
        let result =
            var_func(&global, b"  hello  ", ":trim:b64").unwrap();
        let expected = STANDARD.encode(b"hello");
        assert_eq!(result, expected.as_bytes());
    }

    #[test]
    fn test_var_func_unknown() {
        let global = test_global();
        let result = var_func(&global, b"test", ":unknown");
        assert!(result.is_err());
    }

    // -- varexpand tests --

    #[test]
    fn test_varexpand_no_placeholders() {
        let global = test_global();
        let (result, replaced) =
            varexpand(&global, "hello world").unwrap();
        assert_eq!(result, "hello world");
        assert!(!replaced);
    }

    #[test]
    fn test_varexpand_simple() {
        let mut global = test_global();
        global.variables.push(ToolVar {
            name: "name".to_string(),
            content: b"Alice".to_vec(),
        });
        let (result, replaced) =
            varexpand(&global, "Hello {{name}}!").unwrap();
        assert_eq!(result, "Hello Alice!");
        assert!(replaced);
    }

    #[test]
    fn test_varexpand_missing_var() {
        let global = test_global();
        let (result, replaced) =
            varexpand(&global, "Hello {{nobody}}!").unwrap();
        assert_eq!(result, "Hello !");
        assert!(replaced);
    }

    #[test]
    fn test_varexpand_with_func() {
        let mut global = test_global();
        global.variables.push(ToolVar {
            name: "val".to_string(),
            content: b"  spaced  ".to_vec(),
        });
        let (result, replaced) =
            varexpand(&global, "{{val:trim}}").unwrap();
        assert_eq!(result, "spaced");
        assert!(replaced);
    }

    #[test]
    fn test_varexpand_escape() {
        let mut global = test_global();
        global.variables.push(ToolVar {
            name: "x".to_string(),
            content: b"val".to_vec(),
        });
        // `\{{` should produce literal `{{` in output
        let (result, replaced) =
            varexpand(&global, "a \\{{ {{x}} b").unwrap();
        assert_eq!(result, "a {{ val b");
        assert!(replaced);
    }

    #[test]
    fn test_varexpand_escape_only_no_vars() {
        let global = test_global();
        // Escape without any variable — returns original.
        let (result, replaced) =
            varexpand(&global, "a \\{{ b").unwrap();
        assert_eq!(result, "a \\{{ b");
        assert!(!replaced);
    }

    #[test]
    fn test_varexpand_bad_name() {
        let global = test_global();
        let (result, replaced) =
            varexpand(&global, "Hello {{bad%name}} world").unwrap();
        assert_eq!(result, "Hello {{bad%name}} world");
        assert!(!replaced);
    }

    #[test]
    fn test_varexpand_null_byte_error() {
        let mut global = test_global();
        global.variables.push(ToolVar {
            name: "nullvar".to_string(),
            content: vec![b'a', 0, b'b'],
        });
        let result = varexpand(&global, "{{nullvar}}");
        assert!(result.is_err());
    }

    // -- add_variable tests --

    #[test]
    fn test_add_variable_new() {
        let mut global = test_global();
        add_variable(&mut global, "myvar", b"myval".to_vec());
        assert_eq!(global.variables.len(), 1);
        assert_eq!(global.variables[0].name, "myvar");
        assert_eq!(global.variables[0].content, b"myval");
    }

    #[test]
    fn test_add_variable_overwrite() {
        let mut global = test_global();
        add_variable(&mut global, "myvar", b"first".to_vec());
        add_variable(&mut global, "myvar", b"second".to_vec());
        assert_eq!(global.variables.len(), 1);
        assert_eq!(global.variables[0].content, b"second");
    }

    // -- set_variable tests --

    #[test]
    fn test_set_variable_literal() {
        let mut global = test_global();
        set_variable(&mut global, "myvar=hello").unwrap();
        assert_eq!(global.variables.len(), 1);
        assert_eq!(global.variables[0].name, "myvar");
        assert_eq!(global.variables[0].content, b"hello");
    }

    #[test]
    fn test_set_variable_literal_with_range() {
        let mut global = test_global();
        set_variable(&mut global, "myvar[1-3]=ABCDE").unwrap();
        assert_eq!(global.variables[0].content, b"BCD");
    }

    #[test]
    fn test_set_variable_env_import() {
        let mut global = test_global();
        // Set a known env var for testing.
        env::set_var("CURL_RS_TEST_VAR_12345", "envvalue");
        set_variable(&mut global, "%CURL_RS_TEST_VAR_12345").unwrap();
        assert_eq!(global.variables[0].content, b"envvalue");
        env::remove_var("CURL_RS_TEST_VAR_12345");
    }

    #[test]
    fn test_set_variable_env_import_missing_no_fallback() {
        let mut global = test_global();
        let result = set_variable(
            &mut global,
            "%CURL_RS_NONEXISTENT_VAR_99999",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_set_variable_env_import_missing_with_fallback() {
        let mut global = test_global();
        env::remove_var("CURL_RS_NONEXISTENT_VAR_88888");
        set_variable(
            &mut global,
            "%CURL_RS_NONEXISTENT_VAR_88888=default_val",
        )
        .unwrap();
        assert_eq!(global.variables[0].content, b"default_val");
    }

    #[test]
    fn test_set_variable_bad_syntax() {
        let mut global = test_global();
        // No '=' or '@' — bad syntax, should warn and skip.
        set_variable(&mut global, "myvar").unwrap();
        assert!(global.variables.is_empty());
    }

    #[test]
    fn test_set_variable_empty_name() {
        let mut global = test_global();
        set_variable(&mut global, "=value").unwrap();
        // Empty name → skipped with warning.
        assert!(global.variables.is_empty());
    }
}
