// SPDX-License-Identifier: curl
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// Rust rewrite of curl's src/var.c (--variable store + {{name:func}} expansion).

//! # `var` — the `--variable` store and `{{name:func}}` expansion engine
//!
//! Faithful, memory-safe Rust rewrite of curl 8.19.0-DEV's `src/var.c` (492
//! lines). It implements the two halves of curl's command-line variable
//! feature:
//!
//! * **[`setvariable`]** parses a single `--variable` argument and records the
//!   resulting name/content pair in the store. It supports every form curl
//!   accepts (see `docs/cmdline-opts/variable.md`):
//!   `name=text` (literal), `name@file` (`@-` reads stdin, binary-safe),
//!   `%name` (import an environment variable, error if unset),
//!   `%name=default` / `%name@default` (env import with a literal/file
//!   fallback), and the `name[start-end]` inclusive byte-range selector.
//! * **[`varexpand`]** scans an option argument for `{{name}}` and
//!   `{{name:func:func…}}` templates and substitutes the stored variable
//!   contents, optionally passing them through the `trim`, `json`, `url`,
//!   `b64`, and `64dec` functions.
//!
//! ## Where the store lives
//!
//! curl keeps its variables in an intrusive linked list hung off the global
//! config; here the store is [`GlobalConfig::variables`], a
//! `Vec<`[`ToolVar`]`>` owned by [`crate::args`]. Because that type is defined
//! by the argument layer (the single source of truth for the CLI
//! vocabulary), this module operates *on* that store rather than defining its
//! own: [`ToolVar`]'s `content` is an `Option<String>`, so binary content read
//! from a file is stored via a lossy UTF-8 conversion. The expansion algorithm
//! itself is byte-oriented throughout (it works on `&[u8]`, checks for NUL
//! bytes with a byte scan, and caps the output by byte length), matching
//! curl's `dynbuf`-based implementation exactly for the text inputs the tests
//! and real command lines use.
//!
//! ## Integration with the argument parser
//!
//! [`crate::args`] does not call this module directly (that would form a
//! dependency cycle — `var.rs` consumes `args`'s vocabulary). Instead the
//! argument layer defines two function-pointer hook types,
//! `args::VariableSetterHook` and `args::VariableExpanderHook`, that `main.rs`
//! wires to [`setvariable`] and [`varexpand`]. The signatures here are chosen
//! to match those hooks exactly:
//!
//! * `setvariable(&str, &mut GlobalConfig) -> Result<(), ParameterError>`
//! * `varexpand(&str, &GlobalConfig) -> Result<Option<String>, ParameterError>`
//!
//! For `varexpand`, `Ok(Some(expanded))` means at least one substitution
//! happened (curl's `replaced == TRUE`, so the caller swaps the argument) and
//! `Ok(None)` means the argument is used verbatim.
//!
//! ## Parity notes (behaviour is defined by curl 8.x, not this summary)
//!
//! * An **unknown variable name** expands to the empty string and still counts
//!   as a replacement — it is *not* an error. Only an **unknown function** or a
//!   **NUL byte** surviving in the expanded value produces
//!   [`ParameterError::ExpandError`] (curl's `PARAM_EXPAND_ERROR`). This
//!   matches curl's `src/var.c` and the test corpus (`tests/data/test451`
//!   substitutes `{{none}}` in a *successful* transfer).
//! * Functions are **colon-separated** (`{{v:trim:json}}`); a comma is not a
//!   separator and yields the unknown-function error (`tests/data/test454`).
//! * The `:json` function reuses [`crate::writeout_json::json_quoted`], exactly
//!   as curl's `src/var.c` includes `tool_writeout_json.h`.
//! * `:64dec` emits the literal marker `[64dec-fail]` when the input is not
//!   valid base64 (`tests/data/test487`).
//!
//! ## Safety
//!
//! This module is implemented entirely in safe Rust — there is no `unsafe`
//! anywhere in it — honouring the AAP's containment policy (`unsafe` is
//! permitted only in the FFI crate and narrow OS primitives).
//!
//! ## Visibility
//!
//! `curl-rs` is a binary crate, so the `pub` items here (consumed by sibling
//! modules through the hook pointers rather than by an external crate) would
//! otherwise trip the `dead_code` lint. The module-level `#![allow(dead_code)]`
//! reflects that these functions are the deliberate, stable public surface of
//! the variable engine, mirroring the identical allowance in the sibling
//! [`crate::writeout_json`] module.

#![allow(dead_code)]

use std::io::Read;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use percent_encoding::{percent_encode, AsciiSet, NON_ALPHANUMERIC};

use crate::args::{errorf, notef, warnf, Diag, GlobalConfig, ParameterError, ToolVar};
use crate::writeout_json::json_quoted;

// ===========================================================================
// Constants — reproduced verbatim from src/var.c
// ===========================================================================

/// Maximum length of a variable name (`MAX_VAR_LEN` in `src/var.c`). A name of
/// this length or longer is rejected. Note curl's check is `nlen >= MAX_VAR_LEN`
/// (the C name buffer is `char name[MAX_VAR_LEN]` and must hold a trailing NUL),
/// so the largest accepted name is `MAX_VAR_LEN - 1` = 127 bytes.
const MAX_VAR_LEN: usize = 128;

/// Upper bound on the expanded output of [`varexpand`] (`MAX_EXPAND_CONTENT` in
/// `src/var.c`). curl initialises the output `dynbuf` with this cap; because the
/// `dynbuf` overflow test is `len + used + 1 > toobig` (the `+ 1` reserves the C
/// NUL terminator), the largest expansion that fits is `MAX_EXPAND_CONTENT - 1`
/// bytes. [`push_capped`] reproduces that exact threshold.
const MAX_EXPAND_CONTENT: usize = 10_000_000;

/// The set of ASCII bytes that the `:url` function percent-encodes.
///
/// This is the complement of curl's `ISUNRESERVED` set (`lib/curl_ctype.h`):
/// start from [`NON_ALPHANUMERIC`] (encode every non-`ALPHA`/`DIGIT` ASCII byte)
/// and exempt the four RFC 3986 unreserved punctuation characters `-`, `.`,
/// `_`, `~`. The net effect is that exactly `[A-Za-z0-9-._~]` pass through and
/// every other byte — including all bytes `>= 0x80` — is emitted as `%XX` with
/// **uppercase** hex, byte-for-byte identical to `curl_easy_escape`
/// (`lib/escape.c`, whose `Curl_hexbyte` indexes the uppercase digit table).
const URL_ESCAPE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// The literal marker curl's `:64dec` function emits on a base64 decode failure
/// (`FUNC_64DEC` path in `src/var.c`). Kept as a named constant so the parity
/// string is defined once and cannot drift.
const B64DEC_FAIL: &[u8] = b"[64dec-fail]";

// ===========================================================================
// Character-class predicates — curl's curl_ctype.h macros
// ===========================================================================

/// curl's `ISSPACE` (`lib/curl_ctype.h`):
/// `ISBLANK(x) || (0x0a <= x <= 0x0d)` — i.e. space, tab, and the four bytes
/// `\n`, `\v`, `\f`, `\r`.
///
/// This deliberately does **not** use [`u8::is_ascii_whitespace`], which omits
/// the vertical tab `0x0b`; matching curl's set exactly is required so `:trim`
/// strips the same bytes curl strips.
#[inline]
fn is_curl_space(b: u8) -> bool {
    b == b' ' || b == b'\t' || (0x0a..=0x0d).contains(&b)
}

/// curl's `ISALNUM(x) || (x == '_')` — the legal characters in a variable name.
/// `ISALNUM` is ASCII `[A-Za-z0-9]`; the underscore is the one extra allowed
/// punctuation character.
#[inline]
fn is_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

// ===========================================================================
// Byte-slice search helpers — Rust stand-ins for C's strstr / memchr
// ===========================================================================

/// Find the first occurrence of `needle` in `hay` at or after byte index
/// `from`, returning its absolute index — the analog of `strstr(line + from,
/// needle)`. Returns `None` when `needle` does not occur (or `from` is past the
/// end).
fn find_sub(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if from > hay.len() || needle.is_empty() || needle.len() > hay.len() - from {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// Find the first `byte` in `hay[from..to]`, returning its absolute index — the
/// analog of `memchr(from, byte, to - from)`. Returns `None` when absent.
fn memchr_in(hay: &[u8], from: usize, to: usize, byte: u8) -> Option<usize> {
    hay.get(from..to)
        .and_then(|s| s.iter().position(|&b| b == byte))
        .map(|p| p + from)
}

/// Append `data` to `out`, enforcing curl's `MAX_EXPAND_CONTENT` `dynbuf` cap.
///
/// curl's `curlx_dyn_addn` fails with `CURLE_TOO_LARGE` when
/// `used + len + 1 > toobig`; `varexpand` maps that to `PARAM_NO_MEM`. This
/// reproduces both the exact threshold (`+ 1` for the reserved NUL) and the
/// error mapping.
fn push_capped(out: &mut Vec<u8>, data: &[u8]) -> Result<(), ParameterError> {
    if out.len() + data.len() + 1 > MAX_EXPAND_CONTENT {
        return Err(ParameterError::NoMem);
    }
    out.extend_from_slice(data);
    Ok(())
}

// ===========================================================================
// Variable store — varcontent / varcleanup / addvariable
// ===========================================================================

/// Look up a variable by exact name — curl's `varcontent`.
///
/// The comparison is case-sensitive and exact (curl checks
/// `strlen(name) == nlen && !strncmp(...)`). Because [`addvariable`] prepends
/// new entries, the first match returned here is always the most recently
/// assigned one, reproducing curl's "latest assignment wins" behaviour when the
/// same name is set more than once.
pub fn varcontent<'a>(global: &'a GlobalConfig, name: &[u8]) -> Option<&'a ToolVar> {
    global.variables.iter().find(|v| v.name.as_bytes() == name)
}

/// Free every stored variable — curl's `varcleanup`.
///
/// In C this walks and frees the intrusive list; here it simply clears the
/// owning `Vec` (each [`ToolVar`] is dropped, releasing its heap `String`s).
/// Rust's ownership model makes an explicit call optional — dropping the
/// [`GlobalConfig`] frees the store automatically — but the function is
/// provided for call-site parity with curl's teardown path.
pub fn varcleanup(global: &mut GlobalConfig) {
    global.variables.clear();
}

/// Record a variable, mirroring curl's `addvariable`.
///
/// A fresh entry is *prepended* to the store (curl links the new node at the
/// head of its list), so a later lookup via [`varcontent`] finds this newest
/// definition first. When a variable of the same name already exists, curl
/// emits a `Note: Overwriting variable '…'` diagnostic (shown only while
/// tracing); that note is reproduced here through [`notef`].
///
/// The C `clen` field is implicit in the stored `String`'s length. Binary
/// content (e.g. from `@file`) is converted to a `String` losslessly for valid
/// UTF-8 (the common case) and via [`String::from_utf8_lossy`] otherwise, which
/// is the faithful representation given [`ToolVar::content`] is an
/// `Option<String>`.
fn addvariable(global: &mut GlobalConfig, name: &[u8], content: &[u8]) {
    let name_str = String::from_utf8_lossy(name).into_owned();

    // Emit the overwrite note before mutating, so the immutable existence check
    // does not overlap the mutable insert borrow.
    if global.variables.iter().any(|v| v.name.as_bytes() == name) {
        notef(global.diag(), &format!("Overwriting variable '{name_str}'"));
    }

    let content_str = String::from_utf8_lossy(content).into_owned();
    // Prepend (curl links at the list head) so the newest definition wins.
    global.variables.insert(
        0,
        ToolVar {
            name: name_str,
            content: Some(content_str),
        },
    );
}

// ===========================================================================
// Variable functions — the `:trim`, `:json`, `:url`, `:b64`, `:64dec` suffixes
// ===========================================================================
//
// curl's `varfunc` (src/var.c) applies a colon-separated list of functions to a
// variable's content, left to right, each consuming the previous result. The
// five functions below are the individual transforms; [`varfunc`] is the
// dispatcher. Every transform reproduces curl's `if(clen)` guard: empty input
// yields empty output (so, e.g., `:64dec` on empty content never emits the
// failure marker — curl only attempts a decode when the content is non-empty).

/// `:trim` — strip leading and trailing whitespace.
///
/// Whitespace is curl's `ISSPACE` set (see [`is_curl_space`]): space, tab, and
/// `\n`/`\v`/`\f`/`\r`. Interior bytes — including embedded NULs — are left
/// untouched, matching curl's two `while(ISSPACE(...))` loops.
fn func_trim(content: &[u8]) -> Vec<u8> {
    if content.is_empty() {
        return Vec::new();
    }
    let mut start = 0usize;
    let mut end = content.len();
    while start < end && is_curl_space(content[start]) {
        start += 1;
    }
    while end > start && is_curl_space(content[end - 1]) {
        end -= 1;
    }
    content[start..end].to_vec()
}

/// `:json` — escape the content as the body of a JSON string.
///
/// This delegates to [`crate::writeout_json::json_quoted`], exactly as curl's
/// `src/var.c` includes `tool_writeout_json.h` and calls `jsonquoted(..., FALSE)`.
/// The `false` argument selects the non-lowercasing variant (curl passes
/// `FALSE` here). The returned string is the escaped body *without* surrounding
/// quotes — identical to curl, which writes the escaped bytes straight into the
/// output buffer with no enclosing `"`.
fn func_json(content: &[u8]) -> Vec<u8> {
    if content.is_empty() {
        return Vec::new();
    }
    json_quoted(content, false).into_bytes()
}

/// `:url` — percent-encode the content (`curl_easy_escape` semantics).
///
/// Encodes every byte except the RFC 3986 unreserved set `[A-Za-z0-9-._~]`
/// (curl's `ISUNRESERVED`), emitting `%XX` with uppercase hexadecimal — see
/// [`URL_ESCAPE_SET`]. The [`percent_encoding`] crate always encodes bytes
/// `>= 0x80` and uses uppercase hex, so the output is byte-for-byte identical to
/// curl's `curl_easy_escape` (which builds `%XX` from its uppercase digit
/// table).
fn func_url(content: &[u8]) -> Vec<u8> {
    if content.is_empty() {
        return Vec::new();
    }
    percent_encode(content, URL_ESCAPE_SET)
        .to_string()
        .into_bytes()
}

/// `:b64` — base64-encode the content (standard alphabet, padded).
///
/// Mirrors curl's `curlx_base64_encode`, which produces canonical padded
/// base64 using the standard `A–Za–z0–9+/` alphabet.
fn func_b64(content: &[u8]) -> Vec<u8> {
    if content.is_empty() {
        return Vec::new();
    }
    BASE64_STANDARD.encode(content).into_bytes()
}

/// `:64dec` — base64-decode the content.
///
/// On a decode failure curl emits the exact literal marker `[64dec-fail]`
/// (see [`B64DEC_FAIL`]) rather than raising an error, so a malformed value in a
/// template still produces a (diagnostic) result. The standard-alphabet,
/// padded decoder matches curl's `curlx_base64_decode`, which likewise requires
/// canonical padding and rejects non-alphabet bytes (e.g. the `-` in
/// `tests/data/test487`'s `not-base64-data`).
fn func_64dec(content: &[u8]) -> Vec<u8> {
    if content.is_empty() {
        return Vec::new();
    }
    match BASE64_STANDARD.decode(content) {
        Ok(decoded) => decoded,
        Err(_) => B64DEC_FAIL.to_vec(),
    }
}

/// Apply the colon-separated function list to `content`, left to right — the
/// port of curl's `varfunc`.
///
/// `func_str` is the slice from the variable name's terminating colon up to (but
/// not including) the closing `}}` — i.e. curl's `funcp`, so it always begins
/// with `':'` and has length `flen == clp - funcp`. curl's `FUNCMATCH` macro
/// requires each function name to be immediately followed by `':'` (another
/// function) or `'}'` (the end); splitting the body on `':'` yields exactly
/// those segments, and any segment that is not one of the five known names —
/// including an empty segment such as in `{{v:trim:}}` — is an unknown function.
///
/// On an unknown function curl prints `unknown variable function in '<funcs>'`
/// (with the full colon-prefixed function string) via `errorf` and returns
/// `PARAM_EXPAND_ERROR`; this reproduces both the message and the error code.
/// The function-name validation happens regardless of whether `content` is
/// empty, matching curl (an unknown function on an unset variable is still an
/// error).
fn varfunc(content: &[u8], func_str: &[u8], diag: Diag) -> Result<Vec<u8>, ParameterError> {
    // `func_str` always starts with the ':' that curl's memchr located; strip
    // exactly that one leading colon, then treat each ':'-separated segment as a
    // required function name.
    debug_assert_eq!(func_str.first(), Some(&b':'));
    let body: &[u8] = func_str.get(1..).unwrap_or(&[]);

    let mut current: Vec<u8> = content.to_vec();
    for segment in body.split(|&b| b == b':') {
        current = match segment {
            b"trim" => func_trim(&current),
            b"json" => func_json(&current),
            b"url" => func_url(&current),
            b"b64" => func_b64(&current),
            b"64dec" => func_64dec(&current),
            _ => {
                // Unsupported function: reproduce curl's diagnostic verbatim,
                // including the leading colon of the whole function string.
                let shown = String::from_utf8_lossy(func_str);
                errorf(diag, &format!("unknown variable function in '{shown}'"));
                return Err(ParameterError::ExpandError);
            }
        };
    }
    Ok(current)
}

// ===========================================================================
// varexpand — the {{name}} / {{name:func:func…}} template scanner
// ===========================================================================

/// Byte-level implementation of curl's `varexpand`.
///
/// Scans `input` for `{{…}}` templates and returns:
///
/// * `Ok(Some(bytes))` — at least one variable was substituted (curl's
///   `replaced == TRUE`); `bytes` is the fully expanded result.
/// * `Ok(None)` — no substitution occurred (curl frees the output buffer and
///   sets `replaced = FALSE`); the caller should use the argument verbatim.
/// * `Err(_)` — a hard expansion error (unknown function, embedded NUL in the
///   expanded value, or the `MAX_EXPAND_CONTENT` cap exceeded).
///
/// The algorithm mirrors `src/var.c` step for step:
///
/// * `\{{` is an escape for a literal `{{`; the backslash is consumed and the
///   two braces are emitted verbatim. An escape on its own does **not** count as
///   a replacement, so a string containing only escapes returns `Ok(None)` and
///   is used unchanged (this is curl's behaviour — `added` stays false).
/// * An **unknown variable name** expands to nothing but still counts as a
///   replacement — it is *not* an error (`tests/data/test451`).
/// * A template whose name is empty/too long, or contains characters outside
///   `[A-Za-z0-9_]`, is emitted verbatim with a warning and does not count as a
///   replacement.
/// * An unbalanced `{{` (no closing `}}`) warns and stops scanning; any text
///   already accumulated is kept only if a prior substitution occurred.
fn varexpand_bytes(input: &[u8], global: &GlobalConfig) -> Result<Option<Vec<u8>>, ParameterError> {
    let diag = global.diag();
    let mut out: Vec<u8> = Vec::new();
    let mut added = false;
    // `pos` is curl's `line`: the start of the not-yet-emitted remainder.
    let mut pos = 0usize;

    // curl's `do { envp = strstr(line, "{{"); … } while(envp)` — the loop runs
    // as long as another "{{" is found.
    while let Some(envp) = find_sub(input, pos, b"{{") {
        if envp > pos && input[envp - 1] == b'\\' {
            // Escaped "\{{": emit the text up to the byte before the backslash
            // (dropping the backslash), then a literal "{{", and resume after it.
            push_capped(&mut out, &input[pos..envp - 1])?;
            push_capped(&mut out, b"{{")?;
            pos = envp + 2;
            continue;
        }

        // A real "{{" — locate the matching "}}".
        let clp = match find_sub(input, envp, b"}}") {
            Some(c) => c,
            None => {
                warnf(
                    diag,
                    &format!(
                        "missing close '}}}}' in '{}'",
                        String::from_utf8_lossy(input)
                    ),
                );
                break;
            }
        };

        let name_start = envp + 2; // move over "{{"
                                   // If there is a function list, the name ends at the first ':'.
        let funcp = memchr_in(input, name_start, clp, b':');
        let nlen = match funcp {
            Some(fp) => fp - name_start,
            None => clp - name_start,
        };

        if nlen == 0 || nlen >= MAX_VAR_LEN {
            // Bad name length: emit the whole run (leading text + template) as-is.
            warnf(
                diag,
                &format!(
                    "bad variable name length '{}'",
                    String::from_utf8_lossy(input)
                ),
            );
            push_capped(&mut out, &input[pos..clp + 2])?;
        } else {
            let name = &input[name_start..name_start + nlen];
            if !name.iter().all(|&b| is_name_char(b)) {
                // Invalid characters: emit leading text + template verbatim.
                warnf(
                    diag,
                    &format!("bad variable name: {}", String::from_utf8_lossy(name)),
                );
                push_capped(&mut out, &input[pos..clp + 2])?;
            } else {
                // Valid name — emit the leading text, then the substituted value.
                push_capped(&mut out, &input[pos..name_start - 2])?;

                // Look up the variable; an unknown name resolves to empty content
                // (still a valid substitution, per curl).
                let content: Vec<u8> = match varcontent(global, name) {
                    Some(v) => v
                        .content
                        .as_deref()
                        .map(|s| s.as_bytes().to_vec())
                        .unwrap_or_default(),
                    None => Vec::new(),
                };

                // Apply the colon-separated function list, if any.
                let value: Vec<u8> = match funcp {
                    Some(fp) => varfunc(&content, &input[fp..clp], diag)?,
                    None => content,
                };

                // A NUL byte surviving in the value cannot be represented and is
                // an error — but only when there actually is a non-empty value
                // (curl guards with `value && vlen > 0`). `:json` escapes NULs to
                // `\u0000` and `:url` to `%00`, so those forms never trip this.
                if !value.is_empty() && value.contains(&0) {
                    errorf(diag, "variable contains null byte");
                    return Err(ParameterError::ExpandError);
                }

                push_capped(&mut out, &value)?;
                added = true;
            }
        }

        pos = clp + 2; // resume past the "}}"
    }

    // curl appends the trailing remainder only when a substitution happened.
    if added && pos < input.len() {
        push_capped(&mut out, &input[pos..])?;
    }

    if added {
        Ok(Some(out))
    } else {
        // curl frees the output buffer and reports `replaced = FALSE`.
        Ok(None)
    }
}

/// Expand `{{name}}` / `{{name:func:func…}}` templates in `input` — the public
/// `--expand-<option>` entry point, wired into [`crate::args`] as its
/// `VariableExpanderHook`.
///
/// Returns `Ok(Some(expanded))` when at least one substitution occurred (curl's
/// `replaced == TRUE`, so the caller swaps in the expanded argument), `Ok(None)`
/// when the argument is used verbatim, or `Err(ParameterError)` on a hard
/// expansion failure.
///
/// The expanded bytes are converted to a `String` with
/// [`String::from_utf8_lossy`]. Template literals and stored variable contents
/// are already valid UTF-8 (both originate from `&str` inputs), so the only
/// source of non-UTF-8 bytes is a `:64dec` producing raw binary; such bytes are
/// represented losslessly for all UTF-8 outputs and via the replacement
/// character otherwise, which is the faithful mapping onto the `String`-typed
/// hook contract.
pub fn varexpand(input: &str, global: &GlobalConfig) -> Result<Option<String>, ParameterError> {
    match varexpand_bytes(input.as_bytes(), global)? {
        Some(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
        None => Ok(None),
    }
}

// ===========================================================================
// setvariable — parse a single --variable argument
// ===========================================================================

/// curl's `CURL_OFF_T_MAX` — the signed 64-bit maximum, used as the "unbounded"
/// end offset and as the byte-range parser's overflow ceiling. Represented as a
/// `u64` because offsets here are non-negative.
const CURL_OFF_T_MAX: u64 = i64::MAX as u64;

/// Parse an unsigned base-10 integer starting at `start`, mirroring
/// `curlx_str_number` with `max == CURL_OFF_T_MAX`.
///
/// Requires at least one ASCII digit (no leading sign, space, or `0x` prefix;
/// leading zeroes are accepted). Returns the parsed value and the index just
/// past the last digit, or `None` on "no number" or overflow past
/// [`CURL_OFF_T_MAX`] — both of which curl treats as a syntax error.
fn parse_offset(bytes: &[u8], start: usize) -> Option<(u64, usize)> {
    let mut pos = start;
    // At least one digit is required (STRE_NO_NUM otherwise). `is_some_and` is
    // used rather than `is_none_or` to stay within the 1.75 MSRV.
    if !bytes.get(pos).is_some_and(u8::is_ascii_digit) {
        return None;
    }
    let mut num: u64 = 0;
    while let Some(&b) = bytes.get(pos) {
        if !b.is_ascii_digit() {
            break;
        }
        let n = u64::from(b - b'0');
        // Overflow guard identical to str_num_base's base-10 branch.
        if num > (CURL_OFF_T_MAX - n) / 10 {
            return None; // STRE_OVERFLOW
        }
        num = num * 10 + n;
        pos += 1;
    }
    Some((num, pos))
}

/// Look up an environment variable, returning its raw bytes — the analog of
/// curl's `getenv`.
///
/// On Unix (the only supported target family) environment values are byte
/// strings, so the raw bytes are preserved for binary-safe `%name` imports. The
/// non-Unix fallback exists solely so the module still compiles elsewhere.
#[cfg(unix)]
fn env_bytes(name: &str) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    std::env::var_os(name).map(|v| v.as_bytes().to_vec())
}

#[cfg(not(unix))]
fn env_bytes(name: &str) -> Option<Vec<u8>> {
    std::env::var_os(name).map(|v| v.to_string_lossy().into_owned().into_bytes())
}

/// Read a byte range `[starto, endo]` (inclusive) from `reader` — the port of
/// curl's `file2memory_range` (`src/tool_paramhlp.c`).
///
/// curl seeks seekable files and discards a prefix from non-seekable stdin;
/// both strategies yield the same bytes, so this uses the discard approach
/// uniformly (correct for files and stdin alike): read in 4096-byte chunks,
/// drop the first `starto` bytes, then collect until byte offset `endo`
/// inclusive. `endo == CURL_OFF_T_MAX` means "to end of input". A start beyond
/// the input simply yields empty content (`tests/data/test789`). Read errors
/// map to [`ParameterError::ReadError`]; `Interrupted` is retried, matching
/// stdio's `fread`.
fn file2memory_range<R: Read>(
    mut reader: R,
    starto: u64,
    endo: u64,
) -> Result<Vec<u8>, ParameterError> {
    let mut out: Vec<u8> = Vec::new();
    let mut offset: u64 = 0;
    let mut throwaway: u64 = starto;
    let mut buffer = [0u8; 4096];

    loop {
        let nread = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ParameterError::ReadError),
        };

        let mut n_add = nread;
        let mut start_idx = 0usize;

        if throwaway > 0 {
            if throwaway >= nread as u64 {
                // Entire chunk lies before the start offset — discard it.
                throwaway -= nread as u64;
                offset += nread as u64;
                n_add = 0;
            } else {
                // Discard the leading part, keep the trailing piece.
                start_idx = throwaway as usize;
                n_add = nread - start_idx;
                offset += throwaway;
                throwaway = 0;
            }
        }

        if n_add > 0 {
            if offset > endo {
                break;
            }
            // Clamp so the last byte kept is offset `endo` (inclusive).
            if offset + n_add as u64 > endo {
                n_add = (endo - offset + 1) as usize;
            }
            out.extend_from_slice(&buffer[start_idx..start_idx + n_add]);
            offset += n_add as u64;
            if offset > endo {
                break;
            }
        }
    }

    Ok(out)
}

/// Parse and store a single `--variable` definition — curl's `setvariable`.
///
/// Wired into [`crate::args`] as its `VariableSetterHook`. Recognised forms
/// (see `docs/cmdline-opts/variable.md`):
///
/// * `name=text` — literal assignment.
/// * `name@file` — content read from `file`; `@-` reads stdin (binary-safe).
/// * `%name` — import environment variable `name`; an unset variable with no
///   fallback is an error ([`ParameterError::ExpandError`]).
/// * `%name=default` / `%name@default` — env import with a literal / file
///   fallback used only when the variable is unset.
/// * `name[start-end]…` — apply an inclusive byte range to the file or literal
///   content (`[start-]` runs to the end). The range is **not** applied to an
///   imported environment value, matching curl.
///
/// A name that is empty or `>= MAX_VAR_LEN` bytes, or an otherwise malformed
/// argument, is skipped with a warning and returns `Ok(())` (curl returns
/// `PARAM_OK`). A `start > end` range is a hard [`ParameterError::VarSyntax`].
pub fn setvariable(input: &str, global: &mut GlobalConfig) -> Result<(), ParameterError> {
    // `diag` is a cheap `Copy` snapshot, so it does not hold a borrow of
    // `global` across the later `&mut global` reborrow in `addvariable`.
    let diag = global.diag();
    let bytes = input.as_bytes();
    let mut pos = 0usize;

    // Optional '%' import prefix.
    let import = bytes.first() == Some(&b'%');
    if import {
        pos += 1;
    }

    // Variable name: a run of [A-Za-z0-9_].
    let name_start = pos;
    while pos < bytes.len() && is_name_char(bytes[pos]) {
        pos += 1;
    }
    let nlen = pos - name_start;
    if nlen == 0 || nlen >= MAX_VAR_LEN {
        warnf(
            diag,
            &format!("Bad variable name length ({nlen}), skipping"),
        );
        return Ok(());
    }
    let name = &bytes[name_start..pos];

    // Content resolved so far (`Some` means "already have it", which for an env
    // import suppresses any `=`/`@` fallback and the byte range, per curl).
    let mut content: Option<Vec<u8>> = None;

    if import {
        // Deliberately not curl_getenv(): an empty ("") value must be usable.
        let name_str = std::str::from_utf8(name).unwrap_or_default();
        let has_more = pos < bytes.len();
        match env_bytes(name_str) {
            Some(val) => content = Some(val),
            None => {
                if !has_more {
                    // No assignment and no such variable — fail.
                    errorf(diag, &format!("Variable '{name_str}' import fail, not set"));
                    return Err(ParameterError::ExpandError);
                }
                // Otherwise fall through to the `=`/`@` default.
            }
        }
    }

    // Optional byte range: `[start-end]`, only when '[' is directly followed by
    // a digit (curl's `*line == '[' && ISDIGIT(line[1])`).
    let mut startoffset: u64 = 0;
    let mut endoffset: u64 = CURL_OFF_T_MAX;
    if bytes.get(pos) == Some(&b'[') && bytes.get(pos + 1).is_some_and(u8::is_ascii_digit) {
        pos += 1; // consume '['
        let (s, np) = parse_offset(bytes, pos).ok_or(ParameterError::VarSyntax)?;
        startoffset = s;
        pos = np;
        if bytes.get(pos) != Some(&b'-') {
            return Err(ParameterError::VarSyntax);
        }
        pos += 1;
        if bytes.get(pos) == Some(&b']') {
            // `[start-]` — open-ended, endoffset stays CURL_OFF_T_MAX.
            pos += 1;
        } else {
            let (e, np) = parse_offset(bytes, pos).ok_or(ParameterError::VarSyntax)?;
            endoffset = e;
            pos = np;
            if bytes.get(pos) != Some(&b']') {
                return Err(ParameterError::VarSyntax);
            }
            pos += 1;
        }
        if startoffset > endoffset {
            return Err(ParameterError::VarSyntax);
        }
    }

    // When `content` is already set the value came from a successful `%name`
    // import: curl uses it verbatim and applies neither a `=`/`@` fallback nor
    // the byte range. Only resolve `=`/`@`/error when no value is in hand yet.
    if content.is_none() {
        if bytes.get(pos) == Some(&b'@') {
            // Read from a file, or from stdin for "@-".
            pos += 1;
            let fname = std::str::from_utf8(&bytes[pos..]).unwrap_or_default();
            let data = if fname == "-" {
                let stdin = std::io::stdin();
                let lock = stdin.lock();
                file2memory_range(lock, startoffset, endoffset)?
            } else {
                match std::fs::File::open(fname) {
                    Ok(file) => file2memory_range(file, startoffset, endoffset)?,
                    Err(e) => {
                        errorf(diag, &format!("Failed to open {fname}: {e}"));
                        return Err(ParameterError::ReadError);
                    }
                }
            };
            content = Some(data);
        } else if bytes.get(pos) == Some(&b'=') {
            // Literal assignment, with the byte range applied inline.
            pos += 1;
            let lit = &bytes[pos..];
            let selected: &[u8] = if startoffset != 0 || endoffset != CURL_OFF_T_MAX {
                let clen = lit.len() as u64;
                if startoffset >= clen {
                    &[]
                } else {
                    let end = if endoffset >= clen {
                        clen - 1
                    } else {
                        endoffset
                    };
                    let start = startoffset as usize;
                    let take = (end - startoffset + 1) as usize;
                    &lit[start..start + take]
                }
            } else {
                lit
            };
            content = Some(selected.to_vec());
        } else {
            warnf(diag, &format!("Bad --variable syntax, skipping: {input}"));
            return Ok(());
        }
    }

    let content = content.unwrap_or_default();
    addvariable(global, name, &content);
    Ok(())
}

// ===========================================================================
// Tests — parity checks against curl 8.x behaviour and the tests/data oracle
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn g() -> GlobalConfig {
        GlobalConfig::new()
    }

    #[test]
    fn public_functions_match_args_hook_types() {
        // Statically prove the signatures line up with the hook aliases in
        // `args`, so `main.rs` can install them without a shim. A mismatch would
        // make this fail to compile.
        let _setter: crate::args::VariableSetterHook = setvariable;
        let _expander: crate::args::VariableExpanderHook = varexpand;
    }

    fn content_of(g: &GlobalConfig, name: &str) -> Option<String> {
        varcontent(g, name.as_bytes()).and_then(|v| v.content.clone())
    }

    // --- store: addvariable / varcontent / latest-wins --------------------

    #[test]
    fn addvariable_prepends_latest_wins() {
        let mut cfg = g();
        addvariable(&mut cfg, b"second", b"hello");
        addvariable(&mut cfg, b"second", b"again");
        // curl prepends, so the newest definition is found first.
        assert_eq!(content_of(&cfg, "second").as_deref(), Some("again"));
        // Both entries physically remain in the store (curl frees only on cleanup).
        assert_eq!(cfg.variables.len(), 2);
    }

    #[test]
    fn varcontent_exact_case_sensitive() {
        let mut cfg = g();
        addvariable(&mut cfg, b"Name", b"v");
        assert!(varcontent(&cfg, b"name").is_none());
        assert!(varcontent(&cfg, b"Name").is_some());
        assert!(varcontent(&cfg, b"Nam").is_none());
    }

    #[test]
    fn varcleanup_clears_store() {
        let mut cfg = g();
        addvariable(&mut cfg, b"a", b"1");
        varcleanup(&mut cfg);
        assert!(cfg.variables.is_empty());
    }

    // --- individual functions ---------------------------------------------

    #[test]
    fn trim_strips_curl_whitespace_set() {
        // Space, tab, LF, VTAB (0x0b), FF, CR are all stripped; interior kept.
        assert_eq!(func_trim(b" \t\n\x0b\x0cx y\r\n"), b"x y".to_vec());
        assert_eq!(func_trim(b"noedge"), b"noedge".to_vec());
        assert_eq!(func_trim(b"   "), b"".to_vec());
        assert_eq!(func_trim(b""), b"".to_vec());
    }

    #[test]
    fn json_escapes_controls_and_nul() {
        // Matches tests/data/test451: control bytes -> \u00NN (lowercase), NUL -> \u0000.
        let out = func_json(b"\x01\x02\x03\x00\x04\x05\x06");
        assert_eq!(
            out,
            b"\\u0001\\u0002\\u0003\\u0000\\u0004\\u0005\\u0006".to_vec()
        );
        // Quote and backslash are escaped; body carries no surrounding quotes.
        assert_eq!(func_json(b"a\"b\\c"), b"a\\\"b\\\\c".to_vec());
        assert_eq!(func_json(b""), b"".to_vec());
    }

    #[test]
    fn url_percent_encodes_uppercase() {
        // tests/data/test451 tail: control bytes -> %NN uppercase, NUL -> %00.
        assert_eq!(
            func_url(b"\x01\x02\x03\x00\x04\x05\x06"),
            b"%01%02%03%00%04%05%06".to_vec()
        );
        // Unreserved set passes through untouched; space and others encode.
        assert_eq!(func_url(b"aZ0-._~"), b"aZ0-._~".to_vec());
        assert_eq!(func_url(b"a b/c"), b"a%20b%2Fc".to_vec());
        assert_eq!(func_url(b""), b"".to_vec());
    }

    #[test]
    fn b64_roundtrip_and_fail_marker() {
        let enc = func_b64(b"hello");
        assert_eq!(enc, b"aGVsbG8=".to_vec());
        assert_eq!(func_64dec(&enc), b"hello".to_vec());
        // tests/data/test487: a non-base64 input yields the exact literal marker.
        assert_eq!(func_64dec(b"not-base64-data"), b"[64dec-fail]".to_vec());
        // Empty content never attempts a decode -> empty, NOT the fail marker.
        assert_eq!(func_64dec(b""), b"".to_vec());
        assert_eq!(func_b64(b""), b"".to_vec());
    }

    // --- varfunc dispatcher -------------------------------------------------

    #[test]
    fn varfunc_chains_left_to_right() {
        let d = g().diag();
        // trim then json (test451): leading/trailing ws removed, then JSON-escaped.
        let out = varfunc(b"  \x01\x00\x02  ", b":trim:json", d).unwrap();
        assert_eq!(out, b"\\u0001\\u0000\\u0002".to_vec());
        // trim then url.
        let out = varfunc(b"  \x01\x00\x02  ", b":trim:url", d).unwrap();
        assert_eq!(out, b"%01%00%02".to_vec());
    }

    #[test]
    fn varfunc_unknown_function_errors() {
        let d = g().diag();
        assert_eq!(
            varfunc(b"x", b":super", d),
            Err(ParameterError::ExpandError)
        );
        // An empty trailing segment ({{v:trim:}}) is an unknown function too.
        assert_eq!(
            varfunc(b"x", b":trim:", d),
            Err(ParameterError::ExpandError)
        );
        // A single empty segment ({{v:}}).
        assert_eq!(varfunc(b"x", b":", d), Err(ParameterError::ExpandError));
    }

    #[test]
    fn varfunc_on_empty_content_still_validates_name() {
        let d = g().diag();
        // Valid function on empty content -> empty, no error.
        assert_eq!(varfunc(b"", b":trim", d).unwrap(), b"".to_vec());
        // Unknown function on empty content -> still an error.
        assert_eq!(varfunc(b"", b":nope", d), Err(ParameterError::ExpandError));
    }

    // --- varexpand ----------------------------------------------------------

    #[test]
    fn expand_unknown_variable_is_empty_and_replaced() {
        // tests/data/test451: {{none}} expands to nothing but still counts as a
        // replacement (NOT an error).
        let cfg = g();
        assert_eq!(
            varexpand("--{{none}}--", &cfg).unwrap().as_deref(),
            Some("----")
        );
    }

    #[test]
    fn expand_known_variable() {
        let mut cfg = g();
        addvariable(&mut cfg, b"x", b"VALUE");
        assert_eq!(
            varexpand("<{{x}}>", &cfg).unwrap().as_deref(),
            Some("<VALUE>")
        );
    }

    #[test]
    fn expand_no_template_returns_none() {
        let cfg = g();
        // No {{ at all -> no replacement -> use verbatim.
        assert_eq!(varexpand("plain text", &cfg).unwrap(), None);
    }

    #[test]
    fn expand_test451_combined() {
        // Faithful reconstruction of tests/data/test451's successful expansion.
        let mut cfg = g();
        // `what` holds the 7 bytes 0x01..0x06 with a NUL in the middle.
        addvariable(&mut cfg, b"what", b"\x01\x02\x03\x00\x04\x05\x06");
        addvariable(&mut cfg, b"second", b"hello");
        addvariable(&mut cfg, b"second", b"again"); // latest wins
        let got = varexpand(
            "--{{what:trim:json}}22{{none}}--{{second}}{{what:trim:url}}",
            &cfg,
        )
        .unwrap();
        assert_eq!(
            got.as_deref(),
            Some(
                "--\\u0001\\u0002\\u0003\\u0000\\u0004\\u0005\\u000622--again%01%02%03%00%04%05%06"
            )
        );
    }

    #[test]
    fn expand_escape_backslash_bracebrace() {
        let mut cfg = g();
        addvariable(&mut cfg, b"x", b"Y");
        // `\{{` becomes a literal `{{`; the backslash is consumed. A real
        // substitution elsewhere makes the whole result "replaced".
        assert_eq!(
            varexpand("a\\{{b}} {{x}}", &cfg).unwrap().as_deref(),
            Some("a{{b}} Y")
        );
    }

    #[test]
    fn expand_escape_only_returns_none() {
        // An escape with no real substitution does not count as replaced, so the
        // argument is used verbatim (curl frees the buffer, replaced == FALSE).
        let cfg = g();
        assert_eq!(varexpand("a\\{{b}}", &cfg).unwrap(), None);
    }

    #[test]
    fn expand_raw_nul_byte_errors() {
        // tests/data/test453/456: a NUL surviving in the expanded value is an error.
        let mut cfg = g();
        addvariable(&mut cfg, b"what", b"a\x00b");
        assert_eq!(
            varexpand("{{what}}", &cfg),
            Err(ParameterError::ExpandError)
        );
    }

    #[test]
    fn expand_nul_via_json_is_ok() {
        // :json escapes the NUL to \u0000, so no raw NUL survives -> success.
        let mut cfg = g();
        addvariable(&mut cfg, b"what", b"a\x00b");
        assert_eq!(
            varexpand("{{what:json}}", &cfg).unwrap().as_deref(),
            Some("a\\u0000b")
        );
    }

    #[test]
    fn expand_unknown_function_errors() {
        // tests/data/test452: an unknown function is a hard error.
        let mut cfg = g();
        addvariable(&mut cfg, b"what", b"data");
        assert_eq!(
            varexpand("{{what:super}}", &cfg),
            Err(ParameterError::ExpandError)
        );
    }

    #[test]
    fn expand_comma_separator_is_unknown_function() {
        // tests/data/test454: a comma is NOT a separator; "trim,url" is one bad name.
        let mut cfg = g();
        addvariable(&mut cfg, b"what", b" data ");
        assert_eq!(
            varexpand("{{what:trim,url}}", &cfg),
            Err(ParameterError::ExpandError)
        );
    }

    #[test]
    fn expand_bad_name_length_emitted_verbatim() {
        // Empty name {{}} -> emitted as-is, not a substitution.
        let cfg = g();
        assert_eq!(varexpand("x{{}}y", &cfg).unwrap(), None);
        // Combined with a real substitution, the bad template stays verbatim.
        let mut cfg2 = g();
        addvariable(&mut cfg2, b"a", b"A");
        assert_eq!(
            varexpand("{{}}{{a}}", &cfg2).unwrap().as_deref(),
            Some("{{}}A")
        );
    }

    #[test]
    fn expand_bad_name_chars_emitted_verbatim() {
        // A name with an illegal char is emitted verbatim (with leading text).
        let cfg = g();
        assert_eq!(varexpand("pre{{a-b}}post", &cfg).unwrap(), None);
    }

    #[test]
    fn expand_missing_close_stops() {
        // No closing }} -> warn and stop; nothing substituted -> None.
        let cfg = g();
        assert_eq!(varexpand("{{x", &cfg).unwrap(), None);
        // With a prior substitution, the unterminated tail is kept as suffix.
        let mut cfg2 = g();
        addvariable(&mut cfg2, b"a", b"A");
        assert_eq!(
            varexpand("{{a}}tail{{x", &cfg2).unwrap().as_deref(),
            Some("Atail{{x")
        );
    }

    #[test]
    fn expand_max_content_cap() {
        // Producing more than MAX_EXPAND_CONTENT bytes is PARAM_NO_MEM.
        let mut cfg = g();
        let big = vec![b'a'; MAX_EXPAND_CONTENT]; // MAX bytes of content
        addvariable(&mut cfg, b"big", &big);
        assert_eq!(varexpand("{{big}}", &cfg), Err(ParameterError::NoMem));
    }

    // --- parse_offset -------------------------------------------------------

    #[test]
    fn parse_offset_basics() {
        assert_eq!(parse_offset(b"123]", 0), Some((123, 3)));
        assert_eq!(parse_offset(b"007-", 0), Some((7, 3))); // leading zeroes ok
        assert_eq!(parse_offset(b"-5", 0), None); // no digit -> no number
        assert_eq!(parse_offset(b"", 0), None);
        // Overflow past i64::MAX is rejected.
        assert_eq!(parse_offset(b"99999999999999999999", 0), None);
        assert_eq!(
            parse_offset(&format!("{}", i64::MAX).into_bytes(), 0),
            Some((i64::MAX as u64, 19))
        );
    }

    // --- file2memory_range --------------------------------------------------

    #[test]
    fn file2memory_range_whole_and_ranges() {
        let data = b"0123456789abcdef".to_vec(); // 16 bytes
                                                 // Whole input.
        let all = file2memory_range(Cursor::new(data.clone()), 0, CURL_OFF_T_MAX).unwrap();
        assert_eq!(all, data);
        // tests/data/test790: [5-9] -> "56789".
        let r = file2memory_range(Cursor::new(data.clone()), 5, 9).unwrap();
        assert_eq!(r, b"56789".to_vec());
        // tests/data/test791: [10-30] clamps to end -> "abcdef".
        let r = file2memory_range(Cursor::new(data.clone()), 10, 30).unwrap();
        assert_eq!(r, b"abcdef".to_vec());
        // tests/data/test789: start beyond input -> empty.
        let r = file2memory_range(Cursor::new(data.clone()), 75, 85).unwrap();
        assert_eq!(r, b"".to_vec());
        // tests/data/test788: single byte [15-15].
        let r = file2memory_range(Cursor::new(data.clone()), 15, 15).unwrap();
        assert_eq!(r, b"f".to_vec());
    }

    #[test]
    fn file2memory_range_spans_buffer_boundary() {
        // Exercise the 4096-byte chunk loop and the throwaway/clamp logic.
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let r = file2memory_range(Cursor::new(data.clone()), 4090, 4100).unwrap();
        assert_eq!(r, data[4090..=4100].to_vec());
    }

    // --- setvariable --------------------------------------------------------

    #[test]
    fn set_literal_and_latest_wins() {
        let mut cfg = g();
        setvariable("second=hello", &mut cfg).unwrap();
        setvariable("second=again", &mut cfg).unwrap();
        assert_eq!(content_of(&cfg, "second").as_deref(), Some("again"));
    }

    #[test]
    fn set_empty_literal() {
        let mut cfg = g();
        setvariable("empty=", &mut cfg).unwrap();
        assert_eq!(content_of(&cfg, "empty").as_deref(), Some(""));
    }

    #[test]
    fn set_literal_byte_ranges() {
        // tests/data/test790.
        let mut cfg = g();
        setvariable("n[5-9]=0123456789abcdef", &mut cfg).unwrap();
        assert_eq!(content_of(&cfg, "n").as_deref(), Some("56789"));
        // tests/data/test791: end clamps to last byte.
        let mut cfg = g();
        setvariable("n[10-30]=0123456789abcdef", &mut cfg).unwrap();
        assert_eq!(content_of(&cfg, "n").as_deref(), Some("abcdef"));
        // tests/data/test789: start past end -> empty.
        let mut cfg = g();
        setvariable("n[75-85]=0123456789abcdef", &mut cfg).unwrap();
        assert_eq!(content_of(&cfg, "n").as_deref(), Some(""));
        // Open-ended [start-].
        let mut cfg = g();
        setvariable("n[10-]=0123456789abcdef", &mut cfg).unwrap();
        assert_eq!(content_of(&cfg, "n").as_deref(), Some("abcdef"));
    }

    #[test]
    fn set_start_greater_than_end_is_syntax_error() {
        // tests/data/test787.
        let mut cfg = g();
        assert_eq!(
            setvariable("n[15-14]=data", &mut cfg),
            Err(ParameterError::VarSyntax)
        );
    }

    #[test]
    fn set_bad_range_syntax() {
        let mut cfg = g();
        // Missing closing bracket.
        assert_eq!(
            setvariable("n[5-9=data", &mut cfg),
            Err(ParameterError::VarSyntax)
        );
    }

    #[test]
    fn set_bad_name_length_skips() {
        let mut cfg = g();
        // No name before '=' -> warn + skip, returns Ok, nothing stored.
        setvariable("=noname", &mut cfg).unwrap();
        assert!(cfg.variables.is_empty());
        // '%' with no name.
        setvariable("%", &mut cfg).unwrap();
        assert!(cfg.variables.is_empty());
        // Name >= MAX_VAR_LEN bytes -> skip.
        let long = format!("{}=x", "a".repeat(MAX_VAR_LEN));
        setvariable(&long, &mut cfg).unwrap();
        assert!(cfg.variables.is_empty());
        // Name of exactly MAX_VAR_LEN - 1 is accepted.
        let ok = format!("{}=x", "a".repeat(MAX_VAR_LEN - 1));
        setvariable(&ok, &mut cfg).unwrap();
        assert_eq!(cfg.variables.len(), 1);
    }

    #[test]
    fn set_bad_syntax_skips() {
        let mut cfg = g();
        // A name with neither '=', '@', nor a valid range -> warn + skip.
        setvariable("nofollow", &mut cfg).unwrap();
        assert!(cfg.variables.is_empty());
    }

    #[test]
    fn set_env_import_variants() {
        // Use a unique name to avoid clobbering the ambient environment.
        let key = "CURL_RS_VAR_TEST_IMPORT_XYZ";
        std::env::set_var(key, "envval");
        let mut cfg = g();
        setvariable(&format!("%{key}"), &mut cfg).unwrap();
        assert_eq!(content_of(&cfg, key).as_deref(), Some("envval"));
        // Env present -> the value wins over any default.
        let mut cfg = g();
        setvariable(&format!("%{key}=fallback"), &mut cfg).unwrap();
        assert_eq!(content_of(&cfg, key).as_deref(), Some("envval"));
        std::env::remove_var(key);

        // Unset with no default -> hard error.
        let mut cfg = g();
        assert_eq!(
            setvariable(&format!("%{key}"), &mut cfg),
            Err(ParameterError::ExpandError)
        );
        // Unset with a literal default -> uses the default.
        let mut cfg = g();
        setvariable(&format!("%{key}=fallback"), &mut cfg).unwrap();
        assert_eq!(content_of(&cfg, key).as_deref(), Some("fallback"));
    }

    #[test]
    fn set_from_file_and_stdin_dash_marker() {
        use std::io::Write;
        // Write a temp file and import it, including a byte range.
        let mut tf = tempfile::NamedTempFile::new().unwrap();
        tf.write_all(b"0123456789abcdef").unwrap();
        let path = tf.path().to_str().unwrap().to_string();

        let mut cfg = g();
        setvariable(&format!("f@{path}"), &mut cfg).unwrap();
        assert_eq!(content_of(&cfg, "f").as_deref(), Some("0123456789abcdef"));

        // Byte range applied to file content: [5-9] -> "56789".
        let mut cfg = g();
        setvariable(&format!("f[5-9]@{path}"), &mut cfg).unwrap();
        assert_eq!(content_of(&cfg, "f").as_deref(), Some("56789"));
    }

    #[test]
    fn set_from_missing_file_is_read_error() {
        let mut cfg = g();
        let missing = "/nonexistent/path/curl_rs_var_test_missing_file";
        assert_eq!(
            setvariable(&format!("f@{missing}"), &mut cfg),
            Err(ParameterError::ReadError)
        );
    }

    #[test]
    fn set_then_expand_end_to_end() {
        // Integration: set several variables then expand a template over them.
        let mut cfg = g();
        setvariable("greet=Hello", &mut cfg).unwrap();
        setvariable("name=World", &mut cfg).unwrap();
        assert_eq!(
            varexpand("{{greet}}, {{name}}!", &cfg).unwrap().as_deref(),
            Some("Hello, World!")
        );
    }
}
