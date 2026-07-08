// SPDX-License-Identifier: curl
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// Rust rewrite of curl's src/tool_writeout_json.c (--write-out %{json}).

//! # `writeout_json` — the `%{json}` / `%{header_json}` emitters
//!
//! Faithful Rust rewrite of curl 8.19.0-DEV's `src/tool_writeout_json.c`. It
//! renders the `--write-out` variable set as a JSON object and provides the
//! shared JSON string-quoting helpers.
//!
//! The variable catalogue itself lives in the sibling [`crate::writeout`]
//! module; this module iterates [`crate::writeout::VARIABLES`] and invokes
//! [`crate::writeout::emit_var`] in JSON mode, exactly like curl's
//! `ourWriteOutJSON` walks `mappings[]` calling each `writefunc` with
//! `use_json = true`.
//!
//! As with the other CLI modules, the crate is a binary, so items wired in by
//! later checkpoints (e.g. [`json_quoted`], consumed by `var.rs`) are marked
//! with a module-level `#![allow(dead_code)]`.

#![allow(dead_code)]

use std::io::Write;
// Brings `write!(String, …)` into scope for the `\uXXXX` escape below.
use std::fmt::Write as _;

use curl_rs_lib::{version, CurlCode, Easy};

use crate::writeout::{emit_var, VARIABLES};

/// Upper bound on a single quoted JSON string — curl's `MAX_JSON_STRING`.
///
/// A quoted value whose escaped length exceeds this is dropped (nothing is
/// emitted for it), matching curl's `dynbuf`-overflow behaviour.
pub const MAX_JSON_STRING: usize = 100_000;

/// Escape `input` as the body of a JSON string **without** the surrounding
/// quotes — curl's `jsonquoted`.
///
/// The mandatory JSON escapes are applied (`\\`, `\"`, `\b`, `\f`, `\n`, `\r`,
/// `\t`, and `\u00xx` for other control bytes). When `lowercase` is set, ASCII
/// `A`–`Z` are folded to lowercase via `byte | 0x20` — deliberately *not*
/// `tolower`, so the result is locale-independent, exactly like curl.
///
/// Input is treated as raw bytes; bytes `>= 0x80` are copied through verbatim,
/// so a value that was valid UTF-8 stays valid UTF-8.
pub fn json_quoted(input: &[u8], lowercase: bool) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    for &c in input {
        match c {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'"' => out.extend_from_slice(b"\\\""),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            _ if c < 0x20 => {
                let mut esc = String::new();
                let _ = write!(&mut esc, "\\u{c:04x}");
                out.extend_from_slice(esc.as_bytes());
            }
            _ => {
                let mut o = c;
                if lowercase && o.is_ascii_uppercase() {
                    // Locale-free fold, matching curl's `o |= ('a' - 'A')`.
                    o |= 0x20;
                }
                out.push(o);
            }
        }
    }
    // Only ASCII bytes are ever transformed, so the buffer remains valid UTF-8.
    String::from_utf8(out).unwrap_or_default()
}

/// Write `input` as a fully-quoted JSON string — curl's `jsonWriteString`.
///
/// Emits `"…escaped…"`. If the escaped body would exceed [`MAX_JSON_STRING`],
/// nothing is written (curl's overflow behaviour). All I/O errors are ignored
/// so a `--write-out` failure never changes the exit code.
pub fn json_write_string(w: &mut dyn Write, input: &str, lowercase: bool) {
    let quoted = json_quoted(input.as_bytes(), lowercase);
    if quoted.len() <= MAX_JSON_STRING {
        let _ = w.write_all(b"\"");
        let _ = w.write_all(quoted.as_bytes());
        let _ = w.write_all(b"\"");
    }
}

/// Emit the full `--write-out` variable set as a JSON object — curl's
/// `ourWriteOutJSON`.
///
/// Every variable with a real emitter is rendered as `"name":value` and
/// followed by a comma; `NULL`-`writefunc` (special) variables are skipped.
/// The object is closed with the synthetic `"curl_version"` member, which is
/// not a real `--write-out` variable but is always emitted last, mirroring
/// curl.
pub fn our_writeout_json(w: &mut dyn Write, easy: &Easy, per_result: CurlCode) {
    let _ = w.write_all(b"{");

    for var in VARIABLES {
        if emit_var(w, var, easy, per_result, true) {
            let _ = w.write_all(b",");
        }
    }

    // The variables are alphabetical, but `curl_version` is appended last as a
    // special case (it is not a real `--write-out` variable).
    let _ = w.write_all(b"\"curl_version\":");
    json_write_string(w, version(), false);
    let _ = w.write_all(b"}");
}

/// Emit the response headers as a JSON object — curl's `headerJSON`.
///
/// curl groups repeated header names into JSON arrays via `curl_easy_header` /
/// `curl_easy_nextheader`. The core `curl-rs-lib` handle exposes no
/// header-retrieval API yet, so — like curl with no stored headers — this
/// emits the empty object `{\n}`. When a header API lands, the enumeration is
/// added here without touching callers.
pub fn header_json(w: &mut dyn Write, _easy: &Easy) {
    let _ = w.write_all(b"{");
    let _ = w.write_all(b"\n}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quoted_into_string(input: &str, lowercase: bool) -> String {
        let mut buf: Vec<u8> = Vec::new();
        json_write_string(&mut buf, input, lowercase);
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn quotes_mandatory_escapes() {
        assert_eq!(json_quoted(b"a\\b\"c", false), "a\\\\b\\\"c");
        assert_eq!(json_quoted(b"\n\r\t", false), "\\n\\r\\t");
        assert_eq!(json_quoted(&[0x08, 0x0c], false), "\\b\\f");
    }

    #[test]
    fn quotes_control_bytes_as_unicode_escapes() {
        // 0x01 -> \u0001 ; 0x1f -> \u001f
        assert_eq!(json_quoted(&[0x01, 0x1f], false), "\\u0001\\u001f");
    }

    #[test]
    fn lowercase_folds_only_ascii_upper() {
        assert_eq!(json_quoted(b"AbC-Z9", true), "abc-z9");
        // Non-ASCII bytes are preserved verbatim (UTF-8 'Ä' stays two bytes).
        assert_eq!(json_quoted("Ä".as_bytes(), true), "Ä");
    }

    #[test]
    fn write_string_wraps_in_quotes() {
        assert_eq!(quoted_into_string("hi", false), "\"hi\"");
        assert_eq!(quoted_into_string("", false), "\"\"");
    }

    #[test]
    fn header_json_is_empty_object() {
        let easy = Easy::default();
        let mut buf: Vec<u8> = Vec::new();
        header_json(&mut buf, &easy);
        assert_eq!(String::from_utf8(buf).unwrap(), "{\n}");
    }

    #[test]
    fn writeout_json_is_valid_and_terminated() {
        let easy = Easy::default();
        let mut buf: Vec<u8> = Vec::new();
        our_writeout_json(&mut buf, &easy, CurlCode::Ok);
        let text = String::from_utf8(buf).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        assert!(value["curl_version"].as_str().is_some());
        assert!(value["certs"].is_null());
    }
}
