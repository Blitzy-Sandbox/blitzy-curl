// SPDX-License-Identifier: curl
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// Rust rewrite of curl's src/tool_writeout_json.c (--write-out '%{json}').

//! # `writeout_json` — the `%{json}` / `%{header_json}` emitters
//!
//! Faithful Rust rewrite of curl 8.19.0-DEV's `src/tool_writeout_json.c`
//! (163 lines). It renders the `--write-out` variable set as a single JSON
//! object (`%{json}`), the response headers as a JSON object
//! (`%{header_json}`), and provides the shared JSON string-escaping helpers.
//!
//! ## Byte-for-byte parity
//!
//! Output is required to be byte-compatible with curl 8.x, so nothing here is
//! delegated to `serde_json` for *serialization*: the emitters write the exact
//! byte sequence curl writes (curl's key ordering — the alpha-sorted
//! [`VARIABLES`] table with `curl_version` appended last — its `"name":[…]`
//! header grouping, and its escaping). `serde_json` is used only where the
//! sibling [`crate::writeout`] tests *parse* the emitted text to assert it is
//! well-formed. The standalone [`json_quoted`] escaper is deliberately kept
//! (not replaced by `serde`) because [`crate::writeout`]'s `:json`-style value
//! path needs the un-quoted, curl-exact escaping.
//!
//! ## Shared catalogue
//!
//! The variable catalogue itself lives in [`crate::writeout`]; this module
//! iterates [`crate::writeout::VARIABLES`] and invokes
//! [`crate::writeout::emit_var`] in JSON mode, exactly like curl's
//! `ourWriteOutJSON` walks `mappings[]` calling each `writefunc` with
//! `use_json = true`. [`json_quoted`] is re-used by `var.rs`'s `:json`
//! variable function.
//!
//! ## Writer type — `&mut dyn Write`
//!
//! The emitters take `&mut dyn Write` (a trait object) rather than a generic
//! `&mut impl Write`. This is required, not stylistic: [`crate::writeout`]'s
//! output sink hands out the current stream as `&mut dyn Write` (its
//! `Out::cur`), and the shared [`crate::writeout::emit_var`] entry point — which
//! [`our_writeout_json`] must call — also takes `&mut dyn Write`. A trait
//! object cannot be passed to a generic `impl Write` parameter (the implicit
//! `Sized` bound rejects `dyn Write`), so `&mut dyn Write` is the only signature
//! that composes with the surrounding, already-established machinery.
//!
//! ## Exit-code invariance & safety
//!
//! Per curl parity, a failure inside `--write-out` never changes the process
//! exit code: every `write` here deliberately ignores its `io::Result`. There
//! is no `unsafe` in this module.
//!
//! ## Note on visibility
//!
//! `curl-rs` is a binary crate, so `pub` items exposed for sibling modules
//! (e.g. [`json_quoted`], consumed by `var.rs`, and [`json_write_string`] /
//! [`our_writeout_json`] / [`header_json`], consumed by [`crate::writeout`])
//! have no *external* consumer and would otherwise trip `dead_code`. The
//! module-level `#![allow(dead_code)]` reflects that these items are the
//! deliberate, stable vocabulary of the JSON write-out engine.

#![allow(dead_code)]

use std::io::Write;

use curl_rs_lib::{version, CurlCode, Easy};

use crate::writeout::{emit_var, VARIABLES};

// ===========================================================================
// Constants
// ===========================================================================

/// Upper bound on a single quoted JSON string — curl's `MAX_JSON_STRING`.
///
/// curl escapes each string into a `dynbuf` initialised with this cap
/// (`curlx_dyn_init(&out, MAX_JSON_STRING)`). Because `curlx_dyn`'s overflow
/// check is `len + used + 1 > toobig` (the `+ 1` reserves the C `NUL`
/// terminator, see `lib/curlx/dynbuf.c`), the largest escaped body that fits is
/// `MAX_JSON_STRING - 1` bytes; a value whose escaped form reaches
/// `MAX_JSON_STRING` bytes overflows and curl drops the whole string (quotes
/// included). [`json_write_string`] reproduces that exact threshold.
pub const MAX_JSON_STRING: usize = 100_000;

// ===========================================================================
// json_quoted — curl's `jsonquoted`
// ===========================================================================

/// Escape `input` as the body of a JSON string **without** the surrounding
/// quotes — curl's `jsonquoted`.
///
/// The escaping matches curl byte-for-byte:
///
/// * `\` → `\\`, `"` → `\"`
/// * `0x08` → `\b`, `0x0c` → `\f`, `\n` → `\n`, `\r` → `\r`, `\t` → `\t`
/// * any other byte `< 0x20` → `\u00xx` (lowercase hex, four digits)
/// * every other byte is copied verbatim
///
/// When `lowercase` is set, ASCII `A`–`Z` are folded to lowercase via
/// `byte | 0x20` — deliberately **not** `char::to_lowercase`/`tolower`, so the
/// fold is locale-independent, exactly matching curl's `o |= ('a' - 'A')`.
///
/// Input is treated as raw bytes; bytes `>= 0x80` are copied through unchanged,
/// so a value that was valid UTF-8 stays valid UTF-8 (and is therefore
/// byte-identical to curl's output). Should the escaped bytes not be valid
/// UTF-8 (only possible for a caller passing non-UTF-8 `>= 0x80` bytes, which
/// the `String` return type cannot represent), they are decoded lossily rather
/// than dropped.
#[must_use]
pub fn json_quoted(input: &[u8], lowercase: bool) -> String {
    // Lowercase hex digits for the `\u00xx` control-byte escape.
    const HEX: &[u8; 16] = b"0123456789abcdef";

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
            // Remaining control bytes (0x00-0x07, 0x0b, 0x0e-0x1f): `\u00xx`.
            // `c < 0x20` guarantees the high byte is `00`, so the four hex
            // digits are always `00` followed by the two nibbles of `c`.
            _ if c < 0x20 => {
                out.extend_from_slice(b"\\u00");
                out.push(HEX[(c >> 4) as usize]);
                out.push(HEX[(c & 0x0f) as usize]);
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

    // Only ASCII bytes are ever synthesised (all escapes are ASCII); verbatim
    // `>= 0x80` bytes come straight from the input. The buffer is therefore
    // valid UTF-8 whenever the input was, taking the zero-copy path and staying
    // byte-identical to curl. The lossy branch is an unreachable-in-practice
    // safeguard for a non-UTF-8 caller (the `String` type cannot hold raw
    // bytes).
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

// ===========================================================================
// json_write_string — curl's `jsonWriteString`
// ===========================================================================

/// Write `input` as a fully-quoted JSON string — curl's `jsonWriteString`.
///
/// Emits `"` + [`json_quoted`] + `"`. If the escaped body would overflow
/// curl's `MAX_JSON_STRING`-capped `dynbuf` (i.e. reaches [`MAX_JSON_STRING`]
/// bytes), nothing at all is written — matching curl, which on `dynbuf`
/// overflow skips the entire string, quotes included. All I/O errors are
/// ignored so a `--write-out` failure never changes the exit code.
pub fn json_write_string(out: &mut dyn Write, input: &[u8], lowercase: bool) {
    let quoted = json_quoted(input, lowercase);
    // curl emits only when the body fits within the dynbuf cap; the largest
    // fitting body is `MAX_JSON_STRING - 1` bytes (see [`MAX_JSON_STRING`]).
    if quoted.len() < MAX_JSON_STRING {
        let _ = out.write_all(b"\"");
        let _ = out.write_all(quoted.as_bytes());
        let _ = out.write_all(b"\"");
    }
}

// ===========================================================================
// our_writeout_json — curl's `ourWriteOutJSON`
// ===========================================================================

/// Emit the full `--write-out` variable set as a JSON object — curl's
/// `ourWriteOutJSON`.
///
/// Walks the shared [`VARIABLES`] table in its curl-defined (alphabetical)
/// order, delegating each row to [`emit_var`] in JSON mode. A row with a real
/// emitter renders `"name":value` (or `"name":null` when the datum is absent)
/// and returns `true`, so a `,` is written after it; the special
/// (`NULL`-`writefunc`) rows — `json`, `header_json`, `onerror`, `stderr`,
/// `stdout` — render nothing and return `false`, exactly like curl's
/// `if(mappings[i].writefunc && …)` guard. The object is then closed with the
/// synthetic `"curl_version"` member, which is not a real `--write-out`
/// variable but is always emitted last, mirroring curl.
pub fn our_writeout_json(out: &mut dyn Write, easy: &Easy, per_result: CurlCode) {
    let _ = out.write_all(b"{");

    for var in VARIABLES {
        if emit_var(out, var, easy, per_result, true) {
            let _ = out.write_all(b",");
        }
    }

    // The variables are alphabetical, but `curl_version` is appended last as a
    // special case (it is not a real `--write-out` variable). It carries no
    // trailing comma, so the object stays well-formed.
    let _ = out.write_all(b"\"curl_version\":");
    json_write_string(out, version().as_bytes(), false);
    let _ = out.write_all(b"}");
}

// ===========================================================================
// header_json — curl's `headerJSON`
// ===========================================================================

/// One response-header group: a header name and its value(s) in arrival order.
///
/// This mirrors the shape curl exposes through `curl_easy_nextheader` (one
/// entry per distinct header name) combined with `curl_easy_header` (the
/// `amount` values stored under that name): a single-occurrence header has one
/// value, a repeated header (e.g. `Set-Cookie`) has several.
struct HeaderField {
    /// The header name as received. [`write_headers_object`] lowercases it on
    /// emit, matching curl's `jsonWriteString(name, TRUE)`.
    name: String,
    /// The header's value(s), in the order curl would enumerate them.
    values: Vec<String>,
}

/// Collect the response headers of `easy`, grouped by name in arrival order —
/// the Rust seam for the `curl_easy_nextheader` / `curl_easy_header`
/// enumeration that curl's `headerJSON` walks.
///
/// The core `curl-rs-lib` easy handle does not (yet) expose a response-header
/// store, so this yields an empty list — which makes [`header_json`] emit the
/// empty object `{\n}`, the faithful result for a handle with no stored headers
/// (exactly what curl's `headerJSON` produces when `curl_easy_nextheader`
/// returns `NULL` on the first call). This mirrors the identical seam in the
/// sibling [`crate::writeout`] module (`easy_header`). When a header-retrieval
/// API lands on [`Easy`], only this function changes; the grouping and byte
/// layout in [`write_headers_object`] stay exactly as curl defines them.
fn collect_headers(_easy: &Easy) -> Vec<HeaderField> {
    Vec::new()
}

/// Emit `headers` as curl's `headerJSON` object.
///
/// Layout, byte-for-byte with curl: an opening `{`; then one member per header
/// formatted as `"name":[…]` — the name lowercased, each value a JSON string —
/// with members separated by `,\n`; then a closing `\n}`. Every header, even a
/// single-occurrence one, is rendered as a JSON *array* of its value(s), and a
/// repeated header name is grouped into one array (curl pulls all `amount`
/// values in via `curl_easy_header`). With no headers the output is `{\n}`.
fn write_headers_object(out: &mut dyn Write, headers: &[HeaderField]) {
    let _ = out.write_all(b"{");

    let mut first = true;
    for field in headers {
        // curl only ever enumerates names carrying at least one value, so it
        // never emits an empty `[]`; skip such a (degenerate) group to keep the
        // output a shape curl's `headerJSON` can actually produce.
        if field.values.is_empty() {
            continue;
        }
        // curl writes ",\n" before every member except the first (its `prev`
        // pointer starts NULL).
        if !first {
            let _ = out.write_all(b",\n");
        }
        // Name is lowercased (curl passes TRUE); values are not (FALSE).
        json_write_string(out, field.name.as_bytes(), true);
        let _ = out.write_all(b":[");
        for (i, value) in field.values.iter().enumerate() {
            if i > 0 {
                let _ = out.write_all(b",");
            }
            json_write_string(out, value.as_bytes(), false);
        }
        let _ = out.write_all(b"]");
        first = false;
    }

    let _ = out.write_all(b"\n}");
}

/// Emit the response headers as a JSON object — curl's `headerJSON`.
///
/// Repeated header names are grouped into a single JSON array; a
/// single-occurrence header is still emitted as a one-element array, matching
/// curl exactly. See [`collect_headers`] for the header-source seam and
/// [`write_headers_object`] for the byte layout.
pub fn header_json(out: &mut dyn Write, easy: &Easy) {
    write_headers_object(out, &collect_headers(easy));
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Run [`json_write_string`] into an owned `String` for assertions.
    fn write_string(input: &[u8], lowercase: bool) -> String {
        let mut buf: Vec<u8> = Vec::new();
        json_write_string(&mut buf, input, lowercase);
        String::from_utf8(buf).expect("json_write_string emits valid UTF-8")
    }

    /// Run [`write_headers_object`] into an owned `String` for assertions.
    fn headers_object(headers: &[HeaderField]) -> String {
        let mut buf: Vec<u8> = Vec::new();
        write_headers_object(&mut buf, headers);
        String::from_utf8(buf).expect("write_headers_object emits valid UTF-8")
    }

    fn field(name: &str, values: &[&str]) -> HeaderField {
        HeaderField {
            name: name.to_string(),
            values: values.iter().map(|v| (*v).to_string()).collect(),
        }
    }

    #[test]
    fn json_quoted_mandatory_escapes() {
        // Backslash doubles, quote is escaped.
        assert_eq!(json_quoted(b"a\\b\"c", false), "a\\\\b\\\"c");
        // The named single-character escapes.
        assert_eq!(json_quoted(b"\n\r\t", false), "\\n\\r\\t");
        assert_eq!(json_quoted(&[0x08, 0x0c], false), "\\b\\f");
    }

    #[test]
    fn json_quoted_control_bytes_become_lowercase_u_escapes() {
        // Control bytes lacking a dedicated escape → `\u00xx` (lowercase hex).
        assert_eq!(json_quoted(&[0x00], false), "\\u0000");
        assert_eq!(json_quoted(&[0x01], false), "\\u0001");
        assert_eq!(json_quoted(&[0x07], false), "\\u0007");
        assert_eq!(json_quoted(&[0x0b], false), "\\u000b"); // vertical tab
        assert_eq!(json_quoted(&[0x0e], false), "\\u000e");
        assert_eq!(json_quoted(&[0x1f], false), "\\u001f");
        // The dedicated escapes take precedence over the `\u` path.
        assert_eq!(json_quoted(&[0x09], false), "\\t");
        assert_eq!(json_quoted(&[0x0a], false), "\\n");
        assert_eq!(json_quoted(&[0x0c], false), "\\f");
        assert_eq!(json_quoted(&[0x0d], false), "\\r");
    }

    #[test]
    fn json_quoted_lowercase_is_ascii_only_and_locale_free() {
        assert_eq!(json_quoted(b"AbC-Z9", true), "abc-z9");
        // Without the flag, case is preserved.
        assert_eq!(json_quoted(b"AbC-Z9", false), "AbC-Z9");
        // Non A-Z bytes are untouched even with the flag set.
        assert_eq!(json_quoted(b"123 _.~", true), "123 _.~");
        // Non-ASCII (UTF-8 'Ä' = 0xC3 0x84) is copied verbatim, never folded.
        assert_eq!(json_quoted("Ä".as_bytes(), true), "Ä");
    }

    #[test]
    fn json_quoted_high_bytes_pass_through_verbatim() {
        // A valid multi-byte UTF-8 string survives intact and byte-identical.
        assert_eq!(json_quoted("héllo→".as_bytes(), false), "héllo→");
    }

    #[test]
    fn json_write_string_wraps_in_quotes() {
        assert_eq!(write_string(b"hi", false), "\"hi\"");
        assert_eq!(write_string(b"", false), "\"\"");
        // Escaping still happens inside the quotes.
        assert_eq!(write_string(b"a\"b", false), "\"a\\\"b\"");
        // The lowercase flag threads through to the body.
        assert_eq!(write_string(b"ABC", true), "\"abc\"");
    }

    #[test]
    fn json_write_string_respects_max_json_string_cap() {
        // A body of exactly MAX_JSON_STRING-1 bytes (no escaping) fits and is
        // emitted with its two surrounding quotes.
        let ok = vec![b'a'; MAX_JSON_STRING - 1];
        let out = write_string(&ok, false);
        assert_eq!(out.len(), (MAX_JSON_STRING - 1) + 2);
        assert!(out.starts_with('"') && out.ends_with('"'));

        // A body of MAX_JSON_STRING bytes overflows curl's dynbuf: the whole
        // string (quotes included) is dropped.
        let too_big = vec![b'a'; MAX_JSON_STRING];
        let mut buf: Vec<u8> = Vec::new();
        json_write_string(&mut buf, &too_big, false);
        assert!(buf.is_empty());
    }

    #[test]
    fn header_json_is_empty_object_without_headers() {
        // The core handle exposes no response headers, so — exactly like curl's
        // headerJSON with no stored headers — the object is empty.
        let easy = Easy::default();
        let mut buf: Vec<u8> = Vec::new();
        header_json(&mut buf, &easy);
        assert_eq!(String::from_utf8(buf).unwrap(), "{\n}");
    }

    #[test]
    fn write_headers_object_empty_is_empty_object() {
        assert_eq!(headers_object(&[]), "{\n}");
    }

    #[test]
    fn write_headers_object_single_header_is_one_element_array() {
        // Even a single occurrence is emitted as an array; the name is lowered.
        assert_eq!(
            headers_object(&[field("X-Test", &["value"])]),
            "{\"x-test\":[\"value\"]\n}"
        );
    }

    #[test]
    fn write_headers_object_groups_repeated_names_and_separates_members() {
        // Repeated names collapse into one array; members are separated by
        // ",\n"; names are lowercased, values are not; byte-for-byte with curl.
        let out = headers_object(&[
            field("Content-Type", &["text/html"]),
            field("Set-Cookie", &["a=1", "b=2"]),
        ]);
        assert_eq!(
            out,
            "{\"content-type\":[\"text/html\"],\n\"set-cookie\":[\"a=1\",\"b=2\"]\n}"
        );
    }

    #[test]
    fn write_headers_object_escapes_names_and_values() {
        // Both the (lowercased) name and the value pass through json_quoted.
        let out = headers_object(&[field("X-Quote", &["a\"b\\c"])]);
        assert_eq!(out, "{\"x-quote\":[\"a\\\"b\\\\c\"]\n}");
    }

    #[test]
    fn our_writeout_json_is_valid_and_terminated() {
        let easy = Easy::default();
        let mut buf: Vec<u8> = Vec::new();
        our_writeout_json(&mut buf, &easy, CurlCode::Ok);
        let text = String::from_utf8(buf).unwrap();

        // Structural: a single JSON object.
        assert!(text.starts_with('{') && text.ends_with('}'));
        let value: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");

        // `curl_version` is always present and emitted last as a string.
        let v = value["curl_version"].as_str().expect("curl_version string");
        assert!(v.starts_with("curl-rs/"));

        // The first table row ("certs") has no value on a fresh handle → null.
        assert!(value["certs"].is_null());

        // Special (NULL-writefunc) rows are omitted from the object entirely.
        assert!(value.get("json").is_none());
        assert!(value.get("header_json").is_none());
        assert!(value.get("onerror").is_none());
        assert!(value.get("stdout").is_none());
        assert!(value.get("stderr").is_none());
    }

    #[test]
    fn our_writeout_json_reflects_getinfo_values() {
        // A value sourced from the easy handle appears with the right JSON type
        // (a number, not a quoted string) under the expected key(s).
        let mut easy = Easy::default();
        easy.info.httpcode = 200;
        let mut buf: Vec<u8> = Vec::new();
        our_writeout_json(&mut buf, &easy, CurlCode::Ok);
        let text = String::from_utf8(buf).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        assert_eq!(value["http_code"], 200);
        assert_eq!(value["response_code"], 200);
    }
}
