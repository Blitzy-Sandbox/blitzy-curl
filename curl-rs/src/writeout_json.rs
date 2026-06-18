//! JSON rendering for the `curl` command-line tool's `--write-out` option.
//!
//! This module is the Rust reimplementation of `src/tool_writeout_json.c` from
//! curl 8.x. It produces the two JSON-valued `--write-out` variables:
//!
//! * `%{json}` — a single JSON object containing every `--write-out` variable
//!   (see [`write_out_json`], the port of `ourWriteOutJSON`), and
//! * `%{header_json}` — a JSON object mapping each received response-header name
//!   to the array of its values (see [`header_json`], the port of `headerJSON`).
//!
//! # Byte-for-byte parity
//!
//! curl hand-rolls its JSON serialization — it does **not** use a JSON library —
//! and the curl 8.x regression suite asserts the exact bytes produced. To
//! preserve that observable output (AAP §0.8.2) this module deliberately
//! performs its own byte-level escaping and key ordering rather than delegating
//! to `serde_json`. `serde_json` would diverge in several ways the test suite
//! would catch:
//!
//! * key ordering and the unconditional, special-cased trailing `"curl_version"`
//!   key (which is *not* a real `--write-out` variable);
//! * emitting the literal `null` for a variable whose value is unavailable;
//! * the `%{header_json}` array grouping and its `,\n` member separators; and,
//!   most importantly,
//! * raw byte fidelity. curl escapes over `unsigned char` and copies any byte
//!   `>= 128` verbatim, whereas a `String`/`serde_json` path would force lossy
//!   UTF-8 re-encoding. For this reason [`json_quoted`] both accepts and returns
//!   bytes (`&[u8]` → `Vec<u8>`) instead of `&str`/`String`.
//!
//! # Integration
//!
//! Per the migration plan, `crate::writeout` owns the `--write-out` variable
//! table (the analog of curl's `struct writeoutvar` array) and the per-variable
//! rendering functions; this module owns only the JSON envelope. The coupling is
//! expressed through two small traits — [`JsonVar`], implemented by
//! `writeout.rs`'s variable type, and [`HeaderSource`], implemented by the
//! per-transfer type over `curl_rs_lib`'s header API — so that the data
//! definitions live in exactly one place and there is no module dependency
//! cycle. This module depends on nothing beyond the standard library.

#![forbid(unsafe_code)]

use std::io::{self, Write};

/// Maximum length, in bytes, of a single JSON string value.
///
/// Mirrors `#define MAX_JSON_STRING 100000` in `src/tool_writeout_json.c`. curl
/// initializes the escaping dynamic buffer with this ceiling; if the escaped
/// content would reach it, the bounded buffer reports `CURLE_TOO_LARGE` and the
/// value is dropped entirely (not even the surrounding quotes are emitted). See
/// [`json_write_string`].
pub const MAX_JSON_STRING: usize = 100_000;

/// Lower-case ASCII hex digit for the nibble `n` (the low four bits of `n` are
/// used; callers pass a value in `0..=15`).
#[inline]
fn hex_lower_nibble(n: u8) -> u8 {
    match n & 0x0f {
        d @ 0..=9 => b'0' + d,
        d => b'a' + (d - 10),
    }
}

/// Escape `input` as the *inner* content of a JSON string — i.e. the bytes that
/// go between the surrounding quotes — without adding the quotes themselves.
///
/// This is the Rust port of `jsonquoted()` and reproduces curl's escape table
/// exactly:
///
/// | input byte         | output             |
/// |--------------------|--------------------|
/// | `\` (`0x5c`)       | `\\`               |
/// | `"` (`0x22`)       | `\"`               |
/// | `\b` (`0x08`)      | `\b`               |
/// | `\f` (`0x0c`)      | `\f`               |
/// | `\n` (`0x0a`)      | `\n`               |
/// | `\r` (`0x0d`)      | `\r`               |
/// | `\t` (`0x09`)      | `\t`               |
/// | any other `< 0x20` | `\u00xx` (lower)   |
/// | otherwise          | the byte verbatim  |
///
/// When `lowercase` is `true`, ASCII upper-case bytes (`A..=Z`) are folded to
/// lower case using `byte | 0x20` — exactly as curl does with `o |= ('a' - 'A')`
/// rather than `tolower()`. This keeps the fold locale-independent and, crucially,
/// leaves every byte `>= 128` untouched (the signed-`char` comparison in C never
/// matches them).
///
/// Returns a [`Vec<u8>`] rather than a `String` so that arbitrary, possibly
/// non-UTF-8, header values and info strings are reproduced byte-for-byte,
/// matching curl's `unsigned char` loop. The `MAX_JSON_STRING` ceiling is *not*
/// applied here (it is a property of the bounded output buffer in
/// [`json_write_string`]); this function only performs the escaping.
pub fn json_quoted(input: &[u8], lowercase: bool) -> Vec<u8> {
    // The common case copies most bytes 1:1, so pre-reserve the input length to
    // avoid repeated reallocation while still allowing growth for escapes.
    let mut out = Vec::with_capacity(input.len());
    for &byte in input {
        match byte {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'"' => out.extend_from_slice(b"\\\""),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            // Every other C0 control byte becomes a `\u00xx` escape with four
            // lower-case hex digits, matching curl's `curlx_dyn_addf("\\u%04x")`.
            // Such a byte is always `< 0x20`, so the two high hex digits are
            // always `00`.
            _ if byte < 0x20 => {
                out.extend_from_slice(b"\\u00");
                out.push(hex_lower_nibble(byte >> 4));
                out.push(hex_lower_nibble(byte));
            }
            // Printable and high bytes are copied verbatim, optionally folding
            // ASCII upper-case to lower-case. Bytes `>= 128` are never folded.
            _ => {
                let emitted = if lowercase && byte.is_ascii_uppercase() {
                    byte | 0x20
                } else {
                    byte
                };
                out.push(emitted);
            }
        }
    }
    out
}

/// Write `input` as a complete, quoted JSON string (`"…"`) to `out`.
///
/// Rust port of `jsonWriteString()`. The content is escaped with [`json_quoted`].
/// If the escaped form reaches [`MAX_JSON_STRING`] bytes the whole value is
/// dropped and nothing at all is written — not even the quotes — mirroring curl,
/// where the bounded dynamic buffer reports `CURLE_TOO_LARGE` and
/// `jsonWriteString` then skips its output. An empty `input` is written as `""`.
pub fn json_write_string<W: Write>(out: &mut W, input: &str, lowercase: bool) -> io::Result<()> {
    json_write_bytes(out, input.as_bytes(), lowercase)
}

/// Byte-oriented counterpart of [`json_write_string`].
///
/// Used internally for header names and values, which curl treats as opaque byte
/// strings rather than UTF-8 text. Applies the same [`MAX_JSON_STRING`] ceiling.
fn json_write_bytes<W: Write>(out: &mut W, input: &[u8], lowercase: bool) -> io::Result<()> {
    let escaped = json_quoted(input, lowercase);
    // Bounded exactly like curl's `curlx_dyn_init(&out, MAX_JSON_STRING)`: the
    // buffer can hold at most `MAX_JSON_STRING - 1` content bytes (it reserves a
    // byte for the trailing NUL), so an escaped value whose length reaches
    // `MAX_JSON_STRING` triggers `CURLE_TOO_LARGE` and is discarded silently.
    // Because the escaped length grows monotonically, comparing the final length
    // is equivalent to curl's per-chunk check.
    if escaped.len() < MAX_JSON_STRING {
        out.write_all(b"\"")?;
        // Mirrors curl's `if(curlx_dyn_len(&out))` guard; writing an empty slice
        // is a no-op, so the empty case still yields `""`.
        if !escaped.is_empty() {
            out.write_all(&escaped)?;
        }
        out.write_all(b"\"")?;
    }
    Ok(())
}

/// A single `--write-out` variable able to render itself as one member of the
/// `%{json}` object.
///
/// This is the integration seam between this module and `crate::writeout`, which
/// owns the concrete variable table (the Rust analog of curl's
/// `struct writeoutvar` array) and the per-variable rendering functions.
/// `writeout.rs` implements this trait for its variable type, delegating to the
/// JSON-mode branch of its `writeString` / `writeLong` / `writeOffset` /
/// `writeTime` equivalents.
///
/// The type parameters mirror the arguments curl threads through its `writefunc`
/// pointer:
///
/// * `P` — the per-transfer state (curl's `struct per_transfer`), and
/// * `C` — the transfer's result code (curl's `CURLcode`).
pub trait JsonVar<P, C> {
    /// Emit this variable as a `"name":value` (or `"name":null`) object member.
    ///
    /// Returns `Ok(true)` when a member was written and `Ok(false)` when the
    /// variable produces no JSON output at all. This matches curl, where every
    /// real `writefunc` returns `1` (and is therefore followed by a `,` in
    /// [`write_out_json`]) while the table rows whose `writefunc` is `NULL` —
    /// `json`, `header_json`, `onerror`, `stdout`, `stderr` — contribute nothing
    /// to the object.
    fn write_json_member(&self, out: &mut dyn Write, per: &P, per_result: C) -> io::Result<bool>;
}

/// Render the `%{json}` whole-object dump to `out`.
///
/// Rust port of `ourWriteOutJSON()`. The emitted object is, in order:
///
/// 1. an opening `{`;
/// 2. for every entry of `mappings`, in the table's existing (alphabetical)
///    order, the member produced by [`JsonVar::write_json_member`], each
///    followed by a `,` whenever a member was actually written;
/// 3. the special trailing `"curl_version"` key — which is *not* a real
///    `--write-out` variable — whose value is `curl_version` rendered with
///    [`json_write_string`]; and
/// 4. a closing `}`.
///
/// Because every real variable is followed by a comma, the object always ends in
/// the `…,"curl_version":"…"` tail with no dangling trailing comma — exactly the
/// bytes curl emits. `curl_version` is supplied by the caller (it is
/// `curl_rs_lib::version::version()` in the binary), which keeps this module free
/// of any dependency beyond the standard library.
pub fn write_out_json<W, P, C, V>(
    out: &mut W,
    mappings: &[V],
    per: &P,
    per_result: C,
    curl_version: &str,
) -> io::Result<()>
where
    W: Write,
    C: Copy,
    V: JsonVar<P, C>,
{
    out.write_all(b"{")?;
    for var in mappings {
        // Reborrow `out` as a trait object for the duration of the call so it
        // remains usable afterwards to write the separating comma.
        if var.write_json_member(&mut *out, per, per_result)? {
            out.write_all(b",")?;
        }
    }
    out.write_all(b"\"curl_version\":")?;
    json_write_string(out, curl_version, false)?;
    out.write_all(b"}")?;
    Ok(())
}

/// One response-header occurrence, as surfaced by [`HeaderSource`].
///
/// Mirrors the relevant fields of curl's `struct curl_header`. Both `name` and
/// `value` are raw byte slices because curl treats header text as opaque bytes;
/// header values are not required to be valid UTF-8.
#[derive(Clone, Copy, Debug)]
pub struct HeaderField<'a> {
    /// Header name as received. Its original case is preserved here; it is folded
    /// to lower case only on output.
    pub name: &'a [u8],
    /// Header value as received, emitted verbatim (never case-folded).
    pub value: &'a [u8],
}

/// Read access to a finished transfer's collected response headers.
///
/// This is the second integration seam (alongside [`JsonVar`]). It abstracts
/// curl's `curl_easy_nextheader`/`curl_easy_header` pair as used by `headerJSON`
/// (with `CURLH_HEADER` and `request == -1`): an implementor — the per-transfer
/// type in `crate::writeout`/`crate::operate` — walks `curl_rs_lib`'s header API
/// and returns each plain response header of the latest request.
pub trait HeaderSource {
    /// Every `CURLH_HEADER` response header of the latest request, in the order
    /// received. A header sent multiple times (for example `Set-Cookie`) appears
    /// once per occurrence; [`header_json`] is responsible for grouping them.
    fn response_headers(&self) -> Vec<HeaderField<'_>>;
}

/// Render the `%{header_json}` object to `out`.
///
/// Rust port of `headerJSON()`. Walking the headers in receive order, the first
/// occurrence of each (case-insensitively compared) header name emits
///
/// ```text
/// "<lower-cased name>":["value0","value1",…]
/// ```
///
/// gathering *all* values for that name — so a repeated header becomes a JSON
/// array under a single key — while later occurrences of an already-emitted name
/// are skipped. This reproduces curl, which acts only on the `index == 0` entry
/// of a multi-valued header and pulls the remaining values in via
/// `curl_easy_header`. Members are separated by `,\n`, and the whole object is
/// wrapped in `{` … `\n}` (so an empty header set renders as `{\n}`).
///
/// Header names are lower-cased with [`json_quoted`]'s `lowercase` mode (ASCII
/// `| 0x20`, matching curl's `curl_strequal`-based grouping and locale-free
/// fold); values are emitted verbatim.
pub fn header_json<W, P>(out: &mut W, per: &P) -> io::Result<()>
where
    W: Write,
    P: HeaderSource,
{
    let headers = per.response_headers();
    out.write_all(b"{")?;
    let mut first = true;
    for (idx, field) in headers.iter().enumerate() {
        // Act only on the first (case-insensitive) occurrence of each name — the
        // analog of curl acting on the `index == 0` entry. `curl_strequal` is
        // ASCII case-insensitive, so `eq_ignore_ascii_case` matches its grouping.
        let already_emitted = headers[..idx]
            .iter()
            .any(|earlier| earlier.name.eq_ignore_ascii_case(field.name));
        if already_emitted {
            continue;
        }

        if !first {
            out.write_all(b",\n")?;
        }
        first = false;

        json_write_bytes(out, field.name, true)?;
        out.write_all(b":[")?;
        let mut first_value = true;
        for occurrence in &headers {
            if occurrence.name.eq_ignore_ascii_case(field.name) {
                if !first_value {
                    out.write_all(b",")?;
                }
                first_value = false;
                json_write_bytes(out, occurrence.value, false)?;
            }
        }
        out.write_all(b"]")?;
    }
    out.write_all(b"\n}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- json_quoted (Phase A) ----

    #[test]
    fn json_quoted_escapes_named_specials() {
        assert_eq!(json_quoted(b"\\", false), b"\\\\");
        assert_eq!(json_quoted(b"\"", false), b"\\\"");
        assert_eq!(json_quoted(b"\x08", false), b"\\b");
        assert_eq!(json_quoted(b"\x0c", false), b"\\f");
        assert_eq!(json_quoted(b"\n", false), b"\\n");
        assert_eq!(json_quoted(b"\r", false), b"\\r");
        assert_eq!(json_quoted(b"\t", false), b"\\t");
    }

    #[test]
    fn json_quoted_escapes_other_control_chars_as_u00xx() {
        assert_eq!(json_quoted(b"\x00", false), b"\\u0000");
        assert_eq!(json_quoted(b"\x01", false), b"\\u0001");
        assert_eq!(json_quoted(b"\x07", false), b"\\u0007");
        // 0x0b (vertical tab) and 0x1f have no named escape.
        assert_eq!(json_quoted(b"\x0b", false), b"\\u000b");
        assert_eq!(json_quoted(b"\x1f", false), b"\\u001f");
        // 0x0e..0x1f exercise the high nibble = 1 path.
        assert_eq!(json_quoted(b"\x10", false), b"\\u0010");
    }

    #[test]
    fn json_quoted_lowercase_only_folds_ascii_upper() {
        assert_eq!(json_quoted(b"ABZ", true), b"abz");
        assert_eq!(json_quoted(b"ABZ", false), b"ABZ");
        // Digits, punctuation and already-lower bytes are untouched.
        assert_eq!(json_quoted(b"aZ9-_", true), b"az9-_");
    }

    #[test]
    fn json_quoted_passes_high_bytes_through_raw() {
        // Bytes >= 128 are copied verbatim, never UTF-8 re-encoded and never
        // case-folded even when `lowercase` is true.
        assert_eq!(json_quoted(&[0x80, 0xff], true), vec![0x80, 0xff]);
        // The two bytes of UTF-8 "ß" survive unchanged.
        assert_eq!(json_quoted(&[0xc3, 0x9f], false), vec![0xc3, 0x9f]);
    }

    #[test]
    fn json_quoted_mixed_sequence() {
        assert_eq!(
            json_quoted(b"a\"b\\c\n\x01", false),
            b"a\\\"b\\\\c\\n\\u0001".to_vec()
        );
    }

    // ---- json_write_string (Phase A) ----

    fn write_string(input: &str, lowercase: bool) -> Vec<u8> {
        let mut buf = Vec::new();
        json_write_string(&mut buf, input, lowercase).unwrap();
        buf
    }

    #[test]
    fn json_write_string_wraps_in_quotes() {
        assert_eq!(write_string("hi", false), b"\"hi\"");
        assert_eq!(write_string("", false), b"\"\"");
        assert_eq!(write_string("a\"b", false), b"\"a\\\"b\"");
        assert_eq!(write_string("AB", true), b"\"ab\"");
    }

    #[test]
    fn json_write_string_respects_max_json_string_cap() {
        // Escaped length < MAX_JSON_STRING → emitted with surrounding quotes.
        let just_under = "a".repeat(MAX_JSON_STRING - 1);
        let out = write_string(&just_under, false);
        assert_eq!(out.len(), (MAX_JSON_STRING - 1) + 2);
        assert_eq!(out.first(), Some(&b'"'));
        assert_eq!(out.last(), Some(&b'"'));

        // Escaped length == MAX_JSON_STRING → dropped entirely (no quotes).
        let at_cap = "a".repeat(MAX_JSON_STRING);
        assert!(write_string(&at_cap, false).is_empty());
    }

    // ---- write_out_json (Phase B) ----

    /// Mock `--write-out` variable: `Some(bytes)` emits `bytes` and reports a
    /// written member (a non-NULL `writefunc`); `None` writes nothing and reports
    /// no member (a NULL `writefunc` row such as `json`/`stdout`).
    struct MockVar {
        member: Option<&'static [u8]>,
    }

    impl JsonVar<(), i32> for MockVar {
        fn write_json_member(
            &self,
            out: &mut dyn Write,
            _per: &(),
            _per_result: i32,
        ) -> io::Result<bool> {
            match self.member {
                Some(bytes) => {
                    out.write_all(bytes)?;
                    Ok(true)
                }
                None => Ok(false),
            }
        }
    }

    fn run_write_out_json(vars: &[MockVar], version: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        write_out_json(&mut buf, vars, &(), 0, version).unwrap();
        buf
    }

    #[test]
    fn write_out_json_orders_members_and_appends_curl_version() {
        let vars = [
            MockVar {
                member: Some(b"\"a\":1"),
            },
            // NULL writefunc → skipped, contributes no comma.
            MockVar { member: None },
            MockVar {
                member: Some(b"\"b\":null"),
            },
        ];
        assert_eq!(
            run_write_out_json(&vars, "curl/8.x"),
            b"{\"a\":1,\"b\":null,\"curl_version\":\"curl/8.x\"}".to_vec()
        );
    }

    #[test]
    fn write_out_json_empty_table_is_just_curl_version() {
        assert_eq!(
            run_write_out_json(&[], "X"),
            b"{\"curl_version\":\"X\"}".to_vec()
        );
    }

    #[test]
    fn write_out_json_escapes_curl_version_value() {
        assert_eq!(
            run_write_out_json(&[], "a\"b"),
            b"{\"curl_version\":\"a\\\"b\"}".to_vec()
        );
    }

    // ---- header_json (Phase C) ----

    struct MockHeaders(Vec<(&'static [u8], &'static [u8])>);

    impl HeaderSource for MockHeaders {
        fn response_headers(&self) -> Vec<HeaderField<'_>> {
            self.0
                .iter()
                .map(|(name, value)| HeaderField { name, value })
                .collect()
        }
    }

    fn run_header_json(pairs: Vec<(&'static [u8], &'static [u8])>) -> Vec<u8> {
        let mut buf = Vec::new();
        header_json(&mut buf, &MockHeaders(pairs)).unwrap();
        buf
    }

    #[test]
    fn header_json_empty_is_open_close() {
        assert_eq!(run_header_json(vec![]), b"{\n}".to_vec());
    }

    #[test]
    fn header_json_single_value_is_one_element_array() {
        assert_eq!(
            run_header_json(vec![(b"Content-Type", b"text/html")]),
            b"{\"content-type\":[\"text/html\"]\n}".to_vec()
        );
    }

    #[test]
    fn header_json_multiple_distinct_headers() {
        assert_eq!(
            run_header_json(vec![(b"A", b"1"), (b"B", b"2")]),
            b"{\"a\":[\"1\"],\n\"b\":[\"2\"]\n}".to_vec()
        );
    }

    #[test]
    fn header_json_groups_repeated_header_case_insensitively() {
        assert_eq!(
            run_header_json(vec![(b"Set-Cookie", b"a=1"), (b"set-cookie", b"b=2")]),
            b"{\"set-cookie\":[\"a=1\",\"b=2\"]\n}".to_vec()
        );
    }

    #[test]
    fn header_json_groups_interleaved_in_first_occurrence_order() {
        assert_eq!(
            run_header_json(vec![(b"A", b"1"), (b"B", b"2"), (b"A", b"3")]),
            b"{\"a\":[\"1\",\"3\"],\n\"b\":[\"2\"]\n}".to_vec()
        );
    }

    #[test]
    fn header_json_escapes_values_but_lowercases_only_names() {
        assert_eq!(
            run_header_json(vec![(b"X-Quote", b"a\"b")]),
            b"{\"x-quote\":[\"a\\\"b\"]\n}".to_vec()
        );
    }

    #[test]
    fn header_json_value_high_bytes_pass_through() {
        let out = run_header_json(vec![(b"X", &[0x80, 0xff])]);
        let mut expected = Vec::new();
        expected.extend_from_slice(b"{\"x\":[\"");
        expected.extend_from_slice(&[0x80, 0xff]);
        expected.extend_from_slice(b"\"]\n}");
        assert_eq!(out, expected);
    }

    // ---- Oracle-mirroring tests ----
    //
    // These pin the envelope format to curl's own immutable regression fixtures
    // in `tests/data` (the parity oracle), reproducing the exact member shapes
    // and separators they assert.

    #[test]
    fn write_out_json_matches_oracle_object_shape() {
        // Mirrors the `%{json}` whole-object output asserted by tests/data/test970
        // and test972: alphabetically ordered members of mixed shape (empty
        // string, long, null, time) and the special trailing `curl_version` key,
        // with a comma after every real member and none after `curl_version`.
        let vars = [
            MockVar {
                member: Some(b"\"certs\":\"\""),
            },
            MockVar {
                member: Some(b"\"conn_id\":0"),
            },
            MockVar {
                member: Some(b"\"errormsg\":null"),
            },
            MockVar {
                member: Some(b"\"time_total\":0.000013"),
            },
        ];
        assert_eq!(
            run_write_out_json(&vars, "curl-unit-test-fake-version"),
            b"{\"certs\":\"\",\"conn_id\":0,\"errormsg\":null,\"time_total\":0.000013,\
              \"curl_version\":\"curl-unit-test-fake-version\"}"
                .to_vec()
        );
    }

    #[test]
    fn header_json_matches_oracle_header_shape() {
        // Mirrors the tricky parts of tests/data/test421's `%{header_json}`
        // output: a repeated header collapsed into one array (`vary`), a value
        // containing a double quote that must be escaped (`etag`), and an empty
        // value rendered as `[""]`, all separated by `,\n` and wrapped in
        // `{` … `\n}`.
        let out = run_header_json(vec![
            (b"Vary", b"Accept-Encoding"),
            (b"Vary", b"Accept-Encoding"),
            (b"Vary", b"Accept"),
            (b"ETag", b"W/\"abc\""),
            (b"Access-Control-Expose-Headers", b""),
        ]);
        let mut expected = Vec::new();
        expected
            .extend_from_slice(b"{\"vary\":[\"Accept-Encoding\",\"Accept-Encoding\",\"Accept\"]");
        expected.extend_from_slice(b",\n\"etag\":[\"W/\\\"abc\\\"\"]");
        expected.extend_from_slice(b",\n\"access-control-expose-headers\":[\"\"]");
        expected.extend_from_slice(b"\n}");
        assert_eq!(out, expected);
    }
}
