// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-License-Identifier: curl
//
// Rust rewrite of src/tool_writeout_json.c and src/tool_writeout_json.h.
//
// Implements JSON-formatted output for `--write-out` with `%{json}` and
// `%header{json}` directives.  Every function matches curl 8.x output
// byte-for-byte where deterministic.
//
// Design notes:
//   * `json_quoted` performs per-character escaping matching the C
//     `jsonquoted()` function, with an optional lowercase pass.
//   * `json_write_string` wraps `json_quoted` with JSON key/value
//     formatting, emitting `null` for missing values.
//   * `write_json_long` / `write_json_offset` emit unquoted numeric
//     values.
//   * `write_json_time` converts microsecond timing values to seconds
//     with exactly 6 decimal places.
//   * `header_json` iterates response headers via `Headers::next()`
//     with `CURLH_HEADER` origin mask, grouping multi-value headers
//     into JSON arrays — matching curl 8.x `headerJSON()`.
//   * `our_write_out_json` queries every write-out variable from
//     `EasyHandle::get_info()` and emits the complete JSON object.
//   * Zero `unsafe` blocks — AAP Section 0.7.1.

use std::io::Write;

use anyhow::{Context, Result};

use curl_rs_lib::getinfo::{CurlInfo, InfoValue};
use curl_rs_lib::headers::{Header, Headers, CURLH_HEADER};
use curl_rs_lib::{EasyHandle, version};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum length (in characters) that `json_quoted` will produce.
/// Matches the C `MAX_JSON_STRING` constant (100 000).
pub const MAX_JSON_STRING: usize = 100_000;

// ---------------------------------------------------------------------------
// JSON string escaping
// ---------------------------------------------------------------------------

/// Escape a string for safe embedding inside a JSON value.
///
/// The returned string does **not** include surrounding double-quote
/// characters — the caller is responsible for adding those when needed.
///
/// When `lowercase` is `true` the entire output is converted to ASCII
/// lowercase, matching the C `jsonquoted(…, TRUE)` behaviour used for
/// header names.
///
/// The output is capped at [`MAX_JSON_STRING`] characters.  Any input
/// that would produce a longer escaped representation is silently
/// truncated.
pub fn json_quoted(input: &str, lowercase: bool) -> String {
    // Use serde_json::to_string to get a fully-escaped JSON string,
    // then strip the surrounding quotes that serde_json adds.
    // This handles all control characters, unicode escapes, backslash,
    // double-quote, etc. correctly.
    let escaped = match serde_json::to_string(input) {
        Ok(s) => {
            // serde_json::to_string wraps the string in double quotes.
            // Strip them to get the inner escaped content.
            if s.len() >= 2 {
                s[1..s.len() - 1].to_string()
            } else {
                String::new()
            }
        }
        Err(_) => {
            // Fallback: manual character-by-character escaping
            manual_json_escape(input)
        }
    };

    // Apply optional lowercase
    let result = if lowercase {
        escaped.to_ascii_lowercase()
    } else {
        escaped
    };

    // Cap at MAX_JSON_STRING
    if result.len() > MAX_JSON_STRING {
        // Truncate at a safe boundary — we must not break a multi-byte
        // escape sequence, so we find a character boundary.
        let mut end = MAX_JSON_STRING;
        while end > 0 && !result.is_char_boundary(end) {
            end -= 1;
        }
        result[..end].to_string()
    } else {
        result
    }
}

/// Manual per-character JSON escaping, used as a fallback.
/// Matches the C `jsonquoted()` byte-level logic exactly.
fn manual_json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 2);
    for ch in input.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\u{0008}' => out.push_str("\\b"),  // backspace
            '\u{000C}' => out.push_str("\\f"),  // form feed
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                // Control characters → \u00XX
                let code = c as u32;
                out.push_str(&format!("\\u{:04x}", code));
            }
            c => out.push(c),
        }
        if out.len() >= MAX_JSON_STRING {
            break;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// JSON value formatters
// ---------------------------------------------------------------------------

/// Write a JSON string field: `"key":"escaped_value"` or `"key":null`.
///
/// When `value` is `None`, the JSON `null` literal is emitted (no quotes).
/// When `value` is `Some`, the string is JSON-escaped via [`json_quoted`]
/// and wrapped in double quotes.
pub fn json_write_string<W: Write>(
    key: &str,
    value: Option<&str>,
    stream: &mut W,
) -> Result<()> {
    match value {
        Some(v) => {
            let escaped = json_quoted(v, false);
            write!(stream, "\"{}\":\"{}\"", key, escaped)
                .with_context(|| format!("failed to write JSON string field '{}'", key))?;
        }
        None => {
            write!(stream, "\"{}\":null", key)
                .with_context(|| format!("failed to write JSON null field '{}'", key))?;
        }
    }
    Ok(())
}

/// Write a JSON long integer field: `"key":value`.
///
/// The value is emitted as an unquoted JSON number.
pub fn write_json_long<W: Write>(
    key: &str,
    value: i64,
    stream: &mut W,
) -> Result<()> {
    write!(stream, "\"{}\":{}", key, value)
        .with_context(|| format!("failed to write JSON long field '{}'", key))?;
    Ok(())
}

/// Write a JSON offset (i64) field: `"key":value`.
///
/// Functionally identical to [`write_json_long`] but semantically used for
/// `curl_off_t` equivalent values (sizes, speeds, transfer IDs).
pub fn write_json_offset<W: Write>(
    key: &str,
    value: i64,
    stream: &mut W,
) -> Result<()> {
    write!(stream, "\"{}\":{}", key, value)
        .with_context(|| format!("failed to write JSON offset field '{}'", key))?;
    Ok(())
}

/// Write a JSON timing field: `"key":X.YYYYYY`.
///
/// `value_us` is a timing value in **microseconds**.  It is converted to
/// seconds with exactly 6 decimal places, matching curl 8.x behaviour.
///
/// Example: `write_json_time("time_total", 1_234_567, &mut buf)` →
/// `"time_total":1.234567`
pub fn write_json_time<W: Write>(
    key: &str,
    value_us: i64,
    stream: &mut W,
) -> Result<()> {
    let seconds = value_us / 1_000_000;
    let micros = (value_us % 1_000_000).unsigned_abs();
    write!(stream, "\"{}\":{}.{:06}", key, seconds, micros)
        .with_context(|| format!("failed to write JSON time field '{}'", key))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Header JSON output
// ---------------------------------------------------------------------------

/// Emit response headers as a JSON object to `stream`.
///
/// The output format matches curl 8.x `headerJSON()`:
///
/// ```json
/// {"headers":{"name":["value1","value2"],"other":["single"]}}
/// ```
///
/// Multi-value headers (same name appearing multiple times) are grouped
/// into a JSON array.  All header names are lowercased in the JSON keys,
/// and values are JSON-escaped.
///
/// `headers` is the `Headers` collection from an `EasyHandle`.  We
/// iterate using `Headers::next()` with `CURLH_HEADER` origin and
/// request `-1` (latest request), matching the C loop that calls
/// `curl_easy_nextheader`.
pub fn header_json<W: Write>(
    headers: &Headers,
    stream: &mut W,
) -> Result<()> {
    // Collect all headers into a Vec of (name, value) pairs, preserving
    // insertion order and allowing duplicate names.
    let mut header_pairs: Vec<(String, String)> = Vec::new();
    let mut prev: Option<Header> = None;

    loop {
        let next = headers.next(CURLH_HEADER, -1, prev.as_ref());
        match next {
            Some(h) => {
                let name = json_quoted(h.name(), true); // lowercase name
                let value = json_quoted(h.value(), false);
                header_pairs.push((name, value));
                prev = Some(h);
            }
            None => break,
        }
    }

    // Build the JSON object.  Group by header name — each name maps to a
    // JSON array of values, preserving order of first appearance.
    write!(stream, "{{\"headers\":{{")
        .context("failed to write header JSON opening")?;

    // Use a Vec to preserve insertion order of unique header names.
    let mut seen_names: Vec<String> = Vec::new();
    let mut grouped: Vec<Vec<String>> = Vec::new();

    for (name, value) in &header_pairs {
        if let Some(pos) = seen_names.iter().position(|n| n == name) {
            grouped[pos].push(value.clone());
        } else {
            seen_names.push(name.clone());
            grouped.push(vec![value.clone()]);
        }
    }

    for (i, (name, values)) in seen_names.iter().zip(grouped.iter()).enumerate() {
        if i > 0 {
            write!(stream, ",").context("failed to write header JSON separator")?;
        }
        write!(stream, "\"{}\":[", name)
            .context("failed to write header JSON key")?;
        for (j, val) in values.iter().enumerate() {
            if j > 0 {
                write!(stream, ",").context("failed to write header value separator")?;
            }
            write!(stream, "\"{}\"", val)
                .context("failed to write header JSON value")?;
        }
        write!(stream, "]").context("failed to write header JSON array close")?;
    }

    write!(stream, "}}}}")
        .context("failed to write header JSON closing")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Full JSON write-out
// ---------------------------------------------------------------------------

/// Helper: query a string-typed info value from the easy handle.
fn get_info_string(easy: &EasyHandle, info: CurlInfo) -> Option<String> {
    match easy.get_info(info) {
        Ok(InfoValue::String(opt)) => opt,
        _ => None,
    }
}

/// Helper: query a long-typed info value from the easy handle.
fn get_info_long(easy: &EasyHandle, info: CurlInfo) -> i64 {
    match easy.get_info(info) {
        Ok(InfoValue::Long(v)) => v,
        _ => 0,
    }
}

/// Helper: query an offset-typed info value from the easy handle.
fn get_info_off_t(easy: &EasyHandle, info: CurlInfo) -> i64 {
    match easy.get_info(info) {
        Ok(InfoValue::OffT(v)) => v,
        _ => 0,
    }
}

/// Emit the complete JSON write-out object for a transfer.
///
/// This function queries every write-out variable from the `EasyHandle`
/// and emits the full `%{json}` output matching curl 8.x.
///
/// The output format is a single JSON object with all timing, size, URL,
/// and HTTP-code fields.  The last field is always `"curl_version"`.
///
/// `headers` is an optional reference to the response headers for the
/// transfer.  When provided, cert info and similar header-derived data
/// can be included.
pub fn our_write_out_json<W: Write>(
    easy: &EasyHandle,
    headers: Option<&Headers>,
    stream: &mut W,
) -> Result<()> {
    write!(stream, "{{").context("failed to write JSON opening brace")?;

    // -- String fields --
    json_write_string(
        "url_effective",
        get_info_string(easy, CurlInfo::EffectiveUrl).as_deref(),
        stream,
    )?;
    write!(stream, ",")?;

    json_write_string(
        "method",
        get_info_string(easy, CurlInfo::EffectiveMethod).as_deref(),
        stream,
    )?;
    write!(stream, ",")?;

    // http_code / response_code
    write_json_long("http_code", get_info_long(easy, CurlInfo::ResponseCode), stream)?;
    write!(stream, ",")?;

    write_json_long("http_version", get_info_long(easy, CurlInfo::HttpVersion), stream)?;
    write!(stream, ",")?;

    json_write_string(
        "scheme",
        get_info_string(easy, CurlInfo::Scheme).as_deref(),
        stream,
    )?;
    write!(stream, ",")?;

    json_write_string(
        "content_type",
        get_info_string(easy, CurlInfo::ContentType).as_deref(),
        stream,
    )?;
    write!(stream, ",")?;

    json_write_string(
        "redirect_url",
        get_info_string(easy, CurlInfo::RedirectUrl).as_deref(),
        stream,
    )?;
    write!(stream, ",")?;

    json_write_string(
        "referer",
        get_info_string(easy, CurlInfo::Referer).as_deref(),
        stream,
    )?;
    write!(stream, ",")?;

    json_write_string(
        "ftp_entry_path",
        get_info_string(easy, CurlInfo::FtpEntryPath).as_deref(),
        stream,
    )?;
    write!(stream, ",")?;

    json_write_string(
        "ip",
        get_info_string(easy, CurlInfo::PrimaryIp).as_deref(),
        stream,
    )?;
    write!(stream, ",")?;

    json_write_string(
        "local_ip",
        get_info_string(easy, CurlInfo::LocalIp).as_deref(),
        stream,
    )?;
    write!(stream, ",")?;

    // -- Long / offset integer fields --
    write_json_long("local_port", get_info_long(easy, CurlInfo::LocalPort), stream)?;
    write!(stream, ",")?;

    write_json_long("remote_port", get_info_long(easy, CurlInfo::PrimaryPort), stream)?;
    write!(stream, ",")?;

    write_json_long("num_connects", get_info_long(easy, CurlInfo::NumConnects), stream)?;
    write!(stream, ",")?;

    write_json_long("num_redirects", get_info_long(easy, CurlInfo::RedirectCount), stream)?;
    write!(stream, ",")?;

    write_json_long("ssl_verify_result", get_info_long(easy, CurlInfo::SslVerifyResult), stream)?;
    write!(stream, ",")?;

    write_json_long("proxy_ssl_verify_result", get_info_long(easy, CurlInfo::ProxySslVerifyResult), stream)?;
    write!(stream, ",")?;

    write_json_long("header_size", get_info_long(easy, CurlInfo::HeaderSize), stream)?;
    write!(stream, ",")?;

    write_json_long("request_size", get_info_long(easy, CurlInfo::RequestSize), stream)?;
    write!(stream, ",")?;

    // -- Size / speed / ID offset fields --
    write_json_offset("size_download", get_info_off_t(easy, CurlInfo::SizeDownloadT), stream)?;
    write!(stream, ",")?;

    write_json_offset("size_upload", get_info_off_t(easy, CurlInfo::SizeUploadT), stream)?;
    write!(stream, ",")?;

    write_json_offset("speed_download", get_info_off_t(easy, CurlInfo::SpeedDownloadT), stream)?;
    write!(stream, ",")?;

    write_json_offset("speed_upload", get_info_off_t(easy, CurlInfo::SpeedUploadT), stream)?;
    write!(stream, ",")?;

    write_json_offset("xfer_id", get_info_off_t(easy, CurlInfo::XferId), stream)?;
    write!(stream, ",")?;

    write_json_offset("conn_id", get_info_off_t(easy, CurlInfo::ConnId), stream)?;
    write!(stream, ",")?;

    write_json_offset("earlydata_sent", get_info_off_t(easy, CurlInfo::EarlydataSentT), stream)?;
    write!(stream, ",")?;

    // -- Boolean-as-long fields --
    write_json_long("used_proxy", get_info_long(easy, CurlInfo::UsedProxy), stream)?;
    write!(stream, ",")?;

    // -- Timing fields (microseconds → seconds with 6 decimal places) --
    write_json_time("time_total", get_info_off_t(easy, CurlInfo::TotalTimeT), stream)?;
    write!(stream, ",")?;

    write_json_time("time_namelookup", get_info_off_t(easy, CurlInfo::NamelookupTimeT), stream)?;
    write!(stream, ",")?;

    write_json_time("time_connect", get_info_off_t(easy, CurlInfo::ConnectTimeT), stream)?;
    write!(stream, ",")?;

    write_json_time("time_appconnect", get_info_off_t(easy, CurlInfo::AppconnectTimeT), stream)?;
    write!(stream, ",")?;

    write_json_time("time_pretransfer", get_info_off_t(easy, CurlInfo::PretransferTimeT), stream)?;
    write!(stream, ",")?;

    write_json_time("time_starttransfer", get_info_off_t(easy, CurlInfo::StarttransferTimeT), stream)?;
    write!(stream, ",")?;

    write_json_time("time_redirect", get_info_off_t(easy, CurlInfo::RedirectTimeT), stream)?;
    write!(stream, ",")?;

    write_json_time("time_posttransfer", get_info_off_t(easy, CurlInfo::PosttransferTimeT), stream)?;
    write!(stream, ",")?;

    write_json_time("time_queue", get_info_off_t(easy, CurlInfo::QueueTimeT), stream)?;
    write!(stream, ",")?;

    // -- Certificate info (SList) --
    // CertInfo returns an SList; emit as a JSON array of strings.
    {
        write!(stream, "\"certs\":").context("failed to write certs key")?;
        match easy.get_info(CurlInfo::CertInfo) {
            Ok(InfoValue::SList(slist)) => {
                write!(stream, "[").context("failed to write certs array open")?;
                let items: Vec<String> = slist.into_iter().collect();
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(stream, ",").context("failed to write cert separator")?;
                    }
                    let escaped = json_quoted(item, false);
                    write!(stream, "\"{}\"", escaped)
                        .context("failed to write cert entry")?;
                }
                write!(stream, "]").context("failed to write certs array close")?;
            }
            _ => {
                write!(stream, "[]").context("failed to write empty certs array")?;
            }
        }
    }
    write!(stream, ",")?;

    // -- Headers (if available) --
    if let Some(hdrs) = headers {
        write!(stream, "\"headers\":").context("failed to write headers key")?;
        // Inline the header iteration, producing a JSON object
        // mapping lowercased header names to arrays of values.
        write!(stream, "{{").context("failed to write headers object open")?;

        let mut header_pairs: Vec<(String, String)> = Vec::new();
        let mut prev: Option<Header> = None;
        loop {
            let next = hdrs.next(CURLH_HEADER, -1, prev.as_ref());
            match next {
                Some(h) => {
                    let name = json_quoted(h.name(), true);
                    let value = json_quoted(h.value(), false);
                    header_pairs.push((name, value));
                    prev = Some(h);
                }
                None => break,
            }
        }

        let mut seen_names: Vec<String> = Vec::new();
        let mut grouped: Vec<Vec<String>> = Vec::new();
        for (name, value) in &header_pairs {
            if let Some(pos) = seen_names.iter().position(|n| n == name) {
                grouped[pos].push(value.clone());
            } else {
                seen_names.push(name.clone());
                grouped.push(vec![value.clone()]);
            }
        }
        for (i, (name, values)) in seen_names.iter().zip(grouped.iter()).enumerate() {
            if i > 0 {
                write!(stream, ",").context("failed to write hdr separator")?;
            }
            write!(stream, "\"{}\":[", name).context("failed to write hdr key")?;
            for (j, val) in values.iter().enumerate() {
                if j > 0 {
                    write!(stream, ",").context("failed to write hdr val sep")?;
                }
                write!(stream, "\"{}\"", val).context("failed to write hdr val")?;
            }
            write!(stream, "]").context("failed to write hdr array close")?;
        }

        write!(stream, "}}").context("failed to write headers object close")?;
        write!(stream, ",")?;
    }

    // -- Last field: curl_version (no trailing comma) --
    json_write_string("curl_version", Some(version()), stream)?;

    write!(stream, "}}").context("failed to write JSON closing brace")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_quoted_simple() {
        assert_eq!(json_quoted("hello", false), "hello");
        assert_eq!(json_quoted("hello", true), "hello");
    }

    #[test]
    fn test_json_quoted_escaping() {
        assert_eq!(json_quoted("a\"b", false), "a\\\"b");
        assert_eq!(json_quoted("a\\b", false), "a\\\\b");
        assert_eq!(json_quoted("a\nb", false), "a\\nb");
        assert_eq!(json_quoted("a\rb", false), "a\\rb");
        assert_eq!(json_quoted("a\tb", false), "a\\tb");
    }

    #[test]
    fn test_json_quoted_control_chars() {
        // Backspace (0x08) and form feed (0x0C)
        assert_eq!(json_quoted("\u{0008}", false), "\\b");
        assert_eq!(json_quoted("\u{000C}", false), "\\f");
        // NUL (0x00)
        assert_eq!(json_quoted("\u{0000}", false), "\\u0000");
        // Other control character (0x01)
        assert_eq!(json_quoted("\u{0001}", false), "\\u0001");
    }

    #[test]
    fn test_json_quoted_lowercase() {
        assert_eq!(json_quoted("Content-Type", true), "content-type");
        assert_eq!(json_quoted("HELLO", true), "hello");
    }

    #[test]
    fn test_json_quoted_truncation() {
        let long_input: String = "a".repeat(MAX_JSON_STRING + 100);
        let result = json_quoted(&long_input, false);
        assert!(result.len() <= MAX_JSON_STRING);
    }

    #[test]
    fn test_write_json_string_with_value() {
        let mut buf: Vec<u8> = Vec::new();
        json_write_string("key", Some("value"), &mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "\"key\":\"value\"");
    }

    #[test]
    fn test_write_json_string_null() {
        let mut buf: Vec<u8> = Vec::new();
        json_write_string("key", None, &mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "\"key\":null");
    }

    #[test]
    fn test_write_json_long_positive() {
        let mut buf: Vec<u8> = Vec::new();
        write_json_long("code", 200, &mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "\"code\":200");
    }

    #[test]
    fn test_write_json_long_negative() {
        let mut buf: Vec<u8> = Vec::new();
        write_json_long("val", -1, &mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "\"val\":-1");
    }

    #[test]
    fn test_write_json_offset_large() {
        let mut buf: Vec<u8> = Vec::new();
        write_json_offset("size", 1_073_741_824, &mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "\"size\":1073741824");
    }

    #[test]
    fn test_write_json_time_basic() {
        let mut buf: Vec<u8> = Vec::new();
        write_json_time("time_total", 1_234_567, &mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "\"time_total\":1.234567");
    }

    #[test]
    fn test_write_json_time_zero() {
        let mut buf: Vec<u8> = Vec::new();
        write_json_time("time", 0, &mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "\"time\":0.000000");
    }

    #[test]
    fn test_write_json_time_subsecond() {
        let mut buf: Vec<u8> = Vec::new();
        write_json_time("t", 500, &mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "\"t\":0.000500");
    }

    #[test]
    fn test_write_json_time_exact_seconds() {
        let mut buf: Vec<u8> = Vec::new();
        write_json_time("t", 5_000_000, &mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "\"t\":5.000000");
    }

    #[test]
    fn test_json_quoted_unicode() {
        // Non-ASCII characters should pass through safely
        let result = json_quoted("héllo", false);
        assert!(result.contains("h"));
        // Validate the output is valid JSON content
        let json_str = format!("\"{}\"", result);
        let parsed: serde_json::Result<serde_json::Value> = serde_json::from_str(&json_str);
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_json_quoted_empty() {
        assert_eq!(json_quoted("", false), "");
        assert_eq!(json_quoted("", true), "");
    }

    #[test]
    fn test_write_json_string_special_chars() {
        let mut buf: Vec<u8> = Vec::new();
        json_write_string("ct", Some("text/html; charset=\"utf-8\""), &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        // Validate that the output is parseable JSON fragment
        let full_json = format!("{{{}}}", output);
        let parsed: serde_json::Result<serde_json::Value> = serde_json::from_str(&full_json);
        assert!(parsed.is_ok(), "Output is not valid JSON: {}", full_json);
    }
}
