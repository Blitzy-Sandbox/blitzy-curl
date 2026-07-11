// SPDX-License-Identifier: curl
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// Rust rewrite of curl's src/tool_ipfs.c (ipfs:// / ipns:// gateway rewrite).

//! # IPFS / IPNS gateway URL rewriting
//!
//! Faithful Rust port of curl 8.19.0-DEV's `src/tool_ipfs.c` / `src/tool_ipfs.h`.
//! curl does not speak the IPFS protocol natively; instead the CLI rewrites an
//! `ipfs://<CID>[/path]` or `ipns://<name>[/path]` URL into an ordinary HTTP(S)
//! request against an IPFS *gateway* before the transfer starts. This module
//! reproduces that rewrite byte-for-byte, so a downstream gateway sees exactly
//! the same request path curl 8.x produced.
//!
//! In curl this file is compiled only when IPFS support is enabled
//! (`#ifndef CURL_DISABLE_IPFS`). The workspace mirrors that guard with the
//! `ipfs` Cargo feature, which is **on by default** so the shipped `curl-rs`
//! behaves identically to the standard curl build (Minimal Change Mandate,
//! AAP §0.7.3). The whole module — and the [`OperationConfig::ipfs_gateway`]
//! field it reads — lives behind `#[cfg(feature = "ipfs")]`.
//!
//! ## Gateway resolution
//!
//! [`ipfs_gateway`] determines the gateway base URL in curl's precedence order:
//!
//! 1. the `--ipfs-gateway <URL>` command-line override
//!    ([`OperationConfig::ipfs_gateway`]);
//! 2. the `IPFS_GATEWAY` environment variable;
//! 3. the first line of the gateway file `$IPFS_PATH/gateway` (falling back to
//!    `$HOME/.ipfs/gateway`), bounded by [`MAX_GATEWAY_URL_LEN`].
//!
//! When none of these yields a gateway the automatic detection is considered to
//! have failed and [`CurlCode::FileCouldntReadFile`] is returned — the same
//! `CURLE_FILE_COULDNT_READ_FILE` curl 8.x reports.
//!
//! ## URL rewriting
//!
//! [`ipfs_url_rewrite`] transforms the parsed target [`Url`] (curl's `CURLU`)
//! in place: the CID/name is taken from the URL *host*, the gateway supplies the
//! scheme/host/port, and the path becomes
//! `<gateway-path>/<protocol>/<CID>[<input-path>]`. Any query string on the
//! input URL is left untouched, so `ipfs://<CID>/a/b?x=y` becomes
//! `http://gw/ipfs/<CID>/a/b?x=y`. The exact `CURLE_*` code and the
//! `curl:`-prefixed [`helpf`] diagnostics are preserved for downstream log and
//! exit-code parity (see the curl test corpus `tests/data/test722`–`test741`).
//!
//! ## Memory-safety guarantee
//!
//! This module is written entirely in safe Rust: curl's manual
//! `malloc`/`strdup`/`free` and `FILE*`/`dynbuf` bookkeeping is replaced by owned
//! [`String`]/[`Vec`] values and the buffered standard-library reader, so the
//! `unsafe` keyword is intentionally absent and the crate-wide safety audit
//! stays green.

#![allow(dead_code)]

use crate::args::{helpf, OperationConfig};
use curl_rs_lib::error::{CurlCode, CurlUCode};
use curl_rs_lib::urlapi::{self, CurlUPart, Url};

/// Upper bound on the length of a gateway URL read from the on-disk gateway
/// file — the Rust equivalent of curl's `#define MAX_GATEWAY_URL_LEN 10000`
/// (`src/tool_ipfs.h`). A first line longer than this is rejected (curl's
/// `dynbuf` add fails), which makes automatic gateway detection fail.
const MAX_GATEWAY_URL_LEN: usize = 10_000;

/// Reports whether `input` ends in a `/`.
///
/// Faithful port of curl's `has_trailing_slash` (`src/tool_ipfs.c`):
/// `len && input[len - 1] == '/'`. An empty string is *not* considered to have
/// a trailing slash.
fn has_trailing_slash(input: &str) -> bool {
    input.as_bytes().last() == Some(&b'/')
}

/// Reads the first line of the gateway file at `path`, bounded by
/// [`MAX_GATEWAY_URL_LEN`].
///
/// This mirrors the file-reading half of curl's `ipfs_gateway`: open the file,
/// read characters until the first `\n`/`\r`/EOF, and return the accumulated
/// bytes as the gateway string. Returns `None` — matching curl returning `NULL`
/// — when the file cannot be opened, when the first line is empty, when it
/// exceeds [`MAX_GATEWAY_URL_LEN`], or when the bytes are not valid UTF-8 (a
/// URL must be text). A mid-stream read error is treated like EOF, exactly as
/// curl's `getc` returns `EOF` for both conditions.
fn read_gateway_first_line(path: &str) -> Option<String> {
    use std::io::Read;

    // curl: `curlx_fopen(gateway_composed_c, FOPEN_READTEXT)`; a failure leaves
    // `gfile == NULL` and the function returns NULL.
    let file = std::fs::File::open(path).ok()?;
    let reader = std::io::BufReader::new(file);

    // curl: read the first line, ignore the rest, bounded by MAX_GATEWAY_URL_LEN.
    let mut line: Vec<u8> = Vec::new();
    for byte in reader.bytes() {
        match byte {
            Ok(c) => {
                if c == b'\n' || c == b'\r' {
                    break;
                }
                if line.len() >= MAX_GATEWAY_URL_LEN {
                    // curl: `curlx_dyn_addn` fails past the cap -> `goto fail` -> NULL.
                    return None;
                }
                line.push(c);
            }
            // curl's `getc` returns EOF on read error too, ending the loop.
            Err(_) => break,
        }
    }

    // curl: `if(curlx_dyn_len(&dyn)) gateway = curlx_dyn_ptr(&dyn);` — an empty
    // first line leaves `gateway == NULL`.
    if line.is_empty() {
        return None;
    }
    String::from_utf8(line).ok()
}

/// Resolves the gateway base URL from the environment or the gateway file.
///
/// This is the environment/file portion of curl's `ipfs_gateway` (the
/// `--ipfs-gateway` override is applied by the public [`ipfs_gateway`] before
/// this is consulted):
///
/// 1. `IPFS_GATEWAY` environment variable, if set (returned verbatim, even when
///    empty, matching curl's `curlx_strdup(gateway_env)`);
/// 2. otherwise the gateway file under `$IPFS_PATH` (or `$HOME/.ipfs/` when
///    `IPFS_PATH` is unset — and only when `$HOME` is set and non-empty), whose
///    first line is read via [`read_gateway_first_line`].
///
/// Returns `None` (curl's `NULL`) when neither source produces a gateway.
fn gateway_from_env_or_file() -> Option<String> {
    // curl: `char *gateway_env = getenv("IPFS_GATEWAY"); if(gateway_env) return
    // curlx_strdup(gateway_env);`
    if let Ok(gateway_env) = std::env::var("IPFS_GATEWAY") {
        return Some(gateway_env);
    }

    // curl: `ipfs_path_c = curl_getenv("IPFS_PATH");` with a `$HOME/.ipfs/`
    // fallback when it is unset.
    let ipfs_path = match std::env::var("IPFS_PATH") {
        Ok(path) => path,
        Err(_) => {
            // curl: `if(home && *home) ipfs_path_c = curl_maprintf("%s/.ipfs/", home);`
            // An unset or empty HOME leaves no path, so detection fails.
            let home = std::env::var("HOME").ok()?;
            if home.is_empty() {
                return None;
            }
            format!("{home}/.ipfs/")
        }
    };

    // curl: `curl_maprintf("%s%sgateway", ipfs_path_c,
    //                      has_trailing_slash(ipfs_path_c) ? "" : "/")`.
    let sep = if has_trailing_slash(&ipfs_path) {
        ""
    } else {
        "/"
    };
    let gateway_file = format!("{ipfs_path}{sep}gateway");

    read_gateway_first_line(&gateway_file)
}

/// Determines the IPFS gateway base URL, in curl's precedence order.
///
/// Precedence (highest first), mirroring curl's tool:
///
/// 1. the `--ipfs-gateway <URL>` override in [`OperationConfig::ipfs_gateway`];
/// 2. the `IPFS_GATEWAY` environment variable;
/// 3. the first line of `$IPFS_PATH/gateway`, else `$HOME/.ipfs/gateway`
///    (bounded by [`MAX_GATEWAY_URL_LEN`]).
///
/// The returned string is the *unvalidated* gateway URL; [`ipfs_url_rewrite`]
/// is responsible for parsing it and reporting the appropriate error code.
///
/// # Errors
///
/// Returns [`CurlCode::FileCouldntReadFile`] (curl's
/// `CURLE_FILE_COULDNT_READ_FILE`) when no `--ipfs-gateway` override is given
/// and neither the `IPFS_GATEWAY` environment variable nor the gateway file
/// yields a gateway URL — i.e. automatic gateway detection failed.
pub fn ipfs_gateway(config: &OperationConfig) -> Result<String, CurlCode> {
    // Precedence 1: the explicit --ipfs-gateway argument wins outright. curl
    // checks `config->ipfs_gateway` before ever calling its `ipfs_gateway()`.
    if let Some(gateway) = config.ipfs_gateway.as_deref() {
        return Ok(gateway.to_string());
    }

    // Precedence 2 & 3: environment variable, then the on-disk gateway file.
    gateway_from_env_or_file().ok_or(CurlCode::FileCouldntReadFile)
}

/// Rewrites an `ipfs://<CID>[/path]` or `ipns://<name>[/path]` URL into the
/// gateway HTTP(S) URL, in place on the passed-in [`Url`] handle.
///
/// This is a faithful port of curl's `ipfs_url_rewrite` (`src/tool_ipfs.c`).
/// `protocol` is the scheme token as detected by the caller — `"ipfs"` or
/// `"ipns"` — and is inserted literally into the rewritten path
/// (`/<protocol>/<CID>...`). The handle's scheme, host, port and path are
/// replaced with the gateway's; the query and fragment are left untouched so
/// they survive the rewrite. On return the caller can serialize the handle to
/// obtain the HTTP(S) URL the easy handle will actually fetch.
///
/// The algorithm, step-for-step with the C original:
///
/// 1. take the CID/name from the URL host (URL-decoded); a missing or empty
///    host is a malformed target URL;
/// 2. resolve and parse the gateway (via [`ipfs_gateway`]) — a `--ipfs-gateway`
///    value is parsed with scheme guessing and a parse failure is a *bad
///    argument*; an environment/file gateway is parsed strictly and a failure
///    is a *malformed URL*;
/// 3. reject a gateway that carries a query string;
/// 4. read the gateway scheme/host/port/path;
/// 5. read the input path;
/// 6. write the gateway scheme/host/port back onto the handle;
/// 7. drop a lone `/` input path;
/// 8. build `<gateway-path>[/]<protocol>/<CID><input-path>`;
/// 9. write that path onto the handle.
///
/// # Errors
///
/// * [`CurlCode::UrlMalformat`] — the target URL is malformed, the
///   environment/file gateway is not a valid URL, or the gateway carries a
///   query string.
/// * [`CurlCode::FileCouldntReadFile`] — automatic gateway detection failed
///   (no override, environment variable, or gateway file).
/// * [`CurlCode::BadFunctionArgument`] — the `--ipfs-gateway` argument is a
///   malformed URL.
///
/// On any error the matching `curl:`-prefixed [`helpf`] diagnostic is emitted,
/// exactly as curl prints it, before the code is returned.
pub fn ipfs_url_rewrite(
    url: &mut Url,
    protocol: &str,
    config: &OperationConfig,
) -> Result<(), CurlCode> {
    let result = ipfs_url_rewrite_impl(url, protocol, config);

    // curl's `clean:` label prints a help hint keyed on the result code. The
    // message text is preserved verbatim for downstream stderr parity.
    match result {
        Err(CurlCode::UrlMalformat) => helpf(Some("malformed target URL")),
        Err(CurlCode::FileCouldntReadFile) => {
            helpf(Some("IPFS automatic gateway detection failed"));
        }
        Err(CurlCode::BadFunctionArgument) => {
            helpf(Some("--ipfs-gateway was given a malformed URL"));
        }
        _ => {}
    }

    result
}

/// The rewrite proper, separated from [`ipfs_url_rewrite`] so the `helpf`
/// diagnostic is emitted from a single place (curl's `clean:` label) regardless
/// of which step failed.
fn ipfs_url_rewrite_impl(
    url: &mut Url,
    protocol: &str,
    config: &OperationConfig,
) -> Result<(), CurlCode> {
    // Step 1 — the CID/name is the URL host. curl: `curl_url_get(uh,
    // CURLUPART_HOST, &cid, CURLU_URLDECODE); if(getResult || !cid) goto clean;`
    // with the default `result = CURLE_URL_MALFORMAT`.
    let cid = url
        .get(CurlUPart::Host, urlapi::URLDECODE)
        .map_err(|_| CurlCode::UrlMalformat)?;
    if cid.is_empty() {
        return Err(CurlCode::UrlMalformat);
    }

    // Step 2 — resolve and parse the gateway. A `--ipfs-gateway` value is
    // parsed with CURLU_GUESS_SCHEME and a failure is CURLE_BAD_FUNCTION_ARGUMENT;
    // an environment/file gateway is parsed with no flags and a failure is
    // CURLE_URL_MALFORMAT (and a missing gateway is CURLE_FILE_COULDNT_READ_FILE,
    // surfaced by `ipfs_gateway`).
    let mut gatewayurl = Url::new();
    let from_arg = config.ipfs_gateway.is_some();
    let gateway = ipfs_gateway(config)?;
    let (set_flags, set_err) = if from_arg {
        (urlapi::GUESS_SCHEME, CurlCode::BadFunctionArgument)
    } else {
        (0u32, CurlCode::UrlMalformat)
    };
    gatewayurl
        .set(CurlUPart::Url, Some(&gateway), set_flags)
        .map_err(|_| set_err)?;

    // Step 3 — a gateway with a query is unsupported. curl: `if(curl_url_get(
    // gatewayurl, CURLUPART_QUERY, &gwquery, 0) != CURLUE_NO_QUERY) { result =
    // CURLE_URL_MALFORMAT; goto clean; }` — only "there is no query" is allowed.
    match gatewayurl.get(CurlUPart::Query, 0) {
        Err(CurlUCode::NoQuery) => {}
        _ => return Err(CurlCode::UrlMalformat),
    }

    // Step 4 — read the gateway parts. curl gets HOST/SCHEME/PORT/PATH with
    // CURLU_URLDECODE; any failure (including a gateway with no port) is a
    // malformed URL.
    let gwhost = gatewayurl
        .get(CurlUPart::Host, urlapi::URLDECODE)
        .map_err(|_| CurlCode::UrlMalformat)?;
    let gwscheme = gatewayurl
        .get(CurlUPart::Scheme, urlapi::URLDECODE)
        .map_err(|_| CurlCode::UrlMalformat)?;
    let gwport = gatewayurl
        .get(CurlUPart::Port, urlapi::URLDECODE)
        .map_err(|_| CurlCode::UrlMalformat)?;
    let gwpath = gatewayurl
        .get(CurlUPart::Path, urlapi::URLDECODE)
        .map_err(|_| CurlCode::UrlMalformat)?;

    // Step 5 — the input path. curl: `curl_url_get(uh, CURLUPART_PATH,
    // &inputpath, CURLU_URLDECODE)`; the URL API always yields at least "/".
    let mut inputpath = url
        .get(CurlUPart::Path, urlapi::URLDECODE)
        .map_err(|_| CurlCode::UrlMalformat)?;

    // Step 6 — write the gateway scheme/host/port onto the target handle. curl
    // sets them with CURLU_URLENCODE.
    url.set(CurlUPart::Scheme, Some(&gwscheme), urlapi::URLENCODE)
        .map_err(|_| CurlCode::UrlMalformat)?;
    url.set(CurlUPart::Host, Some(&gwhost), urlapi::URLENCODE)
        .map_err(|_| CurlCode::UrlMalformat)?;
    url.set(CurlUPart::Port, Some(&gwport), urlapi::URLENCODE)
        .map_err(|_| CurlCode::UrlMalformat)?;

    // Step 7 — a lone "/" input path is cleared. curl: `if(inputpath &&
    // (inputpath[0] == '/') && !inputpath[1]) *inputpath = '\0';`
    if inputpath == "/" {
        inputpath.clear();
    }

    // Step 8 — compose the gateway path. curl: `curl_maprintf("%s%s%s/%s%s",
    // gwpath, has_trailing_slash(gwpath) ? "" : "/", protocol, cid, inputpath)`.
    let sep = if has_trailing_slash(&gwpath) { "" } else { "/" };
    let pathbuffer = format!("{gwpath}{sep}{protocol}/{cid}{inputpath}");

    // Step 9 — write the composed path onto the handle (CURLU_URLENCODE). The
    // handle now holds the rewritten HTTP(S) URL; the query/fragment are
    // untouched, so they survive into the request.
    url.set(CurlUPart::Path, Some(&pathbuffer), urlapi::URLENCODE)
        .map_err(|_| CurlCode::UrlMalformat)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// The lowercase CIDv1 used throughout the curl IPFS test corpus
    /// (`tests/data/test722`–`test741`).
    const CID: &str = "bafybeidecnvkrygux6uoukouzps5ofkeevoqland7kopseiod6pzqvjg7u";

    /// Parse a CLI target URL the way the caller (`config2setopts.c`'s
    /// `url_proto_and_rewrite`) does: with scheme guessing and the
    /// unsupported-scheme gate open so `ipfs`/`ipns` are accepted.
    fn parse_input(input: &str) -> Url {
        Url::parse(input, urlapi::GUESS_SCHEME | urlapi::NON_SUPPORT_SCHEME)
            .expect("input URL should parse with GUESS_SCHEME|NON_SUPPORT_SCHEME")
    }

    /// Serialize a handle to its full URL the way the C caller does after the
    /// rewrite (`curl_url_get(uh, CURLUPART_URL, ..., CURLU_URLENCODE)`).
    fn full_url(url: &Url) -> String {
        url.get(CurlUPart::Url, urlapi::URLENCODE)
            .expect("rewritten handle should serialize")
    }

    /// A config carrying an explicit `--ipfs-gateway` value.
    fn config_with_gateway(gateway: &str) -> OperationConfig {
        let mut config = OperationConfig::new();
        config.ipfs_gateway = Some(gateway.to_string());
        config
    }

    // -- has_trailing_slash --------------------------------------------------

    #[test]
    fn trailing_slash_predicate() {
        assert!(has_trailing_slash("/"));
        assert!(has_trailing_slash("/foo/"));
        assert!(!has_trailing_slash("/foo"));
        // An empty string has no trailing slash (curl's `len && ...`).
        assert!(!has_trailing_slash(""));
    }

    // -- read_gateway_first_line ---------------------------------------------

    #[test]
    fn gateway_file_single_line() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "http://127.0.0.1:8080").unwrap();
        let path = f.path().to_str().unwrap().to_string();
        assert_eq!(
            read_gateway_first_line(&path).as_deref(),
            Some("http://127.0.0.1:8080")
        );
    }

    #[test]
    fn gateway_file_first_line_only() {
        // Mirrors test740: a multi-line gateway file yields only the first line.
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "http://127.0.0.1:8080\nfoo\nbar\n").unwrap();
        let path = f.path().to_str().unwrap().to_string();
        assert_eq!(
            read_gateway_first_line(&path).as_deref(),
            Some("http://127.0.0.1:8080")
        );
    }

    #[test]
    fn gateway_file_stops_at_carriage_return() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "http://gw:1\r\nsecond").unwrap();
        let path = f.path().to_str().unwrap().to_string();
        assert_eq!(
            read_gateway_first_line(&path).as_deref(),
            Some("http://gw:1")
        );
    }

    #[test]
    fn gateway_file_empty_first_line_is_none() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "\nfoo").unwrap();
        let path = f.path().to_str().unwrap().to_string();
        assert_eq!(read_gateway_first_line(&path), None);
    }

    #[test]
    fn gateway_file_missing_is_none() {
        assert_eq!(
            read_gateway_first_line("/nonexistent/blitzy/ipfs/gateway"),
            None
        );
    }

    #[test]
    fn gateway_file_overlong_line_is_none() {
        // A first line beyond MAX_GATEWAY_URL_LEN fails detection (curl's dynbuf cap).
        let mut f = tempfile::NamedTempFile::new().unwrap();
        let long = "a".repeat(MAX_GATEWAY_URL_LEN + 1);
        write!(f, "{long}").unwrap();
        let path = f.path().to_str().unwrap().to_string();
        assert_eq!(read_gateway_first_line(&path), None);
    }

    // -- ipfs_gateway (override precedence) ----------------------------------

    #[test]
    fn gateway_override_takes_precedence() {
        // The --ipfs-gateway override is returned verbatim without consulting
        // the environment or the filesystem.
        let config = config_with_gateway("http://127.0.0.1:8080");
        assert_eq!(
            ipfs_gateway(&config).unwrap(),
            "http://127.0.0.1:8080".to_string()
        );
    }

    // -- ipfs_url_rewrite (success) ------------------------------------------

    #[test]
    fn rewrite_plain_ipfs() {
        // test722/test736: ipfs://<cid> -> /ipfs/<cid> on the gateway host.
        let mut url = parse_input(&format!("ipfs://{CID}"));
        let config = config_with_gateway("http://127.0.0.1:8080");
        ipfs_url_rewrite(&mut url, "ipfs", &config).unwrap();
        assert_eq!(full_url(&url), format!("http://127.0.0.1:8080/ipfs/{CID}"));
    }

    #[test]
    fn rewrite_ipfs_with_path() {
        // test732: ipfs://<cid>/a/b -> /ipfs/<cid>/a/b.
        let mut url = parse_input(&format!("ipfs://{CID}/a/b"));
        let config = config_with_gateway("http://127.0.0.1:8080");
        ipfs_url_rewrite(&mut url, "ipfs", &config).unwrap();
        assert_eq!(
            full_url(&url),
            format!("http://127.0.0.1:8080/ipfs/{CID}/a/b")
        );
    }

    #[test]
    fn rewrite_ipfs_preserves_query() {
        // test733: the input query string survives the rewrite untouched.
        let mut url = parse_input(&format!("ipfs://{CID}/a/b?foo=bar&aaa=bbb"));
        let config = config_with_gateway("http://127.0.0.1:8080");
        ipfs_url_rewrite(&mut url, "ipfs", &config).unwrap();
        assert_eq!(
            full_url(&url),
            format!("http://127.0.0.1:8080/ipfs/{CID}/a/b?foo=bar&aaa=bbb")
        );
    }

    #[test]
    fn rewrite_gateway_with_path_prefix() {
        // test730: a gateway path prefix precedes /ipfs/<cid>.
        let mut url = parse_input(&format!("ipfs://{CID}"));
        let config = config_with_gateway("http://127.0.0.1:8080/foo/bar");
        ipfs_url_rewrite(&mut url, "ipfs", &config).unwrap();
        assert_eq!(
            full_url(&url),
            format!("http://127.0.0.1:8080/foo/bar/ipfs/{CID}")
        );
    }

    #[test]
    fn rewrite_ipns_with_path_and_gateway_path() {
        // test735: ipns://<name>/a/b with a gateway path prefix.
        let mut url = parse_input("ipns://fancy.tld/a/b?foo=bar&aaa=bbb");
        let config = config_with_gateway("http://127.0.0.1:8080/some/path");
        ipfs_url_rewrite(&mut url, "ipns", &config).unwrap();
        assert_eq!(
            full_url(&url),
            "http://127.0.0.1:8080/some/path/ipns/fancy.tld/a/b?foo=bar&aaa=bbb"
        );
    }

    // -- ipfs_url_rewrite (errors) -------------------------------------------
    //
    // The error scenarios exercise `ipfs_url_rewrite_impl` directly so the test
    // output is not cluttered by the `helpf` stderr hint; the public wrapper
    // returns the same code and additionally prints the hint.

    #[test]
    fn rewrite_arg_gateway_malformed_is_bad_argument() {
        // test723: --ipfs-gateway with an invalid host -> CURLE_BAD_FUNCTION_ARGUMENT (43).
        let mut url = parse_input(&format!("ipfs://{CID}"));
        let config = config_with_gateway("http://nonexisting,local:8080");
        assert_eq!(
            ipfs_url_rewrite_impl(&mut url, "ipfs", &config),
            Err(CurlCode::BadFunctionArgument)
        );
    }

    #[test]
    fn rewrite_arg_gateway_with_query_is_malformed() {
        // test739: a gateway that parses but carries a query -> CURLE_URL_MALFORMAT (3).
        let mut url = parse_input("ipns://fancy.tld/a/b");
        let config = config_with_gateway("http://127.0.0.1:8080/some/path?biz=baz");
        assert_eq!(
            ipfs_url_rewrite_impl(&mut url, "ipns", &config),
            Err(CurlCode::UrlMalformat)
        );
    }

    #[test]
    fn public_wrapper_returns_ok_on_success() {
        // The public entry point (which also emits diagnostics) succeeds for a
        // well-formed rewrite.
        let mut url = parse_input(&format!("ipfs://{CID}"));
        let config = config_with_gateway("http://127.0.0.1:8080");
        assert_eq!(ipfs_url_rewrite(&mut url, "ipfs", &config), Ok(()));
    }
}
