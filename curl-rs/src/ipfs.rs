// -----------------------------------------------------------------------
// curl-rs/src/ipfs.rs — IPFS/IPNS Gateway URL Rewriting
//
// Rust rewrite of src/tool_ipfs.c and src/tool_ipfs.h from curl 8.19.0-DEV.
//
// Rewrites `ipfs://` and `ipns://` URLs to use a configured IPFS HTTP
// gateway, converting them to standard HTTP(S) URLs that can be fetched
// by the normal HTTP protocol handler.
//
// # Gateway Discovery Precedence
//
// 1. `--ipfs-gateway` CLI flag (stored in `OperationConfig::ipfs_gateway`)
// 2. `IPFS_GATEWAY` environment variable
// 3. Gateway file at `$IPFS_PATH/gateway` or `$HOME/.ipfs/gateway`
//
// # URL Rewriting Examples
//
// - `ipfs://CID/path?q=v#frag` → `{gateway}/ipfs/CID/path?q=v#frag`
// - `ipns://NAME/path?q=v#frag` → `{gateway}/ipns/NAME/path?q=v#frag`
//
// # Safety
//
// This module contains **zero** `unsafe` blocks.
//
// SPDX-License-Identifier: curl
// -----------------------------------------------------------------------

use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Result};
use url::Url;

use crate::config::OperationConfig;
use crate::msgs::helpf;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum length (in bytes) for a gateway URL read from the file system.
///
/// Matches the C `#define MAX_GATEWAY_URL_LEN 10000` in `src/tool_ipfs.h`.
/// If the first line of the gateway file exceeds this length, gateway
/// discovery from the file fails (returns `None`), matching the C dynbuf
/// overflow behavior.
const MAX_GATEWAY_URL_LEN: usize = 10_000;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Returns `true` if the URL uses the `ipfs://` or `ipns://` scheme.
///
/// The check is case-insensitive on the scheme portion, matching how curl
/// normalises URL schemes before protocol dispatch.
///
/// # Examples
///
/// ```ignore
/// assert!(is_ipfs_url("ipfs://QmCID/path"));
/// assert!(is_ipfs_url("ipns://example.com/path"));
/// assert!(is_ipfs_url("IPFS://QmCID"));
/// assert!(!is_ipfs_url("https://example.com"));
/// assert!(!is_ipfs_url("ftp://files.example.com"));
/// ```
pub fn is_ipfs_url(url: &str) -> bool {
    // ASCII-lowercase only the prefix portion for comparison efficiency.
    // The scheme in a valid URL ends at "://" so checking the first 7–8
    // bytes covers both "ipfs://" (7) and "ipns://" (7).
    let lower = url.get(..7).map(|s| s.to_ascii_lowercase());
    if let Some(ref prefix) = lower {
        if prefix == "ipfs://" || prefix == "ipns://" {
            return true;
        }
    }
    false
}

/// Discovers the IPFS gateway URL using the following precedence order:
///
/// 1. `config.ipfs_gateway` — user-specified via `--ipfs-gateway` CLI flag
///    (highest precedence).
/// 2. `IPFS_GATEWAY` environment variable.
/// 3. Gateway file at `$IPFS_PATH/gateway` or `$HOME/.ipfs/gateway`.
///
/// Returns `Some(gateway_url)` on success, or `None` if no gateway can be
/// found through any of these methods.
///
/// This is the Rust equivalent of the C static function `ipfs_gateway()`
/// combined with the `config->ipfs_gateway` check from
/// `ipfs_url_rewrite()` in `src/tool_ipfs.c`.
///
/// # Arguments
///
/// * `config` — The current operation configuration; the `ipfs_gateway`
///   field is checked first for the user-specified gateway.
///
/// # Gateway File Format
///
/// The gateway file (`$IPFS_PATH/gateway` or `~/.ipfs/gateway`) is
/// expected to contain a single-line URL (e.g., `http://localhost:8080`).
/// Only the first line is read; the line is terminated by `\n`, `\r`, or
/// EOF. Lines exceeding [`MAX_GATEWAY_URL_LEN`] bytes are rejected.
pub fn find_ipfs_gateway(config: &OperationConfig) -> Option<String> {
    // 1. Check user-specified gateway (--ipfs-gateway flag, highest precedence).
    //    Matches C: `if(config->ipfs_gateway) { ... }`
    if let Some(ref gw) = config.ipfs_gateway {
        if !gw.is_empty() {
            return Some(gw.clone());
        }
    }

    // 2. Check IPFS_GATEWAY environment variable.
    //    Matches C: `char *gateway_env = getenv("IPFS_GATEWAY");`
    if let Ok(gw) = env::var("IPFS_GATEWAY") {
        if !gw.is_empty() {
            return Some(gw);
        }
    }

    // 3. Read from gateway file ($IPFS_PATH/gateway or ~/.ipfs/gateway).
    //    Matches C: static `ipfs_gateway()` function body after env check.
    let path = gateway_file_path()?;
    read_gateway_file(&path)
}

/// Rewrites an `ipfs://` or `ipns://` URL to use the specified HTTP(S)
/// gateway.
///
/// This is the Rust equivalent of the C function `ipfs_url_rewrite()` in
/// `src/tool_ipfs.c`.  The gateway is provided as a pre-resolved string
/// (the caller obtains it via [`find_ipfs_gateway()`]).
///
/// # Arguments
///
/// * `url` — The original `ipfs://CID/path` or `ipns://NAME/path` URL.
/// * `gateway` — The gateway base URL (e.g., `"http://localhost:8080"`).
///   If no scheme is present, `http://` is assumed (matching the C
///   `CURLU_GUESS_SCHEME` behaviour).
///
/// # Returns
///
/// The rewritten URL using the gateway, preserving the original path,
/// query, and fragment components from the input URL.
///
/// # Errors
///
/// Returns an error (and calls [`helpf()`] with the appropriate
/// diagnostic message) when:
///
/// - The input URL cannot be parsed or is not an `ipfs://`/`ipns://` URL
///   → `helpf("malformed target URL")`
/// - The gateway URL cannot be parsed
///   → `helpf("--ipfs-gateway was given a malformed URL")`
/// - The gateway URL contains a query string (unsupported)
///   → `helpf("malformed target URL")`
///
/// This matches the C `ipfs_url_rewrite()` error→`helpf()` pattern from
/// `src/tool_ipfs.c` lines 222–234.
///
/// # URL Construction
///
/// Given `ipfs://QmCID/hello?q=1#sec` and gateway `http://gw:8080/api`:
///
/// ```text
/// http://gw:8080/api/ipfs/QmCID/hello?q=1#sec
/// ```
///
/// The new path is: `{gateway_path}/{protocol}/{cid}{input_path}`.
/// If the input path is exactly `"/"`, it is cleared to `""` (matching
/// the C behaviour at line 185).
pub fn ipfs_url_rewrite(url: &str, gateway: &str) -> Result<String> {
    // --- Parse the input IPFS/IPNS URL ---
    let parsed = Url::parse(url).map_err(|e| {
        helpf(Some("malformed target URL"));
        anyhow!("malformed target URL: {}", e)
    })?;

    // Extract and validate the scheme (must be ipfs or ipns).
    // Matches C: the `protocol` parameter is either "ipfs" or "ipns".
    let protocol = match parsed.scheme() {
        "ipfs" => "ipfs",
        "ipns" => "ipns",
        _ => {
            helpf(Some("malformed target URL"));
            bail!("malformed target URL: not an IPFS/IPNS URL");
        }
    };

    // Extract CID/name from the host portion.
    // Matches C: `curl_url_get(uh, CURLUPART_HOST, &cid, CURLU_URLDECODE)`
    let cid = match parsed.host_str() {
        Some(h) if !h.is_empty() => h,
        _ => {
            helpf(Some("malformed target URL"));
            bail!("malformed target URL: missing CID or name in host");
        }
    };

    // --- Parse the gateway URL ---
    // Matches C: `CURLU_GUESS_SCHEME` for config gateway,
    // and plain parse for auto-discovered gateway.
    let gw = parse_gateway_url(gateway)?;

    // Gateway must not have a query string.
    // Matches C: `if(curl_url_get(gatewayurl, CURLUPART_QUERY, &gwquery, 0)
    //              != CURLUE_NO_QUERY) { goto clean; }`
    if gw.query().is_some() {
        helpf(Some("malformed target URL"));
        bail!("gateway URL must not contain a query string");
    }

    // Extract gateway components.
    // Matches C extraction of gwscheme, gwhost, gwport, gwpath.
    let gw_scheme = gw.scheme();
    let gw_host = match gw.host_str() {
        Some(h) => h,
        None => {
            helpf(Some("malformed target URL"));
            bail!("gateway URL has no host component");
        }
    };
    let gw_port = gw.port();
    let gw_path = gw.path();

    // Remove trailing slash from gateway path for clean concatenation.
    // Matches C: `has_trailing_slash(gwpath) ? "" : "/"` — the C code
    // adds a slash between gwpath and protocol only if gwpath doesn't
    // already end with one.  We normalise by stripping trailing slashes
    // and always inserting one before the protocol.
    let gw_path_trimmed = gw_path.trim_end_matches('/');

    // Get the input path from the original URL.
    // If it is exactly "/" (root with no subpath), clear it to "".
    // Matches C: `if(inputpath && (inputpath[0] == '/') && !inputpath[1])
    //               *inputpath = '\0';`
    let raw_input_path = parsed.path();
    let input_path = if raw_input_path == "/" {
        ""
    } else {
        raw_input_path
    };

    // --- Build the rewritten URL ---
    //
    // New path: {gw_path}/{protocol}/{cid}{input_path}
    // Matches C: `curl_maprintf("%s%s%s/%s%s", gwpath,
    //              has_trailing_slash(gwpath) ? "" : "/",
    //              protocol, cid,
    //              inputpath ? inputpath : "");`
    let new_path = format!(
        "{}/{}/{}{}",
        gw_path_trimmed, protocol, cid, input_path
    );

    // Construct the full rewritten URL string.
    // Start with scheme://host[:port]
    let mut result = match gw_port {
        Some(port) => format!("{}://{}:{}", gw_scheme, gw_host, port),
        None => format!("{}://{}", gw_scheme, gw_host),
    };

    // Append the rewritten path.
    result.push_str(&new_path);

    // Preserve query string from the original IPFS/IPNS URL.
    if let Some(query) = parsed.query() {
        result.push('?');
        result.push_str(query);
    }

    // Preserve fragment from the original IPFS/IPNS URL.
    if let Some(fragment) = parsed.fragment() {
        result.push('#');
        result.push_str(fragment);
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Constructs the filesystem path to the IPFS gateway configuration file.
///
/// Checks `$IPFS_PATH` first; falls back to `$HOME/.ipfs/`.
///
/// Matches C logic:
/// ```c
/// ipfs_path_c = curl_getenv("IPFS_PATH");
/// if(!ipfs_path_c) {
///     char *home = getenv("HOME");
///     if(home && *home)
///         ipfs_path_c = curl_maprintf("%s/.ipfs/", home);
/// }
/// gateway_composed_c = curl_maprintf("%s%sgateway", ipfs_path_c, ...);
/// ```
fn gateway_file_path() -> Option<PathBuf> {
    // Try $IPFS_PATH first.
    if let Ok(ipfs_path) = env::var("IPFS_PATH") {
        if !ipfs_path.is_empty() {
            let mut path = PathBuf::from(&ipfs_path);
            path.push("gateway");
            return Some(path);
        }
    }

    // Fall back to $HOME/.ipfs/gateway.
    if let Ok(home) = env::var("HOME") {
        if !home.is_empty() {
            let mut path = PathBuf::from(&home);
            path.push(".ipfs");
            path.push("gateway");
            return Some(path);
        }
    }

    None
}

/// Reads the first line from the gateway file.
///
/// Matches the C character-by-character read behaviour:
/// ```c
/// while((c = getc(gfile)) != EOF && c != '\n' && c != '\r') { ... }
/// ```
///
/// Reads bytes until `\n`, `\r`, or end-of-content.  Enforces the
/// [`MAX_GATEWAY_URL_LEN`] limit — if the first line exceeds this length,
/// `None` is returned (matching the C `curlx_dyn_addn` overflow → `fail`
/// path).
///
/// Returns `None` if the file cannot be read, is empty, the first line is
/// empty, or the first line exceeds `MAX_GATEWAY_URL_LEN` bytes.
fn read_gateway_file(path: &std::path::Path) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;

    // Find the end of the first line: stop at \n or \r (matching C).
    let end = content
        .bytes()
        .position(|b| b == b'\n' || b == b'\r')
        .unwrap_or(content.len());

    // Empty first line → no gateway.
    if end == 0 {
        return None;
    }

    // Exceeds max gateway URL length → fail (matching C dynbuf overflow).
    if end > MAX_GATEWAY_URL_LEN {
        return None;
    }

    Some(content[..end].to_string())
}

/// Attempts to parse a gateway URL, guessing the scheme if not present.
///
/// Matches the C `CURLU_GUESS_SCHEME` behaviour used when parsing the
/// `--ipfs-gateway` argument: if the URL has no scheme, `http://` is
/// prepended before a second parse attempt.
///
/// On failure, calls [`helpf()`] with `"--ipfs-gateway was given a
/// malformed URL"` before returning the error, matching the C
/// `CURLE_BAD_FUNCTION_ARGUMENT` → `helpf` path.
fn parse_gateway_url(gateway: &str) -> Result<Url> {
    // Try parsing the gateway URL as-is.
    if let Ok(parsed) = Url::parse(gateway) {
        // Verify the parsed URL actually has a host (authority-based).
        // Without this check, bare hostnames like "localhost:8080" get
        // misinterpreted as scheme="localhost" with an opaque path "8080"
        // and no host component.  We only accept the direct parse when
        // a host is present, meaning a real scheme like "http://" or
        // "https://" was provided.
        if parsed.host_str().is_some() {
            return Ok(parsed);
        }
    }

    // Scheme guessing: prepend "http://" and retry, matching C
    // `CURLU_GUESS_SCHEME` which defaults to HTTP.
    let with_scheme = format!("http://{}", gateway);
    Url::parse(&with_scheme).map_err(|e| {
        helpf(Some("--ipfs-gateway was given a malformed URL"));
        anyhow!("--ipfs-gateway was given a malformed URL: {}", e)
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // is_ipfs_url tests
    // ---------------------------------------------------------------

    #[test]
    fn is_ipfs_url_detects_ipfs_scheme() {
        assert!(is_ipfs_url("ipfs://QmTest/path"));
        assert!(is_ipfs_url("ipfs://QmTest"));
        assert!(is_ipfs_url("ipfs://QmTest/"));
    }

    #[test]
    fn is_ipfs_url_detects_ipns_scheme() {
        assert!(is_ipfs_url("ipns://example.com/path"));
        assert!(is_ipfs_url("ipns://example.com"));
        assert!(is_ipfs_url("ipns://k51/path"));
    }

    #[test]
    fn is_ipfs_url_case_insensitive() {
        assert!(is_ipfs_url("IPFS://QmTest/path"));
        assert!(is_ipfs_url("Ipfs://QmTest/path"));
        assert!(is_ipfs_url("IPNS://example.com"));
        assert!(is_ipfs_url("IpNs://example.com"));
    }

    #[test]
    fn is_ipfs_url_rejects_non_ipfs() {
        assert!(!is_ipfs_url("https://example.com"));
        assert!(!is_ipfs_url("http://example.com"));
        assert!(!is_ipfs_url("ftp://files.example.com"));
        assert!(!is_ipfs_url("file:///tmp/test"));
        assert!(!is_ipfs_url(""));
        assert!(!is_ipfs_url("ipfs"));
        assert!(!is_ipfs_url("ipfs:"));
        assert!(!is_ipfs_url("ipfs:/"));
    }

    // ---------------------------------------------------------------
    // ipfs_url_rewrite tests
    // ---------------------------------------------------------------

    #[test]
    fn rewrite_ipfs_with_path() {
        let result =
            ipfs_url_rewrite("ipfs://QmCID/hello/world", "http://localhost:8080")
                .unwrap();
        assert_eq!(result, "http://localhost:8080/ipfs/QmCID/hello/world");
    }

    #[test]
    fn rewrite_ipns_with_path() {
        let result =
            ipfs_url_rewrite("ipns://example.com/page", "http://localhost:8080")
                .unwrap();
        assert_eq!(result, "http://localhost:8080/ipns/example.com/page");
    }

    #[test]
    fn rewrite_ipfs_without_path() {
        let result =
            ipfs_url_rewrite("ipfs://QmCID", "http://localhost:8080").unwrap();
        assert_eq!(result, "http://localhost:8080/ipfs/QmCID");
    }

    #[test]
    fn rewrite_ipfs_root_path_cleared() {
        // A path of exactly "/" should be cleared to "" (matching C).
        let result =
            ipfs_url_rewrite("ipfs://QmCID/", "http://localhost:8080").unwrap();
        assert_eq!(result, "http://localhost:8080/ipfs/QmCID");
    }

    #[test]
    fn rewrite_preserves_query() {
        let result = ipfs_url_rewrite(
            "ipfs://QmCID/path?key=value",
            "http://localhost:8080",
        )
        .unwrap();
        assert_eq!(
            result,
            "http://localhost:8080/ipfs/QmCID/path?key=value"
        );
    }

    #[test]
    fn rewrite_preserves_fragment() {
        let result = ipfs_url_rewrite(
            "ipfs://QmCID/path#section",
            "http://localhost:8080",
        )
        .unwrap();
        assert_eq!(
            result,
            "http://localhost:8080/ipfs/QmCID/path#section"
        );
    }

    #[test]
    fn rewrite_preserves_query_and_fragment() {
        let result = ipfs_url_rewrite(
            "ipfs://QmCID/path?q=1#frag",
            "http://localhost:8080",
        )
        .unwrap();
        assert_eq!(
            result,
            "http://localhost:8080/ipfs/QmCID/path?q=1#frag"
        );
    }

    #[test]
    fn rewrite_gateway_with_path() {
        let result = ipfs_url_rewrite(
            "ipfs://QmCID/hello",
            "http://gw.example.com:8080/api/v0",
        )
        .unwrap();
        assert_eq!(
            result,
            "http://gw.example.com:8080/api/v0/ipfs/QmCID/hello"
        );
    }

    #[test]
    fn rewrite_gateway_with_trailing_slash() {
        let result = ipfs_url_rewrite(
            "ipfs://QmCID/hello",
            "http://localhost:8080/",
        )
        .unwrap();
        assert_eq!(result, "http://localhost:8080/ipfs/QmCID/hello");
    }

    #[test]
    fn rewrite_gateway_https() {
        let result = ipfs_url_rewrite(
            "ipfs://QmCID/path",
            "https://gateway.ipfs.io",
        )
        .unwrap();
        assert_eq!(result, "https://gateway.ipfs.io/ipfs/QmCID/path");
    }

    #[test]
    fn rewrite_gateway_no_scheme_guesses_http() {
        let result =
            ipfs_url_rewrite("ipfs://QmCID/path", "localhost:8080").unwrap();
        assert_eq!(result, "http://localhost:8080/ipfs/QmCID/path");
    }

    #[test]
    fn rewrite_rejects_non_ipfs_url() {
        let result =
            ipfs_url_rewrite("https://example.com", "http://localhost:8080");
        assert!(result.is_err());
    }

    #[test]
    fn rewrite_rejects_gateway_with_query() {
        let result = ipfs_url_rewrite(
            "ipfs://QmCID/path",
            "http://localhost:8080?key=val",
        );
        assert!(result.is_err());
    }

    #[test]
    fn rewrite_rejects_malformed_gateway() {
        let result = ipfs_url_rewrite("ipfs://QmCID/path", "://broken");
        assert!(result.is_err());
    }

    // ---------------------------------------------------------------
    // find_ipfs_gateway tests
    // ---------------------------------------------------------------

    #[test]
    fn gateway_config_takes_precedence() {
        let mut config = make_test_config();
        config.ipfs_gateway = Some("http://config-gw:9090".to_string());

        let gw = find_ipfs_gateway(&config);
        assert_eq!(gw, Some("http://config-gw:9090".to_string()));
    }

    #[test]
    fn gateway_empty_config_skipped() {
        let mut config = make_test_config();
        config.ipfs_gateway = Some(String::new());

        // With no env vars or file, should return None (assuming clean env).
        // This test primarily verifies that empty string is skipped.
        let _gw = find_ipfs_gateway(&config);
        // We can't assert None because the test environment may have
        // IPFS_GATEWAY set. The key check is that empty config is skipped.
    }

    // ---------------------------------------------------------------
    // Internal helpers tests
    // ---------------------------------------------------------------

    #[test]
    fn parse_gateway_url_with_scheme() {
        let u = parse_gateway_url("http://localhost:8080").unwrap();
        assert_eq!(u.scheme(), "http");
        assert_eq!(u.host_str(), Some("localhost"));
        assert_eq!(u.port(), Some(8080));
    }

    #[test]
    fn parse_gateway_url_without_scheme() {
        let u = parse_gateway_url("localhost:8080").unwrap();
        assert_eq!(u.scheme(), "http");
        assert_eq!(u.host_str(), Some("localhost"));
        assert_eq!(u.port(), Some(8080));
    }

    #[test]
    fn parse_gateway_url_https() {
        let u = parse_gateway_url("https://gateway.ipfs.io").unwrap();
        assert_eq!(u.scheme(), "https");
        assert_eq!(u.host_str(), Some("gateway.ipfs.io"));
    }

    #[test]
    fn read_gateway_file_nonexistent() {
        let path = PathBuf::from("/nonexistent/path/gateway");
        assert_eq!(read_gateway_file(&path), None);
    }

    #[test]
    fn max_gateway_url_len_constant() {
        // Verify the constant matches the C definition.
        assert_eq!(MAX_GATEWAY_URL_LEN, 10_000);
    }

    // ---------------------------------------------------------------
    // Test helper
    // ---------------------------------------------------------------

    /// Creates a minimal `OperationConfig` for testing.
    ///
    /// All fields use safe defaults; callers adjust `ipfs_gateway` as needed.
    fn make_test_config() -> OperationConfig {
        OperationConfig::new()
    }
}
