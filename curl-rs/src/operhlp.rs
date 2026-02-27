// -----------------------------------------------------------------------
// curl-rs/src/operhlp.rs — Operation Helper Routines
//
// Rust rewrite of src/tool_operhlp.c, src/tool_operhlp.h,
// src/tool_helpers.c, and src/tool_helpers.h from curl 8.19.0-DEV.
//
// Consolidates operation helper routines including HTTP method
// enforcement, URL rewriting, error text helpers, ETag handling,
// certificate type detection, and miscellaneous CLI transfer utilities.
//
// # Exported Functions
//
// | Function               | C Origin                                |
// |------------------------|-----------------------------------------|
// | `enforce_http_method`  | `SetHTTPrequest` (tool_helpers.c)       |
// | `http_method_text`     | `reqname[]` table (tool_helpers.c)      |
// | `customrequest_helper` | `customrequest_helper` (tool_helpers.c) |
// | `is_fatal_error`       | `is_fatal_error` (tool_operate.c)       |
// | `result_text`          | `curl_easy_strerror` wrapper            |
// | `url_proto_and_rewrite`| `url_proto_and_rewrite` (config2setopts)|
// | `append2query`         | `append2query` (tool_operate.c)         |
// | `etag_compare`         | `etag_compare` (tool_operate.c)         |
// | `etag_store`           | `etag_store` (tool_operate.c)           |
// | `set_cert_types`       | `set_cert_types` (tool_operate.c)       |
// | `output_expected`      | `output_expected` (tool_operhlp.c)      |
// | `stdin_upload`         | `stdin_upload` (tool_operhlp.c)         |
// | `add_file_name_to_url` | `add_file_name_to_url` (tool_operhlp.c) |
// | `get_url_file_name`    | `get_url_file_name` (tool_operhlp.c)    |
//
// # Safety
//
// This module contains **zero** `unsafe` blocks.
//
// SPDX-License-Identifier: curl
// -----------------------------------------------------------------------

use std::fs;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};

use crate::config::{GlobalConfig, HttpReq, OperationConfig};
use crate::ipfs;
use crate::libinfo;
use crate::msgs;
use curl_rs_lib::{CurlError, CurlUrl, CurlUrlPart, CurlUrlError};

// ---------------------------------------------------------------------------
// HTTP Method Helpers
// ---------------------------------------------------------------------------

/// Human-readable description for each [`HttpReq`] variant.
///
/// Mirrors the C `reqname[]` array in `tool_helpers.c`:
/// ```c
/// const char *reqname[] = {
///   "",
///   "GET (-G, --get)",
///   "HEAD (-I, --head)",
///   "multipart formpost (-F, --form)",
///   "POST (-d, --data)",
///   "PUT (-T, --upload-file)"
/// };
/// ```
///
/// # Examples
///
/// ```ignore
/// assert_eq!(http_method_text(HttpReq::Get), "GET (-G, --get)");
/// assert_eq!(http_method_text(HttpReq::Head), "HEAD (-I, --head)");
/// ```
pub fn http_method_text(req: HttpReq) -> &'static str {
    match req {
        HttpReq::Unspec => "",
        HttpReq::Get => "GET (-G, --get)",
        HttpReq::Head => "HEAD (-I, --head)",
        HttpReq::MimePost => "multipart formpost (-F, --form)",
        HttpReq::SimplePost => "POST (-d, --data)",
        HttpReq::Put => "PUT (-T, --upload-file)",
    }
}

/// Default HTTP method string for each [`HttpReq`] variant.
///
/// Mirrors the C `dflt[]` array in `customrequest_helper` (tool_helpers.c):
/// ```c
/// const char *dflt[] = { "GET","GET","HEAD","POST","POST","PUT" };
/// ```
fn http_method_default(req: HttpReq) -> &'static str {
    match req {
        HttpReq::Unspec => "GET",
        HttpReq::Get => "GET",
        HttpReq::Head => "HEAD",
        HttpReq::MimePost => "POST",
        HttpReq::SimplePost => "POST",
        HttpReq::Put => "PUT",
    }
}

/// Enforce that the requested HTTP method does not conflict with the
/// already-selected method.
///
/// Rust equivalent of C `SetHTTPrequest()` from `src/tool_helpers.c`.
///
/// If `*store` is [`HttpReq::Unspec`] (no method selected yet) or already
/// equals `req`, `*store` is set to `req` and the function returns `false`
/// (success, no conflict).
///
/// If `*store` differs from `req` (i.e., the user specified conflicting
/// flags like both `-I`/`--head` and `-d`/`--data`), a warning is emitted
/// via [`msgs::warnf`] and the function returns `true` (conflict detected).
///
/// # Arguments
///
/// * `global` — Global configuration for controlling warning output.
/// * `req`    — The new HTTP request method to set.
/// * `store`  — Mutable reference to the current method selection.
///
/// # Returns
///
/// `true` if a conflict was detected (caller should treat as error),
/// `false` if the method was accepted.
///
/// # C Equivalent
///
/// ```c
/// int SetHTTPrequest(HttpReq req, HttpReq *store);
/// ```
pub fn enforce_http_method(
    global: &GlobalConfig,
    req: HttpReq,
    store: &mut HttpReq,
) -> bool {
    if *store == HttpReq::Unspec || *store == req {
        *store = req;
        return false;
    }

    // Conflict: the user specified two different HTTP methods.
    msgs::warnf(
        global,
        &format!(
            "You can only select one HTTP request method! \
             You asked for both {} and {}.",
            http_method_text(req),
            http_method_text(*store),
        ),
    );

    true
}

/// Validate a custom HTTP request method (`-X`/`--request`) against the
/// inferred method from other flags, emitting diagnostics for redundant or
/// potentially incorrect usage.
///
/// Rust equivalent of C `customrequest_helper()` from `src/tool_helpers.c`.
///
/// Checks:
/// 1. If `method` matches the default method for the given `req` category,
///    a note is emitted (unnecessary use of `-X`).
/// 2. If `method` is `"head"` (case-insensitive), a warning is emitted
///    suggesting the use of `-I`/`--head` instead.
///
/// # Arguments
///
/// * `global` — Global configuration for controlling note/warning output.
/// * `req`    — The inferred HTTP request category (from other flags).
/// * `method` — The custom method string, or `None` if no `-X` was given.
///
/// # C Equivalent
///
/// ```c
/// void customrequest_helper(HttpReq req, const char *method);
/// ```
pub fn customrequest_helper(
    global: &GlobalConfig,
    req: HttpReq,
    method: Option<&str>,
) {
    let method = match method {
        Some(m) => m,
        None => return,
    };

    let default = http_method_default(req);

    if method.eq_ignore_ascii_case(default) {
        // The custom method matches what would be inferred anyway.
        msgs::notef(
            global,
            &format!(
                "Unnecessary use of -X or --request, {} is already inferred.",
                default,
            ),
        );
    } else if method.eq_ignore_ascii_case("head") {
        // Using -X HEAD is a common mistake — suggest -I instead.
        msgs::warnf(
            global,
            "Setting custom HTTP method to HEAD with -X/--request may not work \
             the way you want. Consider using -I/--head instead.",
        );
    }
}

// ---------------------------------------------------------------------------
// Error Helpers
// ---------------------------------------------------------------------------

/// Convert a [`CurlUrlError`] into a descriptive string for error reporting.
///
/// This is the Rust equivalent of the C `urlerr_cvt()` helper function
/// from `src/tool_operhlp.c` that maps URL-specific error codes to
/// human-friendly messages. Callers can use this when diagnosing URL
/// parsing failures.
///
/// # Examples
///
/// ```ignore
/// let err = CurlUrlError::MalformedInput;
/// assert_eq!(url_error_message(&err), "Malformed URL input");
/// ```
pub fn url_error_message(err: &CurlUrlError) -> &'static str {
    match err {
        CurlUrlError::MalformedInput => "Malformed URL input",
        CurlUrlError::BadPortNumber => "Bad port number in URL",
        CurlUrlError::UnsupportedScheme => "Unsupported URL scheme",
        CurlUrlError::BadScheme => "Bad URL scheme",
        CurlUrlError::BadUser => "Bad user in URL",
        CurlUrlError::BadPassword => "Bad password in URL",
        CurlUrlError::BadHostname => "Bad hostname in URL",
        CurlUrlError::BadPath => "Bad path in URL",
        CurlUrlError::BadQuery => "Bad query in URL",
        CurlUrlError::BadFragment => "Bad fragment in URL",
        CurlUrlError::BadLogin => "Bad login in URL",
        CurlUrlError::BadIpv6 => "Bad IPv6 address in URL",
        CurlUrlError::BadSlashes => "Unsupported number of slashes in URL",
        CurlUrlError::TooLarge => "URL field too large",
        _ => "URL error",
    }
}

/// Determine whether a [`CurlError`] code represents a fatal error that
/// should stop all processing immediately.
///
/// Rust equivalent of C `is_fatal_error()` from `src/tool_operate.c`:
/// ```c
/// static bool is_fatal_error(CURLcode code)
/// {
///   switch(code) {
///   case CURLE_FAILED_INIT:
///   case CURLE_OUT_OF_MEMORY:
///   case CURLE_UNKNOWN_OPTION:
///   case CURLE_BAD_FUNCTION_ARGUMENT:
///     return TRUE;
///   default:
///     break;
///   }
///   return FALSE;
/// }
/// ```
///
/// # Returns
///
/// `true` for critical infrastructure errors that prevent any further
/// transfers from succeeding. `false` for recoverable or transfer-specific
/// errors.
pub fn is_fatal_error(code: CurlError) -> bool {
    matches!(
        code,
        CurlError::FailedInit
            | CurlError::OutOfMemory
            | CurlError::UnknownOption
            | CurlError::BadFunctionArgument
    )
}

/// Map a [`CurlError`] code to its human-readable error message string.
///
/// Delegates to [`CurlError::strerror()`], which produces strings identical
/// to `curl_easy_strerror()` in `lib/strerror.c`.
///
/// # Returns
///
/// A static string describing the error. For `CurlError::Ok`, returns
/// `"No error"`.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(result_text(CurlError::Ok), "No error");
/// assert_eq!(result_text(CurlError::CouldntConnect), "Could not connect to server");
/// ```
pub fn result_text(code: CurlError) -> &'static str {
    code.strerror()
}

// ---------------------------------------------------------------------------
// URL Utilities
// ---------------------------------------------------------------------------

/// Detect the URL scheme, optionally rewrite IPFS/IPNS URLs through a
/// gateway, and return the (possibly rewritten) URL along with the detected
/// protocol token.
///
/// Rust equivalent of C `url_proto_and_rewrite()` from
/// `src/config2setopts.c`:
///
/// 1. Parse the URL with `CURLU_GUESS_SCHEME | CURLU_NON_SUPPORT_SCHEME`.
/// 2. Extract the scheme (with `CURLU_DEFAULT_SCHEME` fallback).
/// 3. If the scheme is `ipfs` or `ipns`, rewrite the URL through the
///    configured IPFS gateway via [`ipfs::ipfs_url_rewrite`].
/// 4. Otherwise, identify the protocol via [`libinfo::proto_token`].
/// 5. Return `(rewritten_url, scheme)`.
///
/// # Arguments
///
/// * `url`    — The original URL string.
/// * `config` — The operation configuration (provides IPFS gateway settings).
///
/// # Returns
///
/// `Ok((rewritten_url, scheme_string))` on success.
///
/// The scheme string is the canonical protocol name (e.g., `"https"`,
/// `"ftp"`) or `"?"` if the protocol is not recognized by the library.
///
/// # Errors
///
/// Returns an error if URL parsing fails or IPFS gateway rewriting fails.
pub fn url_proto_and_rewrite(
    url: &str,
    config: &OperationConfig,
) -> Result<(String, String)> {
    // Parse the URL using CurlUrl with scheme guessing and non-support scheme
    // flags, matching C: curl_url_set(uh, CURLUPART_URL, *url,
    //   CURLU_GUESS_SCHEME | CURLU_NON_SUPPORT_SCHEME)
    let mut uh = CurlUrl::new();
    let set_flags = curl_rs_lib::url::CURLU_GUESS_SCHEME
        | curl_rs_lib::url::CURLU_NON_SUPPORT_SCHEME;

    uh.set(CurlUrlPart::Url, url, set_flags)
        .map_err(|e| anyhow!("Failed to parse URL: {}", e))?;

    // Extract the scheme, using CURLU_DEFAULT_SCHEME to fall back to "https"
    // if no scheme was provided.
    // Matches C: curl_url_get(uh, CURLUPART_SCHEME, &schemep, CURLU_DEFAULT_SCHEME)
    let scheme = uh
        .get(CurlUrlPart::Scheme, curl_rs_lib::url::CURLU_DEFAULT_SCHEME)
        .map_err(|e| anyhow!("Failed to extract URL scheme: {}", e))?;

    let scheme_lower = scheme.to_ascii_lowercase();

    // Check for IPFS/IPNS URLs and rewrite through gateway
    if scheme_lower == "ipfs" || scheme_lower == "ipns" {
        // Find the IPFS gateway
        if let Some(gateway) = ipfs::find_ipfs_gateway(config) {
            let rewritten = ipfs::ipfs_url_rewrite(url, &gateway)?;
            return Ok((rewritten, scheme_lower));
        }
        // No gateway found — the URL stays as-is; caller may handle this.
        // The scheme is still "ipfs" or "ipns".
        return Ok((url.to_string(), scheme_lower));
    }

    // For non-IPFS URLs, identify the protocol via proto_token.
    // Matches C: `proto = proto_token(schemep);`
    let proto = libinfo::proto_token(&scheme_lower)
        .unwrap_or_else(|| "?".to_string());

    Ok((url.to_string(), proto))
}

/// Append query data to a URL string, handling existing query strings.
///
/// Rust equivalent of C `append2query()` from `src/tool_operate.c`.
///
/// Uses [`CurlUrl`] to parse the URL, append the query data via
/// `CURLU_APPENDQUERY`, and retrieve the updated URL.
///
/// # Arguments
///
/// * `url`   — Mutable reference to the URL string. On success, this is
///   replaced with the updated URL containing the appended query.
/// * `query` — The query data to append (e.g., `"key=value"`).
///
/// # Errors
///
/// Returns an error if the URL cannot be parsed or the query cannot be
/// appended.
///
/// # C Equivalent
///
/// ```c
/// static CURLcode append2query(struct OperationConfig *config,
///                               struct per_transfer *per, const char *q);
/// ```
pub fn append2query(url: &mut String, query: &str) -> Result<()> {
    let mut uh = CurlUrl::new();

    // Parse the current URL with scheme guessing.
    // Matches C: curl_url_set(uh, CURLUPART_URL, per->url, CURLU_GUESS_SCHEME)
    if let Err(e) = uh.set(
        CurlUrlPart::Url,
        url.as_str(),
        curl_rs_lib::url::CURLU_GUESS_SCHEME,
    ) {
        bail!("Could not parse the URL, failed to set query: {}", e);
    }

    // Append the query data using the APPENDQUERY flag.
    // Matches C: curl_url_set(uh, CURLUPART_QUERY, q, CURLU_APPENDQUERY)
    uh.set(
        CurlUrlPart::Query,
        query,
        curl_rs_lib::url::CURLU_APPENDQUERY,
    )
    .context("Failed to append query to URL")?;

    // Retrieve the full updated URL.
    // Matches C: curl_url_get(uh, CURLUPART_URL, &updated, CURLU_GUESS_SCHEME)
    let updated = uh
        .get(CurlUrlPart::Url, curl_rs_lib::url::CURLU_GUESS_SCHEME)
        .context("Failed to retrieve updated URL after query append")?;

    *url = updated;
    Ok(())
}

// ---------------------------------------------------------------------------
// ETag Handling
// ---------------------------------------------------------------------------

/// Read the ETag value from the configured compare file and return the
/// `If-None-Match` header string to add to the request.
///
/// Rust equivalent of C `etag_compare()` from `src/tool_operate.c`.
///
/// 1. Opens `config.etag_compare_file` for reading.
/// 2. Reads the stored ETag value (first line, trimmed).
/// 3. Returns `Some("If-None-Match: <etag>")` if successful.
/// 4. Returns `Some("If-None-Match: \"\"")` if file is empty or missing
///    etag content (matching C behavior of sending empty etag).
/// 5. Returns `None` only if no etag_compare_file is configured.
///
/// # Arguments
///
/// * `config` — Operation configuration containing `etag_compare_file`.
/// * `global` — Global configuration for warning output.
///
/// # C Equivalent
///
/// ```c
/// static CURLcode etag_compare(struct OperationConfig *config);
/// ```
pub fn etag_compare(
    config: &OperationConfig,
    global: &GlobalConfig,
) -> Option<String> {
    let etag_file = config.etag_compare_file.as_ref()?;

    // Attempt to read the etag file.
    // Matches C: FILE *file = curlx_fopen(config->etag_compare_file, FOPEN_READTEXT)
    match fs::read_to_string(etag_file) {
        Ok(content) => {
            // Extract the first line and trim whitespace.
            // The C code reads via file2string which reads the entire content.
            let etag_value = content
                .lines()
                .next()
                .unwrap_or("")
                .trim();

            if etag_value.is_empty() {
                // Empty etag — send empty If-None-Match.
                // Matches C: header = curl_maprintf("If-None-Match: \"\"");
                Some("If-None-Match: \"\"".to_string())
            } else {
                // Valid etag — build the If-None-Match header.
                // Matches C: header = curl_maprintf("If-None-Match: %s", etag_from_file);
                Some(format!("If-None-Match: {}", etag_value))
            }
        }
        Err(e) => {
            // File open/read failure — warn and return empty etag header.
            // Matches C: warnf("Failed to open %s: %s", ...)
            msgs::warnf(
                global,
                &format!("Failed to open {}: {}", etag_file, e),
            );
            // C still generates an If-None-Match header with empty value:
            // header = curl_maprintf("If-None-Match: \"\"");
            Some("If-None-Match: \"\"".to_string())
        }
    }
}

/// Store an ETag value to the configured save file.
///
/// Rust equivalent of C `etag_store()` from `src/tool_operate.c`.
///
/// Writes the provided ETag string to `config.etag_save_file`. If the file
/// path is `"-"`, the ETag would be written to stdout (in the CLI context,
/// this is handled by the caller; here we return Ok for that case).
///
/// # Arguments
///
/// * `config` — Operation configuration containing `etag_save_file`.
/// * `etag`   — The ETag value to store.
///
/// # Errors
///
/// Returns an error if the file cannot be created or written to.
///
/// # C Equivalent
///
/// ```c
/// static CURLcode etag_store(struct OperationConfig *config,
///                             struct OutStruct *etag_save, bool *skip);
/// ```
pub fn etag_store(config: &OperationConfig, etag: &str) -> Result<()> {
    let save_file = match config.etag_save_file.as_ref() {
        Some(f) => f,
        None => return Ok(()), // No save file configured — nothing to do.
    };

    // If the save file is "-", the etag is written to stdout by the caller.
    // Matches C: if(strcmp(config->etag_save_file, "-"))
    if save_file == "-" {
        // Stdout mode — the caller handles writing to stdout.
        return Ok(());
    }

    // Create parent directories if needed.
    // Matches C: if(config->create_dirs) { create_dir_hierarchy(...) }
    if config.create_dirs {
        if let Some(parent) = Path::new(save_file).parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| {
                        format!(
                            "Failed to create directory hierarchy for etag save file: {}",
                            save_file,
                        )
                    })?;
            }
        }
    }

    // Write the etag to the file (append mode to match C: "ab").
    // Matches C: FILE *newfile = curlx_fopen(config->etag_save_file, "ab")
    use std::fs::OpenOptions;
    use std::io::Write;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(save_file)
        .with_context(|| {
            format!(
                "Failed creating file for saving etags: \"{}\"",
                save_file,
            )
        })?;

    write!(file, "{}", etag)
        .with_context(|| format!("Failed to write etag to: {}", save_file))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Certificate Type Detection
// ---------------------------------------------------------------------------

/// Check if a string is a PKCS#11 URI (`pkcs11:` prefix).
///
/// Rust equivalent of C `is_pkcs11_uri()` from `src/tool_operate.c`:
/// ```c
/// static bool is_pkcs11_uri(const char *string) {
///   if(curl_strnequal(string, "pkcs11:", 7)) return TRUE;
///   else return FALSE;
/// }
/// ```
fn is_pkcs11_uri(s: &str) -> bool {
    s.len() >= 7
        && s.as_bytes()[..7].eq_ignore_ascii_case(b"pkcs11:")
}

/// Auto-detect and normalize certificate and key types based on PKCS#11
/// URI prefixes.
///
/// Rust equivalent of C `set_cert_types()` from `src/tool_operate.c`.
///
/// For each certificate/key field (`cert`, `key`, `proxy_cert`, `proxy_key`),
/// if the value is a PKCS#11 URI (`pkcs11:...`) and no explicit type has
/// been set, the type is automatically set to `"ENG"` (engine).
///
/// This enables transparent PKCS#11 token usage when the user provides a
/// PKCS#11 URI via `--cert`, `--key`, `--proxy-cert`, or `--proxy-key`
/// without also specifying `--cert-type ENG`.
///
/// # Arguments
///
/// * `config` — Mutable operation configuration. The `cert_type`,
///   `key_type`, `proxy_cert_type`, and `proxy_key_type` fields may be
///   modified.
///
/// # C Equivalent
///
/// ```c
/// static CURLcode set_cert_types(struct OperationConfig *config);
/// ```
pub fn set_cert_types(config: &mut OperationConfig) {
    // Check if config->cert is a PKCS#11 URI and set cert_type if not already
    // set. Matches C: if(config->cert && !config->cert_type &&
    //   is_pkcs11_uri(config->cert))
    if let Some(ref cert) = config.cert {
        if config.cert_type.is_none() && is_pkcs11_uri(cert) {
            config.cert_type = Some("ENG".to_string());
        }
    }

    // Check if config->key is a PKCS#11 URI.
    // Matches C: if(config->key && !config->key_type && is_pkcs11_uri(config->key))
    if let Some(ref key) = config.key {
        if config.key_type.is_none() && is_pkcs11_uri(key) {
            config.key_type = Some("ENG".to_string());
        }
    }

    // Check if config->proxy_cert is a PKCS#11 URI.
    // Matches C: if(config->proxy_cert && !config->proxy_cert_type &&
    //   is_pkcs11_uri(config->proxy_cert))
    if let Some(ref proxy_cert) = config.proxy_cert {
        if config.proxy_cert_type.is_none() && is_pkcs11_uri(proxy_cert) {
            config.proxy_cert_type = Some("ENG".to_string());
        }
    }

    // Check if config->proxy_key is a PKCS#11 URI.
    // Matches C: if(config->proxy_key && !config->proxy_key_type &&
    //   is_pkcs11_uri(config->proxy_key))
    if let Some(ref proxy_key) = config.proxy_key {
        if config.proxy_key_type.is_none() && is_pkcs11_uri(proxy_key) {
            config.proxy_key_type = Some("ENG".to_string());
        }
    }
}

// ---------------------------------------------------------------------------
// Miscellaneous Operation Helpers
// ---------------------------------------------------------------------------

/// Determine whether output (response body) is expected for a given URL
/// and upload file combination.
///
/// Rust equivalent of C `output_expected()` from `src/tool_operhlp.c`:
/// ```c
/// bool output_expected(const char *url, const char *uploadfile) {
///   if(!uploadfile) return TRUE;
///   if(checkprefix("http://", url) || checkprefix("https://", url))
///     return TRUE;
///   return FALSE;
/// }
/// ```
///
/// Downloads always produce output. HTTP(S) uploads also produce output
/// (the server response). Non-HTTP uploads (e.g., FTP PUT) typically do
/// not produce output.
///
/// # Arguments
///
/// * `url`        — The transfer URL.
/// * `uploadfile` — The upload file path, or `None` for downloads.
///
/// # Returns
///
/// `true` if response body output should be expected for this transfer.
pub fn output_expected(url: &str, uploadfile: Option<&str>) -> bool {
    // No upload file means this is a download — always expect output.
    if uploadfile.is_none() {
        return true;
    }

    // HTTP(S) uploads produce response output.
    let url_lower = url.to_ascii_lowercase();
    if url_lower.starts_with("http://") || url_lower.starts_with("https://") {
        return true;
    }

    // Non-HTTP upload — no output expected.
    false
}

/// Check if the upload file path indicates reading from stdin.
///
/// Rust equivalent of C `stdin_upload()` from `src/tool_operhlp.c`:
/// ```c
/// bool stdin_upload(const char *uploadfile) {
///   return !strcmp(uploadfile, "-") || !strcmp(uploadfile, ".");
/// }
/// ```
///
/// Both `"-"` and `"."` are recognized as stdin sentinels, matching
/// curl 8.x behavior where `-T -` and `-T .` both read upload data
/// from standard input.
///
/// # Arguments
///
/// * `uploadfile` — The upload file path to check.
///
/// # Returns
///
/// `true` if the upload source is stdin.
pub fn stdin_upload(uploadfile: &str) -> bool {
    uploadfile == "-" || uploadfile == "."
}

/// Add a filename to a URL if the URL does not already have one in its
/// path component.
///
/// Rust equivalent of C `add_file_name_to_url()` from
/// `src/tool_operhlp.c`. When the URL path ends with `/` or has no
/// filename portion, the local filename (after the last `/` or `\`
/// separator) is URL-encoded and appended to the path.
///
/// If the URL already has a query string, the URL is left unchanged
/// (matching the C behavior where a query string implies the URL is
/// already complete).
///
/// # Arguments
///
/// * `url`      — Mutable reference to the URL string. May be replaced
///   with the updated URL on success.
/// * `filename` — The local filename to append.
///
/// # Errors
///
/// Returns an error if the URL cannot be parsed.
///
/// # C Equivalent
///
/// ```c
/// CURLcode add_file_name_to_url(CURL *curl, char **inurlp, const char *filename);
/// ```
pub fn add_file_name_to_url(url: &mut String, filename: &str) -> Result<()> {
    let mut uh = CurlUrl::new();

    // Parse the URL with scheme guessing and non-support scheme flags.
    // Matches C: curl_url_set(uh, CURLUPART_URL, *inurlp,
    //   CURLU_GUESS_SCHEME | CURLU_NON_SUPPORT_SCHEME)
    let set_flags = curl_rs_lib::url::CURLU_GUESS_SCHEME
        | curl_rs_lib::url::CURLU_NON_SUPPORT_SCHEME;

    uh.set(CurlUrlPart::Url, url.as_str(), set_flags)
        .context("Failed to parse URL for filename addition")?;

    // Extract the path.
    let path = uh
        .get(CurlUrlPart::Path, 0)
        .context("Failed to extract URL path")?;

    // If the URL already has a query string, leave it unchanged.
    // Matches C: curl_url_get(uh, CURLUPART_QUERY, &query, 0) check.
    if uh.get(CurlUrlPart::Query, 0).is_ok() {
        return Ok(());
    }

    // Check if the path already ends with a filename.
    // Matches C: ptr = strrchr(path, '/'); if(!ptr || !*++ptr) { ... }
    let last_slash = path.rfind('/');
    let has_filename = match last_slash {
        Some(pos) => {
            // There is a slash — check if there are chars after it.
            pos + 1 < path.len()
        }
        None => {
            // No slash at all — the entire path is the filename.
            !path.is_empty()
        }
    };

    if has_filename {
        // The URL already has a filename in the path — nothing to do.
        return Ok(());
    }

    // Extract the local filename portion (after the last / or \).
    // Matches C:
    //   filep = strrchr(filename, '/');
    //   file2 = strrchr(filep ? filep : filename, '\\');
    let filep = filename.rfind('/');
    let base_start = filep.map(|p| p + 1).unwrap_or(0);
    let remaining = &filename[base_start..];
    let file2 = remaining.rfind('\\');
    let local_name = match file2 {
        Some(p) => &remaining[p + 1..],
        None => remaining,
    };

    if local_name.is_empty() {
        return Ok(());
    }

    // URL-encode the filename.
    // Matches C: encfile = curl_easy_escape(curl, filep, 0)
    let encoded = percent_encode_filename(local_name);

    // Build the new path.
    let new_path = if path.ends_with('/') {
        // Trailing slash: append directly.
        // Matches C: newpath = curl_maprintf("%s%s", path, encfile)
        format!("{}{}", path, encoded)
    } else {
        // No trailing slash: add one.
        // Matches C: newpath = curl_maprintf("%s/%s", path, encfile)
        format!("{}/{}", path, encoded)
    };

    // Set the new path and retrieve the full updated URL.
    uh.set(CurlUrlPart::Path, &new_path, 0)
        .context("Failed to set updated path on URL")?;

    let new_url = uh
        .get(CurlUrlPart::Url, curl_rs_lib::url::CURLU_DEFAULT_SCHEME)
        .context("Failed to retrieve URL after filename addition")?;

    *url = new_url;
    Ok(())
}

/// URL-encode a filename for safe inclusion in a URL path.
///
/// Encodes all characters except unreserved characters (alphanumeric,
/// `-`, `_`, `.`, `~`) using percent-encoding, matching the behavior of
/// `curl_easy_escape()`.
fn percent_encode_filename(name: &str) -> String {
    let mut encoded = String::with_capacity(name.len() * 3);
    for &byte in name.as_bytes() {
        if byte.is_ascii_alphanumeric()
            || byte == b'-'
            || byte == b'_'
            || byte == b'.'
            || byte == b'~'
        {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{:02X}", byte));
        }
    }
    encoded
}

/// Extract the filename portion from a URL.
///
/// Rust equivalent of C `get_url_file_name()` from `src/tool_operhlp.c`.
///
/// Parses the URL, extracts the path component, and returns the last
/// path segment as the filename. If the path ends with `/`, the trailing
/// slash is stripped and the last directory component is used. If no
/// filename can be determined (empty path or root `/`), returns the
/// default `"curl_response"`.
///
/// # Arguments
///
/// * `url` — The URL to extract the filename from.
///
/// # Returns
///
/// The extracted filename string.
///
/// # Errors
///
/// Returns an error if the URL cannot be parsed.
///
/// # C Equivalent
///
/// ```c
/// CURLcode get_url_file_name(char **filename, const char *url, SANITIZEcode *sc);
/// ```
pub fn get_url_file_name(url: &str) -> Result<String> {
    let mut uh = CurlUrl::new();

    // Parse the URL with scheme guessing.
    // Matches C: curl_url_set(uh, CURLUPART_URL, url, CURLU_GUESS_SCHEME)
    uh.set(
        CurlUrlPart::Url,
        url,
        curl_rs_lib::url::CURLU_GUESS_SCHEME,
    )
    .context("Failed to parse URL for filename extraction")?;

    // Extract the path component.
    let path = uh
        .get(CurlUrlPart::Path, 0)
        .context("Failed to extract URL path for filename")?;

    // Attempt to find the filename in the path.
    // The C code does two iterations: first with the full path, then
    // with the trailing slash removed if the path ended with one.
    // Matches C:
    //   for(i = 0; i < 2; i++) {
    //     pc = strrchr(path, '/');
    //     pc2 = strrchr(pc ? pc + 1 : path, '\\');
    //     ...
    //   }
    let filename = extract_filename_from_path(&path);

    if let Some(name) = filename {
        if !name.is_empty() {
            return Ok(name.to_string());
        }
    }

    // No filename found — use default.
    // Matches C: *filename = curlx_strdup("curl_response");
    Ok("curl_response".to_string())
}

/// Extract the filename from a URL path, handling trailing slashes and
/// backslash separators.
///
/// This is the Rust equivalent of the double-iteration loop in the C
/// `get_url_file_name()` function.
fn extract_filename_from_path(path: &str) -> Option<&str> {
    let mut remaining = path;

    // Two iterations: first try the full path, then strip trailing slash.
    for i in 0..2 {
        // Find the last forward slash.
        let pc_pos = remaining.rfind('/');

        // Find the last backslash in the portion after the forward slash.
        let after_slash = match pc_pos {
            Some(pos) => &remaining[pos + 1..],
            None => remaining,
        };
        let pc2_pos = after_slash.rfind('\\');

        // Determine the effective position of the last separator.
        let effective_name = match pc2_pos {
            Some(p2) => &after_slash[p2 + 1..],
            None => after_slash,
        };

        // If we found a non-empty name after the separator, return it.
        if !effective_name.is_empty() {
            return Some(effective_name);
        }

        // If this is the first iteration and the path ends with a slash,
        // strip the trailing slash and try again.
        // Matches C: if(pc && !pc[1] && !i) { *pc = 0; }
        if i == 0 {
            remaining = remaining.trim_end_matches('/');
            if remaining.is_empty() {
                return None;
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HttpReq;

    #[test]
    fn test_http_method_text_all_variants() {
        assert_eq!(http_method_text(HttpReq::Unspec), "");
        assert_eq!(http_method_text(HttpReq::Get), "GET (-G, --get)");
        assert_eq!(http_method_text(HttpReq::Head), "HEAD (-I, --head)");
        assert_eq!(
            http_method_text(HttpReq::MimePost),
            "multipart formpost (-F, --form)"
        );
        assert_eq!(http_method_text(HttpReq::SimplePost), "POST (-d, --data)");
        assert_eq!(
            http_method_text(HttpReq::Put),
            "PUT (-T, --upload-file)"
        );
    }

    #[test]
    fn test_http_method_default() {
        assert_eq!(http_method_default(HttpReq::Unspec), "GET");
        assert_eq!(http_method_default(HttpReq::Get), "GET");
        assert_eq!(http_method_default(HttpReq::Head), "HEAD");
        assert_eq!(http_method_default(HttpReq::MimePost), "POST");
        assert_eq!(http_method_default(HttpReq::SimplePost), "POST");
        assert_eq!(http_method_default(HttpReq::Put), "PUT");
    }

    #[test]
    fn test_is_fatal_error() {
        // Fatal errors
        assert!(is_fatal_error(CurlError::FailedInit));
        assert!(is_fatal_error(CurlError::OutOfMemory));
        assert!(is_fatal_error(CurlError::UnknownOption));
        assert!(is_fatal_error(CurlError::BadFunctionArgument));

        // Non-fatal errors
        assert!(!is_fatal_error(CurlError::Ok));
        assert!(!is_fatal_error(CurlError::CouldntConnect));
        assert!(!is_fatal_error(CurlError::OperationTimedOut));
        assert!(!is_fatal_error(CurlError::HttpReturnedError));
        assert!(!is_fatal_error(CurlError::SslConnectError));
        assert!(!is_fatal_error(CurlError::WriteError));
    }

    #[test]
    fn test_result_text() {
        assert_eq!(result_text(CurlError::Ok), "No error");
        assert_eq!(
            result_text(CurlError::CouldntConnect),
            "Could not connect to server"
        );
        assert_eq!(
            result_text(CurlError::OperationTimedOut),
            "Timeout was reached"
        );
        assert_eq!(result_text(CurlError::OutOfMemory), "Out of memory");
    }

    #[test]
    fn test_output_expected_no_upload() {
        assert!(output_expected("http://example.com", None));
        assert!(output_expected("ftp://example.com", None));
    }

    #[test]
    fn test_output_expected_http_upload() {
        assert!(output_expected("http://example.com", Some("file.txt")));
        assert!(output_expected("https://example.com", Some("file.txt")));
        assert!(output_expected("HTTP://EXAMPLE.COM", Some("file.txt")));
    }

    #[test]
    fn test_output_expected_non_http_upload() {
        assert!(!output_expected("ftp://example.com", Some("file.txt")));
        assert!(!output_expected("sftp://example.com", Some("file.txt")));
    }

    #[test]
    fn test_stdin_upload() {
        assert!(stdin_upload("-"));
        assert!(stdin_upload("."));
        assert!(!stdin_upload("file.txt"));
        assert!(!stdin_upload(""));
        assert!(!stdin_upload("--"));
    }

    #[test]
    fn test_is_pkcs11_uri() {
        assert!(is_pkcs11_uri("pkcs11:token=mytoken"));
        assert!(is_pkcs11_uri("PKCS11:token=mytoken"));
        assert!(is_pkcs11_uri("Pkcs11:object=mykey"));
        assert!(!is_pkcs11_uri("pem:mycert"));
        assert!(!is_pkcs11_uri("pkcs1"));
        assert!(!is_pkcs11_uri(""));
    }

    #[test]
    fn test_set_cert_types_pkcs11() {
        let mut config = OperationConfig::new();
        config.cert = Some("pkcs11:token=test".to_string());
        config.key = Some("pkcs11:object=key".to_string());

        set_cert_types(&mut config);

        assert_eq!(config.cert_type.as_deref(), Some("ENG"));
        assert_eq!(config.key_type.as_deref(), Some("ENG"));
    }

    #[test]
    fn test_set_cert_types_preserves_explicit() {
        let mut config = OperationConfig::new();
        config.cert = Some("pkcs11:token=test".to_string());
        config.cert_type = Some("PEM".to_string());

        set_cert_types(&mut config);

        // Explicit type should NOT be overridden.
        assert_eq!(config.cert_type.as_deref(), Some("PEM"));
    }

    #[test]
    fn test_set_cert_types_non_pkcs11() {
        let mut config = OperationConfig::new();
        config.cert = Some("/path/to/cert.pem".to_string());

        set_cert_types(&mut config);

        // Non-PKCS#11 cert should not get a type set.
        assert!(config.cert_type.is_none());
    }

    #[test]
    fn test_percent_encode_filename() {
        assert_eq!(percent_encode_filename("hello.txt"), "hello.txt");
        assert_eq!(percent_encode_filename("hello world"), "hello%20world");
        assert_eq!(percent_encode_filename("file&name"), "file%26name");
        assert_eq!(percent_encode_filename("a/b"), "a%2Fb");
    }

    #[test]
    fn test_extract_filename_from_path_basic() {
        assert_eq!(extract_filename_from_path("/dir/file.txt"), Some("file.txt"));
        assert_eq!(extract_filename_from_path("/dir/"), Some("dir"));
        assert_eq!(extract_filename_from_path("/"), None);
        assert_eq!(extract_filename_from_path("file.txt"), Some("file.txt"));
    }

    #[test]
    fn test_extract_filename_from_path_trailing_slash() {
        // With trailing slash, strip it and use the directory name.
        assert_eq!(extract_filename_from_path("/a/b/"), Some("b"));
        assert_eq!(extract_filename_from_path("/a/"), Some("a"));
    }

    #[test]
    fn test_etag_store_no_file_configured() {
        let config = OperationConfig::new();
        // No etag_save_file configured — should be a no-op.
        assert!(etag_store(&config, "\"etag-value\"").is_ok());
    }

    #[test]
    fn test_url_error_message_variants() {
        use curl_rs_lib::CurlUrlError;
        assert_eq!(
            url_error_message(&CurlUrlError::MalformedInput),
            "Malformed URL input"
        );
        assert_eq!(
            url_error_message(&CurlUrlError::BadPortNumber),
            "Bad port number in URL"
        );
        assert_eq!(
            url_error_message(&CurlUrlError::UnsupportedScheme),
            "Unsupported URL scheme"
        );
        assert_eq!(
            url_error_message(&CurlUrlError::BadHostname),
            "Bad hostname in URL"
        );
        assert_eq!(
            url_error_message(&CurlUrlError::BadQuery),
            "Bad query in URL"
        );
        assert_eq!(
            url_error_message(&CurlUrlError::TooLarge),
            "URL field too large"
        );
    }

    #[test]
    fn test_etag_store_stdout_sentinel() {
        let mut config = OperationConfig::new();
        config.etag_save_file = Some("-".to_string());
        // Stdout mode — should succeed without writing.
        assert!(etag_store(&config, "\"etag-value\"").is_ok());
    }
}
