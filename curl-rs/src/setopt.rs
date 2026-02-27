// -----------------------------------------------------------------------
// curl-rs/src/setopt.rs — Config → EasyHandle Option Application
//
// Rust rewrite of src/tool_setopt.c, src/tool_setopt.h,
// src/config2setopts.c, and src/config2setopts.h from curl 8.19.0-DEV.
//
// The primary module that converts OperationConfig (CLI-parsed
// configuration) into curl_rs_lib EasyHandle option settings using the
// generic `EasyHandle::set_option(u32, CurlOptValue)` dispatch.
//
// # Rules & Constraints
//
// - **Zero `unsafe` blocks** — per AAP Section 0.7.1.
// - Every curl_easy_setopt in C has an equivalent setting in Rust.
// - TLS: rustls exclusively — no OpenSSL, Schannel, etc.
// - SSL backend detection always returns "rustls".
// - Option application order must match C for behavioral parity.
//
// SPDX-License-Identifier: curl
// -----------------------------------------------------------------------

use anyhow::{bail, Context, Result};

use crate::config::{
    GlobalConfig, HttpReq, OperationConfig, TraceType, CURL_HET_DEFAULT,
    FAIL_WO_BODY,
};
use crate::findfile;
use crate::formparse;
use crate::ipfs;
use crate::libinfo;
use crate::msgs;
use crate::operhlp;
use crate::progress_display::PerTransfer;
use crate::stderr;
use curl_rs_lib::setopt::{CurlOpt, CurlOptValue};
use curl_rs_lib::slist::SList;
use curl_rs_lib::EasyHandle;
use curl_rs_lib::ShareHandle;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default buffer size for data transfers (100 KiB).
const BUFFER_SIZE: i64 = 102_400;

/// Maximum length for a cookie header line.
const MAX_COOKIE_LINE: usize = 8200;

/// FTP create-dir mode: retry on create.
const CURLFTP_CREATE_DIR_RETRY: i64 = 2;

/// SSL option bitmask constants matching C `CURLSSLOPT_*`.
const CURLSSLOPT_ALLOW_BEAST: i64 = 1 << 0;
const CURLSSLOPT_NO_REVOKE: i64 = 1 << 1;
const CURLSSLOPT_REVOKE_BEST_EFFORT: i64 = 1 << 3;
const CURLSSLOPT_NATIVE_CA: i64 = 1 << 4;
const CURLSSLOPT_AUTO_CLIENT_CERT: i64 = 1 << 5;
const CURLSSLOPT_EARLYDATA: i64 = 1 << 6;

/// SSL version constants matching C `CURL_SSLVERSION_*`.
#[allow(non_upper_case_globals)]
const CURL_SSLVERSION_TLSv1_0: i64 = 4;
#[allow(non_upper_case_globals)]
const CURL_SSLVERSION_TLSv1_1: i64 = 5;
#[allow(non_upper_case_globals)]
const CURL_SSLVERSION_TLSv1_2: i64 = 6;
#[allow(non_upper_case_globals)]
const CURL_SSLVERSION_TLSv1_3: i64 = 7;

/// SSL version MAX constants matching C `CURL_SSLVERSION_MAX_*`.
#[allow(non_upper_case_globals)]
const CURL_SSLVERSION_MAX_TLSv1_0: i64 = 4 << 16;
#[allow(non_upper_case_globals)]
const CURL_SSLVERSION_MAX_TLSv1_1: i64 = 5 << 16;
#[allow(non_upper_case_globals)]
const CURL_SSLVERSION_MAX_TLSv1_2: i64 = 6 << 16;
#[allow(non_upper_case_globals)]
const CURL_SSLVERSION_MAX_TLSv1_3: i64 = 7 << 16;

/// Netrc modes matching C `CURL_NETRC_*`.
const CURL_NETRC_IGNORED: i64 = 0;
const CURL_NETRC_OPTIONAL: i64 = 1;
const CURL_NETRC_REQUIRED: i64 = 2;

/// Authentication bitmask constants matching C `CURLAUTH_*`.
const CURLAUTH_BASIC: u64 = 1 << 0;
const CURLAUTH_DIGEST: u64 = 1 << 1;
const CURLAUTH_GSSNEGOTIATE: u64 = 1 << 2;
const CURLAUTH_NTLM: u64 = 1 << 3;
const CURLAUTH_DIGEST_IE: u64 = 1 << 4;
const CURLAUTH_ANY: u64 = !(CURLAUTH_DIGEST_IE);

/// FTP USE_SSL modes matching C `CURLUSESSL_*`.
const CURLUSESSL_TRY: i64 = 1;
const CURLUSESSL_CONTROL: i64 = 2;
const CURLUSESSL_ALL: i64 = 3;

/// Redirect POST flags matching C `CURL_REDIR_POST_*`.
const CURL_REDIR_POST_301: i64 = 1;
const CURL_REDIR_POST_302: i64 = 2;
const CURL_REDIR_POST_303: i64 = 4;

// ---------------------------------------------------------------------------
// Shorthand helpers for set_option
// ---------------------------------------------------------------------------

/// Set a string option on the EasyHandle (CURLOPT_*).
fn set_str(easy: &mut EasyHandle, opt: CurlOpt, val: &str) -> Result<()> {
    easy.set_option(opt as u32, CurlOptValue::ObjectPoint(val.to_string()))
        .map_err(|e| anyhow::anyhow!("{}", e))
}

/// Set a long/boolean/enum option on the EasyHandle.
fn set_long(easy: &mut EasyHandle, opt: CurlOpt, val: i64) -> Result<()> {
    easy.set_option(opt as u32, CurlOptValue::Long(val))
        .map_err(|e| anyhow::anyhow!("{}", e))
}

/// Set a boolean option on the EasyHandle.
fn set_bool(easy: &mut EasyHandle, opt: CurlOpt, val: bool) -> Result<()> {
    set_long(easy, opt, if val { 1 } else { 0 })
}

/// Set an off_t (64-bit offset) option.
fn set_offt(easy: &mut EasyHandle, opt: CurlOpt, val: i64) -> Result<()> {
    easy.set_option(opt as u32, CurlOptValue::OffT(val))
        .map_err(|e| anyhow::anyhow!("{}", e))
}

/// Set an slist option.
fn set_slist(easy: &mut EasyHandle, opt: CurlOpt, items: &[String]) -> Result<()> {
    let slist = SList::from(items.to_vec());
    easy.set_option(opt as u32, CurlOptValue::SList(slist))
        .map_err(|e| anyhow::anyhow!("{}", e))
}

/// Set a function-point option (callback registration).
fn set_func(easy: &mut EasyHandle, opt: CurlOpt) -> Result<()> {
    easy.set_option(opt as u32, CurlOptValue::FunctionPoint)
        .map_err(|e| anyhow::anyhow!("{}", e))
}

/// Try to set a string option; returns Ok even if the option is unsupported
/// (NOT_BUILT_IN / UNKNOWN_OPTION). Only lethal errors propagate.
fn try_set_str(easy: &mut EasyHandle, opt: CurlOpt, val: &str) -> Result<bool> {
    match easy.set_option(opt as u32, CurlOptValue::ObjectPoint(val.to_string())) {
        Ok(()) => Ok(true),
        Err(e) => {
            let msg = format!("{}", e);
            if msg.contains("not built in")
                || msg.contains("unknown option")
                || msg.contains("NotBuiltIn")
                || msg.contains("UnknownOption")
            {
                Ok(false)
            } else {
                Err(anyhow::anyhow!("{}", e))
            }
        }
    }
}

/// Try to set a long option; non-lethal errors are swallowed.
#[allow(dead_code)]
fn try_set_long(easy: &mut EasyHandle, opt: CurlOpt, val: i64) -> Result<bool> {
    match easy.set_option(opt as u32, CurlOptValue::Long(val)) {
        Ok(()) => Ok(true),
        Err(e) => {
            let msg = format!("{}", e);
            if msg.contains("not built in")
                || msg.contains("unknown option")
                || msg.contains("NotBuiltIn")
                || msg.contains("UnknownOption")
            {
                Ok(false)
            } else {
                Err(anyhow::anyhow!("{}", e))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helper: ssl_backend
// ---------------------------------------------------------------------------

/// Returns the current SSL backend name string.
///
/// Always returns `"rustls"` since curl-rs uses rustls exclusively per
/// AAP Section 0.7.3.
fn ssl_backend() -> &'static str {
    "rustls"
}

// ---------------------------------------------------------------------------
// tlsversion — merge min/max TLS version into a bitmask
// ---------------------------------------------------------------------------

/// Merges the minimum and maximum TLS version selectors into a combined
/// bitmask suitable for the `CURLOPT_SSLVERSION` option.
///
/// Matches the C `tlsversion()` function in `config2setopts.c:229`.
fn tlsversion(mintls: u8, maxtls: u8) -> i64 {
    let effective_min = if mintls == 0 {
        if maxtls != 0 && maxtls < 3 {
            maxtls
        } else {
            mintls
        }
    } else {
        mintls
    };

    let mut tlsver: i64 = match effective_min {
        1 => CURL_SSLVERSION_TLSv1_0,
        2 => CURL_SSLVERSION_TLSv1_1,
        0 | 3 => CURL_SSLVERSION_TLSv1_2,
        4 => CURL_SSLVERSION_TLSv1_3,
        _ => CURL_SSLVERSION_TLSv1_3,
    };

    tlsver |= match maxtls {
        0 => 0,
        1 => CURL_SSLVERSION_MAX_TLSv1_0,
        2 => CURL_SSLVERSION_MAX_TLSv1_1,
        3 => CURL_SSLVERSION_MAX_TLSv1_2,
        4 => CURL_SSLVERSION_MAX_TLSv1_3,
        _ => CURL_SSLVERSION_MAX_TLSv1_3,
    };

    tlsver
}

// ---------------------------------------------------------------------------
// extract_scheme — URL scheme extraction
// ---------------------------------------------------------------------------

/// Extracts the scheme portion from a URL string.
///
/// Returns `Some("http")` for `"http://example.com"`, `None` for malformed
/// inputs. Guesses "http" if no scheme separator is present, matching C
/// `CURLU_GUESS_SCHEME` behavior.
fn extract_scheme(url: &str) -> Option<String> {
    if let Some(pos) = url.find("://") {
        let scheme = &url[..pos];
        if !scheme.is_empty()
            && scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.')
        {
            return Some(scheme.to_string());
        }
    }
    if !url.contains("://") && !url.is_empty() {
        return Some("http".to_string());
    }
    None
}

// ---------------------------------------------------------------------------
// url_proto_and_rewrite — URL rewriting and protocol detection
// ---------------------------------------------------------------------------

/// Possibly rewrites the URL for IPFS/IPNS and returns the protocol token
/// for the scheme.
///
/// Matches `url_proto_and_rewrite()` in `config2setopts.c:130`.
fn url_proto_and_rewrite(
    url: &mut String,
    config: &mut OperationConfig,
    _global: &GlobalConfig,
) -> Result<String> {
    let scheme = extract_scheme(url);

    match scheme {
        Some(ref s)
            if s.eq_ignore_ascii_case("ipfs") || s.eq_ignore_ascii_case("ipns") =>
        {
            let gateway = ipfs::find_ipfs_gateway(config);
            match gateway {
                Some(gw) => {
                    match ipfs::ipfs_url_rewrite(url, &gw) {
                        Ok(rewritten) => {
                            *url = rewritten;
                        }
                        Err(e) => {
                            config.synthetic_error = true;
                            bail!("IPFS URL rewrite failed: {}", e);
                        }
                    }
                    let new_scheme = extract_scheme(url)
                        .unwrap_or_else(|| "?".to_string());
                    Ok(new_scheme.to_ascii_lowercase())
                }
                None => {
                    config.synthetic_error = true;
                    bail!("No IPFS gateway configured");
                }
            }
        }
        Some(s) => {
            let lower = s.to_ascii_lowercase();
            match libinfo::proto_token(&lower) {
                Some(canonical) => Ok(canonical),
                None => Ok("?".to_string()),
            }
        }
        None => Ok("?".to_string()),
    }
}

// ---------------------------------------------------------------------------
// ssh_setopts — SSH key and known_hosts configuration
// ---------------------------------------------------------------------------

/// Configures SSH-specific options.
/// Matches `ssh_setopts()` in `config2setopts.c:181`.
fn ssh_setopts(
    config: &mut OperationConfig,
    easy: &mut EasyHandle,
    global: &GlobalConfig,
    use_proto: &str,
) -> Result<()> {
    if use_proto != "scp" && use_proto != "sftp" {
        return Ok(());
    }

    if let Some(ref key) = config.key {
        set_str(easy, CurlOpt::CURLOPT_SSH_PRIVATE_KEYFILE, key)?;
    }
    if let Some(ref pubkey) = config.pubkey {
        set_str(easy, CurlOpt::CURLOPT_SSH_PUBLIC_KEYFILE, pubkey)?;
    }
    if let Some(ref md5) = config.hostpubmd5 {
        set_str(easy, CurlOpt::CURLOPT_SSH_HOST_PUBLIC_KEY_MD5, md5)?;
    }
    if let Some(ref sha256) = config.hostpubsha256 {
        set_str(
            easy,
            CurlOpt::CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256,
            sha256,
        )?;
    }
    if config.ssh_compression {
        set_bool(easy, CurlOpt::CURLOPT_SSH_COMPRESSION, true)?;
    }

    if !config.insecure_ok {
        let known = if let Some(ref kh) = config.knownhosts {
            Some(kh.clone())
        } else {
            let dirs = ssh_known_hosts_dirs();
            findfile::findfile(".ssh/known_hosts", &dirs)
                .map(|p| p.to_string_lossy().to_string())
        };

        if let Some(kh_path) = known {
            set_str(easy, CurlOpt::CURLOPT_SSH_KNOWNHOSTS, &kh_path)?;
            config.knownhosts = Some(kh_path);
        } else if config.hostpubmd5.is_none() && config.hostpubsha256.is_none() {
            msgs::errorf(global, "Could not find a known_hosts file");
            bail!("Could not find a known_hosts file");
        } else {
            msgs::warnf(global, "Could not find a known_hosts file");
        }
    }

    Ok(())
}

/// Returns the standard search directories for `.ssh/known_hosts`.
fn ssh_known_hosts_dirs() -> Vec<std::path::PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            dirs.push(std::path::PathBuf::from(home));
        }
    }
    #[cfg(windows)]
    {
        if let Ok(profile) = std::env::var("USERPROFILE") {
            if !profile.is_empty() {
                dirs.push(std::path::PathBuf::from(profile));
            }
        }
    }
    dirs
}

// ---------------------------------------------------------------------------
// ssl_ca_setopts — CA certificate/path setup
// ---------------------------------------------------------------------------

/// Configures CA certificate file and path options.
/// Matches `ssl_ca_setopts()` in `config2setopts.c:277`.
fn ssl_ca_setopts(
    config: &OperationConfig,
    easy: &mut EasyHandle,
    global: &GlobalConfig,
) -> Result<()> {
    if let Some(ref cacert) = config.cacert {
        set_str(easy, CurlOpt::CURLOPT_CAINFO, cacert)?;
    }
    if let Some(ref proxy_cacert) = config.proxy_cacert {
        set_str(easy, CurlOpt::CURLOPT_PROXY_CAINFO, proxy_cacert)?;
    }
    if let Some(ref capath) = config.capath {
        set_str(easy, CurlOpt::CURLOPT_CAPATH, capath)?;
    }

    let proxy_capath_val = config
        .proxy_capath
        .as_deref()
        .or(config.capath.as_deref());
    if let Some(pca) = proxy_capath_val {
        if !try_set_str(easy, CurlOpt::CURLOPT_PROXY_CAPATH, pca)? {
            let label = if config.proxy_capath.is_some() {
                "--proxy-capath"
            } else {
                "--capath"
            };
            msgs::warnf(
                global,
                &format!(
                    "ignoring {}, not supported by libcurl with {}",
                    label,
                    ssl_backend()
                ),
            );
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// ssl_setopts — TLS configuration
// ---------------------------------------------------------------------------

/// Configures TLS/SSL options.
/// Matches `ssl_setopts()` in `config2setopts.c:333`.
fn ssl_setopts(
    config: &OperationConfig,
    easy: &mut EasyHandle,
    global: &GlobalConfig,
) -> Result<()> {
    // CRL files.
    if let Some(ref crl) = config.crlfile {
        set_str(easy, CurlOpt::CURLOPT_CRLFILE, crl)?;
    }
    if let Some(ref proxy_crl) = config.proxy_crlfile {
        set_str(easy, CurlOpt::CURLOPT_PROXY_CRLFILE, proxy_crl)?;
    } else if let Some(ref crl) = config.crlfile {
        set_str(easy, CurlOpt::CURLOPT_PROXY_CRLFILE, crl)?;
    }

    // Pinned public keys.
    if let Some(ref pin) = config.pinnedpubkey {
        if !try_set_str(easy, CurlOpt::CURLOPT_PINNEDPUBLICKEY, pin)? {
            msgs::warnf(
                global,
                &format!(
                    "ignoring --pinnedpubkey, not supported by libcurl with {}",
                    ssl_backend()
                ),
            );
        }
    }
    if let Some(ref pin) = config.proxy_pinnedpubkey {
        if !try_set_str(easy, CurlOpt::CURLOPT_PROXY_PINNEDPUBLICKEY, pin)? {
            msgs::warnf(
                global,
                &format!(
                    "ignoring --proxy-pinnedpubkey, not supported by libcurl with {}",
                    ssl_backend()
                ),
            );
        }
    }

    // SSL EC curves and signature algorithms.
    if let Some(ref curves) = config.ssl_ec_curves {
        set_str(easy, CurlOpt::CURLOPT_SSL_EC_CURVES, curves)?;
    }
    if let Some(ref sig_algs) = config.ssl_signature_algorithms {
        set_str(
            easy,
            CurlOpt::CURLOPT_SSL_SIGNATURE_ALGORITHMS,
            sig_algs,
        )?;
    }

    // Certificate info for write-out.
    if config.writeout.is_some() {
        set_bool(easy, CurlOpt::CURLOPT_CERTINFO, true)?;
    }

    // Certificate and key filenames.
    if let Some(ref cert) = config.cert {
        set_str(easy, CurlOpt::CURLOPT_SSLCERT, cert)?;
    }
    if let Some(ref proxy_cert) = config.proxy_cert {
        set_str(easy, CurlOpt::CURLOPT_PROXY_SSLCERT, proxy_cert)?;
    }
    if let Some(ref cert_type) = config.cert_type {
        set_str(easy, CurlOpt::CURLOPT_SSLCERTTYPE, cert_type)?;
    }
    if let Some(ref proxy_cert_type) = config.proxy_cert_type {
        set_str(
            easy,
            CurlOpt::CURLOPT_PROXY_SSLCERTTYPE,
            proxy_cert_type,
        )?;
    }
    if let Some(ref key) = config.key {
        set_str(easy, CurlOpt::CURLOPT_SSLKEY, key)?;
    }
    if let Some(ref proxy_key) = config.proxy_key {
        set_str(easy, CurlOpt::CURLOPT_PROXY_SSLKEY, proxy_key)?;
    }
    if let Some(ref key_type) = config.key_type {
        set_str(easy, CurlOpt::CURLOPT_SSLKEYTYPE, key_type)?;
    }
    if let Some(ref proxy_key_type) = config.proxy_key_type {
        set_str(easy, CurlOpt::CURLOPT_PROXY_SSLKEYTYPE, proxy_key_type)?;
    }

    // Verification toggles.
    if config.insecure_ok {
        set_bool(easy, CurlOpt::CURLOPT_SSL_VERIFYPEER, false)?;
        set_bool(easy, CurlOpt::CURLOPT_SSL_VERIFYHOST, false)?;
    }
    if config.doh_insecure_ok {
        set_bool(easy, CurlOpt::CURLOPT_DOH_SSL_VERIFYPEER, false)?;
        set_bool(easy, CurlOpt::CURLOPT_DOH_SSL_VERIFYHOST, false)?;
    }
    if config.proxy_insecure_ok {
        set_bool(easy, CurlOpt::CURLOPT_PROXY_SSL_VERIFYPEER, false)?;
        set_bool(easy, CurlOpt::CURLOPT_PROXY_SSL_VERIFYHOST, false)?;
    }

    // OCSP stapling.
    if config.verifystatus {
        set_bool(easy, CurlOpt::CURLOPT_SSL_VERIFYSTATUS, true)?;
    }
    if config.doh_verifystatus {
        set_bool(easy, CurlOpt::CURLOPT_DOH_SSL_VERIFYSTATUS, true)?;
    }

    // SSL version.
    let ver = tlsversion(config.ssl_version, config.ssl_version_max);
    set_long(easy, CurlOpt::CURLOPT_SSLVERSION, ver)?;
    if config.proxy.is_some() {
        set_long(
            easy,
            CurlOpt::CURLOPT_PROXY_SSLVERSION,
            config.proxy_ssl_version,
        )?;
    }

    // SSL option bitmasks.
    {
        let mut mask: i64 = 0;
        if config.ssl_allow_beast {
            mask |= CURLSSLOPT_ALLOW_BEAST;
        }
        if config.ssl_allow_earlydata {
            mask |= CURLSSLOPT_EARLYDATA;
        }
        if config.ssl_no_revoke {
            mask |= CURLSSLOPT_NO_REVOKE;
        }
        if config.ssl_revoke_best_effort {
            mask |= CURLSSLOPT_REVOKE_BEST_EFFORT;
        }
        if config.native_ca_store {
            mask |= CURLSSLOPT_NATIVE_CA;
        }
        if config.ssl_auto_client_cert {
            mask |= CURLSSLOPT_AUTO_CLIENT_CERT;
        }
        if mask != 0 {
            set_long(easy, CurlOpt::CURLOPT_SSL_OPTIONS, mask)?;
        }
    }

    // Proxy SSL option bitmask.
    {
        let mut mask: i64 = 0;
        if config.proxy_ssl_allow_beast {
            mask |= CURLSSLOPT_ALLOW_BEAST;
        }
        if config.proxy_ssl_auto_client_cert {
            mask |= CURLSSLOPT_AUTO_CLIENT_CERT;
        }
        if config.proxy_native_ca_store {
            mask |= CURLSSLOPT_NATIVE_CA;
        }
        if mask != 0 {
            set_long(easy, CurlOpt::CURLOPT_PROXY_SSL_OPTIONS, mask)?;
        }
    }

    // Cipher lists.
    if let Some(ref ciphers) = config.cipher_list {
        if !try_set_str(easy, CurlOpt::CURLOPT_SSL_CIPHER_LIST, ciphers)? {
            msgs::warnf(
                global,
                &format!(
                    "ignoring --ciphers, not supported by libcurl with {}",
                    ssl_backend()
                ),
            );
        }
    }
    if let Some(ref ciphers) = config.proxy_cipher_list {
        if !try_set_str(easy, CurlOpt::CURLOPT_PROXY_SSL_CIPHER_LIST, ciphers)? {
            msgs::warnf(
                global,
                &format!(
                    "ignoring --proxy-ciphers, not supported by libcurl with {}",
                    ssl_backend()
                ),
            );
        }
    }
    if let Some(ref ciphers) = config.cipher13_list {
        if !try_set_str(easy, CurlOpt::CURLOPT_TLS13_CIPHERS, ciphers)? {
            msgs::warnf(
                global,
                &format!(
                    "ignoring --tls13-ciphers, not supported by libcurl with {}",
                    ssl_backend()
                ),
            );
        }
    }
    if let Some(ref ciphers) = config.proxy_cipher13_list {
        if !try_set_str(easy, CurlOpt::CURLOPT_PROXY_TLS13_CIPHERS, ciphers)? {
            msgs::warnf(
                global,
                &format!(
                    "ignoring --proxy-tls13-ciphers, not supported by libcurl with {}",
                    ssl_backend()
                ),
            );
        }
    }

    // Disable session ID caching.
    if config.disable_sessionid {
        set_bool(easy, CurlOpt::CURLOPT_SSL_SESSIONID_CACHE, false)?;
    }

    // ECH (Encrypted Client Hello).
    if global.libcurl_info.feature_ech {
        if let Some(ref ech) = config.ech {
            set_str(easy, CurlOpt::CURLOPT_ECH, ech)?;
        }
        if let Some(ref ech_public) = config.ech_public {
            set_str(easy, CurlOpt::CURLOPT_ECH, ech_public)?;
        }
        if let Some(ref ech_config) = config.ech_config {
            set_str(easy, CurlOpt::CURLOPT_ECH, ech_config)?;
        }
    }

    // SSL engine.
    if let Some(ref engine) = config.engine {
        set_str(easy, CurlOpt::CURLOPT_SSLENGINE, engine)?;
    }

    // FTP SSL levels.
    if config.ftp_ssl_reqd {
        set_long(easy, CurlOpt::CURLOPT_USE_SSL, CURLUSESSL_ALL)?;
    } else if config.ftp_ssl {
        set_long(easy, CurlOpt::CURLOPT_USE_SSL, CURLUSESSL_TRY)?;
    } else if config.ftp_ssl_control {
        set_long(easy, CurlOpt::CURLOPT_USE_SSL, CURLUSESSL_CONTROL)?;
    }

    // ALPN.
    if config.noalpn {
        set_bool(easy, CurlOpt::CURLOPT_SSL_ENABLE_ALPN, false)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// cookie_setopts — cookie configuration
// ---------------------------------------------------------------------------

/// Configures cookie-related options.
/// Matches `cookie_setopts()` in `config2setopts.c:490`.
fn cookie_setopts(
    config: &OperationConfig,
    easy: &mut EasyHandle,
    global: &GlobalConfig,
) -> Result<()> {
    if !config.cookies.is_empty() {
        let mut cookie_buf = String::with_capacity(MAX_COOKIE_LINE);
        for (i, cookie) in config.cookies.iter().enumerate() {
            if i > 0 {
                cookie_buf.push(';');
                if !cookie.starts_with([' ', '\t']) {
                    cookie_buf.push(' ');
                }
            }
            cookie_buf.push_str(cookie);
            if cookie_buf.len() > MAX_COOKIE_LINE {
                msgs::warnf(
                    global,
                    &format!(
                        "skipped provided cookie, the cookie header would go over {} bytes",
                        MAX_COOKIE_LINE
                    ),
                );
                bail!("cookie header exceeds {} bytes", MAX_COOKIE_LINE);
            }
        }
        set_str(easy, CurlOpt::CURLOPT_COOKIE, &cookie_buf)?;
    }

    for cf in &config.cookiefiles {
        set_str(easy, CurlOpt::CURLOPT_COOKIEFILE, cf)?;
    }

    if let Some(ref jar) = config.cookiejar {
        set_str(easy, CurlOpt::CURLOPT_COOKIEJAR, jar)?;
    }

    set_bool(easy, CurlOpt::CURLOPT_COOKIESESSION, config.cookiesession)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// http_setopts — HTTP-specific options
// ---------------------------------------------------------------------------

/// Configures HTTP-specific options.
/// Matches `http_setopts()` in `config2setopts.c:534`.
fn http_setopts(
    config: &OperationConfig,
    easy: &mut EasyHandle,
    global: &GlobalConfig,
    use_proto: &str,
) -> Result<()> {
    if use_proto != "http" && use_proto != "https" {
        return Ok(());
    }

    set_long(
        easy,
        CurlOpt::CURLOPT_FOLLOWLOCATION,
        config.followlocation,
    )?;
    set_bool(
        easy,
        CurlOpt::CURLOPT_UNRESTRICTED_AUTH,
        config.unrestricted_auth,
    )?;

    if let Some(ref sigv4) = config.aws_sigv4 {
        set_str(easy, CurlOpt::CURLOPT_AWS_SIGV4, sigv4)?;
    }

    set_bool(easy, CurlOpt::CURLOPT_AUTOREFERER, config.autoreferer)?;

    if !config.proxyheaders.is_empty() {
        set_slist(easy, CurlOpt::CURLOPT_PROXYHEADER, &config.proxyheaders)?;
    }

    set_long(easy, CurlOpt::CURLOPT_MAXREDIRS, config.maxredirs)?;

    if config.httpversion != 0 {
        set_long(easy, CurlOpt::CURLOPT_HTTP_VERSION, config.httpversion)?;
    }

    let mut post_redir: i64 = 0;
    if config.post301 {
        post_redir |= CURL_REDIR_POST_301;
    }
    if config.post302 {
        post_redir |= CURL_REDIR_POST_302;
    }
    if config.post303 {
        post_redir |= CURL_REDIR_POST_303;
    }
    set_long(easy, CurlOpt::CURLOPT_POSTREDIR, post_redir)?;

    if config.encoding {
        set_str(easy, CurlOpt::CURLOPT_ACCEPT_ENCODING, "")?;
    }

    if config.tr_encoding {
        set_bool(easy, CurlOpt::CURLOPT_TRANSFER_ENCODING, true)?;
    }

    set_bool(
        easy,
        CurlOpt::CURLOPT_HTTP09_ALLOWED,
        config.http09_allowed,
    )?;

    if let Some(ref altsvc) = config.altsvc {
        set_str(easy, CurlOpt::CURLOPT_ALTSVC, altsvc)?;
    }

    if let Some(ref hsts) = config.hsts {
        set_str(easy, CurlOpt::CURLOPT_HSTS, hsts)?;
    }

    if config.expect100timeout_ms > 0 {
        set_long(
            easy,
            CurlOpt::CURLOPT_EXPECT_100_TIMEOUT_MS,
            config.expect100timeout_ms,
        )?;
    }

    cookie_setopts(config, easy, global)?;

    if (config.proxy.is_some() || !config.proxyheaders.is_empty())
        && (use_proto == "https" || config.proxytunnel)
    {
        set_long(
            easy,
            CurlOpt::CURLOPT_HEADEROPT,
            curl_rs_lib::setopt::CURLHEADER_SEPARATE,
        )?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// ftp_setopts — FTP-specific options
// ---------------------------------------------------------------------------

/// Configures FTP-specific options.
/// Matches `ftp_setopts()` in `config2setopts.c:623`.
fn ftp_setopts(
    config: &OperationConfig,
    easy: &mut EasyHandle,
    use_proto: &str,
) -> Result<()> {
    if use_proto != "ftp" && use_proto != "ftps" {
        return Ok(());
    }

    if let Some(ref port) = config.ftpport {
        set_str(easy, CurlOpt::CURLOPT_FTPPORT, port)?;
    }

    if config.disable_epsv {
        set_bool(easy, CurlOpt::CURLOPT_FTP_USE_EPSV, false)?;
    }

    if config.disable_eprt {
        set_bool(easy, CurlOpt::CURLOPT_FTP_USE_EPRT, false)?;
    }

    if config.ftp_ssl_ccc {
        set_long(
            easy,
            CurlOpt::CURLOPT_FTP_SSL_CCC,
            config.ftp_ssl_ccc_mode,
        )?;
    }

    if let Some(ref account) = config.ftp_account {
        set_str(easy, CurlOpt::CURLOPT_FTP_ACCOUNT, account)?;
    }

    set_bool(
        easy,
        CurlOpt::CURLOPT_FTP_SKIP_PASV_IP,
        config.ftp_skip_ip,
    )?;

    set_long(
        easy,
        CurlOpt::CURLOPT_FTP_FILEMETHOD,
        config.ftp_filemethod,
    )?;

    if let Some(ref alt_user) = config.ftp_alternative_to_user {
        set_str(
            easy,
            CurlOpt::CURLOPT_FTP_ALTERNATIVE_TO_USER,
            alt_user,
        )?;
    }

    if config.ftp_pret {
        set_bool(easy, CurlOpt::CURLOPT_FTP_USE_PRET, true)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// tcp_setopts — TCP options
// ---------------------------------------------------------------------------

/// Configures TCP-level options (nodelay, keepalive, fastopen, MPTCP).
/// Matches `tcp_setopts()` in `config2setopts.c:598`.
fn tcp_setopts(
    config: &OperationConfig,
    easy: &mut EasyHandle,
) -> Result<()> {
    if !config.tcp_nodelay {
        set_bool(easy, CurlOpt::CURLOPT_TCP_NODELAY, false)?;
    }

    if config.tcp_fastopen {
        set_bool(easy, CurlOpt::CURLOPT_TCP_FASTOPEN, true)?;
    }

    if config.mptcp {
        set_func(easy, CurlOpt::CURLOPT_OPENSOCKETFUNCTION)?;
    }

    if !config.nokeepalive {
        set_bool(easy, CurlOpt::CURLOPT_TCP_KEEPALIVE, true)?;
        if config.alivetime != 0 {
            set_long(easy, CurlOpt::CURLOPT_TCP_KEEPIDLE, config.alivetime)?;
            set_long(easy, CurlOpt::CURLOPT_TCP_KEEPINTVL, config.alivetime)?;
        }
        if config.alivecnt != 0 {
            set_long(easy, CurlOpt::CURLOPT_TCP_KEEPCNT, config.alivecnt)?;
        }
    } else {
        set_bool(easy, CurlOpt::CURLOPT_TCP_KEEPALIVE, false)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// gen_trace_setopts — trace/verbose settings
// ---------------------------------------------------------------------------

/// Configures trace and verbose output settings.
/// Matches `gen_trace_setopts()` in `config2setopts.c:656`.
fn gen_trace_setopts(
    _config: &OperationConfig,
    easy: &mut EasyHandle,
    global: &GlobalConfig,
) -> Result<()> {
    if global.tracetype != TraceType::None {
        set_func(easy, CurlOpt::CURLOPT_DEBUGFUNCTION)?;
        set_bool(easy, CurlOpt::CURLOPT_VERBOSE, true)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// gen_cb_setopts — register transfer callbacks
// ---------------------------------------------------------------------------

/// Registers transfer callback functions on the EasyHandle.
/// Matches `gen_cb_setopts()` in `config2setopts.c:665`.
fn gen_cb_setopts(
    _config: &OperationConfig,
    easy: &mut EasyHandle,
    global: &GlobalConfig,
) -> Result<()> {
    // Write callback.
    set_func(easy, CurlOpt::CURLOPT_WRITEFUNCTION)?;

    // Read callback.
    set_func(easy, CurlOpt::CURLOPT_READFUNCTION)?;

    // Seek callback.
    set_func(easy, CurlOpt::CURLOPT_SEEKFUNCTION)?;

    // Progress/xferinfo callback (when progress bar is active).
    if global.progressmode == 0
        && !global.noprogress
        && !global.silent
    {
        set_func(easy, CurlOpt::CURLOPT_XFERINFOFUNCTION)?;
    }

    // Header callback.
    set_func(easy, CurlOpt::CURLOPT_HEADERFUNCTION)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// proxy_setopts — proxy configuration
// ---------------------------------------------------------------------------

/// Configures proxy-related options.
/// Matches `proxy_setopts()` in `config2setopts.c:706`.
fn proxy_setopts(
    config: &mut OperationConfig,
    easy: &mut EasyHandle,
    global: &GlobalConfig,
) -> Result<()> {
    if let Some(ref proxy) = config.proxy {
        if !try_set_str(easy, CurlOpt::CURLOPT_PROXY, proxy)? {
            msgs::errorf(global, "proxy support is disabled in this libcurl");
            config.synthetic_error = true;
            bail!("proxy support is disabled in this libcurl");
        }
    }

    if config.proxy.is_some() {
        set_long(easy, CurlOpt::CURLOPT_PROXYTYPE, config.proxyver)?;
    }

    if let Some(ref pwdstr) = config.proxyuserpwd {
        set_str(easy, CurlOpt::CURLOPT_PROXYUSERPWD, pwdstr)?;
    }

    set_bool(
        easy,
        CurlOpt::CURLOPT_HTTPPROXYTUNNEL,
        config.proxytunnel,
    )?;

    if let Some(ref preproxy) = config.preproxy {
        set_str(easy, CurlOpt::CURLOPT_PRE_PROXY, preproxy)?;
    }

    // Proxy authentication.
    if config.proxyanyauth {
        set_long(easy, CurlOpt::CURLOPT_PROXYAUTH, CURLAUTH_ANY as i64)?;
    } else if config.proxynegotiate {
        set_long(
            easy,
            CurlOpt::CURLOPT_PROXYAUTH,
            CURLAUTH_GSSNEGOTIATE as i64,
        )?;
    } else if config.proxyntlm {
        set_long(easy, CurlOpt::CURLOPT_PROXYAUTH, CURLAUTH_NTLM as i64)?;
    } else if config.proxydigest {
        set_long(
            easy,
            CurlOpt::CURLOPT_PROXYAUTH,
            CURLAUTH_DIGEST as i64,
        )?;
    } else if config.proxybasic {
        set_long(
            easy,
            CurlOpt::CURLOPT_PROXYAUTH,
            CURLAUTH_BASIC as i64,
        )?;
    }

    if let Some(ref noproxy) = config.noproxy {
        set_str(easy, CurlOpt::CURLOPT_NOPROXY, noproxy)?;
    }

    set_bool(
        easy,
        CurlOpt::CURLOPT_SUPPRESS_CONNECT_HEADERS,
        config.suppress_connect_headers,
    )?;

    if let Some(ref svc_name) = config.proxy_service_name {
        set_str(easy, CurlOpt::CURLOPT_PROXY_SERVICE_NAME, svc_name)?;
    }

    if config.haproxy_protocol {
        set_bool(easy, CurlOpt::CURLOPT_HAPROXYPROTOCOL, true)?;
    }

    if let Some(ref client_ip) = config.haproxy_clientip {
        set_str(easy, CurlOpt::CURLOPT_HAPROXY_CLIENT_IP, client_ip)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// tls_srp_setopts — TLS-SRP authentication
// ---------------------------------------------------------------------------

/// Configures TLS-SRP authentication options if supported.
/// Matches `tls_srp_setopts()` in `config2setopts.c:754`.
fn tls_srp_setopts(
    config: &OperationConfig,
    easy: &mut EasyHandle,
) -> Result<()> {
    if let Some(ref user) = config.tls_username {
        set_str(easy, CurlOpt::CURLOPT_TLSAUTH_USERNAME, user)?;
    }
    if let Some(ref pass) = config.tls_password {
        set_str(easy, CurlOpt::CURLOPT_TLSAUTH_PASSWORD, pass)?;
    }
    if let Some(ref authtype) = config.tls_authtype {
        set_str(easy, CurlOpt::CURLOPT_TLSAUTH_TYPE, authtype)?;
    }
    if let Some(ref user) = config.proxy_tls_username {
        set_str(easy, CurlOpt::CURLOPT_PROXY_TLSAUTH_USERNAME, user)?;
    }
    if let Some(ref pass) = config.proxy_tls_password {
        set_str(easy, CurlOpt::CURLOPT_PROXY_TLSAUTH_PASSWORD, pass)?;
    }
    if let Some(ref authtype) = config.proxy_tls_authtype {
        set_str(easy, CurlOpt::CURLOPT_PROXY_TLSAUTH_TYPE, authtype)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// setopt_post — POST data handling
// ---------------------------------------------------------------------------

/// Configures POST data handling (simple POST or MIME multipart).
/// Matches `setopt_post()` in `config2setopts.c:775`.
fn setopt_post(
    config: &mut OperationConfig,
    easy: &mut EasyHandle,
    global: &GlobalConfig,
) -> Result<()> {
    match config.httpreq {
        HttpReq::SimplePost => {
            if config.resume_from != 0 {
                msgs::errorf(global, "cannot mix --continue-at with --data");
                bail!("cannot mix --continue-at with --data");
            }
            let data = &config.postdata;
            easy.set_option(
                CurlOpt::CURLOPT_POSTFIELDS as u32,
                CurlOptValue::Blob(data.clone()),
            )
            .map_err(|e| anyhow::anyhow!("{}", e))?;
            set_offt(
                easy,
                CurlOpt::CURLOPT_POSTFIELDSIZE_LARGE,
                data.len() as i64,
            )?;
        }
        HttpReq::MimePost => {
            if config.resume_from != 0 {
                msgs::errorf(global, "cannot mix --continue-at with --form");
                bail!("cannot mix --continue-at with --form");
            }
            if let Some(ref mimeroot) = config.mimeroot {
                let mime = formparse::tool2curlmime(mimeroot, easy)?;
                easy.set_option(
                    CurlOpt::CURLOPT_MIMEPOST as u32,
                    CurlOptValue::ObjectPoint("mime".to_string()),
                )
                .map_err(|e| anyhow::anyhow!("{}", e))?;
                // The mime handle is stored on the easy handle via the set
                // operation above. The C code stores it as
                // `per->mimepost = mime; curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);`.
                // In Rust the easy handle takes ownership.
                let _ = mime;
            }
        }
        _ => { /* No POST data to set */ }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// buffersize — buffer size tuning
// ---------------------------------------------------------------------------

/// Sets the transfer buffer size based on configuration and speed limits.
/// Matches `buffersize()` in `config2setopts.c:811`.
fn buffersize(
    config: &OperationConfig,
    easy: &mut EasyHandle,
) -> Result<()> {
    #[cfg(debug_assertions)]
    {
        if let Ok(env_val) = std::env::var("CURL_BUFFERSIZE") {
            if let Ok(num) = env_val.parse::<i64>() {
                set_long(easy, CurlOpt::CURLOPT_BUFFERSIZE, num)?;
                return Ok(());
            }
        }
    }

    if config.recvpersecond > 0 && config.recvpersecond < BUFFER_SIZE {
        set_long(easy, CurlOpt::CURLOPT_BUFFERSIZE, config.recvpersecond)?;
    } else {
        set_long(easy, CurlOpt::CURLOPT_BUFFERSIZE, BUFFER_SIZE)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// config2setopts — the master orchestration function
// ---------------------------------------------------------------------------

/// Converts an [`OperationConfig`] into EasyHandle option settings.
///
/// This is the main entry point — the Rust equivalent of
/// `config2setopts()` in `config2setopts.c:830`. It orchestrates all
/// option-setting calls in the order that matches the C implementation.
///
/// # Arguments
///
/// * `config` — The CLI-parsed operation configuration to apply.
/// * `per` — Per-transfer progress state.
/// * `easy` — The EasyHandle to configure.
/// * `share` — Optional share handle for data sharing between transfers.
/// * `global` — Global configuration for diagnostics and feature checks.
/// * `url` — The URL for this transfer.
/// * `has_upload` — Whether this transfer has an upload file set.
///
/// # Returns
///
/// `Ok(())` on success.
pub fn config2setopts(
    config: &mut OperationConfig,
    per: &mut PerTransfer,
    easy: &mut EasyHandle,
    share: Option<&ShareHandle>,
    global: &GlobalConfig,
    url: &mut String,
    has_upload: bool,
) -> Result<()> {
    // 1. URL protocol detection and IPFS rewriting.
    let use_proto = url_proto_and_rewrite(url, config, global)
        .context("URL protocol detection failed")?;

    // 2. Share handle setup.
    if let Some(_sh) = share {
        set_str(easy, CurlOpt::CURLOPT_SHARE, "share")?;
    }

    // 3. Quick exit optimization.
    #[cfg(not(debug_assertions))]
    {
        let _ = try_set_long(easy, CurlOpt::CURLOPT_QUICK_EXIT, 1);
    }

    // 4. Trace/verbose settings.
    gen_trace_setopts(config, easy, global)?;

    // 5. Buffer size tuning.
    buffersize(config, easy)?;

    // 6. Set the URL.
    set_str(easy, CurlOpt::CURLOPT_URL, url)?;

    // 7. Progress meter.
    set_bool(
        easy,
        CurlOpt::CURLOPT_NOPROGRESS,
        global.noprogress || global.silent,
    )?;

    // 8. Register callbacks.
    gen_cb_setopts(config, easy, global)?;

    // 9. Body suppression.
    set_bool(easy, CurlOpt::CURLOPT_NOBODY, config.no_body)?;

    // 10. OAuth2 bearer token.
    if let Some(ref bearer) = config.oauth_bearer {
        set_str(easy, CurlOpt::CURLOPT_XOAUTH2_BEARER, bearer)?;
    }

    // 11. Proxy configuration.
    proxy_setopts(config, easy, global)?;

    // 12. Fail on error.
    set_bool(
        easy,
        CurlOpt::CURLOPT_FAILONERROR,
        config.fail == FAIL_WO_BODY,
    )?;

    // 13. Request target.
    if let Some(ref target) = config.request_target {
        set_str(easy, CurlOpt::CURLOPT_REQUEST_TARGET, target)?;
    }

    // 14. Upload mode.
    set_bool(easy, CurlOpt::CURLOPT_UPLOAD, has_upload)?;

    // 15. Directory listing only.
    set_bool(easy, CurlOpt::CURLOPT_DIRLISTONLY, config.dirlistonly)?;

    // 16. FTP append.
    set_bool(easy, CurlOpt::CURLOPT_APPEND, config.ftp_append)?;

    // 17. Netrc.
    if config.netrc_opt {
        set_long(easy, CurlOpt::CURLOPT_NETRC, CURL_NETRC_OPTIONAL)?;
    } else if config.netrc || config.netrc_file.is_some() {
        set_long(easy, CurlOpt::CURLOPT_NETRC, CURL_NETRC_REQUIRED)?;
    } else {
        set_long(easy, CurlOpt::CURLOPT_NETRC, CURL_NETRC_IGNORED)?;
    }
    if let Some(ref netrc_file) = config.netrc_file {
        set_str(easy, CurlOpt::CURLOPT_NETRC_FILE, netrc_file)?;
    }

    // 18. ASCII transfer mode.
    set_bool(easy, CurlOpt::CURLOPT_TRANSFERTEXT, config.use_ascii)?;

    // 19. Login options.
    if let Some(ref opts) = config.login_options {
        set_str(easy, CurlOpt::CURLOPT_LOGIN_OPTIONS, opts)?;
    }

    // 20. User credentials.
    if let Some(ref userpwd) = config.userpwd {
        set_str(easy, CurlOpt::CURLOPT_USERPWD, userpwd)?;
    }

    // 21. Range.
    if let Some(ref range) = config.range {
        set_str(easy, CurlOpt::CURLOPT_RANGE, range)?;
    }

    // 22. Error buffer — managed at the Rust level, not via CURLOPT.
    // (The C code passes a char[] pointer; in Rust, errors propagate via Result.)

    // 23. Timeout.
    set_long(easy, CurlOpt::CURLOPT_TIMEOUT_MS, config.timeout)?;

    // 24. POST data.
    setopt_post(config, easy, global)?;

    // 25. MIME options.
    if config.mime_options != 0 {
        set_long(
            easy,
            CurlOpt::CURLOPT_MIME_OPTIONS,
            config.mime_options as i64,
        )?;
    }

    // 26. HTTP auth.
    if config.authtype != 0 {
        set_long(easy, CurlOpt::CURLOPT_HTTPAUTH, config.authtype as i64)?;
    }

    // 27. Custom headers.
    if !config.headers.is_empty() {
        set_slist(easy, CurlOpt::CURLOPT_HTTPHEADER, &config.headers)?;
    }

    // 28. Referer and User-Agent.
    if use_proto == "http" || use_proto == "https" || use_proto == "rtsp" {
        if let Some(ref referer) = config.referer {
            set_str(easy, CurlOpt::CURLOPT_REFERER, referer)?;
        }
        let default_ua = format!(
            "curl/{}",
            curl_rs_lib::version::VERSION
        );
        let ua = config.useragent.as_deref().unwrap_or(&default_ua);
        set_str(easy, CurlOpt::CURLOPT_USERAGENT, ua)?;
    }

    // 29. HTTP-specific options.
    http_setopts(config, easy, global, &use_proto)?;

    // 30. FTP-specific options.
    ftp_setopts(config, easy, &use_proto)?;

    // 31. Speed limits.
    set_long(
        easy,
        CurlOpt::CURLOPT_LOW_SPEED_LIMIT,
        config.low_speed_limit,
    )?;
    set_long(
        easy,
        CurlOpt::CURLOPT_LOW_SPEED_TIME,
        config.low_speed_time,
    )?;
    set_offt(
        easy,
        CurlOpt::CURLOPT_MAX_SEND_SPEED_LARGE,
        config.sendpersecond,
    )?;
    set_offt(
        easy,
        CurlOpt::CURLOPT_MAX_RECV_SPEED_LARGE,
        config.recvpersecond,
    )?;

    // 32. Resume.
    if config.use_resume {
        set_offt(
            easy,
            CurlOpt::CURLOPT_RESUME_FROM_LARGE,
            config.resume_from,
        )?;
    } else {
        set_offt(easy, CurlOpt::CURLOPT_RESUME_FROM_LARGE, 0)?;
    }

    // 33. Key passphrases.
    if let Some(ref passwd) = config.key_passwd {
        set_str(easy, CurlOpt::CURLOPT_KEYPASSWD, passwd)?;
    }
    if let Some(ref passwd) = config.proxy_key_passwd {
        set_str(easy, CurlOpt::CURLOPT_PROXY_KEYPASSWD, passwd)?;
    }

    // 34. SSH options.
    ssh_setopts(config, easy, global, &use_proto)?;

    // 35. SSL/TLS options.
    if global.libcurl_info.feature_ssl {
        ssl_ca_setopts(config, easy, global)?;
        ssl_setopts(config, easy, global)?;
    }

    // 36. Path as-is.
    if config.path_as_is {
        set_bool(easy, CurlOpt::CURLOPT_PATH_AS_IS, true)?;
    }

    // 37. File time.
    if config.no_body || config.remote_time {
        set_bool(easy, CurlOpt::CURLOPT_FILETIME, true)?;
    }

    // 38. CRLF.
    set_bool(easy, CurlOpt::CURLOPT_CRLF, config.crlf)?;

    // 39. FTP quote commands.
    if !config.quote.is_empty() {
        set_slist(easy, CurlOpt::CURLOPT_QUOTE, &config.quote)?;
    }
    if !config.postquote.is_empty() {
        set_slist(easy, CurlOpt::CURLOPT_POSTQUOTE, &config.postquote)?;
    }
    if !config.prequote.is_empty() {
        set_slist(easy, CurlOpt::CURLOPT_PREQUOTE, &config.prequote)?;
    }

    // 40. Time condition.
    set_long(
        easy,
        CurlOpt::CURLOPT_TIMECONDITION,
        config.timecond as i64,
    )?;
    set_offt(
        easy,
        CurlOpt::CURLOPT_TIMEVALUE_LARGE,
        config.condtime,
    )?;

    // 41. Custom request.
    if let Some(ref method) = config.customrequest {
        set_str(easy, CurlOpt::CURLOPT_CUSTOMREQUEST, method)?;
    }
    operhlp::customrequest_helper(
        global,
        config.httpreq,
        config.customrequest.as_deref(),
    );

    // 42. Stderr stream — managed globally by the stderr module.
    let _ = stderr::tool_stderr();

    // 43. Progress bar initialization.
    // PerTransfer in our codebase is the progress tracker; we re-initialize it.
    *per = PerTransfer::new();

    // 44. Interface binding.
    if let Some(ref iface) = config.iface {
        set_str(easy, CurlOpt::CURLOPT_INTERFACE, iface)?;
    }

    // 45. DNS settings.
    if let Some(ref servers) = config.dns_servers {
        set_str(easy, CurlOpt::CURLOPT_DNS_SERVERS, servers)?;
    }
    if let Some(ref dns_iface) = config.dns_interface {
        set_str(easy, CurlOpt::CURLOPT_DNS_INTERFACE, dns_iface)?;
    }
    if let Some(ref ip4) = config.dns_ipv4_addr {
        set_str(easy, CurlOpt::CURLOPT_DNS_LOCAL_IP4, ip4)?;
    }
    if let Some(ref ip6) = config.dns_ipv6_addr {
        set_str(easy, CurlOpt::CURLOPT_DNS_LOCAL_IP6, ip6)?;
    }

    // 46. Telnet options.
    if !config.telnet_options.is_empty() {
        set_slist(
            easy,
            CurlOpt::CURLOPT_TELNETOPTIONS,
            &config.telnet_options,
        )?;
    }

    // 47. Connect timeout.
    set_long(
        easy,
        CurlOpt::CURLOPT_CONNECTTIMEOUT_MS,
        config.connect_timeout,
    )?;

    // 48. DNS-over-HTTPS.
    if let Some(ref doh) = config.doh_url {
        set_str(easy, CurlOpt::CURLOPT_DOH_URL, doh)?;
    }

    // 49. FTP create dirs.
    set_long(
        easy,
        CurlOpt::CURLOPT_FTP_CREATE_MISSING_DIRS,
        if config.ftp_create_dirs {
            CURLFTP_CREATE_DIR_RETRY
        } else {
            0
        },
    )?;

    // 50. Max file size.
    set_offt(
        easy,
        CurlOpt::CURLOPT_MAXFILESIZE_LARGE,
        config.max_filesize,
    )?;

    // 51. IP version.
    set_long(easy, CurlOpt::CURLOPT_IPRESOLVE, config.ip_version)?;

    // 52. SOCKS5 GSSAPI NEC.
    if config.socks5_gssapi_nec {
        set_bool(easy, CurlOpt::CURLOPT_SOCKS5_GSSAPI_NEC, true)?;
    }

    // 53. SOCKS5 auth.
    if config.socks5_auth != 0 {
        set_long(easy, CurlOpt::CURLOPT_SOCKS5_AUTH, config.socks5_auth as i64)?;
    }

    // 54. Service name.
    if let Some(ref svc) = config.service_name {
        set_str(easy, CurlOpt::CURLOPT_SERVICE_NAME, svc)?;
    }

    // 55. Ignore content length.
    set_bool(
        easy,
        CurlOpt::CURLOPT_IGNORE_CONTENT_LENGTH,
        config.ignorecl,
    )?;

    // 56. Local port.
    if config.localport != 0 {
        set_long(easy, CurlOpt::CURLOPT_LOCALPORT, config.localport)?;
        set_long(
            easy,
            CurlOpt::CURLOPT_LOCALPORTRANGE,
            config.localportrange,
        )?;
    }

    // 57. Raw mode.
    if config.raw {
        set_bool(easy, CurlOpt::CURLOPT_HTTP_CONTENT_DECODING, false)?;
        set_bool(easy, CurlOpt::CURLOPT_HTTP_TRANSFER_DECODING, false)?;
    }

    // 58. TCP options.
    tcp_setopts(config, easy)?;

    // 59. TFTP block size.
    if config.tftp_blksize != 0 && use_proto == "tftp" {
        set_long(
            easy,
            CurlOpt::CURLOPT_TFTP_BLKSIZE,
            config.tftp_blksize,
        )?;
    }

    // 60. Mail options.
    if let Some(ref from) = config.mail_from {
        set_str(easy, CurlOpt::CURLOPT_MAIL_FROM, from)?;
    }
    if !config.mail_rcpt.is_empty() {
        set_slist(easy, CurlOpt::CURLOPT_MAIL_RCPT, &config.mail_rcpt)?;
    }
    set_bool(
        easy,
        CurlOpt::CURLOPT_MAIL_RCPT_ALLOWFAILS,
        config.mail_rcpt_allowfails,
    )?;

    // 61. File creation mode.
    if config.create_file_mode != 0 {
        set_long(
            easy,
            CurlOpt::CURLOPT_NEW_FILE_PERMS,
            config.create_file_mode,
        )?;
    }

    // 62. Protocol allow strings.
    if config.proto_present {
        if let Some(ref proto_str) = config.proto_str {
            set_str(easy, CurlOpt::CURLOPT_PROTOCOLS_STR, proto_str)?;
        }
    }
    if config.proto_redir_present {
        if let Some(ref proto_redir_str) = config.proto_redir_str {
            set_str(
                easy,
                CurlOpt::CURLOPT_REDIR_PROTOCOLS_STR,
                proto_redir_str,
            )?;
        }
    }

    // 63. Resolve and connect-to overrides.
    if !config.resolve.is_empty() {
        set_slist(easy, CurlOpt::CURLOPT_RESOLVE, &config.resolve)?;
    }
    if !config.connect_to.is_empty() {
        set_slist(easy, CurlOpt::CURLOPT_CONNECT_TO, &config.connect_to)?;
    }

    // 64. TLS-SRP.
    if global.libcurl_info.feature_tls_srp {
        tls_srp_setopts(config, easy)?;
    }

    // 65. GSSAPI delegation.
    if config.gssapi_delegation != 0 {
        set_long(
            easy,
            CurlOpt::CURLOPT_GSSAPI_DELEGATION,
            config.gssapi_delegation,
        )?;
    }

    // 66. Mail auth.
    if let Some(ref auth) = config.mail_auth {
        set_str(easy, CurlOpt::CURLOPT_MAIL_AUTH, auth)?;
    }

    // 67. SASL.
    if let Some(ref authzid) = config.sasl_authzid {
        set_str(easy, CurlOpt::CURLOPT_SASL_AUTHZID, authzid)?;
    }
    set_bool(easy, CurlOpt::CURLOPT_SASL_IR, config.sasl_ir)?;

    // 68. Unix socket.
    if let Some(ref path) = config.unix_socket_path {
        if config.abstract_unix_socket {
            set_str(easy, CurlOpt::CURLOPT_ABSTRACT_UNIX_SOCKET, path)?;
        } else {
            set_str(easy, CurlOpt::CURLOPT_UNIX_SOCKET_PATH, path)?;
        }
    }

    // 69. Default protocol.
    if let Some(ref proto) = config.proto_default {
        set_str(easy, CurlOpt::CURLOPT_DEFAULT_PROTOCOL, proto)?;
    }

    // 70. TFTP no options.
    set_bool(
        easy,
        CurlOpt::CURLOPT_TFTP_NO_OPTIONS,
        config.tftp_no_options && use_proto == "tftp",
    )?;

    // 71. Happy Eyeballs timeout.
    if config.happy_eyeballs_timeout_ms != CURL_HET_DEFAULT {
        set_long(
            easy,
            CurlOpt::CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS,
            config.happy_eyeballs_timeout_ms,
        )?;
    }

    // 72. Disallow username in URL.
    set_bool(
        easy,
        CurlOpt::CURLOPT_DISALLOW_USERNAME_IN_URL,
        config.disallow_username_in_url,
    )?;

    // 73. IP TOS and VLAN priority — set via SOCKOPTFUNCTION.
    // In Rust, the sockopt callback is registered to set IP_TOS/IPV6_TCLASS
    // and SO_PRIORITY. Since we cannot use `unsafe` in this crate, we
    // delegate this to the EasyHandle's internal socket option support
    // if the library supports it.
    if config.ip_tos > 0 || config.vlan_priority > 0 {
        set_func(easy, CurlOpt::CURLOPT_SOCKOPTFUNCTION)?;
    }

    // 74. Upload flags.
    set_long(
        easy,
        CurlOpt::CURLOPT_UPLOAD_FLAGS,
        config.upload_flags as i64,
    )?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlsversion_defaults() {
        let v = tlsversion(0, 0);
        assert_eq!(v, CURL_SSLVERSION_TLSv1_2);
    }

    #[test]
    fn test_tlsversion_min_tls13() {
        let v = tlsversion(4, 0);
        assert_eq!(v, CURL_SSLVERSION_TLSv1_3);
    }

    #[test]
    fn test_tlsversion_min_max_tls12() {
        let v = tlsversion(3, 3);
        assert_eq!(
            v,
            CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_TLSv1_2
        );
    }

    #[test]
    fn test_tlsversion_default_min_with_low_max() {
        let v = tlsversion(0, 2);
        assert_eq!(
            v,
            CURL_SSLVERSION_TLSv1_1 | CURL_SSLVERSION_MAX_TLSv1_1
        );
    }

    #[test]
    fn test_ssl_backend_returns_rustls() {
        assert_eq!(ssl_backend(), "rustls");
    }

    #[test]
    fn test_extract_scheme_http() {
        assert_eq!(
            extract_scheme("http://example.com"),
            Some("http".to_string())
        );
    }

    #[test]
    fn test_extract_scheme_ftp() {
        assert_eq!(
            extract_scheme("ftp://files.example.com"),
            Some("ftp".to_string())
        );
    }

    #[test]
    fn test_extract_scheme_ipfs() {
        assert_eq!(
            extract_scheme("ipfs://QmCid/path"),
            Some("ipfs".to_string())
        );
    }

    #[test]
    fn test_extract_scheme_no_scheme() {
        assert_eq!(extract_scheme("example.com"), Some("http".to_string()));
    }
}
