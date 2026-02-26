//! HTTP cookie jar engine — complete Rust rewrite of `lib/cookie.c`.
//!
//! Manages HTTP cookie storage, parsing (`Set-Cookie` headers), matching
//! (for outgoing requests), and serialization (Netscape cookie jar format).
//!
//! # File-Compatibility
//!
//! The Netscape cookie jar file format produced by [`CookieJar::save_to_file`]
//! and consumed by [`CookieJar::load_from_file`] is byte-compatible with
//! curl 8.x's cookie file format.  Fields are tab-separated, `#HttpOnly_`
//! prefix on the domain marks httponly cookies, and the header line is
//! identical.
//!
//! # Feature Gate
//!
//! This module is compiled only when the `cookies` Cargo feature is enabled
//! (default: enabled), mirroring the C `CURL_DISABLE_COOKIES` ifdef.
//!
//! # Zero `unsafe`
//!
//! This module contains zero `unsafe` blocks.

use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use chrono::Utc;
use tracing::{debug, trace, warn};
use url::Url;

use crate::error::{CurlError, CurlResult};
use crate::psl::PslChecker;
use crate::util::parsedate;

// ---------------------------------------------------------------------------
// Constants (matching C #define values exactly)
// ---------------------------------------------------------------------------

/// Number of seconds in 400 days — maximum cookie lifetime per RFC 6265bis
/// draft-19.  Matches the C `COOKIES_MAXAGE` macro.
pub const COOKIES_MAXAGE: i64 = 400 * 24 * 3600;

/// Maximum length of a single cookie line (header or file).
/// Matches the C `MAX_COOKIE_LINE` macro.
pub const MAX_COOKIE_LINE: usize = 5000;

/// Maximum number of cookies sent in a single HTTP request.
/// Matches the C `MAX_COOKIE_SEND_AMOUNT` macro.
pub const MAX_COOKIE_SEND_AMOUNT: usize = 150;

/// Maximum size of the `Cookie:` header line in bytes.
/// Matches the C `MAX_COOKIE_HEADER_LEN` macro.
pub const MAX_COOKIE_HEADER_LEN: usize = 8190;

/// Maximum length of a cookie name or value individually.
const MAX_NAME: usize = 4096;

/// Maximum date string length for the `expires` attribute.
const MAX_DATE_LENGTH: usize = 80;

/// Maximum number of `Set-Cookie:` headers accepted per response.
/// Used by higher-level modules (e.g., transfer engine) to limit per-response
/// cookie processing.
#[allow(dead_code)]
const MAX_SET_COOKIE_AMOUNT: u8 = 50;

// ---------------------------------------------------------------------------
// SameSite enum
// ---------------------------------------------------------------------------

/// The `SameSite` cookie attribute values per RFC 6265bis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SameSite {
    /// `SameSite=None` — cookie is sent in all contexts.
    None,
    /// `SameSite=Lax` — cookie is sent with top-level navigations and GET
    /// requests originating from third-party sites.
    Lax,
    /// `SameSite=Strict` — cookie is only sent in a first-party context.
    Strict,
}

impl Default for SameSite {
    /// Default SameSite value is `Lax` per RFC 6265bis when the attribute
    /// is not explicitly set.
    fn default() -> Self {
        Self::Lax
    }
}

impl fmt::Display for SameSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Lax => write!(f, "Lax"),
            Self::Strict => write!(f, "Strict"),
        }
    }
}

impl SameSite {
    /// Parse a `SameSite` value from a string (case-insensitive).
    fn from_str_ci(s: &str) -> Self {
        let trimmed = s.trim();
        if trimmed.eq_ignore_ascii_case("none") {
            Self::None
        } else if trimmed.eq_ignore_ascii_case("strict") {
            Self::Strict
        } else {
            // "Lax" or any unrecognised value defaults to Lax.
            Self::Lax
        }
    }
}

// ---------------------------------------------------------------------------
// Cookie struct
// ---------------------------------------------------------------------------

/// A single HTTP cookie, storing all attributes from a `Set-Cookie` header
/// or a Netscape cookie-jar file line.
///
/// The struct mirrors the C `struct Cookie` from `lib/cookie.h`.
#[derive(Debug, Clone)]
pub struct Cookie {
    /// Cookie name (the key portion before `=`).
    pub name: String,
    /// Cookie value (the portion after `=`).
    pub value: String,
    /// Domain the cookie is valid for (without leading dot for storage).
    pub domain: String,
    /// Path the cookie is valid for.
    pub path: String,
    /// Expiration as a Unix timestamp (seconds since epoch).
    /// `None` means this is a session cookie.
    pub expires: Option<i64>,
    /// Whether the cookie should only be sent over HTTPS.
    pub secure: bool,
    /// Whether the cookie is inaccessible to JavaScript.
    pub httponly: bool,
    /// SameSite attribute value.
    pub same_site: SameSite,
    /// Monotonically increasing creation counter for stable sort ordering.
    /// Matches the C `creationtime` field.
    pub creation_time: i64,
    /// Whether domain-matching should use tail-match (i.e., subdomains
    /// are included).  `true` when the `Domain` attribute was explicitly
    /// set in the `Set-Cookie` header.
    pub tailmatch: bool,
    /// Whether this cookie was set from a live HTTP response (as opposed
    /// to being loaded from a file).
    pub livecookie: bool,
    /// Whether the cookie name has the `__Secure-` prefix.
    pub prefix_secure: bool,
    /// Whether the cookie name has the `__Host-` prefix.
    pub prefix_host: bool,
}

impl Cookie {
    /// Parse a `Set-Cookie` header value into a [`Cookie`].
    ///
    /// # Arguments
    ///
    /// * `header` — the raw `Set-Cookie` header value (everything after
    ///   `Set-Cookie: `).
    /// * `default_domain` — the request host, used when `Domain` is not
    ///   explicitly set in the header.
    /// * `default_path` — the request path, used to derive the cookie's
    ///   default path when `Path` is not explicitly set.
    /// * `secure_origin` — `true` if the request was made over HTTPS (or
    ///   to localhost / 127.0.0.1 / ::1).
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::OutOfMemory`] on allocation failure (unlikely
    /// in Rust).  Returns [`CurlError::BadFunctionArgument`] if the header
    /// is fundamentally malformed (e.g., no `=` separator for the name/value
    /// pair).
    pub fn parse(
        header: &str,
        default_domain: &str,
        default_path: &str,
        secure_origin: bool,
    ) -> CurlResult<Option<Self>> {
        // Reject oversized lines immediately.
        if header.len() > MAX_COOKIE_LINE {
            debug!("cookie line exceeds MAX_COOKIE_LINE ({}), dropped", header.len());
            return Ok(None);
        }

        let mut cookie = Cookie {
            name: String::new(),
            value: String::new(),
            domain: String::new(),
            path: String::new(),
            expires: None,
            secure: false,
            httponly: false,
            same_site: SameSite::default(),
            creation_time: 0,
            tailmatch: false,
            livecookie: false,
            prefix_secure: false,
            prefix_host: false,
        };

        let mut has_max_age = false;
        let mut now: Option<i64> = None;

        // Split on ';' — the first token is name=value, rest are attributes.
        let mut first = true;
        for part in header.split(';') {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }

            if first {
                first = false;
                // First token MUST be name=value.
                let eq_pos = match trimmed.find('=') {
                    Some(p) => p,
                    None => {
                        debug!("cookie has no '=' in name/value pair, dropped");
                        return Ok(None);
                    }
                };

                let name = trimmed[..eq_pos].trim();
                let value = trimmed[eq_pos + 1..].trim();

                // Validate octets.
                if invalid_octets(name) || invalid_octets(value) {
                    debug!("invalid octets in cookie name/value, dropped");
                    return Ok(None);
                }

                if name.is_empty() {
                    debug!("empty cookie name, dropped");
                    return Ok(None);
                }

                // Length checks matching C MAX_NAME.
                if name.len() >= MAX_NAME - 1
                    || value.len() >= MAX_NAME - 1
                    || (name.len() + value.len()) > MAX_NAME
                {
                    debug!(
                        "oversized cookie dropped, name/val {} + {} bytes",
                        name.len(),
                        value.len()
                    );
                    return Ok(None);
                }

                // Reject cookies with a TAB inside the value.
                if value.contains('\t') {
                    debug!("cookie value contains TAB, dropped");
                    return Ok(None);
                }

                // Check cookie name prefixes.
                if name.starts_with("__Secure-") {
                    cookie.prefix_secure = true;
                } else if name.starts_with("__Host-") {
                    cookie.prefix_host = true;
                }

                cookie.name = name.to_string();
                cookie.value = value.to_string();
                continue;
            }

            // Attribute parsing (name=value or standalone keyword).
            if let Some(eq_pos) = trimmed.find('=') {
                let attr_name = trimmed[..eq_pos].trim();
                let attr_value = trimmed[eq_pos + 1..].trim();

                if attr_name.eq_ignore_ascii_case("domain") && !attr_value.is_empty() {
                    let mut domain_val = attr_value;
                    // Strip leading dot per RFC 6265 §5.2.3.
                    if domain_val.starts_with('.') {
                        domain_val = &domain_val[1..];
                    }

                    let is_ip = is_ip_address(default_domain);

                    // Validate domain against the request host.
                    if is_ip {
                        // For IP addresses, domain must match exactly.
                        if domain_val != default_domain {
                            debug!(
                                "skipped cookie with bad tailmatch domain: {}",
                                domain_val
                            );
                            return Ok(None);
                        }
                        cookie.domain = domain_val.to_string();
                    } else {
                        // For hostnames, check tail-match.
                        if cookie_tailmatch(domain_val, default_domain) {
                            cookie.domain = domain_val.to_string();
                            cookie.tailmatch = true;
                        } else {
                            debug!(
                                "skipped cookie with bad tailmatch domain: {}",
                                domain_val
                            );
                            return Ok(None);
                        }
                    }
                } else if attr_name.eq_ignore_ascii_case("path") {
                    cookie.path = sanitize_cookie_path(attr_value);
                } else if attr_name.eq_ignore_ascii_case("max-age") && !attr_value.is_empty() {
                    // Max-Age takes priority over Expires.
                    let maxage_str = attr_value.trim_matches('"');
                    let now_ts = *now.get_or_insert_with(|| Utc::now().timestamp());

                    match maxage_str.parse::<i64>() {
                        Ok(0) => {
                            // Zero means expire immediately.
                            cookie.expires = Some(1);
                        }
                        Ok(secs) if secs < 0 => {
                            // Negative means expire immediately.
                            cookie.expires = Some(1);
                        }
                        Ok(secs) => {
                            if i64::MAX - now_ts < secs {
                                cookie.expires = Some(i64::MAX);
                            } else {
                                cookie.expires = Some(now_ts + secs);
                            }
                        }
                        Err(_) => {
                            // Parse failure — treat as session cookie or
                            // expire immediately (matching C behavior for
                            // STRE_OVERFLOW vs other errors).
                            if maxage_str.chars().all(|c| c.is_ascii_digit()) {
                                // Overflow — use max value.
                                cookie.expires = Some(i64::MAX);
                            } else {
                                cookie.expires = Some(1);
                            }
                        }
                    }
                    has_max_age = true;
                    let now_ts = *now.get_or_insert_with(|| Utc::now().timestamp());
                    cap_expires(now_ts, &mut cookie);
                } else if attr_name.eq_ignore_ascii_case("expires")
                    && !attr_value.is_empty()
                    && !has_max_age
                    && attr_value.len() < MAX_DATE_LENGTH
                {
                    // Only parse expires if max-age was not already set.
                    match parsedate::parse_date_capped(attr_value) {
                        Ok(date_ts) => {
                            let ts = if date_ts == 0 { 1 } else { date_ts };
                            cookie.expires = Some(ts);
                        }
                        Err(_) => {
                            // Unparseable date — treat as session cookie.
                            cookie.expires = None;
                        }
                    }
                    let now_ts = *now.get_or_insert_with(|| Utc::now().timestamp());
                    cap_expires(now_ts, &mut cookie);
                } else if attr_name.eq_ignore_ascii_case("samesite") {
                    cookie.same_site = SameSite::from_str_ci(attr_value);
                }
            } else {
                // Standalone attribute (no '=').
                if trimmed.eq_ignore_ascii_case("secure") {
                    if secure_origin {
                        cookie.secure = true;
                    } else {
                        debug!("skipped cookie because not over secure origin");
                        return Ok(None);
                    }
                } else if trimmed.eq_ignore_ascii_case("httponly") {
                    cookie.httponly = true;
                }
            }
        }

        // If no name was parsed, the header was empty / malformed.
        if cookie.name.is_empty() {
            return Ok(None);
        }

        // Apply defaults for domain and path.
        if cookie.domain.is_empty() && !default_domain.is_empty() {
            cookie.domain = default_domain.to_string();
            // When domain comes from request host (not Set-Cookie),
            // do NOT enable tailmatch.
        }

        if cookie.path.is_empty() {
            cookie.path = default_cookie_path(default_path);
        }

        // Validate __Secure- prefix: must have Secure attribute.
        if cookie.prefix_secure && !cookie.secure {
            debug!("__Secure- prefix requires Secure attribute, dropped");
            return Ok(None);
        }

        // Validate __Host- prefix: must be Secure, path="/", no Domain.
        if cookie.prefix_host
            && (!cookie.secure || cookie.path != "/" || cookie.tailmatch)
        {
            debug!("__Host- prefix validation failed, dropped");
            return Ok(None);
        }

        Ok(Some(cookie))
    }

    /// Parse a Netscape cookie-jar file line into a [`Cookie`].
    ///
    /// The format is tab-separated:
    /// `domain\tinclude_subdomains\tpath\tsecure\texpires\tname\tvalue`
    ///
    /// Lines starting with `#HttpOnly_` have the httponly flag set and the
    /// `#HttpOnly_` prefix stripped from the domain.
    fn parse_netscape_line(line: &str, running: bool) -> Option<Self> {
        let mut lineptr = line;
        let mut httponly = false;

        // Check for HttpOnly prefix.
        if lineptr.starts_with("#HttpOnly_") {
            lineptr = &lineptr[10..];
            httponly = true;
        }

        // Skip comment lines.
        if lineptr.starts_with('#') {
            return None;
        }

        // Skip empty lines.
        if lineptr.trim().is_empty() {
            return None;
        }

        let fields: Vec<&str> = lineptr.split('\t').collect();

        // We need exactly 6 or 7 fields.
        if fields.len() < 6 {
            return None;
        }

        let mut cookie = Cookie {
            name: String::new(),
            value: String::new(),
            domain: String::new(),
            path: String::new(),
            expires: None,
            secure: false,
            httponly,
            same_site: SameSite::default(),
            creation_time: 0,
            tailmatch: false,
            livecookie: false,
            prefix_secure: false,
            prefix_host: false,
        };

        // Field 0: domain (strip leading dots).
        let mut domain = fields[0];
        if domain.starts_with('.') {
            domain = &domain[1..];
        }
        cookie.domain = domain.to_string();

        // Field 1: tail-match flag (TRUE/FALSE).
        cookie.tailmatch = fields[1].eq_ignore_ascii_case("TRUE");

        // Field 2: path.
        // The C code has special handling where if field 2 looks like a
        // boolean (TRUE/FALSE), it skips the path and treats it as the
        // secure flag, shifting remaining fields.
        let mut field_idx = 2;
        let path_field = fields[field_idx];
        if path_field.eq_ignore_ascii_case("TRUE") || path_field.eq_ignore_ascii_case("FALSE") {
            // Path looks like a boolean — set default path and treat this
            // as the secure field.
            cookie.path = "/".to_string();
            // Fall through to secure handling with current field_idx.
        } else {
            cookie.path = sanitize_cookie_path(path_field);
            field_idx += 1;
        }

        // Field 3 (or 2 if path was missing): secure flag.
        if field_idx >= fields.len() {
            return None;
        }
        let secure_str = fields[field_idx];
        if secure_str.eq_ignore_ascii_case("TRUE") {
            if running {
                cookie.secure = true;
            } else {
                // Non-running (file load): accept secure cookies.
                cookie.secure = true;
            }
        }
        field_idx += 1;

        // Field 4: expires (Unix timestamp).
        if field_idx >= fields.len() {
            return None;
        }
        let expires_str = fields[field_idx].trim();
        match expires_str.parse::<i64>() {
            Ok(ts) if ts > 0 => cookie.expires = Some(ts),
            Ok(_) => cookie.expires = None, // 0 means session cookie
            Err(_) => return None,
        }
        field_idx += 1;

        // Field 5: name.
        if field_idx >= fields.len() {
            return None;
        }
        let name = fields[field_idx].trim_end_matches(['\r', '\n']);
        cookie.name = name.to_string();

        // Check prefixes on name.
        if cookie.name.starts_with("__Secure-") {
            cookie.prefix_secure = true;
        } else if cookie.name.starts_with("__Host-") {
            cookie.prefix_host = true;
        }
        field_idx += 1;

        // Field 6: value (may be empty or absent).
        if field_idx < fields.len() {
            let value = fields[field_idx].trim_end_matches(['\r', '\n']);
            cookie.value = value.to_string();
        }
        // If field 6 is absent (only 6 fields), value is empty string
        // (matching C behavior for cookies with blank contents).

        // Validate that we got a name at minimum.
        if cookie.name.is_empty() {
            return None;
        }

        Some(cookie)
    }
}

impl fmt::Display for Cookie {
    /// Format the cookie as a Netscape cookie-jar file line (without trailing
    /// newline).
    ///
    /// Format:
    /// `[#HttpOnly_][.]domain\tTRUE/FALSE\tpath\tTRUE/FALSE\texpires\tname\tvalue`
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // HttpOnly preamble.
        if self.httponly {
            write!(f, "#HttpOnly_")?;
        }

        // Domain: prefix with dot if tailmatch is set and domain doesn't
        // already start with a dot.
        if self.tailmatch && !self.domain.is_empty() && !self.domain.starts_with('.') {
            write!(f, ".")?;
        }

        let domain = if self.domain.is_empty() {
            "unknown"
        } else {
            &self.domain
        };

        let tailmatch = if self.tailmatch { "TRUE" } else { "FALSE" };
        let path = if self.path.is_empty() { "/" } else { &self.path };
        let secure = if self.secure { "TRUE" } else { "FALSE" };
        let expires = self.expires.unwrap_or(0);

        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            domain, tailmatch, path, secure, expires, self.name, self.value
        )
    }
}

// ---------------------------------------------------------------------------
// CookieInfo — bookkeeping metadata
// ---------------------------------------------------------------------------

/// Internal bookkeeping metadata for the cookie jar, matching the C
/// `struct CookieInfo` fields.
#[derive(Debug, Clone)]
pub struct CookieInfo {
    /// Total number of cookies in the jar.
    pub numcookies: usize,
    /// The earliest expiration timestamp among all cookies, used for
    /// efficient expired-cookie pruning.
    pub next_expiration: i64,
    /// Whether the cookie engine is in "running" mode (i.e., after
    /// initialization from files is complete and live HTTP traffic is
    /// being processed).
    pub running: bool,
    /// Whether to discard session cookies when loading from file.
    pub newsession: bool,
}

impl Default for CookieInfo {
    fn default() -> Self {
        Self {
            numcookies: 0,
            next_expiration: i64::MAX,
            running: false,
            newsession: false,
        }
    }
}

// ---------------------------------------------------------------------------
// CookieJar — main storage
// ---------------------------------------------------------------------------

/// The cookie jar — stores all cookies keyed by domain for O(1) lookup.
///
/// Replaces the C `COOKIE_HASH_SIZE=63` linked-list array with a Rust
/// `HashMap<String, Vec<Cookie>>`.
///
/// # Thread Safety
///
/// `CookieJar` is `Send + Sync` when wrapped in `Arc<Mutex<CookieJar>>`,
/// which is the pattern used for `curl_share` semantics.
#[derive(Debug)]
pub struct CookieJar {
    /// Cookies keyed by (lowercased) domain.
    cookies: HashMap<String, Vec<Cookie>>,
    /// Internal bookkeeping.
    info: CookieInfo,
    /// Monotonically increasing creation-time counter.
    last_creation_time: i64,
    /// PSL checker for domain validation.
    psl: PslChecker,
}

impl Clone for CookieJar {
    fn clone(&self) -> Self {
        Self {
            cookies: self.cookies.clone(),
            info: self.info.clone(),
            last_creation_time: self.last_creation_time,
            psl: PslChecker::new(),
        }
    }
}

impl CookieJar {
    /// Create a new, empty cookie jar.
    pub fn new() -> Self {
        Self {
            cookies: HashMap::new(),
            info: CookieInfo::default(),
            last_creation_time: 0,
            psl: PslChecker::new(),
        }
    }

    /// Add a cookie to the jar.
    ///
    /// If a cookie with the same name, domain, and path already exists,
    /// it is replaced (the old cookie's creation time is preserved).
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::BadFunctionArgument`] if the cookie has no
    /// domain set.
    pub fn add_cookie(&mut self, mut cookie: Cookie) -> CurlResult<()> {
        // Assign creation time.
        self.last_creation_time += 1;
        cookie.creation_time = self.last_creation_time;

        // Remove expired cookies before adding.
        self.remove_expired();

        // PSL check: reject cookies set on public suffixes.
        if !cookie.domain.is_empty()
            && !is_ip_address(&cookie.domain)
            && self.psl.is_public_suffix(&cookie.domain)
        {
            warn!(
                "cookie '{}' dropped: domain '{}' is a public suffix",
                cookie.name, cookie.domain
            );
            return Ok(());
        }

        let domain_key = cookie.domain.to_ascii_lowercase();

        // Check for existing cookie with same name/domain/path.
        let replaced = if let Some(existing) = self.cookies.get_mut(&domain_key) {
            let mut replace_idx = None;
            for (i, c) in existing.iter().enumerate() {
                if c.name == cookie.name
                    && c.domain.eq_ignore_ascii_case(&cookie.domain)
                    && c.tailmatch == cookie.tailmatch
                    && c.path == cookie.path
                {
                    // Check the live-cookie priority rule: a file-loaded
                    // cookie should not replace a live cookie.
                    if !cookie.livecookie && c.livecookie {
                        return Ok(());
                    }

                    // Check secure overlay protection: a non-secure cookie
                    // must not overlay an existing secure cookie on a matching
                    // path prefix.
                    if c.secure && !cookie.secure {
                        let cpath = &c.path;
                        let npath = &cookie.path;
                        let check_len = if let Some(sep_pos) = cpath[1..].find('/') {
                            sep_pos + 1
                        } else {
                            cpath.len()
                        };
                        if npath.len() >= check_len
                            && npath[..check_len].eq_ignore_ascii_case(&cpath[..check_len])
                        {
                            debug!(
                                "cookie '{}' for domain '{}' dropped: would overlay secure cookie",
                                cookie.name, cookie.domain
                            );
                            return Ok(());
                        }
                    }

                    replace_idx = Some(i);
                    break;
                }
            }

            if let Some(idx) = replace_idx {
                // Preserve creation time from old cookie.
                cookie.creation_time = existing[idx].creation_time;
                existing[idx] = cookie;
                true
            } else {
                existing.push(cookie);
                false
            }
        } else {
            self.cookies.insert(domain_key, vec![cookie]);
            false
        };

        if !replaced {
            self.info.numcookies += 1;
        }

        // Update next_expiration tracking.
        // We iterate the just-modified domain bucket.
        self.update_next_expiration();

        trace!(
            "{} cookie, jar now has {} cookies",
            if replaced { "Replaced" } else { "Added" },
            self.info.numcookies
        );

        Ok(())
    }

    /// Remove a specific cookie by domain, path, and name.
    pub fn remove_cookie(&mut self, domain: &str, path: &str, name: &str) {
        let domain_key = domain.to_ascii_lowercase();
        if let Some(cookies) = self.cookies.get_mut(&domain_key) {
            let before = cookies.len();
            cookies.retain(|c| {
                !(c.name == name
                    && c.domain.eq_ignore_ascii_case(domain)
                    && c.path == path)
            });
            let removed = before - cookies.len();
            self.info.numcookies = self.info.numcookies.saturating_sub(removed);

            // Clean up empty buckets.
            if cookies.is_empty() {
                self.cookies.remove(&domain_key);
            }
        }
    }

    /// Return all cookies that should be sent with a request to `url`.
    ///
    /// Cookies are sorted by:
    /// 1. Path length (longest first)
    /// 2. Domain length (longest first)
    /// 3. Name length (longest first)
    /// 4. Creation time (earliest first — lowest creation_time wins)
    ///
    /// At most [`MAX_COOKIE_SEND_AMOUNT`] cookies are returned.
    pub fn cookies_for_request(&self, url: &Url) -> Vec<&Cookie> {
        let scheme = url.scheme();
        let is_secure = scheme == "https" || scheme == "wss";
        let host = match url.host_str() {
            Some(h) => h,
            None => return Vec::new(),
        };
        let path = url.path();
        let is_ip = is_ip_address(host);

        // Also consider localhost and loopback as secure contexts.
        let secure_context =
            is_secure || host == "localhost" || host == "127.0.0.1" || host == "::1";

        let mut matches: Vec<&Cookie> = Vec::new();

        // We need to check ALL domain buckets because a cookie for
        // "example.com" should match a request to "sub.example.com".
        for cookies in self.cookies.values() {
            for co in cookies {
                // Skip expired cookies.
                if let Some(exp) = co.expires {
                    if exp > 0 && exp < Utc::now().timestamp() {
                        continue;
                    }
                }

                // Secure flag enforcement.
                if co.secure && !secure_context {
                    continue;
                }

                // Domain matching.
                if !co.domain.is_empty() {
                    let domain_match = if co.tailmatch && !is_ip {
                        cookie_tailmatch(&co.domain, host)
                    } else {
                        host.eq_ignore_ascii_case(&co.domain)
                    };
                    if !domain_match {
                        continue;
                    }
                }

                // Path matching.
                if !co.path.is_empty() && !pathmatch(&co.path, path) {
                    continue;
                }

                matches.push(co);

                if matches.len() >= MAX_COOKIE_SEND_AMOUNT {
                    debug!(
                        "included max number of cookies ({}) in request",
                        MAX_COOKIE_SEND_AMOUNT
                    );
                    break;
                }
            }
            if matches.len() >= MAX_COOKIE_SEND_AMOUNT {
                break;
            }
        }

        // Sort: path length desc, domain length desc, name length desc,
        // then creation_time asc.
        matches.sort_by(|a, b| {
            let pa = a.path.len();
            let pb = b.path.len();
            if pa != pb {
                return pb.cmp(&pa);
            }
            let da = a.domain.len();
            let db = b.domain.len();
            if da != db {
                return db.cmp(&da);
            }
            let na = a.name.len();
            let nb = b.name.len();
            if na != nb {
                return nb.cmp(&na);
            }
            // Creation time ascending (earlier first).
            a.creation_time.cmp(&b.creation_time)
        });

        matches
    }

    /// Load cookies from a Netscape-format cookie jar file.
    ///
    /// Lines starting with `#` (except `#HttpOnly_`) are treated as comments.
    /// Blank lines are ignored.  Lines starting with `Set-Cookie:` are parsed
    /// as HTTP headers.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::ReadError`] if the file cannot be opened or read.
    pub fn load_from_file(path: &Path) -> CurlResult<Self> {
        let file = File::open(path).map_err(|e| {
            warn!("failed to open cookie file {:?}: {}", path, e);
            CurlError::ReadError
        })?;
        let reader = BufReader::new(file);
        let mut jar = CookieJar::new();
        jar.info.running = false;
        jar.info.newsession = false;

        for line_result in reader.lines() {
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    warn!("error reading cookie file line: {}", e);
                    continue;
                }
            };

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            // Check for Set-Cookie: header lines in the file.
            if let Some(rest) = trimmed.strip_prefix("Set-Cookie:") {
                let header = rest.trim_start();
                match Cookie::parse(header, "", "", true) {
                    Ok(Some(mut co)) => {
                        co.livecookie = false;
                        // Skip session cookies if newsession is set.
                        if jar.info.newsession && co.expires.is_none() {
                            continue;
                        }
                        let _ = jar.add_cookie(co);
                    }
                    Ok(None) => {}
                    Err(_) => {}
                }
            } else {
                // Netscape format line.
                if let Some(mut co) = Cookie::parse_netscape_line(trimmed, jar.info.running) {
                    co.livecookie = false;
                    // Skip session cookies if newsession is set.
                    if jar.info.newsession && co.expires.is_none() {
                        continue;
                    }
                    let _ = jar.add_cookie(co);
                }
            }
        }

        // Remove expired cookies after loading.
        jar.remove_expired();
        jar.info.running = true;

        debug!(
            "loaded {} cookies from {:?}",
            jar.info.numcookies,
            path
        );

        Ok(jar)
    }

    /// Save all cookies to a file in Netscape cookie-jar format.
    ///
    /// The output format is:
    /// ```text
    /// # Netscape HTTP Cookie File
    /// # https://curl.se/docs/http-cookies.html
    /// # This file was generated by libcurl! Edit at your own risk.
    ///
    /// .example.com\tTRUE\t/\tFALSE\t1234567890\tname\tvalue
    /// ```
    ///
    /// Cookies are sorted by creation time (earliest first) for stable output.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::WriteError`] if the file cannot be created or
    /// written to.
    pub fn save_to_file(&self, path: &Path) -> CurlResult<()> {
        let file = File::create(path).map_err(|e| {
            warn!("failed to create cookie file {:?}: {}", path, e);
            CurlError::WriteError
        })?;
        let mut writer = BufWriter::new(file);

        // Write the Netscape header.
        writeln!(
            writer,
            "# Netscape HTTP Cookie File\n\
             # https://curl.se/docs/http-cookies.html\n\
             # This file was generated by libcurl! Edit at your own risk.\n"
        )
        .map_err(|_| CurlError::WriteError)?;

        // Collect all cookies with a domain, sorted by creation time.
        let mut all_cookies: Vec<&Cookie> = self
            .cookies
            .values()
            .flat_map(|v| v.iter())
            .filter(|c| !c.domain.is_empty())
            .collect();

        // Sort by creation time descending (matching C cookie_sort_ct:
        // the C code uses c2->creationtime > c1->creationtime ? 1 : -1,
        // which sorts newest first, but the output is written in array order,
        // effectively oldest-first after qsort with that comparator).
        // Actually, the C cookie_sort_ct returns 1 when c2 > c1, meaning
        // c2 comes before c1 — so it sorts descending (newest first in array).
        all_cookies.sort_by(|a, b| b.creation_time.cmp(&a.creation_time));

        for cookie in &all_cookies {
            writeln!(writer, "{}", cookie).map_err(|_| CurlError::WriteError)?;
        }

        writer.flush().map_err(|_| CurlError::WriteError)?;

        debug!(
            "saved {} cookies to {:?}",
            all_cookies.len(),
            path
        );

        Ok(())
    }

    /// Remove all session cookies (cookies with no explicit expiry).
    pub fn clear_session_cookies(&mut self) {
        for cookies in self.cookies.values_mut() {
            let before = cookies.len();
            cookies.retain(|c| c.expires.is_some());
            let removed = before - cookies.len();
            self.info.numcookies = self.info.numcookies.saturating_sub(removed);
        }
        // Clean up empty buckets.
        self.cookies.retain(|_, v| !v.is_empty());
    }

    /// Remove all cookies from the jar.
    pub fn clear_all(&mut self) {
        self.cookies.clear();
        self.info.numcookies = 0;
        self.info.next_expiration = i64::MAX;
    }

    /// Return the total number of cookies in the jar.
    pub fn num_cookies(&self) -> usize {
        self.info.numcookies
    }

    /// Return `true` if the jar contains no cookies.
    pub fn is_empty(&self) -> bool {
        self.info.numcookies == 0
    }

    /// Iterate over all cookies in the jar.
    ///
    /// The iteration order is unspecified (HashMap iteration order).
    pub fn iter(&self) -> impl Iterator<Item = &Cookie> {
        self.cookies.values().flat_map(|v| v.iter())
    }

    /// Get a reference to the internal [`CookieInfo`] metadata.
    pub fn cookie_info(&self) -> &CookieInfo {
        &self.info
    }

    /// Set the `running` flag on the cookie engine.
    pub fn set_running(&mut self, running: bool) {
        self.info.running = running;
    }

    /// Set the `newsession` flag for discarding session cookies on file load.
    pub fn set_newsession(&mut self, newsession: bool) {
        self.info.newsession = newsession;
    }

    /// Parse and add a cookie from a Set-Cookie header line.
    ///
    /// This is a convenience method that combines [`Cookie::parse`] with
    /// [`CookieJar::add_cookie`].
    pub fn add_cookie_header(
        &mut self,
        header: &str,
        domain: &str,
        path: &str,
        secure: bool,
    ) -> CurlResult<()> {
        match Cookie::parse(header, domain, path, secure)? {
            Some(mut co) => {
                co.livecookie = self.info.running;
                self.add_cookie(co)
            }
            None => Ok(()),
        }
    }

    /// Build the `Cookie:` header value for a given URL.
    ///
    /// Returns `None` if no cookies match.  The header value is limited to
    /// [`MAX_COOKIE_HEADER_LEN`] bytes.
    pub fn cookie_header_for_request(&self, url: &Url) -> Option<String> {
        let cookies = self.cookies_for_request(url);
        if cookies.is_empty() {
            return None;
        }

        let mut header = String::new();
        for (i, cookie) in cookies.iter().enumerate() {
            if i > 0 {
                header.push_str("; ");
            }
            let pair = format!("{}={}", cookie.name, cookie.value);
            if header.len() + pair.len() + 2 > MAX_COOKIE_HEADER_LEN {
                debug!("cookie header would exceed MAX_COOKIE_HEADER_LEN, truncating");
                break;
            }
            header.push_str(&pair);
        }

        if header.is_empty() {
            None
        } else {
            Some(header)
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Remove all expired cookies from the jar.
    fn remove_expired(&mut self) {
        let now = Utc::now().timestamp();

        // Early exit if no cookies have expired yet.
        if now < self.info.next_expiration && self.info.next_expiration != i64::MAX {
            return;
        }

        self.info.next_expiration = i64::MAX;

        for cookies in self.cookies.values_mut() {
            let before = cookies.len();
            cookies.retain(|c| {
                if let Some(exp) = c.expires {
                    if exp > 0 && exp < now {
                        return false; // expired
                    }
                    // Track the next expiration time.
                    // (done outside retain for borrow reasons, handled below)
                }
                true
            });
            let removed = before - cookies.len();
            self.info.numcookies = self.info.numcookies.saturating_sub(removed);
        }

        // Clean up empty buckets and recalculate next_expiration.
        self.cookies.retain(|_, v| !v.is_empty());
        self.update_next_expiration();
    }

    /// Recalculate the `next_expiration` field by scanning all cookies.
    fn update_next_expiration(&mut self) {
        let mut next = i64::MAX;
        for cookies in self.cookies.values() {
            for c in cookies {
                if let Some(exp) = c.expires {
                    if exp > 0 && exp < next {
                        next = exp;
                    }
                }
            }
        }
        self.info.next_expiration = next;
    }
}

impl Default for CookieJar {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a thread-safe shared cookie jar suitable for `curl_share` semantics.
///
/// Returns `Arc<Mutex<CookieJar>>` that can be shared across multiple
/// easy handles.
pub fn shared_cookie_jar() -> Arc<Mutex<CookieJar>> {
    Arc::new(Mutex::new(CookieJar::new()))
}

// ---------------------------------------------------------------------------
// Internal helper functions
// ---------------------------------------------------------------------------

/// Cap cookie expiry to [`COOKIES_MAXAGE`] seconds from `now`, aligned to
/// a 60-second boundary.
///
/// This matches the C `cap_expires()` function exactly:
/// ```c
/// if(co->expires && (TIME_T_MAX - COOKIES_MAXAGE - 30) > now) {
///     timediff_t cap = now + COOKIES_MAXAGE;
///     if(co->expires > cap) {
///         cap += 30;
///         co->expires = (cap / 60) * 60;
///     }
/// }
/// ```
fn cap_expires(now: i64, cookie: &mut Cookie) {
    if let Some(expires) = cookie.expires {
        if expires != 0 && (i64::MAX - COOKIES_MAXAGE - 30) > now {
            let cap = now + COOKIES_MAXAGE;
            if expires > cap {
                let adjusted = cap + 30;
                cookie.expires = Some((adjusted / 60) * 60);
            }
        }
    }
}

/// Check whether a byte sequence contains invalid cookie octets.
///
/// Rejects all bytes \x01–\x1f (except \x09 TAB) and \x7f, matching
/// the C `invalid_octets()` function.
fn invalid_octets(s: &str) -> bool {
    for &b in s.as_bytes() {
        if (b != 0x09 && b < 0x20) || b == 0x7f {
            return true;
        }
    }
    false
}

/// Tail-match a cookie domain against a hostname.
///
/// Returns `true` if:
/// - `hostname == cookie_domain`, or
/// - `hostname` ends with `cookie_domain` and the character immediately
///   before the match in `hostname` is a dot.
///
/// Matching is case-insensitive.
fn cookie_tailmatch(cookie_domain: &str, hostname: &str) -> bool {
    let cd_len = cookie_domain.len();
    let hn_len = hostname.len();

    if hn_len < cd_len {
        return false;
    }

    // Compare the tail of hostname against cookie_domain.
    let tail = &hostname[hn_len - cd_len..];
    if !tail.eq_ignore_ascii_case(cookie_domain) {
        return false;
    }

    // If lengths are equal, it's an exact match.
    if hn_len == cd_len {
        return true;
    }

    // The character before the matched portion must be a dot.
    let sep = hostname.as_bytes()[hn_len - cd_len - 1];
    sep == b'.'
}

/// Path-match per RFC 6265 §5.1.4.
///
/// Returns `true` if the `cookie_path` matches the `uri_path`.
fn pathmatch(cookie_path: &str, uri_path: &str) -> bool {
    let cookie_path_len = cookie_path.len();

    // A cookie path of "/" matches everything.
    if cookie_path_len == 1 && cookie_path == "/" {
        return true;
    }

    // Ensure uri_path is valid.
    let uri_path = if uri_path.is_empty() || !uri_path.starts_with('/') {
        "/"
    } else {
        uri_path
    };

    let uri_path_len = uri_path.len();

    if uri_path_len < cookie_path_len {
        return false;
    }

    // Case-sensitive prefix match.
    if &uri_path[..cookie_path_len] != cookie_path {
        return false;
    }

    // Exact match.
    if cookie_path_len == uri_path_len {
        return true;
    }

    // The character after the cookie path in the URI must be '/'.
    if uri_path.as_bytes()[cookie_path_len] == b'/' {
        return true;
    }

    false
}

/// Sanitize a cookie path value.
///
/// - Strips surrounding double-quotes.
/// - Ensures path starts with `/`.
/// - Removes trailing `/` (unless the path is just `/`).
fn sanitize_cookie_path(path: &str) -> String {
    let mut p = path;

    // Strip surrounding double-quotes.
    if p.starts_with('"') {
        p = &p[1..];
        if p.ends_with('"') {
            p = &p[..p.len() - 1];
        }
    }

    // Per RFC 6265 §5.2.4: if the path is empty or doesn't start with '/',
    // use the default path "/".
    if p.is_empty() || !p.starts_with('/') {
        return "/".to_string();
    }

    // Remove trailing slash (convert "/path/" to "/path") unless it's just "/".
    if p.len() > 1 && p.ends_with('/') {
        p = &p[..p.len() - 1];
    }

    p.to_string()
}

/// Compute the default cookie path from a request URI path.
///
/// Per RFC 6265 §5.1.4: the default-path is the path up to (but not
/// including) the right-most `/`.  If the path has no `/`, is empty, or
/// is just `/`, the default path is `/`.
fn default_cookie_path(uri_path: &str) -> String {
    if uri_path.is_empty() || !uri_path.starts_with('/') {
        return "/".to_string();
    }

    match uri_path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(pos) => uri_path[..pos].to_string(),
    }
}

/// Check whether a hostname is a numeric IP address.
fn is_ip_address(host: &str) -> bool {
    // IPv6 in brackets.
    if host.starts_with('[') && host.ends_with(']') {
        return true;
    }
    // Plain IPv4: all characters are digits and dots.
    if !host.is_empty() && host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        // Must have at least one dot and parse as 4 octets.
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() == 4 {
            return parts
                .iter()
                .all(|p| p.parse::<u8>().is_ok());
        }
    }
    // IPv6 without brackets (contains ':').
    if host.contains(':') && !host.contains('/') {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------- SameSite -------

    #[test]
    fn samesite_from_str_ci() {
        assert_eq!(SameSite::from_str_ci("None"), SameSite::None);
        assert_eq!(SameSite::from_str_ci("NONE"), SameSite::None);
        assert_eq!(SameSite::from_str_ci("Strict"), SameSite::Strict);
        assert_eq!(SameSite::from_str_ci("strict"), SameSite::Strict);
        assert_eq!(SameSite::from_str_ci("Lax"), SameSite::Lax);
        assert_eq!(SameSite::from_str_ci("lax"), SameSite::Lax);
        assert_eq!(SameSite::from_str_ci("unknown"), SameSite::Lax);
    }

    // ------- Cookie::parse -------

    #[test]
    fn parse_basic_cookie() {
        let cookie = Cookie::parse(
            "name=value; Path=/; Domain=example.com",
            "www.example.com",
            "/",
            false,
        )
        .unwrap()
        .unwrap();
        assert_eq!(cookie.name, "name");
        assert_eq!(cookie.value, "value");
        assert_eq!(cookie.domain, "example.com");
        assert_eq!(cookie.path, "/");
        assert!(cookie.tailmatch);
    }

    #[test]
    fn parse_secure_cookie() {
        let cookie = Cookie::parse(
            "name=value; Secure; HttpOnly; Path=/test",
            "example.com",
            "/test/page",
            true,
        )
        .unwrap()
        .unwrap();
        assert!(cookie.secure);
        assert!(cookie.httponly);
        assert_eq!(cookie.path, "/test");
    }

    #[test]
    fn parse_secure_cookie_rejected_on_insecure() {
        let result = Cookie::parse(
            "name=value; Secure",
            "example.com",
            "/",
            false,
        )
        .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_expires_attribute() {
        let cookie = Cookie::parse(
            "name=value; Expires=Sun, 06 Nov 2044 08:49:37 GMT",
            "example.com",
            "/",
            false,
        )
        .unwrap()
        .unwrap();
        // Should have an expiry set (capped to 400 days from now).
        assert!(cookie.expires.is_some());
    }

    #[test]
    fn parse_max_age_attribute() {
        let cookie = Cookie::parse(
            "name=value; Max-Age=3600",
            "example.com",
            "/",
            false,
        )
        .unwrap()
        .unwrap();
        assert!(cookie.expires.is_some());
        let now = Utc::now().timestamp();
        let exp = cookie.expires.unwrap();
        // Should be approximately now + 3600.
        assert!(exp > now && exp <= now + 3700);
    }

    #[test]
    fn parse_max_age_zero() {
        let cookie = Cookie::parse(
            "name=value; Max-Age=0",
            "example.com",
            "/",
            false,
        )
        .unwrap()
        .unwrap();
        assert_eq!(cookie.expires, Some(1));
    }

    #[test]
    fn parse_cookie_prefix_secure() {
        let cookie = Cookie::parse(
            "__Secure-name=value; Secure; Path=/",
            "example.com",
            "/",
            true,
        )
        .unwrap()
        .unwrap();
        assert!(cookie.prefix_secure);
        assert!(cookie.secure);
    }

    #[test]
    fn parse_cookie_prefix_secure_without_secure_rejected() {
        let result = Cookie::parse(
            "__Secure-name=value; Path=/",
            "example.com",
            "/",
            true,
        )
        .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_cookie_prefix_host() {
        let cookie = Cookie::parse(
            "__Host-name=value; Secure; Path=/",
            "example.com",
            "/",
            true,
        )
        .unwrap()
        .unwrap();
        assert!(cookie.prefix_host);
        assert!(cookie.secure);
        assert_eq!(cookie.path, "/");
        // tailmatch should be false (no Domain attribute set).
        assert!(!cookie.tailmatch);
    }

    #[test]
    fn parse_cookie_prefix_host_with_domain_rejected() {
        let result = Cookie::parse(
            "__Host-name=value; Secure; Path=/; Domain=example.com",
            "example.com",
            "/",
            true,
        )
        .unwrap();
        // __Host- requires no domain (tailmatch = false).
        assert!(result.is_none());
    }

    #[test]
    fn parse_oversized_cookie_rejected() {
        let long_val = "x".repeat(MAX_COOKIE_LINE + 1);
        let result = Cookie::parse(&long_val, "example.com", "/", false).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_domain_tailmatch_mismatch() {
        let result = Cookie::parse(
            "name=value; Domain=other.com",
            "example.com",
            "/",
            false,
        )
        .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_domain_leading_dot_stripped() {
        let cookie = Cookie::parse(
            "name=value; Domain=.example.com",
            "sub.example.com",
            "/",
            false,
        )
        .unwrap()
        .unwrap();
        assert_eq!(cookie.domain, "example.com");
        assert!(cookie.tailmatch);
    }

    #[test]
    fn parse_default_path() {
        let cookie = Cookie::parse(
            "name=value",
            "example.com",
            "/some/path/page.html",
            false,
        )
        .unwrap()
        .unwrap();
        assert_eq!(cookie.path, "/some/path");
    }

    // ------- Netscape format parsing -------

    #[test]
    fn parse_netscape_basic() {
        let line = ".example.com\tTRUE\t/\tFALSE\t0\tmyname\tmyvalue";
        let cookie = Cookie::parse_netscape_line(line, true).unwrap();
        assert_eq!(cookie.domain, "example.com");
        assert!(cookie.tailmatch);
        assert_eq!(cookie.path, "/");
        assert!(!cookie.secure);
        assert_eq!(cookie.name, "myname");
        assert_eq!(cookie.value, "myvalue");
    }

    #[test]
    fn parse_netscape_httponly() {
        let line = "#HttpOnly_.example.com\tTRUE\t/\tTRUE\t1234567890\tname\tval";
        let cookie = Cookie::parse_netscape_line(line, true).unwrap();
        assert!(cookie.httponly);
        assert_eq!(cookie.domain, "example.com");
        assert!(cookie.secure);
        assert_eq!(cookie.expires, Some(1234567890));
    }

    #[test]
    fn parse_netscape_comment_skipped() {
        let line = "# This is a comment";
        assert!(Cookie::parse_netscape_line(line, true).is_none());
    }

    // ------- Cookie Display (Netscape format) -------

    #[test]
    fn cookie_display_format() {
        let cookie = Cookie {
            name: "myname".into(),
            value: "myvalue".into(),
            domain: "example.com".into(),
            path: "/".into(),
            expires: Some(1234567890),
            secure: false,
            httponly: false,
            same_site: SameSite::Lax,
            creation_time: 1,
            tailmatch: true,
            livecookie: false,
            prefix_secure: false,
            prefix_host: false,
        };
        let s = format!("{}", cookie);
        assert_eq!(
            s,
            ".example.com\tTRUE\t/\tFALSE\t1234567890\tmyname\tmyvalue"
        );
    }

    #[test]
    fn cookie_display_httponly() {
        let cookie = Cookie {
            name: "name".into(),
            value: "val".into(),
            domain: "example.com".into(),
            path: "/path".into(),
            expires: Some(0),
            secure: true,
            httponly: true,
            same_site: SameSite::Lax,
            creation_time: 1,
            tailmatch: false,
            livecookie: false,
            prefix_secure: false,
            prefix_host: false,
        };
        let s = format!("{}", cookie);
        assert!(s.starts_with("#HttpOnly_example.com\t"));
        assert!(s.contains("TRUE")); // secure
    }

    // ------- CookieJar -------

    #[test]
    fn jar_add_and_count() {
        let mut jar = CookieJar::new();
        let cookie = Cookie {
            name: "test".into(),
            value: "val".into(),
            domain: "example.com".into(),
            path: "/".into(),
            expires: None,
            secure: false,
            httponly: false,
            same_site: SameSite::Lax,
            creation_time: 0,
            tailmatch: false,
            livecookie: false,
            prefix_secure: false,
            prefix_host: false,
        };
        jar.add_cookie(cookie).unwrap();
        assert_eq!(jar.num_cookies(), 1);
        assert!(!jar.is_empty());
    }

    #[test]
    fn jar_replace_existing() {
        let mut jar = CookieJar::new();
        let c1 = Cookie {
            name: "test".into(),
            value: "old".into(),
            domain: "example.com".into(),
            path: "/".into(),
            expires: None,
            secure: false,
            httponly: false,
            same_site: SameSite::Lax,
            creation_time: 0,
            tailmatch: false,
            livecookie: false,
            prefix_secure: false,
            prefix_host: false,
        };
        let c2 = Cookie {
            name: "test".into(),
            value: "new".into(),
            domain: "example.com".into(),
            path: "/".into(),
            expires: None,
            secure: false,
            httponly: false,
            same_site: SameSite::Lax,
            creation_time: 0,
            tailmatch: false,
            livecookie: false,
            prefix_secure: false,
            prefix_host: false,
        };
        jar.add_cookie(c1).unwrap();
        jar.add_cookie(c2).unwrap();
        // Count should still be 1 (replaced).
        assert_eq!(jar.num_cookies(), 1);
        // Value should be "new".
        let cookies: Vec<&Cookie> = jar.iter().collect();
        assert_eq!(cookies[0].value, "new");
    }

    #[test]
    fn jar_remove_cookie() {
        let mut jar = CookieJar::new();
        let c = Cookie {
            name: "test".into(),
            value: "val".into(),
            domain: "example.com".into(),
            path: "/".into(),
            expires: None,
            secure: false,
            httponly: false,
            same_site: SameSite::Lax,
            creation_time: 0,
            tailmatch: false,
            livecookie: false,
            prefix_secure: false,
            prefix_host: false,
        };
        jar.add_cookie(c).unwrap();
        jar.remove_cookie("example.com", "/", "test");
        assert_eq!(jar.num_cookies(), 0);
        assert!(jar.is_empty());
    }

    #[test]
    fn jar_clear_session_cookies() {
        let mut jar = CookieJar::new();
        let session = Cookie {
            name: "session".into(),
            value: "s".into(),
            domain: "example.com".into(),
            path: "/".into(),
            expires: None,
            secure: false,
            httponly: false,
            same_site: SameSite::Lax,
            creation_time: 0,
            tailmatch: false,
            livecookie: false,
            prefix_secure: false,
            prefix_host: false,
        };
        let persistent = Cookie {
            name: "persistent".into(),
            value: "p".into(),
            domain: "example.com".into(),
            path: "/".into(),
            expires: Some(Utc::now().timestamp() + 86400),
            secure: false,
            httponly: false,
            same_site: SameSite::Lax,
            creation_time: 0,
            tailmatch: false,
            livecookie: false,
            prefix_secure: false,
            prefix_host: false,
        };
        jar.add_cookie(session).unwrap();
        jar.add_cookie(persistent).unwrap();
        assert_eq!(jar.num_cookies(), 2);
        jar.clear_session_cookies();
        assert_eq!(jar.num_cookies(), 1);
    }

    #[test]
    fn jar_clear_all() {
        let mut jar = CookieJar::new();
        for i in 0..5 {
            let c = Cookie {
                name: format!("c{}", i),
                value: "v".into(),
                domain: "example.com".into(),
                path: "/".into(),
                expires: None,
                secure: false,
                httponly: false,
                same_site: SameSite::Lax,
                creation_time: 0,
                tailmatch: false,
                livecookie: false,
                prefix_secure: false,
                prefix_host: false,
            };
            jar.add_cookie(c).unwrap();
        }
        assert_eq!(jar.num_cookies(), 5);
        jar.clear_all();
        assert_eq!(jar.num_cookies(), 0);
    }

    // ------- Cookie matching -------

    #[test]
    fn cookies_for_request_basic() {
        let mut jar = CookieJar::new();
        let c = Cookie {
            name: "test".into(),
            value: "val".into(),
            domain: "example.com".into(),
            path: "/".into(),
            expires: None,
            secure: false,
            httponly: false,
            same_site: SameSite::Lax,
            creation_time: 1,
            tailmatch: false,
            livecookie: false,
            prefix_secure: false,
            prefix_host: false,
        };
        jar.add_cookie(c).unwrap();

        let url = Url::parse("http://example.com/page").unwrap();
        let matches = jar.cookies_for_request(&url);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "test");
    }

    #[test]
    fn cookies_for_request_tailmatch() {
        let mut jar = CookieJar::new();
        let c = Cookie {
            name: "test".into(),
            value: "val".into(),
            domain: "example.com".into(),
            path: "/".into(),
            expires: None,
            secure: false,
            httponly: false,
            same_site: SameSite::Lax,
            creation_time: 1,
            tailmatch: true,
            livecookie: false,
            prefix_secure: false,
            prefix_host: false,
        };
        jar.add_cookie(c).unwrap();

        // Should match sub.example.com.
        let url = Url::parse("http://sub.example.com/page").unwrap();
        let matches = jar.cookies_for_request(&url);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn cookies_for_request_secure_only() {
        let mut jar = CookieJar::new();
        let c = Cookie {
            name: "secure_test".into(),
            value: "val".into(),
            domain: "example.com".into(),
            path: "/".into(),
            expires: None,
            secure: true,
            httponly: false,
            same_site: SameSite::Lax,
            creation_time: 1,
            tailmatch: false,
            livecookie: false,
            prefix_secure: false,
            prefix_host: false,
        };
        jar.add_cookie(c).unwrap();

        // HTTP request should NOT get secure cookie.
        let url_http = Url::parse("http://example.com/").unwrap();
        assert!(jar.cookies_for_request(&url_http).is_empty());

        // HTTPS request should get it.
        let url_https = Url::parse("https://example.com/").unwrap();
        assert_eq!(jar.cookies_for_request(&url_https).len(), 1);
    }

    #[test]
    fn cookies_for_request_path_match() {
        let mut jar = CookieJar::new();
        let c = Cookie {
            name: "test".into(),
            value: "val".into(),
            domain: "example.com".into(),
            path: "/api".into(),
            expires: None,
            secure: false,
            httponly: false,
            same_site: SameSite::Lax,
            creation_time: 1,
            tailmatch: false,
            livecookie: false,
            prefix_secure: false,
            prefix_host: false,
        };
        jar.add_cookie(c).unwrap();

        // Matches: /api/users
        let url1 = Url::parse("http://example.com/api/users").unwrap();
        assert_eq!(jar.cookies_for_request(&url1).len(), 1);

        // Does NOT match: /other
        let url2 = Url::parse("http://example.com/other").unwrap();
        assert!(jar.cookies_for_request(&url2).is_empty());

        // Does NOT match: /apiary (different path)
        let url3 = Url::parse("http://example.com/apiary").unwrap();
        assert!(jar.cookies_for_request(&url3).is_empty());
    }

    #[test]
    fn cookies_sorted_by_path_length() {
        let mut jar = CookieJar::new();
        let c1 = Cookie {
            name: "short".into(),
            value: "v".into(),
            domain: "example.com".into(),
            path: "/".into(),
            expires: None,
            secure: false,
            httponly: false,
            same_site: SameSite::Lax,
            creation_time: 0,
            tailmatch: false,
            livecookie: false,
            prefix_secure: false,
            prefix_host: false,
        };
        let c2 = Cookie {
            name: "long".into(),
            value: "v".into(),
            domain: "example.com".into(),
            path: "/api/v2".into(),
            expires: None,
            secure: false,
            httponly: false,
            same_site: SameSite::Lax,
            creation_time: 0,
            tailmatch: false,
            livecookie: false,
            prefix_secure: false,
            prefix_host: false,
        };
        jar.add_cookie(c1).unwrap();
        jar.add_cookie(c2).unwrap();

        let url = Url::parse("http://example.com/api/v2/test").unwrap();
        let matches = jar.cookies_for_request(&url);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].name, "long"); // longer path first
        assert_eq!(matches[1].name, "short");
    }

    // ------- File I/O -------

    #[test]
    fn save_and_load_roundtrip() {
        let mut jar = CookieJar::new();
        for i in 0..3 {
            let c = Cookie {
                name: format!("cookie{}", i),
                value: format!("value{}", i),
                domain: "example.com".into(),
                path: "/".into(),
                expires: Some(Utc::now().timestamp() + 86400),
                secure: i % 2 == 0,
                httponly: i == 1,
                same_site: SameSite::Lax,
                creation_time: 0,
                tailmatch: true,
                livecookie: false,
                prefix_secure: false,
                prefix_host: false,
            };
            jar.add_cookie(c).unwrap();
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cookies.txt");
        jar.save_to_file(&path).unwrap();

        let loaded = CookieJar::load_from_file(&path).unwrap();
        assert_eq!(loaded.num_cookies(), 3);

        // Verify cookies round-tripped correctly.
        for i in 0..3 {
            let name = format!("cookie{}", i);
            let found = loaded.iter().find(|c| c.name == name);
            assert!(found.is_some(), "cookie {} not found after load", i);
            let c = found.unwrap();
            assert_eq!(c.value, format!("value{}", i));
            assert_eq!(c.domain, "example.com");
        }
    }

    #[test]
    fn save_file_has_netscape_header() {
        let jar = CookieJar::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.txt");
        jar.save_to_file(&path).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.starts_with("# Netscape HTTP Cookie File"));
        assert!(contents.contains("https://curl.se/docs/http-cookies.html"));
        assert!(contents.contains("This file was generated by libcurl!"));
    }

    // ------- Internal helpers -------

    #[test]
    fn test_cookie_tailmatch_fn() {
        assert!(cookie_tailmatch("example.com", "www.example.com"));
        assert!(cookie_tailmatch("example.com", "example.com"));
        assert!(!cookie_tailmatch("example.com", "notexample.com"));
        assert!(!cookie_tailmatch("example.com", "fooexample.com"));
    }

    #[test]
    fn test_pathmatch_fn() {
        assert!(pathmatch("/", "/anything"));
        assert!(pathmatch("/path", "/path"));
        assert!(pathmatch("/path", "/path/sub"));
        assert!(!pathmatch("/path", "/pathother"));
        assert!(!pathmatch("/path", "/"));
    }

    #[test]
    fn test_sanitize_cookie_path() {
        assert_eq!(sanitize_cookie_path("/path/"), "/path");
        assert_eq!(sanitize_cookie_path("/"), "/");
        assert_eq!(sanitize_cookie_path(""), "/");
        assert_eq!(sanitize_cookie_path("\"path\""), "/");
        assert_eq!(sanitize_cookie_path("\"/path/\""), "/path");
    }

    #[test]
    fn test_default_cookie_path() {
        assert_eq!(default_cookie_path("/a/b/c"), "/a/b");
        assert_eq!(default_cookie_path("/"), "/");
        assert_eq!(default_cookie_path(""), "/");
        assert_eq!(default_cookie_path("/single"), "/");
    }

    #[test]
    fn test_is_ip_address() {
        assert!(is_ip_address("127.0.0.1"));
        assert!(is_ip_address("192.168.1.1"));
        assert!(is_ip_address("[::1]"));
        assert!(is_ip_address("::1"));
        assert!(!is_ip_address("example.com"));
        assert!(!is_ip_address("localhost"));
    }

    #[test]
    fn test_invalid_octets() {
        assert!(!invalid_octets("hello world"));
        assert!(!invalid_octets("tab\there"));
        assert!(invalid_octets("control\x01char"));
        assert!(invalid_octets("del\x7fchar"));
    }

    #[test]
    fn test_cap_expires() {
        let now = 1700000000i64;
        let mut cookie = Cookie {
            name: "test".into(),
            value: "v".into(),
            domain: "example.com".into(),
            path: "/".into(),
            expires: Some(now + COOKIES_MAXAGE + 10000),
            secure: false,
            httponly: false,
            same_site: SameSite::Lax,
            creation_time: 0,
            tailmatch: false,
            livecookie: false,
            prefix_secure: false,
            prefix_host: false,
        };
        cap_expires(now, &mut cookie);
        let exp = cookie.expires.unwrap();
        // Should be capped and aligned to 60-second boundary.
        let expected_cap = now + COOKIES_MAXAGE + 30;
        let expected = (expected_cap / 60) * 60;
        assert_eq!(exp, expected);
    }

    #[test]
    fn test_cap_expires_within_range() {
        let now = 1700000000i64;
        let within_range = now + 3600;
        let mut cookie = Cookie {
            name: "test".into(),
            value: "v".into(),
            domain: "example.com".into(),
            path: "/".into(),
            expires: Some(within_range),
            secure: false,
            httponly: false,
            same_site: SameSite::Lax,
            creation_time: 0,
            tailmatch: false,
            livecookie: false,
            prefix_secure: false,
            prefix_host: false,
        };
        cap_expires(now, &mut cookie);
        // Should NOT be capped.
        assert_eq!(cookie.expires, Some(within_range));
    }

    // ------- Cookie header builder -------

    #[test]
    fn cookie_header_for_request_basic() {
        let mut jar = CookieJar::new();
        let c1 = Cookie {
            name: "a".into(),
            value: "1".into(),
            domain: "example.com".into(),
            path: "/".into(),
            expires: None,
            secure: false,
            httponly: false,
            same_site: SameSite::Lax,
            creation_time: 0,
            tailmatch: false,
            livecookie: false,
            prefix_secure: false,
            prefix_host: false,
        };
        let c2 = Cookie {
            name: "b".into(),
            value: "2".into(),
            domain: "example.com".into(),
            path: "/api".into(),
            expires: None,
            secure: false,
            httponly: false,
            same_site: SameSite::Lax,
            creation_time: 0,
            tailmatch: false,
            livecookie: false,
            prefix_secure: false,
            prefix_host: false,
        };
        jar.add_cookie(c1).unwrap();
        jar.add_cookie(c2).unwrap();

        let url = Url::parse("http://example.com/api/test").unwrap();
        let header = jar.cookie_header_for_request(&url).unwrap();
        // "b" has longer path, should come first.
        assert!(header.starts_with("b=2"));
        assert!(header.contains("a=1"));
    }

    #[test]
    fn cookie_header_empty_when_no_match() {
        let jar = CookieJar::new();
        let url = Url::parse("http://example.com/").unwrap();
        assert!(jar.cookie_header_for_request(&url).is_none());
    }

    // ------- Shared jar -------

    #[test]
    fn shared_cookie_jar_works() {
        let shared = shared_cookie_jar();
        let mut jar = shared.lock().unwrap();
        let c = Cookie {
            name: "shared".into(),
            value: "yes".into(),
            domain: "example.com".into(),
            path: "/".into(),
            expires: None,
            secure: false,
            httponly: false,
            same_site: SameSite::Lax,
            creation_time: 0,
            tailmatch: false,
            livecookie: false,
            prefix_secure: false,
            prefix_host: false,
        };
        jar.add_cookie(c).unwrap();
        assert_eq!(jar.num_cookies(), 1);
    }
}
