//! URL parsing, connection setup, and the public URL API.
//!
//! Rust rewrite of `lib/url.c` (3,904 lines) and `lib/urlapi.c` — provides
//! the `CurlUrl` handle (matching the C `CURLU` / `curl_url_*` API surface),
//! URL part enumeration, connection configuration extraction, and flag
//! constants whose integer values are ABI-compatible with `include/curl/urlapi.h`.
//!
//! # Public API
//!
//! * [`CurlUrl`] — URL handle wrapping the [`url::Url`] crate with
//!   curl-specific extensions (zone IDs, credential extraction, scheme
//!   guessing, IDN conversion, etc.).
//! * [`CurlUrlPart`] — enum of URL components with discriminants matching
//!   `CURLUPART_*` from `include/curl/urlapi.h`.
//! * [`ConnectionConfig`] — connection parameters resolved from a URL and
//!   transfer options.
//! * 16 `CURLU_*` flag constants — bitflags controlling set/get behavior.
//! * [`is_absolute_url`] — detect whether a string is an absolute URL.
//!
//! # FFI Compatibility
//!
//! All `CURLU_*` and `CURLUPART_*` integer values match the C header exactly
//! so the FFI crate can transmute without conversion.

use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;

use url::Url;

use crate::error::{CurlError, CurlResult, CurlUrlError};
use crate::escape;
use crate::idn;

// ---------------------------------------------------------------------------
// CURLU_* flag constants — values MUST match include/curl/urlapi.h
// ---------------------------------------------------------------------------

/// Return the default port number for the scheme (get flag).
pub const CURLU_DEFAULT_PORT: u32 = 1 << 0;

/// Act as if no port number was set if it matches the scheme default (get flag).
pub const CURLU_NO_DEFAULT_PORT: u32 = 1 << 1;

/// Return the default scheme (`https`) if the URL has no scheme (get flag).
pub const CURLU_DEFAULT_SCHEME: u32 = 1 << 2;

/// Allow schemes not natively supported by curl (set flag).
pub const CURLU_NON_SUPPORT_SCHEME: u32 = 1 << 3;

/// Leave dot sequences (`.` / `..`) in the path unchanged (set flag).
pub const CURLU_PATH_AS_IS: u32 = 1 << 4;

/// Reject URLs containing username/password (set flag).
pub const CURLU_DISALLOW_USER: u32 = 1 << 5;

/// URL-decode on get (get flag).
pub const CURLU_URLDECODE: u32 = 1 << 6;

/// URL-encode on set (set flag).
pub const CURLU_URLENCODE: u32 = 1 << 7;

/// Append a form-style query part with `&` separator (set flag).
pub const CURLU_APPENDQUERY: u32 = 1 << 8;

/// Legacy curl-style scheme guessing based on hostname prefix (set flag).
pub const CURLU_GUESS_SCHEME: u32 = 1 << 9;

/// Allow empty authority when the scheme is unknown (set flag).
pub const CURLU_NO_AUTHORITY: u32 = 1 << 10;

/// Allow spaces in the URL (set flag).
pub const CURLU_ALLOW_SPACE: u32 = 1 << 11;

/// Get the hostname in Punycode (get flag).
pub const CURLU_PUNYCODE: u32 = 1 << 12;

/// Convert Punycode hostname to IDN on get (get flag).
pub const CURLU_PUNY2IDN: u32 = 1 << 13;

/// Allow empty queries and fragments when extracting (get flag).
pub const CURLU_GET_EMPTY: u32 = 1 << 14;

/// For get: do not accept a guessed scheme (get flag).
pub const CURLU_NO_GUESS_SCHEME: u32 = 1 << 15;

// ---------------------------------------------------------------------------
// Default scheme
// ---------------------------------------------------------------------------

/// The default scheme used when none is provided and `CURLU_DEFAULT_SCHEME`
/// is active. Matches the C `DEFAULT_SCHEME` in `lib/urlapi.c`.
const DEFAULT_SCHEME: &str = "https";

/// Maximum length of a scheme string (matches C `MAX_SCHEME_LEN`).
const MAX_SCHEME_LEN: usize = 40;

/// Maximum URL length (matches C `MAX_URL_LEN`).
const MAX_URL_LEN: usize = 0xffff;

// ---------------------------------------------------------------------------
// CurlUrlPart — matches CURLUPART_* from include/curl/urlapi.h
// ---------------------------------------------------------------------------

/// Identifies a component of a URL for use with [`CurlUrl::set`] and
/// [`CurlUrl::get`].
///
/// Discriminant values match `CURLUPart` in `include/curl/urlapi.h` exactly
/// for FFI compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CurlUrlPart {
    /// The full URL.
    Url = 0,
    /// The scheme (e.g. `https`).
    Scheme = 1,
    /// The username.
    User = 2,
    /// The password.
    Password = 3,
    /// Protocol-specific options (e.g. IMAP `AUTH=PLAIN`).
    Options = 4,
    /// The hostname.
    Host = 5,
    /// The port number (as a string).
    Port = 6,
    /// The path.
    Path = 7,
    /// The query string (without the leading `?`).
    Query = 8,
    /// The fragment (without the leading `#`).
    Fragment = 9,
    /// The IPv6 zone ID.
    ZoneId = 10,
}

impl CurlUrlPart {
    /// Convert from an integer value, returning `None` for unknown parts.
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Url),
            1 => Some(Self::Scheme),
            2 => Some(Self::User),
            3 => Some(Self::Password),
            4 => Some(Self::Options),
            5 => Some(Self::Host),
            6 => Some(Self::Port),
            7 => Some(Self::Path),
            8 => Some(Self::Query),
            9 => Some(Self::Fragment),
            10 => Some(Self::ZoneId),
            _ => None,
        }
    }
}

impl fmt::Display for CurlUrlPart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Url => "URL",
            Self::Scheme => "Scheme",
            Self::User => "User",
            Self::Password => "Password",
            Self::Options => "Options",
            Self::Host => "Host",
            Self::Port => "Port",
            Self::Path => "Path",
            Self::Query => "Query",
            Self::Fragment => "Fragment",
            Self::ZoneId => "ZoneId",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// Scheme → default port mapping
// ---------------------------------------------------------------------------

/// Returns the default port number for a known scheme, or `None` for unknown
/// schemes. Values match `PORT_*` macros in `lib/urldata.h`.
fn default_port_for_scheme(scheme: &str) -> Option<u16> {
    match scheme.to_ascii_lowercase().as_str() {
        "http" => Some(80),
        "https" => Some(443),
        "ftp" => Some(21),
        "ftps" => Some(990),
        "ssh" | "sftp" | "scp" => Some(22),
        "telnet" => Some(23),
        "dict" => Some(2628),
        "ldap" => Some(389),
        "ldaps" => Some(636),
        "tftp" => Some(69),
        "imap" => Some(143),
        "imaps" => Some(993),
        "pop3" => Some(110),
        "pop3s" => Some(995),
        "smb" | "smbs" => Some(445),
        "smtp" => Some(25),
        "smtps" => Some(465),
        "rtsp" => Some(554),
        "rtmp" => Some(1935),
        "rtmpt" => Some(80),
        "rtmps" => Some(443),
        "gopher" => Some(70),
        "gophers" => Some(70),
        "mqtt" => Some(1883),
        "mqtts" => Some(8883),
        "ws" => Some(80),
        "wss" => Some(443),
        _ => None,
    }
}

/// Returns `true` if the given scheme implies TLS.
fn is_ssl_scheme(scheme: &str) -> bool {
    matches!(
        scheme.to_ascii_lowercase().as_str(),
        "https" | "ftps" | "imaps" | "pop3s" | "smtps" | "ldaps" | "smbs"
            | "rtmps" | "rtmpts" | "mqtts" | "wss" | "gophers"
    )
}

/// Returns `true` if the given scheme is known/supported.
fn is_supported_scheme(scheme: &str) -> bool {
    default_port_for_scheme(scheme).is_some() || scheme.eq_ignore_ascii_case("file")
}

// ---------------------------------------------------------------------------
// CurlUrl — the public URL handle
// ---------------------------------------------------------------------------

/// A URL handle that mirrors the C `CURLU` opaque type.
///
/// Wraps the [`url::Url`] crate for RFC 3986-compliant parsing and adds
/// curl-specific behaviors:
///
/// * Credential extraction (`user:password@host`)
/// * IPv6 zone-ID handling (`[::1%25eth0]`)
/// * Scheme guessing based on hostname prefix
/// * IDN / Punycode conversion
/// * Curl-compatible flag-driven get/set semantics
///
/// # Examples
///
/// ```
/// use curl_rs_lib::url::{CurlUrl, CurlUrlPart, CURLU_DEFAULT_SCHEME};
///
/// let mut u = CurlUrl::new();
/// u.set(CurlUrlPart::Url, "https://example.com/path?q=1#frag", 0).unwrap();
/// assert_eq!(u.get(CurlUrlPart::Scheme, 0).unwrap(), "https");
/// assert_eq!(u.get(CurlUrlPart::Host, 0).unwrap(), "example.com");
/// assert_eq!(u.get(CurlUrlPart::Path, 0).unwrap(), "/path");
/// assert_eq!(u.get(CurlUrlPart::Query, 0).unwrap(), "q=1");
/// assert_eq!(u.get(CurlUrlPart::Fragment, 0).unwrap(), "frag");
/// ```
#[derive(Debug, Clone)]
pub struct CurlUrl {
    /// The scheme component (lowercased).
    scheme: Option<String>,
    /// The username.
    user: Option<String>,
    /// The password.
    password: Option<String>,
    /// Protocol-specific options (e.g. IMAP AUTH).
    options: Option<String>,
    /// The hostname (may be IP literal).
    host: Option<String>,
    /// The IPv6 zone ID (e.g. `eth0`).
    zoneid: Option<String>,
    /// The port number as a string.
    port: Option<String>,
    /// The numeric port value.
    portnum: u16,
    /// The path component.
    path: Option<String>,
    /// The query string (without leading `?`).
    query: Option<String>,
    /// Whether a query was explicitly present (even if empty).
    query_present: bool,
    /// The fragment (without leading `#`).
    fragment: Option<String>,
    /// Whether a fragment was explicitly present (even if empty).
    fragment_present: bool,
    /// Whether the scheme was guessed (not explicitly provided).
    guessed_scheme: bool,
}

impl CurlUrl {
    // -------------------------------------------------------------------
    // Constructor — matches curl_url()
    // -------------------------------------------------------------------

    /// Creates a new, empty URL handle.
    ///
    /// Equivalent to `curl_url()` in C which allocates and zero-initializes
    /// a `struct Curl_URL`.
    pub fn new() -> Self {
        Self {
            scheme: None,
            user: None,
            password: None,
            options: None,
            host: None,
            zoneid: None,
            port: None,
            portnum: 0,
            path: None,
            query: None,
            query_present: false,
            fragment: None,
            fragment_present: false,
            guessed_scheme: false,
        }
    }

    // -------------------------------------------------------------------
    // set() — matches curl_url_set()
    // -------------------------------------------------------------------

    /// Set a specific URL component.
    ///
    /// Equivalent to `curl_url_set()`. Passing an empty string for most parts
    /// is treated as clearing that part (same as C behavior when `part` is
    /// `NULL`). The `flags` parameter is a bitmask of `CURLU_*` constants.
    ///
    /// # Errors
    ///
    /// Returns a [`CurlError`] wrapping the appropriate [`CurlUrlError`].
    pub fn set(&mut self, what: CurlUrlPart, content: &str, flags: u32) -> Result<(), CurlError> {
        // If content is empty and this is not the URL or Query/Fragment part,
        // treat it as a clear operation (matching C: passing NULL clears).
        if content.is_empty() && what != CurlUrlPart::Url
            && what != CurlUrlPart::Query
            && what != CurlUrlPart::Fragment
        {
            self.clear_part(what);
            return Ok(());
        }

        // Reject excessively long inputs.
        if content.len() > MAX_URL_LEN {
            return Err(url_err(CurlUrlError::MalformedInput));
        }

        // Scan for junk characters (control chars, etc.).
        let allow_space = flags & CURLU_ALLOW_SPACE != 0;
        junkscan(content, allow_space)?;

        match what {
            CurlUrlPart::Url => self.set_full_url(content, flags),
            CurlUrlPart::Scheme => self.set_scheme(content, flags),
            CurlUrlPart::User => self.set_user(content, flags),
            CurlUrlPart::Password => self.set_password(content, flags),
            CurlUrlPart::Options => self.set_options(content, flags),
            CurlUrlPart::Host => self.set_host(content, flags),
            CurlUrlPart::ZoneId => self.set_zoneid(content, flags),
            CurlUrlPart::Port => self.set_port(content),
            CurlUrlPart::Path => self.set_path(content, flags),
            CurlUrlPart::Query => self.set_query(content, flags),
            CurlUrlPart::Fragment => self.set_fragment(content, flags),
        }
    }

    // -------------------------------------------------------------------
    // get() — matches curl_url_get()
    // -------------------------------------------------------------------

    /// Get a specific URL component.
    ///
    /// Equivalent to `curl_url_get()`. The `flags` parameter is a bitmask of
    /// `CURLU_*` constants that control decoding, default values, and IDN
    /// conversion.
    ///
    /// # Errors
    ///
    /// Returns a [`CurlError`] wrapping the appropriate [`CurlUrlError`] when
    /// the requested part is not present.
    pub fn get(&self, what: CurlUrlPart, flags: u32) -> Result<String, CurlError> {
        match what {
            CurlUrlPart::Url => self.get_full_url(flags),
            CurlUrlPart::Scheme => self.get_scheme(flags),
            CurlUrlPart::User => self.get_string_part(&self.user, CurlUrlError::NoUser, flags),
            CurlUrlPart::Password => {
                self.get_string_part(&self.password, CurlUrlError::NoPassword, flags)
            }
            CurlUrlPart::Options => {
                self.get_string_part(&self.options, CurlUrlError::NoOptions, flags)
            }
            CurlUrlPart::Host => self.get_host(flags),
            CurlUrlPart::ZoneId => {
                self.get_string_part(&self.zoneid, CurlUrlError::NoZoneId, flags)
            }
            CurlUrlPart::Port => self.get_port(flags),
            CurlUrlPart::Path => self.get_path(flags),
            CurlUrlPart::Query => self.get_query(flags),
            CurlUrlPart::Fragment => self.get_fragment(flags),
        }
    }

    // -------------------------------------------------------------------
    // dup() — matches curl_url_dup()
    // -------------------------------------------------------------------

    /// Duplicate this URL handle.
    ///
    /// Equivalent to `curl_url_dup()` — returns a deep copy.
    pub fn dup(&self) -> Self {
        self.clone()
    }

    // -------------------------------------------------------------------
    // strerror() — matches curl_url_strerror()
    // -------------------------------------------------------------------

    /// Returns the human-readable error message for a URL error code.
    ///
    /// Equivalent to `curl_url_strerror()`. Delegates to
    /// [`CurlUrlError::strerror`].
    pub fn strerror(code: CurlUrlError) -> &'static str {
        code.strerror()
    }

    // -------------------------------------------------------------------
    // clear() — public clear API for FFI layer
    // -------------------------------------------------------------------

    /// Clear (reset to `None`) a single URL component.
    ///
    /// Equivalent to calling `curl_url_set(handle, what, NULL, 0)` in C —
    /// removes the specified component from the URL handle.  For
    /// [`CurlUrlPart::Url`], the entire handle is reset to its initial
    /// (empty) state.
    ///
    /// This method is the public counterpart of the private `clear_part`
    /// helper, exposed for the FFI crate to implement the NULL-content
    /// semantics of `curl_url_set`.
    pub fn clear(&mut self, what: CurlUrlPart) {
        self.clear_part(what);
    }

    // ===================================================================
    // Private: set helpers
    // ===================================================================

    /// Clear (reset to None) a single URL component.
    fn clear_part(&mut self, what: CurlUrlPart) {
        match what {
            CurlUrlPart::Url => {
                *self = Self::new();
            }
            CurlUrlPart::Scheme => {
                self.scheme = None;
                self.guessed_scheme = false;
            }
            CurlUrlPart::User => self.user = None,
            CurlUrlPart::Password => self.password = None,
            CurlUrlPart::Options => self.options = None,
            CurlUrlPart::Host => self.host = None,
            CurlUrlPart::ZoneId => self.zoneid = None,
            CurlUrlPart::Port => {
                self.port = None;
                self.portnum = 0;
            }
            CurlUrlPart::Path => self.path = None,
            CurlUrlPart::Query => {
                self.query = None;
                self.query_present = false;
            }
            CurlUrlPart::Fragment => {
                self.fragment = None;
                self.fragment_present = false;
            }
        }
    }

    /// Set the full URL, potentially resolving relative URLs against the
    /// existing contents.
    fn set_full_url(&mut self, url_str: &str, flags: u32) -> Result<(), CurlError> {
        if url_str.is_empty() {
            // An empty URL is a no-op if we already have a valid URL.
            if self.get_full_url(flags).is_ok() {
                return Ok(());
            }
            return Err(url_err(CurlUrlError::MalformedInput));
        }

        // Check if the new URL is absolute.
        let abs_len = is_absolute_url_len(
            url_str,
            flags & (CURLU_GUESS_SCHEME | CURLU_DEFAULT_SCHEME) != 0,
        );

        if abs_len > 0 {
            // Absolute URL: parse and replace.
            return self.parse_and_replace(url_str, flags);
        }

        // Relative URL: resolve against current base if possible.
        if let Ok(base) = self.get_full_url(flags) {
            if let Ok(base_url) = Url::parse(&base) {
                if let Ok(joined) = base_url.join(url_str) {
                    return self.parse_and_replace(joined.as_str(), flags & !CURLU_PATH_AS_IS);
                }
            }
        }

        // If we can't resolve it as relative, try parsing as absolute.
        self.parse_and_replace(url_str, flags)
    }

    /// Parse a URL string and replace all internal state.
    fn parse_and_replace(&mut self, url_str: &str, flags: u32) -> Result<(), CurlError> {
        let mut tmp = CurlUrl::new();
        tmp.parse_url(url_str, flags)?;
        *self = tmp;
        Ok(())
    }

    /// Core URL parser — populates internal fields from a URL string.
    fn parse_url(&mut self, url_str: &str, flags: u32) -> Result<(), CurlError> {
        let allow_space = flags & CURLU_ALLOW_SPACE != 0;
        junkscan(url_str, allow_space)?;

        let guess_scheme = flags & CURLU_GUESS_SCHEME != 0;
        let default_scheme = flags & CURLU_DEFAULT_SCHEME != 0;

        // Detect scheme.
        let scheme_len = is_absolute_url_len(url_str, guess_scheme || default_scheme);

        // Handle file:// URLs specially.
        if scheme_len > 0 {
            let scheme_str = url_str[..scheme_len].to_ascii_lowercase();
            if scheme_str == "file" {
                return self.parse_file_url(url_str, flags);
            }
        }

        // Determine the effective URL to parse.
        let effective_url: String;
        if scheme_len > 0 {
            let scheme_str = url_str[..scheme_len].to_ascii_lowercase();
            // Check scheme support.
            if !is_supported_scheme(&scheme_str) && flags & CURLU_NON_SUPPORT_SCHEME == 0 {
                return Err(url_err(CurlUrlError::UnsupportedScheme));
            }
            // Validate slashes after scheme.
            let after_colon = &url_str[scheme_len + 1..]; // skip ':'
            let slash_count = after_colon.bytes().take_while(|&b| b == b'/').count();
            if !(1..=3).contains(&slash_count) {
                return Err(url_err(CurlUrlError::BadSlashes));
            }
            effective_url = url_str.to_string();
            self.scheme = Some(scheme_str);
            self.guessed_scheme = false;
        } else {
            // No scheme detected.
            if !default_scheme && !guess_scheme {
                return Err(url_err(CurlUrlError::BadScheme));
            }

            // Build a full URL with a scheme for parsing.
            let with_scheme = format!("{DEFAULT_SCHEME}://{url_str}");
            effective_url = with_scheme;

            if default_scheme {
                self.scheme = Some(DEFAULT_SCHEME.to_string());
                self.guessed_scheme = false;
            }
            // Guess scheme is deferred until we know the host.
        }

        // Use the url crate for RFC 3986 parsing.
        let parsed = Url::parse(&effective_url).map_err(|_| url_err(CurlUrlError::MalformedInput))?;

        // Extract credentials.
        let username = parsed.username();
        if !username.is_empty() {
            if flags & CURLU_DISALLOW_USER != 0 {
                return Err(url_err(CurlUrlError::UserNotAllowed));
            }
            self.user = Some(username.to_string());
        }
        if let Some(pw) = parsed.password() {
            if flags & CURLU_DISALLOW_USER != 0 {
                return Err(url_err(CurlUrlError::UserNotAllowed));
            }
            self.password = Some(pw.to_string());
        }

        // Extract host.
        if let Some(host_str) = parsed.host_str() {
            let mut host = host_str.to_string();

            // Handle IPv6 addresses.
            if let Some(url::Host::Ipv6(addr)) = parsed.host() {
                // Check for zone ID in the original URL.
                let zone = extract_zone_id(url_str);
                if let Some(z) = zone {
                    self.zoneid = Some(z);
                }
                host = format!("[{addr}]");
            }

            if host.is_empty() && flags & CURLU_NO_AUTHORITY == 0 {
                return Err(url_err(CurlUrlError::NoHost));
            }

            // Validate hostname characters.
            if !host.is_empty() {
                validate_hostname(&host)?;
            }

            self.host = Some(host);
        } else if flags & CURLU_NO_AUTHORITY == 0 {
            return Err(url_err(CurlUrlError::NoHost));
        } else {
            self.host = Some(String::new());
        }

        // Guess scheme from hostname prefix if requested.
        if guess_scheme && self.scheme.is_none() {
            if let Some(ref h) = self.host {
                self.scheme = Some(guess_scheme_from_host(h));
                self.guessed_scheme = true;
            }
        }

        // Extract port.
        // The `url` crate's `port()` returns `None` when the port matches the
        // scheme's default. We need to check `port_or_known_default()` and also
        // look at the raw URL for an explicit port specification.
        if let Some(p) = parsed.port() {
            // Explicit non-default port.
            self.portnum = p;
            self.port = Some(p.to_string());
        } else {
            // Check if the URL contains an explicit port that matches the default.
            // The url crate normalizes default ports away, but curl preserves them.
            if let Some(explicit_port) = extract_explicit_port(&effective_url) {
                self.portnum = explicit_port;
                self.port = Some(explicit_port.to_string());
            }
        }

        // Extract path.
        let path_str = parsed.path();
        if path_str.is_empty() || path_str == "/" {
            self.path = None;
        } else if flags & CURLU_PATH_AS_IS != 0 {
            self.path = Some(path_str.to_string());
        } else {
            // Remove dot segments (RFC 3986 §5.2.4) — the url crate
            // already normalizes, but we apply dedotdotify for full parity.
            let dedotted = dedotdotify(path_str);
            if dedotted.is_empty() || dedotted == "/" {
                self.path = None;
            } else {
                self.path = Some(dedotted);
            }
        }

        // Extract query.
        if let Some(q) = parsed.query() {
            self.query = Some(q.to_string());
            self.query_present = true;
        } else {
            // Check if the original URL had a bare '?' (empty query).
            if effective_url.contains('?') {
                let after_q = effective_url.split('?').nth(1).unwrap_or("");
                if after_q.is_empty() || after_q.starts_with('#') {
                    self.query = Some(String::new());
                    self.query_present = true;
                }
            }
        }

        // Extract fragment.
        if let Some(frag) = parsed.fragment() {
            self.fragment = Some(frag.to_string());
            self.fragment_present = true;
        } else if effective_url.contains('#') {
            let after_hash = effective_url.rsplit('#').next().unwrap_or("");
            if after_hash.is_empty() {
                self.fragment_present = true;
            }
        }

        // Apply URL encoding if requested.
        if flags & CURLU_URLENCODE != 0 {
            self.encode_components();
        }

        Ok(())
    }

    /// Parse a `file://` URL.
    fn parse_file_url(&mut self, url_str: &str, flags: u32) -> Result<(), CurlError> {
        if url_str.len() <= 6 {
            return Err(url_err(CurlUrlError::BadFileUrl));
        }

        self.scheme = Some("file".to_string());
        self.guessed_scheme = false;

        // Use the url crate for file URL parsing.
        let parsed = Url::parse(url_str).map_err(|_| url_err(CurlUrlError::BadFileUrl))?;

        // file:// URLs should not have a meaningful host (just "" or "localhost").
        if let Some(host_str) = parsed.host_str() {
            let h = host_str.to_string();
            if !h.is_empty()
                && !h.eq_ignore_ascii_case("localhost")
                && h != "127.0.0.1"
            {
                // On non-Windows, reject non-local hosts.
                #[cfg(not(windows))]
                {
                    return Err(url_err(CurlUrlError::BadFileUrl));
                }
                // On Windows, treat as UNC path.
                #[cfg(windows)]
                {
                    self.host = Some(h);
                }
            }
        }

        let path_str = parsed.path();
        if path_str.is_empty() {
            self.path = None;
        } else {
            // On non-Windows, reject drive letter paths.
            #[cfg(not(windows))]
            {
                let p = path_str.as_bytes();
                if p.len() >= 3
                    && p[0] == b'/'
                    && p[1].is_ascii_alphabetic()
                    && (p[2] == b':' || p[2] == b'|')
                {
                    return Err(url_err(CurlUrlError::BadFileUrl));
                }
            }

            if flags & CURLU_PATH_AS_IS == 0 {
                self.path = Some(dedotdotify(path_str));
            } else {
                self.path = Some(path_str.to_string());
            }
        }

        // Extract query.
        if let Some(q) = parsed.query() {
            self.query = Some(q.to_string());
            self.query_present = true;
        }

        // Extract fragment.
        if let Some(frag) = parsed.fragment() {
            self.fragment = Some(frag.to_string());
            self.fragment_present = true;
        }

        Ok(())
    }

    /// Set the scheme part.
    fn set_scheme(&mut self, scheme: &str, flags: u32) -> Result<(), CurlError> {
        if scheme.is_empty() || scheme.len() > MAX_SCHEME_LEN {
            return Err(url_err(CurlUrlError::BadScheme));
        }

        // Validate scheme characters: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
        let bytes = scheme.as_bytes();
        if !bytes[0].is_ascii_alphabetic() {
            return Err(url_err(CurlUrlError::BadScheme));
        }
        for &b in &bytes[1..] {
            if !b.is_ascii_alphanumeric() && b != b'+' && b != b'-' && b != b'.' {
                return Err(url_err(CurlUrlError::BadScheme));
            }
        }

        let lower = scheme.to_ascii_lowercase();

        // Verify support unless NON_SUPPORT_SCHEME is set.
        if flags & CURLU_NON_SUPPORT_SCHEME == 0 && !is_supported_scheme(&lower) {
            return Err(url_err(CurlUrlError::UnsupportedScheme));
        }

        self.scheme = Some(lower);
        self.guessed_scheme = false;
        Ok(())
    }

    /// Set the user part.
    fn set_user(&mut self, user: &str, flags: u32) -> Result<(), CurlError> {
        let value = if flags & CURLU_URLENCODE != 0 {
            escape::url_encode(user)
        } else {
            normalize_percent_encoding(user)
        };
        self.user = Some(value);
        Ok(())
    }

    /// Set the password part.
    fn set_password(&mut self, password: &str, flags: u32) -> Result<(), CurlError> {
        let value = if flags & CURLU_URLENCODE != 0 {
            escape::url_encode(password)
        } else {
            normalize_percent_encoding(password)
        };
        self.password = Some(value);
        Ok(())
    }

    /// Set the options part.
    fn set_options(&mut self, options: &str, flags: u32) -> Result<(), CurlError> {
        let value = if flags & CURLU_URLENCODE != 0 {
            escape::url_encode(options)
        } else {
            options.to_string()
        };
        self.options = Some(value);
        Ok(())
    }

    /// Set the host part.
    fn set_host(&mut self, host: &str, flags: u32) -> Result<(), CurlError> {
        self.zoneid = None;

        if host.is_empty() && flags & CURLU_NO_AUTHORITY != 0 {
            self.host = Some(String::new());
            return Ok(());
        }

        if host.is_empty() {
            return Err(url_err(CurlUrlError::BadHostname));
        }

        // Check for IPv6 zone ID.
        if host.starts_with('[') {
            if let Some(zone) = extract_zone_id(host) {
                self.zoneid = Some(zone);
            }
        }

        // Validate the hostname.
        let effective_host = if flags & CURLU_URLENCODE != 0 {
            // Hostname should not be URL-encoded for validation.
            host.to_string()
        } else {
            // If the host was provided pre-encoded, decode for validation.
            if host.contains('%') && !host.starts_with('[') {
                match escape::url_decode_string(host) {
                    Ok(decoded) => {
                        validate_hostname(&decoded)?;
                        host.to_string()
                    }
                    Err(_) => {
                        return Err(url_err(CurlUrlError::BadHostname));
                    }
                }
            } else {
                validate_hostname(host)?;
                host.to_string()
            }
        };

        self.host = Some(effective_host);
        Ok(())
    }

    /// Set the zone ID part.
    fn set_zoneid(&mut self, zoneid: &str, flags: u32) -> Result<(), CurlError> {
        let value = if flags & CURLU_URLENCODE != 0 {
            escape::url_encode(zoneid)
        } else {
            zoneid.to_string()
        };
        self.zoneid = Some(value);
        Ok(())
    }

    /// Set the port part (from a string).
    fn set_port(&mut self, port_str: &str) -> Result<(), CurlError> {
        // Must be a valid decimal number in 0..65535.
        let port: u16 = port_str
            .parse()
            .map_err(|_| url_err(CurlUrlError::BadPortNumber))?;

        // Regenerate the string without leading zeros.
        self.port = Some(port.to_string());
        self.portnum = port;
        Ok(())
    }

    /// Set the path part.
    fn set_path(&mut self, path: &str, flags: u32) -> Result<(), CurlError> {
        let mut value = if flags & CURLU_URLENCODE != 0 {
            encode_path(path)
        } else {
            normalize_percent_encoding(path)
        };

        // Enforce leading slash.
        if !value.starts_with('/') {
            value.insert(0, '/');
        }

        // Remove dot segments unless PATH_AS_IS.
        if flags & CURLU_PATH_AS_IS == 0 {
            value = dedotdotify(&value);
        }

        self.path = Some(value);
        Ok(())
    }

    /// Set the query part.
    fn set_query(&mut self, query: &str, flags: u32) -> Result<(), CurlError> {
        self.query_present = true;

        let encoded = if flags & CURLU_URLENCODE != 0 {
            encode_query(query, flags & CURLU_APPENDQUERY != 0)
        } else {
            normalize_percent_encoding(query)
        };

        if flags & CURLU_APPENDQUERY != 0 {
            // Append to existing query with '&' separator.
            if let Some(ref existing) = self.query {
                if !existing.is_empty() {
                    let sep = if existing.ends_with('&') { "" } else { "&" };
                    self.query = Some(format!("{existing}{sep}{encoded}"));
                    return Ok(());
                }
            }
        }

        self.query = Some(encoded);
        Ok(())
    }

    /// Set the fragment part.
    fn set_fragment(&mut self, fragment: &str, flags: u32) -> Result<(), CurlError> {
        self.fragment_present = true;

        let value = if flags & CURLU_URLENCODE != 0 {
            escape::url_encode(fragment)
        } else {
            normalize_percent_encoding(fragment)
        };
        self.fragment = Some(value);
        Ok(())
    }

    /// Apply URL-encoding to relevant stored components.
    fn encode_components(&mut self) {
        if let Some(ref u) = self.user {
            self.user = Some(escape::url_encode(u));
        }
        if let Some(ref p) = self.password {
            self.password = Some(escape::url_encode(p));
        }
    }

    // ===================================================================
    // Private: get helpers
    // ===================================================================

    /// Get the full reconstructed URL.
    fn get_full_url(&self, flags: u32) -> Result<String, CurlError> {
        // file:// is special.
        if self.scheme.as_deref() == Some("file") {
            return self.get_file_url(flags);
        }

        // We need a host for non-file URLs.
        let host = self.host.as_deref().ok_or(url_err(CurlUrlError::NoHost))?;

        // Determine scheme.
        let scheme = if let Some(ref s) = self.scheme {
            s.clone()
        } else if flags & CURLU_DEFAULT_SCHEME != 0 {
            DEFAULT_SCHEME.to_string()
        } else {
            return Err(url_err(CurlUrlError::NoScheme));
        };

        // If NO_GUESS_SCHEME is set and scheme was guessed, suppress it.
        let scheme_prefix = if flags & CURLU_NO_GUESS_SCHEME != 0 && self.guessed_scheme {
            String::new()
        } else {
            format!("{scheme}://")
        };

        // Determine port string.
        let port_str = self.resolve_port_for_get(&scheme, flags);

        // Host representation with zone ID.
        let display_host = self.format_host_for_url(host, flags)?;

        // Build credentials portion.
        let creds = self.format_credentials_for_url();

        // Path (default to "/").
        let path = self.path.as_deref().unwrap_or("/");

        // Query.
        let show_query = self.query.as_ref().is_some_and(|q| {
            !q.is_empty() || (self.query_present && flags & CURLU_GET_EMPTY != 0)
        });

        // Fragment.
        let show_fragment = self.fragment.is_some()
            || (self.fragment_present && flags & CURLU_GET_EMPTY != 0);

        let mut url = format!("{scheme_prefix}{creds}{display_host}");

        if let Some(ref p) = port_str {
            url.push(':');
            url.push_str(p);
        }

        url.push_str(path);

        if show_query {
            url.push('?');
            if let Some(ref q) = self.query {
                url.push_str(q);
            }
        }

        if show_fragment {
            url.push('#');
            if let Some(ref f) = self.fragment {
                url.push_str(f);
            }
        }

        Ok(url)
    }

    /// Get a file:// URL.
    fn get_file_url(&self, flags: u32) -> Result<String, CurlError> {
        let path = self.path.as_deref().unwrap_or("/");

        let show_query = self.query.as_ref().is_some_and(|q| {
            !q.is_empty() || (self.query_present && flags & CURLU_GET_EMPTY != 0)
        });
        let show_fragment = self.fragment.is_some()
            || (self.fragment_present && flags & CURLU_GET_EMPTY != 0);

        let mut url = format!("file://{path}");

        if show_query {
            url.push('?');
            if let Some(ref q) = self.query {
                url.push_str(q);
            }
        }
        if show_fragment {
            url.push('#');
            if let Some(ref f) = self.fragment {
                url.push_str(f);
            }
        }

        Ok(url)
    }

    /// Get the scheme.
    fn get_scheme(&self, flags: u32) -> Result<String, CurlError> {
        // Never URL-decode schemes.
        if flags & CURLU_NO_GUESS_SCHEME != 0 && self.guessed_scheme {
            return Err(url_err(CurlUrlError::NoScheme));
        }
        if let Some(ref s) = self.scheme {
            Ok(s.clone())
        } else if flags & CURLU_DEFAULT_SCHEME != 0 {
            Ok(DEFAULT_SCHEME.to_string())
        } else {
            Err(url_err(CurlUrlError::NoScheme))
        }
    }

    /// Get the host.
    fn get_host(&self, flags: u32) -> Result<String, CurlError> {
        let host = self
            .host
            .as_deref()
            .ok_or(url_err(CurlUrlError::NoHost))?;

        if host.is_empty() {
            return Err(url_err(CurlUrlError::NoHost));
        }

        let mut result = host.to_string();

        // Apply URLDECODE.
        if flags & CURLU_URLDECODE != 0 {
            result = decode_part(&result)?;
        }

        // Apply PUNYCODE (IDN → ASCII).
        if flags & CURLU_PUNYCODE != 0 && !is_ascii_hostname(host) {
            result = idn::idn_to_ascii(&result).map_err(|_| url_err(CurlUrlError::BadHostname))?;
        }

        // Apply PUNY2IDN (ASCII → Unicode).
        if flags & CURLU_PUNY2IDN != 0 && is_ascii_hostname(host) {
            match idn::idn_to_unicode(&result) {
                Ok(unicode) => result = unicode,
                Err(_) => return Err(url_err(CurlUrlError::BadHostname)),
            }
        }

        Ok(result)
    }

    /// Get the port.
    fn get_port(&self, flags: u32) -> Result<String, CurlError> {
        // Check for stored port.
        if let Some(ref p) = self.port {
            // NO_DEFAULT_PORT: suppress if matches scheme default.
            if flags & CURLU_NO_DEFAULT_PORT != 0 {
                if let Some(ref s) = self.scheme {
                    if let Some(def) = default_port_for_scheme(s) {
                        if self.portnum == def {
                            return Err(url_err(CurlUrlError::NoPort));
                        }
                    }
                }
            }
            return Ok(p.clone());
        }

        // DEFAULT_PORT: return scheme default.
        if flags & CURLU_DEFAULT_PORT != 0 {
            if let Some(ref s) = self.scheme {
                if let Some(def) = default_port_for_scheme(s) {
                    return Ok(def.to_string());
                }
            }
        }

        Err(url_err(CurlUrlError::NoPort))
    }

    /// Get the path (defaults to "/" if not set).
    fn get_path(&self, flags: u32) -> Result<String, CurlError> {
        let path = self.path.as_deref().unwrap_or("/");
        let mut result = path.to_string();

        if flags & CURLU_URLDECODE != 0 {
            result = decode_part(&result)?;
        }

        Ok(result)
    }

    /// Get the query.
    fn get_query(&self, flags: u32) -> Result<String, CurlError> {
        if let Some(ref q) = self.query {
            if q.is_empty() && flags & CURLU_GET_EMPTY == 0 {
                return Err(url_err(CurlUrlError::NoQuery));
            }
            let mut result = q.clone();
            if flags & CURLU_URLDECODE != 0 {
                // Plus-decode in query context.
                result = result.replace('+', " ");
                result = decode_part(&result)?;
            }
            Ok(result)
        } else {
            Err(url_err(CurlUrlError::NoQuery))
        }
    }

    /// Get the fragment.
    fn get_fragment(&self, flags: u32) -> Result<String, CurlError> {
        if let Some(ref f) = self.fragment {
            let mut result = f.clone();
            if flags & CURLU_URLDECODE != 0 {
                result = decode_part(&result)?;
            }
            Ok(result)
        } else if self.fragment_present && flags & CURLU_GET_EMPTY != 0 {
            Ok(String::new())
        } else {
            Err(url_err(CurlUrlError::NoFragment))
        }
    }

    /// Generic getter for simple Optional<String> parts.
    fn get_string_part(
        &self,
        value: &Option<String>,
        if_missing: CurlUrlError,
        flags: u32,
    ) -> Result<String, CurlError> {
        if let Some(ref v) = value {
            let mut result = v.clone();
            if flags & CURLU_URLDECODE != 0 {
                result = decode_part(&result)?;
            }
            Ok(result)
        } else {
            Err(url_err(if_missing))
        }
    }

    /// Resolve the port string for URL reconstruction.
    fn resolve_port_for_get(&self, scheme: &str, flags: u32) -> Option<String> {
        if let Some(ref p) = self.port {
            // Suppress default port if requested.
            if flags & CURLU_NO_DEFAULT_PORT != 0 {
                if let Some(def) = default_port_for_scheme(scheme) {
                    if self.portnum == def {
                        return None;
                    }
                }
            }
            Some(p.clone())
        } else if flags & CURLU_DEFAULT_PORT != 0 {
            default_port_for_scheme(scheme).map(|p| p.to_string())
        } else {
            None
        }
    }

    /// Format the host for URL output, handling zone IDs.
    fn format_host_for_url(&self, host: &str, flags: u32) -> Result<String, CurlError> {
        let mut display = host.to_string();

        // IPv6 with zone ID.
        if host.starts_with('[') && self.zoneid.is_some() {
            if let Some(ref zone) = self.zoneid {
                // Insert zone ID: [addr%25zoneid]
                if let Some(pos) = display.rfind(']') {
                    display = format!("{}%25{}]", &display[..pos], zone);
                }
            }
        } else if flags & CURLU_URLENCODE != 0 && !host.starts_with('[') {
            display = escape::url_encode(host);
        } else if flags & CURLU_PUNYCODE != 0 && !is_ascii_hostname(host) {
            display =
                idn::idn_to_ascii(host).map_err(|_| url_err(CurlUrlError::BadHostname))?;
        } else if flags & CURLU_PUNY2IDN != 0 && is_ascii_hostname(host) {
            if let Ok(unicode) = idn::idn_to_unicode(host) {
                display = unicode;
            }
        }

        Ok(display)
    }

    /// Format credentials for URL output.
    fn format_credentials_for_url(&self) -> String {
        let has_creds =
            self.user.is_some() || self.password.is_some() || self.options.is_some();
        if !has_creds {
            return String::new();
        }

        let mut creds = String::new();
        if let Some(ref u) = self.user {
            creds.push_str(u);
        }
        if let Some(ref p) = self.password {
            creds.push(':');
            creds.push_str(p);
        }
        if let Some(ref o) = self.options {
            creds.push(';');
            creds.push_str(o);
        }
        creds.push('@');
        creds
    }
}

impl Default for CurlUrl {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CurlUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.get(CurlUrlPart::Url, 0) {
            Ok(url) => f.write_str(&url),
            Err(_) => f.write_str("<incomplete URL>"),
        }
    }
}

// ---------------------------------------------------------------------------
// ConnectionConfig — from lib/url.c connection setup logic
// ---------------------------------------------------------------------------

/// Connection parameters resolved from a URL and transfer options.
///
/// This struct captures the information extracted from a [`CurlUrl`] that is
/// needed to establish a network connection. It replaces the connection
/// resolution logic spread across `Curl_connect()`, `setup_connection_internals()`,
/// and `findprotocol()` in `lib/url.c`.
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// The resolved scheme (e.g. `https`).
    scheme_value: String,
    /// The resolved hostname.
    host_value: String,
    /// The resolved port number.
    port_value: u16,
    /// The request path.
    path_value: String,
    /// The username for authentication (if any).
    username_value: Option<String>,
    /// The password for authentication (if any).
    password_value: Option<String>,
    /// The proxy URL (if any).
    proxy_url_value: Option<String>,
    /// Whether TLS is required.
    ssl: bool,
    /// The default port for the resolved scheme.
    default_port_value: u16,
}

impl ConnectionConfig {
    /// Create a new `ConnectionConfig` from a [`CurlUrl`].
    ///
    /// Extracts scheme, host, port, path, credentials, and TLS requirement
    /// from the URL handle. If no port is explicitly set, the scheme's
    /// default port is used.
    pub fn from_url(url: &CurlUrl) -> CurlResult<Self> {
        let scheme = url
            .get(CurlUrlPart::Scheme, CURLU_DEFAULT_SCHEME)
            .unwrap_or_else(|_| DEFAULT_SCHEME.to_string());

        let host = url
            .get(CurlUrlPart::Host, 0)
            .unwrap_or_default();

        let default_port = default_port_for_scheme(&scheme).unwrap_or(0);

        let port = url
            .get(CurlUrlPart::Port, CURLU_DEFAULT_PORT)
            .ok()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(default_port);

        let path = url
            .get(CurlUrlPart::Path, 0)
            .unwrap_or_else(|_| "/".to_string());

        let username = url.get(CurlUrlPart::User, 0).ok();
        let password = url.get(CurlUrlPart::Password, 0).ok();

        let ssl = is_ssl_scheme(&scheme);

        tracing::debug!(
            scheme = %scheme,
            host = %host,
            port = port,
            ssl = ssl,
            "Resolved connection config from URL"
        );

        Ok(Self {
            scheme_value: scheme,
            host_value: host,
            port_value: port,
            path_value: path,
            username_value: username,
            password_value: password,
            proxy_url_value: None,
            ssl,
            default_port_value: default_port,
        })
    }

    /// The resolved scheme (e.g. `https`).
    pub fn scheme(&self) -> &str {
        &self.scheme_value
    }

    /// The resolved hostname.
    pub fn host(&self) -> &str {
        &self.host_value
    }

    /// The resolved port number.
    pub fn port(&self) -> u16 {
        self.port_value
    }

    /// The request path.
    pub fn path(&self) -> &str {
        &self.path_value
    }

    /// The username for authentication (if any).
    pub fn username(&self) -> Option<&str> {
        self.username_value.as_deref()
    }

    /// The password for authentication (if any).
    pub fn password(&self) -> Option<&str> {
        self.password_value.as_deref()
    }

    /// The proxy URL (if any).
    pub fn proxy_url(&self) -> Option<&str> {
        self.proxy_url_value.as_deref()
    }

    /// Whether TLS is required for this connection.
    pub fn is_ssl(&self) -> bool {
        self.ssl
    }

    /// The default port for the resolved scheme.
    pub fn default_port(&self) -> u16 {
        self.default_port_value
    }

    /// Set the proxy URL.
    pub fn set_proxy_url(&mut self, proxy: Option<String>) {
        self.proxy_url_value = proxy;
    }
}

// ---------------------------------------------------------------------------
// is_absolute_url — public function export
// ---------------------------------------------------------------------------

/// Returns `true` if the given string is an absolute URL (has a scheme
/// followed by `:`).
///
/// This is the Rust equivalent of `Curl_is_absolute_url()` from
/// `lib/urlapi-int.h` / `lib/urlapi.c`. When `guess_scheme` is true, the
/// detection is stricter: the colon must be followed by `/` to distinguish
/// from a hostname with a port number.
pub fn is_absolute_url(url: &str) -> bool {
    is_absolute_url_len(url, false) > 0
}

/// Returns the length of the scheme if the URL is absolute, or 0 if it is
/// relative. Matches the C `Curl_is_absolute_url()` behavior.
fn is_absolute_url_len(url: &str, guess_scheme: bool) -> usize {
    let bytes = url.as_bytes();

    // On Windows, a drive letter prefix like `C:` should not be mistaken
    // for a scheme when guessing.
    #[cfg(windows)]
    {
        if guess_scheme
            && bytes.len() >= 2
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
        {
            return 0;
        }
    }

    if bytes.is_empty() || !bytes[0].is_ascii_alphabetic() {
        return 0;
    }

    let mut i = 1;
    while i < bytes.len() && i < MAX_SCHEME_LEN {
        let b = bytes[i];
        if b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.' {
            i += 1;
        } else {
            break;
        }
    }

    if i > 0 && i < bytes.len() && bytes[i] == b':' {
        // In guess mode, require '/' after ':' to avoid matching `host:port`.
        if guess_scheme {
            if i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                return i;
            }
            return 0;
        }
        return i;
    }

    0
}

// ---------------------------------------------------------------------------
// Private helper functions
// ---------------------------------------------------------------------------

/// Convert a [`CurlUrlError`] into a [`CurlError`] by wrapping as
/// `UrlMalformat` with the specific URL error as context.
fn url_err(uc: CurlUrlError) -> CurlError {
    // Map specific CURLUcode to CURLcode as `lib/url.c` `Curl_uc_to_curlcode` does.
    match uc {
        CurlUrlError::Ok => CurlError::Ok,
        CurlUrlError::UnsupportedScheme => CurlError::UnsupportedProtocol,
        CurlUrlError::OutOfMemory => CurlError::OutOfMemory,
        CurlUrlError::UserNotAllowed => CurlError::LoginDenied,
        _ => CurlError::UrlMalformat,
    }
}

/// Scan a URL string for junk characters (control chars).
///
/// Matches `Curl_junkscan()` in `lib/urlapi.c`: reject bytes ≤ 0x1f (or
/// ≤ 0x20 if spaces are not allowed) and byte 0x7f.
fn junkscan(url: &str, allow_space: bool) -> Result<(), CurlError> {
    let control_limit: u8 = if allow_space { 0x1f } else { 0x20 };
    for &b in url.as_bytes() {
        if b <= control_limit || b == 0x7f {
            return Err(url_err(CurlUrlError::MalformedInput));
        }
    }
    Ok(())
}

/// Validate a hostname string.
///
/// Matches `hostname_check()` in `lib/urlapi.c`: IPv6 brackets are OK,
/// otherwise reject characters not valid in hostnames.
fn validate_hostname(host: &str) -> Result<(), CurlError> {
    if host.is_empty() {
        return Err(url_err(CurlUrlError::NoHost));
    }

    // IPv6 literal.
    if host.starts_with('[') {
        if !host.ends_with(']') {
            return Err(url_err(CurlUrlError::BadIpv6));
        }
        let inner = &host[1..host.len() - 1];
        // Strip zone ID for validation.
        let addr_part = if let Some(pos) = inner.find('%') {
            &inner[..pos]
        } else {
            inner
        };
        if Ipv6Addr::from_str(addr_part).is_err() {
            return Err(url_err(CurlUrlError::BadIpv6));
        }
        return Ok(());
    }

    // Hostname characters.
    let bad_chars = " \r\n\t/:#?!@{}[]\\$\'\"`^*<>=;,+&()%";
    for ch in host.chars() {
        if bad_chars.contains(ch) {
            return Err(url_err(CurlUrlError::BadHostname));
        }
        if (ch as u32) < 0x20 || ch as u32 == 0x7f {
            return Err(url_err(CurlUrlError::BadHostname));
        }
    }

    Ok(())
}

/// Extract an IPv6 zone ID from a URL string or host.
///
/// Looks for `%25` (or `%`) after an IPv6 address in brackets and extracts
/// the zone ID string.
fn extract_zone_id(url: &str) -> Option<String> {
    // Find the IPv6 bracket section.
    let start = url.find('[')?;
    let end = url[start..].find(']').map(|i| start + i)?;
    let bracket_content = &url[start + 1..end];

    // Zone ID is after % or %25.
    if let Some(pct_pos) = bracket_content.find("%25") {
        let zone = &bracket_content[pct_pos + 3..];
        if !zone.is_empty() {
            return Some(zone.to_string());
        }
    } else if let Some(pct_pos) = bracket_content.find('%') {
        let zone = &bracket_content[pct_pos + 1..];
        if !zone.is_empty() {
            return Some(zone.to_string());
        }
    }

    None
}

/// Guess the URL scheme from the hostname prefix (legacy curl behavior).
///
/// Matches `guess_scheme()` in `lib/urlapi.c`.
fn guess_scheme_from_host(host: &str) -> String {
    let lower = host.to_ascii_lowercase();
    if lower.starts_with("ftp.") {
        "ftp".to_string()
    } else if lower.starts_with("dict.") {
        "dict".to_string()
    } else if lower.starts_with("ldap.") {
        "ldap".to_string()
    } else if lower.starts_with("imap.") {
        "imap".to_string()
    } else if lower.starts_with("smtp.") {
        "smtp".to_string()
    } else if lower.starts_with("pop3.") {
        "pop3".to_string()
    } else {
        "http".to_string()
    }
}

/// Extract an explicit port from a URL string even when it matches the
/// scheme's default. The `url` crate normalizes default ports away, but
/// curl preserves them when explicitly specified. This function parses
/// the raw URL to detect `:PORT` after the host.
fn extract_explicit_port(url: &str) -> Option<u16> {
    // Find the authority section (after "://").
    let authority_start = url.find("://")?;
    let after_scheme = &url[authority_start + 3..];

    // Skip userinfo (anything before '@').
    let host_start = after_scheme.find('@').map_or(0, |pos| pos + 1);
    let host_and_rest = &after_scheme[host_start..];

    // If it's an IPv6 literal, skip to the closing bracket.
    let port_search_start = if host_and_rest.starts_with('[') {
        host_and_rest.find(']').map_or(0, |pos| pos + 1)
    } else {
        0
    };

    let search_area = &host_and_rest[port_search_start..];

    // Find the colon before port.
    let colon_pos = search_area.find(':')?;
    let after_colon = &search_area[colon_pos + 1..];

    // Extract digits until '/', '?', '#' or end.
    let port_str: String = after_colon
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();

    if port_str.is_empty() {
        return None;
    }

    port_str.parse::<u16>().ok()
}

/// Returns `true` if every byte in the hostname is ASCII (no high-bit set).
fn is_ascii_hostname(host: &str) -> bool {
    host.bytes().all(|b| b & 0x80 == 0)
}

/// Normalize percent-encoding to lowercase hex digits (matching C behavior
/// where `curl_url_set` lowercases `%XX` sequences).
fn normalize_percent_encoding(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut result = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h1 = bytes[i + 1];
            let h2 = bytes[i + 2];
            if h1.is_ascii_hexdigit() && h2.is_ascii_hexdigit() {
                result.push('%');
                result.push((h1 as char).to_ascii_lowercase());
                result.push((h2 as char).to_ascii_lowercase());
                i += 3;
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

/// URL-decode a part, rejecting control characters.
fn decode_part(input: &str) -> Result<String, CurlError> {
    let bytes = match escape::url_decode(input) {
        Ok(b) => b,
        Err(_) => return Err(url_err(CurlUrlError::UrlDecode)),
    };
    // Reject control characters (matching C REJECT_CTRL behavior).
    for &b in &bytes {
        if b < 0x20 {
            return Err(url_err(CurlUrlError::UrlDecode));
        }
    }
    String::from_utf8(bytes).map_err(|_| url_err(CurlUrlError::UrlDecode))
}

/// Encode a path component, preserving characters allowed in paths.
fn encode_path(path: &str) -> String {
    let mut result = String::with_capacity(path.len() * 3);
    for &b in path.as_bytes() {
        if b.is_ascii_alphanumeric()
            || b == b'-'
            || b == b'.'
            || b == b'_'
            || b == b'~'
            || is_allowed_in_path(b)
        {
            result.push(b as char);
        } else if b == b' ' {
            result.push_str("%20");
        } else {
            result.push('%');
            result.push(hex_char(b >> 4));
            result.push(hex_char(b & 0x0f));
        }
    }
    result
}

/// Characters allowed unencoded in a URL path beyond unreserved.
/// Matches `allowed_in_path()` in `lib/urlapi.c`.
fn is_allowed_in_path(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'{' | b'}' | b'[' | b']'
            | b'*' | b'+' | b',' | b';' | b'=' | b':' | b'@' | b'/'
    )
}

/// Encode a query string, handling plus-encoding for spaces and the
/// first `=` in append mode.
fn encode_query(query: &str, append_mode: bool) -> String {
    let mut result = String::with_capacity(query.len() * 3);
    let mut first_equals_seen = !append_mode;
    for &b in query.as_bytes() {
        if b == b' ' {
            result.push('+');
        } else if b == b'=' && !first_equals_seen {
            first_equals_seen = true;
            result.push('=');
        } else if b.is_ascii_alphanumeric()
            || b == b'-'
            || b == b'.'
            || b == b'_'
            || b == b'~'
        {
            result.push(b as char);
        } else {
            result.push('%');
            result.push(hex_char(b >> 4));
            result.push(hex_char(b & 0x0f));
        }
    }
    result
}

/// Convert a nibble (0–15) to an uppercase hex character.
fn hex_char(nibble: u8) -> char {
    let n = nibble & 0x0f;
    if n < 10 {
        (b'0' + n) as char
    } else {
        (b'A' + n - 10) as char
    }
}

/// Remove dot segments from a path per RFC 3986 §5.2.4.
///
/// Matches `dedotdotify()` in `lib/urlapi.c`.
fn dedotdotify(input: &str) -> String {
    if input.len() < 2 {
        return input.to_string();
    }

    let mut output: Vec<&str> = Vec::new();
    let segments: Vec<&str> = input.split('/').collect();

    // Handle relative paths.
    let is_absolute = input.starts_with('/');

    // Process each segment.
    let mut i = 0;
    while i < segments.len() {
        let seg = segments[i];
        if seg == "." {
            // Skip single dot.
            i += 1;
            continue;
        } else if seg == ".." {
            // Go up one level.
            if !output.is_empty() && output.last() != Some(&"") {
                output.pop();
            }
            i += 1;
            continue;
        } else if seg == "%2e" || seg == "%2E" {
            // Encoded single dot.
            i += 1;
            continue;
        } else if seg == "%2e%2e" || seg == "%2E%2E" || seg == "%2e." || seg == ".%2e"
            || seg == "%2E." || seg == ".%2E"
        {
            // Encoded double dot.
            if !output.is_empty() && output.last() != Some(&"") {
                output.pop();
            }
            i += 1;
            continue;
        }
        output.push(seg);
        i += 1;
    }

    let result = output.join("/");

    // Ensure absolute paths start with '/'.
    if is_absolute && !result.starts_with('/') {
        format!("/{result}")
    } else {
        result
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Flag constant values match C --

    #[test]
    fn flag_values_match_c() {
        assert_eq!(CURLU_DEFAULT_PORT, 1 << 0);
        assert_eq!(CURLU_NO_DEFAULT_PORT, 1 << 1);
        assert_eq!(CURLU_DEFAULT_SCHEME, 1 << 2);
        assert_eq!(CURLU_NON_SUPPORT_SCHEME, 1 << 3);
        assert_eq!(CURLU_PATH_AS_IS, 1 << 4);
        assert_eq!(CURLU_DISALLOW_USER, 1 << 5);
        assert_eq!(CURLU_URLDECODE, 1 << 6);
        assert_eq!(CURLU_URLENCODE, 1 << 7);
        assert_eq!(CURLU_APPENDQUERY, 1 << 8);
        assert_eq!(CURLU_GUESS_SCHEME, 1 << 9);
        assert_eq!(CURLU_NO_AUTHORITY, 1 << 10);
        assert_eq!(CURLU_ALLOW_SPACE, 1 << 11);
        assert_eq!(CURLU_PUNYCODE, 1 << 12);
        assert_eq!(CURLU_PUNY2IDN, 1 << 13);
        assert_eq!(CURLU_GET_EMPTY, 1 << 14);
        assert_eq!(CURLU_NO_GUESS_SCHEME, 1 << 15);
    }

    // -- CurlUrlPart discriminants match C CURLUPART_* --

    #[test]
    fn url_part_values_match_c() {
        assert_eq!(CurlUrlPart::Url as i32, 0);
        assert_eq!(CurlUrlPart::Scheme as i32, 1);
        assert_eq!(CurlUrlPart::User as i32, 2);
        assert_eq!(CurlUrlPart::Password as i32, 3);
        assert_eq!(CurlUrlPart::Options as i32, 4);
        assert_eq!(CurlUrlPart::Host as i32, 5);
        assert_eq!(CurlUrlPart::Port as i32, 6);
        assert_eq!(CurlUrlPart::Path as i32, 7);
        assert_eq!(CurlUrlPart::Query as i32, 8);
        assert_eq!(CurlUrlPart::Fragment as i32, 9);
        assert_eq!(CurlUrlPart::ZoneId as i32, 10);
    }

    // -- CurlUrl basic lifecycle --

    #[test]
    fn new_and_set_full_url() {
        let mut u = CurlUrl::new();
        u.set(CurlUrlPart::Url, "https://example.com/path?q=1#frag", 0)
            .unwrap();
        assert_eq!(u.get(CurlUrlPart::Scheme, 0).unwrap(), "https");
        assert_eq!(u.get(CurlUrlPart::Host, 0).unwrap(), "example.com");
        assert_eq!(u.get(CurlUrlPart::Path, 0).unwrap(), "/path");
        assert_eq!(u.get(CurlUrlPart::Query, 0).unwrap(), "q=1");
        assert_eq!(u.get(CurlUrlPart::Fragment, 0).unwrap(), "frag");
    }

    #[test]
    fn set_individual_parts() {
        let mut u = CurlUrl::new();
        u.set(CurlUrlPart::Scheme, "https", 0).unwrap();
        u.set(CurlUrlPart::Host, "example.com", 0).unwrap();
        u.set(CurlUrlPart::Path, "/test", 0).unwrap();
        u.set(CurlUrlPart::Port, "8080", 0).unwrap();

        assert_eq!(u.get(CurlUrlPart::Scheme, 0).unwrap(), "https");
        assert_eq!(u.get(CurlUrlPart::Host, 0).unwrap(), "example.com");
        assert_eq!(u.get(CurlUrlPart::Path, 0).unwrap(), "/test");
        assert_eq!(u.get(CurlUrlPart::Port, 0).unwrap(), "8080");
    }

    #[test]
    fn dup_is_independent_copy() {
        let mut u = CurlUrl::new();
        u.set(CurlUrlPart::Url, "https://example.com/path", 0).unwrap();
        let u2 = u.dup();
        assert_eq!(u.get(CurlUrlPart::Host, 0).unwrap(), u2.get(CurlUrlPart::Host, 0).unwrap());
    }

    // -- Port handling --

    #[test]
    fn default_port() {
        let mut u = CurlUrl::new();
        u.set(CurlUrlPart::Url, "https://example.com/", 0).unwrap();
        assert!(u.get(CurlUrlPart::Port, 0).is_err());
        assert_eq!(u.get(CurlUrlPart::Port, CURLU_DEFAULT_PORT).unwrap(), "443");
    }

    #[test]
    fn no_default_port() {
        let mut u = CurlUrl::new();
        u.set(CurlUrlPart::Url, "https://example.com:443/", 0).unwrap();
        assert_eq!(u.get(CurlUrlPart::Port, 0).unwrap(), "443");
        assert!(u.get(CurlUrlPart::Port, CURLU_NO_DEFAULT_PORT).is_err());
    }

    #[test]
    fn explicit_port() {
        let mut u = CurlUrl::new();
        u.set(CurlUrlPart::Url, "https://example.com:8080/", 0).unwrap();
        assert_eq!(u.get(CurlUrlPart::Port, 0).unwrap(), "8080");
    }

    // -- Scheme handling --

    #[test]
    fn default_scheme() {
        let mut u = CurlUrl::new();
        u.set(
            CurlUrlPart::Url,
            "example.com/path",
            CURLU_DEFAULT_SCHEME,
        )
        .unwrap();
        assert_eq!(u.get(CurlUrlPart::Scheme, 0).unwrap(), "https");
    }

    #[test]
    fn guess_scheme_ftp() {
        let mut u = CurlUrl::new();
        u.set(CurlUrlPart::Url, "ftp.example.com/file", CURLU_GUESS_SCHEME)
            .unwrap();
        assert_eq!(u.get(CurlUrlPart::Scheme, 0).unwrap(), "ftp");
    }

    // -- Credentials --

    #[test]
    fn url_with_credentials() {
        let mut u = CurlUrl::new();
        u.set(
            CurlUrlPart::Url,
            "https://user:pass@example.com/path",
            0,
        )
        .unwrap();
        assert_eq!(u.get(CurlUrlPart::User, 0).unwrap(), "user");
        assert_eq!(u.get(CurlUrlPart::Password, 0).unwrap(), "pass");
    }

    #[test]
    fn disallow_user() {
        let mut u = CurlUrl::new();
        let result = u.set(
            CurlUrlPart::Url,
            "https://user:pass@example.com/",
            CURLU_DISALLOW_USER,
        );
        assert!(result.is_err());
    }

    // -- strerror --

    #[test]
    fn strerror_ok() {
        assert_eq!(CurlUrl::strerror(CurlUrlError::Ok), "No error");
    }

    #[test]
    fn strerror_bad_port() {
        assert_eq!(
            CurlUrl::strerror(CurlUrlError::BadPortNumber),
            "Port number was not a decimal number between 0 and 65535"
        );
    }

    // -- is_absolute_url --

    #[test]
    fn absolute_url_detection() {
        assert!(is_absolute_url("https://example.com"));
        assert!(is_absolute_url("ftp://ftp.example.com"));
        assert!(!is_absolute_url("/relative/path"));
        assert!(!is_absolute_url("relative/path"));
    }

    // -- ConnectionConfig --

    #[test]
    fn connection_config_from_url() {
        let mut u = CurlUrl::new();
        u.set(CurlUrlPart::Url, "https://example.com:8443/api/v1", 0)
            .unwrap();
        let cfg = ConnectionConfig::from_url(&u).unwrap();
        assert_eq!(cfg.scheme(), "https");
        assert_eq!(cfg.host(), "example.com");
        assert_eq!(cfg.port(), 8443);
        assert_eq!(cfg.path(), "/api/v1");
        assert!(cfg.is_ssl());
        assert_eq!(cfg.default_port(), 443);
    }

    // -- Dot segment removal --

    #[test]
    fn dedotdotify_simple() {
        assert_eq!(dedotdotify("/a/b/c/./../../g"), "/a/g");
        assert_eq!(dedotdotify("/a/b/../c"), "/a/c");
        assert_eq!(dedotdotify("/a/./b/./c"), "/a/b/c");
    }

    // -- Default port table --

    #[test]
    fn scheme_default_ports() {
        assert_eq!(default_port_for_scheme("http"), Some(80));
        assert_eq!(default_port_for_scheme("https"), Some(443));
        assert_eq!(default_port_for_scheme("ftp"), Some(21));
        assert_eq!(default_port_for_scheme("ftps"), Some(990));
        assert_eq!(default_port_for_scheme("ssh"), Some(22));
        assert_eq!(default_port_for_scheme("sftp"), Some(22));
        assert_eq!(default_port_for_scheme("unknown"), None);
    }

    // -- Hostname validation --

    #[test]
    fn valid_hostnames() {
        assert!(validate_hostname("example.com").is_ok());
        assert!(validate_hostname("192.168.1.1").is_ok());
        assert!(validate_hostname("[::1]").is_ok());
    }

    #[test]
    fn invalid_hostnames() {
        assert!(validate_hostname("").is_err());
        assert!(validate_hostname("host name").is_err());
        assert!(validate_hostname("host/path").is_err());
    }

    // -- File URL parsing --

    #[test]
    fn file_url_basic() {
        let mut u = CurlUrl::new();
        u.set(CurlUrlPart::Url, "file:///tmp/test.txt", 0).unwrap();
        assert_eq!(u.get(CurlUrlPart::Scheme, 0).unwrap(), "file");
        assert_eq!(u.get(CurlUrlPart::Path, 0).unwrap(), "/tmp/test.txt");
    }

    // -- Query append --

    #[test]
    fn append_query() {
        let mut u = CurlUrl::new();
        u.set(CurlUrlPart::Url, "https://example.com/?a=1", 0).unwrap();
        u.set(CurlUrlPart::Query, "b=2", CURLU_APPENDQUERY).unwrap();
        assert_eq!(u.get(CurlUrlPart::Query, 0).unwrap(), "a=1&b=2");
    }

    // -- Clearing parts --

    #[test]
    fn clear_parts() {
        let mut u = CurlUrl::new();
        u.set(CurlUrlPart::Url, "https://user:pass@example.com/path?q=1#frag", 0)
            .unwrap();
        u.set(CurlUrlPart::User, "", 0).unwrap(); // clear user
        assert!(u.get(CurlUrlPart::User, 0).is_err());
        // Other parts should still be present.
        assert_eq!(u.get(CurlUrlPart::Host, 0).unwrap(), "example.com");
    }

    // -- Invalid port --

    #[test]
    fn bad_port_number() {
        let mut u = CurlUrl::new();
        assert!(u.set(CurlUrlPart::Port, "99999", 0).is_err());
        assert!(u.set(CurlUrlPart::Port, "abc", 0).is_err());
    }

    // -- SSL scheme detection --

    #[test]
    fn ssl_schemes() {
        assert!(is_ssl_scheme("https"));
        assert!(is_ssl_scheme("ftps"));
        assert!(!is_ssl_scheme("http"));
        assert!(!is_ssl_scheme("ftp"));
    }
}
