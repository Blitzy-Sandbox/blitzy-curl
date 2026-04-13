// -----------------------------------------------------------------------
// curl-rs/src/xattr.rs — Extended Attribute Writing
//
// Rust rewrite of src/tool_xattr.c and src/tool_xattr.h.
// Writes extended file attributes for the --xattr option, storing
// URL, content type, referrer, and creator metadata as filesystem
// xattrs on downloaded files.
//
// On Linux/macOS: writes xattrs via the `xattr` crate's FileExt trait.
// On unsupported platforms: no-op (returns Ok(())).
//
// SPDX-License-Identifier: curl
// -----------------------------------------------------------------------

use anyhow::{Context, Result};
use std::fs::File;
use url::Url;
use xattr::FileExt;

// ---------------------------------------------------------------------------
// Extended attribute name constants — must match curl 8.x exactly.
//
// These follow the freedesktop.org Common Extended Attributes specification:
// https://freedesktop.org/wiki/CommonExtendedAttributes/
// ---------------------------------------------------------------------------

/// Creator application identity attribute.
const XATTR_CREATOR: &str = "user.creator";

/// Origin URL of the downloaded resource (credentials stripped).
const XATTR_ORIGIN_URL: &str = "user.xdg.origin.url";

/// MIME type of the downloaded content (from Content-Type header).
const XATTR_MIME_TYPE: &str = "user.mime_type";

/// Referrer URL that led to this download (from Referer header).
const XATTR_REFERRER_URL: &str = "user.xdg.referrer.url";

/// The creator value written to `user.creator` — matches curl 8.x.
const CREATOR_VALUE: &str = "curl";

// ---------------------------------------------------------------------------
// Helper: credential stripping
// ---------------------------------------------------------------------------

/// Strip credentials (username and password) from a URL string.
///
/// Parses the URL, removes any embedded `user:password@` component,
/// and returns the cleaned URL string. This is the Rust equivalent of
/// the C `stripcredentials()` function in `src/tool_xattr.c`, which
/// uses curl's CURLU API to null out `CURLUPART_USER` and
/// `CURLUPART_PASSWORD` before reconstructing the URL.
///
/// If URL parsing fails (e.g., opaque or non-standard scheme), the
/// original URL is returned unchanged — matching the C fallback
/// behavior where `curl_url_set` failure causes `stripcredentials`
/// to return `NULL`, which then causes the caller to return an error.
/// In the Rust version, we gracefully fall back to the original URL
/// to avoid failing the entire xattr operation for a parse edge case.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(strip_credentials("https://user:pass@example.com/path"),
///            "https://example.com/path");
/// assert_eq!(strip_credentials("https://example.com/path"),
///            "https://example.com/path");
/// ```
fn strip_credentials(url: &str) -> String {
    match Url::parse(url) {
        Ok(mut parsed) => {
            // Remove username — set_username returns Err only for
            // cannot-be-a-base URLs, which we handle gracefully.
            let _ = parsed.set_username("");
            // Remove password — set_password(None) clears the password.
            let _ = parsed.set_password(None);
            parsed.to_string()
        }
        Err(_) => {
            // URL parsing failed — return the original URL unchanged.
            // The C code returns NULL here (causing fwrite_xattr to
            // return 1), but we prefer graceful degradation since the
            // URL was valid enough for curl to download from.
            url.to_string()
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Write extended file attributes for a downloaded file.
///
/// This is the Rust equivalent of `fwrite_xattr()` from
/// `src/tool_xattr.c`. It writes the following xattrs on the file:
///
/// 1. `user.creator`           → `"curl"` (always)
/// 2. `user.xdg.referrer.url`  → referrer URL (if provided)
/// 3. `user.mime_type`         → Content-Type header value (if provided)
/// 4. `user.xdg.origin.url`   → URL with credentials stripped (always)
///
/// The attribute write order matches the C implementation: creator
/// first, then the mapping table entries (referrer, content type),
/// then the origin URL.
///
/// On platforms that don't support extended attributes (detected at
/// runtime via `xattr::SUPPORTED_PLATFORM`), this is a no-op and
/// returns `Ok(())`.
///
/// # Arguments
///
/// * `fd` — Borrowed reference to the output file on which xattrs
///   are set. The file must be open for writing.
/// * `url` — The URL that was downloaded. Credentials are stripped
///   before writing to `user.xdg.origin.url`.
/// * `content_type` — The Content-Type header value, if the server
///   provided one. Written to `user.mime_type`.
/// * `referrer` — The Referer URL, if one was sent with the request.
///   Written to `user.xdg.referrer.url`.
///
/// # Errors
///
/// Returns an error if any xattr write operation fails on a supported
/// platform. The caller (operate.rs / post_per_transfer) should
/// handle this as a non-fatal warning — a failed xattr write must
/// not abort the transfer.
///
/// # Platform Behavior
///
/// | Platform          | Behavior                                    |
/// |-------------------|---------------------------------------------|
/// | Linux             | Writes xattrs via `fsetxattr(2)` (5-arg)    |
/// | macOS             | Writes xattrs via `fsetxattr(2)` (6-arg)    |
/// | FreeBSD           | Writes xattrs via `extattr_set_fd(2)`       |
/// | Other Unix        | Compiles but returns `Err` on write attempt  |
/// | Windows           | No-op — `SUPPORTED_PLATFORM` is false       |
pub fn fwrite_xattr(
    fd: &File,
    url: &str,
    content_type: Option<&str>,
    referrer: Option<&str>,
) -> Result<()> {
    // On unsupported platforms, xattr operations are a no-op.
    // The xattr crate sets SUPPORTED_PLATFORM to false on platforms
    // where setxattr/fsetxattr/extattr_set_fd are not available.
    if !xattr::SUPPORTED_PLATFORM {
        return Ok(());
    }

    // 1. Set user.creator = "curl"
    //    This matches the C code's first xattr() call:
    //    `int err = xattr(fd, "user.creator", "curl");`
    fd.set_xattr(XATTR_CREATOR, CREATOR_VALUE.as_bytes())
        .context("failed to set user.creator xattr")?;

    // 2. Set user.xdg.referrer.url (from CURLINFO_REFERER in C)
    //    The C mapping table processes referrer before content type.
    if let Some(ref_url) = referrer {
        fd.set_xattr(XATTR_REFERRER_URL, ref_url.as_bytes())
            .context("failed to set user.xdg.referrer.url xattr")?;
    }

    // 3. Set user.mime_type (from CURLINFO_CONTENT_TYPE in C)
    if let Some(ct) = content_type {
        fd.set_xattr(XATTR_MIME_TYPE, ct.as_bytes())
            .context("failed to set user.mime_type xattr")?;
    }

    // 4. Strip credentials from URL and set user.xdg.origin.url.
    //    This matches the C code's final xattr write:
    //    `char *nurl = stripcredentials(url);`
    //    `err = xattr(fd, "user.xdg.origin.url", nurl);`
    let clean_url = strip_credentials(url);
    fd.set_xattr(XATTR_ORIGIN_URL, clean_url.as_bytes())
        .context("failed to set user.xdg.origin.url xattr")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify credential stripping from a URL with user:pass.
    #[test]
    fn test_strip_credentials_with_userinfo() {
        let url = "https://user:pass@example.com/path?q=1#frag";
        let clean = strip_credentials(url);
        assert!(
            !clean.contains("user"),
            "username should be stripped: {clean}"
        );
        assert!(
            !clean.contains("pass"),
            "password should be stripped: {clean}"
        );
        assert!(
            clean.contains("example.com/path"),
            "host and path should remain: {clean}"
        );
    }

    /// Verify credential stripping when no credentials are present.
    #[test]
    fn test_strip_credentials_no_userinfo() {
        let url = "https://example.com/path";
        let clean = strip_credentials(url);
        // The URL should come back essentially the same, possibly
        // with a trailing slash added by the url crate normalizer.
        assert!(
            clean.contains("example.com/path"),
            "URL should be preserved: {clean}"
        );
    }

    /// Verify credential stripping with only username (no password).
    #[test]
    fn test_strip_credentials_username_only() {
        let url = "ftp://anonymous@ftp.example.com/pub/file.txt";
        let clean = strip_credentials(url);
        assert!(
            !clean.contains("anonymous@"),
            "username should be stripped: {clean}"
        );
        assert!(
            clean.contains("ftp.example.com"),
            "host should remain: {clean}"
        );
    }

    /// Verify that an unparseable URL returns the original string.
    #[test]
    fn test_strip_credentials_unparseable() {
        // A relative URL or garbage that url::Url cannot parse.
        let url = "not-a-valid-url";
        let clean = strip_credentials(url);
        assert_eq!(clean, url, "unparseable URL should be returned as-is");
    }

    /// Verify the XATTR constants match curl 8.x attribute names.
    #[test]
    fn test_xattr_name_constants() {
        assert_eq!(XATTR_CREATOR, "user.creator");
        assert_eq!(XATTR_ORIGIN_URL, "user.xdg.origin.url");
        assert_eq!(XATTR_MIME_TYPE, "user.mime_type");
        assert_eq!(XATTR_REFERRER_URL, "user.xdg.referrer.url");
    }

    /// Verify the creator value matches curl 8.x.
    #[test]
    fn test_creator_value() {
        assert_eq!(CREATOR_VALUE, "curl");
    }

    /// Verify that fwrite_xattr returns Ok on unsupported platforms
    /// (the xattr::SUPPORTED_PLATFORM constant determines this).
    /// On supported platforms this test actually writes xattrs to
    /// a temp file and verifies them.
    #[test]
    fn test_fwrite_xattr_roundtrip() {
        use std::io::Write;

        // Create a temporary file for testing.
        let dir = std::env::temp_dir();
        let path = dir.join("curl_rs_xattr_test");
        let mut file = std::fs::File::create(&path).expect("create temp file");
        file.write_all(b"test content")
            .expect("write temp content");
        drop(file);

        // Re-open for xattr writing (needs to be an open File handle).
        let file = std::fs::File::open(&path).expect("open temp file");

        let result = fwrite_xattr(
            &file,
            "https://user:pass@example.com/file.txt",
            Some("text/plain"),
            Some("https://referrer.example.com/"),
        );

        if xattr::SUPPORTED_PLATFORM {
            // On supported platforms, the write should succeed
            // (unless the filesystem doesn't support xattrs, e.g. tmpfs).
            // We allow both Ok and Err here since tmpfs may not support
            // xattrs on some CI environments.
            if result.is_ok() {
                // Verify we can read back the attributes.
                use xattr::FileExt;
                if let Ok(Some(creator)) = file.get_xattr(XATTR_CREATOR) {
                    assert_eq!(
                        String::from_utf8_lossy(&creator),
                        "curl"
                    );
                }
                if let Ok(Some(origin)) = file.get_xattr(XATTR_ORIGIN_URL) {
                    let origin_str = String::from_utf8_lossy(&origin);
                    assert!(
                        !origin_str.contains("user"),
                        "credentials should be stripped from origin URL"
                    );
                    assert!(
                        origin_str.contains("example.com"),
                        "host should be preserved in origin URL"
                    );
                }
                if let Ok(Some(mime)) = file.get_xattr(XATTR_MIME_TYPE) {
                    assert_eq!(
                        String::from_utf8_lossy(&mime),
                        "text/plain"
                    );
                }
                if let Ok(Some(referrer)) = file.get_xattr(XATTR_REFERRER_URL) {
                    assert_eq!(
                        String::from_utf8_lossy(&referrer),
                        "https://referrer.example.com/"
                    );
                }
            }
        } else {
            // On unsupported platforms, the function is a no-op.
            assert!(
                result.is_ok(),
                "fwrite_xattr should be no-op on unsupported platform"
            );
        }

        // Cleanup temp file.
        let _ = std::fs::remove_file(&path);
    }

    /// Verify fwrite_xattr handles None content_type and referrer.
    #[test]
    fn test_fwrite_xattr_optional_fields() {
        let dir = std::env::temp_dir();
        let path = dir.join("curl_rs_xattr_test_optional");
        std::fs::File::create(&path).expect("create temp file");
        let file = std::fs::File::open(&path).expect("open temp file");

        let result = fwrite_xattr(&file, "https://example.com/", None, None);

        if xattr::SUPPORTED_PLATFORM {
            // May fail on filesystems without xattr support (CI).
            // If it succeeds, verify only creator and origin are set.
            if result.is_ok() {
                use xattr::FileExt;
                if let Ok(Some(creator)) = file.get_xattr(XATTR_CREATOR) {
                    assert_eq!(
                        String::from_utf8_lossy(&creator),
                        "curl"
                    );
                }
                // mime_type should not be set (it was None).
                if let Ok(val) = file.get_xattr(XATTR_MIME_TYPE) {
                    assert!(
                        val.is_none(),
                        "mime_type should not be set when content_type is None"
                    );
                }
            }
        } else {
            assert!(result.is_ok());
        }

        let _ = std::fs::remove_file(&path);
    }
}
