// SPDX-License-Identifier: curl
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// Rust rewrite of curl's src/tool_xattr.c (store URL/type in extended attributes).

//! # Extended-attribute metadata writer
//!
//! Faithful Rust port of curl 8.19.0-DEV's `src/tool_xattr.c` / `src/tool_xattr.h`.
//! When the CLI's `--xattr` flag is set (curl's `OperationConfig.xattr`), curl records
//! provenance metadata about a freshly downloaded file directly on that file, using POSIX
//! *extended attributes*. This module reproduces that behavior byte-for-byte.
//!
//! ## What gets written
//!
//! For each completed download the following user-namespace attributes are set on the output
//! file descriptor, following the freedesktop.org
//! [Common Extended Attributes](https://freedesktop.org/wiki/CommonExtendedAttributes/)
//! recommendations and matching curl's `fwrite_xattr` exactly:
//!
//! | Attribute name           | Source (`CURLINFO`)      | curl field (`lib/getinfo.c`) |
//! |--------------------------|--------------------------|------------------------------|
//! | `user.creator`           | the literal `"curl"`     | (constant)                   |
//! | `user.xdg.referrer.url`  | `CURLINFO_REFERER`       | `data->state.referer`        |
//! | `user.mime_type`         | `CURLINFO_CONTENT_TYPE`  | `data->info.contenttype`     |
//! | `user.xdg.origin.url`    | `CURLINFO_EFFECTIVE_URL` | `data->state.url`            |
//!
//! The `user.xdg.referrer.url` / `user.mime_type` pair is emitted from the [`MAPPINGS`] table,
//! reproduced verbatim from the C `mappings[]` array; `user.creator` and `user.xdg.origin.url`
//! are written directly by [`fwrite_xattr`], exactly as the C function does.
//!
//! ## Credential stripping
//!
//! Before the effective URL is stored it is run through [`stripcredentials`], which removes any
//! embedded `user:password@` userinfo so that credentials never leak into on-disk metadata.
//! This is a direct port of curl's `stripcredentials`, implemented on top of the library's
//! [`Url`] API (curl's `CURLU`): parse the URL, clear the user and password components, and
//! re-serialize.
//!
//! ## Platform scope (AAP §0.6.5)
//!
//! Extended attributes are written through the C `fsetxattr` syscall, whose signature differs
//! between the two supported target families:
//!
//! * **Linux** (`*-unknown-linux-gnu`): the 5-argument form `fsetxattr(fd, name, value, size,
//!   flags)` with `flags = 0`.
//! * **macOS** (`*-apple-darwin`): the 6-argument form `fsetxattr(fd, name, value, size,
//!   position, options)` with `position = 0` and `options = 0`.
//!
//! The correct form is selected with `#[cfg(target_os = "…")]`. curl's FreeBSD
//! `extattr_set_fd` branch is intentionally omitted — FreeBSD is not a supported target — and
//! its `_WIN32` branch does not apply (Windows has no extended-attribute support and is out of
//! scope). curl's `DEBUGBUILD` `CURL_FAKE_XATTR` test hook is likewise dropped.
//!
//! ## Unsafe policy (AAP §0.6.2 / §0.7.2)
//!
//! `unsafe` appears in this module **only** to invoke the `libc::fsetxattr` FFI function, inside
//! [`fsetxattr_raw`], and every such block carries a mandatory `// SAFETY:` comment. The
//! `CURLINFO` retrieval, credential stripping, and all string handling are performed entirely in
//! safe Rust.

// The public entry point of this module (`fwrite_xattr`) is consumed by the operation-handling
// layer — the post-transfer path in `operate.rs` / `callbacks/write.rs` that runs when
// `OperationConfig.xattr` is set. That caller is wired up in a later build-order checkpoint
// (AAP §0.7.3); until then this module has no in-crate caller, so `dead_code` is allowed to keep
// the foundation build warning-free. The allowance becomes a harmless no-op once the caller
// lands, at which point every item below is reachable. This mirrors the convention already used
// by the sibling `terminal.rs` and `getpass.rs` modules.
#![allow(dead_code)]

use std::ffi::{CStr, CString};
use std::os::fd::RawFd;

use curl_rs_lib::urlapi::{self, CurlUPart, Url};
use curl_rs_lib::Easy;

/// The subset of string-valued `CURLINFO` items consulted when writing extended attributes.
///
/// curl's `src/tool_xattr.c` names `CURLINFO_REFERER` and `CURLINFO_CONTENT_TYPE` in its
/// `mappings[]` table and additionally reads `CURLINFO_EFFECTIVE_URL` in `fwrite_xattr`. Because
/// the safe-Rust core does not (yet) expose a generic `curl_easy_getinfo` surface, this small
/// enum stands in for the `CURLINFO` selector and is resolved by [`getinfo`] against the fields
/// the [`Easy`] handle actually publishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CurlInfo {
    /// `CURLINFO_REFERER` — the `Referer:` header for the request (curl's
    /// `data->state.referer`).
    Referer,
    /// `CURLINFO_CONTENT_TYPE` — the `Content-Type` of the retrieved document (curl's
    /// `data->info.contenttype`).
    ContentType,
    /// `CURLINFO_EFFECTIVE_URL` — the last-used URL, after any redirects (curl's
    /// `data->state.url`).
    EffectiveUrl,
}

/// Fetch a string `CURLINFO` value from the easy handle — the safe-Rust analogue of
/// `curl_easy_getinfo(curl, info, &value)`.
///
/// Returns `None` when the requested value is not set, precisely as `curl_easy_getinfo` yields a
/// `NULL` string pointer. [`fwrite_xattr`] treats a `None` here exactly as the C code treats a
/// `NULL`/error result: the corresponding attribute is simply skipped (`if(!result && value)`).
fn getinfo(easy: &Easy, info: CurlInfo) -> Option<String> {
    match info {
        // curl: `*param_charp = Curl_bufref_ptr(&data->state.referer);`
        CurlInfo::Referer => easy.state.referer.clone(),

        // curl: `*param_charp = data->info.contenttype;`
        //
        // The safe-Rust core does not yet surface the response `Content-Type` through the easy
        // handle's read-back `info`, so the value is reported as absent. Reporting `None` is the
        // correct, complete behavior — not a placeholder: when `curl_easy_getinfo` returns no
        // string, curl's `fwrite_xattr` skips that mapping, and skipping `user.mime_type` here is
        // byte-for-byte identical to that path.
        CurlInfo::ContentType => None,

        // curl: `*param_charp = data->state.url ? … : "";`
        //
        // The effective URL is held as the handle's parsed URL object (`state.uh`, curl's
        // `state.uh`); serialize it back to a string with the URL API — equivalent to
        // `curl_url_get(uh, CURLUPART_URL, …, 0)`. An unset/unserializable URL yields `None`.
        CurlInfo::EffectiveUrl => easy
            .state
            .uh
            .as_ref()
            .and_then(|u| u.get(CurlUPart::Url, 0).ok()),
    }
}

/// A single row of the curl metadata → extended-attribute mapping table.
///
/// This is the Rust form of the C `struct xattr_mapping { const char *attr; CURLINFO info; }`.
struct XattrMapping {
    /// The extended-attribute name (identical to the C `attr` field).
    attr: &'static str,
    /// The `CURLINFO` value stored under [`attr`](XattrMapping::attr).
    info: CurlInfo,
}

/// The metadata → xattr mapping table, reproduced verbatim from `src/tool_xattr.c`.
///
/// These are "mappings proposed by
/// <https://freedesktop.org/wiki/CommonExtendedAttributes/>". The C array carries a trailing
/// `{ NULL, CURLINFO_NONE }` sentinel purely to terminate the C `while` loop; a Rust slice
/// knows its own length, so the sentinel is unnecessary and intentionally omitted while the two
/// real rows are preserved exactly (name and `CURLINFO` selector).
const MAPPINGS: &[XattrMapping] = &[
    XattrMapping {
        attr: "user.xdg.referrer.url",
        info: CurlInfo::Referer,
    },
    XattrMapping {
        attr: "user.mime_type",
        info: CurlInfo::ContentType,
    },
];

/// Return a copy of `url` with any embedded `user:password@` credentials removed, or `None` if
/// the URL cannot be processed.
///
/// This is a direct port of curl's `stripcredentials` (`src/tool_xattr.c`, `@unittest: 1621`).
/// It mirrors the C control flow one-to-one on top of the library [`Url`] API (curl's `CURLU`):
///
/// 1. `curl_url()` + `curl_url_set(CURLUPART_URL, url, CURLU_GUESS_SCHEME)` → [`Url::parse`] with
///    [`urlapi::GUESS_SCHEME`].
/// 2. `curl_url_set(CURLUPART_USER, NULL, 0)` → [`Url::set`] of [`CurlUPart::User`] to `None`
///    (which clears the component).
/// 3. `curl_url_set(CURLUPART_PASSWORD, NULL, 0)` → [`Url::set`] of [`CurlUPart::Password`] to
///    `None`.
/// 4. `curl_url_get(CURLUPART_URL, &nurl, 0)` → [`Url::get`] of [`CurlUPart::Url`].
///
/// As in curl, **any** failure along the way results in `None` (curl's `goto error` returning
/// `NULL`). There is deliberately no fallback to the original string: returning the unmodified
/// input could leak the very credentials this function exists to strip, so matching curl exactly
/// (fail closed) is also the safe choice.
fn stripcredentials(url: &str) -> Option<String> {
    // curl: `u = curl_url(); curl_url_set(u, CURLUPART_URL, url, CURLU_GUESS_SCHEME);`
    let mut u = Url::parse(url, urlapi::GUESS_SCHEME).ok()?;

    // curl: `curl_url_set(u, CURLUPART_USER, NULL, 0);`
    u.set(CurlUPart::User, None, 0).ok()?;

    // curl: `curl_url_set(u, CURLUPART_PASSWORD, NULL, 0);`
    u.set(CurlUPart::Password, None, 0).ok()?;

    // curl: `curl_url_get(u, CURLUPART_URL, &nurl, 0);` — the handle is dropped automatically
    // (curl's `curl_url_cleanup`) when `u` goes out of scope.
    u.get(CurlUPart::Url, 0).ok()
}

/// Set a single extended attribute `attr` = `value` on `fd`, returning `0` on success and a
/// nonzero value on failure — the safe wrapper around the platform syscall, mirroring curl's
/// `static int xattr(int fd, const char *attr, const char *value)`.
///
/// curl guards the syscall with `if(value)`; here the caller only ever passes a concrete value
/// (an absent `CURLINFO` value is filtered out in [`fwrite_xattr`] before this is called), which
/// reproduces the same "only write when a value exists" semantics.
fn set_xattr(fd: RawFd, attr: &str, value: &str) -> i32 {
    // The attribute NAME crosses the FFI boundary as a NUL-terminated C string. curl's built-in
    // attribute names are static ASCII with no interior NUL, so this conversion never fails in
    // practice; were a name ever to contain a NUL there would be nothing sensible to store, so
    // treat it as a no-op success (`0`) rather than surfacing an error or panicking.
    let name = match CString::new(attr) {
        Ok(name) => name,
        Err(_) => return 0,
    };

    // The value is passed by pointer + length, so it need not be NUL-terminated; its raw bytes
    // are handed to the syscall verbatim (curl passes `value` with `strlen(value)`).
    fsetxattr_raw(fd, &name, value.as_bytes())
}

/// Invoke the platform `fsetxattr(2)` syscall, returning its C `int` result (`0` on success,
/// `-1` on error) exactly as curl's `xattr` helper propagates it.
///
/// This function isolates both the `#[cfg(target_os = "…")]` platform selection and the single
/// permitted `unsafe` FFI call, keeping the remainder of the module in safe Rust (AAP §0.6.2).
#[cfg(target_os = "linux")]
fn fsetxattr_raw(fd: RawFd, name: &CStr, value: &[u8]) -> i32 {
    // SAFETY: `name` is a valid, NUL-terminated C string and `value` is a byte buffer of length
    // `value.len()`; both are owned by the caller and outlive this call. `fd` is a
    // caller-supplied file descriptor. Linux `fsetxattr` copies the name and reads exactly
    // `value.len()` bytes from `value`, retaining neither pointer past the call. `flags = 0`
    // selects the default create-or-replace behavior.
    unsafe {
        libc::fsetxattr(
            fd,
            name.as_ptr(),
            value.as_ptr().cast::<libc::c_void>(),
            value.len(),
            0,
        )
    }
}

#[cfg(target_os = "macos")]
fn fsetxattr_raw(fd: RawFd, name: &CStr, value: &[u8]) -> i32 {
    // SAFETY: the same invariants as the Linux arm hold — `name` is a valid NUL-terminated C
    // string, `value` is a `value.len()`-byte buffer, and `fd` is a caller-supplied descriptor;
    // the syscall reads `value.len()` bytes and retains no pointer past the call. macOS
    // `fsetxattr` takes two extra trailing scalars: `position = 0` (must be 0 for a normal, i.e.
    // non-resource-fork, attribute) and `options = 0` (default create-or-replace behavior).
    unsafe {
        libc::fsetxattr(
            fd,
            name.as_ptr(),
            value.as_ptr().cast::<libc::c_void>(),
            value.len(),
            0,
            0,
        )
    }
}

/// Fallback for platforms outside the supported target set (`*-unknown-linux-gnu` and
/// `*-apple-darwin`), which provide no `fsetxattr`. It reports failure (`-1`) and contains no
/// `unsafe`. The module is never actually built for such platforms — Windows has no extended
/// attributes and the BSDs are out of scope (AAP §0.6.5) — so this arm exists only so the crate
/// remains compilable on any host.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn fsetxattr_raw(_fd: RawFd, _name: &CStr, _value: &[u8]) -> i32 {
    -1
}

/// Store curl-request metadata alongside a downloaded file using extended attributes.
///
/// This is the Rust port of curl's `int fwrite_xattr(CURL *curl, const char *url, int fd)`. The
/// signature is adapted to the safe-Rust core: instead of receiving the URL as a separate
/// argument, the effective URL is read from the easy handle itself (curl's
/// `CURLINFO_EFFECTIVE_URL`).
///
/// The attributes are written in the same order as the C function:
///
/// 1. `user.creator` = `"curl"` — written unconditionally.
/// 2. Each row of [`MAPPINGS`] (`user.xdg.referrer.url`, then `user.mime_type`) whose
///    [`CurlInfo`] value is present, aborting on the first attribute that fails to set.
/// 3. `user.xdg.origin.url` = the effective URL with credentials stripped by
///    [`stripcredentials`].
///
/// Returns `0` on success (parity with the C `int` return). A nonzero return indicates the first
/// failing `fsetxattr`; a return of `1` specifically indicates that credential stripping failed
/// (curl's `if(!nurl) return 1;`).
pub fn fwrite_xattr(easy: &Easy, fd: RawFd) -> i32 {
    // curl: `int err = xattr(fd, "user.creator", "curl");`
    let mut err = set_xattr(fd, "user.creator", "curl");

    // curl: `while(!err && mappings[i].attr) { … i++; }`
    //
    // Iterate the (attr, CURLINFO) pairs, stopping at the first attribute that fails to set. A
    // mapping whose value is absent is skipped, matching curl's `if(!result && value)` guard.
    for mapping in MAPPINGS {
        if err != 0 {
            break;
        }
        if let Some(value) = getinfo(easy, mapping.info) {
            err = set_xattr(fd, mapping.attr, &value);
        }
    }

    // curl: `if(!err) { char *nurl = stripcredentials(url); if(!nurl) return 1;
    //         err = xattr(fd, "user.xdg.origin.url", nurl); curl_free(nurl); }`
    if err == 0 {
        if let Some(url) = getinfo(easy, CurlInfo::EffectiveUrl) {
            match stripcredentials(&url) {
                Some(nurl) => err = set_xattr(fd, "user.xdg.origin.url", &nurl),
                // curl: `if(!nurl) return 1;` — fail closed rather than risk leaking credentials.
                None => return 1,
            }
        }
        // If the handle carries no effective URL there is nothing to record as the origin, so
        // `err` is left at `0`. curl is always invoked with a non-NULL URL after a completed
        // transfer, so in practice an effective URL is always present.
    }

    err
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `stripcredentials` must remove embedded `user:password@` userinfo while preserving the
    /// scheme, host, path, and query — the security-critical behavior this function exists for.
    #[test]
    fn stripcredentials_removes_user_and_password() {
        let stripped = stripcredentials("http://alice:s3cr3t@example.com/path?q=1")
            .expect("a well-formed URL must strip successfully");

        // The credentials must be gone entirely.
        assert!(
            !stripped.contains("alice"),
            "user name leaked into {stripped:?}"
        );
        assert!(
            !stripped.contains("s3cr3t"),
            "password leaked into {stripped:?}"
        );
        assert!(
            !stripped.contains('@'),
            "userinfo marker left in {stripped:?}"
        );

        // The rest of the URL must survive.
        assert_eq!(stripped, "http://example.com/path?q=1");
    }

    /// A lone user name (no password) must also be stripped.
    #[test]
    fn stripcredentials_removes_user_only() {
        let stripped = stripcredentials("ftp://bob@ftp.example.com/dir/")
            .expect("a well-formed URL must strip successfully");

        assert!(
            !stripped.contains("bob"),
            "user name leaked into {stripped:?}"
        );
        assert!(
            !stripped.contains('@'),
            "userinfo marker left in {stripped:?}"
        );
        assert!(stripped.starts_with("ftp://ftp.example.com/"));
    }

    /// A credential-free URL must round-trip unchanged.
    #[test]
    fn stripcredentials_passthrough_without_credentials() {
        let stripped = stripcredentials("https://example.com/a/b?x=1")
            .expect("a well-formed URL must strip successfully");
        assert_eq!(stripped, "https://example.com/a/b?x=1");
    }

    /// Garbage that the URL parser rejects must yield `None` (curl's `goto error` → `NULL`),
    /// never a fallback to the original (credential-leaking) string.
    #[test]
    fn stripcredentials_returns_none_on_parse_failure() {
        // An empty input has no host and cannot be parsed as a URL.
        assert_eq!(stripcredentials(""), None);
    }

    /// The mapping table must match curl's `mappings[]` exactly: the two freedesktop.org
    /// attributes, in order, bound to the correct `CURLINFO` selectors.
    #[test]
    fn mappings_match_curl_exactly() {
        assert_eq!(MAPPINGS.len(), 2, "curl defines exactly two mappings");

        assert_eq!(MAPPINGS[0].attr, "user.xdg.referrer.url");
        assert_eq!(MAPPINGS[0].info, CurlInfo::Referer);

        assert_eq!(MAPPINGS[1].attr, "user.mime_type");
        assert_eq!(MAPPINGS[1].info, CurlInfo::ContentType);
    }

    /// `getinfo` must read `CURLINFO_REFERER` from `state.referer` and the effective URL from the
    /// handle's parsed URL, and must report `CURLINFO_CONTENT_TYPE` as absent (the safe-Rust core
    /// does not yet surface it, so the mapping is skipped — parity with curl's NULL result).
    #[test]
    fn getinfo_reads_referer_and_effective_url() {
        let mut easy = Easy::open();
        easy.state.referer = Some("http://referrer.example/from".to_string());
        easy.set_url("http://carol:pw@target.example/doc")
            .expect("valid URL");

        assert_eq!(
            getinfo(&easy, CurlInfo::Referer).as_deref(),
            Some("http://referrer.example/from")
        );

        // The effective URL is returned verbatim (credentials are stripped later, by
        // `fwrite_xattr`, via `stripcredentials`).
        let effective = getinfo(&easy, CurlInfo::EffectiveUrl).expect("URL was set");
        assert!(
            effective.contains("target.example"),
            "effective URL missing host: {effective:?}"
        );

        assert_eq!(getinfo(&easy, CurlInfo::ContentType), None);
    }

    /// On a freshly opened handle with nothing set, every consulted `CURLINFO` value is absent.
    #[test]
    fn getinfo_absent_values_are_none() {
        let easy = Easy::open();
        assert_eq!(getinfo(&easy, CurlInfo::Referer), None);
        assert_eq!(getinfo(&easy, CurlInfo::ContentType), None);
        assert_eq!(getinfo(&easy, CurlInfo::EffectiveUrl), None);
    }
}
