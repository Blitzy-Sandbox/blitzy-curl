// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! `curl_easy_option_*` C ABI entry points — the easyoption *introspection* surface of libcurl.
//!
//! This module is the `extern "C"` home of the 3 public option-metadata functions declared in
//! `include/curl/options.h` (`curl_easy_option_by_name`, `curl_easy_option_by_id`,
//! `curl_easy_option_next`). It is derived 1:1 from that header and the C entry points
//! `lib/easyoptions.c` (the `optiontable.pl`-generated `Curl_easyopts[]` table) and
//! `lib/easygetopt.c` (the by-name / by-id / next lookup logic), which are retained in-tree as a
//! read-only source-of-truth reference (AAP §0.4.1).
//!
//! # Table model
//! [`CURL_EASYOPTS`] is a process-lifetime `static` array of [`curl_easyoption`] rows — one per
//! `CURLOPT_*` setopt id known to curl 8.x — mirroring the C table byte-for-byte: the same 323
//! entries, in the same ASCII-alphabetical order (`ABSTRACT_UNIX_SOCKET` .. `XOAUTH2_BEARER`),
//! terminated by the same sentinel row `{ NULL, CURLOPT_LASTENTRY, CURLOT_LONG, 0 }`. Legacy
//! spellings kept for source compatibility (e.g. `ENCODING`, `FILE`, `SSLKEYPASSWD`) carry
//! [`CURLOT_FLAG_ALIAS`]. Each row's `name` points into a `'static`, NUL-terminated byte-string
//! literal, so every pointer this module hands back to C stays valid for the life of the process
//! and is *never* freed by the caller. All three functions return borrowed pointers *into* this
//! static table.
//!
//! # Lookup semantics (preserved from `lib/easygetopt.c`)
//! * [`curl_easy_option_by_name`] matches the option name **case-insensitively** (curl's
//!   `curl_strequal`), via [`<[u8]>::eq_ignore_ascii_case`].
//! * [`curl_easy_option_by_id`] matches by numeric id but **skips alias rows**
//!   (`flags & CURLOT_FLAG_ALIAS`), so it returns the canonical option for an id that has aliases
//!   (e.g. `CURLOPT_KEYPASSWD` rather than its `SSLKEYPASSWD` / `SSLCERTPASSWD` aliases).
//! * [`curl_easy_option_next`] walks the table: `NULL` yields the first row, any other row yields
//!   its successor, and the sentinel yields `NULL` (end of iteration).
//!
//! # Safety and unwinding (AAP §0.6.2 / §0.7.2 — binding)
//! `curl-rs-ffi` is the sole crate permitted to use `unsafe`. Every `unsafe` block here carries a
//! `// SAFETY:` comment stating the invariant it upholds, and `#![deny(unsafe_op_in_unsafe_fn)]`
//! (below) forces each raw operation into its own annotated block even inside an
//! `unsafe extern "C" fn`. No panic may unwind across the `extern "C"` boundary: every body runs
//! inside [`catch_unwind`], which yields the null sentinel on panic — exactly mirroring curl's
//! "not found" `NULL` return. `curl_easy_option_by_id` takes no raw pointer and is therefore a safe
//! `extern "C" fn`; the other two dereference a caller pointer and are `unsafe`.
//!
//! # Integer-value stability (AAP §0.6.1)
//! The [`curl_easytype`] discriminants (`CURLOT_LONG == 0` .. `CURLOT_FUNCTION == 8`) and
//! `CURLOT_FLAG_ALIAS == 1` are frozen to curl 8.x, as are the [`CURLoption`] ids the table
//! references (reused verbatim from [`crate::easy::CURLoption`] so every id is consistent across
//! the crate). The sentinel id `CURLOPT_LASTENTRY == 10329` is defined alongside them in
//! `easy.rs`.
//!
//! # cbindgen note (the `type` field)
//! curl's `struct curl_easyoption` has a field literally named `type`, which is a Rust keyword.
//! The Rust field is therefore `type_`, and the struct carries a
//! `/// cbindgen:field-names=[name, id, type, flags]` annotation so the regenerated
//! `include/curl/curl.h` emits the field as `type` (byte-exact with the committed
//! `include/curl/options.h`). cbindgen header generation is best-effort and never clobbers the
//! committed headers, which remain the authoritative ABI surface.

#![deny(unsafe_op_in_unsafe_fn)]

use crate::easy::CURLoption;
use libc::{c_char, c_uint};
use std::ffi::CStr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

/// libcurl `curl_easytype` — the data-type class of a `curl_easy_setopt` option
/// (`include/curl/options.h`).
///
/// `#[repr(C)]` with explicit discriminants freezes the wire values to curl 8.x: `CURLOT_LONG == 0`
/// through `CURLOT_FUNCTION == 8`, in the exact header order. The variant set and order must not
/// change (AAP §0.6.1). cbindgen renders this enum into the generated `include/curl/curl.h`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum curl_easytype {
    /// `long` (a range of values).
    CURLOT_LONG = 0,
    /// `long` (a defined set or bitmask).
    CURLOT_VALUES = 1,
    /// `curl_off_t` (a range of values).
    CURLOT_OFF_T = 2,
    /// pointer (`void *`).
    CURLOT_OBJECT = 3,
    /// `char *` to a NUL-terminated buffer.
    CURLOT_STRING = 4,
    /// `struct curl_slist *`.
    CURLOT_SLIST = 5,
    /// `void *` passed as-is to a callback.
    CURLOT_CBPTR = 6,
    /// blob (`struct curl_blob *`).
    CURLOT_BLOB = 7,
    /// function pointer.
    CURLOT_FUNCTION = 8,
}

/// `CURLOT_FLAG_ALIAS` — set in [`curl_easyoption::flags`] when the row is an "alias": a legacy
/// option name retained for source compatibility that maps onto another option's id
/// (`include/curl/options.h`, `#define CURLOT_FLAG_ALIAS (1 << 0)`). Frozen to `1`.
pub const CURLOT_FLAG_ALIAS: c_uint = 1 << 0;

/// libcurl `struct curl_easyoption` — one metadata row describing a `curl_easy_setopt` option
/// (`include/curl/options.h`).
///
/// Field order and types are byte-exact with the C struct: `name` (the option's C name without the
/// `CURLOPT_` prefix, or `NULL` for the table sentinel), `id` (the [`CURLoption`] setopt id), `type`
/// (its [`curl_easytype`]), and `flags` (a bitmask of `CURLOT_FLAG_*`). The Rust field for `type`
/// is spelled `type_` because `type` is a Rust keyword; the cbindgen annotation below restores the
/// exact C spelling in the generated header.
///
/// cbindgen:field-names=[name, id, type, flags]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct curl_easyoption {
    /// The option's C name minus the `CURLOPT_` prefix (e.g. `"URL"`), or null for the sentinel.
    pub name: *const c_char,
    /// The `curl_easy_setopt` option id this row describes.
    pub id: CURLoption,
    /// The option's argument data-type class. (C field name: `type`.)
    pub type_: curl_easytype,
    /// Bitmask of `CURLOT_FLAG_*` (currently only [`CURLOT_FLAG_ALIAS`]).
    pub flags: c_uint,
}

/// Crate-private newtype wrapper that lets the option table be a `Sync` `static` without attaching
/// a manual `Sync` impl to the public [`curl_easyoption`] type. It is declared `pub(crate)` (rather
/// than module-private) so that it is at least as visible as the `pub(crate)` [`CURL_EASYOPTS`]
/// static whose type it is; otherwise the `private_interfaces` lint fires as an error under the
/// mandated `-D warnings` build/clippy gates. The tuple field stays private, so the table contents
/// remain an implementation detail reachable only through the three accessor functions.
pub(crate) struct OptionTable([curl_easyoption; 324]);

// SAFETY: `OptionTable` is immutable, process-lifetime data initialised at compile time. Its only
// non-`Sync` component is the `*const c_char` `name` field of each row, which always points either
// at a `'static`, NUL-terminated byte-string literal or is null (the sentinel). There is no
// interior mutability and the pointers are never written through, so the table is safe to share
// across threads by shared reference.
unsafe impl Sync for OptionTable {}

/// Construct one immutable table row in `const` context. Takes the `name` pointer by value and
/// never dereferences it, so this is a safe `const fn` usable in the `static` initialiser.
const fn row(
    name: *const c_char,
    id: CURLoption,
    ty: curl_easytype,
    flags: c_uint,
) -> curl_easyoption {
    curl_easyoption {
        name,
        id,
        type_: ty,
        flags,
    }
}

/// Turn a NUL-terminated byte-string literal (e.g. `b"URL\0"`) into a `'static` `*const c_char`.
/// The literal has `'static` storage, so the resulting pointer is valid for the whole process and
/// suitable for the `name` field of a table row. `<[u8; N]>::as_ptr` is a `const fn`, so this
/// expands inside the `static` initialiser (MSRV 1.75 has no `c"…"` C-string literals).
macro_rules! optname {
    ($lit:literal) => {
        $lit.as_ptr() as *const c_char
    };
}

/// The libcurl easyoption metadata table — a byte-for-byte port of `Curl_easyopts[]` from
/// `lib/easyoptions.c`: 323 option rows in ASCII-alphabetical order followed by the
/// `{ NULL, CURLOPT_LASTENTRY, CURLOT_LONG, 0 }` sentinel. Generated from the C table; do not
/// edit by hand (mirror `lib/easyoptions.c`, itself generated by `optiontable.pl`).
///
/// The Rust symbol is `CURL_EASYOPTS` (UPPER_CASE per Rust's static-naming convention); it
/// corresponds to curl's internal `Curl_easyopts[]` table and is crate-private (`pub(crate)`)
/// because the public surface is the three accessor functions, not the array itself.
///
/// `#[rustfmt::skip]` keeps this generated table one row per line (mirroring the C source layout);
/// without it rustfmt would wrap every row across four lines and obscure the tabular structure.
#[rustfmt::skip]
pub(crate) static CURL_EASYOPTS: OptionTable = OptionTable([
    row(optname!(b"ABSTRACT_UNIX_SOCKET\0"), CURLoption::CURLOPT_ABSTRACT_UNIX_SOCKET, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"ACCEPTTIMEOUT_MS\0"), CURLoption::CURLOPT_ACCEPTTIMEOUT_MS, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"ACCEPT_ENCODING\0"), CURLoption::CURLOPT_ACCEPT_ENCODING, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"ADDRESS_SCOPE\0"), CURLoption::CURLOPT_ADDRESS_SCOPE, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"ALTSVC\0"), CURLoption::CURLOPT_ALTSVC, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"ALTSVC_CTRL\0"), CURLoption::CURLOPT_ALTSVC_CTRL, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"APPEND\0"), CURLoption::CURLOPT_APPEND, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"AUTOREFERER\0"), CURLoption::CURLOPT_AUTOREFERER, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"AWS_SIGV4\0"), CURLoption::CURLOPT_AWS_SIGV4, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"BUFFERSIZE\0"), CURLoption::CURLOPT_BUFFERSIZE, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"CAINFO\0"), CURLoption::CURLOPT_CAINFO, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"CAINFO_BLOB\0"), CURLoption::CURLOPT_CAINFO_BLOB, curl_easytype::CURLOT_BLOB, 0),
    row(optname!(b"CAPATH\0"), CURLoption::CURLOPT_CAPATH, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"CA_CACHE_TIMEOUT\0"), CURLoption::CURLOPT_CA_CACHE_TIMEOUT, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"CERTINFO\0"), CURLoption::CURLOPT_CERTINFO, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"CHUNK_BGN_FUNCTION\0"), CURLoption::CURLOPT_CHUNK_BGN_FUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"CHUNK_DATA\0"), CURLoption::CURLOPT_CHUNK_DATA, curl_easytype::CURLOT_CBPTR, 0),
    row(optname!(b"CHUNK_END_FUNCTION\0"), CURLoption::CURLOPT_CHUNK_END_FUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"CLOSESOCKETDATA\0"), CURLoption::CURLOPT_CLOSESOCKETDATA, curl_easytype::CURLOT_CBPTR, 0),
    row(optname!(b"CLOSESOCKETFUNCTION\0"), CURLoption::CURLOPT_CLOSESOCKETFUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"CONNECTTIMEOUT\0"), CURLoption::CURLOPT_CONNECTTIMEOUT, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"CONNECTTIMEOUT_MS\0"), CURLoption::CURLOPT_CONNECTTIMEOUT_MS, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"CONNECT_ONLY\0"), CURLoption::CURLOPT_CONNECT_ONLY, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"CONNECT_TO\0"), CURLoption::CURLOPT_CONNECT_TO, curl_easytype::CURLOT_SLIST, 0),
    row(optname!(b"CONV_FROM_NETWORK_FUNCTION\0"), CURLoption::CURLOPT_CONV_FROM_NETWORK_FUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"CONV_FROM_UTF8_FUNCTION\0"), CURLoption::CURLOPT_CONV_FROM_UTF8_FUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"CONV_TO_NETWORK_FUNCTION\0"), CURLoption::CURLOPT_CONV_TO_NETWORK_FUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"COOKIE\0"), CURLoption::CURLOPT_COOKIE, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"COOKIEFILE\0"), CURLoption::CURLOPT_COOKIEFILE, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"COOKIEJAR\0"), CURLoption::CURLOPT_COOKIEJAR, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"COOKIELIST\0"), CURLoption::CURLOPT_COOKIELIST, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"COOKIESESSION\0"), CURLoption::CURLOPT_COOKIESESSION, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"COPYPOSTFIELDS\0"), CURLoption::CURLOPT_COPYPOSTFIELDS, curl_easytype::CURLOT_OBJECT, 0),
    row(optname!(b"CRLF\0"), CURLoption::CURLOPT_CRLF, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"CRLFILE\0"), CURLoption::CURLOPT_CRLFILE, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"CURLU\0"), CURLoption::CURLOPT_CURLU, curl_easytype::CURLOT_OBJECT, 0),
    row(optname!(b"CUSTOMREQUEST\0"), CURLoption::CURLOPT_CUSTOMREQUEST, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"DEBUGDATA\0"), CURLoption::CURLOPT_DEBUGDATA, curl_easytype::CURLOT_CBPTR, 0),
    row(optname!(b"DEBUGFUNCTION\0"), CURLoption::CURLOPT_DEBUGFUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"DEFAULT_PROTOCOL\0"), CURLoption::CURLOPT_DEFAULT_PROTOCOL, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"DIRLISTONLY\0"), CURLoption::CURLOPT_DIRLISTONLY, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"DISALLOW_USERNAME_IN_URL\0"), CURLoption::CURLOPT_DISALLOW_USERNAME_IN_URL, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"DNS_CACHE_TIMEOUT\0"), CURLoption::CURLOPT_DNS_CACHE_TIMEOUT, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"DNS_INTERFACE\0"), CURLoption::CURLOPT_DNS_INTERFACE, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"DNS_LOCAL_IP4\0"), CURLoption::CURLOPT_DNS_LOCAL_IP4, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"DNS_LOCAL_IP6\0"), CURLoption::CURLOPT_DNS_LOCAL_IP6, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"DNS_SERVERS\0"), CURLoption::CURLOPT_DNS_SERVERS, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"DNS_SHUFFLE_ADDRESSES\0"), CURLoption::CURLOPT_DNS_SHUFFLE_ADDRESSES, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"DNS_USE_GLOBAL_CACHE\0"), CURLoption::CURLOPT_DNS_USE_GLOBAL_CACHE, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"DOH_SSL_VERIFYHOST\0"), CURLoption::CURLOPT_DOH_SSL_VERIFYHOST, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"DOH_SSL_VERIFYPEER\0"), CURLoption::CURLOPT_DOH_SSL_VERIFYPEER, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"DOH_SSL_VERIFYSTATUS\0"), CURLoption::CURLOPT_DOH_SSL_VERIFYSTATUS, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"DOH_URL\0"), CURLoption::CURLOPT_DOH_URL, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"ECH\0"), CURLoption::CURLOPT_ECH, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"EGDSOCKET\0"), CURLoption::CURLOPT_EGDSOCKET, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"ENCODING\0"), CURLoption::CURLOPT_ACCEPT_ENCODING, curl_easytype::CURLOT_STRING, CURLOT_FLAG_ALIAS),
    row(optname!(b"ERRORBUFFER\0"), CURLoption::CURLOPT_ERRORBUFFER, curl_easytype::CURLOT_OBJECT, 0),
    row(optname!(b"EXPECT_100_TIMEOUT_MS\0"), CURLoption::CURLOPT_EXPECT_100_TIMEOUT_MS, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"FAILONERROR\0"), CURLoption::CURLOPT_FAILONERROR, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"FILE\0"), CURLoption::CURLOPT_WRITEDATA, curl_easytype::CURLOT_CBPTR, CURLOT_FLAG_ALIAS),
    row(optname!(b"FILETIME\0"), CURLoption::CURLOPT_FILETIME, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"FNMATCH_DATA\0"), CURLoption::CURLOPT_FNMATCH_DATA, curl_easytype::CURLOT_CBPTR, 0),
    row(optname!(b"FNMATCH_FUNCTION\0"), CURLoption::CURLOPT_FNMATCH_FUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"FOLLOWLOCATION\0"), CURLoption::CURLOPT_FOLLOWLOCATION, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"FORBID_REUSE\0"), CURLoption::CURLOPT_FORBID_REUSE, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"FRESH_CONNECT\0"), CURLoption::CURLOPT_FRESH_CONNECT, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"FTPAPPEND\0"), CURLoption::CURLOPT_APPEND, curl_easytype::CURLOT_LONG, CURLOT_FLAG_ALIAS),
    row(optname!(b"FTPLISTONLY\0"), CURLoption::CURLOPT_DIRLISTONLY, curl_easytype::CURLOT_LONG, CURLOT_FLAG_ALIAS),
    row(optname!(b"FTPPORT\0"), CURLoption::CURLOPT_FTPPORT, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"FTPSSLAUTH\0"), CURLoption::CURLOPT_FTPSSLAUTH, curl_easytype::CURLOT_VALUES, 0),
    row(optname!(b"FTP_ACCOUNT\0"), CURLoption::CURLOPT_FTP_ACCOUNT, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"FTP_ALTERNATIVE_TO_USER\0"), CURLoption::CURLOPT_FTP_ALTERNATIVE_TO_USER, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"FTP_CREATE_MISSING_DIRS\0"), CURLoption::CURLOPT_FTP_CREATE_MISSING_DIRS, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"FTP_FILEMETHOD\0"), CURLoption::CURLOPT_FTP_FILEMETHOD, curl_easytype::CURLOT_VALUES, 0),
    row(optname!(b"FTP_RESPONSE_TIMEOUT\0"), CURLoption::CURLOPT_SERVER_RESPONSE_TIMEOUT, curl_easytype::CURLOT_LONG, CURLOT_FLAG_ALIAS),
    row(optname!(b"FTP_SKIP_PASV_IP\0"), CURLoption::CURLOPT_FTP_SKIP_PASV_IP, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"FTP_SSL\0"), CURLoption::CURLOPT_USE_SSL, curl_easytype::CURLOT_VALUES, CURLOT_FLAG_ALIAS),
    row(optname!(b"FTP_SSL_CCC\0"), CURLoption::CURLOPT_FTP_SSL_CCC, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"FTP_USE_EPRT\0"), CURLoption::CURLOPT_FTP_USE_EPRT, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"FTP_USE_EPSV\0"), CURLoption::CURLOPT_FTP_USE_EPSV, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"FTP_USE_PRET\0"), CURLoption::CURLOPT_FTP_USE_PRET, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"GSSAPI_DELEGATION\0"), CURLoption::CURLOPT_GSSAPI_DELEGATION, curl_easytype::CURLOT_VALUES, 0),
    row(optname!(b"HAPPY_EYEBALLS_TIMEOUT_MS\0"), CURLoption::CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"HAPROXYPROTOCOL\0"), CURLoption::CURLOPT_HAPROXYPROTOCOL, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"HAPROXY_CLIENT_IP\0"), CURLoption::CURLOPT_HAPROXY_CLIENT_IP, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"HEADER\0"), CURLoption::CURLOPT_HEADER, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"HEADERDATA\0"), CURLoption::CURLOPT_HEADERDATA, curl_easytype::CURLOT_CBPTR, 0),
    row(optname!(b"HEADERFUNCTION\0"), CURLoption::CURLOPT_HEADERFUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"HEADEROPT\0"), CURLoption::CURLOPT_HEADEROPT, curl_easytype::CURLOT_VALUES, 0),
    row(optname!(b"HSTS\0"), CURLoption::CURLOPT_HSTS, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"HSTSREADDATA\0"), CURLoption::CURLOPT_HSTSREADDATA, curl_easytype::CURLOT_CBPTR, 0),
    row(optname!(b"HSTSREADFUNCTION\0"), CURLoption::CURLOPT_HSTSREADFUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"HSTSWRITEDATA\0"), CURLoption::CURLOPT_HSTSWRITEDATA, curl_easytype::CURLOT_CBPTR, 0),
    row(optname!(b"HSTSWRITEFUNCTION\0"), CURLoption::CURLOPT_HSTSWRITEFUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"HSTS_CTRL\0"), CURLoption::CURLOPT_HSTS_CTRL, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"HTTP09_ALLOWED\0"), CURLoption::CURLOPT_HTTP09_ALLOWED, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"HTTP200ALIASES\0"), CURLoption::CURLOPT_HTTP200ALIASES, curl_easytype::CURLOT_SLIST, 0),
    row(optname!(b"HTTPAUTH\0"), CURLoption::CURLOPT_HTTPAUTH, curl_easytype::CURLOT_VALUES, 0),
    row(optname!(b"HTTPGET\0"), CURLoption::CURLOPT_HTTPGET, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"HTTPHEADER\0"), CURLoption::CURLOPT_HTTPHEADER, curl_easytype::CURLOT_SLIST, 0),
    row(optname!(b"HTTPPOST\0"), CURLoption::CURLOPT_HTTPPOST, curl_easytype::CURLOT_OBJECT, 0),
    row(optname!(b"HTTPPROXYTUNNEL\0"), CURLoption::CURLOPT_HTTPPROXYTUNNEL, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"HTTP_CONTENT_DECODING\0"), CURLoption::CURLOPT_HTTP_CONTENT_DECODING, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"HTTP_TRANSFER_DECODING\0"), CURLoption::CURLOPT_HTTP_TRANSFER_DECODING, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"HTTP_VERSION\0"), CURLoption::CURLOPT_HTTP_VERSION, curl_easytype::CURLOT_VALUES, 0),
    row(optname!(b"IGNORE_CONTENT_LENGTH\0"), CURLoption::CURLOPT_IGNORE_CONTENT_LENGTH, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"INFILE\0"), CURLoption::CURLOPT_READDATA, curl_easytype::CURLOT_CBPTR, CURLOT_FLAG_ALIAS),
    row(optname!(b"INFILESIZE\0"), CURLoption::CURLOPT_INFILESIZE, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"INFILESIZE_LARGE\0"), CURLoption::CURLOPT_INFILESIZE_LARGE, curl_easytype::CURLOT_OFF_T, 0),
    row(optname!(b"INTERFACE\0"), CURLoption::CURLOPT_INTERFACE, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"INTERLEAVEDATA\0"), CURLoption::CURLOPT_INTERLEAVEDATA, curl_easytype::CURLOT_CBPTR, 0),
    row(optname!(b"INTERLEAVEFUNCTION\0"), CURLoption::CURLOPT_INTERLEAVEFUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"IOCTLDATA\0"), CURLoption::CURLOPT_IOCTLDATA, curl_easytype::CURLOT_CBPTR, 0),
    row(optname!(b"IOCTLFUNCTION\0"), CURLoption::CURLOPT_IOCTLFUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"IPRESOLVE\0"), CURLoption::CURLOPT_IPRESOLVE, curl_easytype::CURLOT_VALUES, 0),
    row(optname!(b"ISSUERCERT\0"), CURLoption::CURLOPT_ISSUERCERT, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"ISSUERCERT_BLOB\0"), CURLoption::CURLOPT_ISSUERCERT_BLOB, curl_easytype::CURLOT_BLOB, 0),
    row(optname!(b"KEEP_SENDING_ON_ERROR\0"), CURLoption::CURLOPT_KEEP_SENDING_ON_ERROR, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"KEYPASSWD\0"), CURLoption::CURLOPT_KEYPASSWD, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"KRB4LEVEL\0"), CURLoption::CURLOPT_KRBLEVEL, curl_easytype::CURLOT_STRING, CURLOT_FLAG_ALIAS),
    row(optname!(b"KRBLEVEL\0"), CURLoption::CURLOPT_KRBLEVEL, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"LOCALPORT\0"), CURLoption::CURLOPT_LOCALPORT, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"LOCALPORTRANGE\0"), CURLoption::CURLOPT_LOCALPORTRANGE, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"LOGIN_OPTIONS\0"), CURLoption::CURLOPT_LOGIN_OPTIONS, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"LOW_SPEED_LIMIT\0"), CURLoption::CURLOPT_LOW_SPEED_LIMIT, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"LOW_SPEED_TIME\0"), CURLoption::CURLOPT_LOW_SPEED_TIME, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"MAIL_AUTH\0"), CURLoption::CURLOPT_MAIL_AUTH, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"MAIL_FROM\0"), CURLoption::CURLOPT_MAIL_FROM, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"MAIL_RCPT\0"), CURLoption::CURLOPT_MAIL_RCPT, curl_easytype::CURLOT_SLIST, 0),
    row(optname!(b"MAIL_RCPT_ALLLOWFAILS\0"), CURLoption::CURLOPT_MAIL_RCPT_ALLOWFAILS, curl_easytype::CURLOT_LONG, CURLOT_FLAG_ALIAS),
    row(optname!(b"MAIL_RCPT_ALLOWFAILS\0"), CURLoption::CURLOPT_MAIL_RCPT_ALLOWFAILS, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"MAXAGE_CONN\0"), CURLoption::CURLOPT_MAXAGE_CONN, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"MAXCONNECTS\0"), CURLoption::CURLOPT_MAXCONNECTS, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"MAXFILESIZE\0"), CURLoption::CURLOPT_MAXFILESIZE, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"MAXFILESIZE_LARGE\0"), CURLoption::CURLOPT_MAXFILESIZE_LARGE, curl_easytype::CURLOT_OFF_T, 0),
    row(optname!(b"MAXLIFETIME_CONN\0"), CURLoption::CURLOPT_MAXLIFETIME_CONN, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"MAXREDIRS\0"), CURLoption::CURLOPT_MAXREDIRS, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"MAX_RECV_SPEED_LARGE\0"), CURLoption::CURLOPT_MAX_RECV_SPEED_LARGE, curl_easytype::CURLOT_OFF_T, 0),
    row(optname!(b"MAX_SEND_SPEED_LARGE\0"), CURLoption::CURLOPT_MAX_SEND_SPEED_LARGE, curl_easytype::CURLOT_OFF_T, 0),
    row(optname!(b"MIMEPOST\0"), CURLoption::CURLOPT_MIMEPOST, curl_easytype::CURLOT_OBJECT, 0),
    row(optname!(b"MIME_OPTIONS\0"), CURLoption::CURLOPT_MIME_OPTIONS, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"NETRC\0"), CURLoption::CURLOPT_NETRC, curl_easytype::CURLOT_VALUES, 0),
    row(optname!(b"NETRC_FILE\0"), CURLoption::CURLOPT_NETRC_FILE, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"NEW_DIRECTORY_PERMS\0"), CURLoption::CURLOPT_NEW_DIRECTORY_PERMS, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"NEW_FILE_PERMS\0"), CURLoption::CURLOPT_NEW_FILE_PERMS, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"NOBODY\0"), CURLoption::CURLOPT_NOBODY, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"NOPROGRESS\0"), CURLoption::CURLOPT_NOPROGRESS, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"NOPROXY\0"), CURLoption::CURLOPT_NOPROXY, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"NOSIGNAL\0"), CURLoption::CURLOPT_NOSIGNAL, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"OPENSOCKETDATA\0"), CURLoption::CURLOPT_OPENSOCKETDATA, curl_easytype::CURLOT_CBPTR, 0),
    row(optname!(b"OPENSOCKETFUNCTION\0"), CURLoption::CURLOPT_OPENSOCKETFUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"PASSWORD\0"), CURLoption::CURLOPT_PASSWORD, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"PATH_AS_IS\0"), CURLoption::CURLOPT_PATH_AS_IS, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"PINNEDPUBLICKEY\0"), CURLoption::CURLOPT_PINNEDPUBLICKEY, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"PIPEWAIT\0"), CURLoption::CURLOPT_PIPEWAIT, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"PORT\0"), CURLoption::CURLOPT_PORT, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"POST\0"), CURLoption::CURLOPT_POST, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"POST301\0"), CURLoption::CURLOPT_POSTREDIR, curl_easytype::CURLOT_VALUES, CURLOT_FLAG_ALIAS),
    row(optname!(b"POSTFIELDS\0"), CURLoption::CURLOPT_POSTFIELDS, curl_easytype::CURLOT_OBJECT, 0),
    row(optname!(b"POSTFIELDSIZE\0"), CURLoption::CURLOPT_POSTFIELDSIZE, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"POSTFIELDSIZE_LARGE\0"), CURLoption::CURLOPT_POSTFIELDSIZE_LARGE, curl_easytype::CURLOT_OFF_T, 0),
    row(optname!(b"POSTQUOTE\0"), CURLoption::CURLOPT_POSTQUOTE, curl_easytype::CURLOT_SLIST, 0),
    row(optname!(b"POSTREDIR\0"), CURLoption::CURLOPT_POSTREDIR, curl_easytype::CURLOT_VALUES, 0),
    row(optname!(b"PREQUOTE\0"), CURLoption::CURLOPT_PREQUOTE, curl_easytype::CURLOT_SLIST, 0),
    row(optname!(b"PREREQDATA\0"), CURLoption::CURLOPT_PREREQDATA, curl_easytype::CURLOT_CBPTR, 0),
    row(optname!(b"PREREQFUNCTION\0"), CURLoption::CURLOPT_PREREQFUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"PRE_PROXY\0"), CURLoption::CURLOPT_PRE_PROXY, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"PRIVATE\0"), CURLoption::CURLOPT_PRIVATE, curl_easytype::CURLOT_OBJECT, 0),
    row(optname!(b"PROGRESSDATA\0"), CURLoption::CURLOPT_XFERINFODATA, curl_easytype::CURLOT_CBPTR, CURLOT_FLAG_ALIAS),
    row(optname!(b"PROGRESSFUNCTION\0"), CURLoption::CURLOPT_PROGRESSFUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"PROTOCOLS\0"), CURLoption::CURLOPT_PROTOCOLS, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"PROTOCOLS_STR\0"), CURLoption::CURLOPT_PROTOCOLS_STR, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"PROXY\0"), CURLoption::CURLOPT_PROXY, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"PROXYAUTH\0"), CURLoption::CURLOPT_PROXYAUTH, curl_easytype::CURLOT_VALUES, 0),
    row(optname!(b"PROXYHEADER\0"), CURLoption::CURLOPT_PROXYHEADER, curl_easytype::CURLOT_SLIST, 0),
    row(optname!(b"PROXYPASSWORD\0"), CURLoption::CURLOPT_PROXYPASSWORD, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"PROXYPORT\0"), CURLoption::CURLOPT_PROXYPORT, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"PROXYTYPE\0"), CURLoption::CURLOPT_PROXYTYPE, curl_easytype::CURLOT_VALUES, 0),
    row(optname!(b"PROXYUSERNAME\0"), CURLoption::CURLOPT_PROXYUSERNAME, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"PROXYUSERPWD\0"), CURLoption::CURLOPT_PROXYUSERPWD, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"PROXY_CAINFO\0"), CURLoption::CURLOPT_PROXY_CAINFO, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"PROXY_CAINFO_BLOB\0"), CURLoption::CURLOPT_PROXY_CAINFO_BLOB, curl_easytype::CURLOT_BLOB, 0),
    row(optname!(b"PROXY_CAPATH\0"), CURLoption::CURLOPT_PROXY_CAPATH, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"PROXY_CRLFILE\0"), CURLoption::CURLOPT_PROXY_CRLFILE, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"PROXY_ISSUERCERT\0"), CURLoption::CURLOPT_PROXY_ISSUERCERT, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"PROXY_ISSUERCERT_BLOB\0"), CURLoption::CURLOPT_PROXY_ISSUERCERT_BLOB, curl_easytype::CURLOT_BLOB, 0),
    row(optname!(b"PROXY_KEYPASSWD\0"), CURLoption::CURLOPT_PROXY_KEYPASSWD, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"PROXY_PINNEDPUBLICKEY\0"), CURLoption::CURLOPT_PROXY_PINNEDPUBLICKEY, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"PROXY_SERVICE_NAME\0"), CURLoption::CURLOPT_PROXY_SERVICE_NAME, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"PROXY_SSLCERT\0"), CURLoption::CURLOPT_PROXY_SSLCERT, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"PROXY_SSLCERTTYPE\0"), CURLoption::CURLOPT_PROXY_SSLCERTTYPE, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"PROXY_SSLCERT_BLOB\0"), CURLoption::CURLOPT_PROXY_SSLCERT_BLOB, curl_easytype::CURLOT_BLOB, 0),
    row(optname!(b"PROXY_SSLKEY\0"), CURLoption::CURLOPT_PROXY_SSLKEY, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"PROXY_SSLKEYTYPE\0"), CURLoption::CURLOPT_PROXY_SSLKEYTYPE, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"PROXY_SSLKEY_BLOB\0"), CURLoption::CURLOPT_PROXY_SSLKEY_BLOB, curl_easytype::CURLOT_BLOB, 0),
    row(optname!(b"PROXY_SSLVERSION\0"), CURLoption::CURLOPT_PROXY_SSLVERSION, curl_easytype::CURLOT_VALUES, 0),
    row(optname!(b"PROXY_SSL_CIPHER_LIST\0"), CURLoption::CURLOPT_PROXY_SSL_CIPHER_LIST, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"PROXY_SSL_OPTIONS\0"), CURLoption::CURLOPT_PROXY_SSL_OPTIONS, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"PROXY_SSL_VERIFYHOST\0"), CURLoption::CURLOPT_PROXY_SSL_VERIFYHOST, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"PROXY_SSL_VERIFYPEER\0"), CURLoption::CURLOPT_PROXY_SSL_VERIFYPEER, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"PROXY_TLS13_CIPHERS\0"), CURLoption::CURLOPT_PROXY_TLS13_CIPHERS, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"PROXY_TLSAUTH_PASSWORD\0"), CURLoption::CURLOPT_PROXY_TLSAUTH_PASSWORD, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"PROXY_TLSAUTH_TYPE\0"), CURLoption::CURLOPT_PROXY_TLSAUTH_TYPE, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"PROXY_TLSAUTH_USERNAME\0"), CURLoption::CURLOPT_PROXY_TLSAUTH_USERNAME, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"PROXY_TRANSFER_MODE\0"), CURLoption::CURLOPT_PROXY_TRANSFER_MODE, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"PUT\0"), CURLoption::CURLOPT_PUT, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"QUICK_EXIT\0"), CURLoption::CURLOPT_QUICK_EXIT, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"QUOTE\0"), CURLoption::CURLOPT_QUOTE, curl_easytype::CURLOT_SLIST, 0),
    row(optname!(b"RANDOM_FILE\0"), CURLoption::CURLOPT_RANDOM_FILE, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"RANGE\0"), CURLoption::CURLOPT_RANGE, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"READDATA\0"), CURLoption::CURLOPT_READDATA, curl_easytype::CURLOT_CBPTR, 0),
    row(optname!(b"READFUNCTION\0"), CURLoption::CURLOPT_READFUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"REDIR_PROTOCOLS\0"), CURLoption::CURLOPT_REDIR_PROTOCOLS, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"REDIR_PROTOCOLS_STR\0"), CURLoption::CURLOPT_REDIR_PROTOCOLS_STR, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"REFERER\0"), CURLoption::CURLOPT_REFERER, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"REQUEST_TARGET\0"), CURLoption::CURLOPT_REQUEST_TARGET, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"RESOLVE\0"), CURLoption::CURLOPT_RESOLVE, curl_easytype::CURLOT_SLIST, 0),
    row(optname!(b"RESOLVER_START_DATA\0"), CURLoption::CURLOPT_RESOLVER_START_DATA, curl_easytype::CURLOT_CBPTR, 0),
    row(optname!(b"RESOLVER_START_FUNCTION\0"), CURLoption::CURLOPT_RESOLVER_START_FUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"RESUME_FROM\0"), CURLoption::CURLOPT_RESUME_FROM, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"RESUME_FROM_LARGE\0"), CURLoption::CURLOPT_RESUME_FROM_LARGE, curl_easytype::CURLOT_OFF_T, 0),
    row(optname!(b"RTSPHEADER\0"), CURLoption::CURLOPT_HTTPHEADER, curl_easytype::CURLOT_SLIST, CURLOT_FLAG_ALIAS),
    row(optname!(b"RTSP_CLIENT_CSEQ\0"), CURLoption::CURLOPT_RTSP_CLIENT_CSEQ, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"RTSP_REQUEST\0"), CURLoption::CURLOPT_RTSP_REQUEST, curl_easytype::CURLOT_VALUES, 0),
    row(optname!(b"RTSP_SERVER_CSEQ\0"), CURLoption::CURLOPT_RTSP_SERVER_CSEQ, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"RTSP_SESSION_ID\0"), CURLoption::CURLOPT_RTSP_SESSION_ID, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"RTSP_STREAM_URI\0"), CURLoption::CURLOPT_RTSP_STREAM_URI, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"RTSP_TRANSPORT\0"), CURLoption::CURLOPT_RTSP_TRANSPORT, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"SASL_AUTHZID\0"), CURLoption::CURLOPT_SASL_AUTHZID, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"SASL_IR\0"), CURLoption::CURLOPT_SASL_IR, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"SEEKDATA\0"), CURLoption::CURLOPT_SEEKDATA, curl_easytype::CURLOT_CBPTR, 0),
    row(optname!(b"SEEKFUNCTION\0"), CURLoption::CURLOPT_SEEKFUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"SERVER_RESPONSE_TIMEOUT\0"), CURLoption::CURLOPT_SERVER_RESPONSE_TIMEOUT, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"SERVER_RESPONSE_TIMEOUT_MS\0"), CURLoption::CURLOPT_SERVER_RESPONSE_TIMEOUT_MS, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"SERVICE_NAME\0"), CURLoption::CURLOPT_SERVICE_NAME, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"SHARE\0"), CURLoption::CURLOPT_SHARE, curl_easytype::CURLOT_OBJECT, 0),
    row(optname!(b"SOCKOPTDATA\0"), CURLoption::CURLOPT_SOCKOPTDATA, curl_easytype::CURLOT_CBPTR, 0),
    row(optname!(b"SOCKOPTFUNCTION\0"), CURLoption::CURLOPT_SOCKOPTFUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"SOCKS5_AUTH\0"), CURLoption::CURLOPT_SOCKS5_AUTH, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"SOCKS5_GSSAPI_NEC\0"), CURLoption::CURLOPT_SOCKS5_GSSAPI_NEC, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"SOCKS5_GSSAPI_SERVICE\0"), CURLoption::CURLOPT_SOCKS5_GSSAPI_SERVICE, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"SSH_AUTH_TYPES\0"), CURLoption::CURLOPT_SSH_AUTH_TYPES, curl_easytype::CURLOT_VALUES, 0),
    row(optname!(b"SSH_COMPRESSION\0"), CURLoption::CURLOPT_SSH_COMPRESSION, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"SSH_HOSTKEYDATA\0"), CURLoption::CURLOPT_SSH_HOSTKEYDATA, curl_easytype::CURLOT_CBPTR, 0),
    row(optname!(b"SSH_HOSTKEYFUNCTION\0"), CURLoption::CURLOPT_SSH_HOSTKEYFUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"SSH_HOST_PUBLIC_KEY_MD5\0"), CURLoption::CURLOPT_SSH_HOST_PUBLIC_KEY_MD5, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"SSH_HOST_PUBLIC_KEY_SHA256\0"), CURLoption::CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"SSH_KEYDATA\0"), CURLoption::CURLOPT_SSH_KEYDATA, curl_easytype::CURLOT_CBPTR, 0),
    row(optname!(b"SSH_KEYFUNCTION\0"), CURLoption::CURLOPT_SSH_KEYFUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"SSH_KNOWNHOSTS\0"), CURLoption::CURLOPT_SSH_KNOWNHOSTS, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"SSH_PRIVATE_KEYFILE\0"), CURLoption::CURLOPT_SSH_PRIVATE_KEYFILE, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"SSH_PUBLIC_KEYFILE\0"), CURLoption::CURLOPT_SSH_PUBLIC_KEYFILE, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"SSLCERT\0"), CURLoption::CURLOPT_SSLCERT, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"SSLCERTPASSWD\0"), CURLoption::CURLOPT_KEYPASSWD, curl_easytype::CURLOT_STRING, CURLOT_FLAG_ALIAS),
    row(optname!(b"SSLCERTTYPE\0"), CURLoption::CURLOPT_SSLCERTTYPE, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"SSLCERT_BLOB\0"), CURLoption::CURLOPT_SSLCERT_BLOB, curl_easytype::CURLOT_BLOB, 0),
    row(optname!(b"SSLENGINE\0"), CURLoption::CURLOPT_SSLENGINE, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"SSLENGINE_DEFAULT\0"), CURLoption::CURLOPT_SSLENGINE_DEFAULT, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"SSLKEY\0"), CURLoption::CURLOPT_SSLKEY, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"SSLKEYPASSWD\0"), CURLoption::CURLOPT_KEYPASSWD, curl_easytype::CURLOT_STRING, CURLOT_FLAG_ALIAS),
    row(optname!(b"SSLKEYTYPE\0"), CURLoption::CURLOPT_SSLKEYTYPE, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"SSLKEY_BLOB\0"), CURLoption::CURLOPT_SSLKEY_BLOB, curl_easytype::CURLOT_BLOB, 0),
    row(optname!(b"SSLVERSION\0"), CURLoption::CURLOPT_SSLVERSION, curl_easytype::CURLOT_VALUES, 0),
    row(optname!(b"SSL_CIPHER_LIST\0"), CURLoption::CURLOPT_SSL_CIPHER_LIST, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"SSL_CTX_DATA\0"), CURLoption::CURLOPT_SSL_CTX_DATA, curl_easytype::CURLOT_CBPTR, 0),
    row(optname!(b"SSL_CTX_FUNCTION\0"), CURLoption::CURLOPT_SSL_CTX_FUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"SSL_EC_CURVES\0"), CURLoption::CURLOPT_SSL_EC_CURVES, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"SSL_ENABLE_ALPN\0"), CURLoption::CURLOPT_SSL_ENABLE_ALPN, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"SSL_ENABLE_NPN\0"), CURLoption::CURLOPT_SSL_ENABLE_NPN, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"SSL_FALSESTART\0"), CURLoption::CURLOPT_SSL_FALSESTART, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"SSL_OPTIONS\0"), CURLoption::CURLOPT_SSL_OPTIONS, curl_easytype::CURLOT_VALUES, 0),
    row(optname!(b"SSL_SESSIONID_CACHE\0"), CURLoption::CURLOPT_SSL_SESSIONID_CACHE, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"SSL_SIGNATURE_ALGORITHMS\0"), CURLoption::CURLOPT_SSL_SIGNATURE_ALGORITHMS, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"SSL_VERIFYHOST\0"), CURLoption::CURLOPT_SSL_VERIFYHOST, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"SSL_VERIFYPEER\0"), CURLoption::CURLOPT_SSL_VERIFYPEER, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"SSL_VERIFYSTATUS\0"), CURLoption::CURLOPT_SSL_VERIFYSTATUS, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"STDERR\0"), CURLoption::CURLOPT_STDERR, curl_easytype::CURLOT_OBJECT, 0),
    row(optname!(b"STREAM_DEPENDS\0"), CURLoption::CURLOPT_STREAM_DEPENDS, curl_easytype::CURLOT_OBJECT, 0),
    row(optname!(b"STREAM_DEPENDS_E\0"), CURLoption::CURLOPT_STREAM_DEPENDS_E, curl_easytype::CURLOT_OBJECT, 0),
    row(optname!(b"STREAM_WEIGHT\0"), CURLoption::CURLOPT_STREAM_WEIGHT, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"SUPPRESS_CONNECT_HEADERS\0"), CURLoption::CURLOPT_SUPPRESS_CONNECT_HEADERS, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"TCP_FASTOPEN\0"), CURLoption::CURLOPT_TCP_FASTOPEN, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"TCP_KEEPALIVE\0"), CURLoption::CURLOPT_TCP_KEEPALIVE, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"TCP_KEEPCNT\0"), CURLoption::CURLOPT_TCP_KEEPCNT, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"TCP_KEEPIDLE\0"), CURLoption::CURLOPT_TCP_KEEPIDLE, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"TCP_KEEPINTVL\0"), CURLoption::CURLOPT_TCP_KEEPINTVL, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"TCP_NODELAY\0"), CURLoption::CURLOPT_TCP_NODELAY, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"TELNETOPTIONS\0"), CURLoption::CURLOPT_TELNETOPTIONS, curl_easytype::CURLOT_SLIST, 0),
    row(optname!(b"TFTP_BLKSIZE\0"), CURLoption::CURLOPT_TFTP_BLKSIZE, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"TFTP_NO_OPTIONS\0"), CURLoption::CURLOPT_TFTP_NO_OPTIONS, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"TIMECONDITION\0"), CURLoption::CURLOPT_TIMECONDITION, curl_easytype::CURLOT_VALUES, 0),
    row(optname!(b"TIMEOUT\0"), CURLoption::CURLOPT_TIMEOUT, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"TIMEOUT_MS\0"), CURLoption::CURLOPT_TIMEOUT_MS, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"TIMEVALUE\0"), CURLoption::CURLOPT_TIMEVALUE, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"TIMEVALUE_LARGE\0"), CURLoption::CURLOPT_TIMEVALUE_LARGE, curl_easytype::CURLOT_OFF_T, 0),
    row(optname!(b"TLS13_CIPHERS\0"), CURLoption::CURLOPT_TLS13_CIPHERS, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"TLSAUTH_PASSWORD\0"), CURLoption::CURLOPT_TLSAUTH_PASSWORD, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"TLSAUTH_TYPE\0"), CURLoption::CURLOPT_TLSAUTH_TYPE, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"TLSAUTH_USERNAME\0"), CURLoption::CURLOPT_TLSAUTH_USERNAME, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"TRAILERDATA\0"), CURLoption::CURLOPT_TRAILERDATA, curl_easytype::CURLOT_CBPTR, 0),
    row(optname!(b"TRAILERFUNCTION\0"), CURLoption::CURLOPT_TRAILERFUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"TRANSFERTEXT\0"), CURLoption::CURLOPT_TRANSFERTEXT, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"TRANSFER_ENCODING\0"), CURLoption::CURLOPT_TRANSFER_ENCODING, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"UNIX_SOCKET_PATH\0"), CURLoption::CURLOPT_UNIX_SOCKET_PATH, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"UNRESTRICTED_AUTH\0"), CURLoption::CURLOPT_UNRESTRICTED_AUTH, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"UPKEEP_INTERVAL_MS\0"), CURLoption::CURLOPT_UPKEEP_INTERVAL_MS, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"UPLOAD\0"), CURLoption::CURLOPT_UPLOAD, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"UPLOAD_BUFFERSIZE\0"), CURLoption::CURLOPT_UPLOAD_BUFFERSIZE, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"UPLOAD_FLAGS\0"), CURLoption::CURLOPT_UPLOAD_FLAGS, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"URL\0"), CURLoption::CURLOPT_URL, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"USERAGENT\0"), CURLoption::CURLOPT_USERAGENT, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"USERNAME\0"), CURLoption::CURLOPT_USERNAME, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"USERPWD\0"), CURLoption::CURLOPT_USERPWD, curl_easytype::CURLOT_STRING, 0),
    row(optname!(b"USE_SSL\0"), CURLoption::CURLOPT_USE_SSL, curl_easytype::CURLOT_VALUES, 0),
    row(optname!(b"VERBOSE\0"), CURLoption::CURLOPT_VERBOSE, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"WILDCARDMATCH\0"), CURLoption::CURLOPT_WILDCARDMATCH, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"WRITEDATA\0"), CURLoption::CURLOPT_WRITEDATA, curl_easytype::CURLOT_CBPTR, 0),
    row(optname!(b"WRITEFUNCTION\0"), CURLoption::CURLOPT_WRITEFUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"WRITEHEADER\0"), CURLoption::CURLOPT_HEADERDATA, curl_easytype::CURLOT_CBPTR, CURLOT_FLAG_ALIAS),
    row(optname!(b"WS_OPTIONS\0"), CURLoption::CURLOPT_WS_OPTIONS, curl_easytype::CURLOT_LONG, 0),
    row(optname!(b"XFERINFODATA\0"), CURLoption::CURLOPT_XFERINFODATA, curl_easytype::CURLOT_CBPTR, 0),
    row(optname!(b"XFERINFOFUNCTION\0"), CURLoption::CURLOPT_XFERINFOFUNCTION, curl_easytype::CURLOT_FUNCTION, 0),
    row(optname!(b"XOAUTH2_BEARER\0"), CURLoption::CURLOPT_XOAUTH2_BEARER, curl_easytype::CURLOT_STRING, 0),
    row(ptr::null(), CURLoption::CURLOPT_LASTENTRY, curl_easytype::CURLOT_LONG, 0),
]);

/// `const struct curl_easyoption *curl_easy_option_by_name(const char *name);`
///
/// Look up an easyoption metadata row by its option name (the `CURLOPT_` prefix removed, e.g.
/// `"URL"`), matched **case-insensitively** to mirror curl's `curl_strequal`. Returns a borrowed
/// pointer into the static table, or null if `name` is null or no option matches. The returned
/// pointer is valid for the life of the process and must not be freed by the caller.
///
/// # Safety
/// `name` must be null or a valid pointer to a NUL-terminated C string that stays valid for the
/// duration of the call.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_option_by_name(name: *const c_char) -> *const curl_easyoption {
    catch_unwind(AssertUnwindSafe(move || {
        if name.is_null() {
            return ptr::null();
        }
        // SAFETY: the caller contract guarantees that a non-null `name` (checked above) points to a
        // valid NUL-terminated C string valid for this call; `CStr::from_ptr` only reads up to and
        // including that terminator.
        let query = unsafe { CStr::from_ptr(name) }.to_bytes();
        for opt in CURL_EASYOPTS.0.iter() {
            if opt.name.is_null() {
                break; // reached the sentinel — stop (curl loops `while(o->name)`)
            }
            // SAFETY: `opt.name` is non-null (checked) and, by construction of the static table,
            // points at a `'static` NUL-terminated byte-string literal.
            let candidate = unsafe { CStr::from_ptr(opt.name) }.to_bytes();
            if candidate.eq_ignore_ascii_case(query) {
                return opt as *const curl_easyoption;
            }
        }
        ptr::null()
    }))
    .unwrap_or(ptr::null())
}

/// `const struct curl_easyoption *curl_easy_option_by_id(CURLoption id);`
///
/// Look up an easyoption metadata row by its numeric [`CURLoption`] id. **Alias rows are skipped**
/// (curl's `lookup()` requires `!(o->flags & CURLOT_FLAG_ALIAS)`), so an id that has one or more
/// legacy aliases resolves to its canonical option. Returns a borrowed pointer into the static
/// table, or null if no (non-alias) option carries `id`. The returned pointer is valid for the life
/// of the process and must not be freed by the caller.
///
/// This function takes its argument by value and dereferences no caller pointer, so it is a safe
/// `extern "C" fn`.
#[no_mangle]
pub extern "C" fn curl_easy_option_by_id(id: CURLoption) -> *const curl_easyoption {
    catch_unwind(AssertUnwindSafe(move || {
        for opt in CURL_EASYOPTS.0.iter() {
            if opt.name.is_null() {
                break; // sentinel — curl's loop condition is `while(o->name)`
            }
            if opt.id == id && (opt.flags & CURLOT_FLAG_ALIAS) == 0 {
                return opt as *const curl_easyoption;
            }
        }
        ptr::null()
    }))
    .unwrap_or(ptr::null())
}

/// `const struct curl_easyoption *curl_easy_option_next(const struct curl_easyoption *prev);`
///
/// Iterate the easyoption table. Passing null returns the first row; passing a row previously
/// returned by this API returns the following row; passing the last row (or the sentinel) returns
/// null. This mirrors curl's `curl_easy_option_next` exactly, including the stop at the
/// null-`name` sentinel. Returned pointers are borrowed into the static table and must not be
/// freed.
///
/// # Safety
/// `prev` must be null or a pointer previously returned by one of the `curl_easy_option_*`
/// functions (i.e. a pointer to an element of the static table); it must not be a dangling or
/// unrelated pointer.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_option_next(
    prev: *const curl_easyoption,
) -> *const curl_easyoption {
    catch_unwind(AssertUnwindSafe(move || {
        if prev.is_null() {
            // curl: `if(!prev) return &Curl_easyopts[0];`
            return CURL_EASYOPTS.0.as_ptr();
        }
        // SAFETY: by the documented contract `prev` points at an element of `CURL_EASYOPTS`
        // (including the sentinel), so reading its `name` field is an in-bounds read of live,
        // immutable data.
        let prev_name = unsafe { (*prev).name };
        if prev_name.is_null() {
            // `prev` is already the sentinel — curl falls through to `return NULL;`.
            return ptr::null();
        }
        // SAFETY: `prev` is a non-sentinel element of the table (its `name` is non-null), so the
        // next slot `prev + 1` is still within the `CURL_EASYOPTS` array (the sentinel guarantees a
        // valid successor slot exists).
        let next = unsafe { prev.add(1) };
        // SAFETY: `next` is in-bounds per the reasoning above; read its `name` to detect whether we
        // have reached the sentinel.
        let next_name = unsafe { (*next).name };
        if next_name.is_null() {
            // curl: after `prev++`, `if(prev->name) return prev;` else fall through to `NULL`.
            ptr::null()
        } else {
            next
        }
    }))
    .unwrap_or(ptr::null())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// Number of real (non-sentinel) option rows, matching `lib/easyoptions.c`.
    const REAL_ENTRIES: usize = 323;

    fn cstr(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    #[test]
    fn table_is_sentinel_terminated() {
        // Full array length = real entries + 1 sentinel.
        assert_eq!(CURL_EASYOPTS.0.len(), REAL_ENTRIES + 1);
        // Last row is the sentinel: null name, CURLOPT_LASTENTRY, CURLOT_LONG, no flags.
        let last = &CURL_EASYOPTS.0[REAL_ENTRIES];
        assert!(last.name.is_null());
        assert_eq!(last.id, CURLoption::CURLOPT_LASTENTRY);
        assert_eq!(last.type_, curl_easytype::CURLOT_LONG);
        assert_eq!(last.flags, 0);
        // No non-sentinel row has a null name.
        for row in &CURL_EASYOPTS.0[..REAL_ENTRIES] {
            assert!(!row.name.is_null());
        }
    }

    #[test]
    fn easytype_and_flag_values_are_frozen() {
        assert_eq!(curl_easytype::CURLOT_LONG as u32, 0);
        assert_eq!(curl_easytype::CURLOT_VALUES as u32, 1);
        assert_eq!(curl_easytype::CURLOT_OFF_T as u32, 2);
        assert_eq!(curl_easytype::CURLOT_OBJECT as u32, 3);
        assert_eq!(curl_easytype::CURLOT_STRING as u32, 4);
        assert_eq!(curl_easytype::CURLOT_SLIST as u32, 5);
        assert_eq!(curl_easytype::CURLOT_CBPTR as u32, 6);
        assert_eq!(curl_easytype::CURLOT_BLOB as u32, 7);
        assert_eq!(curl_easytype::CURLOT_FUNCTION as u32, 8);
        assert_eq!(CURLOT_FLAG_ALIAS, 1);
    }

    #[test]
    fn by_name_exact_and_case_insensitive() {
        let want = cstr("URL");
        // SAFETY: `want` is a valid NUL-terminated C string alive for the call.
        let a = unsafe { curl_easy_option_by_name(want.as_ptr()) };
        assert!(!a.is_null());
        // SAFETY: `a` is a valid pointer into the static table.
        assert_eq!(unsafe { (*a).id }, CURLoption::CURLOPT_URL);
        assert_eq!(unsafe { (*a).type_ }, curl_easytype::CURLOT_STRING);

        // Case-insensitive: "url", "Url", "URL" all resolve to the same row.
        for spelling in ["url", "Url", "uRl"] {
            let s = cstr(spelling);
            // SAFETY: `s` is a valid NUL-terminated C string alive for the call.
            let p = unsafe { curl_easy_option_by_name(s.as_ptr()) };
            assert_eq!(
                p, a,
                "case-insensitive lookup of {spelling:?} must match URL"
            );
        }
    }

    #[test]
    fn by_name_resolves_alias_row() {
        // "ENCODING" is a legacy alias of CURLOPT_ACCEPT_ENCODING.
        let s = cstr("ENCODING");
        // SAFETY: valid C string for the call.
        let p = unsafe { curl_easy_option_by_name(s.as_ptr()) };
        assert!(!p.is_null());
        // SAFETY: `p` points into the static table.
        assert_eq!(unsafe { (*p).id }, CURLoption::CURLOPT_ACCEPT_ENCODING);
        assert_eq!(unsafe { (*p).flags } & CURLOT_FLAG_ALIAS, CURLOT_FLAG_ALIAS);
    }

    #[test]
    fn by_name_null_and_missing_return_null() {
        // Null name.
        // SAFETY: null is an explicitly allowed argument.
        assert!(unsafe { curl_easy_option_by_name(ptr::null()) }.is_null());
        // Unknown option name.
        let s = cstr("THIS_IS_NOT_AN_OPTION");
        // SAFETY: valid C string for the call.
        assert!(unsafe { curl_easy_option_by_name(s.as_ptr()) }.is_null());
    }

    #[test]
    fn by_id_returns_canonical_and_skips_aliases() {
        // CURLOPT_KEYPASSWD is the canonical row; SSLKEYPASSWD & SSLCERTPASSWD are its aliases.
        let p = curl_easy_option_by_id(CURLoption::CURLOPT_KEYPASSWD);
        assert!(!p.is_null());
        // SAFETY: `p` points into the static table.
        assert_eq!(
            unsafe { (*p).flags } & CURLOT_FLAG_ALIAS,
            0,
            "must be the canonical (non-alias) row"
        );
        // SAFETY: canonical row has a non-null name equal to "KEYPASSWD".
        let name = unsafe { CStr::from_ptr((*p).name) };
        assert_eq!(name.to_bytes(), b"KEYPASSWD");
    }

    #[test]
    fn by_id_sentinel_id_not_found() {
        // The sentinel id must never resolve to a row.
        assert!(curl_easy_option_by_id(CURLoption::CURLOPT_LASTENTRY).is_null());
    }

    #[test]
    fn next_iterates_every_real_entry_in_order() {
        // Null -> first row.
        // SAFETY: null is an explicitly allowed argument.
        let first = unsafe { curl_easy_option_next(ptr::null()) };
        assert!(!first.is_null());
        // The table is ASCII-alphabetical; the first row is ABSTRACT_UNIX_SOCKET.
        // SAFETY: `first` points into the static table.
        let first_name = unsafe { CStr::from_ptr((*first).name) };
        assert_eq!(first_name.to_bytes(), b"ABSTRACT_UNIX_SOCKET");

        // Walk to the end, counting rows; iteration must stop at the sentinel (null).
        let mut count = 0usize;
        let mut cur = first;
        while !cur.is_null() {
            count += 1;
            // SAFETY: `cur` is null or a pointer previously returned by this API.
            cur = unsafe { curl_easy_option_next(cur) };
        }
        assert_eq!(
            count, REAL_ENTRIES,
            "next() must visit exactly the real entries"
        );
    }

    #[test]
    fn next_on_last_real_row_and_sentinel_returns_null() {
        // Pointer to the last real row -> next is the sentinel -> returns null.
        let last_real: *const curl_easyoption = &CURL_EASYOPTS.0[REAL_ENTRIES - 1];
        // SAFETY: `last_real` points at a valid table element.
        assert!(unsafe { curl_easy_option_next(last_real) }.is_null());

        // Pointer to the sentinel itself -> returns null.
        let sentinel: *const curl_easyoption = &CURL_EASYOPTS.0[REAL_ENTRIES];
        // SAFETY: `sentinel` points at the valid sentinel element.
        assert!(unsafe { curl_easy_option_next(sentinel) }.is_null());
    }

    #[test]
    fn by_name_and_by_id_agree_for_canonical_options() {
        // For a canonical (non-alias) option, by_name and by_id return the same row.
        let s = cstr("URL");
        // SAFETY: valid C string for the call.
        let by_name = unsafe { curl_easy_option_by_name(s.as_ptr()) };
        let by_id = curl_easy_option_by_id(CURLoption::CURLOPT_URL);
        assert_eq!(by_name, by_id);
    }
}
