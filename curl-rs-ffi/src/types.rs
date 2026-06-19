//! Shared C-ABI type definitions for the `curl-rs-ffi` crate.
//!
//! This module is the single source of truth for **every C-visible type** that
//! crosses the libcurl FFI boundary: opaque handle typedefs, `#[repr(C)]`
//! public data structs (with exact field order and padding), the small C data
//! and enum types, and the `extern "C" fn` callback typedefs.
//!
//! # Why the types live here (and are *not* re-exported from `curl-rs-lib`)
//!
//! The sibling `curl-rs-ffi/cbindgen.toml` sets `[parse] parse_deps = false`,
//! so `cbindgen` only ever sees items that are defined **within this crate**.
//! Consequently, every type that appears in any
//! `#[no_mangle] pub extern "C" fn curl_*` signature in the sibling FFI modules
//! (`easy.rs`, `multi.rs`, `global.rs`, `url.rs`, `ws.rs`, `mime.rs`,
//! `slist.rs`, `options.rs`, `header.rs`, `share.rs`, …) must be defined or
//! aliased here (the `*code` enums live in `error_codes.rs`). This keeps the
//! FFI crate compilable standalone and lets `cbindgen` emit a complete header.
//!
//! For that reason this file intentionally performs **no** `pub use
//! curl_rs_lib::…` of any C-visible type. The real Rust objects (`Easy`,
//! `Multi`, `Share`, the URL parser, …) are boxed by the implementation
//! modules and handed across the boundary as raw pointers to these opaque
//! handle types.
//!
//! # Invariants
//!
//! * This module **exports zero `curl_*` functions** — it contributes `0` to
//!   the 100-symbol `lib/libcurl.def` parity total. It contains no
//!   `#[no_mangle]`/`extern "C"` *function definitions*, only *type* and
//!   *constant* definitions.
//! * Every public struct, enum and union is `#[repr(C)]` with fields written in
//!   the exact order, name and width used by the curl 8.x public headers. Any
//!   reordering or width change is an ABI break.
//! * `curl-rs-ffi` is the only crate permitted `unsafe`; this module itself
//!   needs no `unsafe` blocks — it declares types only.
//!
//! # ABI baseline
//!
//! curl `8.19.0-DEV`, `LIBCURL_VERSION_NUM 0x081300`
//! (see `include/curl/curlver.h`). The authoritative C declarations are the
//! read-only headers under `include/curl/`; this module mirrors them exactly.

// These C type names intentionally use C `snake_case`/`SCREAMING_CASE` spelling
// (`curl_slist`, `curl_off_t`, `CURLMSG_DONE`, …). The crate root also sets this
// allow, but declaring it here keeps the module warning-free when compiled or
// linted in isolation.
#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_double, c_int, c_long, c_short, c_uchar, c_uint, c_void};
use libc::{size_t, sockaddr, time_t};

// =============================================================================
// Phase 1 — Primitive type aliases
// =============================================================================

/// The 64-bit signed file-offset / size type (`curl_off_t`).
///
/// Derived from `include/curl/system.h`: on every target in the support matrix
/// (linux `x86_64`/`aarch64`, macOS `x86_64`/`arm64` — all 64-bit unix) the C
/// `CURL_TYPEOF_CURL_OFF_T` resolves to `long`/`long long`, i.e. a 64-bit
/// signed integer, so `i64` is the exact ABI match.
pub type curl_off_t = i64;

/// The socket descriptor type (`curl_socket_t`).
///
/// On unix this is the C `int` (`include/curl/curl.h`); Windows uses `SOCKET`
/// but that platform is out of the four-target matrix for this crate.
pub type curl_socket_t = c_int;

/// Sentinel value for an invalid socket (`CURL_SOCKET_BAD`), i.e. `(-1)` on
/// unix, mirroring `include/curl/curl.h`.
pub const CURL_SOCKET_BAD: curl_socket_t = -1;

// =============================================================================
// Phase 2 — Opaque handle typedefs
// =============================================================================
//
// These mirror the C public headers, where the easy/share/multi handles are
// declared `typedef void X;` so that the implementation may place an arbitrary
// struct behind the pointer without affecting the ABI. Across FFI they are
// always used as raw pointers (`*mut CURL`, `*mut CURLM`, …); the
// implementation modules box the real Rust object and expose it via
// `Box::into_raw(..) as *mut CURL`.

/// The opaque easy-handle type (`typedef void CURL;`, `include/curl/curl.h`).
pub type CURL = c_void;

/// The opaque share-handle type (`typedef void CURLSH;`, `include/curl/curl.h`).
pub type CURLSH = c_void;

/// The opaque multi-handle type (`typedef void CURLM;`, `include/curl/multi.h`).
pub type CURLM = c_void;

/// The concrete (but opaque to C) tag struct backing the URL-API handle.
///
/// Mirrors `typedef struct Curl_URL CURLU;` in `include/curl/urlapi.h`. The
/// real URL object is boxed behind the pointer inside the FFI `url` module;
/// this zero-sized, `#[repr(C)]` marker only fixes the *pointer* ABI and makes
/// `cbindgen` emit a forward-declared opaque struct.
#[repr(C)]
pub struct Curl_URL {
    _private: [u8; 0],
}

/// The opaque URL-API handle type (`CURLU`, `include/curl/urlapi.h`).
pub type CURLU = Curl_URL;

/// Opaque MIME post container handle (`curl_mime`, `include/curl/curl.h`).
#[repr(C)]
pub struct curl_mime {
    _private: [u8; 0],
}

/// Opaque MIME part handle (`curl_mimepart`, `include/curl/curl.h`).
#[repr(C)]
pub struct curl_mimepart {
    _private: [u8; 0],
}

/// Opaque HTTP/2 server-push headers handle (`struct curl_pushheaders`,
/// `include/curl/multi.h`, used by `curl_pushheader_byname`/`bynum`).
#[repr(C)]
pub struct curl_pushheaders {
    _private: [u8; 0],
}

// --- Multi-handle poll descriptor (`struct curl_waitfd`) --------------------

/// A single descriptor to poll, passed to `curl_multi_wait` / `curl_multi_poll`
/// (as `extra_fds[]`) and filled by `curl_multi_waitfds` (`struct curl_waitfd`,
/// `include/curl/multi.h`).
///
/// The field order, names and widths mirror the C struct exactly: a
/// [`curl_socket_t`] descriptor and two `short` event bitmasks built from the
/// `CURL_WAIT_POLL*` flags below. `revents` is filled by libcurl to report which
/// events actually occurred.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct curl_waitfd {
    /// The socket / file descriptor to monitor.
    pub fd: curl_socket_t,
    /// Requested events bitmask (`CURL_WAIT_POLLIN` / `..PRI` / `..POLLOUT`).
    pub events: c_short,
    /// Returned events bitmask, filled in by libcurl.
    pub revents: c_short,
}

/// `CURL_WAIT_POLLIN` (`include/curl/multi.h`): the descriptor has data to read.
pub const CURL_WAIT_POLLIN: c_short = 0x0001;

/// `CURL_WAIT_POLLPRI` (`include/curl/multi.h`): priority data to read.
pub const CURL_WAIT_POLLPRI: c_short = 0x0002;

/// `CURL_WAIT_POLLOUT` (`include/curl/multi.h`): writing will not block.
pub const CURL_WAIT_POLLOUT: c_short = 0x0004;

// --- Multi socket-callback poll actions (`CURL_POLL_*`) ---------------------

/// `CURL_POLL_NONE` (`include/curl/multi.h`): register, not interested in
/// readiness.
pub const CURL_POLL_NONE: c_int = 0;

/// `CURL_POLL_IN` (`include/curl/multi.h`): wait for the socket to become
/// readable.
pub const CURL_POLL_IN: c_int = 1;

/// `CURL_POLL_OUT` (`include/curl/multi.h`): wait for the socket to become
/// writable.
pub const CURL_POLL_OUT: c_int = 2;

/// `CURL_POLL_INOUT` (`include/curl/multi.h`): wait for readable or writable.
pub const CURL_POLL_INOUT: c_int = 3;

/// `CURL_POLL_REMOVE` (`include/curl/multi.h`): stop monitoring the socket.
pub const CURL_POLL_REMOVE: c_int = 4;

/// `CURL_SOCKET_TIMEOUT` (`include/curl/multi.h`): the "socket" value passed to
/// `curl_multi_socket_action` to signal a timeout (an alias of
/// [`CURL_SOCKET_BAD`]).
pub const CURL_SOCKET_TIMEOUT: curl_socket_t = CURL_SOCKET_BAD;

// --- Multi socket-callback readiness bits (`CURL_CSELECT_*`) ----------------

/// `CURL_CSELECT_IN` (`include/curl/multi.h`): socket is readable
/// (`ev_bitmask`).
pub const CURL_CSELECT_IN: c_int = 0x01;

/// `CURL_CSELECT_OUT` (`include/curl/multi.h`): socket is writable
/// (`ev_bitmask`).
pub const CURL_CSELECT_OUT: c_int = 0x02;

/// `CURL_CSELECT_ERR` (`include/curl/multi.h`): socket has an error condition
/// (`ev_bitmask`).
pub const CURL_CSELECT_ERR: c_int = 0x04;

// --- HTTP/2 server-push callback return values (`CURL_PUSH_*`) --------------

/// `CURL_PUSH_OK` (`include/curl/multi.h`): accept the pushed stream.
pub const CURL_PUSH_OK: c_int = 0;

/// `CURL_PUSH_DENY` (`include/curl/multi.h`): reject the pushed stream.
pub const CURL_PUSH_DENY: c_int = 1;

/// `CURL_PUSH_ERROROUT` (`include/curl/multi.h`): fail the whole connection.
pub const CURL_PUSH_ERROROUT: c_int = 2;

// --- Multi notification kinds (`CURLMNOTIFY_*`) -----------------------------

/// `CURLMNOTIFY_INFO_READ` (`include/curl/multi.h`): a message became readable
/// via `curl_multi_info_read`.
pub const CURLMNOTIFY_INFO_READ: c_uint = 0;

/// `CURLMNOTIFY_EASY_DONE` (`include/curl/multi.h`): an easy handle finished.
pub const CURLMNOTIFY_EASY_DONE: c_uint = 1;

// --- Legacy pipelining bitmask (`CURLPIPE_*`, `CURLMOPT_PIPELINING`) --------

/// `CURLPIPE_NOTHING` (`include/curl/multi.h`): no multiplexing.
pub const CURLPIPE_NOTHING: c_long = 0;

/// `CURLPIPE_HTTP1` (`include/curl/multi.h`): legacy HTTP/1 pipelining (inert).
pub const CURLPIPE_HTTP1: c_long = 1;

/// `CURLPIPE_MULTIPLEX` (`include/curl/multi.h`): enable HTTP/2+ multiplexing.
pub const CURLPIPE_MULTIPLEX: c_long = 2;

// =============================================================================
// Phase 3 — Integer tag aliases for the large option/info enums
// =============================================================================
//
// curl's `CURLoption`, `CURLINFO`, `CURLMoption`, … are enormous C enums. The
// curated `include/curl/curl.h` is the authoritative header (the `cbindgen`
// output is written to `OUT_DIR` and never overwrites it), so this crate does
// not re-declare those 300+ values. C enums are `int`-sized and every curl
// option/info value is positive and fits in `c_int`, so an ABI-compatible
// transparent integer alias is exact. The variadic `setopt`/`getinfo` shims map
// these ints to the typed enums owned by `curl-rs-lib::{options, getinfo}`.

/// ABI-compatible `int` alias for `CURLoption`.
///
/// The typed enumeration is owned by `curl-rs-lib::options` and the variadic
/// `curl_easy_setopt` shim maps this int to it. The full enumeration lives in
/// the curated `include/curl/curl.h`.
pub type CURLoption = c_int;

/// ABI-compatible `int` alias for `CURLINFO`.
///
/// The typed enumeration is owned by `curl-rs-lib::getinfo` and the variadic
/// `curl_easy_getinfo` shim maps this int to it. The full enumeration lives in
/// the curated `include/curl/curl.h`.
pub type CURLINFO = c_int;

/// ABI-compatible `int` alias for `CURLMoption`.
///
/// The typed enumeration is owned by `curl-rs-lib` and the variadic
/// `curl_multi_setopt` shim maps this int to it. The full enumeration lives in
/// the curated `include/curl/multi.h`.
pub type CURLMoption = c_int;

/// ABI-compatible `int` alias for `CURLMinfo_offt` (used by
/// `curl_multi_get_offt`; values `CURLMINFO_NONE = 0` …
/// `CURLMINFO_XFERS_ADDED = 5`). The typed enumeration is owned by
/// `curl-rs-lib::multi` ([`curl_rs_lib::multi::CurlMInfo`]) and the
/// `curl_multi_get_offt` shim maps this int to it; the full enumeration lives in
/// the curated `include/curl/multi.h`. C enums are `int`-sized, so the alias is
/// an exact ABI match.
pub type CURLMinfo_offt = c_int;

/// ABI-compatible `int` alias for `CURLformoption` (used by `curl_forms.option`
/// and `curl_formadd`). The full enumeration lives in the curated
/// `include/curl/curl.h`.
pub type CURLformoption = c_int;

/// ABI-compatible `int` alias for `CURLUPart` (used by `curl_url_get`/`set`;
/// values `CURLUPART_URL = 0` … `CURLUPART_ZONEID`). The typed enumeration may
/// also be modeled in `curl-rs-lib`'s URL module; the full enumeration lives in
/// the curated `include/curl/urlapi.h`.
pub type CURLUPart = c_int;

/// ABI-compatible `int` alias for `CURLSHoption` (used by `curl_share_setopt`).
/// The full enumeration lives in the curated `include/curl/curl.h`.
pub type CURLSHoption = c_int;

// =============================================================================
// Phase 4 — `#[repr(C)]` public data structs, C enums and bit constants
// =============================================================================

/// A single node of a libcurl string list (`struct curl_slist`,
/// `include/curl/curl.h`). Built/consumed by `curl_slist_append` and friends.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct curl_slist {
    /// The null-terminated string payload owned by this node.
    pub data: *mut c_char,
    /// The next node, or null at the end of the list.
    pub next: *mut curl_slist,
}

// --- HTTP POST form (legacy `curl_formadd` API) ----------------------------

/// Specified content is a filename. (`CURL_HTTPPOST_FILENAME`)
pub const CURL_HTTPPOST_FILENAME: c_long = 1 << 0;
/// Specified content is the name of a file to read. (`CURL_HTTPPOST_READFILE`)
pub const CURL_HTTPPOST_READFILE: c_long = 1 << 1;
/// `name` is only a stored pointer; do not free in `curl_formfree`.
/// (`CURL_HTTPPOST_PTRNAME`)
pub const CURL_HTTPPOST_PTRNAME: c_long = 1 << 2;
/// `contents` is only a stored pointer; do not free in `curl_formfree`.
/// (`CURL_HTTPPOST_PTRCONTENTS`)
pub const CURL_HTTPPOST_PTRCONTENTS: c_long = 1 << 3;
/// Upload file from the in-memory buffer. (`CURL_HTTPPOST_BUFFER`)
pub const CURL_HTTPPOST_BUFFER: c_long = 1 << 4;
/// Upload file from pointer contents. (`CURL_HTTPPOST_PTRBUFFER`)
pub const CURL_HTTPPOST_PTRBUFFER: c_long = 1 << 5;
/// Upload file contents via the read callback. (`CURL_HTTPPOST_CALLBACK`)
pub const CURL_HTTPPOST_CALLBACK: c_long = 1 << 6;
/// Use the size in `contentlen` (added in 7.46.0). (`CURL_HTTPPOST_LARGE`)
pub const CURL_HTTPPOST_LARGE: c_long = 1 << 7;

/// A single HTTP multipart/form-data field (`struct curl_httppost`,
/// `include/curl/curl.h`). Field order, names and widths must match the header
/// exactly; this struct is part of the legacy `curl_formadd`/`curl_formget`
/// ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct curl_httppost {
    /// Next entry in the list.
    pub next: *mut curl_httppost,
    /// Pointer to the allocated name.
    pub name: *mut c_char,
    /// Length of the name.
    pub namelength: c_long,
    /// Pointer to the allocated data contents.
    pub contents: *mut c_char,
    /// Length of the contents field (see also `CURL_HTTPPOST_LARGE`).
    pub contentslength: c_long,
    /// Pointer to allocated buffer contents.
    pub buffer: *mut c_char,
    /// Length of the buffer field.
    pub bufferlength: c_long,
    /// `Content-Type` of this part.
    pub contenttype: *mut c_char,
    /// List of extra headers for this form.
    pub contentheader: *mut curl_slist,
    /// If one field name has more than one file, this links to following files.
    pub more: *mut curl_httppost,
    /// Bitmask of the `CURL_HTTPPOST_*` flags defined above.
    pub flags: c_long,
    /// The filename to show; if unset the actual filename is used.
    pub showfilename: *mut c_char,
    /// Custom pointer used for `CURL_HTTPPOST_CALLBACK` posts.
    pub userp: *mut c_void,
    /// Alternative length of contents, used when `CURL_HTTPPOST_LARGE` is set.
    pub contentlen: curl_off_t,
}

/// One entry in the `curl_forms` array passed to `curl_formadd`
/// (`struct curl_forms`, `include/curl/curl.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct curl_forms {
    /// The form option selector.
    pub option: CURLformoption,
    /// The value associated with `option`.
    pub value: *const c_char,
}

// --- FTP wildcard file information -----------------------------------------

/// Enumeration of file types reported during FTP wildcard matching
/// (`curlfiletype`, `include/curl/curl.h`).
///
/// Note: this curl revision has no `CURLFILETYPE_ERROR`; the final variant is
/// `CURLFILETYPE_UNKNOWN`, matching the header exactly.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum curlfiletype {
    /// A regular file.
    CURLFILETYPE_FILE = 0,
    /// A directory.
    CURLFILETYPE_DIRECTORY,
    /// A symbolic link.
    CURLFILETYPE_SYMLINK,
    /// A block device.
    CURLFILETYPE_DEVICE_BLOCK,
    /// A character device.
    CURLFILETYPE_DEVICE_CHAR,
    /// A named pipe (FIFO).
    CURLFILETYPE_NAMEDPIPE,
    /// A socket.
    CURLFILETYPE_SOCKET,
    /// A door (Solaris only).
    CURLFILETYPE_DOOR,
    /// Unknown type — should never occur.
    CURLFILETYPE_UNKNOWN,
}

/// The `filename` field is known. (`CURLFINFOFLAG_KNOWN_FILENAME`)
pub const CURLFINFOFLAG_KNOWN_FILENAME: c_uint = 1 << 0;
/// The `filetype` field is known. (`CURLFINFOFLAG_KNOWN_FILETYPE`)
pub const CURLFINFOFLAG_KNOWN_FILETYPE: c_uint = 1 << 1;
/// The `time` field is known. (`CURLFINFOFLAG_KNOWN_TIME`)
pub const CURLFINFOFLAG_KNOWN_TIME: c_uint = 1 << 2;
/// The `perm` field is known. (`CURLFINFOFLAG_KNOWN_PERM`)
pub const CURLFINFOFLAG_KNOWN_PERM: c_uint = 1 << 3;
/// The `uid` field is known. (`CURLFINFOFLAG_KNOWN_UID`)
pub const CURLFINFOFLAG_KNOWN_UID: c_uint = 1 << 4;
/// The `gid` field is known. (`CURLFINFOFLAG_KNOWN_GID`)
pub const CURLFINFOFLAG_KNOWN_GID: c_uint = 1 << 5;
/// The `size` field is known. (`CURLFINFOFLAG_KNOWN_SIZE`)
pub const CURLFINFOFLAG_KNOWN_SIZE: c_uint = 1 << 6;
/// The `hardlinks` field is known. (`CURLFINFOFLAG_KNOWN_HLINKCOUNT`)
pub const CURLFINFOFLAG_KNOWN_HLINKCOUNT: c_uint = 1 << 7;

/// The nested `strings` sub-struct of [`curl_fileinfo`]. Each non-null pointer
/// points into the parent's `b_data` buffer (`include/curl/curl.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct curl_fileinfo_strings {
    /// Raw textual modification time.
    pub time: *mut c_char,
    /// Raw textual permission string.
    pub perm: *mut c_char,
    /// Owning user name.
    pub user: *mut c_char,
    /// Owning group name.
    pub group: *mut c_char,
    /// Target filename of a symlink.
    pub target: *mut c_char,
}

/// Information about a single file, used during FTP wildcard matching
/// (`struct curl_fileinfo`, `include/curl/curl.h`). Field order and widths must
/// match the header exactly.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct curl_fileinfo {
    /// The file name.
    pub filename: *mut c_char,
    /// The file type.
    pub filetype: curlfiletype,
    /// Modification time (always zero in this revision).
    pub time: time_t,
    /// Permission bits.
    pub perm: c_uint,
    /// Owning user id.
    pub uid: c_int,
    /// Owning group id.
    pub gid: c_int,
    /// File size in bytes.
    pub size: curl_off_t,
    /// Number of hard links.
    pub hardlinks: c_long,
    /// The decoded textual sub-fields (each may point into `b_data`).
    pub strings: curl_fileinfo_strings,
    /// Bitmask of the `CURLFINFOFLAG_KNOWN_*` flags.
    pub flags: c_uint,
    /// libcurl-private backing buffer — never interfere with these fields.
    pub b_data: *mut c_char,
    /// Size of the `b_data` buffer.
    pub b_size: size_t,
    /// Used bytes of the `b_data` buffer.
    pub b_used: size_t,
}

// --- Version information ----------------------------------------------------

/// The `age` discriminant of [`curl_version_info_data`] (`CURLversion`,
/// `include/curl/curl.h`). Each value marks the struct revision in which the
/// trailing fields became valid.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CURLversion {
    /// 7.10.
    CURLVERSION_FIRST = 0,
    /// 7.11.1.
    CURLVERSION_SECOND,
    /// 7.12.0.
    CURLVERSION_THIRD,
    /// 7.16.1.
    CURLVERSION_FOURTH,
    /// 7.57.0.
    CURLVERSION_FIFTH,
    /// 7.66.0.
    CURLVERSION_SIXTH,
    /// 7.70.0.
    CURLVERSION_SEVENTH,
    /// 7.72.0.
    CURLVERSION_EIGHTH,
    /// 7.75.0.
    CURLVERSION_NINTH,
    /// 7.77.0.
    CURLVERSION_TENTH,
    /// 7.87.0.
    CURLVERSION_ELEVENTH,
    /// 8.8.0.
    CURLVERSION_TWELFTH,
    /// Never actually used.
    CURLVERSION_LAST,
}

/// IPv6-enabled. (`CURL_VERSION_IPV6`)
pub const CURL_VERSION_IPV6: c_int = 1 << 0;
/// Kerberos V4 auth is supported (deprecated). (`CURL_VERSION_KERBEROS4`)
pub const CURL_VERSION_KERBEROS4: c_int = 1 << 1;
/// SSL options are present. (`CURL_VERSION_SSL`)
pub const CURL_VERSION_SSL: c_int = 1 << 2;
/// libz features are present. (`CURL_VERSION_LIBZ`)
pub const CURL_VERSION_LIBZ: c_int = 1 << 3;
/// NTLM auth is supported. (`CURL_VERSION_NTLM`)
pub const CURL_VERSION_NTLM: c_int = 1 << 4;
/// Negotiate auth is supported. (`CURL_VERSION_GSSNEGOTIATE`)
pub const CURL_VERSION_GSSNEGOTIATE: c_int = 1 << 5;
/// Built with debug capabilities. (`CURL_VERSION_DEBUG`)
pub const CURL_VERSION_DEBUG: c_int = 1 << 6;
/// Asynchronous DNS resolves. (`CURL_VERSION_ASYNCHDNS`)
pub const CURL_VERSION_ASYNCHDNS: c_int = 1 << 7;
/// SPNEGO auth is supported. (`CURL_VERSION_SPNEGO`)
pub const CURL_VERSION_SPNEGO: c_int = 1 << 8;
/// Supports files larger than 2GB. (`CURL_VERSION_LARGEFILE`)
pub const CURL_VERSION_LARGEFILE: c_int = 1 << 9;
/// Internationalized Domain Names are supported. (`CURL_VERSION_IDN`)
pub const CURL_VERSION_IDN: c_int = 1 << 10;
/// Built against Windows SSPI. (`CURL_VERSION_SSPI`)
pub const CURL_VERSION_SSPI: c_int = 1 << 11;
/// Character conversions supported. (`CURL_VERSION_CONV`)
pub const CURL_VERSION_CONV: c_int = 1 << 12;
/// Debug memory tracking supported. (`CURL_VERSION_CURLDEBUG`)
pub const CURL_VERSION_CURLDEBUG: c_int = 1 << 13;
/// TLS-SRP auth is supported. (`CURL_VERSION_TLSAUTH_SRP`)
pub const CURL_VERSION_TLSAUTH_SRP: c_int = 1 << 14;
/// NTLM delegation to winbind helper is supported. (`CURL_VERSION_NTLM_WB`)
pub const CURL_VERSION_NTLM_WB: c_int = 1 << 15;
/// HTTP/2 support is built-in. (`CURL_VERSION_HTTP2`)
pub const CURL_VERSION_HTTP2: c_int = 1 << 16;
/// Built against a GSS-API library. (`CURL_VERSION_GSSAPI`)
pub const CURL_VERSION_GSSAPI: c_int = 1 << 17;
/// Kerberos V5 auth is supported. (`CURL_VERSION_KERBEROS5`)
pub const CURL_VERSION_KERBEROS5: c_int = 1 << 18;
/// Unix domain sockets support. (`CURL_VERSION_UNIX_SOCKETS`)
pub const CURL_VERSION_UNIX_SOCKETS: c_int = 1 << 19;
/// Mozilla's Public Suffix List is used. (`CURL_VERSION_PSL`)
pub const CURL_VERSION_PSL: c_int = 1 << 20;
/// HTTPS-proxy support is built-in. (`CURL_VERSION_HTTPS_PROXY`)
pub const CURL_VERSION_HTTPS_PROXY: c_int = 1 << 21;
/// Multiple SSL backends are available. (`CURL_VERSION_MULTI_SSL`)
pub const CURL_VERSION_MULTI_SSL: c_int = 1 << 22;
/// Brotli features are present. (`CURL_VERSION_BROTLI`)
pub const CURL_VERSION_BROTLI: c_int = 1 << 23;
/// Alt-Svc handling is built-in. (`CURL_VERSION_ALTSVC`)
pub const CURL_VERSION_ALTSVC: c_int = 1 << 24;
/// HTTP/3 support is built-in. (`CURL_VERSION_HTTP3`)
pub const CURL_VERSION_HTTP3: c_int = 1 << 25;
/// zstd features are present. (`CURL_VERSION_ZSTD`)
pub const CURL_VERSION_ZSTD: c_int = 1 << 26;
/// Unicode support on Windows. (`CURL_VERSION_UNICODE`)
pub const CURL_VERSION_UNICODE: c_int = 1 << 27;
/// HSTS is supported. (`CURL_VERSION_HSTS`)
pub const CURL_VERSION_HSTS: c_int = 1 << 28;
/// libgsasl is supported. (`CURL_VERSION_GSASL`)
pub const CURL_VERSION_GSASL: c_int = 1 << 29;
/// The libcurl API is thread-safe. (`CURL_VERSION_THREADSAFE`)
pub const CURL_VERSION_THREADSAFE: c_int = 1 << 30;

/// The full version/feature report returned by `curl_version_info`
/// (`struct curl_version_info_data`, `include/curl/curl.h`).
///
/// All fields through `CURLVERSION_TWELFTH` are included in the exact header
/// order; consumers gate access on the `age` field. `protocols` and
/// `feature_names` are NULL-terminated arrays of C strings (a pointer to a
/// constant array of constant `char *`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct curl_version_info_data {
    /// Age of the returned struct (which trailing fields are valid).
    pub age: CURLversion,
    /// `LIBCURL_VERSION` human-readable string.
    pub version: *const c_char,
    /// `LIBCURL_VERSION_NUM` numeric version.
    pub version_num: c_uint,
    /// OS/host/cpu/machine string when configured.
    pub host: *const c_char,
    /// Feature bitmask — see the `CURL_VERSION_*` constants.
    pub features: c_int,
    /// SSL backend human-readable version string.
    pub ssl_version: *const c_char,
    /// Unused; always 0.
    pub ssl_version_num: c_long,
    /// libz human-readable version string.
    pub libz_version: *const c_char,
    /// NULL-terminated array of supported protocol names.
    pub protocols: *const *const c_char,
    // Added in CURLVERSION_SECOND.
    /// c-ares human-readable version string.
    pub ares: *const c_char,
    /// c-ares numeric version.
    pub ares_num: c_int,
    // Added in CURLVERSION_THIRD.
    /// libidn human-readable version string.
    pub libidn: *const c_char,
    // Added in CURLVERSION_FOURTH.
    /// iconv numeric version (same as `_libiconv_version` when built with it).
    pub iconv_ver_num: c_int,
    /// libssh human-readable version string.
    pub libssh_version: *const c_char,
    // Added in CURLVERSION_FIFTH.
    /// Brotli numeric version `(MAJOR << 24) | (MINOR << 12) | PATCH`.
    pub brotli_ver_num: c_uint,
    /// Brotli human-readable version string.
    pub brotli_version: *const c_char,
    // Added in CURLVERSION_SIXTH.
    /// nghttp2 numeric version `(MAJOR << 16) | (MINOR << 8) | PATCH`.
    pub nghttp2_ver_num: c_uint,
    /// nghttp2 human-readable version string.
    pub nghttp2_version: *const c_char,
    /// QUIC (+ HTTP/3) library human-readable version, or NULL.
    pub quic_version: *const c_char,
    // Added in CURLVERSION_SEVENTH.
    /// Built-in default `CURLOPT_CAINFO`, possibly NULL.
    pub cainfo: *const c_char,
    /// Built-in default `CURLOPT_CAPATH`, possibly NULL.
    pub capath: *const c_char,
    // Added in CURLVERSION_EIGHTH.
    /// Zstd numeric version `(MAJOR << 24) | (MINOR << 12) | PATCH`.
    pub zstd_ver_num: c_uint,
    /// Zstd human-readable version string.
    pub zstd_version: *const c_char,
    // Added in CURLVERSION_NINTH.
    /// Hyper human-readable version string.
    pub hyper_version: *const c_char,
    // Added in CURLVERSION_TENTH.
    /// gsasl human-readable version string.
    pub gsasl_version: *const c_char,
    // Added in CURLVERSION_ELEVENTH.
    /// NULL-terminated array of supported feature names.
    pub feature_names: *const *const c_char,
    // Added in CURLVERSION_TWELFTH.
    /// RTMP human-readable version string.
    pub rtmp_version: *const c_char,
}

/// The address descriptor handed to the open-socket callback
/// (`struct curl_sockaddr`, `include/curl/curl.h`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct curl_sockaddr {
    /// Address family (`AF_*`).
    pub family: c_int,
    /// Socket type (`SOCK_*`).
    pub socktype: c_int,
    /// Protocol.
    pub protocol: c_int,
    /// Length of `addr` (was a `socklen_t` before 7.18.0).
    pub addrlen: c_uint,
    /// The platform socket address.
    pub addr: sockaddr,
}

// --- Binary blob option value ----------------------------------------------

/// Tell libcurl to copy the blob data. (`CURL_BLOB_COPY`)
pub const CURL_BLOB_COPY: c_uint = 1;
/// Tell libcurl to NOT copy the blob data. (`CURL_BLOB_NOCOPY`)
pub const CURL_BLOB_NOCOPY: c_uint = 0;

/// A binary object passed to the `*_BLOB` options (`struct curl_blob`,
/// `include/curl/easy.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct curl_blob {
    /// Pointer to the data.
    pub data: *mut c_void,
    /// Length of the data in bytes.
    pub len: size_t,
    /// Bit 0 is `CURL_BLOB_COPY`; the rest are reserved and must be zero.
    pub flags: c_uint,
}

// --- WebSockets -------------------------------------------------------------

/// Frame carries text data. (`CURLWS_TEXT`)
pub const CURLWS_TEXT: c_int = 1 << 0;
/// Frame carries binary data. (`CURLWS_BINARY`)
pub const CURLWS_BINARY: c_int = 1 << 1;
/// Frame is a continuation of a fragmented message. (`CURLWS_CONT`)
pub const CURLWS_CONT: c_int = 1 << 2;
/// Close frame. (`CURLWS_CLOSE`)
pub const CURLWS_CLOSE: c_int = 1 << 3;
/// Ping frame. (`CURLWS_PING`)
pub const CURLWS_PING: c_int = 1 << 4;
/// The data carries an offset into the frame. (`CURLWS_OFFSET`)
pub const CURLWS_OFFSET: c_int = 1 << 5;
/// Pong frame. (`CURLWS_PONG`)
pub const CURLWS_PONG: c_int = 1 << 6;

/// `CURLOPT_WS_OPTIONS`: deliver raw frames without libcurl processing.
/// (`CURLWS_RAW_MODE`)
pub const CURLWS_RAW_MODE: c_long = 1 << 0;
/// `CURLOPT_WS_OPTIONS`: disable automatic PONG replies to PINGs.
/// (`CURLWS_NOAUTOPONG`)
pub const CURLWS_NOAUTOPONG: c_long = 1 << 1;

/// Metadata describing a received WebSocket frame
/// (`struct curl_ws_frame`, `include/curl/websockets.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct curl_ws_frame {
    /// Struct age — currently always zero.
    pub age: c_int,
    /// Bitmask of the `CURLWS_*` frame flags.
    pub flags: c_int,
    /// Offset of this data chunk into the frame.
    pub offset: curl_off_t,
    /// Number of payload bytes still pending after this chunk.
    pub bytesleft: curl_off_t,
    /// Size of the current data chunk.
    pub len: size_t,
}

// --- HTTP header access (`curl_easy_header`) -------------------------------

/// A plain server header. (`CURLH_HEADER`)
pub const CURLH_HEADER: c_uint = 1 << 0;
/// A trailer. (`CURLH_TRAILER`)
pub const CURLH_TRAILER: c_uint = 1 << 1;
/// A `CONNECT` header. (`CURLH_CONNECT`)
pub const CURLH_CONNECT: c_uint = 1 << 2;
/// A `1xx` informational header. (`CURLH_1XX`)
pub const CURLH_1XX: c_uint = 1 << 3;
/// A pseudo header. (`CURLH_PSEUDO`)
pub const CURLH_PSEUDO: c_uint = 1 << 4;

/// A single header exposed by `curl_easy_header`/`curl_easy_nextheader`
/// (`struct curl_header`, `include/curl/header.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct curl_header {
    /// Header name (case may differ from the wire).
    pub name: *mut c_char,
    /// Header value.
    pub value: *mut c_char,
    /// Number of headers using this name.
    pub amount: size_t,
    /// Zero-based index of this instance among same-named headers.
    pub index: size_t,
    /// Bitmask of `CURLH_*` origin flags.
    pub origin: c_uint,
    /// Handle used privately by libcurl.
    pub anchor: *mut c_void,
}

// --- Option metadata (`curl_easy_option_*`) --------------------------------

/// The data type carried by an easy option (`curl_easytype`,
/// `include/curl/options.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum curl_easytype {
    /// `long` (a range of values).
    CURLOT_LONG = 0,
    /// `long` (a defined set or bitmask).
    CURLOT_VALUES,
    /// `curl_off_t` (a range of values).
    CURLOT_OFF_T,
    /// `void *` object pointer.
    CURLOT_OBJECT,
    /// `char *` to a null-terminated buffer.
    CURLOT_STRING,
    /// `struct curl_slist *`.
    CURLOT_SLIST,
    /// `void *` passed as-is to a callback.
    CURLOT_CBPTR,
    /// `struct curl_blob *`.
    CURLOT_BLOB,
    /// Function pointer.
    CURLOT_FUNCTION,
}

/// The option is an alias for another option. (`CURLOT_FLAG_ALIAS`)
pub const CURLOT_FLAG_ALIAS: c_uint = 1 << 0;

/// Metadata describing one libcurl easy option, returned by
/// `curl_easy_option_by_*` (`struct curl_easyoption`,
/// `include/curl/options.h`).
///
/// The C field named `type` is a Rust keyword, so it is written here using the
/// raw identifier `r#type`; `cbindgen` strips the `r#` and emits `type`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct curl_easyoption {
    /// The option name (e.g. `"URL"`).
    pub name: *const c_char,
    /// The `CURLOPT_*` identifier.
    pub id: CURLoption,
    /// The option's data type.
    pub r#type: curl_easytype,
    /// Bitmask of `CURLOT_FLAG_*` flags.
    pub flags: c_uint,
}

// --- Multi-handle messages --------------------------------------------------

/// The kind of a [`CURLMsg`] (`CURLMSG`, `include/curl/multi.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CURLMSG {
    /// First, not used.
    CURLMSG_NONE = 0,
    /// This easy handle has completed; `data.result` holds the `CURLcode`.
    CURLMSG_DONE,
    /// Last, not used.
    CURLMSG_LAST,
}

/// The payload union of [`CURLMsg`] (`union` inside `struct CURLMsg`,
/// `include/curl/multi.h`).
///
/// In C the active member for `CURLMSG_DONE` is `CURLcode result`. The real
/// `CURLcode` enum is owned by `error_codes.rs`; to keep this module free of a
/// cyclic/cross-module type reference it is stored here as the equivalent
/// `i32` integer (C enums are `int`-sized, so the layout is identical).
#[repr(C)]
#[derive(Clone, Copy)]
pub union CURLMsg_data {
    /// Message-specific data pointer.
    pub whatever: *mut c_void,
    /// Transfer return code as its `CURLcode` integer value.
    pub result: i32,
}

/// A message read from a multi handle via `curl_multi_info_read`
/// (`struct CURLMsg`, `include/curl/multi.h`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CURLMsg {
    /// What this message means.
    pub msg: CURLMSG,
    /// The easy handle the message concerns.
    pub easy_handle: *mut CURL,
    /// Message-specific payload.
    pub data: CURLMsg_data,
}

// --- SSL backend selection (`curl_global_sslset`) --------------------------

/// The set of TLS backends libcurl can be built against (`curl_sslbackend`,
/// `include/curl/curl.h`). The discriminants are explicit and fixed by the
/// ABI; this Rust rewrite reports `CURLSSLBACKEND_RUSTLS` (= 14) as active.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum curl_sslbackend {
    /// No backend.
    CURLSSLBACKEND_NONE = 0,
    /// OpenSSL (and the AWS-LC/BoringSSL/LibreSSL clones).
    CURLSSLBACKEND_OPENSSL = 1,
    /// GnuTLS.
    CURLSSLBACKEND_GNUTLS = 2,
    /// NSS (deprecated).
    CURLSSLBACKEND_NSS = 3,
    /// Obsolete slot 4 (was QSOSSL).
    CURLSSLBACKEND_OBSOLETE4 = 4,
    /// GSKit (deprecated).
    CURLSSLBACKEND_GSKIT = 5,
    /// PolarSSL (deprecated).
    CURLSSLBACKEND_POLARSSL = 6,
    /// wolfSSL.
    CURLSSLBACKEND_WOLFSSL = 7,
    /// Schannel.
    CURLSSLBACKEND_SCHANNEL = 8,
    /// Secure Transport (deprecated).
    CURLSSLBACKEND_SECURETRANSPORT = 9,
    /// axTLS (deprecated).
    CURLSSLBACKEND_AXTLS = 10,
    /// mbedTLS.
    CURLSSLBACKEND_MBEDTLS = 11,
    /// MesaLink (deprecated).
    CURLSSLBACKEND_MESALINK = 12,
    /// BearSSL (deprecated).
    CURLSSLBACKEND_BEARSSL = 13,
    /// Rustls — the backend this rewrite uses exclusively.
    CURLSSLBACKEND_RUSTLS = 14,
}

/// One available SSL backend, as reported by `curl_global_sslset`
/// (`struct curl_ssl_backend`, `include/curl/curl.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct curl_ssl_backend {
    /// The backend identifier.
    pub id: curl_sslbackend,
    /// The backend's human-readable name.
    pub name: *const c_char,
}

// --- Auxiliary C enums referenced by callbacks -----------------------------

/// Return codes for the I/O-control callback (`curlioerr`,
/// `include/curl/curl.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum curlioerr {
    /// I/O operation successful.
    CURLIOE_OK = 0,
    /// Command was unknown to the callback.
    CURLIOE_UNKNOWNCMD,
    /// Failed to restart the read.
    CURLIOE_FAILRESTART,
    /// Never used.
    CURLIOE_LAST,
}

/// Commands passed to the I/O-control callback (`curliocmd`,
/// `include/curl/curl.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum curliocmd {
    /// No operation.
    CURLIOCMD_NOP = 0,
    /// Restart the read stream from the start.
    CURLIOCMD_RESTARTREAD,
    /// Never used.
    CURLIOCMD_LAST,
}

/// The purpose of a socket passed to the socket-option/open-socket callbacks
/// (`curlsocktype`, `include/curl/curl.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum curlsocktype {
    /// Socket created for a specific IP connection.
    CURLSOCKTYPE_IPCXN = 0,
    /// Socket created by an `accept()` call.
    CURLSOCKTYPE_ACCEPT,
    /// Never used.
    CURLSOCKTYPE_LAST,
}

/// The kind of data passed to the debug/information callback (`curl_infotype`,
/// `include/curl/curl.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum curl_infotype {
    /// Informational text.
    CURLINFO_TEXT = 0,
    /// Incoming header.
    CURLINFO_HEADER_IN,
    /// Outgoing header.
    CURLINFO_HEADER_OUT,
    /// Incoming data.
    CURLINFO_DATA_IN,
    /// Outgoing data.
    CURLINFO_DATA_OUT,
    /// Incoming SSL/TLS data.
    CURLINFO_SSL_DATA_IN,
    /// Outgoing SSL/TLS data.
    CURLINFO_SSL_DATA_OUT,
    /// Marker for the end of the enum.
    CURLINFO_END,
}

// --- Share-handle locking ---------------------------------------------------

/// The piece of shared data a lock guards (`curl_lock_data`,
/// `include/curl/curl.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum curl_lock_data {
    /// Unspecified.
    CURL_LOCK_DATA_NONE = 0,
    /// The share object's own internal state.
    CURL_LOCK_DATA_SHARE,
    /// The cookie store.
    CURL_LOCK_DATA_COOKIE,
    /// The DNS cache.
    CURL_LOCK_DATA_DNS,
    /// The TLS session cache.
    CURL_LOCK_DATA_SSL_SESSION,
    /// The connection cache.
    CURL_LOCK_DATA_CONNECT,
    /// The Public Suffix List data.
    CURL_LOCK_DATA_PSL,
    /// The HSTS cache.
    CURL_LOCK_DATA_HSTS,
    /// Never used.
    CURL_LOCK_DATA_LAST,
}

/// The access mode requested by a share lock (`curl_lock_access`,
/// `include/curl/curl.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum curl_lock_access {
    /// Unspecified action.
    CURL_LOCK_ACCESS_NONE = 0,
    /// Shared (read) access.
    CURL_LOCK_ACCESS_SHARED = 1,
    /// Single (write) access.
    CURL_LOCK_ACCESS_SINGLE = 2,
    /// Never used.
    CURL_LOCK_ACCESS_LAST,
}

// =============================================================================
// Phase 5 — `extern "C" fn` callback typedefs
// =============================================================================
//
// Each callback is modeled as `Option<unsafe extern "C" fn(...) -> Ret>` so
// that a NULL function pointer is representable (matching C, where every one of
// these is nullable) while still being ABI-identical to a bare function pointer
// thanks to the null-pointer optimization. The argument and return types are
// transcribed exactly from `include/curl/curl.h`.

/// `CURLOPT_PROGRESSFUNCTION` callback (`curl_progress_callback`).
pub type curl_progress_callback = Option<
    unsafe extern "C" fn(
        clientp: *mut c_void,
        dltotal: c_double,
        dlnow: c_double,
        ultotal: c_double,
        ulnow: c_double,
    ) -> c_int,
>;

/// `CURLOPT_XFERINFOFUNCTION` callback (`curl_xferinfo_callback`).
pub type curl_xferinfo_callback = Option<
    unsafe extern "C" fn(
        clientp: *mut c_void,
        dltotal: curl_off_t,
        dlnow: curl_off_t,
        ultotal: curl_off_t,
        ulnow: curl_off_t,
    ) -> c_int,
>;

/// `CURLOPT_WRITEFUNCTION` callback (`curl_write_callback`).
pub type curl_write_callback = Option<
    unsafe extern "C" fn(
        buffer: *mut c_char,
        size: size_t,
        nitems: size_t,
        outstream: *mut c_void,
    ) -> size_t,
>;

/// `CURLOPT_READFUNCTION` callback (`curl_read_callback`).
pub type curl_read_callback = Option<
    unsafe extern "C" fn(
        buffer: *mut c_char,
        size: size_t,
        nitems: size_t,
        instream: *mut c_void,
    ) -> size_t,
>;

/// `CURLOPT_RESOLVER_START_FUNCTION` callback (`curl_resolver_start_callback`).
pub type curl_resolver_start_callback = Option<
    unsafe extern "C" fn(
        resolver_state: *mut c_void,
        reserved: *mut c_void,
        userdata: *mut c_void,
    ) -> c_int,
>;

/// `CURLOPT_CHUNK_BGN_FUNCTION` callback (`curl_chunk_bgn_callback`).
pub type curl_chunk_bgn_callback = Option<
    unsafe extern "C" fn(transfer_info: *const c_void, ptr: *mut c_void, remains: c_int) -> c_long,
>;

/// `CURLOPT_CHUNK_END_FUNCTION` callback (`curl_chunk_end_callback`).
pub type curl_chunk_end_callback = Option<unsafe extern "C" fn(ptr: *mut c_void) -> c_long>;

/// `CURLOPT_FNMATCH_FUNCTION` callback (`curl_fnmatch_callback`).
pub type curl_fnmatch_callback = Option<
    unsafe extern "C" fn(ptr: *mut c_void, pattern: *const c_char, string: *const c_char) -> c_int,
>;

/// `CURLOPT_SEEKFUNCTION` callback (`curl_seek_callback`).
pub type curl_seek_callback =
    Option<unsafe extern "C" fn(instream: *mut c_void, offset: curl_off_t, origin: c_int) -> c_int>;

/// `CURLOPT_TRAILERFUNCTION` callback (`curl_trailer_callback`).
pub type curl_trailer_callback =
    Option<unsafe extern "C" fn(list: *mut *mut curl_slist, userdata: *mut c_void) -> c_int>;

/// `CURLOPT_SOCKOPTFUNCTION` callback (`curl_sockopt_callback`).
pub type curl_sockopt_callback = Option<
    unsafe extern "C" fn(
        clientp: *mut c_void,
        curlfd: curl_socket_t,
        purpose: curlsocktype,
    ) -> c_int,
>;

/// `CURLOPT_OPENSOCKETFUNCTION` callback (`curl_opensocket_callback`).
pub type curl_opensocket_callback = Option<
    unsafe extern "C" fn(
        clientp: *mut c_void,
        purpose: curlsocktype,
        address: *mut curl_sockaddr,
    ) -> curl_socket_t,
>;

/// `CURLOPT_CLOSESOCKETFUNCTION` callback (`curl_closesocket_callback`).
pub type curl_closesocket_callback =
    Option<unsafe extern "C" fn(clientp: *mut c_void, item: curl_socket_t) -> c_int>;

/// `CURLOPT_IOCTLFUNCTION` callback (`curl_ioctl_callback`).
pub type curl_ioctl_callback =
    Option<unsafe extern "C" fn(handle: *mut CURL, cmd: c_int, clientp: *mut c_void) -> curlioerr>;

/// `CURLOPT_DEBUGFUNCTION` callback (`curl_debug_callback`).
pub type curl_debug_callback = Option<
    unsafe extern "C" fn(
        handle: *mut CURL,
        type_: curl_infotype,
        data: *mut c_char,
        size: size_t,
        userptr: *mut c_void,
    ) -> c_int,
>;

/// `CURLOPT_PREREQFUNCTION` callback (`curl_prereq_callback`).
pub type curl_prereq_callback = Option<
    unsafe extern "C" fn(
        clientp: *mut c_void,
        conn_primary_ip: *mut c_char,
        conn_local_ip: *mut c_char,
        conn_primary_port: c_int,
        conn_local_port: c_int,
    ) -> c_int,
>;

/// `CURLOPT_SSL_CTX_FUNCTION` callback (`curl_ssl_ctx_callback`).
///
/// Returns a `CURLcode` integer (the real enum is owned by `error_codes.rs`).
pub type curl_ssl_ctx_callback = Option<
    unsafe extern "C" fn(curl: *mut CURL, ssl_ctx: *mut c_void, clientp: *mut c_void) -> i32,
>;

/// `curl_formget` data-delivery callback (`curl_formget_callback`).
pub type curl_formget_callback =
    Option<unsafe extern "C" fn(arg: *mut c_void, buf: *const c_char, len: size_t) -> size_t>;

/// Character-conversion callback (`curl_conv_callback`).
///
/// Returns a `CURLcode` integer (the real enum is owned by `error_codes.rs`).
pub type curl_conv_callback =
    Option<unsafe extern "C" fn(buffer: *mut c_char, length: size_t) -> i32>;

// Memory-management callbacks for `curl_global_init_mem`.

/// Custom `malloc` callback (`curl_malloc_callback`).
pub type curl_malloc_callback = Option<unsafe extern "C" fn(size: size_t) -> *mut c_void>;

/// Custom `free` callback (`curl_free_callback`).
pub type curl_free_callback = Option<unsafe extern "C" fn(ptr: *mut c_void)>;

/// Custom `realloc` callback (`curl_realloc_callback`).
pub type curl_realloc_callback =
    Option<unsafe extern "C" fn(ptr: *mut c_void, size: size_t) -> *mut c_void>;

/// Custom `strdup` callback (`curl_strdup_callback`).
pub type curl_strdup_callback = Option<unsafe extern "C" fn(str: *const c_char) -> *mut c_char>;

/// Custom `calloc` callback (`curl_calloc_callback`).
pub type curl_calloc_callback =
    Option<unsafe extern "C" fn(nmemb: size_t, size: size_t) -> *mut c_void>;

// Share-handle lock/unlock callbacks (`CURLSHOPT_LOCKFUNC`/`UNLOCKFUNC`).

/// Share-handle lock callback (`curl_lock_function`).
pub type curl_lock_function = Option<
    unsafe extern "C" fn(
        handle: *mut CURL,
        data: curl_lock_data,
        locktype: curl_lock_access,
        useptr: *mut c_void,
    ),
>;

/// Share-handle unlock callback (`curl_unlock_function`).
pub type curl_unlock_function =
    Option<unsafe extern "C" fn(handle: *mut CURL, data: curl_lock_data, useptr: *mut c_void)>;

/// TLS session-ticket export callback (`curl_ssls_export_cb`,
/// `include/curl/curl.h`, used by `curl_easy_ssls_export`).
///
/// In C this is a *function type* (`typedef CURLcode curl_ssls_export_cb(...)`),
/// not a function pointer; `curl_easy_ssls_export` takes a pointer to it. It is
/// modeled here as a bare `extern "C" fn` type so that the FFI `easy` module
/// can take it as `Option<curl_ssls_export_cb>`. The return is a `CURLcode`
/// integer (the real enum is owned by `error_codes.rs`).
pub type curl_ssls_export_cb = unsafe extern "C" fn(
    handle: *mut CURL,
    userptr: *mut c_void,
    session_key: *const c_char,
    shmac: *const c_uchar,
    shmac_len: size_t,
    sdata: *const c_uchar,
    sdata_len: size_t,
    valid_until: curl_off_t,
    ietf_tls_id: c_int,
    alpn: *const c_char,
    earlydata_max: size_t,
) -> i32;

// --- Multi-handle callbacks (`include/curl/multi.h`) ------------------------
//
// These four callback typedefs are consumed by `curl_multi_setopt`
// (`CURLMOPT_SOCKETFUNCTION` / `TIMERFUNCTION` / `PUSHFUNCTION` /
// `NOTIFYFUNCTION`). The variadic `curl_multi_setopt` shim in `multi.rs` stores
// the installed pointer and reconstructs the concrete `extern "C" fn` to invoke
// it; these `Option<…>` typedefs name the public C signatures so `cbindgen` and
// callers see the exact ABI (mirroring the curated `include/curl/multi.h`).

/// `CURLMOPT_SOCKETFUNCTION` callback (`curl_socket_callback`,
/// `include/curl/multi.h`). Reports a change in I/O interest for a socket; the
/// return value is `0` on success. `what` is one of the `CURL_POLL_*` values.
pub type curl_socket_callback = Option<
    unsafe extern "C" fn(
        easy: *mut CURL,
        s: curl_socket_t,
        what: c_int,
        userp: *mut c_void,
        socketp: *mut c_void,
    ) -> c_int,
>;

/// `CURLMOPT_TIMERFUNCTION` callback (`curl_multi_timer_callback`,
/// `include/curl/multi.h`). Reports a change in the maximum time the application
/// may wait before driving the multi again; `timeout_ms` is `-1` to clear. The
/// callback should return `0`.
pub type curl_multi_timer_callback = Option<
    unsafe extern "C" fn(multi: *mut CURLM, timeout_ms: c_long, userp: *mut c_void) -> c_int,
>;

/// `CURLMOPT_PUSHFUNCTION` callback (`curl_push_callback`,
/// `include/curl/multi.h`). Approves (`CURL_PUSH_OK`), denies (`CURL_PUSH_DENY`)
/// or fails (`CURL_PUSH_ERROROUT`) a server-pushed HTTP/2 stream.
pub type curl_push_callback = Option<
    unsafe extern "C" fn(
        parent: *mut CURL,
        easy: *mut CURL,
        num_headers: size_t,
        headers: *mut curl_pushheaders,
        userp: *mut c_void,
    ) -> c_int,
>;

/// `CURLMOPT_NOTIFYFUNCTION` callback (`curl_notify_callback`,
/// `include/curl/multi.h`). Delivers a multi-level notification
/// (`CURLMNOTIFY_INFO_READ` / `CURLMNOTIFY_EASY_DONE`) when enabled. Returns
/// nothing.
pub type curl_notify_callback = Option<
    unsafe extern "C" fn(
        multi: *mut CURLM,
        notification: c_uint,
        easy: *mut CURL,
        user_data: *mut c_void,
    ),
>;
