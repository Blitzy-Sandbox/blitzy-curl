//! The MIME / multipart `curl_mime_*` API plus the deprecated `curl_formadd` /
//! `curl_formget` / `curl_formfree` form API — 15 exported `curl_*` symbols.
//!
//! This module is the `extern "C"` boundary for building HTTP `multipart/
//! form-data` (and MIME mail) bodies. It marshals the C ABI onto the safe core
//! ([`curl_rs_lib::mime`]): the opaque `curl_mime` handle wraps a boxed
//! [`core::mime::Mime`], `curl_mimepart` is the (stable) address of a
//! [`core::mime::MimePart`] owned by that `Mime`, and the legacy
//! `curl_httppost` chain is built and serialized through the core's
//! [`core::mime::form_get`] / [`core::mime::HttpPost`] surface.
//!
//! Behavioral oracles: `lib/mime.c` (the MIME API) and `lib/formdata.c` (the
//! deprecated form API). The exact C signatures are pinned against
//! `include/curl/curl.h` (MIME L2442-L2551, form L2632-L2680).
//!
//! # Ownership model (the C-visible contract is preserved)
//!
//! * `curl_mime_init` returns a `Box::into_raw` pointer; `curl_mime_free`
//!   reclaims it with `Box::from_raw`, and the core `Drop` recursively frees the
//!   whole part tree.
//! * `curl_mime_addpart` returns the address of a part **owned by the mime**
//!   (the core stores parts as `Vec<Box<MimePart>>`, so the address is stable
//!   across later `addpart` calls). The caller never frees a part directly.
//! * `curl_mime_subparts` **transfers ownership** of the child mime into the
//!   parent part (`Box::from_raw` into the part); the caller must not free the
//!   subparts afterwards — exactly as curl documents.
//! * Legacy `curl_httppost` nodes and the strings they own are allocated with
//!   `libc::malloc` (via [`crate::global::c_strdup_bytes`]) so that
//!   `curl_formfree` reclaims them with `libc::free`, honoring the crate-wide
//!   `curl_free == libc::free` contract. The `curl_slist` headers attached to a
//!   form node are a **separate** ownership domain (owned by the caller, freed
//!   with `curl_slist_free_all`), so `curl_formfree` never frees them.
//!
//! # Variadic `curl_formadd`
//!
//! `curl_formadd` is a true C-variadic (`...`) terminated by `CURLFORM_END`;
//! the single-trailing-argument trick used by `curl_easy_setopt` does **not**
//! apply because a call carries many option/value pairs. Stable Rust cannot
//! define a C-variadic function, so the exported `curl_formadd` symbol is
//! provided by a tiny C trampoline (`csrc/formadd_trampoline.c`, compiled by
//! `build.rs`). The trampoline collects the argument list into a normalized
//! `curl_forms[]` array and calls the non-variadic Rust implementation
//! [`curlrs_formadd_impl`], which mirrors `FormAdd` in `lib/formdata.c`
//! (AAP §0.7.2 / §0.8.2 / §0.8.3 — the C-linkage exception is documented).
//!
//! # `unsafe`
//!
//! Per AAP §0.7.1 this crate is the sole holder of `unsafe`; every `unsafe`
//! block below carries a `// SAFETY:` comment, and (because the workspace lint
//! policy denies `unsafe_op_in_unsafe_fn`) every unsafe operation inside an
//! `unsafe fn` sits in an explicit `unsafe { }` block.

use std::ffi::{c_char, c_int, c_long, c_void, CStr};
use std::io;
use std::ptr;
use std::slice;

use libc::size_t;

// The async core this FFI layer wraps. Reaching the core via `core::mime::…`
// matches the sibling FFI modules. NOTE: because this alias shadows nothing in
// the extern prelude *for paths we write*, all standard-library utilities below
// are referenced via explicit `std::…` paths (`std::cmp`, `std::ptr`,
// `std::mem`, `std::slice`), never bare `core::…`, which would resolve to the
// standard `core` crate rather than `curl_rs_lib`.
use curl_rs_lib as core;

use crate::error_codes::{result_to_code, CURLFORMcode, CURLcode};
use crate::global::c_strdup_bytes;
use crate::types::{
    curl_formget_callback, curl_forms, curl_free_callback, curl_httppost, curl_mime, curl_mimepart,
    curl_off_t, curl_read_callback, curl_seek_callback, curl_slist, CURL, CURL_HTTPPOST_BUFFER,
    CURL_HTTPPOST_CALLBACK, CURL_HTTPPOST_FILENAME, CURL_HTTPPOST_LARGE, CURL_HTTPPOST_PTRBUFFER,
    CURL_HTTPPOST_PTRCONTENTS, CURL_HTTPPOST_PTRNAME, CURL_HTTPPOST_READFILE,
};

// =============================================================================
// Local constants
//
// These are stable curl ABI values from `include/curl/curl.h`. They are
// declared locally because the symbols that define them in `curl-rs-lib`
// (`transfer.rs`) are not part of this file's dependency whitelist; the values
// are fixed by the public ABI and verified against the header.
// =============================================================================

/// `SEEK_SET` (libc) / origin passed to a `curl_seek_callback` to rewind.
const SEEK_SET: c_int = 0;

/// `CURL_SEEKFUNC_OK` (`include/curl/curl.h`) — a seek callback succeeded.
const CURL_SEEKFUNC_OK: c_int = 0;

/// `CURL_READFUNC_ABORT` (`include/curl/curl.h`) — a read callback aborts the
/// transfer when it returns this sentinel.
const CURL_READFUNC_ABORT: size_t = 0x1000_0000;

/// `CURL_READFUNC_PAUSE` (`include/curl/curl.h`) — a read callback requests a
/// pause. Pausing is meaningless during the synchronous mime serialization that
/// backs `curl_formget`, so it is treated as a read error there.
const CURL_READFUNC_PAUSE: size_t = 0x1000_0001;

/// `CURL_ZERO_TERMINATED` (`include/curl/curl.h`) — the `(size_t)-1` sentinel
/// that tells `curl_mime_data` to measure the data with `strlen` rather than
/// trusting an explicit length.
const CURL_ZERO_TERMINATED: size_t = size_t::MAX;

// `CURLformoption` integer values (`include/curl/curl.h`). Only the values the
// form parser switches on are named here; the full enumeration lives in the
// curated header.
const CURLFORM_NOTHING: c_int = 0;
const CURLFORM_COPYNAME: c_int = 1;
const CURLFORM_PTRNAME: c_int = 2;
const CURLFORM_NAMELENGTH: c_int = 3;
const CURLFORM_COPYCONTENTS: c_int = 4;
const CURLFORM_PTRCONTENTS: c_int = 5;
const CURLFORM_CONTENTSLENGTH: c_int = 6;
const CURLFORM_FILECONTENT: c_int = 7;
const CURLFORM_ARRAY: c_int = 8;
const CURLFORM_FILE: c_int = 10;
const CURLFORM_BUFFER: c_int = 11;
const CURLFORM_BUFFERPTR: c_int = 12;
const CURLFORM_BUFFERLENGTH: c_int = 13;
const CURLFORM_CONTENTTYPE: c_int = 14;
const CURLFORM_CONTENTHEADER: c_int = 15;
const CURLFORM_FILENAME: c_int = 16;
const CURLFORM_END: c_int = 17;
const CURLFORM_STREAM: c_int = 19;
const CURLFORM_CONTENTLEN: c_int = 20;

/// The default content type curl assigns to a file/buffer part whose type is
/// neither given nor guessable (`FILE_CONTENTTYPE_DEFAULT` in `lib/formdata.c`).
const FILE_CONTENTTYPE_DEFAULT: &[u8] = b"application/octet-stream";

// =============================================================================
// Small unsafe helpers
// =============================================================================

/// Reborrow a raw `curl_mime *` as `&mut core::mime::Mime`, or `None` if NULL.
///
/// # Safety
///
/// `m` must be NULL or a pointer returned by `curl_mime_init` that has not been
/// freed; the returned reference must not outlive the handle.
unsafe fn mime_ref<'a>(m: *mut curl_mime) -> Option<&'a mut core::mime::Mime> {
    if m.is_null() {
        None
    } else {
        // SAFETY: per the contract `m` is a live `Box<Mime>` pointer produced by
        // `curl_mime_init`; reborrowing it as `&mut Mime` is sound for the
        // duration of the call (C callers are single-threaded per handle).
        Some(unsafe { &mut *(m as *mut core::mime::Mime) })
    }
}

/// Reborrow a raw `curl_mimepart *` as `&mut core::mime::MimePart`, or `None`
/// if NULL.
///
/// # Safety
///
/// `p` must be NULL or the address of a part owned by a live `curl_mime` (as
/// returned by `curl_mime_addpart`); the reference must not outlive that mime.
unsafe fn part_ref<'a>(p: *mut curl_mimepart) -> Option<&'a mut core::mime::MimePart> {
    if p.is_null() {
        None
    } else {
        // SAFETY: per the contract `p` is the stable address of a boxed
        // `MimePart` owned by a live `Mime` (the core stores parts in a
        // `Vec<Box<MimePart>>`), so reborrowing it as `&mut MimePart` is sound.
        Some(unsafe { &mut *(p as *mut core::mime::MimePart) })
    }
}

/// Borrow an optional C string as bytes: NULL maps to `None` (the "clear"
/// case), a non-NULL pointer to `Some(bytes)` up to the NUL terminator.
///
/// # Safety
///
/// `p` must be NULL or a valid NUL-terminated C string that stays alive for the
/// returned borrow.
unsafe fn opt_cstr_bytes<'a>(p: *const c_char) -> Option<&'a [u8]> {
    if p.is_null() {
        None
    } else {
        // SAFETY: `p` is a valid NUL-terminated C string per the contract;
        // `CStr::from_ptr` borrows it and `to_bytes` excludes the terminator.
        Some(unsafe { CStr::from_ptr(p) }.to_bytes())
    }
}

/// Widen a C `c_long` into the fixed-width `i64` used by `core::mime::HttpPost`.
///
/// On LP64 targets (e.g. `x86_64`/`aarch64` Linux & macOS) `c_long` is already
/// `i64`, so this is a no-op; on ILP32 / LLP64 targets (Windows, 32-bit) where
/// `c_long` is 32-bit it is a correct sign-extending widen. A bare `as i64`
/// would compile everywhere but trips clippy's `unnecessary_cast` on LP64 (and
/// `i64::from` trips `useless_conversion` there), so the platform-portable cast
/// is centralized here behind a single, narrowly-scoped allow.
#[inline]
#[allow(clippy::unnecessary_cast)]
fn clong_to_i64(value: c_long) -> i64 {
    value as i64
}

// =============================================================================
// Phase 1 — MIME lifecycle (oracle: lib/mime.c curl_mime_init / _free / _addpart)
// =============================================================================

/// `curl_mime *curl_mime_init(CURL *easy)` — create a MIME multipart container.
///
/// The container owns its part tree. `easy` is accepted for ABI compatibility
/// but, as in `lib/mime.c`, is needed only to seed the boundary RNG; the safe
/// core seeds its own RNG, so a NULL `easy` still yields a valid handle
/// (matching curl, which does not reject a NULL easy here). Returns NULL only if
/// boundary generation fails.
#[no_mangle]
pub extern "C" fn curl_mime_init(easy: *mut CURL) -> *mut curl_mime {
    // `easy` is unused by the safe core (which owns its RNG); kept for ABI.
    let _ = easy;
    match core::mime::Mime::new() {
        Ok(mime) => Box::into_raw(Box::new(mime)) as *mut curl_mime,
        Err(_) => ptr::null_mut(),
    }
}

/// `void curl_mime_free(curl_mime *mime)` — free a MIME container and every part
/// and subpart it owns. A NULL `mime` is a no-op.
///
/// # Safety
///
/// `mime` must be NULL or a pointer returned by [`curl_mime_init`] that has not
/// already been freed and was not transferred to a part via
/// [`curl_mime_subparts`].
#[no_mangle]
pub unsafe extern "C" fn curl_mime_free(mime: *mut curl_mime) {
    if mime.is_null() {
        return;
    }
    // SAFETY: per the contract `mime` is a live `Box<Mime>` pointer from
    // `curl_mime_init`, reclaimed exactly once here; the core `Drop` walks and
    // frees all parts and nested subparts.
    drop(unsafe { Box::from_raw(mime as *mut core::mime::Mime) });
}

/// `curl_mimepart *curl_mime_addpart(curl_mime *mime)` — append a new empty part
/// and return its (stable) address. The part is **owned by the mime** and is
/// freed only by [`curl_mime_free`]. Returns NULL if `mime` is NULL.
///
/// # Safety
///
/// `mime` must be NULL or a live `curl_mime` handle from [`curl_mime_init`].
#[no_mangle]
pub unsafe extern "C" fn curl_mime_addpart(mime: *mut curl_mime) -> *mut curl_mimepart {
    // SAFETY: `mime` satisfies `mime_ref`'s contract (NULL or a live handle).
    match unsafe { mime_ref(mime) } {
        None => ptr::null_mut(),
        Some(m) => {
            // The core stores parts as `Vec<Box<MimePart>>`, so the returned
            // address stays valid across later `addpart` calls.
            let part: &mut core::mime::MimePart = m.addpart();
            (part as *mut core::mime::MimePart) as *mut curl_mimepart
        }
    }
}

// =============================================================================
// Phase 2 — MIME part setters (oracle: lib/mime.c). All return CURLcode.
// =============================================================================

/// `CURLcode curl_mime_name(curl_mimepart *part, const char *name)` — set (or,
/// with a NULL `name`, clear) the part's `Content-Disposition` name.
///
/// # Safety
///
/// `part` must be NULL or a live part from [`curl_mime_addpart`]; `name` must be
/// NULL or a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_name(part: *mut curl_mimepart, name: *const c_char) -> CURLcode {
    // SAFETY: `part`/`name` satisfy the documented contracts.
    let p = match unsafe { part_ref(part) } {
        Some(p) => p,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
    };
    // SAFETY: `name` is NULL or a valid C string.
    let bytes = unsafe { opt_cstr_bytes(name) };
    result_to_code(p.set_name(bytes))
}

/// `CURLcode curl_mime_filename(curl_mimepart *part, const char *filename)` —
/// set (or, with NULL, clear) the part's `Content-Disposition` filename.
///
/// # Safety
///
/// As for [`curl_mime_name`].
#[no_mangle]
pub unsafe extern "C" fn curl_mime_filename(
    part: *mut curl_mimepart,
    filename: *const c_char,
) -> CURLcode {
    // SAFETY: documented contracts hold.
    let p = match unsafe { part_ref(part) } {
        Some(p) => p,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
    };
    // SAFETY: `filename` is NULL or a valid C string.
    let bytes = unsafe { opt_cstr_bytes(filename) };
    result_to_code(p.set_filename(bytes))
}

/// `CURLcode curl_mime_type(curl_mimepart *part, const char *mimetype)` — set
/// (or, with NULL, clear) the part's explicit `Content-Type`.
///
/// # Safety
///
/// As for [`curl_mime_name`].
#[no_mangle]
pub unsafe extern "C" fn curl_mime_type(
    part: *mut curl_mimepart,
    mimetype: *const c_char,
) -> CURLcode {
    // SAFETY: documented contracts hold.
    let p = match unsafe { part_ref(part) } {
        Some(p) => p,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
    };
    // SAFETY: `mimetype` is NULL or a valid C string.
    let bytes = unsafe { opt_cstr_bytes(mimetype) };
    result_to_code(p.set_type(bytes))
}

/// `CURLcode curl_mime_encoder(curl_mimepart *part, const char *encoding)` —
/// select a transfer encoder by name (`binary`, `8bit`, `7bit`, `base64`,
/// `quoted-printable`), or clear it with NULL. An unrecognized name yields
/// `CURLE_BAD_FUNCTION_ARGUMENT`, matching curl.
///
/// # Safety
///
/// As for [`curl_mime_name`].
#[no_mangle]
pub unsafe extern "C" fn curl_mime_encoder(
    part: *mut curl_mimepart,
    encoding: *const c_char,
) -> CURLcode {
    // SAFETY: documented contracts hold.
    let p = match unsafe { part_ref(part) } {
        Some(p) => p,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
    };
    // SAFETY: `encoding` is NULL or a valid C string.
    match unsafe { opt_cstr_bytes(encoding) } {
        None => result_to_code(p.set_encoder(None)),
        Some(bytes) => match std::str::from_utf8(bytes) {
            Ok(name) => result_to_code(p.set_encoder(Some(name))),
            // A non-UTF-8 name cannot be a valid encoder name; curl would reject
            // it the same way it rejects any unknown encoder.
            Err(_) => CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
        },
    }
}

/// `CURLcode curl_mime_data(curl_mimepart *part, const char *data, size_t
/// datasize)` — copy `datasize` bytes of `data` as the part body. The sentinel
/// [`CURL_ZERO_TERMINATED`] means "measure with `strlen`". A NULL `data` sets an
/// empty body.
///
/// # Safety
///
/// `part` must be NULL or a live part. If `data` is non-NULL it must point to at
/// least `datasize` readable bytes (or be a valid C string when `datasize ==
/// CURL_ZERO_TERMINATED`).
#[no_mangle]
pub unsafe extern "C" fn curl_mime_data(
    part: *mut curl_mimepart,
    data: *const c_char,
    datasize: size_t,
) -> CURLcode {
    // SAFETY: documented contracts hold.
    let p = match unsafe { part_ref(part) } {
        Some(p) => p,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
    };
    if data.is_null() {
        return result_to_code(p.set_data(b""));
    }
    let len = if datasize == CURL_ZERO_TERMINATED {
        // SAFETY: with the sentinel size, `data` is a valid NUL-terminated string.
        unsafe { libc::strlen(data) }
    } else {
        datasize
    };
    // SAFETY: `data` points to at least `len` readable bytes per the contract.
    let bytes = unsafe { slice::from_raw_parts(data as *const u8, len) };
    result_to_code(p.set_data(bytes))
}

/// `CURLcode curl_mime_filedata(curl_mimepart *part, const char *filename)` —
/// stream the part body from a named file at send time. A NULL `filename`
/// clears the body.
///
/// # Safety
///
/// `part` must be NULL or a live part; `filename` must be NULL or a valid
/// NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_filedata(
    part: *mut curl_mimepart,
    filename: *const c_char,
) -> CURLcode {
    // SAFETY: documented contracts hold.
    let p = match unsafe { part_ref(part) } {
        Some(p) => p,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
    };
    // SAFETY: `filename` is NULL or a valid C string.
    match unsafe { opt_cstr_bytes(filename) } {
        // Clearing the data source mirrors curl's `cleanup_part_content`; an
        // empty body serializes identically to curl's `MIMEKIND_NONE`.
        None => result_to_code(p.set_data(b"")),
        Some(bytes) => match std::str::from_utf8(bytes) {
            Ok(path) => result_to_code(p.set_filedata(path)),
            // A non-UTF-8 path cannot be opened by the std file APIs; report the
            // same failure curl reports when the file is unusable.
            Err(_) => CURLcode::CURLE_READ_ERROR,
        },
    }
}

// -----------------------------------------------------------------------------
// Callback-driven body adapter for `curl_mime_data_cb`.
// -----------------------------------------------------------------------------

/// Bridges a C read/seek/free callback trio onto the core
/// [`core::mime::MimeDataReader`] trait so that a callback-sourced part body can
/// be driven by the safe serializer. Mirrors curl's `MIMEKIND_CALLBACK`.
struct CCallbackReader {
    /// The data producer (`CURLOPT_READFUNCTION`-style signature).
    readfunc: curl_read_callback,
    /// Optional rewind callback used to restart the body (e.g. after a redirect).
    seekfunc: curl_seek_callback,
    /// Optional destructor for `arg`, invoked exactly once on drop.
    freefunc: curl_free_callback,
    /// Opaque user pointer threaded through every callback.
    arg: *mut c_void,
}

// SAFETY: `arg` is an opaque pointer the C caller owns; libcurl's contract is
// that a single transfer drives a given part's callbacks, and the serializer
// never shares a `CCallbackReader` across threads simultaneously. Marking it
// `Send` lets the reader live inside the core's `Box<dyn MimeDataReader>` (which
// requires `Send`); we never actually move active callback state across threads
// concurrently.
unsafe impl Send for CCallbackReader {}

impl core::mime::MimeDataReader for CCallbackReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let f = match self.readfunc {
            Some(f) => f,
            // No producer configured: behave as immediate EOF, as curl does when
            // a callback part has no read function.
            None => return Ok(0),
        };
        if buf.is_empty() {
            return Ok(0);
        }
        // SAFETY: hand the callback a writable buffer of `buf.len()` bytes; it
        // returns the number of bytes produced, or a sentinel. The `size`/`nmemb`
        // split mirrors the C convention (`size = 1`).
        let n = unsafe { f(buf.as_mut_ptr() as *mut c_char, 1, buf.len(), self.arg) };
        match n {
            CURL_READFUNC_ABORT => Err(io::Error::other("mime read callback aborted the transfer")),
            CURL_READFUNC_PAUSE => Err(io::Error::other(
                "mime read callback requested pause (unsupported during serialization)",
            )),
            n if n > buf.len() => Err(io::Error::other(
                "mime read callback returned more than the buffer size",
            )),
            n => Ok(n),
        }
    }

    fn rewind(&mut self) -> io::Result<()> {
        match self.seekfunc {
            None => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "mime data source has no seek callback",
            )),
            Some(f) => {
                // SAFETY: ask the user callback to seek the source back to the
                // start; `SEEK_SET` with offset 0 is the rewind convention.
                let r = unsafe { f(self.arg, 0 as curl_off_t, SEEK_SET) };
                if r == CURL_SEEKFUNC_OK {
                    Ok(())
                } else {
                    Err(io::Error::other("mime seek callback failed to rewind"))
                }
            }
        }
    }
}

impl Drop for CCallbackReader {
    fn drop(&mut self) {
        if let Some(f) = self.freefunc {
            // SAFETY: the free callback is invoked exactly once, here, with the
            // same `arg` the caller supplied — honoring curl's ownership contract
            // for `curl_mime_data_cb`.
            unsafe { f(self.arg) };
        }
    }
}

/// `CURLcode curl_mime_data_cb(curl_mimepart *part, curl_off_t datasize,
/// curl_read_callback readfunc, curl_seek_callback seekfunc, curl_free_callback
/// freefunc, void *arg)` — set a callback-driven body of declared size
/// `datasize` (`-1` if unknown).
///
/// # Safety
///
/// `part` must be NULL or a live part. The callbacks must be valid for calls
/// with `arg` until `freefunc` is invoked (on part drop).
#[no_mangle]
pub unsafe extern "C" fn curl_mime_data_cb(
    part: *mut curl_mimepart,
    datasize: curl_off_t,
    readfunc: curl_read_callback,
    seekfunc: curl_seek_callback,
    freefunc: curl_free_callback,
    arg: *mut c_void,
) -> CURLcode {
    // SAFETY: documented contracts hold.
    let p = match unsafe { part_ref(part) } {
        Some(p) => p,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
    };
    let reader = CCallbackReader {
        readfunc,
        seekfunc,
        freefunc,
        arg,
    };
    result_to_code(p.set_data_cb(datasize, Box::new(reader)))
}

/// `CURLcode curl_mime_subparts(curl_mimepart *part, curl_mime *subparts)` —
/// attach a child multipart as this part's body. **Ownership of `subparts` is
/// transferred to `part`**: after a successful call the caller must not free
/// `subparts`. A NULL `subparts` detaches any existing child.
///
/// # Safety
///
/// `part` must be NULL or a live part; `subparts` must be NULL or a live
/// `curl_mime` from [`curl_mime_init`] that has not been freed nor already
/// attached elsewhere.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_subparts(
    part: *mut curl_mimepart,
    subparts: *mut curl_mime,
) -> CURLcode {
    // SAFETY: documented contracts hold.
    let p = match unsafe { part_ref(part) } {
        Some(p) => p,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
    };
    if subparts.is_null() {
        return result_to_code(p.set_subparts(None));
    }
    // SAFETY: take ownership of the child mime. `subparts` is a live `Box<Mime>`
    // pointer from `curl_mime_init`; moving it into the part means the caller
    // must not (and per the documented contract will not) free it again.
    let child = unsafe { *Box::from_raw(subparts as *mut core::mime::Mime) };
    result_to_code(p.set_subparts(Some(child)))
}

/// `CURLcode curl_mime_headers(curl_mimepart *part, struct curl_slist *headers,
/// int take_ownership)` — attach custom headers to the part. When
/// `take_ownership` is non-zero the part assumes responsibility for the C list
/// and it is freed here (the core keeps its own owned copy); otherwise the list
/// is copied and the caller retains ownership. A NULL `headers` clears.
///
/// # Safety
///
/// `part` must be NULL or a live part; `headers` must be NULL or a valid
/// `curl_slist` chain from the slist API.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_headers(
    part: *mut curl_mimepart,
    headers: *mut curl_slist,
    take_ownership: c_int,
) -> CURLcode {
    // SAFETY: documented contracts hold.
    let p = match unsafe { part_ref(part) } {
        Some(p) => p,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
    };
    if headers.is_null() {
        return result_to_code(p.set_headers(None, false));
    }
    let owns = take_ownership != 0;
    // SAFETY: `headers` is a valid `curl_slist` chain; deep-copy it into an owned
    // core `SList` so the core never aliases caller memory.
    let copy = unsafe { crate::slist::raw_to_core(headers) };
    let code = result_to_code(p.set_headers(Some(copy), owns));
    if owns {
        // The part took ownership: free the caller's original C list now, since
        // the core holds its own copy and the caller will not free it.
        // SAFETY: `headers` is a valid, caller-relinquished `curl_slist` chain.
        unsafe { crate::slist::curl_slist_free_all(headers) };
    }
    code
}

// =============================================================================
// Phase 3 — deprecated form API (oracle: lib/formdata.c)
//
// `curl_formadd` builds a C-ABI `curl_httppost` linked list whose owned strings
// are `libc::malloc`'d so that `curl_formfree` reclaims them with `libc::free`.
// `curl_formget` converts that C chain into a core `HttpPost` and serializes it
// through `core::mime::form_get`. The exported variadic `curl_formadd` symbol is
// supplied by the C trampoline (`csrc/formadd_trampoline.c`); the Rust side is
// the non-variadic `curlrs_formadd_impl` invoked by that trampoline.
// =============================================================================

/// Guess a part's `Content-Type` from a filename suffix, mirroring curl's
/// `Curl_mime_contenttype` table (`lib/mime.c`). Returns `None` when no suffix
/// matches, so the caller can fall back to the previous type or the default.
fn guess_content_type(filename: &[u8]) -> Option<&'static [u8]> {
    // Suffix → type, matched case-insensitively against the tail of the name.
    // This is the exact table curl ships (and that `curl-rs-lib` replicates).
    const TABLE: &[(&[u8], &[u8])] = &[
        (b".gif", b"image/gif"),
        (b".jpg", b"image/jpeg"),
        (b".jpeg", b"image/jpeg"),
        (b".png", b"image/png"),
        (b".svg", b"image/svg+xml"),
        (b".txt", b"text/plain"),
        (b".htm", b"text/html"),
        (b".html", b"text/html"),
        (b".pdf", b"application/pdf"),
        (b".xml", b"application/xml"),
    ];
    for (suffix, ctype) in TABLE {
        if filename.len() >= suffix.len() {
            let tail = &filename[filename.len() - suffix.len()..];
            if tail.eq_ignore_ascii_case(suffix) {
                return Some(ctype);
            }
        }
    }
    None
}

/// Mirror of curl's `FormInfo`: the per-part accumulator filled while parsing
/// the option list. It holds **borrowed** caller pointers and the flag/length
/// state; the decision to copy a field (and thus own it) is deferred to
/// [`form_add_check`], exactly as curl defers copying to `FormAddCheck`.
///
/// As in curl, a non-NULL pointer is the "this field was set" marker (curl uses
/// `Curl_bufref_ptr(&field) != NULL`), so duplicate-option detection just checks
/// for a non-NULL pointer.
struct FormInfo {
    /// Caller name pointer (`CURLFORM_COPYNAME` / `CURLFORM_PTRNAME`).
    name: *const c_char,
    /// Explicit name length (`CURLFORM_NAMELENGTH`); 0 means measure with strlen.
    namelength: size_t,
    /// Caller value/filename pointer, or a non-NULL marker for buffer/stream
    /// parts (`CURLFORM_*CONTENTS`, `CURLFORM_FILE`, `CURLFORM_FILECONTENT`).
    value: *const c_char,
    /// Declared content length (`CURLFORM_CONTENTSLENGTH` / `CURLFORM_CONTENTLEN`).
    contentslength: curl_off_t,
    /// Explicit content type pointer (`CURLFORM_CONTENTTYPE`).
    contenttype: *const c_char,
    /// `CURL_HTTPPOST_*` flag accumulator.
    flags: c_long,
    /// Display filename pointer (`CURLFORM_FILENAME` / `CURLFORM_BUFFER`).
    showfilename: *const c_char,
    /// In-memory buffer pointer (`CURLFORM_BUFFERPTR`).
    buffer: *const c_char,
    /// Buffer length (`CURLFORM_BUFFERLENGTH`).
    bufferlength: size_t,
    /// Stream user pointer (`CURLFORM_STREAM`).
    userp: *mut c_void,
    /// Caller-owned per-part headers (`CURLFORM_CONTENTHEADER`); never freed here.
    contentheader: *mut curl_slist,
}

impl FormInfo {
    /// A zero-initialized accumulator (curl uses `calloc` + `Curl_bufref_init`).
    fn new() -> FormInfo {
        FormInfo {
            name: ptr::null(),
            namelength: 0,
            value: ptr::null(),
            contentslength: 0,
            contenttype: ptr::null(),
            flags: 0,
            showfilename: ptr::null(),
            buffer: ptr::null(),
            bufferlength: 0,
            userp: ptr::null_mut(),
            contentheader: ptr::null_mut(),
        }
    }
}

/// The non-variadic implementation behind the C `curl_formadd` trampoline.
///
/// `forms` points to a normalized `curl_forms[]` array of `count` entries the
/// trampoline assembled from the variadic argument list (each entry an
/// `{option, value}` pair, length options carried as the integer reinterpreted
/// as a pointer). A user-supplied `CURLFORM_ARRAY` value points to a further
/// `curl_forms[]` terminated by `CURLFORM_END`. This mirrors `FormAdd` in
/// `lib/formdata.c`, including its two-cursor (outer list vs. array) walk.
///
/// On success the freshly built `curl_httppost` chain is linked into
/// `*httppost` / `*last_post`; on failure nothing is linked and all interim
/// allocations are released.
///
/// # Safety
///
/// `httppost` and `last_post` must be valid, writable `*mut *mut curl_httppost`
/// out-pointers; `forms` must point to `count` readable `curl_forms` entries;
/// every caller pointer referenced by an option must stay valid per that
/// option's documented contract (copied options need only outlive this call).
#[no_mangle]
pub unsafe extern "C" fn curlrs_formadd_impl(
    httppost: *mut *mut curl_httppost,
    last_post: *mut *mut curl_httppost,
    forms: *const curl_forms,
    count: size_t,
) -> CURLFORMcode {
    if httppost.is_null() || last_post.is_null() {
        return CURLFORMcode::CURL_FORMADD_NULL;
    }

    // The FormInfo `more` chain, in order: index 0 is curl's `first_form`.
    let mut infos: Vec<FormInfo> = vec![FormInfo::new()];
    let mut curr: usize = 0;
    let mut retval = CURLFORMcode::CURL_FORMADD_OK;

    // Two independent cursors mirror curl's `params` (outer) vs. `forms` (array)
    // duality: `top_*` walks the trampoline-flattened outer list; `arr_*` walks a
    // user `CURLFORM_ARRAY`. `CURLFORM_END` in the array returns to the outer
    // list; `CURLFORM_END` in the outer list ends parsing.
    let mut top_cur: *const curl_forms = forms;
    let mut top_remaining: size_t = count;
    let mut arr_cur: *const curl_forms = ptr::null();
    let mut in_arr = false;

    while retval == CURLFORMcode::CURL_FORMADD_OK {
        let option: c_int;
        let avalue: *const c_char;

        if in_arr {
            // SAFETY: `arr_cur` points at a live `curl_forms` entry within the
            // caller's NUL/END-terminated array per the option contract.
            let entry = unsafe { &*arr_cur };
            option = entry.option;
            avalue = entry.value;
            // SAFETY: advancing within the same array; the array is terminated
            // by a `CURLFORM_END` entry which stops us before the one-past-end.
            arr_cur = unsafe { arr_cur.add(1) };
            if option == CURLFORM_END {
                in_arr = false;
                continue;
            }
        } else {
            if top_remaining == 0 {
                // Defensive: the trampoline always appends CURLFORM_END, but never
                // read past the supplied count.
                break;
            }
            // SAFETY: `top_cur` is within the `count`-entry trampoline array.
            let entry = unsafe { &*top_cur };
            option = entry.option;
            avalue = entry.value;
            // SAFETY: advancing within the `count`-entry array bound by
            // `top_remaining`.
            top_cur = unsafe { top_cur.add(1) };
            top_remaining -= 1;
            if option == CURLFORM_END {
                break;
            }
        }

        // `cur` is the FormInfo currently being filled.
        let cur_info = &mut infos[curr];
        match option {
            CURLFORM_ARRAY => {
                if in_arr {
                    retval = CURLFORMcode::CURL_FORMADD_ILLEGAL_ARRAY;
                } else {
                    let arr = avalue as *const curl_forms;
                    if arr.is_null() {
                        retval = CURLFORMcode::CURL_FORMADD_NULL;
                    } else {
                        arr_cur = arr;
                        in_arr = true;
                    }
                }
            }
            CURLFORM_PTRNAME => {
                cur_info.flags |= CURL_HTTPPOST_PTRNAME;
                if !cur_info.name.is_null() {
                    retval = CURLFORMcode::CURL_FORMADD_OPTION_TWICE;
                } else if avalue.is_null() {
                    retval = CURLFORMcode::CURL_FORMADD_NULL;
                } else {
                    cur_info.name = avalue;
                }
            }
            CURLFORM_COPYNAME => {
                if !cur_info.name.is_null() {
                    retval = CURLFORMcode::CURL_FORMADD_OPTION_TWICE;
                } else if avalue.is_null() {
                    retval = CURLFORMcode::CURL_FORMADD_NULL;
                } else {
                    cur_info.name = avalue;
                }
            }
            CURLFORM_NAMELENGTH => {
                if cur_info.namelength != 0 {
                    retval = CURLFORMcode::CURL_FORMADD_OPTION_TWICE;
                } else {
                    cur_info.namelength = avalue as size_t;
                }
            }
            CURLFORM_PTRCONTENTS => {
                cur_info.flags |= CURL_HTTPPOST_PTRCONTENTS;
                if !cur_info.value.is_null() {
                    retval = CURLFORMcode::CURL_FORMADD_OPTION_TWICE;
                } else if avalue.is_null() {
                    retval = CURLFORMcode::CURL_FORMADD_NULL;
                } else {
                    cur_info.value = avalue;
                }
            }
            CURLFORM_COPYCONTENTS => {
                if !cur_info.value.is_null() {
                    retval = CURLFORMcode::CURL_FORMADD_OPTION_TWICE;
                } else if avalue.is_null() {
                    retval = CURLFORMcode::CURL_FORMADD_NULL;
                } else {
                    cur_info.value = avalue;
                }
            }
            CURLFORM_CONTENTSLENGTH => {
                cur_info.contentslength = avalue as size_t as curl_off_t;
            }
            CURLFORM_CONTENTLEN => {
                cur_info.flags |= CURL_HTTPPOST_LARGE;
                // The trampoline carries the `curl_off_t` length in the pointer
                // slot; recover its bits via `usize` (pointer-sized on the
                // 64-bit targets) then reinterpret as the signed length.
                cur_info.contentslength = avalue as usize as curl_off_t;
            }
            CURLFORM_FILECONTENT => {
                if cur_info.flags & (CURL_HTTPPOST_PTRCONTENTS | CURL_HTTPPOST_READFILE) != 0 {
                    retval = CURLFORMcode::CURL_FORMADD_OPTION_TWICE;
                } else if avalue.is_null() {
                    retval = CURLFORMcode::CURL_FORMADD_NULL;
                } else {
                    cur_info.value = avalue;
                    cur_info.flags |= CURL_HTTPPOST_READFILE;
                }
            }
            CURLFORM_FILE => {
                if !cur_info.value.is_null() {
                    if cur_info.flags & CURL_HTTPPOST_FILENAME != 0 {
                        // Additional file for the same field: start a new node.
                        if avalue.is_null() {
                            retval = CURLFORMcode::CURL_FORMADD_NULL;
                        } else {
                            let mut more = FormInfo::new();
                            more.flags |= CURL_HTTPPOST_FILENAME;
                            more.value = avalue;
                            infos.push(more);
                            curr = infos.len() - 1;
                        }
                    } else {
                        retval = CURLFORMcode::CURL_FORMADD_OPTION_TWICE;
                    }
                } else if avalue.is_null() {
                    retval = CURLFORMcode::CURL_FORMADD_NULL;
                } else {
                    cur_info.value = avalue;
                    cur_info.flags |= CURL_HTTPPOST_FILENAME;
                }
            }
            CURLFORM_BUFFERPTR => {
                cur_info.flags |= CURL_HTTPPOST_PTRBUFFER | CURL_HTTPPOST_BUFFER;
                if !cur_info.buffer.is_null() {
                    retval = CURLFORMcode::CURL_FORMADD_OPTION_TWICE;
                } else if avalue.is_null() {
                    retval = CURLFORMcode::CURL_FORMADD_NULL;
                } else {
                    cur_info.buffer = avalue;
                    // Make value non-NULL so the part is accepted as complete.
                    cur_info.value = avalue;
                }
            }
            CURLFORM_BUFFERLENGTH => {
                if cur_info.bufferlength != 0 {
                    retval = CURLFORMcode::CURL_FORMADD_OPTION_TWICE;
                } else {
                    cur_info.bufferlength = avalue as size_t;
                }
            }
            CURLFORM_STREAM => {
                cur_info.flags |= CURL_HTTPPOST_CALLBACK;
                if !cur_info.userp.is_null() {
                    retval = CURLFORMcode::CURL_FORMADD_OPTION_TWICE;
                } else if avalue.is_null() {
                    retval = CURLFORMcode::CURL_FORMADD_NULL;
                } else {
                    cur_info.userp = avalue as *mut c_void;
                    // Derive a non-NULL value marker (curl does the same).
                    cur_info.value = avalue;
                }
            }
            CURLFORM_CONTENTTYPE => {
                if !cur_info.contenttype.is_null() {
                    if cur_info.flags & CURL_HTTPPOST_FILENAME != 0 {
                        // Content type for an additional file: new node.
                        if avalue.is_null() {
                            retval = CURLFORMcode::CURL_FORMADD_NULL;
                        } else {
                            let mut more = FormInfo::new();
                            more.flags |= CURL_HTTPPOST_FILENAME;
                            more.contenttype = avalue;
                            infos.push(more);
                            curr = infos.len() - 1;
                        }
                    } else {
                        retval = CURLFORMcode::CURL_FORMADD_OPTION_TWICE;
                    }
                } else if avalue.is_null() {
                    retval = CURLFORMcode::CURL_FORMADD_NULL;
                } else {
                    cur_info.contenttype = avalue;
                }
            }
            CURLFORM_CONTENTHEADER => {
                if !cur_info.contentheader.is_null() {
                    retval = CURLFORMcode::CURL_FORMADD_OPTION_TWICE;
                } else {
                    cur_info.contentheader = avalue as *mut curl_slist;
                }
            }
            CURLFORM_FILENAME | CURLFORM_BUFFER => {
                if !cur_info.showfilename.is_null() {
                    retval = CURLFORMcode::CURL_FORMADD_OPTION_TWICE;
                } else if avalue.is_null() {
                    retval = CURLFORMcode::CURL_FORMADD_NULL;
                } else {
                    cur_info.showfilename = avalue;
                }
            }
            CURLFORM_NOTHING => {
                // No-op placeholder (curl's CURLFORM_NOTHING).
            }
            _ => {
                retval = CURLFORMcode::CURL_FORMADD_UNKNOWN_OPTION;
            }
        }
    }

    // Build the httppost chain, validating completeness, then link or clean up.
    // SAFETY: `httppost`/`last_post` are valid out-pointers per the contract.
    unsafe { finish_formadd(infos, retval, httppost, last_post) }
}

/// Free a `libc`-allocated string if non-NULL (the owned-field destructor used
/// during `curl_formadd` error unwinding and by [`curl_formfree`]).
///
/// # Safety
///
/// `p` must be NULL or a pointer returned by [`c_strdup_bytes`] (i.e.
/// `libc::malloc`'d) that is freed exactly once.
unsafe fn free_owned(p: *mut c_char) {
    if !p.is_null() {
        // SAFETY: `p` is a live `libc::malloc`'d buffer per the contract.
        unsafe { libc::free(p as *mut c_void) };
    }
}

/// Build one `curl_httppost` node from a parsed [`FormInfo`], copying the fields
/// curl owns (name unless `PTRNAME`; contents unless `PTRCONTENTS`/`BUFFER`/
/// `CALLBACK`; content-type and show-filename always) into `libc`-allocated
/// buffers and borrowing the rest. Mirrors `AddHttpPost` together with the
/// per-field copy decisions `FormAddCheck` makes. Returns `None` (→
/// `CURL_FORMADD_MEMORY`) on allocation failure, having freed any interim
/// allocations.
///
/// # Safety
///
/// All non-NULL pointers in `form` must satisfy their option's validity contract
/// (valid C strings / buffers of the stated length).
unsafe fn build_post_node(form: &FormInfo, ctype: Option<&[u8]>) -> Option<*mut curl_httppost> {
    // Effective name length: explicit, else strlen of the name, else 0.
    let namelength: size_t = if form.namelength != 0 {
        form.namelength
    } else if !form.name.is_null() {
        // SAFETY: `form.name` is a valid C string when non-NULL.
        unsafe { libc::strlen(form.name) }
    } else {
        0
    };

    // Guard the `c_long` typecasts below against overflow (AddHttpPost).
    if form.bufferlength as u64 > c_long::MAX as u64 || namelength as u64 > c_long::MAX as u64 {
        return None;
    }

    let ptrname = (form.flags & CURL_HTTPPOST_PTRNAME) != 0;
    let owns_contents = (form.flags
        & (CURL_HTTPPOST_PTRCONTENTS | CURL_HTTPPOST_BUFFER | CURL_HTTPPOST_CALLBACK))
        == 0;

    // ---- name ----
    let name_ptr: *mut c_char = if form.name.is_null() {
        ptr::null_mut()
    } else if ptrname {
        form.name as *mut c_char // borrowed; never freed (PTRNAME)
    } else {
        // SAFETY: `form.name` has at least `namelength` valid bytes.
        let nbytes = unsafe { slice::from_raw_parts(form.name as *const u8, namelength) };
        // SAFETY: copies into a fresh `libc` buffer; freed via `curl_formfree`.
        let p = unsafe { c_strdup_bytes(nbytes) };
        if p.is_null() {
            return None;
        }
        p
    };
    let name_owned = !form.name.is_null() && !ptrname;

    // ---- contents ----
    let contents_ptr: *mut c_char = if form.value.is_null() {
        ptr::null_mut()
    } else if !owns_contents {
        form.value as *mut c_char // borrowed (PTRCONTENTS / BUFFER / CALLBACK)
    } else {
        // Owned copy: length is the declared content length, else strlen. For
        // FILE/FILECONTENT parts the completeness check guarantees length 0, so
        // this measures the filename with strlen, matching curl.
        let copylen: size_t = if form.contentslength != 0 {
            form.contentslength as size_t
        } else {
            // SAFETY: `form.value` is a valid C string when measured by strlen.
            unsafe { libc::strlen(form.value) }
        };
        // SAFETY: `form.value` has at least `copylen` valid bytes.
        let vbytes = unsafe { slice::from_raw_parts(form.value as *const u8, copylen) };
        // SAFETY: copies into a fresh `libc` buffer; freed via `curl_formfree`.
        let p = unsafe { c_strdup_bytes(vbytes) };
        if p.is_null() {
            // SAFETY: free the owned name allocated above (if any).
            if name_owned {
                // SAFETY: `name_ptr` was allocated by this crate above and is freed exactly once here.
                unsafe { free_owned(name_ptr) };
            }
            return None;
        }
        p
    };
    let contents_owned = !form.value.is_null() && owns_contents;

    // ---- content type (always an owned copy when present) ----
    let ctype_ptr: *mut c_char = match ctype {
        None => ptr::null_mut(),
        Some(ct) => {
            // SAFETY: copies into a fresh `libc` buffer; freed via `curl_formfree`.
            let p = unsafe { c_strdup_bytes(ct) };
            if p.is_null() {
                // SAFETY: unwind the owned allocations made so far.
                unsafe {
                    if name_owned {
                        free_owned(name_ptr);
                    }
                    if contents_owned {
                        free_owned(contents_ptr);
                    }
                }
                return None;
            }
            p
        }
    };

    // ---- show filename (always an owned copy when present) ----
    let showfn_ptr: *mut c_char = if form.showfilename.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: `form.showfilename` is a valid C string when non-NULL.
        let sbytes = unsafe { CStr::from_ptr(form.showfilename) }.to_bytes();
        // SAFETY: copies into a fresh `libc` buffer; freed via `curl_formfree`.
        let p = unsafe { c_strdup_bytes(sbytes) };
        if p.is_null() {
            // SAFETY: unwind the owned allocations made so far.
            unsafe {
                if name_owned {
                    free_owned(name_ptr);
                }
                if contents_owned {
                    free_owned(contents_ptr);
                }
                free_owned(ctype_ptr);
            }
            return None;
        }
        p
    };

    // ---- the node itself ----
    // SAFETY: allocate `sizeof(curl_httppost)` bytes for the C-ABI node.
    let node = unsafe { libc::malloc(std::mem::size_of::<curl_httppost>()) } as *mut curl_httppost;
    if node.is_null() {
        // SAFETY: unwind every owned allocation before bailing out.
        unsafe {
            if name_owned {
                free_owned(name_ptr);
            }
            if contents_owned {
                free_owned(contents_ptr);
            }
            free_owned(ctype_ptr);
            free_owned(showfn_ptr);
        }
        return None;
    }

    // SAFETY: `node` points to uninitialized, suitably sized/aligned storage;
    // `ptr::write` initializes every field exactly once. `CURL_HTTPPOST_LARGE`
    // is set unconditionally and `contentlen` carries the length, matching
    // `AddHttpPost` (the `contentslength` C-long field is left 0).
    unsafe {
        ptr::write(
            node,
            curl_httppost {
                next: ptr::null_mut(),
                name: name_ptr,
                namelength: namelength as c_long,
                contents: contents_ptr,
                contentslength: 0,
                buffer: form.buffer as *mut c_char,
                bufferlength: form.bufferlength as c_long,
                contenttype: ctype_ptr,
                contentheader: form.contentheader,
                more: ptr::null_mut(),
                flags: form.flags | CURL_HTTPPOST_LARGE,
                showfilename: showfn_ptr,
                userp: form.userp,
                contentlen: form.contentslength,
            },
        );
    }
    Some(node)
}

/// Link a freshly built node into the chain, mirroring `AddHttpPost`'s linking:
/// a node with a `parent` becomes the head of the parent's `more` list;
/// otherwise it extends the main `*newchain` / `*lastnode` list.
///
/// # Safety
///
/// `node` must be a live node; `parent` NULL or a live node; `newchain` /
/// `lastnode` valid writable out-pointers.
unsafe fn link_post(
    node: *mut curl_httppost,
    parent: *mut curl_httppost,
    newchain: *mut *mut curl_httppost,
    lastnode: *mut *mut curl_httppost,
) {
    if !parent.is_null() {
        // SAFETY: `node`/`parent` are live; splice `node` ahead of the parent's
        // existing `more` list.
        unsafe {
            (*node).more = (*parent).more;
            (*parent).more = node;
        }
    } else {
        // SAFETY: out-pointers are valid; extend the main list.
        unsafe {
            if (*lastnode).is_null() {
                *newchain = node;
            } else {
                (*(*lastnode)).next = node;
            }
            *lastnode = node;
        }
    }
}

/// Validate completeness, build, and link the `curl_httppost` chain from the
/// parsed `FormInfo` list. Mirrors `FormAddCheck` (`lib/formdata.c`), including
/// the multi-file content-type threading via `prevtype`.
///
/// # Safety
///
/// `newchain` / `lastnode` are valid writable out-pointers; the `infos`
/// pointers satisfy their option contracts.
unsafe fn form_add_check(
    infos: &[FormInfo],
    newchain: *mut *mut curl_httppost,
    lastnode: *mut *mut curl_httppost,
) -> CURLFORMcode {
    let mut prevtype: Option<Vec<u8>> = None;
    let mut parent_post: *mut curl_httppost = ptr::null_mut();
    let mut have_post = false;

    for form in infos {
        let name_set = !form.name.is_null();
        let value_set = !form.value.is_null();

        // Completeness checks (FormAddCheck): a missing name/value is only fatal
        // for the first node; length is illegal with FILENAME; FILENAME excludes
        // PTRCONTENTS; an empty PTRBUFFER buffer and READFILE+PTRCONTENTS are
        // illegal.
        if ((!name_set || !value_set) && !have_post)
            || (form.contentslength != 0 && (form.flags & CURL_HTTPPOST_FILENAME) != 0)
            || ((form.flags & CURL_HTTPPOST_FILENAME) != 0
                && (form.flags & CURL_HTTPPOST_PTRCONTENTS) != 0)
            || (form.buffer.is_null()
                && (form.flags & CURL_HTTPPOST_BUFFER) != 0
                && (form.flags & CURL_HTTPPOST_PTRBUFFER) != 0)
            || ((form.flags & CURL_HTTPPOST_READFILE) != 0
                && (form.flags & CURL_HTTPPOST_PTRCONTENTS) != 0)
        {
            return CURLFORMcode::CURL_FORMADD_INCOMPLETE;
        }

        // Determine this node's content type (owned bytes). For FILENAME/BUFFER
        // parts without an explicit type, guess from the filename, then fall
        // back to the previous type, then the default.
        let ctype: Option<Vec<u8>> =
            if (form.flags & (CURL_HTTPPOST_FILENAME | CURL_HTTPPOST_BUFFER)) != 0
                && form.contenttype.is_null()
            {
                let fptr = if (form.flags & CURL_HTTPPOST_BUFFER) != 0 {
                    form.showfilename
                } else {
                    form.value
                };
                let guessed = if fptr.is_null() {
                    None
                } else {
                    // SAFETY: `fptr` is a valid C string when non-NULL.
                    let fbytes = unsafe { CStr::from_ptr(fptr) }.to_bytes();
                    guess_content_type(fbytes)
                };
                let chosen = if let Some(g) = guessed {
                    g.to_vec()
                } else if let Some(prev) = &prevtype {
                    prev.clone()
                } else {
                    FILE_CONTENTTYPE_DEFAULT.to_vec()
                };
                Some(chosen)
            } else if !form.contenttype.is_null() {
                // SAFETY: `form.contenttype` is a valid C string when non-NULL.
                Some(
                    unsafe { CStr::from_ptr(form.contenttype) }
                        .to_bytes()
                        .to_vec(),
                )
            } else {
                None
            };

        // Reject embedded NULs in a length-qualified name (FormAddCheck).
        if name_set && form.namelength != 0 {
            // SAFETY: `form.name` has at least `namelength` readable bytes.
            let nbytes = unsafe { slice::from_raw_parts(form.name as *const u8, form.namelength) };
            if nbytes.contains(&0) {
                return CURLFORMcode::CURL_FORMADD_NULL;
            }
        }

        // SAFETY: `form` pointers satisfy their option contracts.
        let node = match unsafe { build_post_node(form, ctype.as_deref()) } {
            Some(n) => n,
            None => return CURLFORMcode::CURL_FORMADD_MEMORY,
        };

        // SAFETY: `node`/`parent_post` live; out-pointers valid.
        unsafe { link_post(node, parent_post, newchain, lastnode) };
        parent_post = node;
        have_post = true;

        // Thread the content type forward for subsequent files of this field.
        if let Some(ct) = ctype {
            prevtype = Some(ct);
        }
    }

    CURLFORMcode::CURL_FORMADD_OK
}

/// Finalize `curl_formadd`: run [`form_add_check`] when parsing succeeded, then
/// either link the new chain into `*httppost` / `*last_post` (success) or
/// deep-free it (failure). Mirrors the tail of `FormAdd`.
///
/// # Safety
///
/// `httppost` / `last_post` are valid writable out-pointers.
unsafe fn finish_formadd(
    infos: Vec<FormInfo>,
    retval: CURLFORMcode,
    httppost: *mut *mut curl_httppost,
    last_post: *mut *mut curl_httppost,
) -> CURLFORMcode {
    let mut newchain: *mut curl_httppost = ptr::null_mut();
    let mut lastnode: *mut curl_httppost = ptr::null_mut();
    let mut retval = retval;

    if retval == CURLFORMcode::CURL_FORMADD_OK {
        // SAFETY: local out-pointers; `infos` pointers satisfy their contracts.
        retval = unsafe { form_add_check(&infos, &mut newchain, &mut lastnode) };
    }
    // `infos` holds only borrowed pointers, so dropping it frees nothing the
    // chain references.
    drop(infos);

    if retval == CURLFORMcode::CURL_FORMADD_OK {
        // SAFETY: out-pointers are valid; append the new chain to the list.
        unsafe {
            if !(*last_post).is_null() {
                (*(*last_post)).next = newchain;
            } else {
                *httppost = newchain;
            }
            *last_post = lastnode;
        }
    } else {
        // Unlike curl (whose owned strings live in the FormInfo bufrefs and are
        // freed separately), our owned strings live in the nodes themselves, so
        // the error path is a *deep* free of the partial chain.
        // SAFETY: `newchain` is a chain this function built; freed exactly once.
        unsafe { free_post_chain(newchain) };
    }
    retval
}

/// Deep-free a `curl_httppost` chain: recurse into each node's `more` list,
/// release the owned strings (name unless `PTRNAME`; contents unless
/// `PTRCONTENTS`/`BUFFER`/`CALLBACK`; content-type and show-filename always),
/// then the node itself. The `buffer`, `contentheader`, and `userp` pointers are
/// caller-owned and never freed. Mirrors `curl_formfree` in `lib/formdata.c`.
///
/// # Safety
///
/// `form` must be NULL or a `curl_httppost` chain built by this crate (nodes and
/// owned strings `libc`-allocated); it is freed exactly once.
unsafe fn free_post_chain(form: *mut curl_httppost) {
    let mut cur = form;
    while !cur.is_null() {
        // Copy out every field we need before any free, so no read touches freed
        // memory. SAFETY: `cur` is a live node of the chain.
        let next = unsafe { (*cur).next };
        // SAFETY: `cur` is non-null and points to a live, valid node here; `more` is a `Copy` value read out before the node is freed.
        let more = unsafe { (*cur).more };
        // SAFETY: `cur` is non-null and points to a live, valid node here; `flags` is a `Copy` value read out before the node is freed.
        let flags = unsafe { (*cur).flags };
        // SAFETY: `cur` is non-null and points to a live, valid node here; `name` is a `Copy` value read out before the node is freed.
        let name = unsafe { (*cur).name };
        // SAFETY: `cur` is non-null and points to a live, valid node here; `contents` is a `Copy` value read out before the node is freed.
        let contents = unsafe { (*cur).contents };
        // SAFETY: `cur` is non-null and points to a live, valid node here; `contenttype` is a `Copy` value read out before the node is freed.
        let contenttype = unsafe { (*cur).contenttype };
        // SAFETY: `cur` is non-null and points to a live, valid node here; `showfilename` is a `Copy` value read out before the node is freed.
        let showfilename = unsafe { (*cur).showfilename };

        if !more.is_null() {
            // SAFETY: `more` is a live sub-chain owned by this node.
            unsafe { free_post_chain(more) };
        }
        if (flags & CURL_HTTPPOST_PTRNAME) == 0 {
            // SAFETY: an owned (non-PTRNAME) name copy.
            unsafe { free_owned(name) };
        }
        if (flags & (CURL_HTTPPOST_PTRCONTENTS | CURL_HTTPPOST_BUFFER | CURL_HTTPPOST_CALLBACK))
            == 0
        {
            // SAFETY: an owned (non-pointer/buffer/callback) contents copy.
            unsafe { free_owned(contents) };
        }
        // SAFETY: content type and show filename are always owned copies.
        unsafe {
            free_owned(contenttype);
            free_owned(showfilename);
            // Free the node struct itself.
            libc::free(cur as *mut c_void);
        }
        cur = next;
    }
}

/// `void curl_formfree(struct curl_httppost *form)` — free a form post chain
/// previously built by [`curl_formadd`]. A NULL `form` is a no-op.
///
/// # Safety
///
/// `form` must be NULL or a chain built by [`curl_formadd`] that the caller owns
/// and has not already freed.
#[no_mangle]
pub unsafe extern "C" fn curl_formfree(form: *mut curl_httppost) {
    if form.is_null() {
        // A NULL list is an explicit no-op, matching `lib/formdata.c`.
        return;
    }
    // SAFETY: `form` is a caller-owned chain built by this crate.
    unsafe { free_post_chain(form) };
}

/// Convert a C `curl_httppost` chain into the core [`core::mime::HttpPost`]
/// representation that [`core::mime::form_get`] serializes. Each node's owned
/// bytes are copied; the borrowed `contentheader` slist is deep-copied; `more`
/// and `next` are translated recursively.
///
/// Callback (`CURL_HTTPPOST_CALLBACK`) parts have no standalone bytes — the data
/// is produced by the easy handle's `CURLOPT_READFUNCTION` at transfer time. When
/// `fread_func` is `Some` (the live-transfer path, [`httppost_chain_to_body`]),
/// such a part is given a [`CCallbackReader`] that streams its body from that
/// callback using the node's `userp` as the opaque arg — exactly curl's
/// `Curl_getformdata` wiring
/// (`curl_mime_data_cb(part, clen, fread_func, NULL, NULL, post->userp)`,
/// lib/formdata.c). When `fread_func` is `None` (the standalone `curl_formget`
/// serializer, which has no attached handle / read function) the callback body is
/// left empty, matching what curl can produce without a handle.
///
/// # Safety
///
/// `c` must be NULL or a valid `curl_httppost` chain (each owned string a valid
/// C string / buffer of the stated length). When `fread_func` is `Some`, it must
/// be safe to call with each callback node's `userp` for the duration of the
/// serialization driven by the caller.
unsafe fn c_post_to_core(
    c: *const curl_httppost,
    fread_func: curl_read_callback,
) -> Option<Box<core::mime::HttpPost>> {
    if c.is_null() {
        return None;
    }
    // SAFETY: `c` is a live node per the contract.
    let cn = unsafe { &*c };

    let is_file = (cn.flags & (CURL_HTTPPOST_FILENAME | CURL_HTTPPOST_READFILE)) != 0;
    let is_buffer = (cn.flags & CURL_HTTPPOST_BUFFER) != 0;
    let is_callback = (cn.flags & CURL_HTTPPOST_CALLBACK) != 0;
    let is_large = (cn.flags & CURL_HTTPPOST_LARGE) != 0;

    // Seed the scalar fields known up front; the byte buffers are filled in
    // conditionally below. `i64::from` (not `as i64`) keeps this correct on
    // targets where `c_long` is 32-bit (Windows / ILP32) while staying a no-op
    // where `c_long` is already 64-bit — and avoids the same-type-cast lint.
    let mut hp = core::mime::HttpPost {
        flags: cn.flags as u32,
        contentslength: clong_to_i64(cn.contentslength),
        contentlen: cn.contentlen,
        ..Default::default()
    };

    // name
    if !cn.name.is_null() {
        let nl = if cn.namelength > 0 {
            cn.namelength as usize
        } else {
            // SAFETY: `cn.name` is a valid C string when non-NULL.
            unsafe { libc::strlen(cn.name) }
        };
        // SAFETY: `cn.name` has at least `nl` readable bytes.
        hp.name = unsafe { slice::from_raw_parts(cn.name as *const u8, nl) }.to_vec();
        hp.namelength = nl;
    }

    // body bytes, selected by the part kind
    if is_file {
        // `contents` is a filename string for FILE / FILECONTENT parts.
        if !cn.contents.is_null() {
            // SAFETY: a valid C string.
            let len = unsafe { libc::strlen(cn.contents) };
            // SAFETY: `len` readable bytes.
            hp.contents =
                Some(unsafe { slice::from_raw_parts(cn.contents as *const u8, len) }.to_vec());
        }
    } else if is_buffer {
        if !cn.buffer.is_null() {
            let n = if cn.bufferlength > 0 {
                cn.bufferlength as usize
            } else {
                0
            };
            hp.bufferlength = n;
            // SAFETY: `cn.buffer` has at least `n` readable bytes.
            hp.buffer = Some(unsafe { slice::from_raw_parts(cn.buffer as *const u8, n) }.to_vec());
        }
    } else if is_callback {
        // A `CURL_HTTPPOST_CALLBACK` part (a `CURLFORM_STREAM` field) carries no
        // standalone bytes. On the live-transfer path `fread_func` is the easy
        // handle's `CURLOPT_READFUNCTION`, so attach a reader that streams the
        // body from that callback with this node's `userp` as the opaque arg —
        // exactly curl's `Curl_getformdata`, which converts such a part via
        // `curl_mime_data_cb(part, clen, fread_func, NULL, NULL, post->userp)`
        // (lib/formdata.c L811-817; the seek/free callbacks are NULL there too).
        // The declared size (`contentslength`/`contentlen`) is applied to the
        // part later by `apply_fill`. With `fread_func == None` (standalone
        // `curl_formget`) the body is left empty, as before.
        if fread_func.is_some() {
            hp.reader = Some(Box::new(CCallbackReader {
                readfunc: fread_func,
                seekfunc: None,
                freefunc: None,
                arg: cn.userp,
            }));
        }
    } else if !cn.contents.is_null() {
        // Plain data: length from `contentlen` when LARGE, else `contentslength`,
        // else strlen.
        let declared = if is_large {
            cn.contentlen
        } else {
            clong_to_i64(cn.contentslength)
        };
        let n = if declared > 0 {
            declared as usize
        } else {
            // SAFETY: a valid C string.
            unsafe { libc::strlen(cn.contents) }
        };
        // SAFETY: `cn.contents` has at least `n` readable bytes.
        hp.contents = Some(unsafe { slice::from_raw_parts(cn.contents as *const u8, n) }.to_vec());
    }

    // content type
    if !cn.contenttype.is_null() {
        // SAFETY: a valid C string.
        hp.contenttype = Some(
            unsafe { CStr::from_ptr(cn.contenttype) }
                .to_bytes()
                .to_vec(),
        );
    }
    // show filename
    if !cn.showfilename.is_null() {
        // SAFETY: a valid C string.
        hp.showfilename = Some(
            unsafe { CStr::from_ptr(cn.showfilename) }
                .to_bytes()
                .to_vec(),
        );
    }
    // borrowed per-part headers → owned deep copy
    if !cn.contentheader.is_null() {
        // SAFETY: a valid, caller-owned `curl_slist` chain (read only).
        hp.contentheader = Some(unsafe { crate::slist::raw_to_core(cn.contentheader) });
    }

    // recurse into the additional files and the next sibling (threading the
    // same read function so every callback part in the chain is wired alike).
    // SAFETY: `more`/`next` are NULL or live sub-chains.
    hp.more = unsafe { c_post_to_core(cn.more, fread_func) };
    // SAFETY: `cn.next` is NULL or a live `curl_httppost` sub-chain owned by this crate (read only).
    hp.next = unsafe { c_post_to_core(cn.next, fread_func) };

    Some(Box::new(hp))
}

/// Serialize a stored `CURLOPT_HTTPPOST` legacy form chain into an owned
/// `multipart/form-data` request body and its boundary-bearing `Content-Type`,
/// the memory-safe FFI equivalent of curl's `Curl_getformdata` + mime readback
/// performed at transfer time (`lib/formdata.c`; `lib/http.c` `HTTPREQ_POST_FORM`).
///
/// The `#![forbid(unsafe_code)]` core stores `CURLOPT_HTTPPOST` only as an opaque
/// address it cannot dereference, so — exactly as the CLI's `-F` handler eagerly
/// serializes its MIME tree and hands the core an owned body via
/// `Easy::set_mime_body` — the FFI walks the C `curl_httppost` chain here, at
/// perform time, into a [`core::mime::Mime`], reads it back into the finished
/// multipart body, and announces the matching `multipart/form-data; boundary=…`
/// `Content-Type`. `CURL_HTTPPOST_CALLBACK` (`CURLFORM_STREAM`) parts are streamed
/// from the easy handle's `CURLOPT_READFUNCTION` (`read_fn_addr`) with each node's
/// `userp` as the opaque arg (see [`c_post_to_core`]); the produced bytes — and
/// thus the wire — are byte-for-byte identical to curl's, differing only in the
/// body's memory ownership (the AAP G1 mandate). The boundary is read with
/// [`boundary_str`](core::mime::Mime::boundary_str) *before*
/// [`into_form_body`](core::mime::Mime::into_form_body) consumes the tree, so the
/// announced `boundary=` parameter matches the delimiter framing the body.
///
/// Returns the `(body, content_type)` pair, or `None` when `chain` is `0`
/// (unset) or serialization fails (a callback abort / read error / boundary RNG
/// failure), in which case the caller leaves the body unmaterialized.
///
/// # Safety
///
/// `chain`, when non-zero, must be a live `curl_httppost` chain (each owned
/// string a valid C string / buffer of the stated length). `read_fn_addr`, when
/// non-zero, must be a `curl_read_callback` address (stored by
/// `curl_easy_setopt(CURLOPT_READFUNCTION, …)`) safe to call with each callback
/// part's `userp` for the duration of this serialization.
pub(crate) unsafe fn httppost_chain_to_body(
    chain: usize,
    read_fn_addr: usize,
) -> Option<(Vec<u8>, String)> {
    if chain == 0 {
        return None;
    }
    // The easy handle's `CURLOPT_READFUNCTION` drives `CURL_HTTPPOST_CALLBACK`
    // parts (curl's `data->set.fread_func`). A `0` address (never set) → `None`,
    // so callback parts serialize empty (curl behaves the same with no reader).
    let fread_func: curl_read_callback = if read_fn_addr == 0 {
        None
    } else {
        // SAFETY: `read_fn_addr` is a `curl_read_callback` previously stored by
        // `curl_easy_setopt(CURLOPT_READFUNCTION, …)`, so its ABI matches the
        // transmuted signature (the same transmute the upload `CReadBridge`
        // performs on this very field in `easy.rs`).
        Some(unsafe {
            std::mem::transmute::<
                usize,
                unsafe extern "C" fn(*mut c_char, size_t, size_t, *mut c_void) -> size_t,
            >(read_fn_addr)
        })
    };
    // SAFETY: per this function's contract `chain` is a live `curl_httppost`
    // chain and `fread_func` is safe to call with each callback node's `userp`.
    let mut hp = unsafe { c_post_to_core(chain as *const curl_httppost, fread_func) }?;
    // Build the MIME tree from the chain, then read it back into the finished
    // body — the same `httppost_to_mime` + `into_form_body` path `curl_formget`
    // uses, so the encoded parts match curl byte-for-byte.
    let mime = core::mime::httppost_to_mime(&mut hp).ok()?;
    let boundary = String::from_utf8_lossy(mime.boundary_str()).into_owned();
    let content_type = format!("multipart/form-data; boundary={boundary}");
    let body = mime.into_form_body().ok()?;
    Some((body, content_type))
}

/// `int curl_formget(struct curl_httppost *form, void *arg, curl_formget_callback
/// append)` — serialize a form post to `multipart/form-data` bytes, delivering
/// them to `append(arg, buf, len)` in chunks. Returns `0` on success and a
/// nonzero `CURLcode` on failure. Serialization is synchronous (no runtime
/// bridge needed). Mirrors `curl_formget` in `lib/formdata.c`.
///
/// # Safety
///
/// `form` must be NULL or a valid `curl_httppost` chain; `append`, when present,
/// must be safe to call with `arg` and a `(ptr, len)` chunk.
#[no_mangle]
pub unsafe extern "C" fn curl_formget(
    form: *mut curl_httppost,
    arg: *mut c_void,
    append: curl_formget_callback,
) -> c_int {
    let appendfn = match append {
        Some(f) => f,
        // curl returns CURLE_BAD_FUNCTION_ARGUMENT for a NULL append callback.
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
    };
    if form.is_null() {
        // Nothing to serialize.
        return 0;
    }

    // SAFETY: `form` is a valid chain per the contract. `None` read function:
    // `curl_formget` is a standalone serializer with no attached easy handle, so
    // any `CURL_HTTPPOST_CALLBACK` part serializes with an empty body (curl
    // likewise cannot read callback data without a transfer).
    let mut head = match unsafe { c_post_to_core(form, None) } {
        Some(h) => h,
        None => return 0,
    };

    let bytes = match core::mime::form_get(&mut head) {
        Ok(b) => b,
        Err(e) => return CURLcode::from(e) as c_int,
    };

    // Deliver in 8 KiB chunks, matching curl's serialization buffer size.
    let total = bytes.len();
    let mut off = 0usize;
    while off < total {
        let n = std::cmp::min(8192usize, total - off);
        // SAFETY: `bytes[off..]` is a valid readable slice of at least `n` bytes;
        // the callback consumes exactly `n` and returns the count it accepted.
        let written = unsafe { appendfn(arg, bytes[off..].as_ptr() as *const c_char, n) };
        if written != n {
            // A short write is a serialization read failure, as in curl.
            return CURLcode::CURLE_READ_ERROR as c_int;
        }
        off += n;
    }
    0
}

// =============================================================================
// Tests
//
// These exercise the FFI boundary directly (calling the `extern "C"` entrypoints
// the way a C consumer would): handle lifecycle and NULL-safety, every part
// setter's success and bad-argument paths, the callback-body Drop/`freefunc`
// contract, the subparts ownership transfer, the header copy-vs-own split, and
// the full `curl_formadd` (via the non-variadic `curlrs_formadd_impl` the C
// trampoline calls) -> `curl_formget` -> `curl_formfree` round trip, including
// the documented `CURLFORMcode` error returns. Allocation/free balance and the
// absence of double-frees are additionally covered by the ASan FFI gate
// (AAP §0.8.1); here we assert observable behavior and that the ownership
// contracts hold.
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    // --- small helpers -------------------------------------------------------

    /// A NUL-terminated C-string pointer into a borrowed byte literal. The bytes
    /// must include their own trailing `\0` and outlive the call.
    fn cptr(bytes: &[u8]) -> *const c_char {
        debug_assert_eq!(
            bytes.last(),
            Some(&0),
            "test C strings must be NUL-terminated"
        );
        bytes.as_ptr() as *const c_char
    }

    /// Naive substring search for structural assertions on serialized bodies
    /// whose multipart boundary is random.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// `curl_formget` append callback: accumulate the delivered bytes into the
    /// `Vec<u8>` passed via `arg`, accepting every byte (returning `len`).
    unsafe extern "C" fn collect_append(
        arg: *mut c_void,
        buf: *const c_char,
        len: size_t,
    ) -> size_t {
        // SAFETY: `arg` is the `&mut Vec<u8>` the test handed to curl_formget;
        // `buf`/`len` describe a readable chunk per the callback contract.
        let sink = unsafe { &mut *(arg as *mut Vec<u8>) };
        // SAFETY: `buf as *const u8` points to at least `len` initialized, readable bytes for the duration of the borrow.
        let chunk = unsafe { slice::from_raw_parts(buf as *const u8, len) };
        sink.extend_from_slice(chunk);
        len
    }

    // --- MIME lifecycle ------------------------------------------------------

    #[test]
    fn mime_init_addpart_free_lifecycle() {
        let mime = curl_mime_init(ptr::null_mut());
        assert!(!mime.is_null(), "curl_mime_init must yield a handle");

        // SAFETY: `mime` is a live handle from curl_mime_init.
        let p1 = unsafe { curl_mime_addpart(mime) };
        assert!(!p1.is_null(), "first addpart must succeed");
        // SAFETY: same live handle.
        let p2 = unsafe { curl_mime_addpart(mime) };
        assert!(!p2.is_null(), "second addpart must succeed");
        assert_ne!(p1, p2, "each part must be a distinct object");

        // The first part's address stays stable after a second addpart (the core
        // stores parts as `Vec<Box<MimePart>>`), so p1 is still usable.
        // SAFETY: p1 is owned by `mime` and not freed.
        let rc = unsafe { curl_mime_name(p1, cptr(b"still-valid\0")) };
        assert_eq!(rc, CURLcode::CURLE_OK);

        // SAFETY: reclaim the whole tree exactly once.
        unsafe { curl_mime_free(mime) };
    }

    #[test]
    fn mime_addpart_null_mime_is_null() {
        // SAFETY: NULL is an explicitly handled input.
        let p = unsafe { curl_mime_addpart(ptr::null_mut()) };
        assert!(p.is_null());
    }

    #[test]
    fn mime_free_null_is_noop() {
        // SAFETY: NULL free must be a no-op (must not crash).
        unsafe { curl_mime_free(ptr::null_mut()) };
    }

    // --- setters: success + NULL-part bad-argument ---------------------------

    #[test]
    fn mime_setters_success() {
        let mime = curl_mime_init(ptr::null_mut());
        // SAFETY: live handle.
        let part = unsafe { curl_mime_addpart(mime) };
        assert!(!part.is_null());

        // SAFETY: `part` is owned by `mime`; the C strings are NUL-terminated.
        unsafe {
            assert_eq!(curl_mime_name(part, cptr(b"field\0")), CURLcode::CURLE_OK);
            assert_eq!(
                curl_mime_filename(part, cptr(b"file.txt\0")),
                CURLcode::CURLE_OK
            );
            assert_eq!(
                curl_mime_type(part, cptr(b"text/plain\0")),
                CURLcode::CURLE_OK
            );
            assert_eq!(
                curl_mime_encoder(part, cptr(b"base64\0")),
                CURLcode::CURLE_OK
            );
            // Explicit length.
            assert_eq!(
                curl_mime_data(part, cptr(b"hello\0"), 5),
                CURLcode::CURLE_OK
            );
            // CURL_ZERO_TERMINATED => measure with strlen.
            assert_eq!(
                curl_mime_data(part, cptr(b"hello world\0"), CURL_ZERO_TERMINATED),
                CURLcode::CURLE_OK
            );
        }
        // SAFETY: free once.
        unsafe { curl_mime_free(mime) };
    }

    #[test]
    fn mime_name_null_clears() {
        let mime = curl_mime_init(ptr::null_mut());
        // SAFETY: live handle.
        let part = unsafe { curl_mime_addpart(mime) };
        // SAFETY: set then clear the name.
        unsafe {
            assert_eq!(curl_mime_name(part, cptr(b"x\0")), CURLcode::CURLE_OK);
            assert_eq!(curl_mime_name(part, ptr::null()), CURLcode::CURLE_OK);
        }
        // SAFETY: free once.
        unsafe { curl_mime_free(mime) };
    }

    #[test]
    fn mime_setters_null_part_bad_argument() {
        let n = ptr::null_mut();
        // SAFETY: every setter must reject a NULL part with CURLE_BAD_FUNCTION_ARGUMENT.
        unsafe {
            assert_eq!(
                curl_mime_name(n, cptr(b"a\0")),
                CURLcode::CURLE_BAD_FUNCTION_ARGUMENT
            );
            assert_eq!(
                curl_mime_filename(n, cptr(b"a\0")),
                CURLcode::CURLE_BAD_FUNCTION_ARGUMENT
            );
            assert_eq!(
                curl_mime_type(n, cptr(b"a\0")),
                CURLcode::CURLE_BAD_FUNCTION_ARGUMENT
            );
            assert_eq!(
                curl_mime_encoder(n, cptr(b"base64\0")),
                CURLcode::CURLE_BAD_FUNCTION_ARGUMENT
            );
            assert_eq!(
                curl_mime_data(n, cptr(b"a\0"), 1),
                CURLcode::CURLE_BAD_FUNCTION_ARGUMENT
            );
            assert_eq!(
                curl_mime_filedata(n, cptr(b"a\0")),
                CURLcode::CURLE_BAD_FUNCTION_ARGUMENT
            );
            assert_eq!(
                curl_mime_subparts(n, ptr::null_mut()),
                CURLcode::CURLE_BAD_FUNCTION_ARGUMENT
            );
            assert_eq!(
                curl_mime_headers(n, ptr::null_mut(), 0),
                CURLcode::CURLE_BAD_FUNCTION_ARGUMENT
            );
            assert_eq!(
                curl_mime_data_cb(n, 0, None, None, None, ptr::null_mut()),
                CURLcode::CURLE_BAD_FUNCTION_ARGUMENT
            );
        }
    }

    #[test]
    fn mime_encoder_invalid_is_bad_argument() {
        let mime = curl_mime_init(ptr::null_mut());
        // SAFETY: live handle.
        let part = unsafe { curl_mime_addpart(mime) };
        // SAFETY: an unknown encoder name must be rejected (not OK).
        let rc = unsafe { curl_mime_encoder(part, cptr(b"no-such-encoding\0")) };
        assert_eq!(rc, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT);
        // SAFETY: free once.
        unsafe { curl_mime_free(mime) };
    }

    // --- data_cb Drop / freefunc contract ------------------------------------

    /// A read callback that always signals EOF.
    unsafe extern "C" fn eof_read(
        _buf: *mut c_char,
        _size: size_t,
        _nitems: size_t,
        _instream: *mut c_void,
    ) -> size_t {
        0
    }

    /// A free callback that bumps the `AtomicU32` counter pointed to by `arg`.
    unsafe extern "C" fn counting_free(arg: *mut c_void) {
        // SAFETY: `arg` is the `&AtomicU32` the test installed; it outlives the
        // free call (the test reclaims it afterwards).
        let counter = unsafe { &*(arg as *const AtomicU32) };
        counter.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn mime_data_cb_freefunc_runs_exactly_once_on_free() {
        // Heap counter delivered to the callbacks via `arg`; kept alive past the
        // free so we can read it, then reclaimed by the test.
        let counter: *mut AtomicU32 = Box::into_raw(Box::new(AtomicU32::new(0)));

        let mime = curl_mime_init(ptr::null_mut());
        // SAFETY: live handle.
        let part = unsafe { curl_mime_addpart(mime) };
        // SAFETY: install a callback body; `arg` points at the live counter.
        let rc = unsafe {
            curl_mime_data_cb(
                part,
                -1,
                Some(eof_read),
                None,
                Some(counting_free),
                counter as *mut c_void,
            )
        };
        assert_eq!(rc, CURLcode::CURLE_OK);

        // Freeing the mime drops the part, which drops the CCallbackReader,
        // which must invoke `freefunc` exactly once.
        // SAFETY: free once.
        unsafe { curl_mime_free(mime) };

        // SAFETY: the counter box is still alive (counting_free does not free it).
        let calls = unsafe { (*counter).load(Ordering::SeqCst) };
        assert_eq!(calls, 1, "freefunc must run exactly once on part drop");

        // SAFETY: reclaim the counter box exactly once.
        drop(unsafe { Box::from_raw(counter) });
    }

    // --- subparts ownership transfer -----------------------------------------

    #[test]
    fn mime_subparts_transfer_then_detach() {
        let parent = curl_mime_init(ptr::null_mut());
        // SAFETY: live handle.
        let ppart = unsafe { curl_mime_addpart(parent) };

        let child = curl_mime_init(ptr::null_mut());
        // SAFETY: live child handle.
        let cpart = unsafe { curl_mime_addpart(child) };
        // SAFETY: configure the child part.
        unsafe {
            assert_eq!(curl_mime_name(cpart, cptr(b"inner\0")), CURLcode::CURLE_OK);
            assert_eq!(
                curl_mime_data(cpart, cptr(b"body\0"), 4),
                CURLcode::CURLE_OK
            );
        }

        // Ownership transfer: `child` is consumed by `ppart`.
        // SAFETY: both live; child not previously attached.
        let rc = unsafe { curl_mime_subparts(ppart, child) };
        assert_eq!(rc, CURLcode::CURLE_OK);

        // Verify via the internal reborrow helper that the part now owns a child.
        // SAFETY: `ppart` is owned by `parent` and still valid.
        let has_child = unsafe { part_ref(ppart) }
            .expect("ppart is non-NULL")
            .subparts()
            .is_some();
        assert!(has_child, "subparts must be attached after transfer");

        // Detach with NULL subparts.
        // SAFETY: `ppart` still valid; NULL detaches.
        let rc = unsafe { curl_mime_subparts(ppart, ptr::null_mut()) };
        assert_eq!(rc, CURLcode::CURLE_OK);
        // SAFETY: re-inspect.
        let detached = unsafe { part_ref(ppart) }
            .expect("ppart is non-NULL")
            .subparts()
            .is_none();
        assert!(detached, "subparts must be cleared after NULL detach");

        // `child` was consumed by the (now-undone) transfer; we must NOT free it
        // separately. Freeing only the parent reclaims everything still attached.
        // SAFETY: free the parent once.
        unsafe { curl_mime_free(parent) };
    }

    // --- headers copy vs. take-ownership -------------------------------------

    #[test]
    fn mime_headers_copy_and_take_ownership() {
        // take_ownership = 0 (copy): the caller still owns and frees the list.
        let mime = curl_mime_init(ptr::null_mut());
        // SAFETY: live handle.
        let part = unsafe { curl_mime_addpart(mime) };
        // SAFETY: build a one-element slist owned by the test.
        let list =
            unsafe { crate::slist::curl_slist_append(ptr::null_mut(), cptr(b"X-Test: 1\0")) };
        assert!(!list.is_null());
        // SAFETY: copy semantics — part keeps its own deep copy.
        let rc = unsafe { curl_mime_headers(part, list, 0) };
        assert_eq!(rc, CURLcode::CURLE_OK);
        // Caller still owns `list`; free it (the part copy is independent).
        // SAFETY: free the caller-owned list once.
        unsafe { crate::slist::curl_slist_free_all(list) };
        // SAFETY: free the mime (drops the part's copied headers).
        unsafe { curl_mime_free(mime) };

        // take_ownership = 1: the call assumes ownership of the original list, so
        // the test must NOT free it afterwards.
        let mime2 = curl_mime_init(ptr::null_mut());
        // SAFETY: live handle.
        let part2 = unsafe { curl_mime_addpart(mime2) };
        // SAFETY: build a list to hand over.
        let owned =
            unsafe { crate::slist::curl_slist_append(ptr::null_mut(), cptr(b"X-Owned: yes\0")) };
        assert!(!owned.is_null());
        // SAFETY: ownership transfer.
        let rc = unsafe { curl_mime_headers(part2, owned, 1) };
        assert_eq!(rc, CURLcode::CURLE_OK);
        // Do NOT free `owned`. Freeing the mime reclaims everything.
        // SAFETY: free the mime once.
        unsafe { curl_mime_free(mime2) };

        // Clearing headers with a NULL list is accepted.
        let mime3 = curl_mime_init(ptr::null_mut());
        // SAFETY: live handle.
        let part3 = unsafe { curl_mime_addpart(mime3) };
        // SAFETY: NULL clears.
        let rc = unsafe { curl_mime_headers(part3, ptr::null_mut(), 0) };
        assert_eq!(rc, CURLcode::CURLE_OK);
        // SAFETY: free once.
        unsafe { curl_mime_free(mime3) };
    }

    // --- deprecated form API: round trip + error returns ---------------------

    #[test]
    fn formadd_formget_formfree_roundtrip() {
        let name = b"field1\0";
        let value = b"value1\0";
        let forms = [
            curl_forms {
                option: CURLFORM_COPYNAME,
                value: cptr(name),
            },
            curl_forms {
                option: CURLFORM_COPYCONTENTS,
                value: cptr(value),
            },
            curl_forms {
                option: CURLFORM_END,
                value: ptr::null(),
            },
        ];

        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();
        // SAFETY: valid out-pointers; `forms` has 3 readable entries.
        let rc = unsafe { curlrs_formadd_impl(&mut post, &mut last, forms.as_ptr(), forms.len()) };
        assert_eq!(rc, CURLFORMcode::CURL_FORMADD_OK);
        assert!(!post.is_null(), "a node must be linked on success");

        // Serialize via curl_formget into a Vec and check the field round-trips.
        let mut sink: Vec<u8> = Vec::new();
        // SAFETY: `post` is a live chain; `collect_append` accepts all bytes.
        let got = unsafe {
            curl_formget(
                post,
                &mut sink as *mut Vec<u8> as *mut c_void,
                Some(collect_append),
            )
        };
        assert_eq!(got, 0, "curl_formget must report success");
        assert!(!sink.is_empty(), "serialization must produce bytes");
        assert!(
            contains(&sink, b"name=\"field1\""),
            "the field name must appear in the multipart body"
        );
        assert!(
            contains(&sink, b"value1"),
            "the field contents must appear in the multipart body"
        );

        // SAFETY: free the whole chain exactly once.
        unsafe { curl_formfree(post) };
    }

    #[test]
    fn formadd_ptrcontents_with_length_roundtrips() {
        // PTRCONTENTS borrows the data; the buffer must outlive curl_formget and
        // must NOT be freed by curl_formfree (its PTRCONTENTS flag is respected).
        let name = b"pn\0";
        let body = b"PTRBODY"; // not NUL-terminated on purpose; length is explicit
        let forms = [
            curl_forms {
                option: CURLFORM_COPYNAME,
                value: cptr(name),
            },
            curl_forms {
                option: CURLFORM_PTRCONTENTS,
                value: body.as_ptr() as *const c_char,
            },
            curl_forms {
                option: CURLFORM_CONTENTSLENGTH,
                // length carried in the pointer slot, exactly as the trampoline does
                value: body.len() as *const c_char,
            },
            curl_forms {
                option: CURLFORM_END,
                value: ptr::null(),
            },
        ];

        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();
        // SAFETY: valid out-pointers; 4 readable entries.
        let rc = unsafe { curlrs_formadd_impl(&mut post, &mut last, forms.as_ptr(), forms.len()) };
        assert_eq!(rc, CURLFORMcode::CURL_FORMADD_OK);
        assert!(!post.is_null());

        let mut sink: Vec<u8> = Vec::new();
        // SAFETY: live chain.
        let got = unsafe {
            curl_formget(
                post,
                &mut sink as *mut Vec<u8> as *mut c_void,
                Some(collect_append),
            )
        };
        assert_eq!(got, 0);
        assert!(
            contains(&sink, b"PTRBODY"),
            "PTRCONTENTS body must round-trip"
        );

        // SAFETY: free the chain; the borrowed `body` is left untouched.
        unsafe { curl_formfree(post) };
    }

    #[test]
    fn formadd_null_post_pointer_is_null_error() {
        let forms = [curl_forms {
            option: CURLFORM_END,
            value: ptr::null(),
        }];
        let mut last: *mut curl_httppost = ptr::null_mut();
        // SAFETY: NULL httppost out-pointer must be rejected.
        let rc =
            unsafe { curlrs_formadd_impl(ptr::null_mut(), &mut last, forms.as_ptr(), forms.len()) };
        assert_eq!(rc, CURLFORMcode::CURL_FORMADD_NULL);
    }

    #[test]
    fn formadd_incomplete_when_name_only() {
        let name = b"orphan\0";
        let forms = [
            curl_forms {
                option: CURLFORM_COPYNAME,
                value: cptr(name),
            },
            curl_forms {
                option: CURLFORM_END,
                value: ptr::null(),
            },
        ];
        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();
        // SAFETY: valid out-pointers.
        let rc = unsafe { curlrs_formadd_impl(&mut post, &mut last, forms.as_ptr(), forms.len()) };
        assert_eq!(rc, CURLFORMcode::CURL_FORMADD_INCOMPLETE);
        assert!(
            post.is_null(),
            "nothing must be linked on an incomplete add"
        );
    }

    #[test]
    fn formadd_option_twice_is_rejected() {
        let a = b"a\0";
        let b = b"b\0";
        let forms = [
            curl_forms {
                option: CURLFORM_COPYNAME,
                value: cptr(a),
            },
            curl_forms {
                option: CURLFORM_COPYNAME,
                value: cptr(b),
            },
            curl_forms {
                option: CURLFORM_END,
                value: ptr::null(),
            },
        ];
        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();
        // SAFETY: valid out-pointers.
        let rc = unsafe { curlrs_formadd_impl(&mut post, &mut last, forms.as_ptr(), forms.len()) };
        assert_eq!(rc, CURLFORMcode::CURL_FORMADD_OPTION_TWICE);
        assert!(post.is_null());
    }

    #[test]
    fn formadd_unknown_option_is_rejected() {
        let forms = [
            curl_forms {
                option: 9999, // not a valid CURLformoption
                value: ptr::null(),
            },
            curl_forms {
                option: CURLFORM_END,
                value: ptr::null(),
            },
        ];
        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();
        // SAFETY: valid out-pointers.
        let rc = unsafe { curlrs_formadd_impl(&mut post, &mut last, forms.as_ptr(), forms.len()) };
        assert_eq!(rc, CURLFORMcode::CURL_FORMADD_UNKNOWN_OPTION);
        assert!(post.is_null());
    }

    #[test]
    fn formget_null_append_is_bad_argument() {
        // Build a valid single-field post first.
        let name = b"f\0";
        let value = b"v\0";
        let forms = [
            curl_forms {
                option: CURLFORM_COPYNAME,
                value: cptr(name),
            },
            curl_forms {
                option: CURLFORM_COPYCONTENTS,
                value: cptr(value),
            },
            curl_forms {
                option: CURLFORM_END,
                value: ptr::null(),
            },
        ];
        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();
        // SAFETY: valid out-pointers.
        let rc = unsafe { curlrs_formadd_impl(&mut post, &mut last, forms.as_ptr(), forms.len()) };
        assert_eq!(rc, CURLFORMcode::CURL_FORMADD_OK);

        // NULL append callback => CURLE_BAD_FUNCTION_ARGUMENT (43).
        // SAFETY: live chain; NULL callback is the tested input.
        let got = unsafe { curl_formget(post, ptr::null_mut(), None) };
        assert_eq!(got, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int);

        // SAFETY: free once.
        unsafe { curl_formfree(post) };
    }

    #[test]
    fn formget_null_form_is_success_noop() {
        // SAFETY: a NULL form serializes to nothing and returns 0.
        let got = unsafe { curl_formget(ptr::null_mut(), ptr::null_mut(), Some(collect_append)) };
        assert_eq!(got, 0);
    }

    #[test]
    fn formfree_null_is_noop() {
        // SAFETY: NULL free must be a no-op.
        unsafe { curl_formfree(ptr::null_mut()) };
    }
}
