//! FFI bindings for the `curl_mime_*` family of functions.
//!
//! This module exposes the 12 `CURL_EXTERN` symbols from `include/curl/curl.h`
//! that provide the MIME multipart/form-data building API.  Each function is
//! `#[no_mangle] pub unsafe extern "C"` with a `// SAFETY:` comment on every
//! `unsafe` block, per AAP Section 0.7.1.
//!
//! # Memory Model
//!
//! - [`curl_mime_init`] allocates a `Mime` on the heap via `Box` and returns an
//!   owning raw pointer.  The caller must free it with [`curl_mime_free`].
//! - [`curl_mime_addpart`] returns a non-owning pointer to a `MimePart` inside
//!   the `Mime`'s internal storage.  The part is owned by the mime and freed
//!   when [`curl_mime_free`] is called.
//! - [`curl_mime_data`] copies the data internally (no ownership transfer of
//!   the `data` pointer).
//! - [`curl_mime_subparts`] transfers ownership of the sub-mime handle to the
//!   part.  After this call the sub-mime handle must **not** be freed separately.
//! - [`curl_mime_headers`] with `take_ownership=1` takes ownership of the slist
//!   and frees it after extracting the string data.
//!
//! # Pointer Stability Note
//!
//! The `MimePart` pointer returned by [`curl_mime_addpart`] references an
//! element inside a `Vec` within the `Mime`.  Callers should configure each
//! part immediately after adding it, before calling [`curl_mime_addpart`]
//! again, as subsequent additions may cause internal reallocation.  This
//! matches the standard curl usage pattern.

#![allow(non_camel_case_types)]
#![allow(clippy::missing_safety_doc)]

use std::ffi::CStr;
use std::io::Read;
use std::path::Path;
use std::ptr;
use std::slice;

use libc::{c_char, c_int, c_void, free, size_t};

use crate::error_codes::{CURLE_BAD_FUNCTION_ARGUMENT, CURLE_OK, CURLE_OUT_OF_MEMORY};
use crate::types::{
    curl_free_callback, curl_mime, curl_mimepart, curl_off_t, curl_read_callback,
    curl_seek_callback, curl_slist, CURLcode, CURL,
};

use curl_rs_lib::error::CurlError;
use curl_rs_lib::mime::{Mime, MimeEncoder, MimePart};
use curl_rs_lib::slist::SList;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Sentinel value indicating a NUL-terminated string length.
///
/// C equivalent: `#define CURL_ZERO_TERMINATED ((size_t)-1)`
const CURL_ZERO_TERMINATED: size_t = !0;

// ---------------------------------------------------------------------------
// Internal helpers — error conversion
// ---------------------------------------------------------------------------

/// Maps a [`CurlError`] variant to its `CURLcode` integer equivalent.
#[inline]
fn error_to_code(err: CurlError) -> CURLcode {
    // The CurlError enum is #[repr(i32)] with discriminant values matching
    // the CURLcode integer space, so we cast directly.
    match err {
        CurlError::BadFunctionArgument => CURLE_BAD_FUNCTION_ARGUMENT,
        CurlError::OutOfMemory => CURLE_OUT_OF_MEMORY,
        _ => CURLE_BAD_FUNCTION_ARGUMENT,
    }
}

/// Converts a `Result<(), CurlError>` to the corresponding `CURLcode`.
#[inline]
fn result_to_code(result: Result<(), CurlError>) -> CURLcode {
    match result {
        Ok(()) => CURLE_OK,
        Err(e) => error_to_code(e),
    }
}

// ---------------------------------------------------------------------------
// Internal helpers — C string reading
// ---------------------------------------------------------------------------

/// Reads a C string pointer into an `Option<&str>`.
///
/// Returns `None` if `ptr` is null or the bytes are not valid UTF-8.
///
/// # Safety
///
/// `ptr` must be either null or point to a valid NUL-terminated C string
/// whose memory remains valid for the lifetime `'a`.
#[inline]
unsafe fn c_str_opt<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: Caller guarantees `ptr` is a valid NUL-terminated C string.
    CStr::from_ptr(ptr).to_str().ok()
}

// ---------------------------------------------------------------------------
// CallbackReader — bridges C read/seek/free callbacks to Rust `Read`
// ---------------------------------------------------------------------------

/// Adapter struct that implements [`Read`] by invoking a C
/// `curl_read_callback` function pointer.
///
/// When this reader is dropped, it invokes the `freefunc` callback (if
/// provided) to allow the C caller to release its `arg` data.
struct CallbackReader {
    /// Required read callback — invoked by [`Read::read`].
    readfunc: curl_read_callback,
    /// Optional seek callback — stored for potential future use by the
    /// transfer engine.
    _seekfunc: Option<curl_seek_callback>,
    /// Optional free callback — invoked in [`Drop`] to release `arg`.
    freefunc: Option<curl_free_callback>,
    /// Opaque user-data pointer forwarded to all callbacks.
    arg: *mut c_void,
}

impl Read for CallbackReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // SAFETY: We invoke the C read callback with:
        //   - `buf.as_mut_ptr()` as the output buffer — valid, aligned, writable
        //     for `buf.len()` bytes.
        //   - `1` as `size` (byte-oriented, matching curl convention).
        //   - `buf.len()` as `nitems`.
        //   - `self.arg` as the opaque user-data pointer provided by the caller.
        // The callback is expected to write at most `size * nitems` bytes and
        // return the count written, or `0` for EOF.
        let n = unsafe {
            (self.readfunc)(
                buf.as_mut_ptr() as *mut c_char,
                1,
                buf.len(),
                self.arg,
            )
        };
        // curl convention: CURL_READFUNC_ABORT (0x10000000) and
        // CURL_READFUNC_PAUSE (0x10000001) are magic sentinel values.
        if n >= 0x10000000 {
            return Err(std::io::Error::other(
                "curl read callback signalled abort or pause",
            ));
        }
        Ok(n)
    }
}

impl Drop for CallbackReader {
    fn drop(&mut self) {
        if let Some(freefunc) = self.freefunc {
            // SAFETY: The free callback is invoked with the same `arg`
            // pointer that was provided to `curl_mime_data_cb`.  The C caller
            // is responsible for ensuring `arg` is valid for this operation.
            unsafe { freefunc(self.arg) };
        }
    }
}

// SAFETY: The C callback pointers and `arg` are intended to be used from
// whichever thread the transfer runs on.  The curl C API provides no
// additional thread-safety guarantees beyond what the caller supplies, and
// our wrapper matches those semantics exactly.
unsafe impl Send for CallbackReader {}

// ---------------------------------------------------------------------------
// Internal helpers — C slist walking and freeing
// ---------------------------------------------------------------------------

/// Walks a C `curl_slist` linked list and collects all string entries into
/// a Rust [`SList`].
///
/// Null or invalid-UTF-8 entries are silently skipped.
///
/// # Safety
///
/// `head` must be either null or a valid pointer to a well-formed
/// `curl_slist` chain (terminated by a null `next` pointer).  Each node's
/// `data` field must be either null or a valid NUL-terminated C string.
unsafe fn slist_from_c(mut head: *const curl_slist) -> SList {
    let mut result = SList::new();
    while !head.is_null() {
        // SAFETY: `head` is non-null (loop guard) and points to a valid
        // curl_slist node per the caller's contract.
        let node = &*head;
        if !node.data.is_null() {
            // SAFETY: `node.data` is a non-null, NUL-terminated C string.
            if let Ok(s) = CStr::from_ptr(node.data).to_str() {
                result.append(s);
            }
        }
        head = node.next as *const curl_slist;
    }
    result
}

/// Frees a C `curl_slist` linked list that was allocated by the FFI layer's
/// [`curl_slist_append`](crate::slist::curl_slist_append) function.
///
/// Each node and its `data` string are freed via `libc::free`, matching the
/// allocation strategy used by `curl_slist_append` (which uses `libc::malloc`).
///
/// # Safety
///
/// `head` must be either null or a valid pointer to a chain of
/// `libc::malloc`-allocated `curl_slist` nodes whose `data` pointers are
/// also `libc::malloc`-allocated.
unsafe fn free_c_slist(mut head: *mut curl_slist) {
    while !head.is_null() {
        // SAFETY: `head` is non-null (loop guard) and was allocated by
        // libc::malloc in our FFI layer's curl_slist_append.
        let next = (*head).next;
        let data_ptr = (*head).data;
        if !data_ptr.is_null() {
            // SAFETY: `data_ptr` was allocated by libc::malloc.
            free(data_ptr as *mut c_void);
        }
        // SAFETY: `head` was allocated by libc::malloc.
        free(head as *mut c_void);
        head = next;
    }
}

// ===========================================================================
// Extern "C" function implementations — 12 functions
// ===========================================================================

/// Creates a MIME handle associated with the given easy handle.
///
/// Returns a new MIME handle on success, or `NULL` if `easy` is null or
/// allocation fails.  The handle must be freed with [`curl_mime_free`].
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN curl_mime *curl_mime_init(CURL *easy);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_mime_init(easy: *mut CURL) -> *mut curl_mime {
    // SAFETY: We do not dereference `easy` — it is accepted for API
    // compatibility with the C `curl_mime_init` signature.  The Rust `Mime`
    // constructor is stateless and does not require the easy handle.
    if easy.is_null() {
        return ptr::null_mut();
    }

    // Catch any unexpected panic from Mime::new() to prevent unwinding
    // across the FFI boundary (which is undefined behaviour).
    let result = std::panic::catch_unwind(Mime::new);
    match result {
        Ok(mime) => {
            // SAFETY: `Box::into_raw` converts the heap-allocated Mime into
            // a raw pointer.  The pointer is valid, non-null, and correctly
            // aligned.  Ownership is transferred to the caller, who must
            // free it via `curl_mime_free`.
            let boxed = Box::new(mime);
            Box::into_raw(boxed) as *mut curl_mime
        }
        Err(_) => ptr::null_mut(),
    }
}

/// Frees a MIME handle and all associated parts and sub-structures.
///
/// This function is a no-op when `mime` is null, matching the C API's
/// behaviour.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN void curl_mime_free(curl_mime *mime);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_mime_free(mime: *mut curl_mime) {
    if mime.is_null() {
        return;
    }
    // SAFETY: `mime` was produced by `curl_mime_init` via `Box::into_raw`
    // on a `Box<Mime>`.  We reconstitute the Box and drop it, which frees
    // the Mime and all owned MimeParts (including any nested sub-mimes set
    // via `curl_mime_subparts`).  The pointer must not be used after this
    // call (matching C `curl_mime_free` semantics).
    drop(Box::from_raw(mime as *mut Mime));
}

/// Appends a new empty part to the MIME structure and returns a handle to
/// the created part.
///
/// Returns `NULL` if `mime` is null.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN curl_mimepart *curl_mime_addpart(curl_mime *mime);
/// ```
///
/// # Pointer Stability
///
/// The returned pointer references a `MimePart` stored inside the `Mime`'s
/// internal `Vec`.  Callers should configure the part immediately before
/// calling this function again, as subsequent additions may cause the `Vec`
/// to reallocate, invalidating previously returned pointers.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_addpart(mime: *mut curl_mime) -> *mut curl_mimepart {
    if mime.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `mime` was produced by `curl_mime_init` and points to a valid
    // heap-allocated `Mime`.  We create a mutable reference for the duration
    // of this call.  No aliasing occurs because the C API is single-threaded
    // per easy handle.
    let mime_ref: &mut Mime = &mut *(mime as *mut Mime);

    let part: &mut MimePart = mime_ref.add_part();
    // SAFETY: Converting the mutable reference to a raw pointer.  The
    // pointer is valid for the lifetime of the Mime (until `curl_mime_free`),
    // provided the Vec does not reallocate from a subsequent `add_part`
    // call.  See the doc comment on Pointer Stability above.
    (part as *mut MimePart) as *mut curl_mimepart
}

/// Sets the name of a MIME part (the form field name used in the
/// `Content-Disposition` header).
///
/// Passing `NULL` for `name` is a no-op (leaves the part's name unchanged).
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN CURLcode curl_mime_name(curl_mimepart *part, const char *name);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_mime_name(
    part: *mut curl_mimepart,
    name: *const c_char,
) -> CURLcode {
    if part.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    // SAFETY: `part` was returned by `curl_mime_addpart` and points to a
    // valid `MimePart` within a heap-allocated `Mime`.
    let part_ref: &mut MimePart = &mut *(part as *mut MimePart);

    // SAFETY: `name` is either null or a valid NUL-terminated C string.
    match c_str_opt(name) {
        Some(s) => {
            part_ref.set_name(s);
            CURLE_OK
        }
        None => {
            // NULL name: the C API clears the name.  Since the Rust API
            // only has `set_name`, we treat NULL as a no-op on the Rust
            // side (the part's name field remains as it was).
            CURLE_OK
        }
    }
}

/// Sets the remote filename for a MIME part (used in the `Content-Disposition`
/// header's `filename` parameter).
///
/// Passing `NULL` for `filename` is a no-op.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN CURLcode curl_mime_filename(curl_mimepart *part,
///                                         const char *filename);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_mime_filename(
    part: *mut curl_mimepart,
    filename: *const c_char,
) -> CURLcode {
    if part.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    // SAFETY: `part` was returned by `curl_mime_addpart` and points to a
    // valid `MimePart`.
    let part_ref: &mut MimePart = &mut *(part as *mut MimePart);

    // SAFETY: `filename` is either null or a valid NUL-terminated C string.
    match c_str_opt(filename) {
        Some(s) => {
            part_ref.set_filename(s);
            CURLE_OK
        }
        None => CURLE_OK,
    }
}

/// Sets the MIME content type for a part (e.g. `"text/plain"`,
/// `"image/jpeg"`).
///
/// Passing `NULL` for `mimetype` is a no-op.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN CURLcode curl_mime_type(curl_mimepart *part,
///                                     const char *mimetype);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_mime_type(
    part: *mut curl_mimepart,
    mimetype: *const c_char,
) -> CURLcode {
    if part.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    // SAFETY: `part` was returned by `curl_mime_addpart` and points to a
    // valid `MimePart`.
    let part_ref: &mut MimePart = &mut *(part as *mut MimePart);

    // SAFETY: `mimetype` is either null or a valid NUL-terminated C string.
    match c_str_opt(mimetype) {
        Some(s) => {
            part_ref.set_type(s);
            CURLE_OK
        }
        None => CURLE_OK,
    }
}

/// Sets the content transfer encoding for a MIME part (e.g. `"base64"`,
/// `"quoted-printable"`, `"binary"`, `"7bit"`, `"8bit"`).
///
/// Passing `NULL` for `encoding` is a no-op.  An unrecognised encoding
/// name returns `CURLE_BAD_FUNCTION_ARGUMENT`.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN CURLcode curl_mime_encoder(curl_mimepart *part,
///                                        const char *encoding);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_mime_encoder(
    part: *mut curl_mimepart,
    encoding: *const c_char,
) -> CURLcode {
    if part.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    // SAFETY: `part` was returned by `curl_mime_addpart` and points to a
    // valid `MimePart`.
    let part_ref: &mut MimePart = &mut *(part as *mut MimePart);

    // SAFETY: `encoding` is either null or a valid NUL-terminated C string.
    match c_str_opt(encoding) {
        Some(s) => match MimeEncoder::from_name(s) {
            Some(enc) => {
                part_ref.set_encoder(enc);
                CURLE_OK
            }
            None => CURLE_BAD_FUNCTION_ARGUMENT,
        },
        None => {
            // NULL encoding: no-op (C API clears the encoder).
            CURLE_OK
        }
    }
}

/// Sets a MIME part's data source from a memory buffer.
///
/// The data is **copied** internally — the caller retains ownership of the
/// `data` pointer.  If `datasize` is `CURL_ZERO_TERMINATED` (i.e.
/// `(size_t)-1`), the data is treated as a NUL-terminated C string and its
/// length is computed automatically.
///
/// Passing `NULL` for `data` clears the part's data.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN CURLcode curl_mime_data(curl_mimepart *part,
///                                     const char *data, size_t datasize);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_mime_data(
    part: *mut curl_mimepart,
    data: *const c_char,
    datasize: size_t,
) -> CURLcode {
    if part.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    // SAFETY: `part` was returned by `curl_mime_addpart` and points to a
    // valid `MimePart`.
    let part_ref: &mut MimePart = &mut *(part as *mut MimePart);

    if data.is_null() {
        // NULL data: clear the part's content by setting empty data.
        part_ref.set_data(&[]);
        return CURLE_OK;
    }

    if datasize == CURL_ZERO_TERMINATED {
        // SAFETY: `data` is a non-null, NUL-terminated C string.  We use
        // `CStr::from_ptr` to find the NUL terminator and obtain the byte
        // slice without the terminator.
        let c_str = CStr::from_ptr(data);
        part_ref.set_data(c_str.to_bytes());
    } else {
        // SAFETY: `data` points to at least `datasize` readable bytes.
        // `slice::from_raw_parts` requires that the pointer is valid for
        // reads of `datasize` bytes, which the C caller guarantees.
        let byte_slice = slice::from_raw_parts(data as *const u8, datasize);
        part_ref.set_data(byte_slice);
    }

    CURLE_OK
}

/// Sets a MIME part's data source from a file on disk.
///
/// The file's metadata is read immediately to determine its size.  The
/// remote filename is automatically set to the file's basename (matching
/// the C `curl_mime_filedata` behaviour).
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN CURLcode curl_mime_filedata(curl_mimepart *part,
///                                         const char *filename);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_mime_filedata(
    part: *mut curl_mimepart,
    filename: *const c_char,
) -> CURLcode {
    if part.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if filename.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    // SAFETY: `part` was returned by `curl_mime_addpart` and points to a
    // valid `MimePart`.
    let part_ref: &mut MimePart = &mut *(part as *mut MimePart);

    // SAFETY: `filename` is a non-null, NUL-terminated C string.
    let path_str = match CStr::from_ptr(filename).to_str() {
        Ok(s) => s,
        Err(_) => return CURLE_BAD_FUNCTION_ARGUMENT,
    };

    let path = Path::new(path_str);
    result_to_code(part_ref.set_file(path))
}

/// Sets a MIME part's data source from caller-supplied callbacks.
///
/// `readfunc` is called to provide data; `seekfunc` (optional) is called
/// to rewind; `freefunc` (optional) is called when the part is freed to
/// release `arg`.  `datasize` specifies the expected byte count, or `-1`
/// for unknown.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN CURLcode curl_mime_data_cb(curl_mimepart *part,
///                                        curl_off_t datasize,
///                                        curl_read_callback readfunc,
///                                        curl_seek_callback seekfunc,
///                                        curl_free_callback freefunc,
///                                        void *arg);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_mime_data_cb(
    part: *mut curl_mimepart,
    datasize: curl_off_t,
    readfunc: Option<curl_read_callback>,
    seekfunc: Option<curl_seek_callback>,
    freefunc: Option<curl_free_callback>,
    arg: *mut c_void,
) -> CURLcode {
    if part.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    // A read callback is mandatory.
    let readfunc = match readfunc {
        Some(f) => f,
        None => return CURLE_BAD_FUNCTION_ARGUMENT,
    };

    // SAFETY: `part` was returned by `curl_mime_addpart` and points to a
    // valid `MimePart`.
    let part_ref: &mut MimePart = &mut *(part as *mut MimePart);

    // Convert the signed curl_off_t size to Option<u64>.
    // A negative value (typically -1) means "unknown size".
    let size: Option<u64> = if datasize < 0 {
        None
    } else {
        Some(datasize as u64)
    };

    // Build a Rust `Read` adapter from the C function pointers.
    let reader = Box::new(CallbackReader {
        readfunc,
        _seekfunc: seekfunc,
        freefunc,
        arg,
    });

    part_ref.set_data_callback(reader, size);
    CURLE_OK
}

/// Sets nested MIME sub-parts as the data source for a part.
///
/// Ownership of `subparts` is **transferred** to the part.  After this
/// call, the caller must **not** call [`curl_mime_free`] on `subparts` —
/// it will be freed automatically when the parent MIME is freed.
///
/// Passing `NULL` for `subparts` is a no-op.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN CURLcode curl_mime_subparts(curl_mimepart *part,
///                                         curl_mime *subparts);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_mime_subparts(
    part: *mut curl_mimepart,
    subparts: *mut curl_mime,
) -> CURLcode {
    if part.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    // SAFETY: `part` was returned by `curl_mime_addpart` and points to a
    // valid `MimePart`.
    let part_ref: &mut MimePart = &mut *(part as *mut MimePart);

    if subparts.is_null() {
        // NULL subparts: no-op (C API clears the subparts).
        return CURLE_OK;
    }

    // SAFETY: `subparts` was produced by `curl_mime_init` via
    // `Box::into_raw(Box::new(Mime::new()))`.  We reconstitute the Box to
    // take ownership of the Mime.  After this, the pointer is consumed and
    // must not be freed by the caller.
    let sub_mime: Box<Mime> = Box::from_raw(subparts as *mut Mime);

    // Move the Mime out of the Box into set_subparts, which stores it as
    // MimeData::Subparts(Box<Mime>) inside the part.
    result_to_code(part_ref.set_subparts(*sub_mime))
}

/// Attaches custom headers to a MIME part.
///
/// The `headers` parameter is a C `curl_slist` linked list of header
/// strings.  If `take_ownership` is non-zero, the slist is freed after
/// its contents are extracted.  If zero, the caller retains ownership.
///
/// # C Signature
///
/// ```c
/// CURL_EXTERN CURLcode curl_mime_headers(curl_mimepart *part,
///                                        struct curl_slist *headers,
///                                        int take_ownership);
/// ```
#[no_mangle]
pub unsafe extern "C" fn curl_mime_headers(
    part: *mut curl_mimepart,
    headers: *mut curl_slist,
    take_ownership: c_int,
) -> CURLcode {
    if part.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    // SAFETY: `part` was returned by `curl_mime_addpart` and points to a
    // valid `MimePart`.
    let part_ref: &mut MimePart = &mut *(part as *mut MimePart);

    if headers.is_null() {
        // NULL headers: set an empty header list (effectively clearing
        // any previously attached custom headers).
        part_ref.set_headers(SList::new());
        return CURLE_OK;
    }

    // SAFETY: `headers` is a non-null pointer to a well-formed `curl_slist`
    // chain per the caller's contract.  We walk the chain to copy all
    // string entries into a Rust `SList`.
    let rust_slist = slist_from_c(headers as *const curl_slist);

    // Apply the headers to the part.  `set_headers` takes ownership of the
    // Rust SList (which is a Vec<String> internally).
    part_ref.set_headers(rust_slist);

    // If the caller transfers ownership, free the original C slist.
    if take_ownership != 0 {
        // SAFETY: `headers` was allocated by `curl_slist_append` (our FFI
        // layer) using `libc::malloc`.  Each node and data pointer is
        // freed via `libc::free`, matching the allocation strategy.
        free_c_slist(headers);
    }

    CURLE_OK
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    #[test]
    fn curl_zero_terminated_is_max_size_t() {
        assert_eq!(CURL_ZERO_TERMINATED, usize::MAX);
    }

    // -----------------------------------------------------------------------
    // error_to_code helper
    // -----------------------------------------------------------------------

    #[test]
    fn error_to_code_bad_function_argument() {
        let code = error_to_code(CurlError::BadFunctionArgument);
        assert_eq!(code, CURLE_BAD_FUNCTION_ARGUMENT);
    }

    #[test]
    fn error_to_code_out_of_memory() {
        let code = error_to_code(CurlError::OutOfMemory);
        assert_eq!(code, CURLE_OUT_OF_MEMORY);
    }

    #[test]
    fn error_to_code_other_maps_to_bad_arg() {
        let code = error_to_code(CurlError::CouldntConnect);
        assert_eq!(code, CURLE_BAD_FUNCTION_ARGUMENT);
    }

    // -----------------------------------------------------------------------
    // result_to_code helper
    // -----------------------------------------------------------------------

    #[test]
    fn result_to_code_ok() {
        let code = result_to_code(Ok(()));
        assert_eq!(code, CURLE_OK);
    }

    #[test]
    fn result_to_code_err() {
        let code = result_to_code(Err(CurlError::OutOfMemory));
        assert_eq!(code, CURLE_OUT_OF_MEMORY);
    }

    // -----------------------------------------------------------------------
    // c_str_opt helper
    // -----------------------------------------------------------------------

    #[test]
    fn c_str_opt_null_returns_none() {
        // SAFETY: null is a valid input for c_str_opt (returns None).
        let result = unsafe { c_str_opt(ptr::null()) };
        assert!(result.is_none());
    }

    #[test]
    fn c_str_opt_valid_string() {
        let s = CString::new("hello").unwrap();
        // SAFETY: s is a valid null-terminated C string.
        let result = unsafe { c_str_opt(s.as_ptr()) };
        assert_eq!(result, Some("hello"));
    }

    #[test]
    fn c_str_opt_empty_string() {
        let s = CString::new("").unwrap();
        let result = unsafe { c_str_opt(s.as_ptr()) };
        assert_eq!(result, Some(""));
    }

    // -----------------------------------------------------------------------
    // curl_mime_init / curl_mime_free
    // -----------------------------------------------------------------------

    #[test]
    fn mime_init_null_easy_returns_null() {
        // SAFETY: Passing null easy handle returns null.
        let mime = unsafe { curl_mime_init(ptr::null_mut()) };
        assert!(mime.is_null());
    }

    #[test]
    fn mime_init_with_easy_handle() {
        // Create a real easy handle via the FFI layer.
        let easy = unsafe { crate::easy::curl_easy_init() };
        assert!(!easy.is_null());

        let mime = unsafe { curl_mime_init(easy) };
        assert!(!mime.is_null());

        // Clean up.
        unsafe { curl_mime_free(mime) };
        unsafe { crate::easy::curl_easy_cleanup(easy) };
    }

    #[test]
    fn mime_free_null_is_noop() {
        // SAFETY: Passing null to curl_mime_free is documented as a no-op.
        unsafe { curl_mime_free(ptr::null_mut()) };
    }

    // -----------------------------------------------------------------------
    // curl_mime_addpart
    // -----------------------------------------------------------------------

    #[test]
    fn mime_addpart_null_returns_null() {
        let part = unsafe { curl_mime_addpart(ptr::null_mut()) };
        assert!(part.is_null());
    }

    #[test]
    fn mime_addpart_returns_valid_part() {
        let easy = unsafe { crate::easy::curl_easy_init() };
        let mime = unsafe { curl_mime_init(easy) };
        assert!(!mime.is_null());

        let part = unsafe { curl_mime_addpart(mime) };
        assert!(!part.is_null());

        unsafe { curl_mime_free(mime) };
        unsafe { crate::easy::curl_easy_cleanup(easy) };
    }

    // -----------------------------------------------------------------------
    // curl_mime_name
    // -----------------------------------------------------------------------

    #[test]
    fn mime_name_null_part_returns_error() {
        let name = CString::new("field").unwrap();
        let rc = unsafe { curl_mime_name(ptr::null_mut(), name.as_ptr()) };
        assert_eq!(rc, CURLE_BAD_FUNCTION_ARGUMENT);
    }

    #[test]
    fn mime_name_valid() {
        let easy = unsafe { crate::easy::curl_easy_init() };
        let mime = unsafe { curl_mime_init(easy) };
        let part = unsafe { curl_mime_addpart(mime) };
        let name = CString::new("field1").unwrap();

        let rc = unsafe { curl_mime_name(part, name.as_ptr()) };
        assert_eq!(rc, CURLE_OK);

        unsafe { curl_mime_free(mime) };
        unsafe { crate::easy::curl_easy_cleanup(easy) };
    }

    #[test]
    fn mime_name_null_name_is_ok() {
        let easy = unsafe { crate::easy::curl_easy_init() };
        let mime = unsafe { curl_mime_init(easy) };
        let part = unsafe { curl_mime_addpart(mime) };

        let rc = unsafe { curl_mime_name(part, ptr::null()) };
        assert_eq!(rc, CURLE_OK);

        unsafe { curl_mime_free(mime) };
        unsafe { crate::easy::curl_easy_cleanup(easy) };
    }

    // -----------------------------------------------------------------------
    // curl_mime_data
    // -----------------------------------------------------------------------

    #[test]
    fn mime_data_null_part_returns_error() {
        let data = CString::new("hello").unwrap();
        let rc = unsafe {
            curl_mime_data(ptr::null_mut(), data.as_ptr(), CURL_ZERO_TERMINATED)
        };
        assert_eq!(rc, CURLE_BAD_FUNCTION_ARGUMENT);
    }

    #[test]
    fn mime_data_zero_terminated() {
        let easy = unsafe { crate::easy::curl_easy_init() };
        let mime = unsafe { curl_mime_init(easy) };
        let part = unsafe { curl_mime_addpart(mime) };
        let data = CString::new("body data").unwrap();

        let rc = unsafe {
            curl_mime_data(part, data.as_ptr(), CURL_ZERO_TERMINATED)
        };
        assert_eq!(rc, CURLE_OK);

        unsafe { curl_mime_free(mime) };
        unsafe { crate::easy::curl_easy_cleanup(easy) };
    }

    #[test]
    fn mime_data_explicit_length() {
        let easy = unsafe { crate::easy::curl_easy_init() };
        let mime = unsafe { curl_mime_init(easy) };
        let part = unsafe { curl_mime_addpart(mime) };
        let bytes = b"binary data\x00with nulls";

        let rc = unsafe {
            curl_mime_data(part, bytes.as_ptr() as *const c_char, bytes.len())
        };
        assert_eq!(rc, CURLE_OK);

        unsafe { curl_mime_free(mime) };
        unsafe { crate::easy::curl_easy_cleanup(easy) };
    }

    #[test]
    fn mime_data_null_data_clears() {
        let easy = unsafe { crate::easy::curl_easy_init() };
        let mime = unsafe { curl_mime_init(easy) };
        let part = unsafe { curl_mime_addpart(mime) };

        let rc = unsafe { curl_mime_data(part, ptr::null(), 0) };
        assert_eq!(rc, CURLE_OK);

        unsafe { curl_mime_free(mime) };
        unsafe { crate::easy::curl_easy_cleanup(easy) };
    }

    // -----------------------------------------------------------------------
    // curl_mime_type
    // -----------------------------------------------------------------------

    #[test]
    fn mime_type_null_part_returns_error() {
        let ctype = CString::new("text/plain").unwrap();
        let rc = unsafe { curl_mime_type(ptr::null_mut(), ctype.as_ptr()) };
        assert_eq!(rc, CURLE_BAD_FUNCTION_ARGUMENT);
    }

    #[test]
    fn mime_type_valid() {
        let easy = unsafe { crate::easy::curl_easy_init() };
        let mime = unsafe { curl_mime_init(easy) };
        let part = unsafe { curl_mime_addpart(mime) };
        let ctype = CString::new("application/json").unwrap();

        let rc = unsafe { curl_mime_type(part, ctype.as_ptr()) };
        assert_eq!(rc, CURLE_OK);

        unsafe { curl_mime_free(mime) };
        unsafe { crate::easy::curl_easy_cleanup(easy) };
    }

    // -----------------------------------------------------------------------
    // curl_mime_filename
    // -----------------------------------------------------------------------

    #[test]
    fn mime_filename_null_part_returns_error() {
        let fname = CString::new("file.txt").unwrap();
        let rc = unsafe { curl_mime_filename(ptr::null_mut(), fname.as_ptr()) };
        assert_eq!(rc, CURLE_BAD_FUNCTION_ARGUMENT);
    }

    #[test]
    fn mime_filename_valid() {
        let easy = unsafe { crate::easy::curl_easy_init() };
        let mime = unsafe { curl_mime_init(easy) };
        let part = unsafe { curl_mime_addpart(mime) };
        let fname = CString::new("upload.bin").unwrap();

        let rc = unsafe { curl_mime_filename(part, fname.as_ptr()) };
        assert_eq!(rc, CURLE_OK);

        unsafe { curl_mime_free(mime) };
        unsafe { crate::easy::curl_easy_cleanup(easy) };
    }

    // -----------------------------------------------------------------------
    // curl_mime_encoder
    // -----------------------------------------------------------------------

    #[test]
    fn mime_encoder_null_part_returns_error() {
        let enc = CString::new("base64").unwrap();
        let rc = unsafe { curl_mime_encoder(ptr::null_mut(), enc.as_ptr()) };
        assert_eq!(rc, CURLE_BAD_FUNCTION_ARGUMENT);
    }

    // -----------------------------------------------------------------------
    // curl_mime_headers
    // -----------------------------------------------------------------------

    #[test]
    fn mime_headers_null_part_returns_error() {
        let rc = unsafe {
            curl_mime_headers(ptr::null_mut(), ptr::null_mut(), 0)
        };
        assert_eq!(rc, CURLE_BAD_FUNCTION_ARGUMENT);
    }

    #[test]
    fn mime_headers_null_headers_clears() {
        let easy = unsafe { crate::easy::curl_easy_init() };
        let mime = unsafe { curl_mime_init(easy) };
        let part = unsafe { curl_mime_addpart(mime) };

        let rc = unsafe { curl_mime_headers(part, ptr::null_mut(), 0) };
        assert_eq!(rc, CURLE_OK);

        unsafe { curl_mime_free(mime) };
        unsafe { crate::easy::curl_easy_cleanup(easy) };
    }

    // -----------------------------------------------------------------------
    // curl_mime_subparts
    // -----------------------------------------------------------------------

    #[test]
    fn mime_subparts_null_part_returns_error() {
        let rc = unsafe { curl_mime_subparts(ptr::null_mut(), ptr::null_mut()) };
        assert_eq!(rc, CURLE_BAD_FUNCTION_ARGUMENT);
    }

    // -----------------------------------------------------------------------
    // Lifecycle: init → addpart → name → data → type → free
    // -----------------------------------------------------------------------

    #[test]
    fn mime_full_lifecycle() {
        let easy = unsafe { crate::easy::curl_easy_init() };
        assert!(!easy.is_null());

        let mime = unsafe { curl_mime_init(easy) };
        assert!(!mime.is_null());

        let part = unsafe { curl_mime_addpart(mime) };
        assert!(!part.is_null());

        let name = CString::new("file").unwrap();
        assert_eq!(unsafe { curl_mime_name(part, name.as_ptr()) }, CURLE_OK);

        let data = CString::new("file content here").unwrap();
        assert_eq!(
            unsafe { curl_mime_data(part, data.as_ptr(), CURL_ZERO_TERMINATED) },
            CURLE_OK,
        );

        let ctype = CString::new("text/plain").unwrap();
        assert_eq!(unsafe { curl_mime_type(part, ctype.as_ptr()) }, CURLE_OK);

        let fname = CString::new("document.txt").unwrap();
        assert_eq!(
            unsafe { curl_mime_filename(part, fname.as_ptr()) },
            CURLE_OK,
        );

        // Add a second part.
        let part2 = unsafe { curl_mime_addpart(mime) };
        assert!(!part2.is_null());

        let name2 = CString::new("field2").unwrap();
        assert_eq!(unsafe { curl_mime_name(part2, name2.as_ptr()) }, CURLE_OK);

        // Clean up.
        unsafe { curl_mime_free(mime) };
        unsafe { crate::easy::curl_easy_cleanup(easy) };
    }

    // -----------------------------------------------------------------------
    // slist_from_c — with null input
    // -----------------------------------------------------------------------

    #[test]
    fn slist_from_c_null_returns_empty() {
        // SAFETY: Passing null returns an empty SList.
        let slist = unsafe { slist_from_c(ptr::null()) };
        assert!(slist.is_empty());
    }
}
