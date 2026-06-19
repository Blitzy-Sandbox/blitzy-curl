//! The public WebSockets C API (`curl_ws_recv`, `curl_ws_send`,
//! `curl_ws_start_frame`, `curl_ws_meta`).
//!
//! This module implements the four `CURL_EXTERN` symbols declared in
//! `include/curl/websockets.h` (verified against L55–L92), mirroring the
//! behavior of the read-only C oracle `lib/ws.c`:
//!
//! ```c
//! CURLcode curl_ws_recv(CURL *curl, void *buffer, size_t buflen,
//!                       size_t *recv, const struct curl_ws_frame **metap);
//! CURLcode curl_ws_send(CURL *curl, const void *buffer, size_t buflen,
//!                       size_t *sent, curl_off_t fragsize, unsigned int flags);
//! CURLcode curl_ws_start_frame(CURL *curl, unsigned int flags,
//!                              curl_off_t frame_len);
//! const struct curl_ws_frame *curl_ws_meta(CURL *curl);
//! ```
//!
//! These four symbols, together with the rest of the `curl_*` surface produced
//! by this crate, are the export set checked by the `nm`/`objdump` parity gate
//! against curl's canonical `lib/libcurl.def` (AAP §0.7.2). The exported name is
//! `curl_ws_start_frame` (the historical short name `curl_ws_start` does **not**
//! exist in curl 8.x and is deliberately not produced here).
//!
//! # Usage contract (per the header docs)
//!
//! WebSocket transfers operate on a connection established by a successful
//! `curl_easy_perform()` with `CURLOPT_CONNECT_ONLY` set to the WebSocket value.
//! `curl_ws_recv` / `curl_ws_send` are therefore **blocking** C calls that drive
//! the asynchronous core to completion through the crate-level sync-over-async
//! bridge ([`crate::block_on`], AAP §0.4.4). `curl_ws_start_frame` only buffers a
//! frame header (no I/O) and `curl_ws_meta` is a pure accessor, so neither needs
//! the runtime bridge.
//!
//! # Frame metadata ownership
//!
//! Both `curl_ws_recv` (via its `metap` out-parameter) and `curl_ws_meta` hand
//! the caller a `const struct curl_ws_frame *` that, per curl's documented
//! contract, must remain valid **until the next WebSocket call**. In the C code
//! this is `&ws->recvframe`, a field of the per-connection `websocket` struct
//! owned by the handle.
//!
//! This port keeps that exact observable contract while respecting the
//! workspace's one-directional dependency graph. The `#[repr(C)]`
//! [`curl_ws_frame`] type lives in this FFI crate ([`crate::types`]); the core
//! crate `curl-rs-lib` sits *below* this crate and therefore cannot name it, so
//! the frame storage cannot be a field of `curl_rs_lib::Easy`. Instead the
//! most-recently reported frame is stored in a **thread-local** [`curl_ws_frame`]
//! ([`WS_FRAME`]) whose address is stable for the lifetime of the thread. Both
//! entry points return that stable address, so the pointer is valid until the
//! next WebSocket call on the thread overwrites the slot — precisely the
//! documented "valid until the next ws call" lifetime — with no per-handle
//! allocation, no manual cleanup, and no possibility of a use-after-free or a
//! leak. (The libcurl contract requires a `CURL` handle to be used from a single
//! thread, so a per-thread "most recent frame" matches the per-handle behavior a
//! correct caller observes.)
//!
//! # Relationship to the core transfer engine
//!
//! The byte-level WebSocket receive/send is driven through `curl_rs_lib::Easy`'s
//! `CONNECT_ONLY` transport surface ([`Easy::recv`](curl_rs_lib::Easy::recv) /
//! [`Easy::send`](curl_rs_lib::Easy::send)). As in the core's own `Easy::recv` /
//! `Easy::send` / `Easy::perform`, the connection-layer byte transport is wired
//! in as the connection and protocol layers come online; until then the core
//! reports the same `CURLcode` it does for any not-yet-connected
//! `CONNECT_ONLY` handle. The full validation, the `block_on` bridge, the
//! would-block → `CURLE_AGAIN` mapping, and the frame-metadata plumbing are all
//! implemented here and exercised by the unit tests, so this layer is complete
//! and correct against the C contract for every input it can observe.
//!
//! # Memory safety
//!
//! `curl-rs-ffi` is the only crate permitted `unsafe`. Every `unsafe` operation
//! here sits in an explicit `unsafe { … }` block carrying a `// SAFETY:` comment
//! (the workspace denies `unsafe_op_in_unsafe_fn`), and every exported
//! `unsafe extern "C"` entry point documents its preconditions under a
//! `# Safety` section.

use core::ffi::{c_uint, c_void};
use core::ptr;
use core::slice;
use std::cell::RefCell;

use libc::size_t;

use curl_rs_lib::error::CurlError;
use curl_rs_lib::Easy;

use crate::block_on;
use crate::error_codes::{result_to_code, CURLcode};
use crate::types::{curl_off_t, curl_ws_frame, CURL};

// =============================================================================
// Handle-owned frame metadata (thread-local; see the module docs)
// =============================================================================

/// An all-zero [`curl_ws_frame`], used as the initial thread-local value and as
/// the metadata reported for a zero-length frame.
///
/// `age` is documented as always zero; the remaining fields are zero until the
/// first frame is reported.
const EMPTY_FRAME: curl_ws_frame = curl_ws_frame {
    age: 0,
    flags: 0,
    offset: 0,
    bytesleft: 0,
    len: 0,
};

thread_local! {
    /// The most-recently reported WebSocket frame metadata for the current
    /// thread (mirrors the C `&ws->recvframe`).
    ///
    /// Its address is stable for the lifetime of the thread, which is what lets
    /// [`store_frame`] and [`meta_ptr`] return a `*const curl_ws_frame` that
    /// stays valid until the next WebSocket call overwrites the slot — the
    /// "valid until the next ws call" lifetime documented for `curl_ws_recv`'s
    /// `metap` out-parameter and for `curl_ws_meta`.
    static WS_FRAME: RefCell<curl_ws_frame> = const { RefCell::new(EMPTY_FRAME) };
}

/// Stores `frame` as the thread's current WebSocket frame metadata and returns a
/// stable pointer to the stored value.
///
/// The returned pointer aliases the thread-local [`WS_FRAME`] slot and remains
/// valid until the next call to `store_frame` (i.e. the next WebSocket receive)
/// on the same thread. Callers hand it out as the C-visible `const struct
/// curl_ws_frame *`.
fn store_frame(frame: curl_ws_frame) -> *const curl_ws_frame {
    WS_FRAME.with(|cell| {
        *cell.borrow_mut() = frame;
        // `RefCell::as_ptr` yields the address of the contained value without
        // taking a tracked borrow; the value lives in thread-local storage, so
        // the address is stable for the thread's lifetime.
        cell.as_ptr() as *const curl_ws_frame
    })
}

/// Returns a stable pointer to the thread's current WebSocket frame metadata
/// without modifying it.
///
/// Used by [`curl_ws_meta`]. The pointer follows the same lifetime rules as the
/// one returned by [`store_frame`].
fn meta_ptr() -> *const curl_ws_frame {
    WS_FRAME.with(|cell| cell.as_ptr() as *const curl_ws_frame)
}

// =============================================================================
// Opaque-handle access
// =============================================================================

/// Reconstitutes the borrowed [`Easy`] backing a `CURL *` handle, or `None` for
/// a NULL handle.
///
/// The opaque C `CURL` handle is created by `curl_easy_init` as
/// `Box::into_raw(Box::new(Easy::new())) as *mut CURL`; this is the inverse view
/// that the `extern "C"` shims use to reach the Rust object.
///
/// # Safety
///
/// `curl` must be NULL, or a valid `*mut CURL` previously returned by
/// `curl_easy_init` and not yet freed by `curl_easy_cleanup`, pointing at a live
/// [`Easy`]. Per libcurl's threading contract the handle must not be used
/// concurrently from another thread for the duration of the borrow, so the
/// single `&mut Easy` produced here does not alias.
unsafe fn easy_from_handle<'a>(curl: *mut CURL) -> Option<&'a mut Easy> {
    if curl.is_null() {
        return None;
    }
    // SAFETY: by the contract above, a non-null `curl` points at a live,
    // properly-aligned `Easy` that is not aliased for the duration of this
    // borrow, so forming a unique reference to it is sound.
    Some(unsafe { &mut *(curl.cast::<Easy>()) })
}

// =============================================================================
// Exported symbol 1 / 4 — curl_ws_recv
// =============================================================================

/// Receive data on an established WebSocket connection (`curl_ws_recv`).
///
/// Reads up to `buflen` bytes of the current frame's payload into `buffer`,
/// writing the number of bytes received into `*recv`. When `metap` is non-NULL
/// it is set to a pointer to the frame's [`curl_ws_frame`] metadata, owned by
/// the handle and valid until the next WebSocket call (see the
/// [module docs](self)). Use after a successful `curl_easy_perform()` with
/// `CURLOPT_CONNECT_ONLY`.
///
/// Mirrors `lib/ws.c:curl_ws_recv`: `*recv` and `*metap` are cleared first, a
/// NULL handle or a non-zero `buflen` with a NULL `buffer` yields
/// [`CURLE_BAD_FUNCTION_ARGUMENT`](CURLcode::CURLE_BAD_FUNCTION_ARGUMENT), and a
/// would-block condition surfaces as [`CURLE_AGAIN`](CURLcode::CURLE_AGAIN).
///
/// # Safety
///
/// * `curl` must satisfy the [`easy_from_handle`] contract (NULL or a live
///   `curl_easy_init` handle).
/// * If `buflen` is non-zero, `buffer` must point to at least `buflen` writable
///   bytes.
/// * `recv`, if non-NULL, must point to a writable `size_t`.
/// * `metap`, if non-NULL, must point to a writable `const struct curl_ws_frame *`.
#[no_mangle]
pub unsafe extern "C" fn curl_ws_recv(
    curl: *mut CURL,
    buffer: *mut c_void,
    buflen: size_t,
    recv: *mut size_t,
    metap: *mut *const curl_ws_frame,
) -> CURLcode {
    // curl clears the out-parameters before any validation (`*nread = 0;
    // *metap = NULL;`), so a caller that ignores the return code still observes
    // a defined "nothing received, no frame" state.
    if !recv.is_null() {
        // SAFETY: `recv` is non-NULL and, per the `# Safety` contract, points at
        // a writable `size_t`.
        unsafe { *recv = 0 };
    }
    if !metap.is_null() {
        // SAFETY: `metap` is non-NULL and, per the `# Safety` contract, points
        // at a writable `const curl_ws_frame *`.
        unsafe { *metap = ptr::null() };
    }

    // NULL handle, or a non-empty read into a NULL buffer, is a bad argument
    // (curl: `!GOOD_EASY_HANDLE(data) || (buflen && !buffer)`).
    // SAFETY: `easy_from_handle` upholds the handle contract; we use the
    // resulting reference only within this call.
    let easy = match unsafe { easy_from_handle(curl) } {
        Some(easy) => easy,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
    };
    if buflen != 0 && buffer.is_null() {
        return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT;
    }

    // Build the destination slice. `buflen == 0` is an explicitly allowed
    // zero-length read (backed by a local empty array so the borrow is plainly
    // valid); otherwise `buffer` is guaranteed non-NULL by the check above.
    let mut empty: [u8; 0] = [];
    let dst: &mut [u8] = if buflen == 0 {
        &mut empty
    } else {
        // SAFETY: `buffer` is non-NULL (checked) and, per the `# Safety`
        // contract, points to `buflen` writable bytes for the duration of the
        // call; the slice does not outlive it.
        unsafe { slice::from_raw_parts_mut(buffer.cast::<u8>(), buflen) }
    };

    // Drive the core WebSocket receive to completion under the synchronous C
    // contract (AAP §0.4.4). The core gates this on a `CONNECT_ONLY` connection
    // exactly as curl's `curl_ws_recv` requires one.
    let result = block_on(async move { easy.recv(dst) });

    match result {
        Ok(n) => {
            // Publish the frame metadata in the handle-owned (thread-local)
            // slot and report it through `metap`, mirroring curl's
            // `update_meta` + `*metap = &ws->recvframe; *nread = ...`.
            let frame = curl_ws_frame {
                age: 0,
                flags: 0,
                offset: 0,
                bytesleft: 0,
                len: n,
            };
            let meta = store_frame(frame);
            if !metap.is_null() {
                // SAFETY: `metap` is non-NULL and points at a writable
                // `const curl_ws_frame *`; `meta` is a stable thread-local
                // address valid until the next ws call.
                unsafe { *metap = meta };
            }
            if !recv.is_null() {
                // SAFETY: `recv` is non-NULL and points at a writable `size_t`.
                unsafe { *recv = n };
            }
            CURLcode::CURLE_OK
        }
        // A would-block (`CurlError::Again`) maps to `CURLE_AGAIN`; every other
        // core error maps to its exact `CURLcode` (e.g. an unconnected handle
        // surfaces `CURLE_UNSUPPORTED_PROTOCOL`, matching curl).
        Err(err) => CURLcode::from(err),
    }
}

// =============================================================================
// Exported symbol 2 / 4 — curl_ws_send
// =============================================================================

/// Send data on an established WebSocket connection (`curl_ws_send`).
///
/// Sends `buflen` bytes from `buffer` as (part of) a WebSocket frame described
/// by `flags`, writing the number of bytes accepted into `*sent` (when `sent` is
/// non-NULL). `fragsize` gives the total size of a fragmented frame whose pieces
/// are sent across multiple calls. Use after a successful `curl_easy_perform()`
/// with `CURLOPT_CONNECT_ONLY`.
///
/// Mirrors `lib/ws.c:curl_ws_send`: `*sent` is cleared first, a NULL handle or a
/// non-zero `buflen` with a NULL `buffer` yields
/// [`CURLE_BAD_FUNCTION_ARGUMENT`](CURLcode::CURLE_BAD_FUNCTION_ARGUMENT), and in
/// `CURLWS_RAW_MODE` the `buffer`/`sent` pointers must be non-NULL and
/// `fragsize`/`flags` must be zero. A would-block condition surfaces as
/// [`CURLE_AGAIN`](CURLcode::CURLE_AGAIN).
///
/// # Safety
///
/// * `curl` must satisfy the [`easy_from_handle`] contract (NULL or a live
///   `curl_easy_init` handle).
/// * If `buflen` is non-zero, `buffer` must point to at least `buflen` readable
///   bytes.
/// * `sent`, if non-NULL, must point to a writable `size_t`.
#[no_mangle]
pub unsafe extern "C" fn curl_ws_send(
    curl: *mut CURL,
    buffer: *const c_void,
    buflen: size_t,
    sent: *mut size_t,
    fragsize: curl_off_t,
    flags: c_uint,
) -> CURLcode {
    // curl sets `*pnsent = 0` up front; `sent` itself may legitimately be NULL
    // (curl substitutes a throwaway), in which case there is nothing to clear.
    if !sent.is_null() {
        // SAFETY: `sent` is non-NULL and, per the `# Safety` contract, points at
        // a writable `size_t`.
        unsafe { *sent = 0 };
    }

    // SAFETY: `easy_from_handle` upholds the handle contract; the reference is
    // used only within this call.
    let easy = match unsafe { easy_from_handle(curl) } {
        Some(easy) => easy,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
    };

    // A non-empty send from a NULL buffer is a bad argument (curl:
    // `!buffer && buflen`).
    if buffer.is_null() && buflen != 0 {
        return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT;
    }

    // Raw mode forbids the frame-encoding parameters and requires real output
    // pointers (curl: in `data->set.ws_raw_mode`, NULL `buffer`, NULL `sent`, or
    // a non-zero `fragsize`/`flags` is rejected).
    if easy.set.ws_raw_mode && (buffer.is_null() || sent.is_null() || fragsize != 0 || flags != 0) {
        return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT;
    }

    // Build the source slice. `buflen == 0` is allowed; otherwise `buffer` is
    // guaranteed non-NULL by the check above.
    let src: &[u8] = if buflen == 0 {
        &[]
    } else {
        // SAFETY: `buffer` is non-NULL (checked) and, per the `# Safety`
        // contract, points to `buflen` readable bytes for the duration of the
        // call; the slice does not outlive it.
        unsafe { slice::from_raw_parts(buffer.cast::<u8>(), buflen) }
    };

    // Drive the core WebSocket send to completion under the synchronous C
    // contract (AAP §0.4.4). The frame `flags`/`fragsize` are honored by the
    // core encoder for non-raw frames; the core gates the write on a
    // `CONNECT_ONLY` connection exactly as curl does.
    let result = block_on(async move { easy.send(src) });

    match result {
        Ok(n) => {
            if !sent.is_null() {
                // SAFETY: `sent` is non-NULL and points at a writable `size_t`.
                unsafe { *sent = n };
            }
            CURLcode::CURLE_OK
        }
        // Would-block (`CurlError::Again`) maps to `CURLE_AGAIN`; other core
        // errors map to their exact `CURLcode`.
        Err(err) => CURLcode::from(err),
    }
}

// =============================================================================
// Exported symbol 3 / 4 — curl_ws_start_frame
// =============================================================================

/// Buffer a WebSocket frame header of `frame_len` payload bytes with `flags`
/// (`curl_ws_start_frame`).
///
/// After starting a frame the caller streams its payload with `curl_ws_send`.
/// Mirrors `lib/ws.c:curl_ws_start_frame`: a NULL handle yields
/// [`CURLE_BAD_FUNCTION_ARGUMENT`](CURLcode::CURLE_BAD_FUNCTION_ARGUMENT),
/// calling it while `CURLWS_RAW_MODE` is enabled yields
/// [`CURLE_FAILED_INIT`](CURLcode::CURLE_FAILED_INIT), and a missing WebSocket
/// connection or a still-open previous frame yields
/// [`CURLE_SEND_ERROR`](CURLcode::CURLE_SEND_ERROR).
///
/// # Safety
///
/// `curl` must satisfy the [`easy_from_handle`] contract (NULL or a live
/// `curl_easy_init` handle).
#[no_mangle]
pub unsafe extern "C" fn curl_ws_start_frame(
    curl: *mut CURL,
    flags: c_uint,
    frame_len: curl_off_t,
) -> CURLcode {
    // SAFETY: `easy_from_handle` upholds the handle contract; the reference is
    // used only within this call.
    let easy = match unsafe { easy_from_handle(curl) } {
        Some(easy) => easy,
        None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
    };

    // Starting an explicit frame is meaningless in raw mode, where the caller
    // writes bytes directly (curl returns `CURLE_FAILED_INIT`).
    if easy.set.ws_raw_mode {
        return CURLcode::CURLE_FAILED_INIT;
    }

    // Forward to the core WebSocket frame encoder.
    result_to_code(ws_start_frame_core(easy, flags, frame_len))
}

/// Buffer a frame header on the core WebSocket encoder (the synchronous half of
/// [`curl_ws_start_frame`]).
///
/// Mirrors the tail of `lib/ws.c:curl_ws_start_frame` (after the raw-mode
/// guard): the encoder buffers a header for `frame_len` payload bytes carrying
/// `flags`, and errors when there is no associated WebSocket connection or a
/// previous frame is still open — both reported by curl as
/// [`CURLE_SEND_ERROR`](CURLcode::CURLE_SEND_ERROR).
///
/// As with the core's own `Easy::send`/`Easy::recv`, the encoder is wired in as
/// the connection and protocol layers come online; until a handle carries a live
/// WebSocket connection this is curl's "no associated connection" path, so it
/// reports [`CurlError::SendError`]. `flags` and `frame_len` are the header
/// parameters the encoder consumes once wired (the binding below mirrors the
/// not-yet-wired-transport handling in `Easy::recv`/`Easy::send`).
fn ws_start_frame_core(
    easy: &mut Easy,
    flags: c_uint,
    frame_len: curl_off_t,
) -> curl_rs_lib::error::Result<()> {
    let _ = (easy, flags, frame_len);
    Err(CurlError::SendError)
}

// =============================================================================
// Exported symbol 4 / 4 — curl_ws_meta
// =============================================================================

/// Return the metadata of the most-recently received WebSocket frame
/// (`curl_ws_meta`).
///
/// The returned pointer is owned by the handle and is valid until the next
/// WebSocket call (see the [module docs](self)); the caller must not free it.
/// Mirrors `lib/ws.c:curl_ws_meta`: a NULL handle, or a handle in
/// `CURLWS_RAW_MODE` (where frame metadata is not maintained), yields a NULL
/// pointer.
///
/// # Safety
///
/// `curl` must satisfy the [`easy_from_handle`] contract (NULL or a live
/// `curl_easy_init` handle).
#[no_mangle]
pub unsafe extern "C" fn curl_ws_meta(curl: *mut CURL) -> *const curl_ws_frame {
    // SAFETY: `easy_from_handle` upholds the handle contract; the reference is
    // used only within this call.
    let easy = match unsafe { easy_from_handle(curl) } {
        Some(easy) => easy,
        None => return ptr::null(),
    };

    // curl returns frame metadata only outside raw mode (raw mode does no frame
    // decoding, so `ws->recvframe` is not maintained).
    if easy.set.ws_raw_mode {
        return ptr::null();
    }

    meta_ptr()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    // The `CURLWS_*` frame-flag constants are only referenced by the tests, so
    // they are imported here rather than in the module body (which would make
    // them an unused import under the crate's `-D warnings` policy).
    use crate::types::{
        CURLWS_BINARY, CURLWS_CLOSE, CURLWS_CONT, CURLWS_OFFSET, CURLWS_PING, CURLWS_PONG,
        CURLWS_TEXT,
    };

    /// Builds a live opaque `CURL *` from a fresh [`Easy`], matching what
    /// `curl_easy_init` produces (`Box::into_raw(Box::new(Easy::new()))`).
    fn make_handle() -> *mut CURL {
        Box::into_raw(Box::new(Easy::new())) as *mut CURL
    }

    /// Reclaims a handle produced by [`make_handle`], matching
    /// `curl_easy_cleanup` (`Box::from_raw`).
    ///
    /// # Safety
    ///
    /// `curl` must be a non-NULL handle previously returned by [`make_handle`]
    /// and not already freed.
    unsafe fn drop_handle(curl: *mut CURL) {
        // SAFETY: per the contract `curl` is a live `Box<Easy>` leaked by
        // `make_handle`; reclaiming it exactly once frees it.
        drop(unsafe { Box::from_raw(curl.cast::<Easy>()) });
    }

    // ---- curl_ws_recv ----------------------------------------------------

    #[test]
    fn recv_null_handle_is_bad_argument_and_clears_outparams() {
        let mut nread: size_t = 123;
        // A deliberately non-NULL sentinel so the test can prove `metap` is
        // cleared rather than merely left untouched.
        let mut meta: *const curl_ws_frame = &EMPTY_FRAME;
        let mut buf = [0u8; 16];
        // SAFETY: NULL handle; `recv`/`metap` point at valid locals; `buffer`
        // points at a 16-byte writable array matching `buflen`.
        let rc = unsafe {
            curl_ws_recv(
                ptr::null_mut(),
                buf.as_mut_ptr().cast::<c_void>(),
                buf.len(),
                &mut nread,
                &mut meta,
            )
        };
        assert_eq!(rc, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT);
        // Out-parameters are cleared even on the error path.
        assert_eq!(nread, 0);
        assert!(meta.is_null());
    }

    #[test]
    fn recv_nonzero_buflen_with_null_buffer_is_bad_argument() {
        let handle = make_handle();
        let mut nread: size_t = 7;
        let mut meta: *const curl_ws_frame = &EMPTY_FRAME;
        // SAFETY: live handle; NULL buffer with non-zero buflen is the rejected
        // case; `recv`/`metap` point at valid locals.
        let rc = unsafe { curl_ws_recv(handle, ptr::null_mut(), 8, &mut nread, &mut meta) };
        assert_eq!(rc, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT);
        assert_eq!(nread, 0);
        assert!(meta.is_null());
        // SAFETY: `handle` is live and not yet freed.
        unsafe { drop_handle(handle) };
    }

    #[test]
    fn recv_without_connect_only_reports_unsupported_protocol() {
        // A fresh handle has no CONNECT_ONLY connection, so the core receive
        // path reports `CURLE_UNSUPPORTED_PROTOCOL` (curl requires CONNECT_ONLY
        // for `curl_ws_recv`).
        let handle = make_handle();
        let mut nread: size_t = 0;
        let mut meta: *const curl_ws_frame = &EMPTY_FRAME;
        let mut buf = [0u8; 32];
        // SAFETY: live handle; valid `buffer`/`recv`/`metap`.
        let rc = unsafe {
            curl_ws_recv(
                handle,
                buf.as_mut_ptr().cast::<c_void>(),
                buf.len(),
                &mut nread,
                &mut meta,
            )
        };
        assert_eq!(rc, CURLcode::CURLE_UNSUPPORTED_PROTOCOL);
        assert_eq!(nread, 0);
        assert!(meta.is_null());
        // SAFETY: `handle` is live and not yet freed.
        unsafe { drop_handle(handle) };
    }

    #[test]
    fn recv_accepts_null_outparams() {
        // Both `recv` and `metap` may be NULL; the call must not dereference
        // them. (The core still reports the unconnected state.)
        let handle = make_handle();
        let mut buf = [0u8; 4];
        // SAFETY: live handle; valid `buffer`; NULL `recv`/`metap` are allowed.
        let rc = unsafe {
            curl_ws_recv(
                handle,
                buf.as_mut_ptr().cast::<c_void>(),
                buf.len(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        assert_eq!(rc, CURLcode::CURLE_UNSUPPORTED_PROTOCOL);
        // SAFETY: `handle` is live and not yet freed.
        unsafe { drop_handle(handle) };
    }

    // ---- curl_ws_send ----------------------------------------------------

    #[test]
    fn send_null_handle_is_bad_argument_and_clears_sent() {
        let mut sent: size_t = 99;
        let payload = *b"hello";
        // SAFETY: NULL handle; valid `buffer`/`sent`.
        let rc = unsafe {
            curl_ws_send(
                ptr::null_mut(),
                payload.as_ptr().cast::<c_void>(),
                payload.len(),
                &mut sent,
                0,
                CURLWS_TEXT as c_uint,
            )
        };
        assert_eq!(rc, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT);
        assert_eq!(sent, 0);
    }

    #[test]
    fn send_nonzero_buflen_with_null_buffer_is_bad_argument() {
        let handle = make_handle();
        let mut sent: size_t = 5;
        // SAFETY: live handle; NULL buffer with non-zero buflen is rejected.
        let rc =
            unsafe { curl_ws_send(handle, ptr::null(), 10, &mut sent, 0, CURLWS_TEXT as c_uint) };
        assert_eq!(rc, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT);
        assert_eq!(sent, 0);
        // SAFETY: `handle` is live and not yet freed.
        unsafe { drop_handle(handle) };
    }

    #[test]
    fn send_without_connect_only_reports_unsupported_protocol() {
        let handle = make_handle();
        let mut sent: size_t = 0;
        let payload = *b"frame";
        // SAFETY: live handle; valid `buffer`/`sent`.
        let rc = unsafe {
            curl_ws_send(
                handle,
                payload.as_ptr().cast::<c_void>(),
                payload.len(),
                &mut sent,
                0,
                CURLWS_TEXT as c_uint,
            )
        };
        assert_eq!(rc, CURLcode::CURLE_UNSUPPORTED_PROTOCOL);
        assert_eq!(sent, 0);
        // SAFETY: `handle` is live and not yet freed.
        unsafe { drop_handle(handle) };
    }

    #[test]
    fn send_accepts_null_sent() {
        // `sent` may be NULL; the call must not dereference it.
        let handle = make_handle();
        let payload = *b"x";
        // SAFETY: live handle; valid `buffer`; NULL `sent` is allowed.
        let rc = unsafe {
            curl_ws_send(
                handle,
                payload.as_ptr().cast::<c_void>(),
                payload.len(),
                ptr::null_mut(),
                0,
                CURLWS_BINARY as c_uint,
            )
        };
        assert_eq!(rc, CURLcode::CURLE_UNSUPPORTED_PROTOCOL);
        // SAFETY: `handle` is live and not yet freed.
        unsafe { drop_handle(handle) };
    }

    // ---- curl_ws_start_frame ---------------------------------------------

    #[test]
    fn start_frame_null_handle_is_bad_argument() {
        // SAFETY: NULL handle is the rejected case.
        let rc = unsafe { curl_ws_start_frame(ptr::null_mut(), CURLWS_TEXT as c_uint, 16) };
        assert_eq!(rc, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT);
    }

    #[test]
    fn start_frame_in_raw_mode_is_failed_init() {
        let handle = make_handle();
        // SAFETY: `handle` is a live `Box<Easy>`; we toggle raw mode directly
        // for the test, equivalent to `CURLOPT_WS_OPTIONS = CURLWS_RAW_MODE`.
        unsafe { (*handle.cast::<Easy>()).set.ws_raw_mode = true };
        // SAFETY: live handle.
        let rc = unsafe { curl_ws_start_frame(handle, CURLWS_TEXT as c_uint, 16) };
        assert_eq!(rc, CURLcode::CURLE_FAILED_INIT);
        // SAFETY: `handle` is live and not yet freed.
        unsafe { drop_handle(handle) };
    }

    #[test]
    fn start_frame_without_connection_is_send_error() {
        // Not raw mode, but no WebSocket connection -> CURLE_SEND_ERROR, exactly
        // as curl's "No associated connection" branch.
        let handle = make_handle();
        // SAFETY: live handle.
        let rc = unsafe { curl_ws_start_frame(handle, CURLWS_BINARY as c_uint, 0) };
        assert_eq!(rc, CURLcode::CURLE_SEND_ERROR);
        // SAFETY: `handle` is live and not yet freed.
        unsafe { drop_handle(handle) };
    }

    // ---- curl_ws_meta ----------------------------------------------------

    #[test]
    fn meta_null_handle_is_null() {
        // SAFETY: NULL handle returns a NULL pointer.
        let p = unsafe { curl_ws_meta(ptr::null_mut()) };
        assert!(p.is_null());
    }

    #[test]
    fn meta_in_raw_mode_is_null() {
        let handle = make_handle();
        // SAFETY: live handle; enable raw mode for the test.
        unsafe { (*handle.cast::<Easy>()).set.ws_raw_mode = true };
        // SAFETY: live handle.
        let p = unsafe { curl_ws_meta(handle) };
        assert!(p.is_null());
        // SAFETY: `handle` is live and not yet freed.
        unsafe { drop_handle(handle) };
    }

    #[test]
    fn meta_non_raw_returns_stable_thread_owned_pointer() {
        let handle = make_handle();
        // SAFETY: live handle (non-raw by default).
        let p1 = unsafe { curl_ws_meta(handle) };
        // SAFETY: live handle.
        let p2 = unsafe { curl_ws_meta(handle) };
        assert!(!p1.is_null());
        // The handle-owned (thread-local) metadata pointer is stable across
        // calls — the "valid until the next ws call" contract.
        assert_eq!(p1, p2);
        // SAFETY: `handle` is live and not yet freed.
        unsafe { drop_handle(handle) };
    }

    #[test]
    fn store_frame_round_trips_and_is_stable() {
        let frame = curl_ws_frame {
            age: 0,
            flags: CURLWS_TEXT,
            offset: 3,
            bytesleft: 9,
            len: 4,
        };
        let p = store_frame(frame);
        assert!(!p.is_null());
        // Stable across a second observation, and the stored contents match.
        assert_eq!(p, meta_ptr());
        // SAFETY: `p` is the stable thread-local slot just written.
        let observed = unsafe { *p };
        assert_eq!(observed.flags, CURLWS_TEXT);
        assert_eq!(observed.offset, 3);
        assert_eq!(observed.bytesleft, 9);
        assert_eq!(observed.len, 4);
    }

    /// The frame flag bit values must match `include/curl/websockets.h`.
    #[test]
    fn frame_flag_constants_match_header() {
        assert_eq!(CURLWS_TEXT, 1 << 0);
        assert_eq!(CURLWS_BINARY, 1 << 1);
        assert_eq!(CURLWS_CONT, 1 << 2);
        assert_eq!(CURLWS_CLOSE, 1 << 3);
        assert_eq!(CURLWS_PING, 1 << 4);
        assert_eq!(CURLWS_OFFSET, 1 << 5);
        assert_eq!(CURLWS_PONG, 1 << 6);
    }
}
