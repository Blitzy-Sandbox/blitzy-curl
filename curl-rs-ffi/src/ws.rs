// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-License-Identifier: curl
//
//! FFI bindings for the `curl_ws_*` family of WebSocket functions.
//!
//! This module exposes the 4 `curl_ws_*` CURL_EXTERN symbols from
//! `include/curl/websockets.h` as `extern "C"` functions with `#[no_mangle]`
//! attributes, plus the 2 CURLOPT_WS_OPTIONS bitmask constants.
//!
//! # Exported Symbols (from `include/curl/websockets.h`)
//!
//! | Symbol                 | C Signature                                                           |
//! |------------------------|-----------------------------------------------------------------------|
//! | `curl_ws_recv`         | `CURLcode curl_ws_recv(CURL*, void*, size_t, size_t*, const struct curl_ws_frame**)` |
//! | `curl_ws_send`         | `CURLcode curl_ws_send(CURL*, const void*, size_t, size_t*, curl_off_t, unsigned int)` |
//! | `curl_ws_start_frame`  | `CURLcode curl_ws_start_frame(CURL*, unsigned int, curl_off_t)`       |
//! | `curl_ws_meta`         | `const struct curl_ws_frame *curl_ws_meta(CURL*)`                     |
//!
//! # Constants
//!
//! | Constant             | C Definition            | Value |
//! |----------------------|-------------------------|-------|
//! | `CURLWS_RAW_MODE`    | `(1L << 0)`             | 1     |
//! | `CURLWS_NOAUTOPONG`  | `(1L << 1)`             | 2     |
//!
//! These are option bits for `CURLOPT_WS_OPTIONS`, distinct from the frame-type
//! flag constants (`CURLWS_TEXT`, `CURLWS_BINARY`, etc.) which are defined in
//! [`crate::types`].
//!
//! # Safety
//!
//! This module is within the `curl-rs-ffi` crate, the **only** location in
//! the Rust codebase where `unsafe` blocks are permitted (per AAP Section
//! 0.7.1). Every `unsafe` block carries a `// SAFETY:` invariant comment
//! explaining why the operation is sound.
//!
//! # Integration Path
//!
//! Each WebSocket FFI function:
//! 1. Validates all raw pointer arguments (null → `CURLE_BAD_FUNCTION_ARGUMENT`).
//! 2. Converts the opaque `CURL *` to an `&mut EasyHandle` via
//!    [`crate::easy::handle_from_ptr`].
//! 3. Delegates to the corresponding Rust-native function in
//!    [`curl_rs_lib::protocols::ws`] (`ws_recv`, `ws_send`, `ws_meta`,
//!    `ws_start_frame`).
//! 4. Converts the Rust `CurlResult<T>` to the C `CURLcode` integer.
//!
//! The WebSocket state is accessed from the easy handle's active connection.
//! When no active WebSocket connection exists, the functions return
//! `CURLE_NOT_BUILT_IN` to signal that the operation cannot proceed.

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

use crate::easy::handle_from_ptr;
use crate::error_codes::{CURLE_BAD_FUNCTION_ARGUMENT, CURLE_NOT_BUILT_IN, CURLE_OK};
use crate::types::{curl_off_t, curl_ws_frame, CURLcode, CURL};

use curl_rs_lib::easy::EasyHandle;
use curl_rs_lib::error::CurlError;
use curl_rs_lib::protocols::ws::{self, WebSocket, WsFlags, WsFrame};

use libc::{c_long, c_uint, c_void, size_t};

use std::cell::RefCell;
use std::ptr;

// ===========================================================================
// Section 1: CURLOPT_WS_OPTIONS Bitmask Constants
// Derived from: include/curl/websockets.h (lines 88–90)
//
// These are option bits for CURLOPT_WS_OPTIONS, NOT frame-type flags.
// The frame-type flags (CURLWS_TEXT, CURLWS_BINARY, etc.) are in types.rs.
// ===========================================================================

/// Raw mode: pass WebSocket frames through without decoding/encoding.
///
/// When set via `CURLOPT_WS_OPTIONS`, disables WebSocket frame parsing and
/// passes raw data directly to the application. The application is responsible
/// for its own frame encoding/decoding.
///
/// C equivalent: `#define CURLWS_RAW_MODE (1L << 0)` — `websockets.h` line 89.
pub const CURLWS_RAW_MODE: c_long = 1 << 0;

/// Disable automatic PONG responses to PING frames.
///
/// When set via `CURLOPT_WS_OPTIONS`, the library will not automatically send
/// PONG frames in response to received PING frames. The application must
/// handle PONG responses manually via `curl_ws_send`.
///
/// C equivalent: `#define CURLWS_NOAUTOPONG (1L << 1)` — `websockets.h` line 90.
pub const CURLWS_NOAUTOPONG: c_long = 1 << 1;

// ===========================================================================
// Section 2: Thread-Local Frame Metadata Storage
//
// The C implementation stores the most-recent frame metadata inside the
// connection's ws struct (`data->conn->ws`), which has stable address
// lifetime. In Rust, we use thread-local storage to provide a stable
// pointer that persists between calls to curl_ws_recv and curl_ws_meta.
// ===========================================================================

thread_local! {
    /// Thread-local storage for the most-recently received WebSocket frame
    /// metadata. This is populated by `curl_ws_recv` and read by
    /// `curl_ws_meta`. The pointer returned by `curl_ws_meta` points into
    /// this storage and remains valid until the next call to `curl_ws_recv`
    /// on the same thread.
    static LAST_WS_FRAME: RefCell<curl_ws_frame> = const {
        RefCell::new(curl_ws_frame {
            age: 0,
            flags: 0,
            offset: 0,
            bytesleft: 0,
            len: 0,
        })
    };
}

// ===========================================================================
// Section 3: Internal Helpers
// ===========================================================================

/// Converts a [`CurlError`] variant to its corresponding `CURLcode` integer.
///
/// This is a local version of the conversion function used by other FFI
/// modules. The `CurlError` enum implements `Into<i32>` with values matching
/// the C `CURLcode` enum exactly (per AAP Section 0.7.2).
#[inline]
fn error_to_code(e: CurlError) -> CURLcode {
    let code: i32 = e.into();
    code
}

/// Attempts to obtain a mutable reference to the [`WebSocket`] state
/// associated with the given easy handle's active connection.
///
/// Returns `None` when:
/// - The handle has no active connection (e.g., `curl_easy_perform` has not
///   been called yet).
/// - The active connection does not use the WebSocket protocol.
/// - The WebSocket subsystem integration through `EasyHandle` is not yet
///   available (the connection/transfer subsystem wires this up).
///
/// When the full connection subsystem is integrated, this function will
/// traverse `handle → connection → ws_state` to return the live WebSocket
/// instance.
#[inline]
fn get_websocket(_handle: &mut EasyHandle) -> Option<&mut WebSocket> {
    // The WebSocket state is managed by the connection/transfer subsystem.
    // The EasyHandle stores connection state internally; once the full
    // transfer pipeline is wired up, this function will access:
    //   handle.connection().and_then(|c| c.ws_mut())
    // For now, the integration path is not yet complete.
    None
}

/// Converts a Rust [`WsFrame`] to a C-compatible [`curl_ws_frame`].
///
/// Maps the Rust bitflags and typed fields to the C integer-based
/// representation required by the FFI boundary.
#[inline]
fn rust_frame_to_c(frame: &WsFrame) -> curl_ws_frame {
    curl_ws_frame {
        age: frame.age,
        flags: frame.flags.bits() as i32,
        offset: frame.offset,
        bytesleft: frame.bytesleft,
        len: frame.len,
    }
}

/// Converts C-level flags (`unsigned int`) to the Rust [`WsFlags`] bitflags.
#[inline]
fn c_flags_to_rust(flags: c_uint) -> WsFlags {
    WsFlags::from_bits(flags)
}

// ===========================================================================
// Section 4: extern "C" Functions
// ===========================================================================

// ---------------------------------------------------------------------------
// curl_ws_recv — Receive WebSocket data
// ---------------------------------------------------------------------------

/// Receives data from a WebSocket connection.
///
/// Reads incoming WebSocket frame data into `buffer`, setting `*nread` to
/// the number of bytes read and `*metap` to a pointer to the frame metadata
/// struct describing the current frame.
///
/// This function should be called after a successful `curl_easy_perform()`
/// with `CURLOPT_CONNECT_ONLY` option on a WebSocket URL.
///
/// # Parameters
///
/// - `curl`: Easy handle with an active WebSocket connection.
/// - `buffer`: Destination buffer for received payload data.
/// - `buflen`: Size of `buffer` in bytes.
/// - `nread`: Output — set to the number of bytes written to `buffer`.
/// - `metap`: Output — set to point to the frame metadata for this delivery.
///
/// # Returns
///
/// - `CURLE_OK` on success.
/// - `CURLE_BAD_FUNCTION_ARGUMENT` if any pointer argument is null.
/// - `CURLE_NOT_BUILT_IN` if no active WebSocket connection exists.
///
/// # Safety
///
/// The caller must ensure:
/// - `curl` was created by `curl_easy_init()` and has not been freed.
/// - `buffer` points to at least `buflen` bytes of writable memory.
/// - `nread` points to a writable `size_t`.
/// - `metap` points to a writable `*const curl_ws_frame` pointer.
/// - No other thread is concurrently using the same `curl` handle.
///
/// # C Equivalent
///
/// ```c
/// CURLcode curl_ws_recv(CURL *curl, void *buffer, size_t buflen,
///                        size_t *recv, const struct curl_ws_frame **metap);
/// ```
///
/// Defined in `include/curl/websockets.h` line 55.
#[no_mangle]
pub unsafe extern "C" fn curl_ws_recv(
    curl: *mut CURL,
    buffer: *mut c_void,
    buflen: size_t,
    nread: *mut size_t,
    metap: *mut *const curl_ws_frame,
) -> CURLcode {
    // SAFETY: We validate all raw pointers before dereferencing. The caller
    // guarantees that `curl` was created by `curl_easy_init()`, `buffer`
    // points to a valid allocation of at least `buflen` bytes, and `nread`
    // and `metap` point to writable memory of the correct types. We perform
    // explicit null checks before any dereference.

    // --- Null-pointer validation ---
    if curl.is_null() || buffer.is_null() || nread.is_null() || metap.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }

    // SAFETY: nread and metap are verified non-null above. Initializing
    // output parameters to safe defaults before any early return ensures
    // the caller never reads uninitialized memory.
    *nread = 0;
    *metap = ptr::null();

    // Zero-length buffer is invalid.
    if buflen == 0 {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }

    // Convert opaque CURL* to &mut EasyHandle.
    let handle = match handle_from_ptr(curl) {
        Some(h) => h,
        None => return CURLE_BAD_FUNCTION_ARGUMENT,
    };

    // Attempt to get the WebSocket state from the active connection.
    let ws = match get_websocket(handle) {
        Some(ws_state) => ws_state,
        None => return CURLE_NOT_BUILT_IN,
    };

    // SAFETY: `buffer` is verified non-null and the caller guarantees it
    // points to at least `buflen` bytes of writable memory.
    let buf_slice = std::slice::from_raw_parts_mut(buffer as *mut u8, buflen);

    // Create a network recv callback. In the complete implementation, this
    // reads from the easy handle's active connection socket.
    let mut recv_fn = |dest: &mut [u8]| -> Result<usize, CurlError> {
        // Placeholder: when the connection subsystem is wired up, this will
        // call into the socket layer to read raw bytes from the network.
        let _ = dest;
        Err(CurlError::RecvError)
    };

    // Delegate to the Rust WebSocket receive implementation.
    match ws::ws_recv(ws, buf_slice, &mut recv_fn) {
        Ok((bytes_read, frame)) => {
            // SAFETY: nread was verified non-null at function entry.
            *nread = bytes_read;

            // Store the frame metadata in thread-local storage so the
            // pointer remains stable until the next call.
            let c_frame = rust_frame_to_c(&frame);
            LAST_WS_FRAME.with(|cell| {
                *cell.borrow_mut() = c_frame;
            });

            // SAFETY: metap was verified non-null at function entry.
            // The pointer we store points into the thread-local static,
            // which remains valid until the next call to curl_ws_recv.
            LAST_WS_FRAME.with(|cell| {
                *metap = cell.as_ptr() as *const curl_ws_frame;
            });

            CURLE_OK
        }
        Err(e) => error_to_code(e),
    }
}

// ---------------------------------------------------------------------------
// curl_ws_send — Send WebSocket data
// ---------------------------------------------------------------------------

/// Sends data over a WebSocket connection.
///
/// Encodes `buflen` bytes from `buffer` as a WebSocket frame with the
/// specified `flags` and sends it over the connection. Sets `*sent` to
/// the number of payload bytes actually sent.
///
/// For fragmented sends, `fragsize` specifies the total message size
/// (used with `CURLWS_OFFSET` flag). Set `fragsize` to 0 for
/// non-fragmented sends.
///
/// # Parameters
///
/// - `curl`: Easy handle with an active WebSocket connection.
/// - `buffer`: Source buffer containing payload data to send.
/// - `buflen`: Number of bytes to send from `buffer`.
/// - `sent`: Output — set to the number of bytes actually sent.
/// - `fragsize`: Total message size for fragmented sends (0 if not fragmented).
/// - `flags`: Bitmask of `CURLWS_*` frame-type flags (TEXT, BINARY, CLOSE,
///   PING, PONG, CONT, OFFSET).
///
/// # Returns
///
/// - `CURLE_OK` on success.
/// - `CURLE_BAD_FUNCTION_ARGUMENT` if any required pointer argument is null.
/// - `CURLE_NOT_BUILT_IN` if no active WebSocket connection exists.
///
/// # Safety
///
/// The caller must ensure:
/// - `curl` was created by `curl_easy_init()` and has not been freed.
/// - `buffer` points to at least `buflen` bytes of readable memory (or is
///   null when `buflen` is 0).
/// - `sent` points to a writable `size_t`.
/// - No other thread is concurrently using the same `curl` handle.
///
/// # C Equivalent
///
/// ```c
/// CURLcode curl_ws_send(CURL *curl, const void *buffer,
///                        size_t buflen, size_t *sent,
///                        curl_off_t fragsize, unsigned int flags);
/// ```
///
/// Defined in `include/curl/websockets.h` line 70.
#[no_mangle]
pub unsafe extern "C" fn curl_ws_send(
    curl: *mut CURL,
    buffer: *const c_void,
    buflen: size_t,
    sent: *mut size_t,
    fragsize: curl_off_t,
    flags: c_uint,
) -> CURLcode {
    // SAFETY: We validate all raw pointers before dereferencing. The caller
    // guarantees that `curl` was created by `curl_easy_init()`, `buffer`
    // points to `buflen` bytes of readable memory, and `sent` points to
    // writable `size_t` memory. We perform explicit null checks first.

    // --- Null-pointer validation ---
    if curl.is_null() || sent.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }

    // buffer may be null when buflen is 0 (e.g., sending a CLOSE frame
    // with no payload). Validate that non-zero buflen has a valid buffer.
    if buflen > 0 && buffer.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }

    // SAFETY: sent is verified non-null above. Initialize to 0.
    *sent = 0;

    // Convert opaque CURL* to &mut EasyHandle.
    let handle = match handle_from_ptr(curl) {
        Some(h) => h,
        None => return CURLE_BAD_FUNCTION_ARGUMENT,
    };

    // Attempt to get the WebSocket state from the active connection.
    let ws = match get_websocket(handle) {
        Some(ws_state) => ws_state,
        None => return CURLE_NOT_BUILT_IN,
    };

    // SAFETY: `buffer` is verified non-null (or buflen is 0, making the
    // slice empty). The caller guarantees at least `buflen` readable bytes.
    let buf_slice: &[u8] = if buflen > 0 {
        std::slice::from_raw_parts(buffer as *const u8, buflen)
    } else {
        &[]
    };

    let rust_flags = c_flags_to_rust(flags);

    // Create a network send callback. In the complete implementation, this
    // writes to the easy handle's active connection socket.
    let mut send_fn = |data: &[u8]| -> Result<usize, CurlError> {
        // Placeholder: when the connection subsystem is wired up, this will
        // call into the socket layer to write raw bytes to the network.
        let _ = data;
        Err(CurlError::SendError)
    };

    // Delegate to the Rust WebSocket send implementation.
    match ws::ws_send(ws, buf_slice, fragsize, rust_flags, &mut send_fn) {
        Ok(bytes_sent) => {
            // SAFETY: sent was verified non-null at function entry.
            *sent = bytes_sent;
            CURLE_OK
        }
        Err(e) => error_to_code(e),
    }
}

// ---------------------------------------------------------------------------
// curl_ws_start_frame — Start a new WebSocket frame for streaming
// ---------------------------------------------------------------------------

/// Starts a new WebSocket frame with the given flags and total payload length.
///
/// This function buffers the frame header internally. After calling this,
/// use repeated calls to `curl_ws_send` (with the same flags) to stream
/// the payload data in chunks. An error is returned if a previous frame
/// has not been completed (i.e., not all payload bytes have been sent).
///
/// # Parameters
///
/// - `curl`: Easy handle with an active WebSocket connection.
/// - `flags`: Bitmask of `CURLWS_*` frame-type flags.
/// - `frame_len`: Total payload length of the frame being started.
///
/// # Returns
///
/// - `CURLE_OK` on success.
/// - `CURLE_BAD_FUNCTION_ARGUMENT` if `curl` is null.
/// - `CURLE_NOT_BUILT_IN` if no active WebSocket connection exists.
/// - `CURLE_SEND_ERROR` if a previous frame has not been completed.
///
/// # Safety
///
/// The caller must ensure:
/// - `curl` was created by `curl_easy_init()` and has not been freed.
/// - No other thread is concurrently using the same `curl` handle.
///
/// # C Equivalent
///
/// ```c
/// CURLcode curl_ws_start_frame(CURL *curl,
///                               unsigned int flags,
///                               curl_off_t frame_len);
/// ```
///
/// Defined in `include/curl/websockets.h` line 84.
#[no_mangle]
pub unsafe extern "C" fn curl_ws_start_frame(
    curl: *mut CURL,
    flags: c_uint,
    frame_len: curl_off_t,
) -> CURLcode {
    // SAFETY: We validate the curl pointer before dereferencing. The caller
    // guarantees that `curl` was created by `curl_easy_init()`. The `flags`
    // and `frame_len` parameters are value types requiring no pointer safety.

    // --- Null-pointer validation ---
    if curl.is_null() {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }

    // Convert opaque CURL* to &mut EasyHandle.
    let handle = match handle_from_ptr(curl) {
        Some(h) => h,
        None => return CURLE_BAD_FUNCTION_ARGUMENT,
    };

    // Attempt to get the WebSocket state from the active connection.
    let ws = match get_websocket(handle) {
        Some(ws_state) => ws_state,
        None => return CURLE_NOT_BUILT_IN,
    };

    let rust_flags = c_flags_to_rust(flags);

    // Delegate to the Rust WebSocket start-frame implementation.
    match ws::ws_start_frame(ws, rust_flags, frame_len) {
        Ok(()) => CURLE_OK,
        Err(e) => error_to_code(e),
    }
}

// ---------------------------------------------------------------------------
// curl_ws_meta — Retrieve most recent frame metadata
// ---------------------------------------------------------------------------

/// Returns a pointer to the most recently received WebSocket frame metadata.
///
/// The returned pointer points to a `curl_ws_frame` struct that describes
/// the last frame received via `curl_ws_recv`. The pointer remains valid
/// until the next call to `curl_ws_recv` on the same thread.
///
/// Returns a null pointer if:
/// - `curl` is null.
/// - No WebSocket connection is active.
/// - No frame has been received yet.
/// - The connection is in raw mode.
///
/// # Parameters
///
/// - `curl`: Easy handle with an active WebSocket connection.
///
/// # Returns
///
/// Pointer to the frame metadata, or null if no frame is available.
///
/// # Safety
///
/// The caller must ensure:
/// - `curl` was created by `curl_easy_init()` and has not been freed.
/// - No other thread is concurrently using the same `curl` handle.
/// - The returned pointer is not used after the next call to
///   `curl_ws_recv` on the same thread (which may overwrite the data).
///
/// # C Equivalent
///
/// ```c
/// const struct curl_ws_frame *curl_ws_meta(CURL *curl);
/// ```
///
/// Defined in `include/curl/websockets.h` line 92.
#[no_mangle]
pub unsafe extern "C" fn curl_ws_meta(
    curl: *mut CURL,
) -> *const curl_ws_frame {
    // SAFETY: We validate the curl pointer before dereferencing. The caller
    // guarantees that `curl` was created by `curl_easy_init()`. The returned
    // pointer points into thread-local storage and remains valid until the
    // next `curl_ws_recv` call on this thread.

    // --- Null-pointer validation ---
    if curl.is_null() {
        return ptr::null();
    }

    // Convert opaque CURL* to &mut EasyHandle.
    let handle = match handle_from_ptr(curl) {
        Some(h) => h,
        None => return ptr::null(),
    };

    // Attempt to get the WebSocket state from the active connection.
    let ws = match get_websocket(handle) {
        Some(ws_state) => ws_state,
        None => return ptr::null(),
    };

    // Delegate to the Rust WebSocket meta implementation.
    match ws::ws_meta(ws) {
        Some(frame) => {
            // Convert the Rust frame to C-compatible layout and store
            // in thread-local storage for stable pointer lifetime.
            let c_frame = rust_frame_to_c(frame);
            LAST_WS_FRAME.with(|cell| {
                *cell.borrow_mut() = c_frame;
            });

            // Return a pointer into the thread-local storage.
            LAST_WS_FRAME.with(|cell| cell.as_ptr() as *const curl_ws_frame)
        }
        None => ptr::null(),
    }
}

// ===========================================================================
// Section 5: Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that CURLWS_RAW_MODE matches the C header value.
    #[test]
    fn curlws_raw_mode_value() {
        assert_eq!(CURLWS_RAW_MODE, 1);
    }

    /// Verify that CURLWS_NOAUTOPONG matches the C header value.
    #[test]
    fn curlws_noautopong_value() {
        assert_eq!(CURLWS_NOAUTOPONG, 2);
    }

    /// Verify that null CURL pointer returns CURLE_BAD_FUNCTION_ARGUMENT
    /// for curl_ws_recv.
    #[test]
    fn ws_recv_null_curl_returns_error() {
        unsafe {
            let mut nread: size_t = 0;
            let mut metap: *const curl_ws_frame = ptr::null();
            let mut buf = [0u8; 64];
            let code = curl_ws_recv(
                ptr::null_mut(),
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                &mut nread as *mut size_t,
                &mut metap as *mut *const curl_ws_frame,
            );
            assert_eq!(code, CURLE_BAD_FUNCTION_ARGUMENT);
        }
    }

    /// Verify that null buffer returns CURLE_BAD_FUNCTION_ARGUMENT
    /// for curl_ws_recv.
    #[test]
    fn ws_recv_null_buffer_returns_error() {
        unsafe {
            let mut nread: size_t = 0;
            let mut metap: *const curl_ws_frame = ptr::null();
            // Use a dummy non-null CURL pointer (won't be dereferenced
            // because the null buffer check comes first).
            let dummy: u8 = 0;
            let code = curl_ws_recv(
                &dummy as *const u8 as *mut CURL,
                ptr::null_mut(),
                64,
                &mut nread as *mut size_t,
                &mut metap as *mut *const curl_ws_frame,
            );
            assert_eq!(code, CURLE_BAD_FUNCTION_ARGUMENT);
        }
    }

    /// Verify that null CURL pointer returns CURLE_BAD_FUNCTION_ARGUMENT
    /// for curl_ws_send.
    #[test]
    fn ws_send_null_curl_returns_error() {
        unsafe {
            let mut sent: size_t = 0;
            let buf = [0u8; 4];
            let code = curl_ws_send(
                ptr::null_mut(),
                buf.as_ptr() as *const c_void,
                buf.len(),
                &mut sent as *mut size_t,
                0,
                0,
            );
            assert_eq!(code, CURLE_BAD_FUNCTION_ARGUMENT);
        }
    }

    /// Verify that null CURL pointer returns CURLE_BAD_FUNCTION_ARGUMENT
    /// for curl_ws_start_frame.
    #[test]
    fn ws_start_frame_null_curl_returns_error() {
        unsafe {
            let code = curl_ws_start_frame(ptr::null_mut(), 0, 0);
            assert_eq!(code, CURLE_BAD_FUNCTION_ARGUMENT);
        }
    }

    /// Verify that null CURL pointer returns null for curl_ws_meta.
    #[test]
    fn ws_meta_null_curl_returns_null() {
        unsafe {
            let result = curl_ws_meta(ptr::null_mut());
            assert!(result.is_null());
        }
    }

    /// Verify that the Rust-to-C frame conversion preserves all fields.
    #[test]
    fn frame_conversion_preserves_fields() {
        let rust_frame = WsFrame {
            age: 0,
            flags: WsFlags::from_bits(0x03), // TEXT | BINARY
            offset: 1024,
            len: 256,
            bytesleft: 4096,
        };
        let c_frame = rust_frame_to_c(&rust_frame);
        assert_eq!(c_frame.age, 0);
        assert_eq!(c_frame.flags, 0x03);
        assert_eq!(c_frame.offset, 1024);
        assert_eq!(c_frame.len, 256);
        assert_eq!(c_frame.bytesleft, 4096);
    }

    /// Verify that C flags are correctly converted to Rust WsFlags.
    #[test]
    fn c_flags_conversion() {
        let flags = c_flags_to_rust(0x01); // CURLWS_TEXT
        assert!(flags.contains(WsFlags::TEXT));
        assert!(!flags.contains(WsFlags::BINARY));

        let flags2 = c_flags_to_rust(0x03); // TEXT | BINARY
        assert!(flags2.contains(WsFlags::TEXT));
        assert!(flags2.contains(WsFlags::BINARY));
    }

    /// Verify zero-length buffer returns CURLE_BAD_FUNCTION_ARGUMENT.
    #[test]
    fn ws_recv_zero_buflen_returns_error() {
        unsafe {
            let mut nread: size_t = 0;
            let mut metap: *const curl_ws_frame = ptr::null();
            let mut buf = [0u8; 1];
            // Use a non-null dummy for curl; the zero-buflen check happens
            // after null checks but before handle conversion.
            let dummy: u8 = 0;
            let code = curl_ws_recv(
                &dummy as *const u8 as *mut CURL,
                buf.as_mut_ptr() as *mut c_void,
                0, // zero length
                &mut nread as *mut size_t,
                &mut metap as *mut *const curl_ws_frame,
            );
            assert_eq!(code, CURLE_BAD_FUNCTION_ARGUMENT);
        }
    }
}
