// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! `curl_ws_*` C ABI entry points — the WebSocket surface of libcurl.
//!
//! This module is the `extern "C"` home of the four public WebSocket functions of the libcurl
//! ABI, all declared in `include/curl/websockets.h`: [`curl_ws_recv`], [`curl_ws_send`],
//! [`curl_ws_start_frame`], and [`curl_ws_meta`]. It is derived 1:1 from that header and the C
//! entry point `lib/ws.c`, which is retained in-tree as a read-only source-of-truth reference
//! (AAP §0.4.1). The WebSocket API operates on an easy handle that has completed a
//! `curl_easy_perform()` in `CURLOPT_CONNECT_ONLY` mode (the same model curl uses).
//!
//! # Frozen ABI surface
//! Besides the four functions, this module owns the WebSocket ABI types the header defines and
//! that no sibling module owns: the [`curl_ws_frame`] metadata struct (byte-exact field order
//! and types) and the `CURLWS_*` bit constants. Their integer values are a **frozen ABI
//! contract** transcribed verbatim from `include/curl/websockets.h` (AAP §0.6.1): the seven
//! frame/flag bits [`CURLWS_TEXT`]…[`CURLWS_PONG`], and the two `CURLOPT_WS_OPTIONS` bitmask bits
//! [`CURLWS_RAW_MODE`] and [`CURLWS_NOAUTOPONG`]. `cbindgen` regenerates the C declarations from
//! these definitions for the verification header; it never clobbers the committed header, which
//! remains authoritative.
//!
//! # Handle model
//! The opaque C `CURL *` is a `Box<`[`curl_rs_lib::url::Easy`]`>` in disguise (see `easy.rs`);
//! every signature therefore uses `*mut c_void`, matching the `typedef void CURL;` in the public
//! headers. Borrowing a live handle goes through [`as_mut`] / [`as_ref`], which null-check the
//! pointer and bound the borrow to the call — this module never reclaims (frees) the handle;
//! that is [`curl_easy_cleanup`](crate::easy)'s job.
//!
//! # Safety and unwinding (AAP §0.6.2 / §0.7.2 — binding)
//! `curl-rs-ffi` is the sole crate permitted to use `unsafe`; `curl-rs-lib` is built with
//! `#![forbid(unsafe_code)]`. Every `unsafe` block here carries a `// SAFETY:` comment stating the
//! invariant it upholds, and `#![deny(unsafe_op_in_unsafe_fn)]` (below) forces each raw operation
//! into its own annotated block even inside an `unsafe extern "C" fn`. No panic may unwind across
//! the `extern "C" fn` boundary: the `CURLcode`-returning entry points run their fallible bodies
//! inside [`ffi_guard`] (which maps a caught panic to an error code), and the pointer-returning
//! [`curl_ws_meta`] runs inside [`catch_unwind`] (which yields the null sentinel), mirroring
//! curl's own out-of-band `NULL` / error-code returns.
//!
//! # Behavioral parity (AAP §0.6.3, §0.7.3)
//! The reachable argument-validation prologue of each function reproduces `lib/ws.c` exactly —
//! the same NULL/bad-handle checks and the same `CURLcode` values curl returns before a live
//! WebSocket connection is consulted. The receive/transmit data path (frame decode/encode, the
//! automatic PING→PONG response, and the `curl_ws_frame` payload accounting) is driven by the
//! core WebSocket protocol in `curl-rs-lib`; that wiring is not yet connected to [`Easy`] at this
//! checkpoint, so the branches that require a live connection are marked `// NOTE(parity):` and
//! return the exact `CURLcode` curl returns for a not-yet-connected handle. The ABI — signatures,
//! struct layout, and frozen integer values — is exact now regardless of that wiring.

// Force every raw-pointer operation into an explicit `unsafe { … }` block carrying its own
// adjacent `// SAFETY:` note, even inside an `unsafe extern "C" fn` (AAP §0.7.2). The C-style
// symbol/type names (`curl_ws_frame`, `curl_ws_recv`, `CURLWS_*`) are permitted by the
// crate-root `#![allow(non_camel_case_types)]` / `#![allow(non_snake_case)]` in `lib.rs`.
#![deny(unsafe_op_in_unsafe_fn)]

use crate::easy::curl_off_t;
use crate::{as_mut, as_ref, ffi_guard, CURLcode};
use curl_rs_lib::url::Easy;
use libc::{c_int, c_long, c_uint, c_void, size_t};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

// ===========================================================================
// Frozen ABI types and constants (include/curl/websockets.h) owned by this module.
// ===========================================================================

/// `struct curl_ws_frame` — metadata describing the WebSocket frame currently being received
/// (`include/curl/websockets.h`).
///
/// The field order and types are byte-exact with the C definition so the struct has an identical
/// layout under `#[repr(C)]`; libcurl hands a caller a `const struct curl_ws_frame *` (via the
/// `metap` out-parameter of [`curl_ws_recv`] or the return of [`curl_ws_meta`]) that points at
/// handle-owned storage — the caller must **not** free it, and it stays valid only until the next
/// WebSocket call on the same handle.
#[repr(C)]
pub struct curl_ws_frame {
    /// `int age` — reserved for versioning this struct; currently always zero.
    pub age: c_int,
    /// `int flags` — a bitwise-OR of the `CURLWS_*` frame/flag bits describing this frame
    /// (e.g. [`CURLWS_TEXT`], [`CURLWS_BINARY`], [`CURLWS_CLOSE`]).
    pub flags: c_int,
    /// `curl_off_t offset` — the byte offset of this data chunk into the overall frame payload.
    pub offset: curl_off_t,
    /// `curl_off_t bytesleft` — the number of payload bytes still pending after this chunk.
    pub bytesleft: curl_off_t,
    /// `size_t len` — the size, in bytes, of the current data chunk.
    pub len: size_t,
}

// --- Frame / flag bits (the `flags` field and the `flags` argument of curl_ws_send) ----------
//
// These are curl's `(1 << n)` frame-type / control bits. curl's C macros are plain `int`; the
// primary API consumer is `curl_ws_send(… , unsigned int flags)`, so they are typed `c_uint`
// here and compose naturally into the `flags` argument (and, cast to `c_int`, into the
// `curl_ws_frame.flags` field). Values are frozen and unit-tested below.

/// `#define CURLWS_TEXT (1 << 0)` — the frame carries UTF-8 text payload.
pub const CURLWS_TEXT: c_uint = 1 << 0;
/// `#define CURLWS_BINARY (1 << 1)` — the frame carries binary payload.
pub const CURLWS_BINARY: c_uint = 1 << 1;
/// `#define CURLWS_CONT (1 << 2)` — this is a continuation of a fragmented frame (more to come).
pub const CURLWS_CONT: c_uint = 1 << 2;
/// `#define CURLWS_CLOSE (1 << 3)` — a CLOSE control frame.
pub const CURLWS_CLOSE: c_uint = 1 << 3;
/// `#define CURLWS_PING (1 << 4)` — a PING control frame.
pub const CURLWS_PING: c_uint = 1 << 4;
/// `#define CURLWS_OFFSET (1 << 5)` — the send is a partial frame; `fragsize`/offset apply.
pub const CURLWS_OFFSET: c_uint = 1 << 5;
/// `#define CURLWS_PONG (1 << 6)` — a PONG control frame (a flag for [`curl_ws_send`]).
pub const CURLWS_PONG: c_uint = 1 << 6;

// --- CURLOPT_WS_OPTIONS bitmask bits ---------------------------------------------------------
//
// curl declares these with the `1L` suffix, i.e. C `long`; `CURLOPT_WS_OPTIONS` is a
// `CURLOPTTYPE_LONG` option whose value is fetched as a `long`, so they are typed `c_long`.

/// `#define CURLWS_RAW_MODE (1L << 0)` — deliver raw WebSocket frames without libcurl's
/// automatic framing/decoding (a `CURLOPT_WS_OPTIONS` bit).
pub const CURLWS_RAW_MODE: c_long = 1 << 0;
/// `#define CURLWS_NOAUTOPONG (1L << 1)` — suppress libcurl's automatic PONG response to PING
/// frames (a `CURLOPT_WS_OPTIONS` bit).
pub const CURLWS_NOAUTOPONG: c_long = 1 << 1;

// ===========================================================================
// The four `CURL_EXTERN` WebSocket entry points (include/curl/websockets.h).
// ===========================================================================

/// `CURLcode curl_ws_recv(CURL *curl, void *buffer, size_t buflen, size_t *recv,
/// const struct curl_ws_frame **metap);`
///
/// Receive a chunk of a WebSocket frame into `buffer[..buflen]` on a handle connected with
/// `CURLOPT_CONNECT_ONLY`. On entry both out-parameters are cleared (`*recv = 0`,
/// `*metap = NULL`); on success `*recv` holds the number of payload bytes written into `buffer`
/// and `*metap` points at the handle-owned [`curl_ws_frame`] describing the current frame (valid
/// until the next WebSocket call on the handle — the caller must not free it). Returns `CURLE_OK`,
/// `CURLE_AGAIN` when no data is available yet, or a mapped error.
///
/// # Safety
/// `curl` must be null or a valid, live handle produced by this crate's constructors; when
/// `buflen != 0`, `buffer` must be valid for writes of `buflen` bytes; `recv`, when non-null, must
/// be a valid `size_t *`; and `metap`, when non-null, must be a valid `*const curl_ws_frame` slot.
/// All must remain valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn curl_ws_recv(
    curl: *mut c_void,
    buffer: *mut c_void,
    buflen: size_t,
    recv: *mut size_t,
    metap: *mut *const curl_ws_frame,
) -> c_int {
    ffi_guard(
        CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
        AssertUnwindSafe(move || {
            // curl clears both out-parameters first (`*nread = 0; *metap = NULL;` in lib/ws.c). It
            // dereferences them unconditionally; the boundary layer must never dereference a NULL
            // pointer (AAP §0.6.2), so each write is null-checked while preserving curl's
            // observable "cleared on entry" behavior for the valid (non-null) case. The parameter
            // is named `recv` for byte-exact ABI parity with the header; it is only ever written
            // through, never confused with a receive operation.
            if !recv.is_null() {
                // SAFETY: `recv` is non-null (checked) and, per the contract, points to a writable
                // `size_t` valid for this call.
                unsafe {
                    *recv = 0;
                }
            }
            if !metap.is_null() {
                // SAFETY: `metap` is non-null (checked) and points to a writable
                // `*const curl_ws_frame` slot valid for this call.
                unsafe {
                    *metap = ptr::null();
                }
            }
            // `GOOD_EASY_HANDLE(data)` → a null / invalid handle is `CURLE_BAD_FUNCTION_ARGUMENT`.
            // SAFETY: per the C contract `curl` is null or a live `Easy`; `as_mut` null-checks it
            // and borrows it for this call only (the handle is never reclaimed here).
            let easy = match unsafe { as_mut::<Easy>(curl as *mut Easy) } {
                Some(easy) => easy,
                None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
            };
            // `(buflen && !buffer)` → asking for bytes with no destination buffer is invalid.
            if buflen != 0 && buffer.is_null() {
                return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int;
            }
            // curl then consults `data->conn`. With no connection it distinguishes two cases
            // (lib/ws.c):
            //   * not in CONNECT_ONLY mode → CURLE_UNSUPPORTED_PROTOCOL ("CONNECT_ONLY is required")
            //   * in CONNECT_ONLY mode but no established connection → CURLE_BAD_FUNCTION_ARGUMENT
            //     ("connection not found")
            // NOTE(parity): the receive data path (frame decode + automatic PING→PONG) is driven by
            // the core WebSocket protocol once it is wired to `Easy`; no live connection exists at
            // this checkpoint, so these two reachable return codes are byte-exact with curl now.
            if !easy.set.connect_only {
                return CURLcode::CURLE_UNSUPPORTED_PROTOCOL as c_int;
            }
            CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int
        }),
    )
}

/// `CURLcode curl_ws_send(CURL *curl, const void *buffer, size_t buflen, size_t *sent,
/// curl_off_t fragsize, unsigned int flags);`
///
/// Send `buflen` bytes from `buffer` as a WebSocket frame described by `flags` (a bitwise-OR of
/// the `CURLWS_*` bits — [`CURLWS_TEXT`], [`CURLWS_BINARY`], [`CURLWS_PING`], [`CURLWS_PONG`],
/// [`CURLWS_CLOSE`], [`CURLWS_CONT`], [`CURLWS_OFFSET`]) on a handle connected with
/// `CURLOPT_CONNECT_ONLY`. `fragsize` is the total size of the fragment when a frame is sent in
/// parts (`0` for a complete frame). `*sent` receives the number of bytes accepted; matching curl,
/// a null `sent` is tolerated. Returns `CURLE_OK`, `CURLE_AGAIN` on a would-block, or a mapped
/// error.
///
/// # Safety
/// `curl` must be null or a valid, live handle; when `buflen != 0`, `buffer` must be valid for
/// reads of `buflen` bytes; `sent`, when non-null, must be a valid `size_t *`. All must remain
/// valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn curl_ws_send(
    curl: *mut c_void,
    buffer: *const c_void,
    buflen: size_t,
    sent: *mut size_t,
    fragsize: curl_off_t,
    flags: c_uint,
) -> c_int {
    // `fragsize` and `flags` steer the frame encoder, which is reached only once a live connection
    // exists (see the NOTE(parity) below); bind them here so the exact ABI signature is preserved
    // without an unused-variable warning under `-D warnings`.
    let _ = (fragsize, flags);
    ffi_guard(
        CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
        AssertUnwindSafe(move || {
            // `GOOD_EASY_HANDLE(data)` is checked before `sent` is touched (lib/ws.c).
            // SAFETY: per the C contract `curl` is null or a live `Easy`; `as_mut` null-checks it
            // and borrows it for this call only (never reclaimed here).
            let _easy = match unsafe { as_mut::<Easy>(curl as *mut Easy) } {
                Some(easy) => easy,
                None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
            };
            // curl tolerates a NULL `sent` (`size_t *pnsent = sent ? sent : &ndummy;`) and then
            // clears it (`*pnsent = 0;`). Honor that: only write through a non-null `sent`.
            if !sent.is_null() {
                // SAFETY: `sent` is non-null (checked) and points to a writable `size_t` valid for
                // this call.
                unsafe {
                    *sent = 0;
                }
            }
            // `if(!buffer && buflen)` → a non-empty send with a NULL payload is invalid.
            if buffer.is_null() && buflen != 0 {
                return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int;
            }
            // curl next requires an associated connection (attaching the CONNECT_ONLY connection
            // first); without one it returns CURLE_SEND_ERROR ("No associated connection").
            // NOTE(parity): frame encoding and transmission are driven by the core WebSocket
            // protocol once it is wired to `Easy`; no connection can be attached at this checkpoint,
            // so curl's `if(!data->conn)` outcome is the reachable, byte-exact result.
            CURLcode::CURLE_SEND_ERROR as c_int
        }),
    )
}

/// `CURLcode curl_ws_start_frame(CURL *curl, unsigned int flags, curl_off_t frame_len);`
///
/// Buffer a WebSocket frame header describing a frame of total length `frame_len` with the given
/// `flags` (a bitwise-OR of the `CURLWS_*` bits), so subsequent [`curl_ws_send`] calls append its
/// payload in parts. curl rejects this call in raw mode ([`CURLWS_RAW_MODE`]) and when a previous
/// frame is still incomplete. Returns `CURLE_OK` or a mapped error.
///
/// # Safety
/// `curl` must be null or a valid, live handle produced by this crate's constructors.
#[no_mangle]
pub unsafe extern "C" fn curl_ws_start_frame(
    curl: *mut c_void,
    flags: c_uint,
    frame_len: curl_off_t,
) -> c_int {
    // `flags` and `frame_len` are consumed by the frame-head encoder, reached only once a live
    // connection exists (see the NOTE(parity) below); bind them so the exact ABI signature is
    // preserved without an unused-variable warning under `-D warnings`.
    let _ = (flags, frame_len);
    ffi_guard(
        CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
        AssertUnwindSafe(move || {
            // `GOOD_EASY_HANDLE(data)` → a null / invalid handle is `CURLE_BAD_FUNCTION_ARGUMENT`.
            // SAFETY: per the C contract `curl` is null or a live `Easy`; `as_mut` null-checks it
            // and borrows it for this call only (never reclaimed here).
            let easy = match unsafe { as_mut::<Easy>(curl as *mut Easy) } {
                Some(easy) => easy,
                None => return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int,
            };
            // curl rejects starting a frame while raw mode is enabled, up front: CURLE_FAILED_INIT
            // ("cannot curl_ws_start_frame() with CURLWS_RAW_MODE enabled").
            if easy.set.ws_raw_mode {
                return CURLcode::CURLE_FAILED_INIT as c_int;
            }
            // curl then requires an associated connection; without one it returns CURLE_SEND_ERROR
            // ("No associated connection"). The subsequent "previous frame not finished" guard in
            // curl also returns CURLE_SEND_ERROR.
            // NOTE(parity): frame-head buffering is driven by the core WebSocket protocol once it is
            // wired to `Easy`; no live connection exists at this checkpoint, so curl's
            // `if(!data->conn)` outcome is the reachable, byte-exact result.
            CURLcode::CURLE_SEND_ERROR as c_int
        }),
    )
}

/// `const struct curl_ws_frame *curl_ws_meta(CURL *curl);`
///
/// Return a pointer to the handle-owned [`curl_ws_frame`] describing the frame currently being
/// received, for use from within a write callback on a non-raw-mode WebSocket transfer. The
/// returned pointer is handle-owned (the caller must not free it) and stays valid until the next
/// WebSocket call. Returns null when the metadata is not applicable (e.g. outside a write callback,
/// in raw mode, or when the handle has no live WebSocket connection).
///
/// # Safety
/// `curl` must be null or a valid, live handle produced by this crate's constructors.
#[no_mangle]
pub unsafe extern "C" fn curl_ws_meta(curl: *mut c_void) -> *const curl_ws_frame {
    // Pointer-returning entry point: a panic must not unwind across the FFI boundary, so the body
    // runs inside `catch_unwind` and any caught panic yields the null sentinel (mirroring curl's
    // `return NULL;`).
    catch_unwind(AssertUnwindSafe(move || {
        // `GOOD_EASY_HANDLE(data)` → a null / invalid handle yields null.
        // SAFETY: per the C contract `curl` is null or a live `Easy`; `as_ref` null-checks it and
        // borrows it (read-only) for this call only.
        let _easy = match unsafe { as_ref::<Easy>(curl as *const Easy) } {
            Some(easy) => easy,
            None => return ptr::null(),
        };
        // curl returns `&ws->recvframe` only when the call originates inside a write callback
        // (`Curl_is_in_callback`), the handle has a live connection, it is not in raw mode, and the
        // connection carries WebSocket metadata; otherwise it falls through to `return NULL;`.
        // NOTE(parity): callback-context tracking and the live WebSocket connection are driven by
        // the core protocol once wired to `Easy`; none exist at this checkpoint, so the fall-through
        // NULL is always the reachable, byte-exact result. When wired, return `&ws.recvframe` here.
        ptr::null()
    }))
    .unwrap_or(ptr::null())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::{
        curl_ws_frame, curl_ws_meta, curl_ws_recv, curl_ws_send, curl_ws_start_frame,
        CURLWS_BINARY, CURLWS_CLOSE, CURLWS_CONT, CURLWS_NOAUTOPONG, CURLWS_OFFSET, CURLWS_PING,
        CURLWS_PONG, CURLWS_RAW_MODE, CURLWS_TEXT,
    };
    use crate::easy::curl_off_t;
    use crate::{box_from_raw, box_into_raw, CURLcode};
    use curl_rs_lib::url::Easy;
    use libc::{c_int, c_void, size_t};
    use std::{mem, ptr};

    /// Build a live raw handle from a freshly-opened [`Easy`] configured by `cfg`, invoke `f` with
    /// the opaque `CURL *`, then reclaim and drop the handle so the test leaks nothing.
    fn with_handle<R>(cfg: impl FnOnce(&mut Easy), f: impl FnOnce(*mut c_void) -> R) -> R {
        let mut easy = Easy::open();
        cfg(&mut easy);
        let raw = box_into_raw(easy);
        let out = f(raw as *mut c_void);
        // SAFETY: `raw` was just produced by `box_into_raw` for `Easy`, is non-null, and is
        // reclaimed exactly once here.
        let _reclaimed = unsafe { box_from_raw(raw) };
        out
    }

    // --- Frozen constant values (include/curl/websockets.h) ---------------------------------

    #[test]
    fn frame_flag_bits_match_frozen_abi() {
        assert_eq!(CURLWS_TEXT, 1 << 0);
        assert_eq!(CURLWS_BINARY, 1 << 1);
        assert_eq!(CURLWS_CONT, 1 << 2);
        assert_eq!(CURLWS_CLOSE, 1 << 3);
        assert_eq!(CURLWS_PING, 1 << 4);
        assert_eq!(CURLWS_OFFSET, 1 << 5);
        assert_eq!(CURLWS_PONG, 1 << 6);
    }

    #[test]
    fn ws_options_bits_match_frozen_abi() {
        assert_eq!(CURLWS_RAW_MODE, 1);
        assert_eq!(CURLWS_NOAUTOPONG, 2);
    }

    // --- curl_ws_frame layout ---------------------------------------------------------------

    #[test]
    fn curl_ws_frame_layout_is_byte_exact() {
        // Field order/types byte-exact with the C struct: (age, flags: c_int),
        // (offset, bytesleft: curl_off_t), (len: size_t). Constructing with typed literals is a
        // compile-time check of the contract; the runtime asserts confirm the values round-trip.
        let f = curl_ws_frame {
            age: 0,
            flags: (CURLWS_TEXT | CURLWS_CONT) as c_int,
            offset: 4,
            bytesleft: 7,
            len: 3,
        };
        assert_eq!(f.age, 0);
        assert_eq!(f.flags, (CURLWS_TEXT | CURLWS_CONT) as c_int);
        assert_eq!(f.offset, 4);
        assert_eq!(f.bytesleft, 7);
        assert_eq!(f.len, 3);
        // `#[repr(C)]` with naturally-aligned fields introduces no padding on the supported
        // 64-bit targets, so the total size is exactly the sum of the field sizes.
        assert_eq!(
            mem::size_of::<curl_ws_frame>(),
            2 * mem::size_of::<c_int>()
                + 2 * mem::size_of::<curl_off_t>()
                + mem::size_of::<size_t>()
        );
    }

    // --- Null-handle behavior ---------------------------------------------------------------

    #[test]
    fn recv_null_handle_clears_outparams_and_errors() {
        // Seed `meta` with a non-null sentinel to prove the call overwrites it with NULL.
        let sentinel = curl_ws_frame {
            age: 1,
            flags: 0,
            offset: 0,
            bytesleft: 0,
            len: 0,
        };
        let mut nread: size_t = 123;
        let mut meta: *const curl_ws_frame = &sentinel;
        // SAFETY: null handle with valid out-parameters — the documented NULL-handle path.
        let rc =
            unsafe { curl_ws_recv(ptr::null_mut(), ptr::null_mut(), 0, &mut nread, &mut meta) };
        assert_eq!(rc, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int);
        assert_eq!(nread, 0);
        assert!(meta.is_null());
    }

    #[test]
    fn recv_tolerates_null_outparams() {
        // curl dereferences the out-parameters unconditionally; our boundary must not. Passing
        // NULL for both must be handled without a NULL dereference.
        // SAFETY: null handle and null out-parameters — must be safe (no NULL deref).
        let rc = unsafe {
            curl_ws_recv(
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        assert_eq!(rc, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int);
    }

    #[test]
    fn send_null_handle_errors() {
        let mut sent: size_t = 9;
        // SAFETY: null handle with a valid `sent` out-parameter.
        let rc =
            unsafe { curl_ws_send(ptr::null_mut(), ptr::null(), 0, &mut sent, 0, CURLWS_TEXT) };
        assert_eq!(rc, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int);
    }

    #[test]
    fn send_tolerates_null_sent_on_null_handle() {
        // A NULL `sent` must be tolerated even on the bad-handle path (matches curl).
        // SAFETY: null handle and null `sent` — must be safe.
        let rc = unsafe {
            curl_ws_send(
                ptr::null_mut(),
                ptr::null(),
                0,
                ptr::null_mut(),
                0,
                CURLWS_PONG,
            )
        };
        assert_eq!(rc, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int);
    }

    #[test]
    fn start_frame_null_handle_errors() {
        // SAFETY: null handle.
        let rc = unsafe { curl_ws_start_frame(ptr::null_mut(), CURLWS_BINARY, 10) };
        assert_eq!(rc, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int);
    }

    #[test]
    fn meta_null_handle_is_null() {
        // SAFETY: null handle.
        let p = unsafe { curl_ws_meta(ptr::null_mut()) };
        assert!(p.is_null());
    }

    // --- Live-handle argument-validation parity (curl lib/ws.c) ------------------------------

    #[test]
    fn recv_without_connect_only_is_unsupported_protocol() {
        with_handle(
            |e| e.set.connect_only = false,
            |h| {
                let mut nread: size_t = 5;
                let mut meta: *const curl_ws_frame = ptr::null();
                // SAFETY: `h` is a live handle; out-parameters are valid.
                let rc = unsafe { curl_ws_recv(h, ptr::null_mut(), 0, &mut nread, &mut meta) };
                assert_eq!(rc, CURLcode::CURLE_UNSUPPORTED_PROTOCOL as c_int);
                assert_eq!(nread, 0);
                assert!(meta.is_null());
            },
        );
    }

    #[test]
    fn recv_with_connect_only_reports_connection_not_found() {
        with_handle(
            |e| e.set.connect_only = true,
            |h| {
                let mut nread: size_t = 5;
                let mut meta: *const curl_ws_frame = ptr::null();
                // SAFETY: live handle; valid out-parameters.
                let rc = unsafe { curl_ws_recv(h, ptr::null_mut(), 0, &mut nread, &mut meta) };
                assert_eq!(rc, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int);
            },
        );
    }

    #[test]
    fn recv_nonzero_buflen_null_buffer_is_bad_argument() {
        with_handle(
            |e| e.set.connect_only = true,
            |h| {
                let mut nread: size_t = 0;
                let mut meta: *const curl_ws_frame = ptr::null();
                // SAFETY: live handle; buflen != 0 with a NULL buffer is the invalid case tested.
                let rc = unsafe { curl_ws_recv(h, ptr::null_mut(), 8, &mut nread, &mut meta) };
                assert_eq!(rc, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int);
            },
        );
    }

    #[test]
    fn send_live_handle_no_connection_is_send_error() {
        with_handle(
            |e| e.set.connect_only = true,
            |h| {
                let payload = [1u8, 2, 3];
                let mut sent: size_t = 99;
                // SAFETY: live handle; `payload` is valid for `buflen` reads; `sent` valid.
                let rc = unsafe {
                    curl_ws_send(
                        h,
                        payload.as_ptr() as *const c_void,
                        payload.len(),
                        &mut sent,
                        0,
                        CURLWS_BINARY,
                    )
                };
                assert_eq!(rc, CURLcode::CURLE_SEND_ERROR as c_int);
                assert_eq!(sent, 0);
            },
        );
    }

    #[test]
    fn send_null_buffer_nonzero_len_is_bad_argument() {
        with_handle(
            |_e| {},
            |h| {
                let mut sent: size_t = 0;
                // SAFETY: live handle; NULL buffer with non-zero buflen is the invalid case.
                let rc = unsafe { curl_ws_send(h, ptr::null(), 4, &mut sent, 0, CURLWS_TEXT) };
                assert_eq!(rc, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT as c_int);
            },
        );
    }

    #[test]
    fn start_frame_raw_mode_is_failed_init() {
        with_handle(
            |e| e.set.ws_raw_mode = true,
            |h| {
                // SAFETY: live handle in raw mode.
                let rc = unsafe { curl_ws_start_frame(h, CURLWS_TEXT, 16) };
                assert_eq!(rc, CURLcode::CURLE_FAILED_INIT as c_int);
            },
        );
    }

    #[test]
    fn start_frame_non_raw_no_connection_is_send_error() {
        with_handle(
            |e| e.set.ws_raw_mode = false,
            |h| {
                // SAFETY: live handle, not raw mode, no connection.
                let rc = unsafe { curl_ws_start_frame(h, CURLWS_TEXT, 16) };
                assert_eq!(rc, CURLcode::CURLE_SEND_ERROR as c_int);
            },
        );
    }

    #[test]
    fn meta_live_handle_is_null_without_connection() {
        with_handle(
            |_e| {},
            |h| {
                // SAFETY: live handle; no callback context / connection → NULL.
                let p = unsafe { curl_ws_meta(h) };
                assert!(p.is_null());
            },
        );
    }
}
