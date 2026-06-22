//! The easy-handle engine — the Rust replacement for curl's `lib/easy.c`.
//!
//! This module is the heart of the libcurl handle ABI. The opaque C `CURL`
//! handle is backed by the [`Easy`] struct defined here; at the FFI boundary
//! (`curl-rs-ffi`) the struct is boxed and exposed as an opaque pointer via
//! `Box::into_raw`/`Box::from_raw`. **That raw-pointer dance happens only in the
//! FFI crate** — this module is entirely pointer-free and compiles under
//! `#![forbid(unsafe_code)]` (AAP §0.7.1 / §0.8.1).
//!
//! # What lives here
//!
//! [`Easy`] owns the full per-handle state, organized to mirror curl's
//! `struct Curl_easy` split between *configured options* and *runtime state*:
//!
//! * [`Easy::set`] — a [`UserDefined`] (curl's `set`): every option written by
//!   `curl_easy_setopt`. This is the single source of truth for the request
//!   configuration and is the only state carried over by
//!   [`duphandle`](Easy::duphandle).
//! * [`Easy::info`] — an [`Info`] (curl's `info`): the runtime/response data
//!   read back by `curl_easy_getinfo` (effective URL, response code, timings,
//!   sizes, …). Reset at the start of every [`perform`](Easy::perform).
//! * `state` — the minimal transfer-lifecycle flags (pause bits, whether a
//!   live connection is attached). Private; not part of the public surface.
//! * `response_headers` — the received-header store ([`HeaderCollector`]) used
//!   by the header API.
//!
//! All state uses idiomatic owned types (`String`, `Vec<u8>`, `Option<_>`,
//! `Arc<_>` for shared state) rather than raw pointers, so the handle is freed
//! deterministically by `Drop` when the box is dropped in the FFI layer — no
//! explicit `free()` and no `Drop` impl is required.
//!
//! # `getinfo` string-ownership invariant (AAP §0.7.4)
//!
//! C-visible strings returned by `curl_easy_getinfo` (for example
//! `CURLINFO_EFFECTIVE_URL`) must remain valid until the next call on the
//! handle or until cleanup. That invariant is satisfied structurally: every
//! such string is an owned `CString`/`String` held inside [`Easy::info`]. The
//! FFI shim hands out a borrowed `*const c_char` into that owned buffer; the
//! buffer is only replaced on the next `perform`/`getinfo` mutation or freed
//! when the handle is dropped. [`crate::getinfo::retrieve`] reads these owned
//! buffers and never allocates a fresh C string that the caller would have to
//! free.
//!
//! # Synchronous C ABI over an asynchronous core (AAP §0.4.4)
//!
//! [`perform`](Easy::perform) is `async`: it drives a transfer to completion on
//! the async core. The C contract (`curl_easy_perform`) is synchronous, so the
//! FFI crate bridges the two by calling `block_on` on a thread-local Tokio
//! runtime. The async machinery therefore stays entirely inside the safe core;
//! only synchronous, ABI-stable entry points are exposed to C.
//!
//! # Scope of `perform` at this layer
//!
//! The full byte-loop transfer driver (`transfer::run`/`drive_transfer`) is
//! owned by the connection/protocol layer and is wired in as those modules come
//! online. Within this module's dependency closure no scheme handler is
//! registered, so [`perform`](Easy::perform) performs the faithful preflight
//! that curl does before dispatch — it resolves and validates the request URL,
//! records the effective URL and scheme into [`Info`], and then reports
//! [`CurlError::UnsupportedProtocol`], exactly as curl's
//! `Curl_get_scheme_handler` returning `NULL` does. See [`perform`](Easy::perform)
//! for the precise contract and the seam where the protocol drive layers in.

#![forbid(unsafe_code)]

use std::ffi::CString;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::Once;

use crate::conn::Connection;
use crate::error::{CurlError, Result};
use crate::getinfo::{self, CurlInfo, Info, InfoValue};
use crate::headers::HeaderCollector;
use crate::options::CurlOption;
use crate::protocols::ws::{WsConnState, WsFrameMeta};
use crate::setopt::{self, CDataPtr, OptionValue, StrId, UserDefined};
use crate::transfer::{uc_to_curlcode, ReadCallback, WriteCallbacks};
use crate::url::{CurlUPart, CurlUrl, CURLU_GUESS_SCHEME};

// ===========================================================================
// ABI constants
//
// These mirror values from the curl public headers. They are duplicated here
// (rather than imported) because the canonical home for the FFI-facing integer
// constants is the `curl-rs-ffi` crate; the core only needs the handful that
// drive `Easy` behaviour (the SSL-backend ids reported by `global_sslset` and
// the pause bitmask interpreted by `pause`).
// ===========================================================================

/// `CURLSSLBACKEND_NONE` — no/unknown TLS backend (include/curl/curl.h).
pub const CURLSSLBACKEND_NONE: i32 = 0;

/// `CURLSSLBACKEND_RUSTLS` — the rustls backend id (include/curl/curl.h). This
/// is the single TLS backend the rewrite ships, so it is the only id for which
/// [`global_sslset`] reports success.
pub const CURLSSLBACKEND_RUSTLS: i32 = 14;

/// `CURLPAUSE_RECV` — pause the receiving side of a transfer
/// (include/curl/easy.h, bit `1 << 0`).
pub const CURLPAUSE_RECV: i32 = 1 << 0;

/// `CURLPAUSE_SEND` — pause the sending side of a transfer
/// (include/curl/easy.h, bit `1 << 2`).
pub const CURLPAUSE_SEND: i32 = 1 << 2;

/// `CURLPAUSE_ALL` — pause both directions (`CURLPAUSE_RECV | CURLPAUSE_SEND`).
pub const CURLPAUSE_ALL: i32 = CURLPAUSE_RECV | CURLPAUSE_SEND;

/// `CURLPAUSE_CONT` — resume both directions (clear all pause bits, value `0`).
pub const CURLPAUSE_CONT: i32 = 0;

/// Outcome of [`global_sslset`], mirroring curl's `CURLsslset` enum.
///
/// curl lets an application select the TLS backend once, before
/// `curl_global_init`, via `curl_global_sslset`. Because the rewrite ships a
/// single `rustls` backend, the only success path is selecting rustls (by id
/// [`CURLSSLBACKEND_RUSTLS`] or by the name `"rustls"`); any other backend is
/// reported as [`UnknownBackend`](SslSetResult::UnknownBackend), and a request
/// to change the backend after it has been locked in is reported as
/// [`TooLate`](SslSetResult::TooLate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum SslSetResult {
    /// `CURLSSLSET_OK` — the requested backend (rustls) was selected.
    Ok = 0,
    /// `CURLSSLSET_UNKNOWN_BACKEND` — the requested backend is not available.
    UnknownBackend = 1,
    /// `CURLSSLSET_TOO_LATE` — a different backend was already locked in (the
    /// library has been initialized or a backend was already selected).
    TooLate = 2,
    /// `CURLSSLSET_NO_BACKENDS` — the library was built with no TLS backend.
    /// Never returned by this build (rustls is always present); present only
    /// for ABI completeness.
    NoBackends = 3,
}

// ===========================================================================
// Process-global initialization state (curl's `lib/easy.c` `initialized`
// counter and the SSL/QUIC/… one-time setup).
//
// curl tracks global init with a plain `static unsigned int initialized` guarded
// by a mutex: `curl_global_init` does `if(initialized++) return CURLE_OK;` and
// `curl_global_cleanup` does `if(--initialized) return;`. We reproduce that
// reference-counted, idempotent behaviour with lock-free atomics, and install
// the process-wide rustls crypto provider exactly once via a `Once`.
// ===========================================================================

/// Reference count of outstanding `global_init` calls (curl's `initialized`).
/// Real one-time work runs on the `0 -> 1` transition; teardown on `1 -> 0`.
static GLOBAL_INIT_COUNT: AtomicUsize = AtomicUsize::new(0);

/// The `CURL_GLOBAL_*` flag bits supplied to the first [`global_init`] call.
/// Retained for introspection; subsequent init calls (curl semantics) keep the
/// first call's flags.
static GLOBAL_INIT_FLAGS: AtomicI64 = AtomicI64::new(0);

/// Guards the one-time installation of the rustls process-default crypto
/// provider so repeated [`global_init`] calls never re-attempt it.
static CRYPTO_PROVIDER_ONCE: Once = Once::new();

/// Install the process-wide rustls [`CryptoProvider`] exactly once.
///
/// The workspace links both `aws-lc-rs` (rustls' default) and `ring` (pulled in
/// transitively by `quinn`), so rustls cannot auto-select a provider and a
/// process-default **must** be installed explicitly before any TLS use. We pin
/// the same `aws-lc-rs` provider the TLS layer (`crate::tls`) installs, keeping
/// the choice consistent across the crate. `install_default` returns `Err` if a
/// provider is already installed (for example by the TLS layer initializing
/// first); that is the desired idempotent outcome, so the result is ignored.
///
/// [`CryptoProvider`]: rustls::crypto::CryptoProvider
fn install_default_crypto_provider() {
    CRYPTO_PROVIDER_ONCE.call_once(|| {
        // Safe API: returns Err(existing_provider) if one is already set, which
        // we intentionally discard — the post-condition ("a default provider is
        // installed") holds either way.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// `curl_global_init` — initialize the library's process-global state.
///
/// Idempotent and reference-counted, exactly like curl: the first call performs
/// the one-time setup (records the flags and installs the rustls crypto
/// provider); every subsequent call simply increments the counter and returns
/// `Ok(())`. Each successful `global_init` must be balanced by a
/// [`global_cleanup`]. `flags` carries the `CURL_GLOBAL_*` bitmask; all bits are
/// accepted (the rustls-based core has no per-flag subsystems to toggle), and
/// the first call's value is retained.
///
/// Returns `Ok(())` always: the only one-time work that can "fail" is the crypto
/// provider install, whose failure means a provider is already present — a
/// success for our purposes.
pub fn global_init(flags: i64) -> Result<()> {
    let prev = GLOBAL_INIT_COUNT.fetch_add(1, Ordering::SeqCst);
    if prev == 0 {
        // First initialization (the `0 -> 1` transition): do the one-time work.
        GLOBAL_INIT_FLAGS.store(flags, Ordering::SeqCst);
        install_default_crypto_provider();
    }
    Ok(())
}

/// `curl_global_cleanup` — release the library's process-global state.
///
/// Reference-counted mirror of [`global_init`]: each call decrements the init
/// counter and only the final call (the `1 -> 0` transition) tears down. Extra
/// cleanups beyond the matching inits are ignored rather than underflowing the
/// counter (curl would corrupt its counter; we stay memory-safe). The rustls
/// crypto provider is process-global and intentionally **not** uninstalled —
/// there is no safe way to revoke it and a later re-init reuses it.
pub fn global_cleanup() {
    // CAS loop: decrement only while the counter is positive, so concurrent or
    // unbalanced cleanups can never wrap below zero.
    let mut cur = GLOBAL_INIT_COUNT.load(Ordering::SeqCst);
    loop {
        if cur == 0 {
            return; // nothing to clean up
        }
        match GLOBAL_INIT_COUNT.compare_exchange_weak(
            cur,
            cur - 1,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => {
                if cur - 1 == 0 {
                    // Final cleanup: reset the recorded flags. (The crypto
                    // provider remains installed for the process lifetime.)
                    GLOBAL_INIT_FLAGS.store(0, Ordering::SeqCst);
                }
                return;
            }
            Err(actual) => cur = actual,
        }
    }
}

/// `curl_global_sslset` — select the TLS backend (report the single rustls one).
///
/// This build ships exactly one TLS backend (`rustls`) and is **not** a
/// multi-SSL build, so the semantics reduce to curl's single-backend path in
/// `Curl_init_sslset_nolock` (lib/vtls/vtls.c): selecting the available backend
/// returns [`SslSetResult::Ok`] and requesting any other backend returns
/// [`SslSetResult::UnknownBackend`]. `TOO_LATE` is a multi-SSL-only outcome and
/// `NO_BACKENDS` a no-SSL-only outcome; neither can occur here, so this function
/// is a pure, stateless mapping (callable before or after [`global_init`]).
///
/// A backend matches when `id` equals [`CURLSSLBACKEND_RUSTLS`] or `name`
/// case-insensitively equals `"rustls"` (curl matches by id or name, the latter
/// via the case-insensitive `curl_strequal`). The FFI shim fills the caller's
/// `avail` out-parameter with the one-entry backend list separately.
#[must_use]
pub fn global_sslset(id: i32, name: Option<&str>) -> SslSetResult {
    let matches_rustls =
        id == CURLSSLBACKEND_RUSTLS || name.is_some_and(|n| n.eq_ignore_ascii_case("rustls"));
    if matches_rustls {
        SslSetResult::Ok
    } else {
        SslSetResult::UnknownBackend
    }
}

// ===========================================================================
// The easy handle
// ===========================================================================

/// Minimal transfer-lifecycle state held alongside the configured options and
/// the response info.
///
/// curl keeps a large `struct SingleRequest` / `struct UrlState` of transient
/// per-transfer flags; at this layer the engine only needs the handful that the
/// public easy API inspects directly — the pause bits read/written by
/// [`Easy::pause`] and whether a live connection is attached (which gates
/// `pause`/`recv`/`send`). The remaining transient state is owned by the
/// connection/transfer layer and threaded in as those modules come online.
#[derive(Debug, Default)]
struct EasyState {
    /// Receiving side paused (curl's `KEEP_RECV_PAUSE`); set via [`CURLPAUSE_RECV`].
    recv_paused: bool,
    /// Sending side paused (curl's `KEEP_SEND_PAUSE`); set via [`CURLPAUSE_SEND`].
    send_paused: bool,
    /// Whether a live connection is attached to the handle (curl's
    /// `data->conn != NULL`). Gates `pause`/`recv`/`send`, which are only valid
    /// once a connection exists. The connection layer sets this on
    /// attach/detach.
    has_connection: bool,
}

/// The easy handle — the Rust backing of the opaque C `CURL` pointer.
///
/// See the [module documentation](self) for the full design. In short: [`set`]
/// holds the configured options, [`info`] holds the runtime/response data (and
/// owns the C-visible result strings), and the private `state`/`response_headers`
/// hold the transient transfer state and received headers.
///
/// The struct is freed deterministically by `Drop` (no explicit `Drop` impl is
/// needed — every field owns its storage), which is what reclaims the handle
/// when `curl_easy_cleanup` drops the box in the FFI layer.
///
/// [`set`]: Easy::set
/// [`info`]: Easy::info
pub struct Easy {
    /// Configured options (curl's `data->set`): everything written by
    /// `curl_easy_setopt`. The sole state deep-copied by
    /// [`duphandle`](Easy::duphandle).
    pub set: UserDefined,
    /// Runtime/response info (curl's `data->info`): read back by
    /// `curl_easy_getinfo`. Owns the C-visible result strings (effective URL,
    /// scheme, content-type, …). Reset at the start of each
    /// [`perform`](Easy::perform).
    pub info: Info,
    /// Transient transfer-lifecycle flags (pause bits, connection-attached).
    state: EasyState,
    /// Received-header store backing the header API (curl's
    /// `data->state.httphdrs`).
    response_headers: HeaderCollector,
    /// The connection retained by a `CURLOPT_CONNECT_ONLY` transfer (curl's
    /// `data->conn` surviving past `perform` for the app's own I/O). `None`
    /// until a CONNECT_ONLY [`perform`](Easy::perform) succeeds; populated by
    /// [`attach_ws_connection`](Easy::attach_ws_connection) so the subsequent
    /// `curl_ws_*` (and raw `curl_easy_recv`/`send`) calls have a live socket to
    /// drive. It is held alongside [`ws_state`](Self::ws_state) rather than
    /// inside the connection's `proto_state` so the framing engine and the
    /// connection can be borrowed disjointly.
    ///
    /// The connection is wrapped in a [`std::sync::Mutex`] purely to keep `Easy`
    /// `Sync`: a bare [`Connection`] is `Send` but not `Sync` (its
    /// `dyn ConnectionFilter` chain is `Send`-only), and the protocol futures
    /// hold `&Easy` across `Send` await points, which requires `Easy: Sync`.
    /// `Mutex<Connection>` restores `Sync` (a `Mutex<T>` is `Sync` whenever
    /// `T: Send`). The handle is never shared across threads concurrently (the
    /// libcurl threading contract), so the mutex is only ever reached via
    /// [`Mutex::get_mut`] on `&mut self` — no lock is taken and no guard is held
    /// across `.await`.
    connect_only_conn: Option<std::sync::Mutex<Connection>>,
    /// The RFC 6455 framing engine for a retained `ws`/`wss` CONNECT_ONLY
    /// connection (curl's per-connection `websocket` state, `CURL_META_PROTO_WS_CONN`).
    /// `Some` only while a WebSocket CONNECT_ONLY connection is attached; this is
    /// the "active WebSocket context" that gates `curl_ws_meta` (a NULL result
    /// outside it — QA F5-MINOR-2) and backs `curl_ws_send`/`curl_ws_recv`.
    ws_state: Option<WsConnState>,
    /// The per-handle cookie jar (curl's `data->cookies`), lazily created by the
    /// transfer engine when the cookie engine is active and no shared jar is
    /// attached via `CURLOPT_SHARE`. Held on the handle so in-memory cookies
    /// captured on one transfer carry to the next transfer on the same handle
    /// (e.g. multiple URLs in one invocation), matching curl. When a cookie
    /// share is attached the engine uses that shared jar instead and this stays
    /// `None`. Reset to `None` by [`duphandle`](Easy::duphandle) (a duplicated
    /// handle starts with an empty jar, like curl's empty caches).
    #[cfg(feature = "cookies")]
    cookie_jar: Option<std::sync::Arc<std::sync::Mutex<crate::cookie::CookieJar>>>,
    /// The per-handle HSTS store (curl's `data->hsts`), lazily created by the
    /// transfer engine when the HSTS engine is active and no shared store is
    /// attached via `CURLOPT_SHARE`. Held on the handle so an `http→https`
    /// upgrade learned on one transfer carries to the next transfer on the same
    /// handle, matching curl. When an HSTS share is attached the engine uses
    /// that shared store instead and this stays `None`. Reset to `None` by
    /// [`duphandle`](Easy::duphandle).
    #[cfg(feature = "hsts")]
    hsts_store: Option<std::sync::Arc<std::sync::Mutex<crate::hsts::HstsStore>>>,
    /// The most recent failure diagnostic latched by the engine (curl's
    /// `data->state.errorbuf` / `CURLOPT_ERRORBUFFER` value), as a Rust-native
    /// string the safe core can write directly. The C `CURLOPT_ERRORBUFFER`
    /// pointer cannot be populated from the `#![forbid(unsafe_code)]` core (the
    /// documented foundation limitation), but a front-end that drives the
    /// library through this Rust API (the `curl-rs` CLI) reads the message back
    /// via [`last_error`](Self::last_error) for the `curl: (N) <msg>` line and
    /// `%{errormsg}`. Reset at the start of each [`perform`](Easy::perform),
    /// mirroring curl clearing the error buffer per transfer. Only specific
    /// `failf` sites whose exact text differs from the static code description
    /// populate this today (e.g. the decompression-bomb diagnostic).
    last_error: Option<String>,
}

// `Easy` is `Debug` (formerly derived) but the retained-connection fields hold
// heavy, non-`Debug` engine types (`Connection`, `WsConnState`); render those
// compactly as presence flags so the handle stays printable without forcing a
// noisy `Debug` onto the connection/framing internals.
impl core::fmt::Debug for Easy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Easy")
            .field("set", &self.set)
            .field("info", &self.info)
            .field("state", &self.state)
            .field("response_headers", &self.response_headers)
            .field("connect_only_conn", &self.connect_only_conn.is_some())
            .field("ws_state", &self.ws_state.is_some())
            .finish()
    }
}

impl Easy {
    /// `curl_easy_init` — allocate and initialize a fresh easy handle.
    ///
    /// All options start at curl's documented defaults (via
    /// [`UserDefined::default`], which encodes e.g. `maxredirs = 30`, the
    /// default read-buffer size, ALPN enabled, TCP no-delay on, FTP EPSV on, …),
    /// and the runtime info/state start empty. The FFI layer boxes the returned
    /// value and hands the caller the resulting opaque `CURL*`.
    #[must_use]
    pub fn new() -> Self {
        Easy {
            set: UserDefined::new(),
            info: Info::new(),
            state: EasyState::default(),
            response_headers: HeaderCollector::new(),
            connect_only_conn: None,
            ws_state: None,
            #[cfg(feature = "cookies")]
            cookie_jar: None,
            #[cfg(feature = "hsts")]
            hsts_store: None,
            last_error: None,
        }
    }

    /// The most recent engine failure diagnostic, if one was latched during the
    /// last [`perform`](Easy::perform) (curl's `CURLOPT_ERRORBUFFER` value). See
    /// [`last_error`](Self::last_error) field docs for the foundation-limitation
    /// rationale. Returns `None` when no specific message was recorded, so the
    /// caller falls back to [`crate::error::CurlError::description`].
    #[must_use]
    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    /// Latch an engine failure diagnostic (the safe-core analogue of curl's
    /// `Curl_failf` writing `CURLOPT_ERRORBUFFER`). Called by the protocol
    /// drivers for the few `failf` messages whose exact text differs from the
    /// static `CURLcode` description and must reach the `curl: (N) <msg>` line.
    pub fn set_last_error(&mut self, msg: impl Into<String>) {
        self.last_error = Some(msg.into());
    }

    /// Clear the latched failure diagnostic (curl resets the error buffer at the
    /// start of each transfer). Invoked by [`pre_perform`](Self::pre_perform).
    pub fn clear_last_error(&mut self) {
        self.last_error = None;
    }
}

impl Default for Easy {
    /// Equivalent to [`Easy::new`].
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Option / info delegation and small accessors
// ---------------------------------------------------------------------------

impl Easy {
    /// `curl_easy_setopt` (typed) — apply a single option to this handle.
    ///
    /// Delegates to [`crate::setopt::apply`], which performs curl's full
    /// per-option validation and stores the value into [`Easy::set`]. The
    /// variadic C `curl_easy_setopt` shim in the FFI crate reads its single
    /// trailing argument, builds the typed [`OptionValue`] for the option's type
    /// group, and calls this method.
    ///
    /// # Errors
    ///
    /// Returns whatever [`crate::setopt::apply`] returns — typically
    /// [`CurlError::UnknownOption`](crate::error::CurlError) for an unrecognized
    /// option or [`CurlError::BadFunctionArgument`] for an out-of-range or
    /// wrong-typed value.
    pub fn setopt(&mut self, opt: CurlOption, val: OptionValue) -> Result<()> {
        setopt::apply(&mut self.set, opt, val)
    }

    /// `curl_easy_getinfo` (typed) — read one piece of runtime info.
    ///
    /// Delegates to [`crate::getinfo::retrieve`], returning an [`InfoValue`] that
    /// borrows from this handle's owned [`Info`] store, so any string result
    /// stays valid until the next mutating call or cleanup (the ownership
    /// invariant documented on the [module](self)). The variadic C
    /// `curl_easy_getinfo` shim writes the borrowed value through the caller's
    /// out-pointer.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::BadFunctionArgument`] for an unknown selector, per
    /// [`crate::getinfo::retrieve`].
    pub fn getinfo(&self, info: CurlInfo) -> Result<InfoValue<'_>> {
        getinfo::retrieve(&self.info, info)
    }

    /// The currently configured request URL (`CURLOPT_URL`), if any.
    ///
    /// This is the *configured* URL; the post-transfer *effective* URL (after any
    /// redirects) is reported via `getinfo(CURLINFO_EFFECTIVE_URL)`.
    #[must_use]
    pub fn url(&self) -> Option<&str> {
        self.set.str(StrId::SetUrl)
    }

    /// Shared, immutable access to the received-header store.
    #[must_use]
    pub fn headers(&self) -> &HeaderCollector {
        &self.response_headers
    }

    /// Mutable access to the received-header store (used by the transfer engine
    /// to record incoming response headers).
    pub fn headers_mut(&mut self) -> &mut HeaderCollector {
        &mut self.response_headers
    }

    /// Attach a pre-serialized `multipart/form-data` request body and its
    /// `Content-Type` (the `CURLOPT_MIMEPOST` effect, by value).
    ///
    /// This is the safe-core counterpart to `CURLOPT_MIMEPOST`: where the C ABI
    /// stores an opaque `curl_mime *` that the `#![forbid(unsafe_code)]` core
    /// cannot dereference, the caller (the CLI's `-F` handler, or the FFI shim)
    /// serializes the MIME tree via [`Mime::to_bytes`](crate::mime::Mime::to_bytes)
    /// and hands the engine the finished body plus its boundary-bearing
    /// `Content-Type`. The request method is switched to the MIME-post family and
    /// `no_body` is cleared, exactly as `CURLOPT_MIMEPOST` does, so the transfer
    /// engine frames and streams the body (`build_request_body` returns it and the
    /// HTTP/1 builder emits the `Content-Type` header unless the application set
    /// its own).
    pub fn set_mime_body(&mut self, body: Vec<u8>, content_type: String) {
        self.set.mime_body = Some(body);
        self.set.mime_content_type = Some(content_type);
        self.set.method = crate::setopt::HttpReq::PostMime;
        self.set.opt_no_body = false;
    }

    /// The `Content-Type` programmed alongside a multipart body by
    /// [`set_mime_body`](Easy::set_mime_body) — e.g.
    /// `multipart/form-data; boundary=…` for a `-F`/`CURLOPT_MIMEPOST` request,
    /// or `None` when no multipart body is configured. Read-only introspection
    /// used by the request builder (and exposed for the CLI/FFI seams).
    #[must_use]
    pub fn mime_content_type(&self) -> Option<&str> {
        self.set.mime_content_type.as_deref()
    }

    /// Whether either transfer direction is currently paused.
    ///
    /// Reflects the pause bits set by [`pause`](Easy::pause)
    /// (`CURLPAUSE_RECV` / `CURLPAUSE_SEND`).
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.state.recv_paused || self.state.send_paused
    }
}

// ---------------------------------------------------------------------------
// Reset and duplication
// ---------------------------------------------------------------------------

impl Easy {
    /// `curl_easy_reset` — restore all options to their defaults.
    ///
    /// Re-initializes the configured options ([`Easy::set`]) to curl's defaults
    /// and clears the runtime info, received headers, and pause state, while
    /// **preserving the attached share handle and any live connection**. This
    /// mirrors curl's `curl_easy_reset`, which `memset`s `data->set` and re-runs
    /// `Curl_init_userdefined` but deliberately leaves `data->share` and the
    /// connection cache intact.
    pub fn reset(&mut self) {
        // Preserve the share handle across the option reset: in curl `data->share`
        // is stored separately from `data->set` and survives a reset. Move it out,
        // rebuild the defaults, then restore it.
        let saved_share = self.set.share.take();
        self.set = UserDefined::new();
        self.set.share = saved_share;

        // Reset runtime/response info and received headers.
        self.info = Info::new();
        self.response_headers = HeaderCollector::new();

        // Clear the transient transfer flags (the pause bits are wiped with the
        // request state) but keep `has_connection`: curl preserves the connection
        // cache across a reset, so a connect-only handle keeps its connection.
        let had_connection = self.state.has_connection;
        self.state = EasyState {
            recv_paused: false,
            send_paused: false,
            has_connection: had_connection,
        };
    }

    /// `curl_easy_duphandle` — clone a handle's *configuration* into a new handle.
    ///
    /// Deep-copies the configured options ([`Easy::set`]) and starts the clone
    /// with fresh runtime info, empty received headers, cleared transient state,
    /// and **no** attached share or connection — matching curl's
    /// `curl_easy_duphandle`, whose `dupset` copies only `UserDefined`
    /// (deep-copying every owned string/blob) and whose result has its own empty
    /// caches and runtime state. The share handle is *not* inherited
    /// (`data->share` is separate from `data->set` in curl).
    #[must_use]
    pub fn duphandle(&self) -> Easy {
        Easy {
            set: Self::dup_userdefined(&self.set),
            info: Info::new(),
            state: EasyState::default(),
            response_headers: HeaderCollector::new(),
            // A duplicated handle inherits no live connection (curl's
            // `curl_easy_duphandle` starts with empty caches and no `data->conn`).
            connect_only_conn: None,
            ws_state: None,
            // A duplicated handle starts with an empty per-handle cookie jar
            // (curl's `curl_easy_duphandle` starts with empty caches); a shared
            // jar, if any, is carried by the duplicated `CURLOPT_SHARE`.
            #[cfg(feature = "cookies")]
            cookie_jar: None,
            // A duplicated handle starts with an empty per-handle HSTS store
            // (curl's `curl_easy_duphandle` starts with empty caches); a shared
            // store, if any, is carried by the duplicated `CURLOPT_SHARE`.
            #[cfg(feature = "hsts")]
            hsts_store: None,
            // A duplicated handle carries no latched failure diagnostic.
            last_error: None,
        }
    }

    /// Resolve the HSTS store to use for this transfer (curl's `data->hsts`).
    ///
    /// When a `CURLOPT_SHARE` carrying `CURL_LOCK_DATA_HSTS` is attached, curl
    /// points `data->hsts` at the share's store so every easy handle using the
    /// share reads and writes the same HSTS policies; this returns that shared
    /// store. Otherwise it returns a per-handle store, created on first use and
    /// retained on the handle so an upgrade learned on one transfer persists to
    /// the next on the same handle. The returned `Arc` is a cheap clone of the
    /// store handle, not a copy of the entries.
    #[cfg(feature = "hsts")]
    pub(crate) fn hsts_store_handle(
        &mut self,
    ) -> std::sync::Arc<std::sync::Mutex<crate::hsts::HstsStore>> {
        if let Some(shared) = self.set.share.as_ref().and_then(crate::share::Share::hsts) {
            return shared;
        }
        self.hsts_store
            .get_or_insert_with(|| {
                std::sync::Arc::new(std::sync::Mutex::new(crate::hsts::HstsStore::new()))
            })
            .clone()
    }

    /// Resolve the cookie jar to use for this transfer (curl's `data->cookies`).
    ///
    /// When a `CURLOPT_SHARE` carrying `CURL_LOCK_DATA_COOKIE` is attached, curl
    /// points `data->cookies` at the share's jar so every easy handle using the
    /// share reads and writes the same cookies; this returns that shared jar.
    /// Otherwise it returns a per-handle jar, created on first use and retained
    /// on the handle so cookies captured on one transfer persist to the next on
    /// the same handle (e.g. multiple URLs in one CLI invocation). The returned
    /// `Arc` is a cheap clone of the jar handle, not a copy of the cookies.
    #[cfg(feature = "cookies")]
    pub(crate) fn cookie_jar_handle(
        &mut self,
    ) -> std::sync::Arc<std::sync::Mutex<crate::cookie::CookieJar>> {
        if let Some(shared) = self.set.share.as_ref().and_then(crate::share::Share::cookies) {
            return shared;
        }
        self.cookie_jar
            .get_or_insert_with(|| {
                std::sync::Arc::new(std::sync::Mutex::new(crate::cookie::CookieJar::new()))
            })
            .clone()
    }

    /// Deep-copy a [`UserDefined`] for [`duphandle`](Easy::duphandle).
    ///
    /// curl's `dupset` (lib/easy.c) copies `src->set` wholesale and then (a)
    /// clears the duplicated MIME pointer — the MIME tree is deep-copied
    /// separately by the FFI/MIME layer and is never aliased — and (b)
    /// deep-copies every owned string and blob (including the `COPYPOSTFIELDS`
    /// buffer). We reproduce that field-by-field, since `UserDefined` deliberately
    /// does not derive `Clone` (its own docs note that duplication is this
    /// bespoke deep copy):
    ///
    /// * `Copy` scalars (pointers-as-addresses, integers, bools, enum tags) are
    ///   bit-copied.
    /// * Owned containers (`String`/`Vec`/`Option<…>`, the TLS configs, the
    ///   priority list, the parsed-URL handle, …) are `.clone()`d (a true deep
    ///   copy).
    /// * The opaque MIME handle (`mimepost`) is reset to [`CDataPtr::NULL`],
    ///   mirroring curl's `dst->set.mimepostp = NULL`.
    /// * The `share` handle is dropped (`None`): dup does not inherit it.
    fn dup_userdefined(src: &UserDefined) -> UserDefined {
        UserDefined {
            out: src.out,
            in_set: src.in_set,
            writeheader: src.writeheader,
            err: src.err,
            debugdata: src.debugdata,
            progress_client: src.progress_client,
            seek_client: src.seek_client,
            ioctl_client: src.ioctl_client,
            sockopt_client: src.sockopt_client,
            opensocket_client: src.opensocket_client,
            closesocket_client: src.closesocket_client,
            prereq_userp: src.prereq_userp,
            resolver_start_client: src.resolver_start_client,
            interleave_client: src.interleave_client,
            wildcardptr: src.wildcardptr,
            fnmatch_data: src.fnmatch_data,
            ssh_keyfunc_userp: src.ssh_keyfunc_userp,
            ssh_hostkeyfunc_userp: src.ssh_hostkeyfunc_userp,
            hsts_read_userp: src.hsts_read_userp,
            hsts_write_userp: src.hsts_write_userp,
            trailer_data: src.trailer_data,
            private_data: src.private_data,
            errorbuffer: src.errorbuffer,
            postfields: src.postfields,
            httppost: src.httppost,
            fwrite_func: src.fwrite_func,
            fread_func_set: src.fread_func_set,
            fwrite_header: src.fwrite_header,
            fwrite_rtp: src.fwrite_rtp,
            fprogress: src.fprogress,
            fxferinfo: src.fxferinfo,
            fdebug: src.fdebug,
            ioctl_func: src.ioctl_func,
            seek_func: src.seek_func,
            fsockopt: src.fsockopt,
            fopensocket: src.fopensocket,
            fclosesocket: src.fclosesocket,
            fprereq: src.fprereq,
            resolver_start: src.resolver_start,
            ssh_keyfunc: src.ssh_keyfunc,
            ssh_hostkeyfunc: src.ssh_hostkeyfunc,
            chunk_bgn: src.chunk_bgn,
            chunk_end: src.chunk_end,
            fnmatch: src.fnmatch,
            trailer_callback: src.trailer_callback,
            hsts_read: src.hsts_read,
            hsts_write: src.hsts_write,
            httpauth: src.httpauth,
            proxyauth: src.proxyauth,
            httpauth_iestyle: src.httpauth_iestyle,
            proxyauth_iestyle: src.proxyauth_iestyle,
            socks5auth: src.socks5auth,
            postfieldsize: src.postfieldsize,
            filesize: src.filesize,
            low_speed_limit: src.low_speed_limit,
            max_send_speed: src.max_send_speed,
            max_recv_speed: src.max_recv_speed,
            set_resume_from: src.set_resume_from,
            max_filesize: src.max_filesize,
            timeout: src.timeout,
            connecttimeout: src.connecttimeout,
            happy_eyeballs_timeout: src.happy_eyeballs_timeout,
            server_response_timeout: src.server_response_timeout,
            accepttimeout: src.accepttimeout,
            dns_cache_timeout_ms: src.dns_cache_timeout_ms,
            upkeep_interval_ms: src.upkeep_interval_ms,
            conn_max_idle_ms: src.conn_max_idle_ms,
            conn_max_age_ms: src.conn_max_age_ms,
            timevalue: src.timevalue,
            headers: src.headers.clone(),
            proxyheaders: src.proxyheaders.clone(),
            telnet_options: src.telnet_options.clone(),
            resolve: src.resolve.clone(),
            connect_to: src.connect_to.clone(),
            http200aliases: src.http200aliases.clone(),
            quote: src.quote.clone(),
            postquote: src.postquote.clone(),
            prequote: src.prequote.clone(),
            mail_rcpt: src.mail_rcpt.clone(),
            strings: src.strings.clone(),
            blobs: src.blobs.clone(),
            copypostfields: src.copypostfields.clone(),
            cookiefiles: src.cookiefiles.clone(),
            cookie_commands: src.cookie_commands.clone(),
            hstsfiles: src.hstsfiles.clone(),
            uh: src.uh.clone(),
            // Duplicate the raw `CURLOPT_CURLU` pointer verbatim, matching curl's
            // `curl_easy_duphandle` which copies `set.uh` (the stored pointer).
            // The dup'd handle re-resolves it into `uh` at its own perform time.
            uh_ptr: src.uh_ptr,
            ssl: src.ssl.clone(),
            proxy_ssl: src.proxy_ssl.clone(),
            general_ssl: src.general_ssl.clone(),
            priority: src.priority.clone(),
            buffer_size: src.buffer_size,
            upload_buffer_size: src.upload_buffer_size,
            ssh_auth_types: src.ssh_auth_types,
            new_directory_perms: src.new_directory_perms,
            new_file_perms: src.new_file_perms,
            scope_id: src.scope_id,
            allowed_protocols: src.allowed_protocols,
            redir_protocols: src.redir_protocols,
            maxconnects: src.maxconnects,
            rtsp_next_client_cseq: src.rtsp_next_client_cseq,
            rtsp_next_server_cseq: src.rtsp_next_server_cseq,
            tcp_keepidle: src.tcp_keepidle,
            tcp_keepintvl: src.tcp_keepintvl,
            tcp_keepcnt: src.tcp_keepcnt,
            proxyport: src.proxyport,
            use_port: src.use_port,
            localport: src.localport,
            localportrange: src.localportrange,
            expect_100_timeout: src.expect_100_timeout,
            low_speed_time: src.low_speed_time,
            tftp_blksize: src.tftp_blksize,
            proxytype: src.proxytype,
            ftp_filemethod: src.ftp_filemethod,
            ftpsslauth: src.ftpsslauth,
            ftp_ccc: src.ftp_ccc,
            use_netrc: src.use_netrc,
            ftp_create_missing_dirs: src.ftp_create_missing_dirs,
            use_ssl: src.use_ssl,
            timecondition: src.timecondition,
            method: src.method,
            httpwant: src.httpwant,
            ipver: src.ipver,
            upload_flags: src.upload_flags,
            gssapi_delegation: src.gssapi_delegation,
            http_follow_mode: src.http_follow_mode,
            rtspreq: src.rtspreq,
            maxredirs: src.maxredirs,
            connect_only: src.connect_only,
            connect_only_ws: src.connect_only_ws,
            mail_rcpt_allowfails: src.mail_rcpt_allowfails,
            mime_formescape: src.mime_formescape,
            is_fread_set: src.is_fread_set,
            tftp_no_options: src.tftp_no_options,
            sep_headers: src.sep_headers,
            cookiesession: src.cookiesession,
            crlf: src.crlf,
            ssh_compression: src.ssh_compression,
            quick_exit: src.quick_exit,
            get_filetime: src.get_filetime,
            tunnel_thru_httpproxy: src.tunnel_thru_httpproxy,
            prefer_ascii: src.prefer_ascii,
            remote_append: src.remote_append,
            list_only: src.list_only,
            ftp_use_port: src.ftp_use_port,
            ftp_use_epsv: src.ftp_use_epsv,
            ftp_use_eprt: src.ftp_use_eprt,
            ftp_use_pret: src.ftp_use_pret,
            ftp_skip_ip: src.ftp_skip_ip,
            wildcard_enabled: src.wildcard_enabled,
            http_fail_on_error: src.http_fail_on_error,
            http_keep_sending_on_error: src.http_keep_sending_on_error,
            http_transfer_encoding: src.http_transfer_encoding,
            allow_auth_to_other_hosts: src.allow_auth_to_other_hosts,
            include_header: src.include_header,
            http_auto_referer: src.http_auto_referer,
            opt_no_body: src.opt_no_body,
            verbose: src.verbose,
            noprogress: src.noprogress,
            reuse_forbid: src.reuse_forbid,
            reuse_fresh: src.reuse_fresh,
            no_signal: src.no_signal,
            tcp_nodelay: src.tcp_nodelay,
            ignorecl: src.ignorecl,
            http_te_skip: src.http_te_skip,
            http_ce_skip: src.http_ce_skip,
            proxy_transfer_mode: src.proxy_transfer_mode,
            socks5_gssapi_nec: src.socks5_gssapi_nec,
            sasl_ir: src.sasl_ir,
            tcp_keepalive: src.tcp_keepalive,
            tcp_fastopen: src.tcp_fastopen,
            ssl_enable_alpn: src.ssl_enable_alpn,
            path_as_is: src.path_as_is,
            pipewait: src.pipewait,
            suppress_connect_headers: src.suppress_connect_headers,
            dns_shuffle_addresses: src.dns_shuffle_addresses,
            haproxyprotocol: src.haproxyprotocol,
            abstract_unix_socket: src.abstract_unix_socket,
            disallow_username_in_url: src.disallow_username_in_url,
            doh: src.doh,
            doh_verifypeer: src.doh_verifypeer,
            doh_verifyhost: src.doh_verifyhost,
            doh_verifystatus: src.doh_verifystatus,
            http09_allowed: src.http09_allowed,
            ws_raw_mode: src.ws_raw_mode,
            ws_no_auto_pong: src.ws_no_auto_pong,
            post301: src.post301,
            post302: src.post302,
            post303: src.post303,
            cookie_engine: src.cookie_engine,
            hsts_enable: src.hsts_enable,
            altsvc_ctrl: src.altsvc_ctrl,

            // The MIME tree is deep-copied by the FFI/MIME layer; the core never
            // aliases the opaque handle (curl's `dupset` sets `mimepostp = NULL`).
            // The derived serialized body is likewise not inherited — the dup
            // must re-attach its own MIME post, consistent with the NULL reset.
            mimepost: CDataPtr::NULL,
            mime_body: None,
            mime_content_type: None,
            // dup does not inherit the share handle (curl keeps `data->share`
            // separate from `data->set`, so the clone starts share-less).
            share: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Transfer
// ---------------------------------------------------------------------------

impl Easy {
    /// Preflight a transfer: reset per-transfer info, then resolve and validate
    /// the request URL, recording the effective URL and scheme into [`Info`].
    ///
    /// This mirrors the work curl does in `Curl_connect` / `create_conn` before
    /// it looks up the protocol handler: it requires a URL (`CURLOPT_URL`, or a
    /// pre-parsed `CURLOPT_CURLU` handle), parses it (guessing the scheme as curl
    /// does for schemeless inputs), and stores the normalized effective URL and
    /// the upper-cased scheme so `getinfo(CURLINFO_EFFECTIVE_URL)` and
    /// `getinfo(CURLINFO_SCHEME)` are populated even when the transfer itself
    /// cannot yet proceed.
    ///
    /// # Errors
    ///
    /// * [`CurlError::UrlMalformat`] if no URL is configured, or the URL (or its
    ///   normalized form) is not valid — including an interior NUL, which cannot
    ///   be represented as a C string.
    /// * Any URL-parse error mapped through [`crate::transfer::uc_to_curlcode`]
    ///   to the matching `CURLcode`.
    fn pre_perform(&mut self) -> Result<()> {
        // Each perform is a fresh transfer: reset the runtime/response info so
        // stale values from a previous transfer never leak (curl re-inits
        // `data->info` at transfer start).
        self.info = Info::new();

        // Clear any failure diagnostic latched by a prior transfer on this
        // handle (curl clears `CURLOPT_ERRORBUFFER` at transfer start).
        self.last_error = None;

        // Resolve the URL handle: prefer an explicitly-set `CURLOPT_CURLU`
        // (`set.uh`); otherwise parse the `CURLOPT_URL` string. With neither
        // there is nothing to transfer.
        let url = if let Some(uh) = self.set.uh.as_ref() {
            uh.clone()
        } else if let Some(url_str) = self.set.str(StrId::SetUrl) {
            let mut u = CurlUrl::new();
            // curl guesses the scheme for schemeless inputs (e.g. "example.com"
            // -> "http"); `CURLU_GUESS_SCHEME` reproduces that.
            u.set(CurlUPart::Url, Some(url_str), CURLU_GUESS_SCHEME)
                .map_err(uc_to_curlcode)?;
            u
        } else {
            return Err(CurlError::UrlMalformat);
        };

        // Record the normalized effective URL (curl's `CURLINFO_EFFECTIVE_URL`).
        let effective = url.get(CurlUPart::Url, 0).map_err(uc_to_curlcode)?;
        self.info.effective_url =
            Some(CString::new(effective).map_err(|_| CurlError::UrlMalformat)?);

        // Record the scheme, upper-cased to match curl's `CURLINFO_SCHEME` (the
        // URL API stores schemes lower-cased; curl reports them upper-cased).
        let scheme = url.get(CurlUPart::Scheme, 0).map_err(uc_to_curlcode)?;
        self.info.scheme =
            Some(CString::new(scheme.to_ascii_uppercase()).map_err(|_| CurlError::UrlMalformat)?);

        Ok(())
    }

    /// `curl_easy_perform` — drive a single transfer to completion.
    ///
    /// This is `async`: the FFI crate bridges it to the synchronous C contract by
    /// `block_on`-ing a thread-local Tokio runtime (AAP §0.4.4). curl implements
    /// `curl_easy_perform` via an internal multi handle that it drives to
    /// completion; the asynchronous equivalent here awaits the transfer future.
    ///
    /// # Client output/input
    ///
    /// This convenience entry uses curl's *default* client callbacks: response
    /// body bytes are written to `stdout` (curl's default `CURLOPT_WRITEFUNCTION`
    /// of `fwrite` to `stdout`), header bytes are delivered only when
    /// `CURLOPT_HEADER` folds them into the output, and an upload body is read
    /// from `stdin` (the default `CURLOPT_READFUNCTION`). Front-ends that
    /// register their own callbacks — the CLI's write/header/read handlers, or a
    /// libcurl consumer's `CURLOPT_WRITEFUNCTION`/`CURLOPT_READFUNCTION` bridged
    /// at the FFI boundary — call [`perform_with`](Easy::perform_with) directly
    /// with their own sink/source.
    ///
    /// # Errors
    ///
    /// Propagates any error from [`perform_with`](Easy::perform_with): a
    /// preflight failure (notably [`CurlError::UrlMalformat`]), the protocol
    /// handler's connect/transfer error, or [`CurlError::UnsupportedProtocol`]
    /// for a scheme with no registered handler.
    pub async fn perform(&mut self) -> Result<()> {
        // curl's default client I/O (see the doc above). These owned sinks live
        // only for the duration of the transfer.
        let mut sink = DefaultClientOutput::new();
        let mut source = DefaultClientInput;
        self.perform_with(&mut sink, &mut source).await
    }

    /// Drive a single transfer to completion, delivering response body/header
    /// bytes to `sink` and pulling any upload body from `source`.
    ///
    /// This is the sink-explicit form of [`perform`](Easy::perform) — the seam
    /// the FFI and CLI front-ends use to route a transfer through the *user's*
    /// registered callbacks (`CURLOPT_WRITEFUNCTION` / `CURLOPT_READFUNCTION` /
    /// `CURLOPT_HEADERFUNCTION`). The FFI crate supplies a sink that invokes the
    /// stored C function pointers (the only place that raw-pointer call is
    /// allowed); the CLI supplies a Rust-native sink; tests supply collecting
    /// doubles.
    ///
    /// It performs curl's pre-dispatch preflight (URL resolution/validation,
    /// recording the effective URL and scheme — see
    /// [`pre_perform`](Easy::pre_perform)) and then hands off to the protocol
    /// engine ([`crate::protocols::perform_transfer`]), which dispatches on the
    /// scheme to the registered handler and drives the byte movement.
    ///
    /// # Errors
    ///
    /// * Any error from [`pre_perform`](Easy::pre_perform) (URL resolution /
    ///   validation), notably [`CurlError::UrlMalformat`].
    /// * The protocol handler's connect/do/transfer error.
    /// * [`CurlError::UnsupportedProtocol`] for a scheme whose handler is not
    ///   compiled in, or whose end-to-end network drive is not yet wired.
    pub async fn perform_with(
        &mut self,
        sink: &mut dyn WriteCallbacks,
        source: &mut dyn ReadCallback,
    ) -> Result<()> {
        // Preflight: resolve/validate the URL and populate the effective-URL and
        // scheme info. Any failure here short-circuits exactly as curl's
        // pre-dispatch checks do.
        self.pre_perform()?;

        // Dispatch on the resolved scheme and drive the transfer (curl's
        // connect → do → transfer → done for a single easy handle). FILE — the
        // only `PROTOPT_NONETWORK` scheme — is driven end-to-end; recognized
        // network schemes whose `conn`/exchange drive is not yet wired report
        // `UnsupportedProtocol`, exactly as curl's missing-handler path does.
        crate::protocols::perform_transfer(self, sink, source).await
    }
}

/// curl's default `CURLOPT_WRITEFUNCTION` / `CURLOPT_HEADERFUNCTION`: response
/// body bytes are written to `stdout`. The default path configures *no separate
/// header destination* (curl's `-D`/`--dump-header` is what would set one), so
/// the header-stream callback is NULL and header bytes are silently consumed on
/// that stream. Response headers still reach `stdout` when `CURLOPT_HEADER`
/// (`-i`/`-I`) is set, because the client-writer ([`crate::transfer`]'s
/// `cw_out_write`) routes header bytes to the *body* stream in that case. Used
/// by [`Easy::perform`] when no front-end sink is supplied.
struct DefaultClientOutput;

impl DefaultClientOutput {
    /// Build the default output sink.
    fn new() -> Self {
        Self
    }
}

impl WriteCallbacks for DefaultClientOutput {
    fn write_body(&mut self, data: &[u8]) -> usize {
        use std::io::Write;
        // A short write (fewer bytes than supplied) fails the transfer with
        // `CURLE_WRITE_ERROR`, exactly as curl's `cw_out_cb_write` does; on an
        // I/O error report `0` taken so the engine raises that error.
        match std::io::stdout().write_all(data) {
            Ok(()) => data.len(),
            Err(_) => 0,
        }
    }

    fn write_header(&mut self, _data: &[u8]) -> Option<usize> {
        // The default CLI path configures no separate header destination (no
        // `-D`/`--dump-header`), so curl's header-stream callback is NULL and
        // the bytes are silently consumed. Returning `None` models that NULL
        // callback. Response headers still reach `stdout` when `CURLOPT_HEADER`
        // (`-i`/`-I`) is on, because `CwOut::do_client_write` routes header
        // bytes to the *body* stream in that case — delivering them via
        // [`Self::write_body`]. Writing here too would emit each header twice.
        None
    }
}

/// curl's default `CURLOPT_READFUNCTION`: an upload body is read from `stdin`.
/// Used by [`Easy::perform`] when no front-end source is supplied.
struct DefaultClientInput;

impl ReadCallback for DefaultClientInput {
    fn read(&mut self, buf: &mut [u8]) -> usize {
        use std::io::Read;
        // End-of-input (`0`) on EOF or error, matching a `CURLOPT_READFUNCTION`
        // returning `0` to signal the upload is complete.
        std::io::stdin().read(buf).unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Connection-level operations: pause / recv / send / upkeep
// ---------------------------------------------------------------------------

impl Easy {
    /// `curl_easy_pause` — pause or resume a transfer's directions.
    ///
    /// `bitmask` is the `CURLPAUSE_*` set: [`CURLPAUSE_RECV`] and/or
    /// [`CURLPAUSE_SEND`] to pause those directions, [`CURLPAUSE_CONT`] (`0`) to
    /// resume both, or [`CURLPAUSE_ALL`] to pause both. Matching curl, pausing is
    /// only meaningful while a transfer/connection is active: with no connection
    /// attached this returns [`CurlError::BadFunctionArgument`] (curl's
    /// `curl_easy_pause` returns `CURLE_BAD_FUNCTION_ARGUMENT` when
    /// `!data->conn`).
    ///
    /// Bits absent from `bitmask` are cleared, so passing [`CURLPAUSE_CONT`]
    /// resumes both directions.
    ///
    /// # Errors
    ///
    /// [`CurlError::BadFunctionArgument`] if no connection is attached.
    pub fn pause(&mut self, bitmask: i32) -> Result<()> {
        // curl: pausing requires an active connection.
        if !self.state.has_connection {
            return Err(CurlError::BadFunctionArgument);
        }
        // Update the per-direction pause bits from the bitmask.
        self.state.recv_paused = bitmask & CURLPAUSE_RECV != 0;
        self.state.send_paused = bitmask & CURLPAUSE_SEND != 0;
        // (When unpausing, curl flushes any buffered data; that buffering lives
        // in the transfer/connection layer and is driven there once wired in.)
        Ok(())
    }

    /// `curl_easy_recv` — receive raw bytes on a `CONNECT_ONLY` connection.
    ///
    /// Reads up to `buf.len()` bytes into `buf`, returning the number received.
    /// Like curl, this is only valid on a connection established with
    /// `CURLOPT_CONNECT_ONLY`; without such a connection it returns
    /// [`CurlError::UnsupportedProtocol`] (curl's `curl_easy_recv` requires
    /// `easy_connection()` and otherwise returns `CURLE_UNSUPPORTED_PROTOCOL`).
    ///
    /// # Errors
    ///
    /// [`CurlError::UnsupportedProtocol`] if no `CONNECT_ONLY` connection is
    /// attached (the raw byte transport, owned by the connection layer, is wired
    /// in as it comes online).
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        // curl: raw recv requires a CONNECT_ONLY connection (`easy_connection()`);
        // otherwise CURLE_UNSUPPORTED_PROTOCOL.
        if !self.set.connect_only || !self.state.has_connection {
            return Err(CurlError::UnsupportedProtocol);
        }
        // A CONNECT_ONLY connection is attached, but the raw byte transport lives
        // in the connection layer and is wired in as it comes online; the read
        // buffer is intentionally left untouched until then.
        let _ = buf;
        Err(CurlError::UnsupportedProtocol)
    }

    /// `curl_easy_send` — send raw bytes on a `CONNECT_ONLY` connection.
    ///
    /// Writes up to `buf.len()` bytes from `buf`, returning the number sent. Like
    /// curl, this is only valid on a connection established with
    /// `CURLOPT_CONNECT_ONLY`; without such a connection it returns
    /// [`CurlError::UnsupportedProtocol`] (curl's `curl_easy_send` requires
    /// `easy_connection()` and otherwise returns `CURLE_UNSUPPORTED_PROTOCOL`).
    ///
    /// # Errors
    ///
    /// [`CurlError::UnsupportedProtocol`] if no `CONNECT_ONLY` connection is
    /// attached (the raw byte transport, owned by the connection layer, is wired
    /// in as it comes online).
    pub fn send(&mut self, buf: &[u8]) -> Result<usize> {
        // curl: raw send requires a CONNECT_ONLY connection (`easy_connection()`);
        // otherwise CURLE_UNSUPPORTED_PROTOCOL.
        if !self.set.connect_only || !self.state.has_connection {
            return Err(CurlError::UnsupportedProtocol);
        }
        // A CONNECT_ONLY connection is attached, but the raw byte transport lives
        // in the connection layer and is wired in as it comes online; the payload
        // is intentionally left unsent until then.
        let _ = buf;
        Err(CurlError::UnsupportedProtocol)
    }

    // ----- WebSocket CONNECT_ONLY surface (backs the `curl_ws_*` FFI) ------

    /// Attach a retained WebSocket `CURLOPT_CONNECT_ONLY` connection to the
    /// handle (the Rust analog of `Curl_ws_accept` leaving `data->conn` and the
    /// connection's `websocket` state live past the upgrade `perform`).
    ///
    /// Called by the WebSocket transfer driver once the HTTP/1.1 Upgrade has
    /// completed: the live [`Connection`] and its [`WsConnState`] framing engine
    /// are moved onto the handle so the subsequent `curl_ws_send`/`curl_ws_recv`/
    /// `curl_ws_meta` calls operate on them. `has_connection` is set so the
    /// connection-gated entrypoints observe the attached socket.
    pub(crate) fn attach_ws_connection(&mut self, conn: Connection, ws: WsConnState) {
        self.state.has_connection = true;
        self.connect_only_conn = Some(std::sync::Mutex::new(conn));
        self.ws_state = Some(ws);
    }

    /// Whether a live WebSocket context is attached (an active `ws`/`wss`
    /// CONNECT_ONLY connection). This is the gate curl applies before returning
    /// frame metadata from `curl_ws_meta` (`data->conn` + the connection's
    /// `websocket` state); outside it, `curl_ws_meta` must report NULL
    /// (QA F5-MINOR-2).
    #[must_use]
    pub fn is_websocket(&self) -> bool {
        self.ws_state.is_some()
    }

    /// `curl_ws_send` — send one WebSocket frame (or frame chunk) on the
    /// retained connection.
    ///
    /// Frames the `payload` per RFC 6455 (opcode/FIN from `flags`, masked) and
    /// transmits it, returning the number of *payload* bytes accepted. With
    /// `CURLWS_OFFSET`, `fragsize` is the total frame length and this call
    /// supplies one chunk. In `CURLWS_RAW_MODE` the bytes go out verbatim.
    ///
    /// # Errors
    ///
    /// [`CurlError::UnsupportedProtocol`] when no WebSocket connection is
    /// attached (curl requires a `CONNECT_ONLY` WebSocket connection), plus any
    /// framing/transport error from the connection.
    pub async fn ws_send(&mut self, payload: &[u8], flags: u32, fragsize: i64) -> Result<usize> {
        // Borrow the two disjoint fields directly so the framing engine and the
        // connection are held mutably at the same time (the borrow checker
        // splits `self.ws_state` and `self.connect_only_conn`). `get_mut` on the
        // wrapping mutex never blocks given `&mut self`.
        let ws = self
            .ws_state
            .as_mut()
            .ok_or(CurlError::UnsupportedProtocol)?;
        let conn = self
            .connect_only_conn
            .as_mut()
            .ok_or(CurlError::UnsupportedProtocol)?
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ws.ws_send(conn, payload, flags, fragsize).await
    }

    /// `curl_ws_recv` — receive and decode the next WebSocket frame (or chunk)
    /// from the retained connection into `buf`.
    ///
    /// Returns the number of payload bytes written to `buf` and the frame
    /// metadata. Control PINGs are auto-answered (unless `CURLWS_NOAUTOPONG`) and
    /// not surfaced.
    ///
    /// # Errors
    ///
    /// [`CurlError::UnsupportedProtocol`] when no WebSocket connection is
    /// attached; [`CurlError::GotNothing`] on a clean close; plus any
    /// framing/transport error.
    pub async fn ws_recv(&mut self, buf: &mut [u8]) -> Result<(usize, WsFrameMeta)> {
        let ws = self
            .ws_state
            .as_mut()
            .ok_or(CurlError::UnsupportedProtocol)?;
        let conn = self
            .connect_only_conn
            .as_mut()
            .ok_or(CurlError::UnsupportedProtocol)?
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ws.ws_recv(conn, buf).await
    }

    /// `curl_ws_start_frame` — buffer a frame header for piecewise
    /// (`CURLWS_OFFSET`) delivery without sending payload yet.
    ///
    /// # Errors
    ///
    /// [`CurlError::SendError`] when no WebSocket connection is attached (curl's
    /// "no associated connection" path) or a previous frame is still open.
    pub fn ws_start_frame(&mut self, flags: u32, frame_len: i64) -> Result<()> {
        // curl's `curl_ws_start_frame` reports `CURLE_SEND_ERROR` when there is
        // no associated WebSocket connection.
        let ws = self.ws_state.as_mut().ok_or(CurlError::SendError)?;
        // Route any diagnostic straight into the connection's error buffer (so
        // verbose/`CURLINFO` observes it), borrowing the disjoint `connect_only_conn`
        // field via `get_mut` (never blocks under `&mut self`).
        match self
            .connect_only_conn
            .as_mut()
            .map(|m| m.get_mut().unwrap_or_else(std::sync::PoisonError::into_inner))
        {
            Some(conn) => ws.ws_start_frame(&mut conn.filter_data.error_buffer, flags, frame_len),
            None => {
                let mut err_buf = None;
                ws.ws_start_frame(&mut err_buf, flags, frame_len)
            }
        }
    }

    /// `curl_ws_meta` — the metadata of the most recently received frame, or
    /// `None` when no WebSocket context is attached (QA F5-MINOR-2: curl returns
    /// NULL outside an active WebSocket transfer).
    #[must_use]
    pub fn ws_meta(&self) -> Option<WsFrameMeta> {
        self.ws_state.as_ref().map(WsConnState::meta)
    }

    /// `curl_easy_upkeep` — perform connection-pool upkeep.
    ///
    /// curl runs `Curl_cpool_upkeep` over the handle's connection cache, pinging
    /// idle connections whose keep-alive interval has elapsed. With no
    /// connections attached this is a successful no-op (curl returns
    /// `CURLE_OK`); the connection layer extends this to actually ping idle
    /// connections once wired in.
    ///
    /// # Errors
    ///
    /// Currently infallible (`Ok(())`); the signature returns [`Result`] to match
    /// curl's `CURLcode`-returning `curl_easy_upkeep` and to remain stable when
    /// real upkeep is wired in.
    pub fn upkeep(&self) -> Result<()> {
        Ok(())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::Share;

    // ---- construction & defaults ----------------------------------------

    #[test]
    fn new_uses_curl_defaults() {
        let e = Easy::new();
        // A representative slice of curl's documented defaults, verified against
        // `UserDefined::default` (which mirrors lib/url.c `Curl_init_userdefined`).
        assert_eq!(e.set.maxredirs, 30);
        assert_eq!(e.set.buffer_size, 16_384);
        assert!(!e.set.connect_only);
        assert!(e.set.ftp_use_epsv);
        assert!(e.set.tcp_nodelay);
        assert!(e.set.ssl_enable_alpn);
        // Fresh runtime info.
        assert_eq!(e.info.response_code, 0);
        assert!(e.info.effective_url.is_none());
        assert!(e.info.scheme.is_none());
        // No URL configured, not paused.
        assert!(e.url().is_none());
        assert!(!e.is_paused());
    }

    #[test]
    fn default_equals_new() {
        let a = Easy::default();
        let b = Easy::new();
        assert_eq!(a.set.maxredirs, b.set.maxredirs);
        assert_eq!(a.url(), b.url());
    }

    // ---- setopt / getinfo -----------------------------------------------

    #[test]
    fn setopt_url_then_url_accessor() {
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some("http://example.com/".to_string())),
        )
        .unwrap();
        assert_eq!(e.url(), Some("http://example.com/"));
    }

    #[test]
    fn setopt_wrong_value_type_is_bad_argument() {
        let mut e = Easy::new();
        // CURLOPT_URL is a string option; passing a long is a type error.
        let err = e
            .setopt(CurlOption::CURLOPT_URL, OptionValue::Long(7))
            .unwrap_err();
        assert_eq!(err, CurlError::BadFunctionArgument);
    }

    #[test]
    fn getinfo_response_code_default_zero() {
        let e = Easy::new();
        assert_eq!(
            e.getinfo(CurlInfo::ResponseCode).unwrap(),
            InfoValue::Long(0)
        );
    }

    // ---- preflight / perform --------------------------------------------

    #[test]
    fn pre_perform_populates_effective_url_and_scheme() {
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some("http://example.com/".to_string())),
        )
        .unwrap();
        e.pre_perform().expect("preflight succeeds for a valid URL");

        let eff = e.info.effective_url.as_ref().unwrap().to_str().unwrap();
        assert!(
            eff.starts_with("http://example.com"),
            "effective URL = {eff}"
        );
        let scheme = e.info.scheme.as_ref().unwrap().to_str().unwrap();
        assert_eq!(scheme, "HTTP"); // curl reports the scheme upper-cased
    }

    #[test]
    fn pre_perform_without_url_is_url_malformat() {
        let mut e = Easy::new();
        assert_eq!(e.pre_perform().unwrap_err(), CurlError::UrlMalformat);
    }

    #[test]
    fn pre_perform_resets_stale_info() {
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some("http://example.com/".to_string())),
        )
        .unwrap();
        e.pre_perform().unwrap();
        assert!(e.info.effective_url.is_some());

        // Clear the URL; the next preflight resets info *before* it fails, so the
        // stale effective URL must be gone.
        e.setopt(CurlOption::CURLOPT_URL, OptionValue::Str(None))
            .unwrap();
        assert_eq!(e.pre_perform().unwrap_err(), CurlError::UrlMalformat);
        assert!(
            e.info.effective_url.is_none(),
            "stale effective URL not cleared"
        );
    }

    #[tokio::test]
    async fn perform_preflights_then_reports_unsupported_protocol() {
        let mut e = Easy::new();
        // Every *recognized* scheme is now driven end-to-end over the network
        // (wiring that absence was exactly QA findings F4/F5-CRIT-*), so to
        // exercise the "preflight succeeds, then the transfer reports
        // UnsupportedProtocol" path we use a scheme with no registered handler
        // at all. curl's URL parser rejects an unknown scheme unless
        // `CURLU_NON_SUPPORT_SCHEME` is set, so the URL is supplied as a
        // pre-parsed `CURLOPT_CURLU` handle built with that flag (the
        // string-parse preflight path would otherwise reject it). Dispatch fails
        // at scheme lookup before any socket opens — so this stays network-free.
        let mut uh = CurlUrl::new();
        uh.set(
            CurlUPart::Url,
            Some("xyz://example.com/"),
            crate::url::CURLU_NON_SUPPORT_SCHEME,
        )
        .expect("CURLU_NON_SUPPORT_SCHEME accepts an unknown scheme");
        e.set.uh = Some(uh);

        // No registered handler for this scheme: the transfer cannot proceed,
        // but the preflight must have populated the effective URL / scheme first.
        assert_eq!(
            e.perform().await.unwrap_err(),
            CurlError::UnsupportedProtocol
        );

        match e.getinfo(CurlInfo::EffectiveUrl).unwrap() {
            InfoValue::Str(Some(s)) => {
                assert!(s.to_str().unwrap().starts_with("xyz://example.com"));
            }
            other => panic!("expected effective-url string, got {other:?}"),
        }
        match e.getinfo(CurlInfo::Scheme).unwrap() {
            InfoValue::Str(Some(s)) => assert_eq!(s.to_str().unwrap(), "XYZ"),
            other => panic!("expected scheme string, got {other:?}"),
        }
        assert_eq!(
            e.getinfo(CurlInfo::ResponseCode).unwrap(),
            InfoValue::Long(0)
        );
    }

    #[tokio::test]
    async fn perform_without_url_is_url_malformat() {
        let mut e = Easy::new();
        assert_eq!(e.perform().await.unwrap_err(), CurlError::UrlMalformat);
    }

    // ---- perform_with: end-to-end FILE (PROTOPT_NONETWORK) drive ---------
    //
    // These exercise the public transfer entry point — `perform_with` →
    // `crate::protocols::perform_transfer` → the FILE handler's
    // connect/do_it/run_download/run_upload — proving a `file://` transfer runs
    // through the real protocol-dispatch + transfer drive (not the old
    // unconditional `UnsupportedProtocol`). The CLI and FFI front-ends drive the
    // same path with their own sinks/sources.

    /// A [`WriteCallbacks`] sink that accumulates body and header bytes — the
    /// Rust-native analog of a `CURLOPT_WRITEFUNCTION` collecting output.
    #[derive(Default)]
    struct CollectSink {
        body: Vec<u8>,
        headers: Vec<u8>,
    }

    impl WriteCallbacks for CollectSink {
        fn write_body(&mut self, data: &[u8]) -> usize {
            self.body.extend_from_slice(data);
            data.len()
        }
        fn write_header(&mut self, data: &[u8]) -> Option<usize> {
            self.headers.extend_from_slice(data);
            Some(data.len())
        }
    }

    /// A [`ReadCallback`] upload source serving bytes from an in-memory buffer
    /// (the analog of a `CURLOPT_READFUNCTION` over a fixed payload).
    struct SliceSource {
        data: Vec<u8>,
        pos: usize,
    }

    impl ReadCallback for SliceSource {
        fn read(&mut self, buf: &mut [u8]) -> usize {
            let n = (self.data.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            n
        }
    }

    /// An empty upload source (no bytes), for download transfers.
    struct NoSource;
    impl ReadCallback for NoSource {
        fn read(&mut self, _buf: &mut [u8]) -> usize {
            0
        }
    }

    #[tokio::test]
    async fn perform_with_drives_file_download_into_sink() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("page.txt");
        std::fs::write(&path, b"hello from file").unwrap();

        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("file://{}", path.display()))),
        )
        .unwrap();

        let mut sink = CollectSink::default();
        let mut source = NoSource;
        // The public transfer entry point drives the FILE handler end-to-end.
        e.perform_with(&mut sink, &mut source).await.unwrap();

        assert_eq!(sink.body, b"hello from file");
        // Post-transfer info recorded by the handler (`file_do`).
        assert!(e.info.filetime > 0, "filetime recorded for --remote-time");
        // Preflight still populated the effective URL / scheme.
        match e.getinfo(CurlInfo::Scheme).unwrap() {
            InfoValue::Str(Some(s)) => assert_eq!(s.to_str().unwrap(), "FILE"),
            other => panic!("expected scheme string, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn perform_drives_file_download_to_default_output() {
        // The argument-free `perform()` uses the default stdout sink; it must
        // succeed for a readable file (bytes go to the process stdout).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("page.txt");
        std::fs::write(&path, b"to stdout").unwrap();

        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("file://{}", path.display()))),
        )
        .unwrap();
        e.perform().await.unwrap();
    }

    #[tokio::test]
    async fn perform_with_file_upload_writes_target() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("upload.txt");

        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("file://{}", path.display()))),
        )
        .unwrap();
        // CURLOPT_UPLOAD → method PUT, the upload signal the FILE handler reads.
        e.setopt(CurlOption::CURLOPT_UPLOAD, OptionValue::Long(1))
            .unwrap();

        let mut sink = CollectSink::default();
        let mut source = SliceSource {
            data: b"payload bytes".to_vec(),
            pos: 0,
        };
        e.perform_with(&mut sink, &mut source).await.unwrap();

        let written = std::fs::read(&path).unwrap();
        assert_eq!(written, b"payload bytes");
    }

    #[tokio::test]
    async fn perform_with_missing_file_maps_to_couldnt_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.txt");

        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("file://{}", path.display()))),
        )
        .unwrap();

        let mut sink = CollectSink::default();
        let mut source = NoSource;
        // A missing file fails at connect with CURLE_FILE_COULDNT_READ_FILE,
        // exactly as curl's `file_connect` does.
        assert_eq!(
            e.perform_with(&mut sink, &mut source).await.unwrap_err(),
            CurlError::FileCouldntReadFile
        );
    }

    #[tokio::test]
    async fn perform_with_unknown_scheme_is_unsupported() {
        // A scheme with no registered handler reports UnsupportedProtocol. Every
        // *recognized* scheme is now driven over the network, so this uses a
        // truly unknown scheme, supplied as a pre-parsed `CURLOPT_CURLU` handle
        // built with `CURLU_NON_SUPPORT_SCHEME` (the string-parse preflight
        // rejects an unknown scheme otherwise). Dispatch fails at scheme lookup —
        // no socket is opened.
        let mut e = Easy::new();
        let mut uh = CurlUrl::new();
        uh.set(
            CurlUPart::Url,
            Some("xyz://example.com/"),
            crate::url::CURLU_NON_SUPPORT_SCHEME,
        )
        .expect("CURLU_NON_SUPPORT_SCHEME accepts an unknown scheme");
        e.set.uh = Some(uh);

        let mut sink = CollectSink::default();
        let mut source = NoSource;
        assert_eq!(
            e.perform_with(&mut sink, &mut source).await.unwrap_err(),
            CurlError::UnsupportedProtocol
        );
    }

    // ---- reset -----------------------------------------------------------

    #[test]
    fn reset_restores_defaults_and_clears_info() {
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some("http://example.com/".to_string())),
        )
        .unwrap();
        e.set.maxredirs = 2;
        e.pre_perform().unwrap();
        assert!(e.info.effective_url.is_some());

        e.reset();

        // Options back to defaults …
        assert!(e.url().is_none());
        assert_eq!(e.set.maxredirs, 30);
        // … and runtime info cleared.
        assert!(e.info.effective_url.is_none());
        assert_eq!(e.info.response_code, 0);
    }

    #[test]
    fn reset_preserves_share_and_connection_but_clears_pause() {
        let mut e = Easy::new();
        e.set.share = Some(Share::new());
        e.state.has_connection = true;
        e.state.recv_paused = true;

        e.reset();

        // curl keeps `data->share` and the connection cache across a reset; the
        // pause bits are wiped with the request state.
        assert!(e.set.share.is_some(), "share must survive reset");
        assert!(e.state.has_connection, "connection must survive reset");
        assert!(!e.is_paused(), "pause bits cleared on reset");
    }

    // ---- duphandle -------------------------------------------------------

    #[test]
    fn duphandle_clones_config_not_runtime() {
        let mut parent = Easy::new();
        parent
            .setopt(
                CurlOption::CURLOPT_URL,
                OptionValue::Str(Some("http://example.com/".to_string())),
            )
            .unwrap();
        parent.set.maxredirs = 5;
        parent.pre_perform().unwrap(); // populate runtime info
        parent.state.has_connection = true; // simulate a live connection

        let child = parent.duphandle();

        // Configuration is deep-copied.
        assert_eq!(child.url(), Some("http://example.com/"));
        assert_eq!(child.set.maxredirs, 5);
        // Runtime / connection state is fresh, NOT inherited.
        assert!(child.info.effective_url.is_none());
        assert!(!child.state.has_connection);
        assert!(!child.is_paused());
    }

    #[test]
    fn duphandle_does_not_inherit_share() {
        let mut parent = Easy::new();
        parent.set.share = Some(Share::new());
        let child = parent.duphandle();
        assert!(parent.set.share.is_some(), "parent keeps its share");
        assert!(
            child.set.share.is_none(),
            "child must not inherit the share"
        );
    }

    #[test]
    fn duphandle_is_independent_of_parent() {
        let mut parent = Easy::new();
        parent
            .setopt(
                CurlOption::CURLOPT_URL,
                OptionValue::Str(Some("http://a.test/".to_string())),
            )
            .unwrap();

        let mut child = parent.duphandle();
        // Mutating the child must not affect the parent (a true deep copy).
        child
            .setopt(
                CurlOption::CURLOPT_URL,
                OptionValue::Str(Some("http://b.test/".to_string())),
            )
            .unwrap();
        child.set.maxredirs = 99;

        assert_eq!(parent.url(), Some("http://a.test/"));
        assert_eq!(parent.set.maxredirs, 30);
        assert_eq!(child.url(), Some("http://b.test/"));
        assert_eq!(child.set.maxredirs, 99);
    }

    #[test]
    fn duphandle_deep_copies_owned_strings() {
        // The child must own its own copy of every string option even after the
        // parent is dropped.
        let mut parent = Easy::new();
        parent
            .setopt(
                CurlOption::CURLOPT_URL,
                OptionValue::Str(Some("http://deep.test/".to_string())),
            )
            .unwrap();
        let child = parent.duphandle();
        drop(parent);
        assert_eq!(child.url(), Some("http://deep.test/"));
    }

    // ---- pause / recv / send / upkeep -----------------------------------

    #[test]
    fn pause_without_connection_is_bad_argument() {
        let mut e = Easy::new();
        assert_eq!(
            e.pause(CURLPAUSE_ALL).unwrap_err(),
            CurlError::BadFunctionArgument
        );
    }

    #[test]
    fn pause_sets_and_clears_direction_bits() {
        let mut e = Easy::new();
        e.state.has_connection = true; // pausing requires a connection

        e.pause(CURLPAUSE_RECV).unwrap();
        assert!(e.is_paused());
        assert!(e.state.recv_paused);
        assert!(!e.state.send_paused);

        e.pause(CURLPAUSE_ALL).unwrap();
        assert!(e.state.recv_paused && e.state.send_paused);

        e.pause(CURLPAUSE_CONT).unwrap();
        assert!(!e.is_paused());
        assert!(!e.state.recv_paused && !e.state.send_paused);
    }

    #[test]
    fn recv_send_require_connect_only_connection() {
        let mut e = Easy::new();
        let mut rbuf = [0u8; 8];
        let wbuf = [0u8; 8];

        // No CONNECT_ONLY, no connection.
        assert_eq!(
            e.recv(&mut rbuf).unwrap_err(),
            CurlError::UnsupportedProtocol
        );
        assert_eq!(e.send(&wbuf).unwrap_err(), CurlError::UnsupportedProtocol);

        // CONNECT_ONLY set but still no connection.
        e.set.connect_only = true;
        assert_eq!(
            e.recv(&mut rbuf).unwrap_err(),
            CurlError::UnsupportedProtocol
        );
        assert_eq!(e.send(&wbuf).unwrap_err(), CurlError::UnsupportedProtocol);

        // Even with both preconditions, the raw byte transport is not wired in
        // this layer, so the seam still reports UNSUPPORTED_PROTOCOL.
        e.state.has_connection = true;
        assert_eq!(
            e.recv(&mut rbuf).unwrap_err(),
            CurlError::UnsupportedProtocol
        );
        assert_eq!(e.send(&wbuf).unwrap_err(), CurlError::UnsupportedProtocol);
    }

    #[test]
    fn upkeep_is_ok_without_connections() {
        let e = Easy::new();
        assert!(e.upkeep().is_ok());
    }

    // ---- global init / cleanup / sslset ---------------------------------

    #[test]
    fn global_init_and_cleanup_are_idempotent() {
        // Balanced init/cleanup pairs always succeed; an unmatched extra cleanup
        // is a safe no-op (never underflows or panics).
        assert!(global_init(0).is_ok());
        assert!(global_init(3).is_ok()); // arbitrary CURL_GLOBAL_* bits accepted
        global_cleanup();
        global_cleanup();
        global_cleanup(); // extra, unbalanced — must not panic
    }

    #[test]
    fn global_sslset_selects_rustls_only() {
        // The single rustls backend is selectable by id or (case-insensitive) name.
        assert_eq!(global_sslset(CURLSSLBACKEND_RUSTLS, None), SslSetResult::Ok);
        assert_eq!(
            global_sslset(CURLSSLBACKEND_NONE, Some("rustls")),
            SslSetResult::Ok
        );
        assert_eq!(
            global_sslset(CURLSSLBACKEND_NONE, Some("RuStLs")),
            SslSetResult::Ok
        );
        // Any other backend is unknown in this single-backend, non-multi-SSL build.
        assert_eq!(
            global_sslset(1, Some("openssl")),
            SslSetResult::UnknownBackend
        );
        assert_eq!(
            global_sslset(CURLSSLBACKEND_NONE, None),
            SslSetResult::UnknownBackend
        );
    }

    // ---- perform_with: end-to-end HTTP/1.1 over a loopback server -----------
    //
    // These drive the REAL HTTP stack — connect (resolving the 127.0.0.1 literal
    // + the TCP dial), the HTTP/1.1 request build/send, the response parse, the
    // `HopSink` redirect/body routing, and the `CwOut` delivery — against an
    // in-process loopback server returning canned replies. They are the network
    // analog of the `file://` `perform_with` tests above and exercise the
    // transfer engine over a real socket. No external network is used (loopback
    // only), so they are hermetic.

    /// Spawn a loopback HTTP server that accepts `replies.len()` connections in
    /// turn, reads each request head (through the blank line) plus any
    /// `Content-Length` body so the client's send fully drains, then writes the
    /// corresponding canned reply and closes (every reply carries
    /// `Connection: close`). Returns the bound port and a handle capturing the
    /// raw bytes of each received request (one entry per connection).
    async fn spawn_loopback_http(
        replies: Vec<Vec<u8>>,
    ) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let cap_task = std::sync::Arc::clone(&captured);
        tokio::spawn(async move {
            for reply in replies {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let mut acc: Vec<u8> = Vec::new();
                let mut buf = [0u8; 2048];
                // Read up to and including the end-of-headers blank line.
                let head_end = loop {
                    match sock.read(&mut buf).await {
                        Ok(0) => break acc.len(),
                        Ok(n) => {
                            acc.extend_from_slice(&buf[..n]);
                            if let Some(p) = acc.windows(4).position(|w| w == b"\r\n\r\n") {
                                break p + 4;
                            }
                        }
                        Err(_) => break acc.len(),
                    }
                };
                // Drain any declared request body (a POST/PUT payload).
                let head = String::from_utf8_lossy(&acc[..head_end]).to_ascii_lowercase();
                let want_body = head
                    .split("content-length:")
                    .nth(1)
                    .and_then(|s| s.split("\r\n").next())
                    .and_then(|s| s.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                while acc.len() < head_end + want_body {
                    match sock.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => acc.extend_from_slice(&buf[..n]),
                        Err(_) => break,
                    }
                }
                if let Ok(mut g) = cap_task.lock() {
                    g.push(acc);
                }
                let _ = sock.write_all(&reply).await;
                let _ = sock.flush().await;
                // Dropping `sock` closes the connection (EOF for the client).
            }
        });
        (port, captured)
    }

    /// Run `perform_with` against a sink, failing the test (rather than hanging)
    /// if it does not complete promptly.
    async fn perform_guarded(e: &mut Easy, sink: &mut dyn WriteCallbacks) {
        let mut source = NoSource;
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            e.perform_with(sink, &mut source),
        )
        .await
        .expect("transfer must not hang")
        .expect("transfer must succeed");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_drives_http_get_into_sink() {
        let (port, _cap) = spawn_loopback_http(vec![b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nhello world".to_vec()]).await;
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("http://127.0.0.1:{port}/"))),
        )
        .unwrap();
        let mut sink = CollectSink::default();
        perform_guarded(&mut e, &mut sink).await;

        // The final response body reached the application sink verbatim.
        assert_eq!(sink.body, b"hello world");
        // The header callback observed the status line.
        let hdrs = String::from_utf8_lossy(&sink.headers);
        assert!(hdrs.starts_with("HTTP/1.1 200"), "status not seen: {hdrs:?}");
        // CURLINFO_RESPONSE_CODE recorded the 200.
        match e.getinfo(CurlInfo::ResponseCode).unwrap() {
            InfoValue::Long(c) => assert_eq!(c, 200),
            other => panic!("expected long response code, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_http_404_delivers_body_and_records_code() {
        // Without `--fail`, a 4xx is a successful transfer whose body (the error
        // page) is delivered and whose code is recorded (curl's default).
        let (port, _cap) = spawn_loopback_http(vec![b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nnot found".to_vec()]).await;
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("http://127.0.0.1:{port}/missing"))),
        )
        .unwrap();
        let mut sink = CollectSink::default();
        perform_guarded(&mut e, &mut sink).await;

        assert_eq!(sink.body, b"not found");
        match e.getinfo(CurlInfo::ResponseCode).unwrap() {
            InfoValue::Long(c) => assert_eq!(c, 404),
            other => panic!("expected long response code, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_http_post_sends_request_body() {
        // Setting CURLOPT_COPYPOSTFIELDS selects POST and supplies the body; the
        // request line and the payload must appear on the wire.
        let (port, cap) = spawn_loopback_http(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
        ])
        .await;
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("http://127.0.0.1:{port}/submit"))),
        )
        .unwrap();
        e.setopt(
            CurlOption::CURLOPT_COPYPOSTFIELDS,
            OptionValue::Bytes(Some(b"field=value&x=1".to_vec())),
        )
        .unwrap();
        let mut sink = CollectSink::default();
        perform_guarded(&mut e, &mut sink).await;

        assert_eq!(sink.body, b"ok");
        let reqs = cap.lock().unwrap();
        let req = String::from_utf8_lossy(&reqs[0]);
        assert!(req.starts_with("POST /submit "), "method/path wrong: {req:?}");
        assert!(req.contains("field=value&x=1"), "body not sent: {req:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_http_follows_redirect_to_final_body() {
        // End-to-end verification of Issue #4: with following enabled, only the
        // FINAL hop's body reaches the application — the intermediate 301 body is
        // suppressed (not leaked). The server answers two connections: a 301 with
        // a relative Location, then the 200 final response.
        let (port, _cap) = spawn_loopback_http(vec![
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: /final\r\nContent-Length: 13\r\nConnection: close\r\n\r\nredirect-page".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nfinal body".to_vec(),
        ])
        .await;
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("http://127.0.0.1:{port}/start"))),
        )
        .unwrap();
        e.setopt(CurlOption::CURLOPT_FOLLOWLOCATION, OptionValue::Long(1))
            .unwrap();
        let mut sink = CollectSink::default();
        perform_guarded(&mut e, &mut sink).await;

        // Only the final body is delivered; the intermediate redirect page must
        // NOT leak into the application output.
        assert_eq!(sink.body, b"final body");
        assert!(
            !sink.body.windows(8).any(|w| w == b"redirect"),
            "intermediate 301 body leaked: {:?}",
            String::from_utf8_lossy(&sink.body)
        );
        match e.getinfo(CurlInfo::ResponseCode).unwrap() {
            InfoValue::Long(c) => assert_eq!(c, 200),
            other => panic!("expected long response code, got {other:?}"),
        }
    }


    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_http_head_request_sends_head_and_skips_body() {
        // CURLOPT_NOBODY issues a HEAD; the server replies with headers only (the
        // declared Content-Length describes the would-be GET body). The client
        // must NOT read a body and must record the status.
        let (port, cap) = spawn_loopback_http(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n".to_vec(),
        ])
        .await;
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("http://127.0.0.1:{port}/resource"))),
        )
        .unwrap();
        e.setopt(CurlOption::CURLOPT_NOBODY, OptionValue::Long(1))
            .unwrap();
        let mut sink = CollectSink::default();
        perform_guarded(&mut e, &mut sink).await;

        assert!(sink.body.is_empty(), "HEAD must not deliver a body");
        let reqs = cap.lock().unwrap();
        let req = String::from_utf8_lossy(&reqs[0]);
        assert!(req.starts_with("HEAD /resource "), "method wrong: {req:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_http_sends_custom_request_headers() {
        // CURLOPT_HTTPHEADER adds/overrides request headers; they must appear on
        // the wire (curl's Curl_add_custom_headers).
        let (port, cap) = spawn_loopback_http(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
        ])
        .await;
        let mut headers = crate::slist::SList::default();
        headers.append("X-Test: foo").unwrap();
        headers.append("User-Agent: probe/1.0").unwrap();
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("http://127.0.0.1:{port}/"))),
        )
        .unwrap();
        e.setopt(
            CurlOption::CURLOPT_HTTPHEADER,
            OptionValue::Slist(Some(headers)),
        )
        .unwrap();
        let mut sink = CollectSink::default();
        perform_guarded(&mut e, &mut sink).await;

        assert_eq!(sink.body, b"ok");
        let reqs = cap.lock().unwrap();
        let req = String::from_utf8_lossy(&reqs[0]);
        assert!(req.contains("X-Test: foo\r\n"), "custom header missing: {req:?}");
        assert!(
            req.contains("User-Agent: probe/1.0\r\n"),
            "overridden UA missing: {req:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_http_reads_eof_framed_body() {
        // A response with no Content-Length and Connection: close frames the body
        // by the connection close (curl's "read until EOF"). The full body must
        // still be delivered.
        let (port, _cap) = spawn_loopback_http(vec![
            b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody-by-eof".to_vec(),
        ])
        .await;
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("http://127.0.0.1:{port}/stream"))),
        )
        .unwrap();
        let mut sink = CollectSink::default();
        perform_guarded(&mut e, &mut sink).await;

        assert_eq!(sink.body, b"body-by-eof");
    }


    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_http_1_0_uses_http_1_0_request_line() {
        // CURLOPT_HTTP_VERSION = 1.0 forces the HTTP/1.0 request line.
        let (port, cap) = spawn_loopback_http(vec![
            b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nv10".to_vec(),
        ])
        .await;
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("http://127.0.0.1:{port}/"))),
        )
        .unwrap();
        e.setopt(CurlOption::CURLOPT_HTTP_VERSION, OptionValue::Long(1))
            .unwrap();
        let mut sink = CollectSink::default();
        perform_guarded(&mut e, &mut sink).await;

        assert_eq!(sink.body, b"v10");
        let reqs = cap.lock().unwrap();
        let req = String::from_utf8_lossy(&reqs[0]);
        let first = req.lines().next().unwrap_or_default();
        assert!(first.ends_with("HTTP/1.0"), "request line not 1.0: {first:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_http_failonerror_returns_error_on_404() {
        // CURLOPT_FAILONERROR makes a 4xx a hard error (CURLE_HTTP_RETURNED_ERROR),
        // exercising http_should_fail on the live response.
        let (port, _cap) = spawn_loopback_http(vec![
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\nConnection: close\r\n\r\n404".to_vec(),
        ])
        .await;
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("http://127.0.0.1:{port}/missing"))),
        )
        .unwrap();
        e.setopt(CurlOption::CURLOPT_FAILONERROR, OptionValue::Long(1))
            .unwrap();
        let mut sink = CollectSink::default();
        let mut source = NoSource;
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            e.perform_with(&mut sink, &mut source),
        )
        .await
        .expect("transfer must not hang");
        assert_eq!(res.unwrap_err(), CurlError::HttpReturnedError);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_http_basic_auth_sends_authorization_header() {
        // CURLOPT_USERPWD with the default Basic scheme emits the canonical
        // `Authorization: Basic base64(user:pass)` header. base64("user:pass")
        // is the well-known "dXNlcjpwYXNz".
        let (port, cap) = spawn_loopback_http(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
        ])
        .await;
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("http://127.0.0.1:{port}/"))),
        )
        .unwrap();
        e.setopt(
            CurlOption::CURLOPT_USERPWD,
            OptionValue::Str(Some("user:pass".to_string())),
        )
        .unwrap();
        let mut sink = CollectSink::default();
        perform_guarded(&mut e, &mut sink).await;

        assert_eq!(sink.body, b"ok");
        let reqs = cap.lock().unwrap();
        let req = String::from_utf8_lossy(&reqs[0]);
        assert!(
            req.contains("Authorization: Basic dXNlcjpwYXNz\r\n"),
            "basic auth header missing/wrong: {req:?}"
        );
    }


    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_http_dechunks_chunked_response_body() {
        // A `Transfer-Encoding: chunked` response must be de-chunked before the
        // decoded payload reaches the sink (the chunk sizes/CRLF framing removed).
        let (port, _cap) = spawn_loopback_http(vec![
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
              5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
                .to_vec(),
        ])
        .await;
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("http://127.0.0.1:{port}/"))),
        )
        .unwrap();
        let mut sink = CollectSink::default();
        perform_guarded(&mut e, &mut sink).await;
        assert_eq!(sink.body, b"hello world", "chunked body not decoded");
        assert_eq!(
            e.getinfo(CurlInfo::ResponseCode).unwrap(),
            InfoValue::Long(200)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_http_put_upload_sends_body_with_put_method() {
        // CURLOPT_UPLOAD selects PUT and streams the read source as the request
        // body, framed by CURLOPT_INFILESIZE (a fixed Content-Length).
        const PAYLOAD: &[u8] = b"the quick brown fox";
        let (port, cap) = spawn_loopback_http(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
        ])
        .await;
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("http://127.0.0.1:{port}/upload"))),
        )
        .unwrap();
        e.setopt(CurlOption::CURLOPT_UPLOAD, OptionValue::Long(1))
            .unwrap();
        e.setopt(
            CurlOption::CURLOPT_INFILESIZE,
            OptionValue::Long(PAYLOAD.len() as i64),
        )
        .unwrap();
        let mut sink = CollectSink::default();
        let mut source = SliceSource {
            data: PAYLOAD.to_vec(),
            pos: 0,
        };
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            e.perform_with(&mut sink, &mut source),
        )
        .await
        .expect("PUT upload must not hang")
        .expect("PUT upload must succeed");

        let reqs = cap.lock().unwrap();
        let req = String::from_utf8_lossy(&reqs[0]);
        assert!(
            req.starts_with("PUT /upload HTTP/1.1\r\n"),
            "expected PUT request line: {req:?}"
        );
        assert!(
            req.ends_with("the quick brown fox"),
            "uploaded body missing from request: {req:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_http_204_no_content_has_empty_body() {
        // A 204 response is body-less by definition: the engine must not block
        // waiting for a body and must report the 204 status with no payload.
        let (port, _cap) = spawn_loopback_http(vec![
            b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".to_vec(),
        ])
        .await;
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("http://127.0.0.1:{port}/"))),
        )
        .unwrap();
        let mut sink = CollectSink::default();
        perform_guarded(&mut e, &mut sink).await;
        assert!(sink.body.is_empty(), "204 must deliver no body");
        assert_eq!(
            e.getinfo(CurlInfo::ResponseCode).unwrap(),
            InfoValue::Long(204)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_http_custom_request_sets_method() {
        // CURLOPT_CUSTOMREQUEST overrides the method verb verbatim (here DELETE)
        // while otherwise behaving like the default no-body request.
        let (port, cap) = spawn_loopback_http(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ngone".to_vec(),
        ])
        .await;
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("http://127.0.0.1:{port}/item/7"))),
        )
        .unwrap();
        e.setopt(
            CurlOption::CURLOPT_CUSTOMREQUEST,
            OptionValue::Str(Some("DELETE".to_string())),
        )
        .unwrap();
        let mut sink = CollectSink::default();
        perform_guarded(&mut e, &mut sink).await;
        assert_eq!(sink.body, b"gone");
        let reqs = cap.lock().unwrap();
        let req = String::from_utf8_lossy(&reqs[0]);
        assert!(
            req.starts_with("DELETE /item/7 HTTP/1.1\r\n"),
            "expected DELETE request line: {req:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_http_large_body_reassembled_across_reads() {
        // A body larger than a single socket read must be reassembled intact,
        // exercising the engine's incremental body-write loop.
        let payload = vec![b'x'; 5000];
        let mut reply =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", payload.len())
                .into_bytes();
        reply.extend_from_slice(&payload);
        let (port, _cap) = spawn_loopback_http(vec![reply]).await;
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("http://127.0.0.1:{port}/big"))),
        )
        .unwrap();
        let mut sink = CollectSink::default();
        perform_guarded(&mut e, &mut sink).await;
        assert_eq!(sink.body.len(), 5000, "large body truncated/short");
        assert!(sink.body.iter().all(|&b| b == b'x'), "large body corrupted");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_http_response_headers_reach_sink() {
        // Response header lines are delivered to the write-callback header path;
        // a custom response header must appear among the captured header lines.
        let (port, _cap) = spawn_loopback_http(vec![
            b"HTTP/1.1 200 OK\r\nX-Served-By: rust-loopback\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                .to_vec(),
        ])
        .await;
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("http://127.0.0.1:{port}/"))),
        )
        .unwrap();
        let mut sink = CollectSink::default();
        perform_guarded(&mut e, &mut sink).await;
        assert_eq!(sink.body, b"ok");
        let headers = String::from_utf8_lossy(&sink.headers);
        assert!(
            headers.contains("X-Served-By: rust-loopback"),
            "custom response header not delivered to sink: {headers:?}"
        );
        assert!(
            headers.starts_with("HTTP/1.1 200"),
            "status line missing from header stream: {headers:?}"
        );
    }


    // ---- perform_with: end-to-end FTP passive download over loopback --------

    /// Spawn a minimal passive-mode FTP server on loopback that serves a single
    /// file via `RETR`. It answers the standard control dialog leniently and, on
    /// `EPSV`/`PASV`, opens a data listener whose port it advertises; the
    /// subsequent `RETR` streams `body` on the accepted data connection, framed
    /// by the data-channel close. Returns the bound control port. This drives the
    /// real FTP handler's connect/login/PWD/TYPE/SIZE/passive-negotiation and the
    /// data-channel download path (`run_do_phase`) end-to-end.
    #[cfg(feature = "ftp")]
    async fn spawn_loopback_ftp(
        body: &'static [u8],
    ) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Captures the bytes received on a STOR upload's data channel.
        let uploaded = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let up_task = std::sync::Arc::clone(&uploaded);
        tokio::spawn(async move {
            let Ok((ctrl, _)) = listener.accept().await else {
                return;
            };
            let (rd, mut wr) = ctrl.into_split();
            let mut lines = BufReader::new(rd).lines();
            let _ = wr.write_all(b"220 loopback FTP ready\r\n").await;
            // The data listener bound by the most recent EPSV/PASV, awaiting RETR.
            let mut data_listener: Option<tokio::net::TcpListener> = None;
            while let Ok(Some(line)) = lines.next_line().await {
                let upper = line.trim_end().to_ascii_uppercase();
                let cmd = upper.split_whitespace().next().unwrap_or("");
                match cmd {
                    "USER" => {
                        let _ = wr.write_all(b"331 need password\r\n").await;
                    }
                    "PASS" => {
                        let _ = wr.write_all(b"230 logged in\r\n").await;
                    }
                    "PWD" | "XPWD" => {
                        let _ = wr.write_all(b"257 \"/\" is the current directory\r\n").await;
                    }
                    "CWD" => {
                        let _ = wr.write_all(b"250 directory changed\r\n").await;
                    }
                    "TYPE" => {
                        let _ = wr.write_all(b"200 type set\r\n").await;
                    }
                    "SIZE" => {
                        let _ = wr
                            .write_all(format!("213 {}\r\n", body.len()).as_bytes())
                            .await;
                    }
                    "MDTM" => {
                        let _ = wr.write_all(b"213 20200101000000\r\n").await;
                    }
                    "REST" => {
                        let _ = wr.write_all(b"350 restart marker accepted\r\n").await;
                    }
                    "FEAT" => {
                        let _ = wr.write_all(b"211-Features:\r\n EPSV\r\n PASV\r\n211 End\r\n").await;
                    }
                    "OPTS" => {
                        let _ = wr.write_all(b"200 ok\r\n").await;
                    }
                    "SYST" => {
                        let _ = wr.write_all(b"215 UNIX Type: L8\r\n").await;
                    }
                    "EPSV" => {
                        let dl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                        let dp = dl.local_addr().unwrap().port();
                        data_listener = Some(dl);
                        let _ = wr
                            .write_all(
                                format!("229 Entering Extended Passive Mode (|||{dp}|)\r\n")
                                    .as_bytes(),
                            )
                            .await;
                    }
                    "PASV" => {
                        let dl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                        let dp = dl.local_addr().unwrap().port();
                        data_listener = Some(dl);
                        let (hi, lo) = (dp / 256, dp % 256);
                        let _ = wr
                            .write_all(
                                format!("227 Entering Passive Mode (127,0,0,1,{hi},{lo})\r\n")
                                    .as_bytes(),
                            )
                            .await;
                    }
                    "RETR" | "LIST" | "NLST" => {
                        let _ = wr.write_all(b"150 opening data connection\r\n").await;
                        if let Some(dl) = data_listener.take() {
                            if let Ok((mut dsock, _)) = dl.accept().await {
                                let _ = dsock.write_all(body).await;
                                let _ = dsock.flush().await;
                                // Dropping `dsock` closes the data channel (EOF).
                            }
                        }
                        let _ = wr.write_all(b"226 transfer complete\r\n").await;
                    }
                    "STOR" | "APPE" => {
                        let _ = wr.write_all(b"150 ready to receive\r\n").await;
                        if let Some(dl) = data_listener.take() {
                            if let Ok((mut dsock, _)) = dl.accept().await {
                                let mut got = Vec::new();
                                let _ = dsock.read_to_end(&mut got).await;
                                if let Ok(mut g) = up_task.lock() {
                                    *g = got;
                                }
                            }
                        }
                        let _ = wr.write_all(b"226 transfer complete\r\n").await;
                    }
                    "QUIT" => {
                        let _ = wr.write_all(b"221 goodbye\r\n").await;
                        break;
                    }
                    _ => {
                        let _ = wr.write_all(b"200 ok\r\n").await;
                    }
                }
            }
        });
        (port, uploaded)
    }

    #[cfg(feature = "ftp")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_ftp_downloads_file_into_sink() {
        // A passive-mode FTP GET: the control dialog logs in and negotiates EPSV,
        // and the file body arrives on the data channel into the sink.
        let (port, _up) = spawn_loopback_ftp(b"ftp file contents\n").await;
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("ftp://user:pass@127.0.0.1:{port}/file.txt"))),
        )
        .unwrap();
        let mut sink = CollectSink::default();
        perform_guarded(&mut e, &mut sink).await;

        assert_eq!(sink.body, b"ftp file contents\n");
    }

    #[cfg(feature = "ftp")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_ftp_lists_directory() {
        // A directory URL (trailing slash) triggers a LIST; the listing body is
        // delivered on the data channel.
        let (port, _up) =
            spawn_loopback_ftp(b"-rw-r--r-- 1 owner group 17 Jan 01 file.txt\r\n").await;
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("ftp://user:pass@127.0.0.1:{port}/"))),
        )
        .unwrap();
        let mut sink = CollectSink::default();
        perform_guarded(&mut e, &mut sink).await;

        assert!(
            sink.body.windows(8).any(|w| w == b"file.txt"),
            "directory listing missing: {:?}",
            String::from_utf8_lossy(&sink.body)
        );
    }

    #[cfg(feature = "ftp")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_ftp_uploads_file_from_source() {
        // CURLOPT_UPLOAD drives a STOR: the read source's bytes must arrive on the
        // server's data channel (the run_upload path).
        let (port, uploaded) = spawn_loopback_ftp(b"").await;
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("ftp://user:pass@127.0.0.1:{port}/upload.txt"))),
        )
        .unwrap();
        e.setopt(CurlOption::CURLOPT_UPLOAD, OptionValue::Long(1))
            .unwrap();
        let payload = b"uploaded payload\n";
        e.setopt(
            CurlOption::CURLOPT_INFILESIZE,
            OptionValue::Long(payload.len() as i64),
        )
        .unwrap();
        let mut sink = CollectSink::default();
        let mut source = SliceSource {
            data: payload.to_vec(),
            pos: 0,
        };
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            e.perform_with(&mut sink, &mut source),
        )
        .await
        .expect("transfer must not hang")
        .expect("upload must succeed");

        let got = uploaded.lock().unwrap().clone();
        assert_eq!(got, payload, "server did not receive the uploaded body");
    }


    // ---- perform_with: end-to-end Gopher over loopback ----------------------

    #[cfg(feature = "gopher")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_gopher_sends_selector_and_reads_body() {
        // Gopher: the client writes a single selector line (CRLF-terminated) then
        // reads the response body, framed by the connection close.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let cap = std::sync::Arc::clone(&captured);
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                // Read the selector line (up to the CRLF the client sends).
                let mut acc = Vec::new();
                let mut buf = [0u8; 256];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            acc.extend_from_slice(&buf[..n]);
                            if acc.contains(&b'\n') {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                if let Ok(mut g) = cap.lock() {
                    *g = acc;
                }
                let _ = sock.write_all(b"gopher menu body\r\n").await;
                let _ = sock.flush().await;
                // Drop sock → EOF frames the body.
            }
        });

        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("gopher://127.0.0.1:{port}/1/welcome"))),
        )
        .unwrap();
        let mut sink = CollectSink::default();
        perform_guarded(&mut e, &mut sink).await;

        assert_eq!(sink.body, b"gopher menu body\r\n");
        // The selector reached the server (curl strips the leading "/1").
        let sel = String::from_utf8_lossy(&captured.lock().unwrap()).to_string();
        assert!(sel.contains("welcome"), "selector not sent: {sel:?}");
    }

    // ---- perform_with: end-to-end RTSP over loopback ------------------------

    /// Spawn a minimal RTSP responder on a loopback port.
    ///
    /// Reads one request head (terminated by the blank `\r\n\r\n`), captures the
    /// raw request bytes, parses the request `CSeq`, and echoes a `200 OK`
    /// response that mirrors that `CSeq` (RTSP mandates the response `CSeq` match
    /// the request). `extra_headers` is appended verbatim after the `CSeq` line.
    /// When `body` is `Some`, a `Content-Length` header frames it; otherwise the
    /// response is header-only. The socket is closed after the reply.
    #[cfg(feature = "rtsp")]
    async fn spawn_loopback_rtsp(
        extra_headers: &'static str,
        body: Option<&'static [u8]>,
    ) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let cap = std::sync::Arc::clone(&captured);
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                // Read the request head up to the terminating blank line.
                let mut head = Vec::new();
                let mut buf = [0u8; 256];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            head.extend_from_slice(&buf[..n]);
                            if head.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                // Parse the request CSeq so the reply can mirror it.
                let head_str = String::from_utf8_lossy(&head);
                let cseq = head_str
                    .lines()
                    .find_map(|l| {
                        let l = l.trim_end();
                        let rest = l.strip_prefix("CSeq:").or_else(|| l.strip_prefix("cseq:"))?;
                        Some(rest.trim().to_string())
                    })
                    .unwrap_or_else(|| "0".to_string());
                if let Ok(mut g) = cap.lock() {
                    *g = head;
                }
                let mut resp = format!("RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n{extra_headers}");
                match body {
                    Some(b) => {
                        resp.push_str(&format!("Content-Length: {}\r\n\r\n", b.len()));
                        let mut bytes = resp.into_bytes();
                        bytes.extend_from_slice(b);
                        let _ = sock.write_all(&bytes).await;
                    }
                    None => {
                        resp.push_str("\r\n");
                        let _ = sock.write_all(resp.as_bytes()).await;
                    }
                }
                let _ = sock.flush().await;
                // Drop sock → close; harmless once the framed reply is consumed.
            }
        });
        (port, captured)
    }

    #[cfg(feature = "rtsp")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_rtsp_describe_delivers_sdp_body() {
        // DESCRIBE is a body-bearing method: the engine reads the response headers
        // (capturing the CSeq) and then the Content-Length-framed SDP body, which
        // must reach the write sink intact.
        const SDP: &[u8] = b"v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=rtsp-test\r\n";
        let (port, captured) =
            spawn_loopback_rtsp("Content-Type: application/sdp\r\n", Some(SDP)).await;

        let url = format!("rtsp://127.0.0.1:{port}/stream");
        let mut e = Easy::new();
        e.setopt(CurlOption::CURLOPT_URL, OptionValue::Str(Some(url.clone())))
            .unwrap();
        // Select DESCRIBE and target the explicit stream URI (curl's request line).
        e.setopt(CurlOption::CURLOPT_RTSP_REQUEST, OptionValue::Long(2))
            .unwrap();
        e.setopt(
            CurlOption::CURLOPT_RTSP_STREAM_URI,
            OptionValue::Str(Some(url.clone())),
        )
        .unwrap();

        let mut sink = CollectSink::default();
        let mut source = NoSource;
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            e.perform_with(&mut sink, &mut source),
        )
        .await
        .expect("RTSP DESCRIBE must not hang")
        .expect("RTSP DESCRIBE must succeed");

        // The SDP body reached the sink intact.
        assert_eq!(sink.body, SDP, "SDP body not delivered");
        // The request line is a DESCRIBE for the configured stream URI.
        let req = String::from_utf8_lossy(&captured.lock().unwrap()).to_string();
        assert!(
            req.starts_with(&format!("DESCRIBE {url} RTSP/1.0\r\n")),
            "unexpected request line: {req:?}"
        );
        assert!(req.contains("CSeq: 1\r\n"), "missing/incorrect CSeq: {req:?}");
        // The matched response CSeq is surfaced via getinfo.
        assert_eq!(
            e.getinfo(CurlInfo::RtspCseqRecv).unwrap(),
            InfoValue::Long(1)
        );
    }

    #[cfg(feature = "rtsp")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_rtsp_options_reads_response_headers() {
        // OPTIONS is the default request and carries no body in either direction;
        // the engine sends the request and consumes the header-only response,
        // recording the round-tripped CSeq.
        let (port, captured) =
            spawn_loopback_rtsp("Public: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN\r\n", None).await;

        let url = format!("rtsp://127.0.0.1:{port}/stream");
        let mut e = Easy::new();
        e.setopt(CurlOption::CURLOPT_URL, OptionValue::Str(Some(url.clone())))
            .unwrap();
        // OPTIONS (value 1) is also the default, but set it explicitly to exercise
        // the option path.
        e.setopt(CurlOption::CURLOPT_RTSP_REQUEST, OptionValue::Long(1))
            .unwrap();
        e.setopt(
            CurlOption::CURLOPT_RTSP_STREAM_URI,
            OptionValue::Str(Some(url.clone())),
        )
        .unwrap();

        let mut sink = CollectSink::default();
        let mut source = NoSource;
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            e.perform_with(&mut sink, &mut source),
        )
        .await
        .expect("RTSP OPTIONS must not hang")
        .expect("RTSP OPTIONS must succeed");

        // No body for OPTIONS.
        assert!(sink.body.is_empty(), "OPTIONS must not deliver a body");
        let req = String::from_utf8_lossy(&captured.lock().unwrap()).to_string();
        assert!(
            req.starts_with(&format!("OPTIONS {url} RTSP/1.0\r\n")),
            "unexpected request line: {req:?}"
        );
        assert_eq!(
            e.getinfo(CurlInfo::RtspCseqRecv).unwrap(),
            InfoValue::Long(1)
        );
    }


    // ---- perform_with: end-to-end POP3 over loopback ------------------------

    /// Spawn a minimal single-channel POP3 server on loopback.
    ///
    /// It greets, answers `CAPA` with `-ERR` (so the client uses the clear-text
    /// `USER`/`PASS` path), accepts the login, and serves a dot-terminated
    /// multi-line body for `RETR`/`LIST`. Captures every command line received.
    /// Returns the bound port and the captured-command handle. This drives the
    /// real POP3 connect/greeting/CAPA/USER/PASS state machine and the
    /// dot-terminated body reader end-to-end.
    #[cfg(feature = "pop3")]
    async fn spawn_loopback_pop3(
        body: &'static str,
    ) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let cmds = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let cmds_task = std::sync::Arc::clone(&cmds);
        tokio::spawn(async move {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let (rd, mut wr) = sock.into_split();
            let mut lines = BufReader::new(rd).lines();
            let _ = wr.write_all(b"+OK POP3 loopback ready\r\n").await;
            while let Ok(Some(line)) = lines.next_line().await {
                if let Ok(mut g) = cmds_task.lock() {
                    g.push(line.clone());
                }
                let upper = line.trim_end().to_ascii_uppercase();
                let verb = upper.split_whitespace().next().unwrap_or("");
                match verb {
                    // Unrecognised → clear-text USER/PASS path.
                    "CAPA" => {
                        let _ = wr.write_all(b"-ERR unknown command\r\n").await;
                    }
                    "USER" => {
                        let _ = wr.write_all(b"+OK send PASS\r\n").await;
                    }
                    "PASS" => {
                        let _ = wr.write_all(b"+OK logged in\r\n").await;
                    }
                    "STAT" => {
                        let _ = wr.write_all(b"+OK 1 100\r\n").await;
                    }
                    "RETR" => {
                        let _ = wr
                            .write_all(format!("+OK {} octets\r\n", body.len()).as_bytes())
                            .await;
                        let _ = wr.write_all(body.as_bytes()).await;
                        let _ = wr.write_all(b"\r\n.\r\n").await;
                    }
                    "LIST" => {
                        let _ = wr.write_all(b"+OK 1 messages\r\n1 100\r\n.\r\n").await;
                    }
                    "QUIT" => {
                        let _ = wr.write_all(b"+OK bye\r\n").await;
                        break;
                    }
                    _ => {
                        let _ = wr.write_all(b"+OK\r\n").await;
                    }
                }
            }
        });
        (port, cmds)
    }

    #[cfg(feature = "pop3")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_pop3_retrieves_message_body() {
        // `pop3://host/1` issues `RETR 1`; the dot-terminated message body must be
        // delivered to the sink (with the trailing dot terminator removed).
        const MSG: &str = "Subject: hi\r\n\r\nHello mail body";
        let (port, cmds) = spawn_loopback_pop3(MSG).await;
        let mut e = Easy::new();
        // URL-embedded credentials drive the clear-text USER/PASS path.
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("pop3://bob:secret@127.0.0.1:{port}/1"))),
        )
        .unwrap();
        let mut sink = CollectSink::default();
        perform_guarded(&mut e, &mut sink).await;

        let body = String::from_utf8_lossy(&sink.body);
        assert!(body.contains("Hello mail body"), "POP3 body missing: {body:?}");
        // The clear-text login and RETR ran in order over the real socket.
        let seen = cmds.lock().unwrap().clone();
        assert!(seen.iter().any(|c| c.starts_with("USER bob")), "no USER: {seen:?}");
        assert!(seen.iter().any(|c| c.starts_with("PASS secret")), "no PASS: {seen:?}");
        assert!(seen.iter().any(|c| c.starts_with("RETR 1")), "no RETR: {seen:?}");
    }

    #[cfg(feature = "pop3")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_pop3_lists_mailbox() {
        // `pop3://host/` with no message id issues `LIST`, whose dot-terminated
        // listing body is delivered to the sink.
        let (port, cmds) = spawn_loopback_pop3("unused").await;
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("pop3://bob:secret@127.0.0.1:{port}/"))),
        )
        .unwrap();
        let mut sink = CollectSink::default();
        perform_guarded(&mut e, &mut sink).await;

        let body = String::from_utf8_lossy(&sink.body);
        assert!(body.contains("1 100"), "POP3 LIST body missing: {body:?}");
        let seen = cmds.lock().unwrap().clone();
        assert!(seen.iter().any(|c| c.trim_end() == "LIST"), "no LIST: {seen:?}");
    }


    // ---- perform_with: end-to-end IMAP over loopback ------------------------

    /// Spawn a minimal IMAP4rev1 server on loopback that echoes each command's
    /// tag in its tagged completion line.
    ///
    /// It greets, advertises only `IMAP4rev1` on `CAPABILITY` (no `LOGINDISABLED`
    /// and no SASL mechanism → the client uses cleartext `LOGIN`), accepts the
    /// login, `SELECT`s any mailbox, and answers a `UID FETCH … BODY[]` with a
    /// sized literal carrying `body`. Captures every command line received and
    /// returns the bound port plus the capture handle. This drives the real IMAP
    /// connect/CAPABILITY/LOGIN/SELECT/FETCH state machine and the literal-body
    /// reader end-to-end.
    #[cfg(feature = "imap")]
    async fn spawn_loopback_imap(
        body: &'static str,
    ) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let cmds = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let cmds_task = std::sync::Arc::clone(&cmds);
        tokio::spawn(async move {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let (rd, mut wr) = sock.into_split();
            let mut lines = BufReader::new(rd).lines();
            let _ = wr.write_all(b"* OK IMAP4 loopback ready\r\n").await;
            while let Ok(Some(line)) = lines.next_line().await {
                if let Ok(mut g) = cmds_task.lock() {
                    g.push(line.clone());
                }
                let mut parts = line.split_whitespace();
                let tag = parts.next().unwrap_or("*").to_string();
                let mut verb = parts.next().unwrap_or("").to_ascii_uppercase();
                // `UID FETCH`/`UID SEARCH` carry the real command in the next word.
                if verb == "UID" {
                    verb = parts.next().unwrap_or("").to_ascii_uppercase();
                }
                match verb.as_str() {
                    "CAPABILITY" => {
                        let _ = wr.write_all(b"* CAPABILITY IMAP4rev1\r\n").await;
                        let _ = wr
                            .write_all(format!("{tag} OK CAPABILITY completed\r\n").as_bytes())
                            .await;
                    }
                    "LOGIN" => {
                        let _ = wr
                            .write_all(format!("{tag} OK LOGIN completed\r\n").as_bytes())
                            .await;
                    }
                    "SELECT" => {
                        let _ = wr.write_all(b"* 1 EXISTS\r\n").await;
                        let _ = wr.write_all(b"* OK [UIDVALIDITY 1] ok\r\n").await;
                        let _ = wr
                            .write_all(
                                format!("{tag} OK [READ-WRITE] SELECT completed\r\n").as_bytes(),
                            )
                            .await;
                    }
                    "FETCH" => {
                        // Sized-literal body: `{N}` then exactly N bytes.
                        let _ = wr
                            .write_all(
                                format!("* 1 FETCH (BODY[] {{{}}}\r\n", body.len()).as_bytes(),
                            )
                            .await;
                        let _ = wr.write_all(body.as_bytes()).await;
                        let _ = wr.write_all(b")\r\n").await;
                        let _ = wr
                            .write_all(format!("{tag} OK FETCH completed\r\n").as_bytes())
                            .await;
                    }
                    "LOGOUT" => {
                        let _ = wr.write_all(b"* BYE logging out\r\n").await;
                        let _ = wr
                            .write_all(format!("{tag} OK LOGOUT completed\r\n").as_bytes())
                            .await;
                        break;
                    }
                    _ => {
                        let _ = wr.write_all(format!("{tag} OK\r\n").as_bytes()).await;
                    }
                }
            }
        });
        (port, cmds)
    }

    #[cfg(feature = "imap")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_imap_fetches_message_literal_body() {
        // `imap://user:pass@host/INBOX;UID=1` SELECTs INBOX then `UID FETCH 1
        // BODY[]`; the sized literal body must be delivered to the sink intact.
        const MSG: &str = "From: a@b\r\nSubject: hi\r\n\r\nimap body!";
        let (port, cmds) = spawn_loopback_imap(MSG).await;
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!(
                "imap://bob:secret@127.0.0.1:{port}/INBOX;UID=1"
            ))),
        )
        .unwrap();
        let mut sink = CollectSink::default();
        perform_guarded(&mut e, &mut sink).await;

        let got = String::from_utf8_lossy(&sink.body);
        assert!(got.contains("imap body!"), "IMAP literal body missing: {got:?}");
        // The cleartext login, SELECT, and UID FETCH ran in order over the socket.
        let seen = cmds.lock().unwrap().clone();
        assert!(
            seen.iter().any(|c| c.contains("LOGIN bob secret")),
            "no cleartext LOGIN: {seen:?}"
        );
        assert!(
            seen.iter().any(|c| c.contains("SELECT INBOX")),
            "no SELECT: {seen:?}"
        );
        assert!(
            seen.iter().any(|c| c.contains("UID FETCH 1 BODY[]")),
            "no UID FETCH: {seen:?}"
        );
    }


    // ---- perform_with: end-to-end SMTP over loopback ------------------------

    /// Spawn a minimal ESMTP server on loopback.
    ///
    /// It greets, answers `EHLO` with a multi-line `250` (no `AUTH`, so the
    /// client — given no credentials — skips authentication), accepts
    /// `MAIL FROM`/`RCPT TO`, returns `354` to `DATA`, reads the message until the
    /// `<CRLF>.<CRLF>` terminator (capturing the body lines), and acknowledges.
    /// Returns the bound port and the captured-message handle. This drives the
    /// real SMTP connect/EHLO/MAIL/RCPT/DATA upload state machine end-to-end.
    #[cfg(feature = "smtp")]
    async fn spawn_loopback_smtp() -> (u16, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let message = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let msg_task = std::sync::Arc::clone(&message);
        tokio::spawn(async move {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let (rd, mut wr) = sock.into_split();
            let mut lines = BufReader::new(rd).lines();
            let _ = wr.write_all(b"220 loopback SMTP ready\r\n").await;
            let mut in_data = false;
            while let Ok(Some(line)) = lines.next_line().await {
                if in_data {
                    // The lone "." line terminates the DATA payload.
                    if line == "." {
                        in_data = false;
                        let _ = wr.write_all(b"250 2.0.0 OK queued\r\n").await;
                        continue;
                    }
                    if let Ok(mut g) = msg_task.lock() {
                        g.extend_from_slice(line.as_bytes());
                        g.extend_from_slice(b"\r\n");
                    }
                    continue;
                }
                let upper = line.trim_end().to_ascii_uppercase();
                let verb = upper.split_whitespace().next().unwrap_or("");
                match verb {
                    "EHLO" => {
                        let _ = wr.write_all(b"250-loopback at your service\r\n").await;
                        let _ = wr.write_all(b"250 SIZE 1048576\r\n").await;
                    }
                    "HELO" => {
                        let _ = wr.write_all(b"250 loopback\r\n").await;
                    }
                    "MAIL" => {
                        let _ = wr.write_all(b"250 2.1.0 sender OK\r\n").await;
                    }
                    "RCPT" => {
                        let _ = wr.write_all(b"250 2.1.5 recipient OK\r\n").await;
                    }
                    "DATA" => {
                        let _ = wr
                            .write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                            .await;
                        in_data = true;
                    }
                    "QUIT" => {
                        let _ = wr.write_all(b"221 2.0.0 bye\r\n").await;
                        break;
                    }
                    _ => {
                        let _ = wr.write_all(b"250 OK\r\n").await;
                    }
                }
            }
        });
        (port, message)
    }

    #[cfg(feature = "smtp")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_smtp_sends_message_envelope_and_body() {
        // A full SMTP submit: EHLO → MAIL FROM → RCPT TO → DATA → message body.
        // The uploaded message must arrive on the server's DATA channel.
        const MSG: &[u8] = b"From: sender@example.com\r\n\
                             To: rcpt@example.com\r\n\
                             Subject: loopback test\r\n\
                             \r\n\
                             Hello SMTP body line\r\n";
        let (port, message) = spawn_loopback_smtp().await;
        let mut rcpts = crate::slist::SList::default();
        rcpts.append("<rcpt@example.com>").unwrap();
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("smtp://127.0.0.1:{port}/"))),
        )
        .unwrap();
        e.setopt(
            CurlOption::CURLOPT_MAIL_FROM,
            OptionValue::Str(Some("<sender@example.com>".to_string())),
        )
        .unwrap();
        e.setopt(CurlOption::CURLOPT_MAIL_RCPT, OptionValue::Slist(Some(rcpts)))
            .unwrap();
        e.setopt(CurlOption::CURLOPT_UPLOAD, OptionValue::Long(1))
            .unwrap();
        e.setopt(
            CurlOption::CURLOPT_INFILESIZE,
            OptionValue::Long(MSG.len() as i64),
        )
        .unwrap();
        let mut sink = CollectSink::default();
        let mut source = SliceSource {
            data: MSG.to_vec(),
            pos: 0,
        };
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            e.perform_with(&mut sink, &mut source),
        )
        .await
        .expect("SMTP submit must not hang")
        .expect("SMTP submit must succeed");

        // The server received the message body via DATA.
        let got = String::from_utf8_lossy(&message.lock().unwrap()).to_string();
        assert!(
            got.contains("Hello SMTP body line"),
            "SMTP body not received by server: {got:?}"
        );
        assert!(
            got.contains("Subject: loopback test"),
            "SMTP headers not received: {got:?}"
        );
    }

    // ---- perform_with: HTTP redirect following + POST body ------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_http_follows_redirect_and_discards_intermediate_body() {
        // CURLOPT_FOLLOWLOCATION: a 301 with a relative Location is followed to
        // the final 200 over a fresh connection. The intermediate 3xx body must
        // be discarded (it must never leak into the application sink); only the
        // final body is delivered — the redirect-final-body contract (Issue #4).
        let (port, cap) = spawn_loopback_http(vec![
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: /final\r\nContent-Length: 17\r\nConnection: close\r\n\r\nintermediate body".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nfinal body!".to_vec(),
        ])
        .await;
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("http://127.0.0.1:{port}/start"))),
        )
        .unwrap();
        e.setopt(CurlOption::CURLOPT_FOLLOWLOCATION, OptionValue::Long(1))
            .unwrap();
        let mut sink = CollectSink::default();
        perform_guarded(&mut e, &mut sink).await;

        // Only the final body reaches the sink; the 301 body is suppressed.
        assert_eq!(sink.body, b"final body!", "final redirected body wrong");
        assert!(
            !sink
                .body
                .windows("intermediate".len())
                .any(|w| w == b"intermediate"),
            "intermediate 3xx body leaked into sink: {:?}",
            String::from_utf8_lossy(&sink.body)
        );
        // The engine reports the final 200 and a single redirect hop.
        assert_eq!(
            e.getinfo(CurlInfo::ResponseCode).unwrap(),
            InfoValue::Long(200)
        );
        assert_eq!(
            e.getinfo(CurlInfo::RedirectCount).unwrap(),
            InfoValue::Long(1)
        );
        // The effective URL is the followed target.
        match e.getinfo(CurlInfo::EffectiveUrl).unwrap() {
            InfoValue::Str(Some(s)) => assert!(
                s.to_bytes().ends_with(b"/final"),
                "effective URL not the redirect target: {s:?}"
            ),
            other => panic!("unexpected effective URL info: {other:?}"),
        }
        // The second request went to the resolved relative target.
        let reqs = cap.lock().unwrap();
        assert_eq!(
            reqs.len(),
            2,
            "expected exactly two requests (original + follow)"
        );
        let second = String::from_utf8_lossy(&reqs[1]);
        assert!(
            second.starts_with("GET /final HTTP/1.1\r\n"),
            "follow-up request not GET /final: {second:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_http_post_copypostfields_sends_body() {
        // CURLOPT_COPYPOSTFIELDS selects POST and streams an owned body with a
        // computed Content-Length; the server must observe the POST request line
        // and the exact body bytes.
        const BODY: &[u8] = b"field=value&n=42";
        let (port, cap) = spawn_loopback_http(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
        ])
        .await;
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("http://127.0.0.1:{port}/submit"))),
        )
        .unwrap();
        e.setopt(
            CurlOption::CURLOPT_COPYPOSTFIELDS,
            OptionValue::Bytes(Some(BODY.to_vec())),
        )
        .unwrap();
        let mut sink = CollectSink::default();
        perform_guarded(&mut e, &mut sink).await;

        assert_eq!(sink.body, b"ok");
        let reqs = cap.lock().unwrap();
        let req = String::from_utf8_lossy(&reqs[0]);
        assert!(
            req.starts_with("POST /submit HTTP/1.1\r\n"),
            "expected POST request line: {req:?}"
        );
        assert!(
            req.to_ascii_lowercase().contains("content-length: 16\r\n"),
            "expected computed Content-Length for the POST body: {req:?}"
        );
        assert!(
            req.ends_with("field=value&n=42"),
            "POST body missing from request: {req:?}"
        );
    }

    // ---- perform_with: FTP append upload (APPE) -----------------------------

    #[cfg(feature = "ftp")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_with_ftp_append_upload_sends_body() {
        // CURLOPT_APPEND issues APPE instead of STOR; the uploaded payload must
        // still reach the data channel intact.
        const PAYLOAD: &[u8] = b"appended ftp payload\n";
        let (port, up) = spawn_loopback_ftp(b"").await;
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("ftp://user:pass@127.0.0.1:{port}/out.txt"))),
        )
        .unwrap();
        e.setopt(CurlOption::CURLOPT_UPLOAD, OptionValue::Long(1))
            .unwrap();
        e.setopt(CurlOption::CURLOPT_APPEND, OptionValue::Long(1))
            .unwrap();
        e.setopt(
            CurlOption::CURLOPT_INFILESIZE,
            OptionValue::Long(PAYLOAD.len() as i64),
        )
        .unwrap();
        let mut sink = CollectSink::default();
        let mut source = SliceSource {
            data: PAYLOAD.to_vec(),
            pos: 0,
        };
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            e.perform_with(&mut sink, &mut source),
        )
        .await
        .expect("FTP append must not hang")
        .expect("FTP append must succeed");

        assert_eq!(
            &*up.lock().unwrap(),
            PAYLOAD,
            "server did not receive the appended FTP body"
        );
    }







}
