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

use crate::error::{CurlError, Result};
use crate::getinfo::{self, CurlInfo, Info, InfoValue};
use crate::headers::HeaderCollector;
use crate::options::CurlOption;
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
#[derive(Debug)]
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
        }
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
        }
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
            mimepost: CDataPtr::NULL,
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
        let mut sink = DefaultClientOutput::new(self.set.include_header);
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
/// body bytes are written to `stdout`, and header bytes are delivered to the
/// same output only when `CURLOPT_HEADER` is set (curl writes headers to the
/// body output in that case). Used by [`Easy::perform`] when no front-end sink
/// is supplied.
struct DefaultClientOutput {
    /// `CURLOPT_HEADER`: whether header bytes are written alongside the body.
    include_header: bool,
}

impl DefaultClientOutput {
    /// Build the default output sink, honoring the handle's `CURLOPT_HEADER`.
    fn new(include_header: bool) -> Self {
        Self { include_header }
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

    fn write_header(&mut self, data: &[u8]) -> Option<usize> {
        if !self.include_header {
            // No header sink configured: curl silently consumes header bytes
            // (`cw_get_writefunc` yields a NULL callback).
            return None;
        }
        use std::io::Write;
        match std::io::stdout().write_all(data) {
            Ok(()) => Some(data.len()),
            Err(_) => Some(0),
        }
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
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some("http://example.com/".to_string())),
        )
        .unwrap();

        // No protocol handler in this layer: the transfer cannot proceed, but the
        // preflight must have populated the effective URL / scheme first.
        assert_eq!(
            e.perform().await.unwrap_err(),
            CurlError::UnsupportedProtocol
        );

        match e.getinfo(CurlInfo::EffectiveUrl).unwrap() {
            InfoValue::Str(Some(s)) => {
                assert!(s.to_str().unwrap().starts_with("http://example.com"));
            }
            other => panic!("expected effective-url string, got {other:?}"),
        }
        match e.getinfo(CurlInfo::Scheme).unwrap() {
            InfoValue::Str(Some(s)) => assert_eq!(s.to_str().unwrap(), "HTTP"),
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
        // A recognized network scheme whose end-to-end drive is not yet wired
        // still reports UnsupportedProtocol (the keystone-remaining path).
        let mut e = Easy::new();
        e.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some("http://example.com/".to_string())),
        )
        .unwrap();

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
}
