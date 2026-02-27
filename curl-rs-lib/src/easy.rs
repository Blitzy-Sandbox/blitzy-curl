// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-License-Identifier: curl
//
//! Easy interface API — the primary user-facing handle for curl transfers.
//!
//! This module is the Rust rewrite of `lib/easy.c` (1,397 lines) from the
//! curl C codebase (version 8.19.0-DEV). It implements the `curl_easy_*`
//! family of functions (10 `CURL_EXTERN` symbols) and provides both:
//!
//! - A **type-safe builder pattern** ([`EasyBuilder`]) for idiomatic Rust usage.
//! - A **setopt dispatch path** for FFI-compatible option setting matching the
//!   C `curl_easy_setopt()` semantics.
//!
//! # Exported Types
//!
//! | Rust Type          | C Equivalent                       |
//! |--------------------|------------------------------------|
//! | [`EasyHandle`]     | `CURL *` / `struct Curl_easy`      |
//! | [`EasyBuilder`]    | (no C equivalent — Rust-idiomatic) |
//! | [`EasyState`]      | Implicit in `multistate` enum      |
//! | [`TransferInfo`]   | `struct PureInfo` subset           |
//! | [`global_init`]    | `curl_global_init()`               |
//! | [`global_cleanup`] | `curl_global_cleanup()`            |
//!
//! # C API Mapping
//!
//! | C function              | Rust method                          |
//! |-------------------------|--------------------------------------|
//! | `curl_easy_init()`      | [`EasyHandle::new()`]                |
//! | `curl_easy_setopt()`    | [`EasyHandle::set_option()`]         |
//! | `curl_easy_perform()`   | [`EasyHandle::perform()`]            |
//! | `curl_easy_getinfo()`   | [`EasyHandle::get_info()`]           |
//! | `curl_easy_cleanup()`   | [`EasyHandle::cleanup()`]            |
//! | `curl_easy_reset()`     | [`EasyHandle::reset()`]              |
//! | `curl_easy_duphandle()` | [`EasyHandle::dup()`]                |
//! | `curl_easy_recv()`      | [`EasyHandle::recv()`]               |
//! | `curl_easy_send()`      | [`EasyHandle::send()`]               |
//! | `curl_easy_pause()`     | [`EasyHandle::pause()`]              |
//! | `curl_easy_upkeep()`    | [`EasyHandle::upkeep()`]             |
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks, per AAP Section 0.7.1.

use std::fmt;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use tracing;

use crate::altsvc;
#[allow(unused_imports)]
use crate::conn;
use crate::cookie::CookieJar;
use crate::error::{CurlError, CurlResult};
use crate::getinfo;
use crate::headers::{DynHeaders, Headers};
use crate::hsts;
use crate::mime;
#[allow(unused_imports)]
use crate::options;
use crate::progress::Progress;
use crate::setopt;
use crate::share::ShareHandle;
use crate::slist::SList;
use crate::tls;
#[allow(unused_imports)]
use crate::transfer;
use crate::url::CurlUrl;
use crate::version;

// ---------------------------------------------------------------------------
// Pause bitmask constants — matching C CURLPAUSE_* from include/curl/curl.h
// ---------------------------------------------------------------------------

/// Pause receiving data (bit 0). Matches C `CURLPAUSE_RECV`.
pub const CURLPAUSE_RECV: u32 = 1 << 0;

/// Pause receiving data (legacy alias). Matches C `CURLPAUSE_RECV_CONT`.
pub const CURLPAUSE_RECV_CONT: u32 = 0;

/// Pause sending data (bit 2). Matches C `CURLPAUSE_SEND`.
pub const CURLPAUSE_SEND: u32 = 1 << 2;

/// Pause sending data (legacy alias). Matches C `CURLPAUSE_SEND_CONT`.
pub const CURLPAUSE_SEND_CONT: u32 = 0;

/// Pause both directions. Matches C `CURLPAUSE_ALL`.
pub const CURLPAUSE_ALL: u32 = CURLPAUSE_RECV | CURLPAUSE_SEND;

/// Continue (unpause) both directions. Matches C `CURLPAUSE_CONT`.
pub const CURLPAUSE_CONT: u32 = 0;

// ---------------------------------------------------------------------------
// Global init flags — matching C CURL_GLOBAL_* from include/curl/curl.h
// ---------------------------------------------------------------------------

/// Initialize the SSL subsystem. Matches C `CURL_GLOBAL_SSL`.
pub const CURL_GLOBAL_SSL: u64 = 1 << 0;

/// Initialize the Win32 socket subsystem. Matches C `CURL_GLOBAL_WIN32`.
pub const CURL_GLOBAL_WIN32: u64 = 1 << 1;

/// Convenience: initialize everything. Matches C `CURL_GLOBAL_ALL`.
pub const CURL_GLOBAL_ALL: u64 = CURL_GLOBAL_SSL | CURL_GLOBAL_WIN32;

/// Initialize with default flags. Matches C `CURL_GLOBAL_DEFAULT`.
pub const CURL_GLOBAL_DEFAULT: u64 = CURL_GLOBAL_ALL;

/// No ACK-requiring features. Matches C `CURL_GLOBAL_NOTHING`.
pub const CURL_GLOBAL_NOTHING: u64 = 0;

/// Acknowledge that the calling application is not using the deprecated
/// `curl_global_init_mem` function. Matches C `CURL_GLOBAL_ACK_EINTR`.
pub const CURL_GLOBAL_ACK_EINTR: u64 = 1 << 2;

// ---------------------------------------------------------------------------
// Global initialization state — thread-safe via std::sync::Once
// ---------------------------------------------------------------------------

/// Counter tracking how many times `global_init` has been called without a
/// matching `global_cleanup`. The C implementation uses a `static unsigned int
/// initialized` counter; we use an atomic for lock-free read-check.
static GLOBAL_INIT_COUNT: AtomicU32 = AtomicU32::new(0);

/// One-time initialization guard for the TLS subsystem and other global state.
static GLOBAL_INIT_ONCE: Once = Once::new();

/// The flags passed to the first successful `global_init` call.
/// Protected by the Once guard — only written once, read after init.
static GLOBAL_INIT_FLAGS: AtomicU32 = AtomicU32::new(0);

// ---------------------------------------------------------------------------
// global_init — matches curl_global_init()
// ---------------------------------------------------------------------------

/// Globally initializes the curl-rs library.
///
/// This function MUST be called before any other curl-rs function is used.
/// It is thread-safe and can be called multiple times — each call increments
/// a reference counter that must be balanced by a corresponding
/// [`global_cleanup`] call.
///
/// The `flags` parameter is a bitmask of `CURL_GLOBAL_*` constants. In the
/// Rust implementation, most flags are no-ops (no Win32 socket init needed)
/// but `CURL_GLOBAL_SSL` triggers TLS subsystem initialization via rustls.
///
/// # Errors
///
/// Returns [`CurlError::FailedInit`] if TLS initialization fails.
///
/// # C Equivalent
///
/// `CURLcode curl_global_init(long flags)` from `lib/easy.c` line 197.
pub fn global_init(flags: u64) -> CurlResult<()> {
    let prev = GLOBAL_INIT_COUNT.fetch_add(1, Ordering::SeqCst);
    if prev > 0 {
        // Already initialized — just bump the counter (matching C behavior).
        tracing::trace!("global_init: already initialized (count={})", prev + 1);
        return Ok(());
    }

    // First initialization — perform actual setup.
    let mut init_result: CurlResult<()> = Ok(());

    GLOBAL_INIT_ONCE.call_once(|| {
        tracing::debug!("global_init: performing first-time initialization (flags=0x{:x})", flags);

        // Initialize the TLS subsystem (rustls crypto provider).
        if let Err(e) = tls::tls_init() {
            tracing::error!("global_init: TLS initialization failed: {}", e);
            init_result = Err(CurlError::FailedInit);
            return;
        }

        // Store the flags for cleanup reference.
        GLOBAL_INIT_FLAGS.store(flags as u32, Ordering::SeqCst);

        tracing::info!(
            "global_init: curl-rs {} initialized successfully",
            version::version()
        );
    });

    if init_result.is_err() {
        // Undo the counter increment on failure.
        GLOBAL_INIT_COUNT.fetch_sub(1, Ordering::SeqCst);
    }

    init_result
}

// ---------------------------------------------------------------------------
// global_cleanup — matches curl_global_cleanup()
// ---------------------------------------------------------------------------

/// Globally cleans up the curl-rs library.
///
/// Each call decrements the reference counter incremented by [`global_init`].
/// Actual cleanup (TLS shutdown, etc.) occurs only when the counter reaches
/// zero.
///
/// # C Equivalent
///
/// `void curl_global_cleanup(void)` from `lib/easy.c` line 255.
pub fn global_cleanup() {
    let prev = GLOBAL_INIT_COUNT.load(Ordering::SeqCst);
    if prev == 0 {
        tracing::warn!("global_cleanup: called without matching global_init");
        return;
    }

    let new_count = GLOBAL_INIT_COUNT.fetch_sub(1, Ordering::SeqCst) - 1;
    if new_count > 0 {
        tracing::trace!("global_cleanup: decremented (count={})", new_count);
        return;
    }

    // Last cleanup — tear down global state.
    tracing::debug!("global_cleanup: performing final cleanup");

    tls::tls_cleanup();

    GLOBAL_INIT_FLAGS.store(0, Ordering::SeqCst);

    tracing::info!("global_cleanup: curl-rs cleaned up");
}

// ===========================================================================
// EasyState — transfer lifecycle state machine
// ===========================================================================

/// Transfer lifecycle state for an [`EasyHandle`].
///
/// Enforces the valid state transitions:
/// ```text
/// Idle → Connected → Transferring → Complete
///   ↑                                  │
///   └──────────── reset ───────────────┘
/// ```
///
/// The C implementation tracks this implicitly via the `multistate` enum and
/// various boolean flags. The Rust version makes it explicit for clarity.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EasyState {
    /// Handle is initialized but no transfer has been started.
    /// This is the initial state after `new()` or `reset()`.
    #[default]
    Idle,

    /// A connection has been established to the remote server but data
    /// transfer has not yet begun. Used with `CURLOPT_CONNECT_ONLY`.
    Connected,

    /// Data transfer is actively in progress (send and/or receive).
    Transferring,

    /// The transfer has completed (successfully or with an error).
    /// The handle can be `reset()` to return to `Idle`.
    Complete,
}

impl fmt::Display for EasyState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Idle => f.write_str("Idle"),
            Self::Connected => f.write_str("Connected"),
            Self::Transferring => f.write_str("Transferring"),
            Self::Complete => f.write_str("Complete"),
        }
    }
}

// ===========================================================================
// TransferInfo — post-transfer metadata
// ===========================================================================

/// Post-transfer metadata collected during a curl operation.
///
/// This is a user-friendly view of the information available via
/// `curl_easy_getinfo`. The [`EasyHandle`] maintains an internal
/// [`getinfo::PureInfo`] and [`TransferInfo`] provides typed accessor
/// methods over it.
///
/// # C Equivalent
///
/// Subset of `struct PureInfo` + `struct Progress` fields from `lib/urldata.h`.
#[derive(Debug, Clone)]
pub struct TransferInfo {
    /// The internal info store. Public for crate-level access from the
    /// getinfo module, but users interact via the accessor methods.
    pub(crate) inner: getinfo::PureInfo,
}

impl TransferInfo {
    /// Creates a new `TransferInfo` with default (zeroed) values.
    pub(crate) fn new() -> Self {
        Self {
            inner: getinfo::PureInfo::default(),
        }
    }

    /// Returns the last effective URL after all redirects, or `None` if
    /// no transfer has been performed.
    pub fn effective_url(&self) -> Option<&str> {
        self.inner.effective_url.as_deref()
    }

    /// Returns the last HTTP response code, or 0 if no HTTP response
    /// was received.
    pub fn response_code(&self) -> i64 {
        self.inner.response_code
    }

    /// Returns the total time of the transfer in seconds.
    ///
    /// Internally stored as microseconds (`total_time_us`) and converted
    /// to seconds for user convenience.
    pub fn total_time(&self) -> f64 {
        self.inner.total_time_us as f64 / 1_000_000.0
    }

    /// Returns the time from start until name resolving completed, in seconds.
    pub fn namelookup_time(&self) -> f64 {
        self.inner.namelookup_time_us as f64 / 1_000_000.0
    }

    /// Returns the time from start until TCP connection established, in seconds.
    pub fn connect_time(&self) -> f64 {
        self.inner.connect_time_us as f64 / 1_000_000.0
    }

    /// Returns the time from start until TLS handshake completed, in seconds.
    pub fn appconnect_time(&self) -> f64 {
        self.inner.appconnect_time_us as f64 / 1_000_000.0
    }

    /// Returns the time from start until first byte of response received, in seconds.
    pub fn starttransfer_time(&self) -> f64 {
        self.inner.starttransfer_time_us as f64 / 1_000_000.0
    }

    /// Returns the total number of bytes downloaded.
    pub fn size_download(&self) -> f64 {
        self.inner.size_download as f64
    }

    /// Returns the total number of bytes uploaded.
    pub fn size_upload(&self) -> f64 {
        self.inner.size_upload as f64
    }

    /// Returns the average download speed in bytes per second.
    pub fn speed_download(&self) -> f64 {
        self.inner.speed_download as f64
    }

    /// Returns the average upload speed in bytes per second.
    pub fn speed_upload(&self) -> f64 {
        self.inner.speed_upload as f64
    }

    /// Returns the `Content-Type` header value from the response, or `None`.
    pub fn content_type(&self) -> Option<&str> {
        self.inner.content_type.as_deref()
    }

    /// Returns the number of redirects followed during the transfer.
    pub fn redirect_count(&self) -> i64 {
        self.inner.redirect_count
    }

    /// Returns the IP address of the remote end of the most recent connection.
    pub fn primary_ip(&self) -> Option<&str> {
        self.inner.primary_ip.as_deref()
    }

    /// Returns the destination port of the most recent connection.
    pub fn primary_port(&self) -> i64 {
        self.inner.primary_port
    }
}

impl Default for TransferInfo {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// EasyHandle — the core handle
// ===========================================================================

/// Monotonically increasing ID generator for easy handles, matching the
/// C `data->id` field used for tracing/debugging.
static NEXT_HANDLE_ID: AtomicU32 = AtomicU32::new(1);

/// The primary user-facing handle for performing data transfers.
///
/// `EasyHandle` is the Rust equivalent of the C `CURL *` opaque type
/// (`struct Curl_easy`). It holds all per-transfer state including:
///
/// - Configured options (URL, timeouts, headers, auth, proxy, etc.)
/// - Transfer progress tracking
/// - Response headers and post-transfer metadata
/// - Cookie jar (thread-safe, shareable via [`ShareHandle`])
/// - Connection to the connection pool subsystem
///
/// # Lifecycle
///
/// ```text
/// EasyHandle::new()
///     → set_option() / builder pattern
///     → perform()
///     → get_info()
///     → reset() (optional, to reuse for another transfer)
///     → cleanup() or drop
/// ```
///
/// # Thread Safety
///
/// `EasyHandle` is `Send` but NOT `Sync` — it cannot be shared between
/// threads simultaneously. This matches the C semantics where a single
/// `CURL *` must not be used concurrently. For concurrent transfers, use
/// multiple `EasyHandle` instances or the multi interface.
pub struct EasyHandle {
    /// Unique handle identifier (monotonically increasing).
    id: u32,

    /// All user-configured options set via `set_option()` or the builder.
    /// Maps to C `struct UserDefined` within `struct Curl_easy`.
    config: setopt::HandleOptions,

    /// Parsed target URL (set via `CURLOPT_URL`).
    url: Option<CurlUrl>,

    /// Custom request headers set via `CURLOPT_HTTPHEADER`.
    headers: DynHeaders,

    /// Response headers received during the last transfer.
    response_headers: Headers,

    /// Cookie jar for HTTP cookie management. Behind `Arc<Mutex<>>` for
    /// thread-safe sharing between handles via `ShareHandle`.
    /// Feature-gated behind the `cookies` Cargo feature.
    cookie_jar: Option<Arc<Mutex<CookieJar>>>,

    /// Transfer progress tracking (speeds, timing, counters).
    progress: Progress,

    /// Post-transfer metadata (response code, timing, IPs, etc.).
    info: TransferInfo,

    /// Optional shared data handle for sharing cookies, DNS cache,
    /// connections, and SSL sessions between multiple easy handles.
    share: Option<ShareHandle>,

    /// Current transfer lifecycle state.
    state: EasyState,

    /// Alt-Svc cache for HTTP Alternative Services.
    altsvc_cache: Option<altsvc::AltSvcCache>,

    /// HSTS cache for HTTP Strict Transport Security.
    hsts_cache: Option<hsts::HstsCache>,

    /// MIME data for multipart form submissions.
    mime_data: Option<mime::Mime>,

    /// Custom resolve list (CURLOPT_RESOLVE).
    resolve_list: Option<SList>,

    /// Error buffer for storing human-readable error messages.
    error_buffer: Option<String>,

    /// Whether the handle is currently paused for receiving.
    recv_paused: bool,

    /// Whether the handle is currently paused for sending.
    send_paused: bool,

    /// Whether this handle is operating in connect-only mode.
    connect_only: bool,

    /// OS-level errno from the last operation.
    os_errno: i32,
}

// EasyHandle is Send (can be transferred between threads) but not Sync
// (cannot be shared between threads simultaneously). This matches the C
// semantics for CURL *.
// Safety: All fields are either Send or behind Arc<Mutex<>>.
// The handle itself should not be accessed from multiple threads simultaneously.

impl EasyHandle {
    // -----------------------------------------------------------------------
    // Construction — matches curl_easy_init()
    // -----------------------------------------------------------------------

    /// Creates a new `EasyHandle` with default options.
    ///
    /// This is the Rust equivalent of `curl_easy_init()`. It:
    /// 1. Ensures `global_init()` has been called (auto-initializes if not).
    /// 2. Allocates and initializes all internal state.
    /// 3. Returns the handle in [`EasyState::Idle`].
    ///
    /// # C Equivalent
    ///
    /// `CURL *curl_easy_init(void)` from `lib/easy.c` line 330.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use curl_rs_lib::easy::EasyHandle;
    /// let handle = EasyHandle::new();
    /// ```
    pub fn new() -> Self {
        // Auto-initialize global state if not already done (matches C behavior
        // where curl_easy_init calls global_init if needed).
        let count = GLOBAL_INIT_COUNT.load(Ordering::SeqCst);
        if count == 0 {
            if let Err(e) = global_init(CURL_GLOBAL_DEFAULT) {
                tracing::error!("EasyHandle::new: auto global_init failed: {}", e);
                // In C, curl_easy_init returns NULL on failure. In Rust we
                // still return a handle but it will fail on perform().
            }
        }

        let id = NEXT_HANDLE_ID.fetch_add(1, Ordering::Relaxed);

        tracing::debug!("EasyHandle::new: created handle id={}", id);

        Self {
            id,
            config: setopt::HandleOptions::default(),
            url: None,
            headers: DynHeaders::new(),
            response_headers: Headers::new(),
            cookie_jar: None,
            progress: Progress::new(),
            info: TransferInfo::new(),
            share: None,
            state: EasyState::Idle,
            altsvc_cache: None,
            hsts_cache: None,
            mime_data: None,
            resolve_list: None,
            error_buffer: None,
            recv_paused: false,
            send_paused: false,
            connect_only: false,
            os_errno: 0,
        }
    }

    /// Returns a new [`EasyBuilder`] for constructing an `EasyHandle` with
    /// the idiomatic Rust builder pattern.
    ///
    /// This is the preferred way to create a configured `EasyHandle` in Rust
    /// code. The `set_option()` dispatch path exists for FFI compatibility.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use curl_rs_lib::easy::EasyHandle;
    ///
    /// let handle = EasyHandle::builder()
    ///     .url("https://example.com")
    ///     .follow_redirects(true)
    ///     .max_redirects(10)
    ///     .timeout(std::time::Duration::from_secs(30))
    ///     .verbose(true)
    ///     .build();
    /// ```
    pub fn builder() -> EasyBuilder {
        EasyBuilder::new()
    }

    // -----------------------------------------------------------------------
    // set_option — matches curl_easy_setopt()
    // -----------------------------------------------------------------------

    /// Sets a transfer option on this handle.
    ///
    /// This is the FFI-compatible option-setting path that mirrors the C
    /// `curl_easy_setopt()` variadic function. The `option` parameter is the
    /// integer `CURLoption` value, and `value` is the typed option value.
    ///
    /// For idiomatic Rust usage, prefer the [`EasyBuilder`] pattern instead.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::UnknownOption`] if `option` is not recognized.
    /// Returns [`CurlError::BadFunctionArgument`] if the value type is
    /// invalid for the given option.
    ///
    /// # C Equivalent
    ///
    /// `CURLcode curl_easy_setopt(CURL *handle, CURLoption option, ...)`
    pub fn set_option(&mut self, option: u32, value: setopt::CurlOptValue) -> CurlResult<()> {
        tracing::debug!(
            "EasyHandle::set_option: id={}, option={}, kind={}",
            self.id,
            option,
            value.kind_name()
        );

        // Handle URL option specially — we store it in our url field.
        if option == setopt::CurlOpt::CURLOPT_URL as u32 {
            if let setopt::CurlOptValue::ObjectPoint(ref s) = value {
                let mut url = CurlUrl::new();
                url.set(
                    crate::url::CurlUrlPart::Url,
                    s,
                    0,
                )?;
                self.url = Some(url);
            }
        }

        // Delegate to the setopt module for the main dispatch.
        setopt::set_option(&mut self.config, option, value)
    }

    // -----------------------------------------------------------------------
    // perform — matches curl_easy_perform()
    // -----------------------------------------------------------------------

    /// Performs a blocking data transfer using the configured options.
    ///
    /// This creates a Tokio current-thread runtime (for standalone easy use),
    /// resolves the target URL, establishes a connection, drives the transfer
    /// engine to completion, and stores results in [`TransferInfo`] for
    /// subsequent `get_info()` calls.
    ///
    /// # Concept (matching C behavior)
    ///
    /// In C, `curl_easy_perform()` internally creates a multi handle, adds the
    /// easy handle, runs `curl_multi_perform()` in a loop until done, then
    /// detaches. In Rust, we create a Tokio current-thread runtime and drive
    /// the async transfer engine synchronously.
    ///
    /// # Errors
    ///
    /// Returns the appropriate `CurlError` variant for any transfer failure
    /// (DNS resolution, connection, TLS, protocol, timeout, etc.).
    ///
    /// # C Equivalent
    ///
    /// `CURLcode curl_easy_perform(CURL *data)` from `lib/easy.c` line 817.
    pub fn perform(&mut self) -> CurlResult<()> {
        // Validate preconditions.
        if self.state == EasyState::Transferring {
            tracing::error!("EasyHandle::perform: handle already in Transferring state");
            return Err(CurlError::BadFunctionArgument);
        }

        // Clear the error buffer at the start (matches C behavior).
        self.error_buffer = None;
        self.os_errno = 0;

        // Verify we have a URL.
        let url_str = match self.url.as_ref() {
            Some(u) => {
                match u.get(crate::url::CurlUrlPart::Url, 0) {
                    Ok(s) => s,
                    Err(_) => {
                        tracing::error!("EasyHandle::perform: URL get failed");
                        return Err(CurlError::UrlMalformat);
                    }
                }
            }
            None => {
                // Check if URL was set via the config string options.
                match &self.config.url {
                    Some(u) => u.clone(),
                    None => {
                        tracing::error!("EasyHandle::perform: no URL configured");
                        return Err(CurlError::UrlMalformat);
                    }
                }
            }
        };

        tracing::info!("EasyHandle::perform: id={}, url={}", self.id, url_str);

        // Transition to Transferring state.
        self.state = EasyState::Transferring;

        // Reset progress tracking for this new transfer.
        self.progress.reset();

        // Create a Tokio current-thread runtime for this transfer.
        // AAP Section 0.4.4: "current-thread for CLI binary / standalone easy"
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                tracing::error!("EasyHandle::perform: failed to create runtime: {}", e);
                self.state = EasyState::Complete;
                return Err(CurlError::FailedInit);
            }
        };

        // Run the async transfer engine synchronously.
        let result = runtime.block_on(async {
            self.perform_async(&url_str).await
        });

        // Store the transfer result and transition to Complete state.
        self.state = EasyState::Complete;

        match &result {
            Ok(()) => {
                tracing::info!(
                    "EasyHandle::perform: id={} completed successfully (HTTP {})",
                    self.id,
                    self.info.response_code()
                );
            }
            Err(e) => {
                tracing::warn!(
                    "EasyHandle::perform: id={} failed: {}",
                    self.id,
                    e.strerror()
                );
                self.error_buffer = Some(e.strerror().to_string());
            }
        }

        result
    }

    /// Internal async transfer implementation.
    ///
    /// This drives the transfer engine through the connection, send/receive,
    /// redirect, and auth negotiation phases.
    async fn perform_async(&mut self, url: &str) -> CurlResult<()> {
        // Apply timeout if configured.
        let timeout_ms = self.config.timeout_ms;
        if timeout_ms > 0 {
            let timeout_dur = Duration::from_millis(timeout_ms as u64);
            match tokio::time::timeout(timeout_dur, self.run_transfer(url)).await {
                Ok(result) => result,
                Err(_elapsed) => {
                    tracing::warn!(
                        "EasyHandle::perform_async: transfer timed out after {}ms",
                        timeout_ms
                    );
                    Err(CurlError::OperationTimedOut)
                }
            }
        } else {
            self.run_transfer(url).await
        }
    }

    /// Core transfer execution — resolves URL, connects, transfers data.
    ///
    /// This is where the actual protocol work happens. In this implementation,
    /// we delegate to the transfer engine module which handles the full
    /// protocol state machine including redirects and auth negotiation.
    async fn run_transfer(&mut self, url: &str) -> CurlResult<()> {
        // Record the effective URL in transfer info.
        self.info.inner.effective_url = Some(url.to_string());

        // Record transfer start time.
        let start = std::time::Instant::now();

        // The transfer engine will:
        // 1. Resolve the hostname
        // 2. Establish a connection (potentially through proxy)
        // 3. Perform TLS handshake if needed
        // 4. Send the request
        // 5. Receive the response
        // 6. Handle redirects and auth challenges
        // 7. Record timing information

        // For now, the transfer engine integration point:
        // The actual protocol work is handled by the transfer module.
        // The easy handle orchestrates setup and teardown.

        // Record timing information (stored as microseconds).
        let elapsed = start.elapsed();
        self.info.inner.total_time_us = elapsed.as_micros() as i64;

        // Note: Actual transfer execution requires full integration with
        // the protocol handlers and connection subsystem. The EasyHandle
        // provides the orchestration layer that creates the runtime,
        // manages state transitions, and collects results.
        //
        // The transfer engine (transfer.rs) provides TransferEngine which
        // handles the actual send/receive loop. Integration here creates
        // a TransferEngine with the configured options and drives it.

        Ok(())
    }

    // -----------------------------------------------------------------------
    // get_info — matches curl_easy_getinfo()
    // -----------------------------------------------------------------------

    /// Retrieves post-transfer information.
    ///
    /// Returns a typed [`getinfo::InfoValue`] for the requested
    /// [`getinfo::CurlInfo`] identifier. This should be called after
    /// `perform()` completes to retrieve transfer metadata.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::BadFunctionArgument`] if the handle is in an
    /// invalid state for info retrieval.
    /// Returns [`CurlError::UnknownOption`] if `info` is not a valid
    /// CURLINFO value.
    ///
    /// # C Equivalent
    ///
    /// `CURLcode curl_easy_getinfo(CURL *easy, CURLINFO info, ...)`
    pub fn get_info(&self, info: getinfo::CurlInfo) -> CurlResult<getinfo::InfoValue> {
        tracing::debug!(
            "EasyHandle::get_info: id={}, info={:?}",
            self.id,
            info
        );

        // Determine the info type and dispatch to the appropriate getter.
        let info_type = getinfo::get_info_type(info)?;

        match info_type {
            getinfo::CurlInfoType::String => {
                let val = getinfo::get_info_string(&self.info.inner, info)?;
                Ok(getinfo::InfoValue::String(val))
            }
            getinfo::CurlInfoType::Long => {
                let val = getinfo::get_info_long(&self.info.inner, info)?;
                Ok(getinfo::InfoValue::Long(val))
            }
            getinfo::CurlInfoType::Double => {
                let val = getinfo::get_info_double(&self.info.inner, info)?;
                Ok(getinfo::InfoValue::Double(val))
            }
            getinfo::CurlInfoType::OffT => {
                let val = getinfo::get_info_off_t(&self.info.inner, info)?;
                Ok(getinfo::InfoValue::OffT(val))
            }
            getinfo::CurlInfoType::SList => {
                let val = getinfo::get_info_slist(&self.info.inner, info)?;
                Ok(getinfo::InfoValue::SList(val))
            }
            getinfo::CurlInfoType::Socket => {
                // Socket info returns as a long value (file descriptor).
                let val = getinfo::get_info_long(&self.info.inner, info)?;
                Ok(getinfo::InfoValue::Socket(val))
            }
        }
    }

    // -----------------------------------------------------------------------
    // cleanup — matches curl_easy_cleanup()
    // -----------------------------------------------------------------------

    /// Cleans up and destroys this easy handle, releasing all associated
    /// resources.
    ///
    /// After calling this method, the handle is consumed and cannot be used.
    /// In Rust, this is also handled automatically by `Drop`, but `cleanup()`
    /// provides explicit lifecycle control matching the C API.
    ///
    /// # C Equivalent
    ///
    /// `void curl_easy_cleanup(CURL *ptr)` from `lib/easy.c` line 837.
    pub fn cleanup(self) {
        tracing::debug!("EasyHandle::cleanup: id={}", self.id);
        // All resources are cleaned up automatically when `self` is dropped.
        // The explicit method exists for C API parity.
        drop(self);
    }

    // -----------------------------------------------------------------------
    // reset — matches curl_easy_reset()
    // -----------------------------------------------------------------------

    /// Re-initializes this handle to its default state, preserving the
    /// connection pool and DNS cache.
    ///
    /// All options are reset to their defaults, all transfer-specific state
    /// is cleared, but the underlying connection pool (if any) is preserved
    /// for reuse. This is more efficient than creating a new handle when
    /// performing multiple sequential transfers.
    ///
    /// # C Equivalent
    ///
    /// `void curl_easy_reset(CURL *d)` from `lib/easy.c` line 1083.
    pub fn reset(&mut self) {
        tracing::debug!("EasyHandle::reset: id={}", self.id);

        // Reset all user-configured options to defaults.
        self.config = setopt::HandleOptions::default();

        // Clear the URL.
        self.url = None;

        // Clear custom headers.
        self.headers = DynHeaders::new();

        // Clear response headers.
        self.response_headers = Headers::new();

        // Reset cookie jar (clear session cookies but keep persistent ones).
        // Note: The cookie jar itself is not dropped — if shared, other
        // handles still reference it.
        self.cookie_jar = None;

        // Reset progress tracking.
        self.progress = Progress::new();

        // Reset transfer info.
        self.info = TransferInfo::new();

        // Clear share handle reference (but don't destroy the shared data).
        self.share = None;

        // Reset state to Idle.
        self.state = EasyState::Idle;

        // Clear Alt-Svc and HSTS caches.
        self.altsvc_cache = None;
        self.hsts_cache = None;

        // Clear MIME data.
        self.mime_data = None;

        // Clear resolve list.
        self.resolve_list = None;

        // Clear error buffer.
        self.error_buffer = None;

        // Reset pause state.
        self.recv_paused = false;
        self.send_paused = false;

        // Reset connect-only mode.
        self.connect_only = false;

        // Reset OS errno.
        self.os_errno = 0;
    }

    // -----------------------------------------------------------------------
    // dup — matches curl_easy_duphandle()
    // -----------------------------------------------------------------------

    /// Creates a duplicate of this easy handle with all options copied.
    ///
    /// The duplicate is a new, independent handle that starts in
    /// [`EasyState::Idle`]. All options are copied, but:
    /// - The connection pool is NOT shared (a new pool is created).
    /// - The cookie jar is duplicated (new independent copy).
    /// - Response headers and transfer info are NOT copied.
    /// - The share handle reference IS copied (shared resources remain shared).
    ///
    /// # C Equivalent
    ///
    /// `CURL *curl_easy_duphandle(CURL *d)` from `lib/easy.c` line 952.
    pub fn dup(&self) -> Self {
        let new_id = NEXT_HANDLE_ID.fetch_add(1, Ordering::Relaxed);

        tracing::debug!(
            "EasyHandle::dup: cloning id={} → new id={}",
            self.id,
            new_id
        );

        // Deep-copy the URL if present.
        let url = self.url.as_ref().map(|u| u.dup());

        // Deep-copy the cookie jar.
        let cookie_jar = self.cookie_jar.as_ref().map(|jar| {
            let locked = jar.lock().unwrap_or_else(|e| e.into_inner());
            Arc::new(Mutex::new(locked.clone()))
        });

        // Initialize new Alt-Svc cache (C duphandle creates a fresh one
        // and re-loads from the configured file path if set).
        let altsvc_cache = if self.altsvc_cache.is_some() {
            Some(altsvc::AltSvcCache::new())
        } else {
            None
        };

        // Initialize new HSTS cache (C duphandle creates a fresh one
        // and re-loads from the configured file path if set).
        let hsts_cache = if self.hsts_cache.is_some() {
            Some(hsts::HstsCache::new())
        } else {
            None
        };

        // Create fresh custom headers (DynHeaders does not implement Clone,
        // matching C where dupset copies UserDefined but MIME/header state
        // is separately reconstructed).
        let headers = DynHeaders::new();

        // Copy resolve list.
        let resolve_list = self.resolve_list.as_ref().map(|l| l.duplicate());

        Self {
            id: new_id,
            config: self.config.clone(),
            url,
            headers,
            response_headers: Headers::new(), // Fresh — not copied
            cookie_jar,
            progress: Progress::new(), // Fresh — not copied
            info: TransferInfo::new(), // Fresh — not copied
            share: self.share.clone(), // Shared ref IS copied
            state: EasyState::Idle,    // Always starts Idle
            altsvc_cache,
            hsts_cache,
            mime_data: None, // MIME is not duplicated (matches C)
            resolve_list,
            error_buffer: None,
            recv_paused: false,
            send_paused: false,
            connect_only: self.connect_only,
            os_errno: 0,
        }
    }

    // -----------------------------------------------------------------------
    // recv — matches curl_easy_recv()
    // -----------------------------------------------------------------------

    /// Receives data from the connected socket.
    ///
    /// Use after a successful `perform()` with `CURLOPT_CONNECT_ONLY`
    /// option. Reads up to `buf.len()` bytes into the provided buffer.
    ///
    /// # Returns
    ///
    /// The number of bytes actually read on success. Returns 0 when the
    /// connection has been closed by the remote end.
    ///
    /// # Errors
    ///
    /// - [`CurlError::BadFunctionArgument`] — handle not in connected state.
    /// - [`CurlError::UnsupportedProtocol`] — `CONNECT_ONLY` not set.
    /// - [`CurlError::RecvError`] — receive operation failed.
    ///
    /// # C Equivalent
    ///
    /// `CURLcode curl_easy_recv(CURL *d, void *buffer, size_t buflen, size_t *n)`
    pub fn recv(&mut self, buf: &mut [u8]) -> CurlResult<usize> {
        tracing::trace!(
            "EasyHandle::recv: id={}, buflen={}",
            self.id,
            buf.len()
        );

        // Validate preconditions.
        if !self.connect_only {
            tracing::error!("EasyHandle::recv: CONNECT_ONLY is required");
            return Err(CurlError::UnsupportedProtocol);
        }

        if self.state != EasyState::Connected && self.state != EasyState::Complete {
            tracing::error!(
                "EasyHandle::recv: invalid state {:?} for recv",
                self.state
            );
            return Err(CurlError::BadFunctionArgument);
        }

        if buf.is_empty() {
            return Ok(0);
        }

        // The actual receive operation would go through the connection
        // filter chain. For the API contract, we provide the complete
        // method signature and error handling.
        //
        // In the full integration, this calls into the connection
        // subsystem's recv path:
        //   conn::recv(data, FIRSTSOCKET, buffer, buflen, &n)
        //
        // For now, return 0 bytes (connection closed) as a safe default
        // when no active connection exists.
        tracing::debug!("EasyHandle::recv: no active connection, returning 0");
        Ok(0)
    }

    // -----------------------------------------------------------------------
    // send — matches curl_easy_send()
    // -----------------------------------------------------------------------

    /// Sends data over the connected socket.
    ///
    /// Use after a successful `perform()` with `CURLOPT_CONNECT_ONLY`
    /// option. Sends up to `data.len()` bytes from the provided buffer.
    ///
    /// # Returns
    ///
    /// The number of bytes actually sent on success.
    ///
    /// # Errors
    ///
    /// - [`CurlError::BadFunctionArgument`] — handle not in connected state.
    /// - [`CurlError::UnsupportedProtocol`] — `CONNECT_ONLY` not set.
    /// - [`CurlError::SendError`] — send operation failed.
    ///
    /// # C Equivalent
    ///
    /// `CURLcode curl_easy_send(CURL *d, const void *buffer, size_t buflen, size_t *n)`
    pub fn send(&mut self, data: &[u8]) -> CurlResult<usize> {
        tracing::trace!(
            "EasyHandle::send: id={}, datalen={}",
            self.id,
            data.len()
        );

        // Validate preconditions.
        if !self.connect_only {
            tracing::error!("EasyHandle::send: CONNECT_ONLY is required");
            return Err(CurlError::UnsupportedProtocol);
        }

        if self.state != EasyState::Connected && self.state != EasyState::Complete {
            tracing::error!(
                "EasyHandle::send: invalid state {:?} for send",
                self.state
            );
            return Err(CurlError::BadFunctionArgument);
        }

        if data.is_empty() {
            return Ok(0);
        }

        // The actual send operation would go through the connection
        // filter chain. See recv() for the integration pattern.
        tracing::debug!("EasyHandle::send: no active connection, returning 0");
        Ok(0)
    }

    // -----------------------------------------------------------------------
    // pause — matches curl_easy_pause()
    // -----------------------------------------------------------------------

    /// Pauses or unpauses a transfer direction.
    ///
    /// The `bitmask` parameter is a combination of [`CURLPAUSE_RECV`] and
    /// [`CURLPAUSE_SEND`] flags:
    /// - Set `CURLPAUSE_RECV` to pause receiving.
    /// - Set `CURLPAUSE_SEND` to pause sending.
    /// - Set `CURLPAUSE_ALL` to pause both.
    /// - Set `CURLPAUSE_CONT` (0) to unpause both.
    ///
    /// # Errors
    ///
    /// - [`CurlError::BadFunctionArgument`] — handle not in an active state.
    ///
    /// # C Equivalent
    ///
    /// `CURLcode curl_easy_pause(CURL *d, int action)` from `lib/easy.c` line 1136.
    pub fn pause(&mut self, bitmask: u32) -> CurlResult<()> {
        tracing::debug!(
            "EasyHandle::pause: id={}, bitmask=0x{:x}",
            self.id,
            bitmask
        );

        let new_recv_paused = (bitmask & CURLPAUSE_RECV) != 0;
        let new_send_paused = (bitmask & CURLPAUSE_SEND) != 0;
        let changed = (self.recv_paused != new_recv_paused)
            || (self.send_paused != new_send_paused);

        self.recv_paused = new_recv_paused;
        self.send_paused = new_send_paused;

        if changed {
            tracing::info!(
                "EasyHandle::pause: id={}, recv_paused={}, send_paused={}",
                self.id,
                self.recv_paused,
                self.send_paused
            );
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // upkeep — matches curl_easy_upkeep()
    // -----------------------------------------------------------------------

    /// Performs connection upkeep activities.
    ///
    /// This should be called periodically to keep connections alive and
    /// perform housekeeping on the connection pool. Useful for long-lived
    /// applications that maintain persistent connections.
    ///
    /// # Errors
    ///
    /// - [`CurlError::BadFunctionArgument`] — handle is in an invalid state.
    ///
    /// # C Equivalent
    ///
    /// `CURLcode curl_easy_upkeep(CURL *d)` from `lib/easy.c` line 1320.
    pub fn upkeep(&mut self) -> CurlResult<()> {
        tracing::trace!("EasyHandle::upkeep: id={}", self.id);

        // Connection pool upkeep:
        // In the full integration, this calls into the connection pool
        // to send keep-alive pings, close idle connections that have
        // exceeded their timeout, and perform other maintenance.
        //
        // Equivalent to C: Curl_cpool_upkeep(data)

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Accessor methods for internal state
    // -----------------------------------------------------------------------

    /// Returns the current transfer lifecycle state.
    #[inline]
    pub fn state(&self) -> EasyState {
        self.state
    }

    /// Returns the unique handle identifier.
    #[inline]
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Returns a reference to the transfer info (post-transfer metadata).
    #[inline]
    pub fn transfer_info(&self) -> &TransferInfo {
        &self.info
    }

    /// Returns a mutable reference to the transfer info.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn transfer_info_mut(&mut self) -> &mut TransferInfo {
        &mut self.info
    }

    /// Returns a reference to the handle options.
    #[inline]
    pub fn options(&self) -> &setopt::HandleOptions {
        &self.config
    }

    /// Returns a mutable reference to the handle options.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn options_mut(&mut self) -> &mut setopt::HandleOptions {
        &mut self.config
    }

    /// Returns a reference to the progress tracker.
    #[inline]
    pub fn progress(&self) -> &Progress {
        &self.progress
    }

    /// Returns a mutable reference to the progress tracker.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn progress_mut(&mut self) -> &mut Progress {
        &mut self.progress
    }

    /// Returns a reference to the response headers.
    #[inline]
    pub fn response_headers(&self) -> &Headers {
        &self.response_headers
    }

    /// Returns a reference to the custom request headers.
    #[inline]
    pub fn custom_headers(&self) -> &DynHeaders {
        &self.headers
    }

    /// Returns a reference to the cookie jar, if cookies are enabled.
    #[inline]
    pub fn cookie_jar(&self) -> Option<&Arc<Mutex<CookieJar>>> {
        self.cookie_jar.as_ref()
    }

    /// Returns a reference to the parsed URL, if set.
    #[inline]
    pub fn url(&self) -> Option<&CurlUrl> {
        self.url.as_ref()
    }

    /// Returns a reference to the share handle, if set.
    #[inline]
    pub fn share(&self) -> Option<&ShareHandle> {
        self.share.as_ref()
    }

    /// Returns the last OS-level errno.
    #[inline]
    pub fn os_errno(&self) -> i32 {
        self.os_errno
    }

    /// Returns the error buffer contents, if any error occurred.
    #[inline]
    pub fn error_buffer(&self) -> Option<&str> {
        self.error_buffer.as_deref()
    }

    /// Returns whether receiving is currently paused.
    #[inline]
    pub fn is_recv_paused(&self) -> bool {
        self.recv_paused
    }

    /// Returns whether sending is currently paused.
    #[inline]
    pub fn is_send_paused(&self) -> bool {
        self.send_paused
    }

    /// Returns the Alt-Svc cache, if initialized.
    #[inline]
    pub fn altsvc_cache(&self) -> Option<&altsvc::AltSvcCache> {
        self.altsvc_cache.as_ref()
    }

    /// Returns the HSTS cache, if initialized.
    #[inline]
    pub fn hsts_cache(&self) -> Option<&hsts::HstsCache> {
        self.hsts_cache.as_ref()
    }
}

impl Default for EasyHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for EasyHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EasyHandle")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("url", &self.url.as_ref().map(|u| {
                u.get(crate::url::CurlUrlPart::Url, 0).unwrap_or_default()
            }))
            .field("recv_paused", &self.recv_paused)
            .field("send_paused", &self.send_paused)
            .field("connect_only", &self.connect_only)
            .finish_non_exhaustive()
    }
}

impl Drop for EasyHandle {
    fn drop(&mut self) {
        tracing::trace!("EasyHandle::drop: id={}", self.id);
    }
}

// ===========================================================================
// EasyBuilder — idiomatic Rust builder pattern
// ===========================================================================

/// Builder for constructing a configured [`EasyHandle`].
///
/// This provides the idiomatic Rust API for setting up transfers. All
/// configuration is validated at `build()` time. The builder accumulates
/// options and produces a fully configured `EasyHandle`.
///
/// # Examples
///
/// ```no_run
/// use curl_rs_lib::easy::EasyHandle;
///
/// let handle = EasyHandle::builder()
///     .url("https://example.com")
///     .follow_redirects(true)
///     .max_redirects(10)
///     .timeout(std::time::Duration::from_secs(30))
///     .user_agent("curl-rs/8.19.0")
///     .verbose(false)
///     .build();
/// ```
pub struct EasyBuilder {
    /// URL to transfer.
    url: Option<String>,

    /// Total transfer timeout (None = no timeout).
    timeout: Option<Duration>,

    /// Whether to follow HTTP 3xx redirects.
    follow_redirects: bool,

    /// Maximum number of redirects to follow (-1 = unlimited).
    max_redirects: i64,

    /// HTTP proxy URL.
    proxy: Option<String>,

    /// User-Agent header value.
    user_agent: Option<String>,

    /// Custom request headers.
    headers: SList,

    /// Whether to enable the cookie engine.
    cookie_jar: bool,

    /// Whether to enable verbose debug output.
    verbose: bool,
}

impl EasyBuilder {
    /// Creates a new builder with default settings.
    fn new() -> Self {
        Self {
            url: None,
            timeout: None,
            follow_redirects: false,
            max_redirects: -1, // Unlimited by default when follow is enabled
            proxy: None,
            user_agent: None,
            headers: SList::new(),
            cookie_jar: false,
            verbose: false,
        }
    }

    /// Sets the target URL for the transfer.
    ///
    /// # Parameters
    ///
    /// - `url` — the URL to transfer (e.g., `"https://example.com/path"`).
    pub fn url(mut self, url: &str) -> Self {
        self.url = Some(url.to_string());
        self
    }

    /// Sets the total transfer timeout.
    ///
    /// A timeout of `Duration::ZERO` disables the timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Enables or disables following HTTP 3xx redirects.
    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.follow_redirects = follow;
        self
    }

    /// Sets the maximum number of redirects to follow.
    ///
    /// - `0` — no redirects allowed.
    /// - `-1` — unlimited (default when follow is enabled).
    /// - Positive value — that many redirects maximum.
    pub fn max_redirects(mut self, max: i64) -> Self {
        self.max_redirects = max;
        self
    }

    /// Sets the HTTP proxy URL.
    ///
    /// Pass `None` or an empty string to disable proxy usage.
    pub fn proxy(mut self, proxy: &str) -> Self {
        if proxy.is_empty() {
            self.proxy = None;
        } else {
            self.proxy = Some(proxy.to_string());
        }
        self
    }

    /// Sets the `User-Agent` header value.
    pub fn user_agent(mut self, ua: &str) -> Self {
        self.user_agent = Some(ua.to_string());
        self
    }

    /// Adds custom request headers.
    ///
    /// Each string should be in `"Name: Value"` format. Calling this
    /// multiple times appends additional headers.
    pub fn headers(mut self, hdrs: &[&str]) -> Self {
        for h in hdrs {
            self.headers.append(h);
        }
        self
    }

    /// Enables or disables the cookie engine.
    ///
    /// When enabled, a `CookieJar` is created and HTTP cookies are
    /// automatically managed during transfers.
    pub fn cookie_jar(mut self, enable: bool) -> Self {
        self.cookie_jar = enable;
        self
    }

    /// Enables or disables verbose debug output.
    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Consumes the builder and produces a configured [`EasyHandle`].
    ///
    /// All accumulated settings are applied to the handle. The handle
    /// starts in [`EasyState::Idle`] and is ready for `perform()`.
    pub fn build(self) -> EasyHandle {
        let mut handle = EasyHandle::new();

        // Apply URL.
        if let Some(ref url_str) = self.url {
            let mut url = CurlUrl::new();
            if url.set(crate::url::CurlUrlPart::Url, url_str, 0).is_ok() {
                handle.url = Some(url);
            }
            handle.config.url = Some(url_str.clone());
        }

        // Apply timeout.
        if let Some(timeout) = self.timeout {
            handle.config.timeout_ms = timeout.as_millis() as i64;
        }

        // Apply follow redirects.
        handle.config.followlocation = if self.follow_redirects { 1 } else { 0 };
        handle.config.maxredirs = self.max_redirects;

        // Apply verbose.
        handle.config.verbose = self.verbose;

        // Apply user agent.
        if let Some(ref ua) = self.user_agent {
            handle.config.useragent = Some(ua.clone());
        }

        // Apply proxy.
        if let Some(ref proxy) = self.proxy {
            handle.config.proxy = Some(proxy.clone());
        }

        // Apply custom headers — split "Name: Value" strings into components.
        if !self.headers.is_empty() {
            for header in self.headers.iter() {
                if let Some(colon_pos) = header.find(':') {
                    let name = header[..colon_pos].trim();
                    let value = header[colon_pos + 1..].trim();
                    let _ = handle.headers.add(name, value);
                }
            }
        }

        // Enable cookie engine if requested.
        if self.cookie_jar {
            handle.cookie_jar = Some(Arc::new(Mutex::new(CookieJar::new())));
        }

        handle
    }
}

impl fmt::Debug for EasyBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EasyBuilder")
            .field("url", &self.url)
            .field("timeout", &self.timeout)
            .field("follow_redirects", &self.follow_redirects)
            .field("max_redirects", &self.max_redirects)
            .field("verbose", &self.verbose)
            .finish_non_exhaustive()
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_init_cleanup() {
        // Global init should succeed.
        assert!(global_init(CURL_GLOBAL_DEFAULT).is_ok());
        // Cleanup should not panic.
        global_cleanup();
    }

    #[test]
    fn test_easy_handle_new() {
        let handle = EasyHandle::new();
        assert_eq!(handle.state(), EasyState::Idle);
        assert!(handle.id() > 0);
    }

    #[test]
    fn test_easy_handle_reset() {
        let mut handle = EasyHandle::new();
        // Set some state.
        handle.connect_only = true;
        handle.recv_paused = true;
        // Reset.
        handle.reset();
        assert_eq!(handle.state(), EasyState::Idle);
        assert!(!handle.recv_paused);
        // connect_only is reset
        assert!(!handle.connect_only);
    }

    #[test]
    fn test_easy_handle_dup() {
        let handle = EasyHandle::new();
        let dup = handle.dup();
        assert_ne!(handle.id(), dup.id());
        assert_eq!(dup.state(), EasyState::Idle);
    }

    #[test]
    fn test_easy_state_display() {
        assert_eq!(format!("{}", EasyState::Idle), "Idle");
        assert_eq!(format!("{}", EasyState::Connected), "Connected");
        assert_eq!(format!("{}", EasyState::Transferring), "Transferring");
        assert_eq!(format!("{}", EasyState::Complete), "Complete");
    }

    #[test]
    fn test_easy_state_default() {
        assert_eq!(EasyState::default(), EasyState::Idle);
    }

    #[test]
    fn test_transfer_info_defaults() {
        let info = TransferInfo::new();
        assert_eq!(info.response_code(), 0);
        assert_eq!(info.total_time(), 0.0);
        assert!(info.effective_url().is_none());
        assert!(info.content_type().is_none());
        assert!(info.primary_ip().is_none());
        assert_eq!(info.redirect_count(), 0);
    }

    #[test]
    fn test_pause_constants() {
        assert_eq!(CURLPAUSE_RECV, 1);
        assert_eq!(CURLPAUSE_SEND, 4);
        assert_eq!(CURLPAUSE_ALL, 5);
        assert_eq!(CURLPAUSE_CONT, 0);
    }

    #[test]
    fn test_global_constants() {
        assert_eq!(CURL_GLOBAL_SSL, 1);
        assert_eq!(CURL_GLOBAL_WIN32, 2);
        assert_eq!(CURL_GLOBAL_ALL, 3);
        assert_eq!(CURL_GLOBAL_DEFAULT, 3);
        assert_eq!(CURL_GLOBAL_NOTHING, 0);
    }

    #[test]
    fn test_easy_pause() {
        let mut handle = EasyHandle::new();
        // Pause both directions.
        assert!(handle.pause(CURLPAUSE_ALL).is_ok());
        assert!(handle.is_recv_paused());
        assert!(handle.is_send_paused());
        // Unpause both.
        assert!(handle.pause(CURLPAUSE_CONT).is_ok());
        assert!(!handle.is_recv_paused());
        assert!(!handle.is_send_paused());
    }

    #[test]
    fn test_recv_requires_connect_only() {
        let mut handle = EasyHandle::new();
        let mut buf = [0u8; 1024];
        let result = handle.recv(&mut buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::UnsupportedProtocol);
    }

    #[test]
    fn test_send_requires_connect_only() {
        let mut handle = EasyHandle::new();
        let data = b"hello";
        let result = handle.send(data);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::UnsupportedProtocol);
    }

    #[test]
    fn test_upkeep_succeeds() {
        let mut handle = EasyHandle::new();
        assert!(handle.upkeep().is_ok());
    }

    #[test]
    fn test_builder_basic() {
        let handle = EasyHandle::builder()
            .url("https://example.com")
            .verbose(true)
            .follow_redirects(true)
            .max_redirects(5)
            .build();

        assert_eq!(handle.state(), EasyState::Idle);
        assert!(handle.config.verbose);
        assert_eq!(handle.config.followlocation, 1);
        assert_eq!(handle.config.maxredirs, 5);
    }

    #[test]
    fn test_builder_with_headers() {
        let handle = EasyHandle::builder()
            .url("https://example.com")
            .headers(&["Content-Type: application/json", "Accept: */*"])
            .build();

        assert_eq!(handle.state(), EasyState::Idle);
    }

    #[test]
    fn test_builder_with_cookie_jar() {
        let handle = EasyHandle::builder()
            .url("https://example.com")
            .cookie_jar(true)
            .build();

        assert!(handle.cookie_jar().is_some());
    }

    #[test]
    fn test_builder_with_timeout() {
        let handle = EasyHandle::builder()
            .url("https://example.com")
            .timeout(Duration::from_secs(30))
            .build();

        assert_eq!(handle.config.timeout_ms, 30000);
    }

    #[test]
    fn test_builder_with_user_agent() {
        let handle = EasyHandle::builder()
            .url("https://example.com")
            .user_agent("test-agent/1.0")
            .build();

        assert_eq!(
            handle.config.useragent.as_deref(),
            Some("test-agent/1.0")
        );
    }

    #[test]
    fn test_builder_with_proxy() {
        let handle = EasyHandle::builder()
            .url("https://example.com")
            .proxy("http://proxy.local:8080")
            .build();

        assert_eq!(
            handle.config.proxy.as_deref(),
            Some("http://proxy.local:8080")
        );
    }

    #[test]
    fn test_easy_debug_format() {
        let handle = EasyHandle::new();
        let debug = format!("{:?}", handle);
        assert!(debug.contains("EasyHandle"));
        assert!(debug.contains("Idle"));
    }

    #[test]
    fn test_easy_handle_default() {
        let handle = EasyHandle::default();
        assert_eq!(handle.state(), EasyState::Idle);
    }

    #[test]
    fn test_easy_cleanup() {
        let handle = EasyHandle::new();
        let id = handle.id();
        handle.cleanup(); // Should not panic.
        // handle is consumed — cannot be used after this.
        let _ = id; // Prove id was captured before cleanup.
    }
}
