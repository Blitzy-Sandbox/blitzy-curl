//! Shared handle API — Arc-based shared state for sharing data between
//! multiple easy handles.
//!
//! Rust rewrite of `lib/curl_share.c` and `lib/curl_share.h` from curl
//! 8.19.0-DEV.  Implements the `curl_share_*` family of functions using
//! Rust's `Arc<Mutex<T>>` for thread-safe shared ownership, replacing the
//! C manual locking and reference-counting approach.
//!
//! # Architecture
//!
//! [`ShareHandle`] wraps `Arc<Mutex<ShareData>>`.  Each shared resource
//! inside [`ShareData`] is independently wrapped in its own `Arc<Mutex<T>>`
//! (or `Arc<T>` for read-only data like [`PslChecker`]) so that:
//!
//! 1. Multiple easy handles can hold a reference-counted clone of the
//!    specific resource they need.
//! 2. Fine-grained locking allows concurrent access to independent
//!    resources (e.g., one thread locks the cookie jar while another
//!    locks the DNS cache).
//!
//! # C API Mapping
//!
//! | C function              | Rust equivalent                        |
//! |-------------------------|----------------------------------------|
//! | `curl_share_init()`     | [`ShareHandle::new()`]                 |
//! | `curl_share_setopt()`   | [`ShareHandle::set_option()`]          |
//! | `curl_share_cleanup()`  | [`ShareHandle::cleanup()`]             |
//! | `curl_share_strerror()` | [`ShareHandle::strerror()`]            |
//!
//! # Integer Value Parity
//!
//! All enum discriminants match their C counterparts exactly:
//!
//! - [`CurlShareLock`] maps to `curl_lock_data` (values 2–7)
//! - [`CurlShOption`] maps to `CURLSHoption` (values 1–5)
//! - [`CurlSHcode`] from `crate::error` maps to `CURLSHcode` (values 0–5)
//!
//! # Thread Safety
//!
//! All public types are `Send + Sync`.  The outer `Mutex<ShareData>` is held
//! only for short administrative operations (enable/disable sharing,
//! attach/detach easy handles).  Per-resource locks are acquired independently
//! by easy handles during transfers.
//!
//! # Zero `unsafe`
//!
//! This module contains zero `unsafe` blocks, per AAP Section 0.7.1.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::conn::ConnectionPool;
#[cfg(feature = "cookies")]
use crate::cookie::CookieJar;
use crate::dns::DnsCache;
use crate::error::CurlSHcode;
use crate::hsts::HstsCache;
use crate::psl::PslChecker;
use crate::tls::session_cache::SessionCache;

// ---------------------------------------------------------------------------
// Internal constants — matching C `curl_lock_data` integer values
// ---------------------------------------------------------------------------

/// Bit position for `CURL_LOCK_DATA_SHARE` (1) — internal share-level lock.
const SHARE_BIT: u32 = 1 << 1;

// ---------------------------------------------------------------------------
// Default resource sizes — matching C `curl_share_setopt()` allocation params
// ---------------------------------------------------------------------------

/// Default DNS cache timeout in seconds (matches `CURL_TIMEOUT_RESOLVE` = 300
/// in `lib/hostip.h` line 38).
const DEFAULT_DNS_CACHE_TIMEOUT_SECS: u64 = 300;

/// Default SSL session cache max peers (matches C `25` in
/// `Curl_ssl_scache_create(25, 2, ...)` called by `curl_share_setopt()`).
const DEFAULT_SSL_CACHE_MAX_PEERS: usize = 25;

/// Default SSL session cache max sessions per peer (matches C `2`).
const DEFAULT_SSL_CACHE_MAX_SESSIONS: usize = 2;

/// Default connection pool max total (matches C `103` bucket count in
/// `Curl_cpool_init()` called by `curl_share_setopt()`).
const DEFAULT_CPOOL_MAX_TOTAL: usize = 103;

/// Default connection pool max per host (0 = unlimited, matching C behaviour).
const DEFAULT_CPOOL_MAX_PER_HOST: usize = 0;

// ---------------------------------------------------------------------------
// CurlShareLock — maps to C `curl_lock_data`
// ---------------------------------------------------------------------------

/// Data types that can be shared between easy handles.
///
/// Maps 1:1 to the C `curl_lock_data` enum in `include/curl/curl.h`.
/// Internal-only values (`CURL_LOCK_DATA_NONE` = 0 and
/// `CURL_LOCK_DATA_SHARE` = 1) are not exposed — they are used only within
/// the share handle implementation itself.
///
/// # Integer Values
///
/// | Rust variant    | C constant                  | Value |
/// |-----------------|-----------------------------|-------|
/// | `Cookie`        | `CURL_LOCK_DATA_COOKIE`     | 2     |
/// | `Dns`           | `CURL_LOCK_DATA_DNS`        | 3     |
/// | `SslSession`    | `CURL_LOCK_DATA_SSL_SESSION`| 4     |
/// | `Connect`       | `CURL_LOCK_DATA_CONNECT`    | 5     |
/// | `Psl`           | `CURL_LOCK_DATA_PSL`        | 6     |
/// | `Hsts`          | `CURL_LOCK_DATA_HSTS`       | 7     |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CurlShareLock {
    /// Share cookie data (`CURL_LOCK_DATA_COOKIE` = 2).
    Cookie = 2,
    /// Share DNS cache (`CURL_LOCK_DATA_DNS` = 3).
    Dns = 3,
    /// Share SSL/TLS session cache (`CURL_LOCK_DATA_SSL_SESSION` = 4).
    SslSession = 4,
    /// Share connection pool (`CURL_LOCK_DATA_CONNECT` = 5).
    Connect = 5,
    /// Share public suffix list data (`CURL_LOCK_DATA_PSL` = 6).
    Psl = 6,
    /// Share HSTS cache (`CURL_LOCK_DATA_HSTS` = 7).
    Hsts = 7,
}

impl CurlShareLock {
    /// Returns the bitmask bit for this lock type (1 << value).
    ///
    /// Used by [`ShareData::specifier`] to track which data types are shared,
    /// matching the C `share->specifier |= (1 << type)` pattern.
    #[inline]
    fn as_bit(self) -> u32 {
        1u32 << (self as u32)
    }

    /// Attempt to convert an `i32` to a [`CurlShareLock`].
    ///
    /// Returns `None` for values outside the valid range (2–7) or for
    /// internal-only values (0 = NONE, 1 = SHARE).
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            2 => Some(Self::Cookie),
            3 => Some(Self::Dns),
            4 => Some(Self::SslSession),
            5 => Some(Self::Connect),
            6 => Some(Self::Psl),
            7 => Some(Self::Hsts),
            _ => None,
        }
    }
}

impl fmt::Display for CurlShareLock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cookie => write!(f, "Cookie"),
            Self::Dns => write!(f, "DNS"),
            Self::SslSession => write!(f, "SSL Session"),
            Self::Connect => write!(f, "Connection"),
            Self::Psl => write!(f, "PSL"),
            Self::Hsts => write!(f, "HSTS"),
        }
    }
}

// ---------------------------------------------------------------------------
// CurlShOption — maps to C `CURLSHoption`
// ---------------------------------------------------------------------------

/// Share configuration options matching C `CURLSHoption`.
///
/// Used with [`ShareHandle::set_option()`] to control which data types are
/// shared between easy handles attached to a share handle.
///
/// # Integer Values
///
/// | Rust variant  | C constant           | Value |
/// |---------------|----------------------|-------|
/// | `Share`       | `CURLSHOPT_SHARE`    | 1     |
/// | `Unshare`     | `CURLSHOPT_UNSHARE`  | 2     |
/// | `LockFunc`    | `CURLSHOPT_LOCKFUNC` | 3     |
/// | `UnlockFunc`  | `CURLSHOPT_UNLOCKFUNC`| 4    |
/// | `UserData`    | `CURLSHOPT_USERDATA` | 5     |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CurlShOption {
    /// Specify a data type to share (`CURLSHOPT_SHARE` = 1).
    Share = 1,
    /// Specify a data type to stop sharing (`CURLSHOPT_UNSHARE` = 2).
    Unshare = 2,
    /// Set a user-provided lock function (`CURLSHOPT_LOCKFUNC` = 3).
    ///
    /// In pure Rust mode, the internal `Mutex` provides thread safety
    /// automatically.  This option exists for FFI compatibility with C
    /// callers who supply their own synchronization primitives.
    LockFunc = 3,
    /// Set a user-provided unlock function (`CURLSHOPT_UNLOCKFUNC` = 4).
    ///
    /// See [`LockFunc`](Self::LockFunc) for details.
    UnlockFunc = 4,
    /// Set the opaque user-data pointer passed to lock/unlock callbacks
    /// (`CURLSHOPT_USERDATA` = 5).
    UserData = 5,
}

impl CurlShOption {
    /// Attempt to convert an `i32` to a [`CurlShOption`].
    ///
    /// Returns `None` for values outside the valid range (1–5).
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            1 => Some(Self::Share),
            2 => Some(Self::Unshare),
            3 => Some(Self::LockFunc),
            4 => Some(Self::UnlockFunc),
            5 => Some(Self::UserData),
            _ => None,
        }
    }
}

impl fmt::Display for CurlShOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Share => write!(f, "CURLSHOPT_SHARE"),
            Self::Unshare => write!(f, "CURLSHOPT_UNSHARE"),
            Self::LockFunc => write!(f, "CURLSHOPT_LOCKFUNC"),
            Self::UnlockFunc => write!(f, "CURLSHOPT_UNLOCKFUNC"),
            Self::UserData => write!(f, "CURLSHOPT_USERDATA"),
        }
    }
}

// ---------------------------------------------------------------------------
// LockAccess — maps to C `curl_lock_access`
// ---------------------------------------------------------------------------

/// Lock access type passed to user-provided lock callbacks.
///
/// Maps to C `curl_lock_access` in `include/curl/curl.h`.
/// Used primarily in the FFI layer; in pure Rust mode, the `Mutex` does not
/// distinguish between shared and exclusive access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum LockAccess {
    /// Unspecified action (`CURL_LOCK_ACCESS_NONE` = 0).
    None = 0,
    /// Shared (read) access (`CURL_LOCK_ACCESS_SHARED` = 1).
    Shared = 1,
    /// Exclusive (write) access (`CURL_LOCK_ACCESS_SINGLE` = 2).
    Single = 2,
}

// ---------------------------------------------------------------------------
// Callback type aliases for FFI lock/unlock functions
// ---------------------------------------------------------------------------

/// User-provided lock callback function type.
///
/// Mirrors the C `curl_lock_function` signature:
/// ```c
/// void (*curl_lock_function)(CURL *handle, curl_lock_data data,
///                            curl_lock_access locktype, void *userptr);
/// ```
///
/// In the Rust API, `handle` is abstracted away (the share handle manages
/// locking internally) and `userptr` is represented as a `usize`.
///
/// This is primarily used by the FFI crate (`curl-rs-ffi`) to bridge C
/// callback function pointers.  Pure Rust callers should not need to set
/// lock functions — the internal `Mutex` provides thread safety.
pub type LockCallback = Box<dyn Fn(CurlShareLock, LockAccess, usize) + Send + Sync>;

/// User-provided unlock callback function type.
///
/// Mirrors the C `curl_unlock_function` signature:
/// ```c
/// void (*curl_unlock_function)(CURL *handle, curl_lock_data data,
///                              void *userptr);
/// ```
pub type UnlockCallback = Box<dyn Fn(CurlShareLock, usize) + Send + Sync>;

// ---------------------------------------------------------------------------
// ShareData — shared data container
// ---------------------------------------------------------------------------

/// Shared data container holding all optional shared resources.
///
/// Each resource is independently wrapped in `Arc<Mutex<T>>` (or `Arc<T>`
/// for read-only resources) to allow fine-grained locking.  An easy handle
/// that needs a shared resource clones the `Arc` from this struct and locks
/// it independently, without holding the outer `ShareData` lock.
///
/// Maps to the C `struct Curl_share` from `lib/curl_share.h`.
pub struct ShareData {
    /// Shared cookie storage engine.
    ///
    /// Initialized when `set_option(Share, Cookie)` is called, matching the
    /// C `Curl_cookie_init()` call in `curl_share_setopt()`.
    #[cfg(feature = "cookies")]
    pub cookies: Option<Arc<Mutex<CookieJar>>>,

    /// Shared DNS resolution cache.
    ///
    /// Initialized when `set_option(Share, Dns)` is called, matching the C
    /// `Curl_hash_init(&share->dnscache, 23)` pattern.
    pub dns_cache: Option<Arc<Mutex<DnsCache>>>,

    /// Shared connection pool.
    ///
    /// Initialized when `set_option(Share, Connect)` is called, matching
    /// the C `Cpool_init(&share->cpool, ...)` call in `curl_share_setopt()`.
    pub connections: Option<Arc<Mutex<ConnectionPool>>>,

    /// Shared TLS session resumption cache.
    ///
    /// Initialized when `set_option(Share, SslSession)` is called, matching
    /// the C `Curl_ssl_scache_create(25, 2, ...)` call.
    pub ssl_session: Option<Arc<Mutex<SessionCache>>>,

    /// Shared public suffix list checker (read-only, no Mutex needed).
    ///
    /// Initialized when `set_option(Share, Psl)` is called.
    pub psl: Option<Arc<PslChecker>>,

    /// Shared HSTS (HTTP Strict Transport Security) cache.
    ///
    /// Initialized when `set_option(Share, Hsts)` is called, matching
    /// the C `Curl_hsts_init()` call in `curl_share_setopt()`.
    pub hsts: Option<Arc<Mutex<HstsCache>>>,

    // -- internal state (not directly exposed) --------------------------------

    /// Bitmask of currently shared data types.
    ///
    /// Each bit position corresponds to a `CurlShareLock` discriminant value.
    /// Bit 1 (`CURL_LOCK_DATA_SHARE`) is always set after initialization,
    /// matching the C `share->specifier |= (1 << CURL_LOCK_DATA_SHARE)`.
    specifier: u32,

    /// Number of easy handles currently attached to this share.
    ///
    /// When `dirty > 0`, `set_option()` returns `CurlSHcode::InUse` and
    /// `cleanup()` refuses to destroy resources.  Matches the C
    /// `share->dirty` volatile counter.
    dirty: u32,

    /// Optional user-provided lock callback (primarily for FFI).
    lock_func: Option<LockCallback>,

    /// Optional user-provided unlock callback (primarily for FFI).
    unlock_func: Option<UnlockCallback>,

    /// Opaque user-data pointer passed to lock/unlock callbacks.
    ///
    /// Stored as `usize` to allow FFI pass-through of `void *` without
    /// `unsafe`.  The FFI crate converts between `*mut c_void` and `usize`.
    user_data: usize,
}

impl ShareData {
    /// Creates a new, empty [`ShareData`] with the SHARE specifier bit set.
    ///
    /// Matches C `curl_share_init()` which sets
    /// `share->specifier |= (1 << CURL_LOCK_DATA_SHARE)`.
    fn new() -> Self {
        Self {
            #[cfg(feature = "cookies")]
            cookies: None,
            dns_cache: None,
            connections: None,
            ssl_session: None,
            psl: None,
            hsts: None,
            specifier: SHARE_BIT,
            dirty: 0,
            lock_func: None,
            unlock_func: None,
            user_data: 0,
        }
    }

    /// Enable sharing for the given data type.
    ///
    /// Allocates the resource if it does not already exist, matching the
    /// C `CURLSHOPT_SHARE` branch in `curl_share_setopt()`.
    fn share(&mut self, lock: CurlShareLock) -> Result<(), CurlSHcode> {
        match lock {
            CurlShareLock::Cookie => {
                #[cfg(feature = "cookies")]
                if self.cookies.is_none() {
                    self.cookies = Some(Arc::new(Mutex::new(CookieJar::new())));
                }
            }
            CurlShareLock::Dns => {
                // DNS cache may already be initialized — this is a no-op if so.
                if self.dns_cache.is_none() {
                    let timeout = Duration::from_secs(DEFAULT_DNS_CACHE_TIMEOUT_SECS);
                    self.dns_cache = Some(Arc::new(Mutex::new(DnsCache::new(timeout))));
                }
            }
            CurlShareLock::SslSession => {
                if self.ssl_session.is_none() {
                    self.ssl_session = Some(Arc::new(Mutex::new(SessionCache::new(
                        DEFAULT_SSL_CACHE_MAX_PEERS,
                        DEFAULT_SSL_CACHE_MAX_SESSIONS,
                    ))));
                }
            }
            CurlShareLock::Connect => {
                // Safe to call multiple times — matches C comment:
                // "It is safe to set this option several times on a share."
                if self.connections.is_none() {
                    self.connections = Some(Arc::new(Mutex::new(ConnectionPool::new(
                        DEFAULT_CPOOL_MAX_TOTAL,
                        DEFAULT_CPOOL_MAX_PER_HOST,
                    ))));
                }
            }
            CurlShareLock::Psl => {
                if self.psl.is_none() {
                    self.psl = Some(Arc::new(PslChecker::new()));
                }
            }
            CurlShareLock::Hsts => {
                if self.hsts.is_none() {
                    self.hsts = Some(Arc::new(Mutex::new(HstsCache::new())));
                }
            }
        }

        // Set the specifier bit for this data type.
        self.specifier |= lock.as_bit();
        Ok(())
    }

    /// Disable sharing for the given data type and clean up the resource.
    ///
    /// Matches the C `CURLSHOPT_UNSHARE` branch in `curl_share_setopt()`.
    fn unshare(&mut self, lock: CurlShareLock) -> Result<(), CurlSHcode> {
        // Clear the specifier bit.
        self.specifier &= !lock.as_bit();

        match lock {
            CurlShareLock::Cookie => {
                #[cfg(feature = "cookies")]
                {
                    if let Some(ref jar) = self.cookies {
                        if let Ok(mut c) = jar.lock() {
                            c.clear_all();
                        }
                    }
                    self.cookies = None;
                }
            }
            CurlShareLock::Dns => {
                // DNS cache clear — no explicit destroy needed; dropping the
                // Arc will clean up when no other handles hold a reference.
                if let Some(ref cache) = self.dns_cache {
                    if let Ok(c) = cache.lock() {
                        c.clear();
                    }
                }
                self.dns_cache = None;
            }
            CurlShareLock::SslSession => {
                // Drop the session cache — sessions expire naturally.
                self.ssl_session = None;
            }
            CurlShareLock::Connect => {
                // Connection pool — no explicit teardown on unshare in C.
                // The pool is destroyed only in cleanup().
                // Matching C behavior: unshare just clears the bit.
            }
            CurlShareLock::Psl => {
                self.psl = None;
            }
            CurlShareLock::Hsts => {
                if let Some(ref cache) = self.hsts {
                    if let Ok(mut h) = cache.lock() {
                        h.clear();
                    }
                }
                self.hsts = None;
            }
        }
        Ok(())
    }

    /// Returns `true` if the given data type is currently shared.
    #[inline]
    fn is_sharing(&self, lock: CurlShareLock) -> bool {
        (self.specifier & lock.as_bit()) != 0
    }

    /// Destroy all shared resources.
    ///
    /// Matches the cleanup sequence in C `curl_share_cleanup()`:
    /// connections → DNS → cookies → HSTS → SSL sessions → PSL.
    fn destroy_all(&mut self) {
        // Connection pool — explicit destroy (matches C `Curl_cpool_destroy`).
        if self.specifier & CurlShareLock::Connect.as_bit() != 0 {
            if let Some(ref pool) = self.connections {
                if let Ok(mut p) = pool.lock() {
                    p.destroy();
                }
            }
        }
        self.connections = None;

        // DNS cache — explicit destroy (matches C `Curl_dnscache_destroy`).
        if let Some(ref cache) = self.dns_cache {
            if let Ok(c) = cache.lock() {
                c.destroy();
            }
        }
        self.dns_cache = None;

        // Cookie jar — cleanup (matches C `Curl_cookie_cleanup`).
        #[cfg(feature = "cookies")]
        {
            if let Some(ref jar) = self.cookies {
                if let Ok(mut c) = jar.lock() {
                    c.clear_all();
                }
            }
            self.cookies = None;
        }

        // HSTS cache — cleanup (matches C `Curl_hsts_cleanup`).
        if let Some(ref cache) = self.hsts {
            if let Ok(mut h) = cache.lock() {
                h.clear();
            }
        }
        self.hsts = None;

        // SSL session cache — drop (matches C `Curl_ssl_scache_destroy`).
        // Dropping the Arc will destroy the cache when no other references
        // remain.
        self.ssl_session = None;

        // PSL checker — drop (matches C `Curl_psl_destroy`).
        self.psl = None;

        // Clear the specifier entirely.
        self.specifier = 0;
    }
}

impl fmt::Debug for ShareData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("ShareData");
        #[cfg(feature = "cookies")]
        s.field("cookies", &self.cookies.is_some());
        s.field("dns_cache", &self.dns_cache.is_some())
            .field("connections", &self.connections.is_some())
            .field("ssl_session", &self.ssl_session.is_some())
            .field("psl", &self.psl.is_some())
            .field("hsts", &self.hsts.is_some())
            .field("specifier", &format_args!("0x{:04x}", self.specifier))
            .field("dirty", &self.dirty)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// ShareHandle — the public handle type
// ---------------------------------------------------------------------------

/// A share handle for sharing data between multiple easy handles.
///
/// Wraps `Arc<Mutex<ShareData>>` to provide thread-safe shared ownership
/// of resources such as cookies, DNS cache, connection pool, TLS session
/// cache, HSTS cache, and the public suffix list.
///
/// # Usage
///
/// ```rust,no_run
/// use curl_rs_lib::share::{ShareHandle, CurlShOption, CurlShareLock};
///
/// let share = ShareHandle::new();
/// share.set_option(CurlShOption::Share, CurlShareLock::Cookie).unwrap();
/// share.set_option(CurlShOption::Share, CurlShareLock::Dns).unwrap();
///
/// // Attach the share handle to easy handles...
/// // (done via easy handle configuration)
///
/// // When done:
/// share.cleanup().unwrap();
/// ```
///
/// # C API Equivalent
///
/// | C call                          | Rust method                                |
/// |---------------------------------|--------------------------------------------|
/// | `curl_share_init()`             | `ShareHandle::new()`                       |
/// | `curl_share_setopt(SHARE, ...)`  | `share.set_option(Share, lock_data)`       |
/// | `curl_share_setopt(UNSHARE, ...)`| `share.set_option(Unshare, lock_data)`     |
/// | `curl_share_cleanup()`          | `share.cleanup()`                          |
/// | `curl_share_strerror(code)`     | `ShareHandle::strerror(code)`              |
pub struct ShareHandle {
    /// The inner shared data, behind Arc + Mutex for thread-safe access.
    inner: Arc<Mutex<ShareData>>,
}

impl ShareHandle {
    // ====================================================================
    // Construction
    // ====================================================================

    /// Creates a new share handle with no shared data types enabled.
    ///
    /// Equivalent to `curl_share_init()` in `lib/curl_share.c`.
    ///
    /// The newly created handle has the internal `CURL_LOCK_DATA_SHARE`
    /// specifier bit set (matching C behaviour) but no user-visible data
    /// types are shared until [`set_option()`](Self::set_option) is called
    /// with [`CurlShOption::Share`].
    pub fn new() -> Self {
        ShareHandle {
            inner: Arc::new(Mutex::new(ShareData::new())),
        }
    }

    // ====================================================================
    // Option Setting
    // ====================================================================

    /// Set a share option to enable or disable sharing of a data type.
    ///
    /// Equivalent to `curl_share_setopt()` in `lib/curl_share.c`.
    ///
    /// # Arguments
    ///
    /// * `option` — The share option to set.  For [`CurlShOption::Share`]
    ///   and [`CurlShOption::Unshare`], the `lock_data` parameter specifies
    ///   which data type to share/unshare.  For [`CurlShOption::LockFunc`],
    ///   [`CurlShOption::UnlockFunc`], and [`CurlShOption::UserData`],
    ///   this method is a no-op in pure Rust mode (internal `Mutex` provides
    ///   thread safety); use the dedicated [`set_lock_func()`](Self::set_lock_func),
    ///   [`set_unlock_func()`](Self::set_unlock_func), and
    ///   [`set_user_data()`](Self::set_user_data) methods for FFI callers.
    /// * `lock_data` — The data type to share or unshare.
    ///
    /// # Errors
    ///
    /// * [`CurlSHcode::Invalid`] — The share handle's internal lock is
    ///   poisoned (should never happen under normal operation).
    /// * [`CurlSHcode::InUse`] — One or more easy handles are currently
    ///   attached to this share handle.  Options cannot be changed while
    ///   the share is in use.
    pub fn set_option(
        &self,
        option: CurlShOption,
        lock_data: CurlShareLock,
    ) -> Result<(), CurlSHcode> {
        let mut data = self.inner.lock().map_err(|_| CurlSHcode::Invalid)?;

        // Do not allow setting options while one or more handles are using
        // this share — matches C `if(share->dirty) return CURLSHE_IN_USE`.
        if data.dirty > 0 {
            return Err(CurlSHcode::InUse);
        }

        match option {
            CurlShOption::Share => data.share(lock_data),
            CurlShOption::Unshare => data.unshare(lock_data),
            // Lock/unlock function and user-data options are handled by
            // dedicated type-safe methods.  In the generic set_option
            // pathway, these are accepted as no-ops for API compatibility.
            CurlShOption::LockFunc
            | CurlShOption::UnlockFunc
            | CurlShOption::UserData => Ok(()),
        }
    }

    // ====================================================================
    // Cleanup
    // ====================================================================

    /// Destroy the share handle and all shared resources.
    ///
    /// Equivalent to `curl_share_cleanup()` in `lib/curl_share.c`.
    ///
    /// # Errors
    ///
    /// * [`CurlSHcode::Invalid`] — Internal lock is poisoned.
    /// * [`CurlSHcode::InUse`] — One or more easy handles are still
    ///   attached.  Detach all handles before calling cleanup.
    pub fn cleanup(&self) -> Result<(), CurlSHcode> {
        let mut data = self.inner.lock().map_err(|_| CurlSHcode::Invalid)?;

        if data.dirty > 0 {
            return Err(CurlSHcode::InUse);
        }

        // Destroy all shared resources in the same order as C.
        data.destroy_all();
        Ok(())
    }

    // ====================================================================
    // Error Strings
    // ====================================================================

    /// Returns the human-readable error message for a share error code.
    ///
    /// Equivalent to `curl_share_strerror()` in `lib/strerror.c`.
    /// The returned strings are character-for-character identical to the
    /// C implementation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use curl_rs_lib::error::CurlSHcode;
    /// use curl_rs_lib::share::ShareHandle;
    ///
    /// assert_eq!(ShareHandle::strerror(CurlSHcode::Ok), "No error");
    /// assert_eq!(ShareHandle::strerror(CurlSHcode::InUse), "Share currently in use");
    /// ```
    pub fn strerror(code: CurlSHcode) -> &'static str {
        code.strerror()
    }

    // ====================================================================
    // Sharing State Queries
    // ====================================================================

    /// Returns `true` if the given data type is currently shared.
    ///
    /// Checks whether the specifier bitmask has the corresponding bit set,
    /// matching the C `share->specifier & (1 << type)` pattern.
    pub fn is_sharing(&self, lock: CurlShareLock) -> bool {
        match self.inner.lock() {
            Ok(data) => data.is_sharing(lock),
            Err(_) => false,
        }
    }

    // ====================================================================
    // Resource Accessors
    // ====================================================================

    /// Returns a cloned `Arc` reference to the shared cookie jar, if sharing
    /// cookies is enabled.
    ///
    /// The caller can hold this `Arc<Mutex<CookieJar>>` independently
    /// of the share handle and lock/unlock the cookie jar as needed.
    ///
    /// Only available when the `cookies` Cargo feature is enabled.
    #[cfg(feature = "cookies")]
    pub fn get_cookies(&self) -> Option<Arc<Mutex<CookieJar>>> {
        self.inner
            .lock()
            .ok()
            .and_then(|data| data.cookies.clone())
    }

    /// Returns a cloned `Arc` reference to the shared DNS cache, if sharing
    /// DNS data is enabled.
    pub fn get_dns_cache(&self) -> Option<Arc<Mutex<DnsCache>>> {
        self.inner
            .lock()
            .ok()
            .and_then(|data| data.dns_cache.clone())
    }

    /// Returns a cloned `Arc` reference to the shared connection pool, if
    /// sharing connections is enabled.
    pub fn get_connection_pool(&self) -> Option<Arc<Mutex<ConnectionPool>>> {
        self.inner
            .lock()
            .ok()
            .and_then(|data| data.connections.clone())
    }

    /// Returns a cloned `Arc` reference to the shared TLS session cache, if
    /// sharing SSL sessions is enabled.
    pub fn get_session_cache(&self) -> Option<Arc<Mutex<SessionCache>>> {
        self.inner
            .lock()
            .ok()
            .and_then(|data| data.ssl_session.clone())
    }

    /// Returns a cloned `Arc` reference to the shared HSTS cache, if
    /// sharing HSTS data is enabled.
    pub fn get_hsts(&self) -> Option<Arc<Mutex<HstsCache>>> {
        self.inner
            .lock()
            .ok()
            .and_then(|data| data.hsts.clone())
    }

    /// Returns a cloned `Arc` reference to the shared public suffix list
    /// checker, if sharing PSL data is enabled.
    ///
    /// Note: PSL is read-only and uses `Arc<PslChecker>` without a `Mutex`,
    /// as the data is immutable after initialization.
    pub fn get_psl(&self) -> Option<Arc<PslChecker>> {
        self.inner
            .lock()
            .ok()
            .and_then(|data| data.psl.clone())
    }

    // ====================================================================
    // FFI Callback Setters
    // ====================================================================

    /// Set the user-provided lock callback function.
    ///
    /// Primarily for the FFI crate to forward C `curl_lock_function`
    /// callbacks.  In pure Rust mode, the internal `Mutex` handles
    /// thread safety and this callback is never invoked by the library
    /// itself.
    ///
    /// # Errors
    ///
    /// * [`CurlSHcode::Invalid`] — Internal lock is poisoned.
    /// * [`CurlSHcode::InUse`] — Share is in use by one or more handles.
    pub fn set_lock_func(&self, func: Option<LockCallback>) -> Result<(), CurlSHcode> {
        let mut data = self.inner.lock().map_err(|_| CurlSHcode::Invalid)?;
        if data.dirty > 0 {
            return Err(CurlSHcode::InUse);
        }
        data.lock_func = func;
        Ok(())
    }

    /// Set the user-provided unlock callback function.
    ///
    /// See [`set_lock_func()`](Self::set_lock_func) for details.
    pub fn set_unlock_func(&self, func: Option<UnlockCallback>) -> Result<(), CurlSHcode> {
        let mut data = self.inner.lock().map_err(|_| CurlSHcode::Invalid)?;
        if data.dirty > 0 {
            return Err(CurlSHcode::InUse);
        }
        data.unlock_func = func;
        Ok(())
    }

    /// Set the opaque user-data pointer passed to lock/unlock callbacks.
    ///
    /// The value is stored as a `usize` and passed through to the
    /// lock/unlock callbacks as-is.  The FFI crate converts between
    /// `*mut c_void` and `usize`.
    ///
    /// # Errors
    ///
    /// * [`CurlSHcode::Invalid`] — Internal lock is poisoned.
    /// * [`CurlSHcode::InUse`] — Share is in use by one or more handles.
    pub fn set_user_data(&self, user_data: usize) -> Result<(), CurlSHcode> {
        let mut data = self.inner.lock().map_err(|_| CurlSHcode::Invalid)?;
        if data.dirty > 0 {
            return Err(CurlSHcode::InUse);
        }
        data.user_data = user_data;
        Ok(())
    }

    // ====================================================================
    // Internal Handle Management (crate-visible)
    //
    // These methods are used by easy.rs and other internal modules when
    // they need to attach/detach from a share or invoke user-level
    // lock callbacks.  They appear "unused" during isolated compilation
    // of the share module.
    // ====================================================================

    /// Mark this share as being used by an additional easy handle.
    ///
    /// Increments the internal `dirty` counter.  While `dirty > 0`,
    /// [`set_option()`](Self::set_option) and [`cleanup()`](Self::cleanup)
    /// will return [`CurlSHcode::InUse`].
    ///
    /// Called by the easy handle when `CURLOPT_SHARE` is set to this share.
    ///
    /// # Errors
    ///
    /// * [`CurlSHcode::Invalid`] — Internal lock is poisoned.
    #[allow(dead_code)]
    pub(crate) fn attach(&self) -> Result<(), CurlSHcode> {
        let mut data = self.inner.lock().map_err(|_| CurlSHcode::Invalid)?;
        data.dirty = data.dirty.saturating_add(1);
        Ok(())
    }

    /// Mark this share as no longer being used by an easy handle.
    ///
    /// Decrements the internal `dirty` counter.  When it reaches zero,
    /// [`set_option()`](Self::set_option) and [`cleanup()`](Self::cleanup)
    /// become available again.
    ///
    /// Called by the easy handle when `CURLOPT_SHARE` is set to `NULL` or
    /// when the easy handle is closed.
    ///
    /// # Errors
    ///
    /// * [`CurlSHcode::Invalid`] — Internal lock is poisoned.
    #[allow(dead_code)]
    pub(crate) fn detach(&self) -> Result<(), CurlSHcode> {
        let mut data = self.inner.lock().map_err(|_| CurlSHcode::Invalid)?;
        data.dirty = data.dirty.saturating_sub(1);
        Ok(())
    }

    /// Invoke the user-provided lock callback, if one is set.
    ///
    /// Used by easy handles to acquire a user-level lock before accessing
    /// shared data.  In pure Rust mode, this is typically a no-op because
    /// the `Mutex` on each resource provides synchronization.
    #[allow(dead_code)]
    pub(crate) fn lock(
        &self,
        lock_data: CurlShareLock,
        access: LockAccess,
    ) -> Result<(), CurlSHcode> {
        let data = self.inner.lock().map_err(|_| CurlSHcode::Invalid)?;

        // Only invoke the callback if this data type is shared and a
        // lock function is registered.
        if data.is_sharing(lock_data) {
            if let Some(ref func) = data.lock_func {
                func(lock_data, access, data.user_data);
            }
        }
        Ok(())
    }

    /// Invoke the user-provided unlock callback, if one is set.
    ///
    /// Used by easy handles to release a user-level lock after accessing
    /// shared data.
    #[allow(dead_code)]
    pub(crate) fn unlock(&self, lock_data: CurlShareLock) -> Result<(), CurlSHcode> {
        let data = self.inner.lock().map_err(|_| CurlSHcode::Invalid)?;

        if data.is_sharing(lock_data) {
            if let Some(ref func) = data.unlock_func {
                func(lock_data, data.user_data);
            }
        }
        Ok(())
    }

    /// Returns a clone of the inner `Arc` for direct access to the shared
    /// data (used by internal subsystems that need to check multiple fields
    /// atomically).
    #[allow(dead_code)]
    pub(crate) fn inner(&self) -> Arc<Mutex<ShareData>> {
        Arc::clone(&self.inner)
    }
}

impl Clone for ShareHandle {
    /// Cloning a share handle produces a new handle pointing to the same
    /// underlying shared data.  Both handles share the same `Arc` and
    /// `Mutex`.
    fn clone(&self) -> Self {
        ShareHandle {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Default for ShareHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ShareHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.inner.lock() {
            Ok(data) => f
                .debug_struct("ShareHandle")
                .field("data", &*data)
                .finish(),
            Err(_) => f
                .debug_struct("ShareHandle")
                .field("data", &"<poisoned>")
                .finish(),
        }
    }
}

impl fmt::Display for ShareHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.inner.lock() {
            Ok(data) => {
                let mut shared = Vec::new();
                if data.is_sharing(CurlShareLock::Cookie) {
                    shared.push("cookies");
                }
                if data.is_sharing(CurlShareLock::Dns) {
                    shared.push("DNS");
                }
                if data.is_sharing(CurlShareLock::SslSession) {
                    shared.push("SSL sessions");
                }
                if data.is_sharing(CurlShareLock::Connect) {
                    shared.push("connections");
                }
                if data.is_sharing(CurlShareLock::Psl) {
                    shared.push("PSL");
                }
                if data.is_sharing(CurlShareLock::Hsts) {
                    shared.push("HSTS");
                }
                if shared.is_empty() {
                    write!(f, "ShareHandle(sharing nothing)")
                } else {
                    write!(f, "ShareHandle(sharing: {})", shared.join(", "))
                }
            }
            Err(_) => write!(f, "ShareHandle(<poisoned>)"),
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- CurlShareLock discriminant values ----------------------------------

    #[test]
    fn share_lock_integer_values_match_c() {
        assert_eq!(CurlShareLock::Cookie as i32, 2);
        assert_eq!(CurlShareLock::Dns as i32, 3);
        assert_eq!(CurlShareLock::SslSession as i32, 4);
        assert_eq!(CurlShareLock::Connect as i32, 5);
        assert_eq!(CurlShareLock::Psl as i32, 6);
        assert_eq!(CurlShareLock::Hsts as i32, 7);
    }

    #[test]
    fn share_lock_from_i32_round_trips() {
        for val in 2..=7 {
            let lock = CurlShareLock::from_i32(val).unwrap();
            assert_eq!(lock as i32, val);
        }
        assert!(CurlShareLock::from_i32(0).is_none());
        assert!(CurlShareLock::from_i32(1).is_none());
        assert!(CurlShareLock::from_i32(8).is_none());
        assert!(CurlShareLock::from_i32(-1).is_none());
    }

    // -- CurlShOption discriminant values -----------------------------------

    #[test]
    fn share_option_integer_values_match_c() {
        assert_eq!(CurlShOption::Share as i32, 1);
        assert_eq!(CurlShOption::Unshare as i32, 2);
        assert_eq!(CurlShOption::LockFunc as i32, 3);
        assert_eq!(CurlShOption::UnlockFunc as i32, 4);
        assert_eq!(CurlShOption::UserData as i32, 5);
    }

    #[test]
    fn share_option_from_i32_round_trips() {
        for val in 1..=5 {
            let opt = CurlShOption::from_i32(val).unwrap();
            assert_eq!(opt as i32, val);
        }
        assert!(CurlShOption::from_i32(0).is_none());
        assert!(CurlShOption::from_i32(6).is_none());
    }

    // -- ShareHandle construction -------------------------------------------

    #[test]
    fn new_share_has_no_shared_data() {
        let share = ShareHandle::new();
        assert!(!share.is_sharing(CurlShareLock::Cookie));
        assert!(!share.is_sharing(CurlShareLock::Dns));
        assert!(!share.is_sharing(CurlShareLock::SslSession));
        assert!(!share.is_sharing(CurlShareLock::Connect));
        assert!(!share.is_sharing(CurlShareLock::Psl));
        assert!(!share.is_sharing(CurlShareLock::Hsts));
    }

    #[test]
    fn new_share_has_no_resources() {
        let share = ShareHandle::new();
        #[cfg(feature = "cookies")]
        assert!(share.get_cookies().is_none());
        assert!(share.get_dns_cache().is_none());
        assert!(share.get_connection_pool().is_none());
        assert!(share.get_session_cache().is_none());
        assert!(share.get_psl().is_none());
        assert!(share.get_hsts().is_none());
    }

    // -- set_option: Share --------------------------------------------------

    #[cfg(feature = "cookies")]
    #[test]
    fn share_cookie_creates_jar() {
        let share = ShareHandle::new();
        share.set_option(CurlShOption::Share, CurlShareLock::Cookie).unwrap();
        assert!(share.is_sharing(CurlShareLock::Cookie));
        assert!(share.get_cookies().is_some());
    }

    #[test]
    fn share_dns_creates_cache() {
        let share = ShareHandle::new();
        share.set_option(CurlShOption::Share, CurlShareLock::Dns).unwrap();
        assert!(share.is_sharing(CurlShareLock::Dns));
        assert!(share.get_dns_cache().is_some());
    }

    #[test]
    fn share_ssl_session_creates_cache() {
        let share = ShareHandle::new();
        share.set_option(CurlShOption::Share, CurlShareLock::SslSession).unwrap();
        assert!(share.is_sharing(CurlShareLock::SslSession));
        assert!(share.get_session_cache().is_some());
    }

    #[test]
    fn share_connect_creates_pool() {
        let share = ShareHandle::new();
        share.set_option(CurlShOption::Share, CurlShareLock::Connect).unwrap();
        assert!(share.is_sharing(CurlShareLock::Connect));
        assert!(share.get_connection_pool().is_some());
    }

    #[test]
    fn share_psl_creates_checker() {
        let share = ShareHandle::new();
        share.set_option(CurlShOption::Share, CurlShareLock::Psl).unwrap();
        assert!(share.is_sharing(CurlShareLock::Psl));
        assert!(share.get_psl().is_some());
    }

    #[test]
    fn share_hsts_creates_cache() {
        let share = ShareHandle::new();
        share.set_option(CurlShOption::Share, CurlShareLock::Hsts).unwrap();
        assert!(share.is_sharing(CurlShareLock::Hsts));
        assert!(share.get_hsts().is_some());
    }

    // -- set_option: Unshare ------------------------------------------------

    #[cfg(feature = "cookies")]
    #[test]
    fn unshare_removes_resource() {
        let share = ShareHandle::new();
        share.set_option(CurlShOption::Share, CurlShareLock::Cookie).unwrap();
        assert!(share.get_cookies().is_some());

        share.set_option(CurlShOption::Unshare, CurlShareLock::Cookie).unwrap();
        assert!(!share.is_sharing(CurlShareLock::Cookie));
        assert!(share.get_cookies().is_none());
    }

    #[test]
    fn unshare_dns_removes_cache() {
        let share = ShareHandle::new();
        share.set_option(CurlShOption::Share, CurlShareLock::Dns).unwrap();
        share.set_option(CurlShOption::Unshare, CurlShareLock::Dns).unwrap();
        assert!(!share.is_sharing(CurlShareLock::Dns));
        assert!(share.get_dns_cache().is_none());
    }

    #[test]
    fn unshare_hsts_removes_cache() {
        let share = ShareHandle::new();
        share.set_option(CurlShOption::Share, CurlShareLock::Hsts).unwrap();
        share.set_option(CurlShOption::Unshare, CurlShareLock::Hsts).unwrap();
        assert!(!share.is_sharing(CurlShareLock::Hsts));
        assert!(share.get_hsts().is_none());
    }

    // -- set_option with dirty handle ---------------------------------------

    #[test]
    fn set_option_fails_when_in_use() {
        let share = ShareHandle::new();
        share.attach().unwrap();
        let result = share.set_option(CurlShOption::Share, CurlShareLock::Cookie);
        assert_eq!(result, Err(CurlSHcode::InUse));
        share.detach().unwrap();
    }

    // -- cleanup ------------------------------------------------------------

    #[test]
    fn cleanup_succeeds_when_not_in_use() {
        let share = ShareHandle::new();
        share.set_option(CurlShOption::Share, CurlShareLock::Cookie).unwrap();
        share.set_option(CurlShOption::Share, CurlShareLock::Dns).unwrap();
        share.cleanup().unwrap();
        assert!(!share.is_sharing(CurlShareLock::Cookie));
        assert!(!share.is_sharing(CurlShareLock::Dns));
    }

    #[test]
    fn cleanup_fails_when_in_use() {
        let share = ShareHandle::new();
        share.attach().unwrap();
        let result = share.cleanup();
        assert_eq!(result, Err(CurlSHcode::InUse));
        share.detach().unwrap();
    }

    // -- strerror -----------------------------------------------------------

    #[test]
    fn strerror_matches_c_strings() {
        assert_eq!(ShareHandle::strerror(CurlSHcode::Ok), "No error");
        assert_eq!(ShareHandle::strerror(CurlSHcode::BadOption), "Unknown share option");
        assert_eq!(ShareHandle::strerror(CurlSHcode::InUse), "Share currently in use");
        assert_eq!(ShareHandle::strerror(CurlSHcode::Invalid), "Invalid share handle");
        assert_eq!(ShareHandle::strerror(CurlSHcode::NoMem), "Out of memory");
        assert_eq!(
            ShareHandle::strerror(CurlSHcode::NotBuiltIn),
            "Feature not enabled in this library"
        );
    }

    // -- attach / detach ----------------------------------------------------

    #[test]
    fn attach_detach_cycle() {
        let share = ShareHandle::new();
        share.attach().unwrap();
        share.attach().unwrap();
        // Cannot cleanup while attached.
        assert_eq!(share.cleanup(), Err(CurlSHcode::InUse));
        share.detach().unwrap();
        // Still one attachment remaining.
        assert_eq!(share.cleanup(), Err(CurlSHcode::InUse));
        share.detach().unwrap();
        // Now cleanup succeeds.
        share.cleanup().unwrap();
    }

    // -- lock/unlock callbacks ----------------------------------------------

    #[test]
    fn lock_func_option_is_noop() {
        let share = ShareHandle::new();
        // LockFunc/UnlockFunc/UserData through set_option are no-ops in
        // pure Rust mode.
        share
            .set_option(CurlShOption::LockFunc, CurlShareLock::Cookie)
            .unwrap();
        share
            .set_option(CurlShOption::UnlockFunc, CurlShareLock::Cookie)
            .unwrap();
        share
            .set_option(CurlShOption::UserData, CurlShareLock::Cookie)
            .unwrap();
    }

    #[test]
    fn dedicated_lock_func_setter_works() {
        let share = ShareHandle::new();
        share.set_option(CurlShOption::Share, CurlShareLock::Cookie).unwrap();

        let lock_called = Arc::new(Mutex::new(false));
        let lock_called_clone = Arc::clone(&lock_called);
        share
            .set_lock_func(Some(Box::new(move |_data, _access, _udata| {
                *lock_called_clone.lock().unwrap() = true;
            })))
            .unwrap();

        // Invoke the lock callback internally.
        share.lock(CurlShareLock::Cookie, LockAccess::Single).unwrap();
        assert!(*lock_called.lock().unwrap());
    }

    // -- Display / Debug ----------------------------------------------------

    #[test]
    fn display_shows_shared_types() {
        let share = ShareHandle::new();
        assert!(share.to_string().contains("nothing"));

        share.set_option(CurlShOption::Share, CurlShareLock::Cookie).unwrap();
        share.set_option(CurlShOption::Share, CurlShareLock::Dns).unwrap();
        let display = share.to_string();
        assert!(display.contains("cookies"));
        assert!(display.contains("DNS"));
    }

    #[test]
    fn debug_format_works() {
        let share = ShareHandle::new();
        let debug_str = format!("{:?}", share);
        assert!(debug_str.contains("ShareHandle"));
    }

    // -- Clone semantics ----------------------------------------------------

    #[test]
    fn clone_shares_same_data() {
        let share = ShareHandle::new();
        share.set_option(CurlShOption::Share, CurlShareLock::Cookie).unwrap();

        let cloned = share.clone();
        assert!(cloned.is_sharing(CurlShareLock::Cookie));

        // Modifying through one handle is visible through the other.
        cloned.set_option(CurlShOption::Share, CurlShareLock::Dns).unwrap();
        assert!(share.is_sharing(CurlShareLock::Dns));
    }

    // -- Idempotent sharing -------------------------------------------------

    #[cfg(feature = "cookies")]
    #[test]
    fn share_same_type_twice_is_idempotent() {
        let share = ShareHandle::new();
        share.set_option(CurlShOption::Share, CurlShareLock::Cookie).unwrap();
        let jar1 = share.get_cookies().unwrap();
        share.set_option(CurlShOption::Share, CurlShareLock::Cookie).unwrap();
        let jar2 = share.get_cookies().unwrap();
        // Should be the same Arc (same underlying allocation).
        assert!(Arc::ptr_eq(&jar1, &jar2));
    }

    // -- Default trait ------------------------------------------------------

    #[test]
    fn default_creates_empty_share() {
        let share: ShareHandle = Default::default();
        assert!(!share.is_sharing(CurlShareLock::Cookie));
    }

    // -- LockAccess values --------------------------------------------------

    #[test]
    fn lock_access_values_match_c() {
        assert_eq!(LockAccess::None as i32, 0);
        assert_eq!(LockAccess::Shared as i32, 1);
        assert_eq!(LockAccess::Single as i32, 2);
    }

    // -- Multiple data types shared simultaneously --------------------------

    #[test]
    fn share_all_types() {
        let share = ShareHandle::new();
        share.set_option(CurlShOption::Share, CurlShareLock::Cookie).unwrap();
        share.set_option(CurlShOption::Share, CurlShareLock::Dns).unwrap();
        share.set_option(CurlShOption::Share, CurlShareLock::SslSession).unwrap();
        share.set_option(CurlShOption::Share, CurlShareLock::Connect).unwrap();
        share.set_option(CurlShOption::Share, CurlShareLock::Psl).unwrap();
        share.set_option(CurlShOption::Share, CurlShareLock::Hsts).unwrap();

        assert!(share.is_sharing(CurlShareLock::Cookie));
        assert!(share.is_sharing(CurlShareLock::Dns));
        assert!(share.is_sharing(CurlShareLock::SslSession));
        assert!(share.is_sharing(CurlShareLock::Connect));
        assert!(share.is_sharing(CurlShareLock::Psl));
        assert!(share.is_sharing(CurlShareLock::Hsts));

        #[cfg(feature = "cookies")]
        assert!(share.get_cookies().is_some());
        assert!(share.get_dns_cache().is_some());
        assert!(share.get_session_cache().is_some());
        assert!(share.get_connection_pool().is_some());
        assert!(share.get_psl().is_some());
        assert!(share.get_hsts().is_some());
    }

    // -- Thread safety smoke test -------------------------------------------

    #[test]
    fn share_handle_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ShareHandle>();
    }
}
