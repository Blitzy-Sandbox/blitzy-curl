// Shared-state handle (`curl_share` / `CURLSH`) for the curl-rs workspace.
//
// SPDX-License-Identifier: curl
//
// This file is a memory-safe Rust reimplementation of curl's share interface
// (`lib/curl_share.c` plus the public `CURLSH` / `CURLSHcode` / `CURLSHoption`
// / `CURL_LOCK_DATA_*` declarations in `include/curl/curl.h`). The original C
// sources are
//   Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// and are licensed under the curl license (https://curl.se/docs/copyright.html).
// This Rust port preserves the observable behavior and the public result codes
// of the share interface; it is a behavioral translation, not a line-by-line
// one (AAP §0.4.3 / §0.7.1).

//! The shared-state handle — the safe replacement for libcurl's `curl_share`
//! (`CURLSH`, `lib/curl_share.c`).
//!
//! # What the share interface is
//!
//! A *share* lets several easy handles cooperate by pooling state that would
//! otherwise be private to each handle. curl supports sharing six kinds of
//! data, enumerated by `CURL_LOCK_DATA_*`: the cookie jar, the DNS cache, the
//! TLS session-ID cache, the connection cache, the HSTS store, and the Public
//! Suffix List. An application creates a share with `curl_share_init`, selects
//! which data types to share with `curl_share_setopt(CURLSHOPT_SHARE, …)`,
//! attaches the share to one or more easy handles (`CURLOPT_SHARE`), and tears
//! it down with `curl_share_cleanup` once no handle references it.
//!
//! In C the handle is an opaque, reference-counted `struct Curl_share` whose
//! concurrency is delegated to a pair of caller-supplied lock/unlock callbacks
//! (`CURLSHOPT_LOCKFUNC` / `CURLSHOPT_UNLOCKFUNC`): libcurl calls them around
//! every access to a shared resource and the application is responsible for the
//! actual mutual exclusion. Forgetting to set the callbacks while sharing from
//! multiple threads is a classic data race.
//!
//! # The Rust model: `Arc<Mutex<…>>` instead of refcount + callbacks
//!
//! This port replaces the manual reference count and the caller-supplied lock
//! callbacks with Rust's own thread-safe primitives (AAP §0.4.3):
//!
//! * The handle is an [`Arc`] — cloning it to attach the share to another easy
//!   handle is a cheap atomic reference-count bump, and the shared state is
//!   freed deterministically when the last clone is dropped (this is the safe
//!   analogue of curl's refcount + `curl_share_cleanup` free).
//! * Each shared resource lives behind its **own** [`Mutex`] (an
//!   `Arc<Mutex<CookieJar>>`, `Arc<Mutex<HstsStore>>`, …), preserving curl's
//!   *per-data-type* locking granularity: concurrent transfers contend only on
//!   the specific resource they touch, never on an unrelated one.
//! * Data-race freedom is therefore guaranteed *by construction* — the borrow
//!   checker and the `Mutex` make a missing-lock data race impossible, so the
//!   correctness of the share no longer depends on the application wiring up
//!   lock callbacks correctly.
//!
//! ## User lock callbacks are still honored (API compatibility)
//!
//! Because the C ABI exposes `CURLSHOPT_LOCKFUNC` / `CURLSHOPT_UNLOCKFUNC` /
//! `CURLSHOPT_USERDATA`, existing applications still pass them, and some use the
//! callbacks for their own bookkeeping (metrics, tracing). The share therefore
//! still *stores* the callback addresses and the user-data pointer so the FFI
//! layer (`curl-rs-ffi`) can invoke them around accesses for behavioral
//! compatibility. They are advisory only: the data integrity of every shared
//! resource is guaranteed by its [`Mutex`], not by the callbacks. The callback
//! addresses are stored as plain integers ([`usize`]) so that [`SharedData`]
//! remains [`Send`] + [`Sync`] (a raw `*mut` field would not be); reconstituting
//! a real C function pointer from the integer is an `unsafe` operation that
//! lives exclusively in `curl-rs-ffi`.
//!
//! # Memory safety
//!
//! This module contains **zero `unsafe`** and carries `#![forbid(unsafe_code)]`.
//! The opaque `CURLSH*` pointer ⇄ [`Box`]/[`Arc`] conversion, the variadic
//! `curl_share_setopt` trailing-argument decoding, and the lock-callback
//! invocation are all performed in `curl-rs-ffi`; this crate exposes only safe,
//! strongly typed methods (AAP §0.7.1).
//!
//! # Result codes
//!
//! Every fallible method returns [`crate::error::CurlShError`], whose integer
//! values are exactly curl's `CURLSHcode` (`CURLSHE_OK` = 0 … `CURLSHE_NOT_BUILT_IN`
//! = 5). The `CURLSHE_INVALID` code (a NULL / corrupt handle) is produced at the
//! FFI boundary — a `&Share` is always valid here — so the methods below never
//! return it themselves.
//!
//! # Capability gating
//!
//! Sharing the cookie jar, the HSTS store, or the PSL requires the corresponding
//! capability to be compiled in, mirroring curl's `#ifdef` gates
//! (`CURL_DISABLE_COOKIES`, `CURL_DISABLE_HSTS`, `USE_LIBPSL`). Those subsystems
//! are Cargo features (`cookies`, `hsts`, `psl`, all default-on); when a feature
//! is disabled, requesting its data type returns
//! [`CurlShError::NotBuiltIn`](crate::error::CurlShError::NotBuiltIn), exactly as
//! the C build returns `CURLSHE_NOT_BUILT_IN`.

#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex, RwLock};

// `crate::error::CurlShError` is the share result-code enum; its discriminants
// are the exact `CURLSHcode` integers consumed at the FFI boundary.
use crate::error::CurlShError;

// The Public Suffix List handle is always available (the `Psl` type has a
// zero-sized fallback when the `psl` feature is off — see `crate::psl`).
use crate::psl::Psl;

// The cookie jar and HSTS store types only exist when their feature is enabled
// (their whole module is `#![cfg(feature = "…")]`), so the imports — and every
// use of them below — are gated identically. With the feature off, requesting
// that data type yields `CURLSHE_NOT_BUILT_IN`, matching curl's `#ifdef`.
#[cfg(feature = "cookies")]
use crate::cookie::CookieJar;
#[cfg(feature = "hsts")]
use crate::hsts::HstsStore;

// ===========================================================================
// CURL_LOCK_DATA_* — the shareable data types
// ===========================================================================

/// The kind of state a share can pool, mirroring C's `curl_lock_data`
/// (`include/curl/curl.h`).
///
/// The discriminants are the exact C integer values: they are used both as the
/// `CURLSHOPT_SHARE` / `CURLSHOPT_UNSHARE` selector and — as `1 << value` — as
/// the bit position in the share's "specifier" bitmask of currently shared
/// types.
///
/// [`LockData::Share`] is reserved for curl's internal use (it marks a lock that
/// protects the share's own metadata rather than a user-visible resource) and is
/// set in the specifier from construction, exactly as `curl_share_init` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum LockData {
    /// `CURL_LOCK_DATA_NONE` (0) — unspecified; never shared.
    None = 0,
    /// `CURL_LOCK_DATA_SHARE` (1) — internal: the share's own metadata lock.
    Share = 1,
    /// `CURL_LOCK_DATA_COOKIE` (2) — the cookie jar.
    Cookie = 2,
    /// `CURL_LOCK_DATA_DNS` (3) — the DNS / host-name cache.
    Dns = 3,
    /// `CURL_LOCK_DATA_SSL_SESSION` (4) — the TLS session-ID cache.
    SslSession = 4,
    /// `CURL_LOCK_DATA_CONNECT` (5) — the connection cache / pool.
    Connect = 5,
    /// `CURL_LOCK_DATA_PSL` (6) — the Public Suffix List.
    Psl = 6,
    /// `CURL_LOCK_DATA_HSTS` (7) — the HTTP Strict-Transport-Security store.
    Hsts = 7,
}

impl LockData {
    /// Returns the exact C `curl_lock_data` integer for this data type.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// Returns the bit position of this data type in the share's specifier
    /// bitmask — `1 << value`, matching curl's `share->specifier`.
    #[must_use]
    pub const fn bit(self) -> u32 {
        // The discriminant is always in `0..=7`, so the shift can never overflow
        // a `u32`; this is why the specifier math needs no `unsafe` and no
        // saturation, unlike the C `1 << type` on an arbitrary `int`.
        1u32 << (self as u32)
    }

    /// Builds a [`LockData`] from a raw `curl_lock_data` integer.
    ///
    /// Returns `None` for any value outside the defined range (`0..=7`); the
    /// `CURLSHOPT_SHARE` / `CURLSHOPT_UNSHARE` dispatch maps that `None` to
    /// [`CurlShError::BadOption`], exactly as curl's `default:` switch arm does.
    #[must_use]
    pub const fn from_i32(value: i32) -> Option<LockData> {
        match value {
            0 => Some(LockData::None),
            1 => Some(LockData::Share),
            2 => Some(LockData::Cookie),
            3 => Some(LockData::Dns),
            4 => Some(LockData::SslSession),
            5 => Some(LockData::Connect),
            6 => Some(LockData::Psl),
            7 => Some(LockData::Hsts),
            _ => None,
        }
    }
}

// ===========================================================================
// CURL_LOCK_ACCESS_* — the lock access type
// ===========================================================================

/// The access mode requested when locking a shared resource, mirroring C's
/// `curl_lock_access` (`include/curl/curl.h`).
///
/// This is passed as the third argument to the user lock callback. With the
/// `Arc<Mutex<…>>` model the distinction is advisory — a `Mutex` grants
/// exclusive access regardless — but the value is preserved so the FFI layer can
/// hand the application the same access hint curl would (e.g. so a reader/writer
/// lock the application maintains for metrics can pick the right mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum LockAccess {
    /// `CURL_LOCK_ACCESS_NONE` (0) — unspecified action.
    None = 0,
    /// `CURL_LOCK_ACCESS_SHARED` (1) — shared/read access ("for read perhaps").
    Shared = 1,
    /// `CURL_LOCK_ACCESS_SINGLE` (2) — exclusive/write access ("for write perhaps").
    Single = 2,
}

impl LockAccess {
    /// Returns the exact C `curl_lock_access` integer for this access mode.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// Builds a [`LockAccess`] from a raw `curl_lock_access` integer.
    ///
    /// Returns `None` for any value outside the defined range (`0..=2`).
    #[must_use]
    pub const fn from_i32(value: i32) -> Option<LockAccess> {
        match value {
            0 => Some(LockAccess::None),
            1 => Some(LockAccess::Shared),
            2 => Some(LockAccess::Single),
            _ => None,
        }
    }
}

// ===========================================================================
// CURLSHoption — the share-handle option selectors
// ===========================================================================

/// A `curl_share_setopt` option selector, mirroring C's `CURLSHoption`
/// (`include/curl/curl.h`).
///
/// This type identifies *which* knob is being set; the accompanying value is
/// carried by [`ShareSetting`], which fuses the option with its value so that an
/// option can never be paired with the wrong value kind. It exists primarily so
/// the FFI layer can map the raw C `CURLSHoption` integer it receives onto the
/// typed [`ShareSetting`] (any integer that does not map — including
/// [`ShareOption::None`] — is reported as [`CurlShError::BadOption`], matching
/// curl's `default:` switch arm).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ShareOption {
    /// `CURLSHOPT_NONE` (0) — not a usable option.
    None = 0,
    /// `CURLSHOPT_SHARE` (1) — start sharing a data type.
    Share = 1,
    /// `CURLSHOPT_UNSHARE` (2) — stop sharing a data type.
    Unshare = 2,
    /// `CURLSHOPT_LOCKFUNC` (3) — set the lock callback.
    LockFunc = 3,
    /// `CURLSHOPT_UNLOCKFUNC` (4) — set the unlock callback.
    UnlockFunc = 4,
    /// `CURLSHOPT_USERDATA` (5) — set the user-data pointer.
    UserData = 5,
}

impl ShareOption {
    /// Returns the exact C `CURLSHoption` integer for this option.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// Builds a [`ShareOption`] from a raw `CURLSHoption` integer.
    ///
    /// Returns `None` for any value outside the defined range (`0..=5`). The FFI
    /// layer treats that `None` as [`CurlShError::BadOption`].
    #[must_use]
    pub const fn from_i32(value: i32) -> Option<ShareOption> {
        match value {
            0 => Some(ShareOption::None),
            1 => Some(ShareOption::Share),
            2 => Some(ShareOption::Unshare),
            3 => Some(ShareOption::LockFunc),
            4 => Some(ShareOption::UnlockFunc),
            5 => Some(ShareOption::UserData),
            _ => None,
        }
    }
}

// ===========================================================================
// ShareSetting — a fused (option, value) pair for `setopt`
// ===========================================================================

/// A strongly typed `curl_share_setopt` request — the option fused with its
/// single trailing argument.
///
/// `curl_share_setopt(share, option, …)` is C-variadic: the type of the trailing
/// argument depends on `option` (an `int` data-type selector for
/// `CURLSHOPT_SHARE` / `CURLSHOPT_UNSHARE`, a function pointer for the lock/unlock
/// callbacks, a `void*` for the user data). Modeling each option together with
/// its value makes a mismatched pairing unrepresentable, which is the safe
/// counterpart of the C variadic decoding the FFI layer performs.
///
/// The `Share` / `Unshare` variants carry the **raw** `i32` data-type selector
/// (not a [`LockData`]) so that the "unknown data type ⇒ [`CurlShError::BadOption`]"
/// decision happens — and is unit-tested — inside [`Share::setopt`], exactly
/// where curl's `switch(type) { … default: … }` makes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareSetting {
    /// `CURLSHOPT_SHARE`: begin sharing the data type with this raw
    /// `curl_lock_data` selector.
    Share(i32),
    /// `CURLSHOPT_UNSHARE`: stop sharing the data type with this raw
    /// `curl_lock_data` selector.
    Unshare(i32),
    /// `CURLSHOPT_LOCKFUNC`: set (or, with `None`, clear) the lock callback,
    /// given as a raw function-pointer address (see the module docs on why this
    /// is a [`usize`] rather than a function pointer).
    LockFunc(Option<usize>),
    /// `CURLSHOPT_UNLOCKFUNC`: set (or clear) the unlock callback address.
    UnlockFunc(Option<usize>),
    /// `CURLSHOPT_USERDATA`: set the user-data pointer address passed to the
    /// lock/unlock callbacks (`0` denotes a NULL pointer).
    UserData(usize),
}

// ===========================================================================
// SharedData — the inner, lock-protected state of a share handle
// ===========================================================================

/// The mutable inner state of a [`Share`], protected by the share's [`RwLock`].
///
/// This is the safe analogue of C's `struct Curl_share`. Each shareable resource
/// that this crate owns a concrete type for (the cookie jar, the HSTS store, the
/// PSL) lives behind its **own** [`Arc<Mutex<…>>`] so that locking is per
/// data type, exactly as in curl. The remaining curl-shared resources — the DNS
/// cache (`CURL_LOCK_DATA_DNS`), the TLS session cache
/// (`CURL_LOCK_DATA_SSL_SESSION`) and the connection pool
/// (`CURL_LOCK_DATA_CONNECT`) — are tracked only by their bit in [`specifier`]
/// here: their concrete stores are owned by the engine modules that are wired up
/// by sibling migration steps, and those modules consult [`Share::is_sharing`]
/// to decide whether to use the shared instance. Recording the *intent* to share
/// them in the specifier is precisely what curl's `share->specifier` does.
///
/// [`specifier`]: SharedData::specifier
#[derive(Debug)]
struct SharedData {
    /// Bitmask of currently shared data types: bit `LockData::X.bit()` is set
    /// while type `X` is shared. Mirrors curl's `share->specifier`. The
    /// `LockData::Share` bit is set from construction (curl sets it in
    /// `curl_share_init`).
    specifier: u32,

    /// Number of easy handles currently attached to this share. While this is
    /// non-zero the share is "in use" and both [`Share::setopt`] and
    /// [`Share::cleanup`] refuse to proceed, returning [`CurlShError::InUse`].
    /// This is the safe counterpart of curl's `share->dirty` flag (here a count
    /// so that attaching and detaching multiple handles is balanced exactly).
    users: usize,

    /// The shared cookie jar, allocated when `CURL_LOCK_DATA_COOKIE` is shared
    /// and freed when it is unshared (or when the share is dropped). Present
    /// only when the `cookies` capability is compiled in.
    #[cfg(feature = "cookies")]
    cookies: Option<Arc<Mutex<CookieJar>>>,

    /// The shared HSTS store, allocated when `CURL_LOCK_DATA_HSTS` is shared.
    /// Present only when the `hsts` capability is compiled in.
    #[cfg(feature = "hsts")]
    hsts: Option<Arc<Mutex<HstsStore>>>,

    /// The shared Public Suffix List, allocated when `CURL_LOCK_DATA_PSL` is
    /// shared. Present only when the `psl` capability is compiled in.
    #[cfg(feature = "psl")]
    psl: Option<Arc<Mutex<Psl>>>,

    /// Address of the user `curl_lock_function`, or `None` if unset. Stored as a
    /// plain integer to keep `SharedData: Send + Sync`; the FFI layer turns it
    /// back into a callable C function pointer (see the module docs).
    lock_fn: Option<usize>,

    /// Address of the user `curl_unlock_function`, or `None` if unset.
    unlock_fn: Option<usize>,

    /// Address of the user-data `void*` passed to the lock/unlock callbacks
    /// (`0` denotes NULL). Mirrors curl's `share->clientdata`.
    user_data: usize,
}

impl SharedData {
    /// Builds the initial inner state of a freshly created share.
    ///
    /// Mirrors the field initialization in `curl_share_init`: every resource
    /// starts unshared, the user callbacks start unset, and the internal
    /// `CURL_LOCK_DATA_SHARE` bit is pre-set in the specifier.
    fn new() -> SharedData {
        SharedData {
            specifier: LockData::Share.bit(),
            users: 0,
            #[cfg(feature = "cookies")]
            cookies: None,
            #[cfg(feature = "hsts")]
            hsts: None,
            #[cfg(feature = "psl")]
            psl: None,
            lock_fn: None,
            unlock_fn: None,
            user_data: 0,
        }
    }
}

// ===========================================================================
// Share — the public, clonable share handle
// ===========================================================================

/// A shared-state handle — the safe, thread-safe replacement for libcurl's
/// opaque `CURLSH` (`curl_share_init` / `curl_share_setopt` /
/// `curl_share_cleanup`).
///
/// A `Share` is a thin, cheaply clonable wrapper around an
/// [`Arc<RwLock<SharedData>>`]. Cloning it — which is how the same share is
/// attached to several easy handles — is an atomic reference-count bump; all
/// clones observe the same shared state. When the last clone is dropped the
/// inner state, and with it every shared resource, is freed deterministically
/// (the safe analogue of `curl_share_cleanup`'s final `free`).
///
/// # Concurrency
///
/// `Share` is [`Send`] + [`Sync`]: it may be moved to, and used concurrently
/// from, multiple threads. The handle metadata (the specifier, the in-use count,
/// the callback addresses) is guarded by the outer [`RwLock`]; each shared
/// resource is independently guarded by its own [`Mutex`], so transfers contend
/// only on the specific resource they touch.
///
/// # Method receivers
///
/// Every mutating method takes `&self`, not `&mut self`: a `Share` is an
/// `Arc`-backed handle that is intentionally aliased across easy handles and
/// threads, so exclusive `&mut` access is neither available nor desired.
/// Mutation goes through the interior [`RwLock`]/[`Mutex`], which is the
/// idiomatic Rust expression of the shared, internally-synchronized handle that
/// curl implements in C with a refcount and lock callbacks.
#[derive(Debug, Clone)]
pub struct Share {
    inner: Arc<RwLock<SharedData>>,
}

impl Default for Share {
    fn default() -> Self {
        Share::new()
    }
}

impl Share {
    // -- lock helpers --------------------------------------------------------
    //
    // `std`'s `RwLock` becomes "poisoned" if a thread panics while holding the
    // guard. Our invariant is structural — the protected data is never left in a
    // logically invalid state by any method here — so recovering the inner data
    // after a panic is safe and strictly better than propagating the poison as a
    // panic of its own. Both helpers therefore recover via `into_inner()` rather
    // than `unwrap()`, so no method on `Share` can panic on a poisoned lock.

    /// Acquires a shared (read) guard on the inner state, recovering from lock
    /// poisoning.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, SharedData> {
        self.inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Acquires an exclusive (write) guard on the inner state, recovering from
    /// lock poisoning.
    fn write(&self) -> std::sync::RwLockWriteGuard<'_, SharedData> {
        self.inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    // -- construction --------------------------------------------------------

    /// Creates a new, empty share handle — the equivalent of `curl_share_init`.
    ///
    /// No data types are shared yet (apart from the internal
    /// `CURL_LOCK_DATA_SHARE` marker), no user lock callbacks are set, and the
    /// handle is not in use. Sharing of specific resources is enabled with
    /// [`setopt`](Share::setopt) / [`share_data`](Share::share_data).
    ///
    /// Unlike curl's `curl_share_init`, this never returns "out of memory":
    /// allocation failure aborts the process in Rust rather than yielding a NULL
    /// handle, so the FFI shim treats this as infallible.
    #[must_use]
    pub fn new() -> Share {
        Share {
            inner: Arc::new(RwLock::new(SharedData::new())),
        }
    }

    // -- option setting (curl_share_setopt) ----------------------------------

    /// Applies a share option — the equivalent of `curl_share_setopt`.
    ///
    /// The option and its value are carried together by [`ShareSetting`]; see
    /// the convenience wrappers [`share_data`](Share::share_data),
    /// [`unshare_data`](Share::unshare_data),
    /// [`set_lock_function`](Share::set_lock_function),
    /// [`set_unlock_function`](Share::set_unlock_function) and
    /// [`set_user_data`](Share::set_user_data) for typed entry points.
    ///
    /// # Behavior (mirrors `curl_share_setopt`)
    ///
    /// * If any easy handle is currently attached (the share is "in use"), the
    ///   call is rejected with [`CurlShError::InUse`] — curl performs this
    ///   `share->dirty` check before touching any option.
    /// * `Share(type)` / `Unshare(type)` enable / disable sharing of a data
    ///   type. An unknown selector, or one of the non-settable selectors
    ///   ([`LockData::None`] / the internal [`LockData::Share`] marker), yields
    ///   [`CurlShError::BadOption`]. A data type whose capability is compiled
    ///   out yields [`CurlShError::NotBuiltIn`].
    /// * `LockFunc` / `UnlockFunc` / `UserData` store the user lock callbacks and
    ///   user-data pointer and always succeed.
    ///
    /// # Errors
    ///
    /// Returns [`CurlShError::InUse`], [`CurlShError::BadOption`] or
    /// [`CurlShError::NotBuiltIn`] as described above.
    pub fn setopt(&self, setting: ShareSetting) -> Result<(), CurlShError> {
        // A single write guard covers the in-use check and the mutation, so the
        // check and the change are atomic (curl's C version is not, but holding
        // the lock for the whole call is strictly safer and just as correct).
        let mut data = self.write();

        // curl: `if(share->dirty) return CURLSHE_IN_USE;` — refuse to reconfigure
        // a share while handles are using it, for EVERY option.
        if data.users > 0 {
            return Err(CurlShError::InUse);
        }

        match setting {
            ShareSetting::Share(data_type) => Self::enable_share(&mut data, data_type),
            ShareSetting::Unshare(data_type) => Self::disable_share(&mut data, data_type),
            ShareSetting::LockFunc(addr) => {
                data.lock_fn = addr;
                Ok(())
            }
            ShareSetting::UnlockFunc(addr) => {
                data.unlock_fn = addr;
                Ok(())
            }
            ShareSetting::UserData(addr) => {
                data.user_data = addr;
                Ok(())
            }
        }
    }

    /// Implements the `CURLSHOPT_SHARE` switch arm of `curl_share_setopt`.
    ///
    /// On success the corresponding bit is set in the specifier (curl's
    /// `if(!res) share->specifier |= (1 << type);`).
    fn enable_share(data: &mut SharedData, data_type: i32) -> Result<(), CurlShError> {
        let Some(lock) = LockData::from_i32(data_type) else {
            // curl `default:` arm — an unknown data type is a bad option.
            return Err(CurlShError::BadOption);
        };

        let res = match lock {
            // DNS, CONNECT and SSL_SESSION need no concrete store allocated here
            // (in curl the DNS cache and connection pool live on the share and
            // the TLS session cache is allocated under `USE_SSL`, which — with
            // rustls always present — is always available). Their shared stores
            // are owned by the engine modules wired up by sibling steps, which
            // consult `is_sharing()`; recording the intent in the specifier is
            // all that is required of the handle, exactly as curl's `break;`
            // arms do.
            LockData::Dns | LockData::Connect | LockData::SslSession => Ok(()),
            LockData::Cookie => Self::enable_cookie(data),
            LockData::Hsts => Self::enable_hsts(data),
            LockData::Psl => Self::enable_psl(data),
            // NONE and the internal SHARE marker are not user-settable share
            // types; curl's `CURLSHOPT_SHARE` switch has no case for them, so
            // they fall through to `default: CURLSHE_BAD_OPTION`.
            LockData::None | LockData::Share => Err(CurlShError::BadOption),
        };

        if res.is_ok() {
            data.specifier |= lock.bit();
        }
        res
    }

    /// Implements the `CURLSHOPT_UNSHARE` switch arm of `curl_share_setopt`.
    ///
    /// curl clears the specifier bit *before* the switch (`share->specifier &=
    /// ~(1 << type)`), so the bit is dropped for every known selector — even the
    /// PSL one, for which the switch then returns `CURLSHE_BAD_OPTION` because
    /// curl's `CURLSHOPT_UNSHARE` switch has no PSL case. This port reproduces
    /// that behavior exactly for wire/test parity.
    fn disable_share(data: &mut SharedData, data_type: i32) -> Result<(), CurlShError> {
        let Some(lock) = LockData::from_i32(data_type) else {
            // Unknown type: nothing was ever shared under it, so there is no bit
            // to clear; curl's `default:` arm returns a bad option.
            return Err(CurlShError::BadOption);
        };

        // curl clears the bit unconditionally before the switch.
        data.specifier &= !lock.bit();

        match lock {
            LockData::Dns | LockData::Connect | LockData::SslSession => Ok(()),
            LockData::Cookie => Self::disable_cookie(data),
            LockData::Hsts => Self::disable_hsts(data),
            // curl's UNSHARE switch has NO PSL case, so PSL — like NONE and the
            // internal SHARE marker — hits `default: CURLSHE_BAD_OPTION`. The
            // specifier bit was already cleared above, matching curl precisely;
            // any allocated PSL slot is released on drop.
            LockData::Psl | LockData::None | LockData::Share => Err(CurlShError::BadOption),
        }
    }

    // -- per-resource enable/disable helpers (capability-gated) --------------
    //
    // Each shareable resource this crate owns a type for has a feature-gated
    // pair of helpers. When the capability is compiled in, sharing allocates the
    // `Arc<Mutex<…>>` slot (idempotently) and unsharing releases it; when it is
    // compiled out, the C build returns `CURLSHE_NOT_BUILT_IN`, so we do too.
    // Gating whole functions (rather than blocks inside the match) keeps the
    // call sites identical across feature combinations.

    /// `CURL_LOCK_DATA_COOKIE` share, with the `cookies` capability present:
    /// allocate the shared jar if not already present.
    #[cfg(feature = "cookies")]
    fn enable_cookie(data: &mut SharedData) -> Result<(), CurlShError> {
        if data.cookies.is_none() {
            data.cookies = Some(Arc::new(Mutex::new(CookieJar::new())));
        }
        Ok(())
    }

    /// `CURL_LOCK_DATA_COOKIE` share without the `cookies` capability:
    /// `CURLSHE_NOT_BUILT_IN`, matching curl's `#if !CURL_DISABLE_COOKIES` gate.
    #[cfg(not(feature = "cookies"))]
    fn enable_cookie(_data: &mut SharedData) -> Result<(), CurlShError> {
        Err(CurlShError::NotBuiltIn)
    }

    /// `CURL_LOCK_DATA_COOKIE` unshare with the `cookies` capability: release the
    /// shared jar.
    #[cfg(feature = "cookies")]
    fn disable_cookie(data: &mut SharedData) -> Result<(), CurlShError> {
        data.cookies = None;
        Ok(())
    }

    /// `CURL_LOCK_DATA_COOKIE` unshare without the `cookies` capability.
    #[cfg(not(feature = "cookies"))]
    fn disable_cookie(_data: &mut SharedData) -> Result<(), CurlShError> {
        Err(CurlShError::NotBuiltIn)
    }

    /// `CURL_LOCK_DATA_HSTS` share with the `hsts` capability: allocate the
    /// shared store if not already present.
    #[cfg(feature = "hsts")]
    fn enable_hsts(data: &mut SharedData) -> Result<(), CurlShError> {
        if data.hsts.is_none() {
            data.hsts = Some(Arc::new(Mutex::new(HstsStore::new())));
        }
        Ok(())
    }

    /// `CURL_LOCK_DATA_HSTS` share without the `hsts` capability:
    /// `CURLSHE_NOT_BUILT_IN`, matching curl's `#ifndef CURL_DISABLE_HSTS` gate.
    #[cfg(not(feature = "hsts"))]
    fn enable_hsts(_data: &mut SharedData) -> Result<(), CurlShError> {
        Err(CurlShError::NotBuiltIn)
    }

    /// `CURL_LOCK_DATA_HSTS` unshare with the `hsts` capability: release the
    /// shared store.
    #[cfg(feature = "hsts")]
    fn disable_hsts(data: &mut SharedData) -> Result<(), CurlShError> {
        data.hsts = None;
        Ok(())
    }

    /// `CURL_LOCK_DATA_HSTS` unshare without the `hsts` capability.
    #[cfg(not(feature = "hsts"))]
    fn disable_hsts(_data: &mut SharedData) -> Result<(), CurlShError> {
        Err(CurlShError::NotBuiltIn)
    }

    /// `CURL_LOCK_DATA_PSL` share with the `psl` capability: allocate the shared
    /// Public Suffix List if not already present. (curl's `CURLSHOPT_SHARE` PSL
    /// arm only records the bit; this port additionally allocates the shared
    /// slot as requested by the migration plan — see the module docs.)
    #[cfg(feature = "psl")]
    fn enable_psl(data: &mut SharedData) -> Result<(), CurlShError> {
        if data.psl.is_none() {
            data.psl = Some(Arc::new(Mutex::new(Psl::new())));
        }
        Ok(())
    }

    /// `CURL_LOCK_DATA_PSL` share without the `psl` capability:
    /// `CURLSHE_NOT_BUILT_IN`, matching curl's `#ifndef USE_LIBPSL` gate.
    #[cfg(not(feature = "psl"))]
    fn enable_psl(_data: &mut SharedData) -> Result<(), CurlShError> {
        Err(CurlShError::NotBuiltIn)
    }

    // -- typed convenience wrappers ------------------------------------------

    /// Begins sharing a data type — `curl_share_setopt(CURLSHOPT_SHARE, type)`.
    ///
    /// # Errors
    ///
    /// See [`setopt`](Share::setopt): [`CurlShError::InUse`] if a handle is
    /// attached, [`CurlShError::BadOption`] for a non-settable type, or
    /// [`CurlShError::NotBuiltIn`] if the type's capability is compiled out.
    pub fn share_data(&self, data: LockData) -> Result<(), CurlShError> {
        self.setopt(ShareSetting::Share(data.as_i32()))
    }

    /// Stops sharing a data type — `curl_share_setopt(CURLSHOPT_UNSHARE, type)`.
    ///
    /// # Errors
    ///
    /// See [`setopt`](Share::setopt). Note that — matching curl — unsharing
    /// [`LockData::Psl`] returns [`CurlShError::BadOption`] even though the bit
    /// is cleared.
    pub fn unshare_data(&self, data: LockData) -> Result<(), CurlShError> {
        self.setopt(ShareSetting::Unshare(data.as_i32()))
    }

    /// Sets (or, with `None`, clears) the user lock callback —
    /// `curl_share_setopt(CURLSHOPT_LOCKFUNC, fn)`. The value is the function's
    /// raw address; the FFI layer supplies and later invokes it.
    ///
    /// # Errors
    ///
    /// [`CurlShError::InUse`] if a handle is currently attached.
    pub fn set_lock_function(&self, addr: Option<usize>) -> Result<(), CurlShError> {
        self.setopt(ShareSetting::LockFunc(addr))
    }

    /// Sets (or clears) the user unlock callback —
    /// `curl_share_setopt(CURLSHOPT_UNLOCKFUNC, fn)`.
    ///
    /// # Errors
    ///
    /// [`CurlShError::InUse`] if a handle is currently attached.
    pub fn set_unlock_function(&self, addr: Option<usize>) -> Result<(), CurlShError> {
        self.setopt(ShareSetting::UnlockFunc(addr))
    }

    /// Sets the user-data pointer passed to the lock/unlock callbacks —
    /// `curl_share_setopt(CURLSHOPT_USERDATA, ptr)` (`0` denotes NULL).
    ///
    /// # Errors
    ///
    /// [`CurlShError::InUse`] if a handle is currently attached.
    pub fn set_user_data(&self, addr: usize) -> Result<(), CurlShError> {
        self.setopt(ShareSetting::UserData(addr))
    }

    // -- shared-resource accessors (for easy-handle integration) -------------
    //
    // An easy handle configured with `CURLOPT_SHARE` calls these to obtain the
    // shared resource in place of its private one. Each returns a cheap
    // `Arc::clone` of the resource (so the easy handle holds its own owning
    // reference) only while that data type is actually shared — i.e. the
    // specifier bit is set — keeping the accessor consistent with `is_sharing`.

    /// Returns the shared cookie jar if cookie sharing is currently enabled,
    /// else `None`. Present only when the `cookies` capability is compiled in.
    #[cfg(feature = "cookies")]
    #[must_use]
    pub fn cookies(&self) -> Option<Arc<Mutex<CookieJar>>> {
        let data = self.read();
        if data.specifier & LockData::Cookie.bit() != 0 {
            data.cookies.clone()
        } else {
            None
        }
    }

    /// Returns the shared HSTS store if HSTS sharing is currently enabled, else
    /// `None`. Present only when the `hsts` capability is compiled in.
    #[cfg(feature = "hsts")]
    #[must_use]
    pub fn hsts(&self) -> Option<Arc<Mutex<HstsStore>>> {
        let data = self.read();
        if data.specifier & LockData::Hsts.bit() != 0 {
            data.hsts.clone()
        } else {
            None
        }
    }

    /// Returns the shared Public Suffix List if PSL sharing is currently
    /// enabled, else `None`. Present only when the `psl` capability is compiled
    /// in.
    #[cfg(feature = "psl")]
    #[must_use]
    pub fn psl(&self) -> Option<Arc<Mutex<Psl>>> {
        let data = self.read();
        if data.specifier & LockData::Psl.bit() != 0 {
            data.psl.clone()
        } else {
            None
        }
    }

    /// Returns `true` if the given data type is currently shared.
    ///
    /// This tests the specifier bit, so it answers the question "should a
    /// transfer use the shared instance of this resource?" for the data types
    /// that have no concrete slot here (DNS, the TLS session cache, the
    /// connection pool) as well as for the ones that do.
    #[must_use]
    pub fn is_sharing(&self, data: LockData) -> bool {
        self.read().specifier & data.bit() != 0
    }

    /// Returns the raw specifier bitmask of shared data types (curl's
    /// `share->specifier`). Primarily useful for diagnostics and for the FFI
    /// layer; individual types are better queried with [`is_sharing`](Share::is_sharing).
    #[must_use]
    pub fn specifier(&self) -> u32 {
        self.read().specifier
    }

    // -- in-use ("dirty") tracking -------------------------------------------
    //
    // An easy handle registers/unregisters its use of the share as it is
    // attached (`CURLOPT_SHARE` set) and detached (set to NULL, or the handle is
    // cleaned up). While any handle is attached the share is "in use" and refuses
    // reconfiguration / cleanup — the safe counterpart of curl's `share->dirty`.

    /// Registers that an easy handle has attached to this share.
    ///
    /// Call when an easy handle's `CURLOPT_SHARE` is set to this share.
    pub fn add_user(&self) {
        self.write().users += 1;
    }

    /// Registers that an easy handle has detached from this share.
    ///
    /// Call when an easy handle stops using this share (its `CURLOPT_SHARE` is
    /// cleared or the handle is cleaned up). Saturates at zero, so an unbalanced
    /// detach can never underflow.
    pub fn remove_user(&self) {
        let mut data = self.write();
        data.users = data.users.saturating_sub(1);
    }

    /// Returns `true` if one or more easy handles are currently attached
    /// (curl's `share->dirty`). While this holds, [`setopt`](Share::setopt) and
    /// [`cleanup`](Share::cleanup) return [`CurlShError::InUse`].
    #[must_use]
    pub fn is_in_use(&self) -> bool {
        self.read().users > 0
    }

    /// Returns the number of easy handles currently attached to this share.
    #[must_use]
    pub fn user_count(&self) -> usize {
        self.read().users
    }

    // -- FFI-edge accessors for the user lock callbacks ----------------------
    //
    // The FFI layer reads these to invoke the application's lock/unlock
    // callbacks around shared-resource accesses (for behavioral compatibility)
    // and to hand them the user-data pointer. The values are raw addresses; the
    // `unsafe` reconstruction of a callable function pointer lives in
    // `curl-rs-ffi`.

    /// Returns the stored `curl_lock_function` address, or `None` if unset.
    #[must_use]
    pub fn lock_function(&self) -> Option<usize> {
        self.read().lock_fn
    }

    /// Returns the stored `curl_unlock_function` address, or `None` if unset.
    #[must_use]
    pub fn unlock_function(&self) -> Option<usize> {
        self.read().unlock_fn
    }

    /// Returns the stored user-data pointer address (`0` denotes NULL).
    #[must_use]
    pub fn user_data(&self) -> usize {
        self.read().user_data
    }

    // -- teardown (curl_share_cleanup) ---------------------------------------

    /// Checks whether the share may be cleaned up — the equivalent of the
    /// in-use guard at the top of `curl_share_cleanup`.
    ///
    /// Returns [`CurlShError::InUse`] if any easy handle is still attached (curl
    /// returns `CURLSHE_IN_USE` and leaves the handle intact in that case);
    /// otherwise returns `Ok(())`, after which the caller (the FFI shim) drops
    /// its handle. The shared state and every shared resource are then freed
    /// deterministically when the last [`Share`] clone is dropped — the safe
    /// replacement for `curl_share_cleanup`'s explicit `free` of the cookie jar,
    /// HSTS store, session cache, connection pool and DNS cache.
    ///
    /// # Errors
    ///
    /// [`CurlShError::InUse`] if the share is still attached to one or more easy
    /// handles.
    pub fn cleanup(&self) -> Result<(), CurlShError> {
        if self.is_in_use() {
            Err(CurlShError::InUse)
        } else {
            Ok(())
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Compile-time proof that the handle and its inner state are thread-safe,
    /// which is the foundational requirement of the share interface: a `Share`
    /// cloned across threads and used by concurrent transfers must not data-race
    /// (AAP §0.7.1). If any field made these `!Send`/`!Sync` (e.g. a raw pointer
    /// for the lock callbacks instead of a `usize`) this would fail to compile.
    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn handle_types_are_send_and_sync() {
        assert_send_sync::<Share>();
        assert_send_sync::<SharedData>();
        assert_send_sync::<LockData>();
        assert_send_sync::<LockAccess>();
        assert_send_sync::<ShareOption>();
        assert_send_sync::<ShareSetting>();
    }

    // -- enum integer mappings ----------------------------------------------

    #[test]
    fn lock_data_integer_values_match_c() {
        // Exact `curl_lock_data` values from include/curl/curl.h.
        assert_eq!(LockData::None.as_i32(), 0);
        assert_eq!(LockData::Share.as_i32(), 1);
        assert_eq!(LockData::Cookie.as_i32(), 2);
        assert_eq!(LockData::Dns.as_i32(), 3);
        assert_eq!(LockData::SslSession.as_i32(), 4);
        assert_eq!(LockData::Connect.as_i32(), 5);
        assert_eq!(LockData::Psl.as_i32(), 6);
        assert_eq!(LockData::Hsts.as_i32(), 7);
    }

    #[test]
    fn lock_data_round_trips_and_rejects_unknown() {
        for raw in 0..=7 {
            let parsed = LockData::from_i32(raw).expect("0..=7 are defined");
            assert_eq!(parsed.as_i32(), raw);
        }
        assert_eq!(LockData::from_i32(8), None);
        assert_eq!(LockData::from_i32(-1), None);
        assert_eq!(LockData::from_i32(99), None);
    }

    #[test]
    fn lock_data_bit_positions() {
        assert_eq!(LockData::None.bit(), 1 << 0);
        assert_eq!(LockData::Share.bit(), 1 << 1);
        assert_eq!(LockData::Cookie.bit(), 1 << 2);
        assert_eq!(LockData::Hsts.bit(), 1 << 7);
    }

    #[test]
    fn lock_access_integer_values_match_c() {
        assert_eq!(LockAccess::None.as_i32(), 0);
        assert_eq!(LockAccess::Shared.as_i32(), 1);
        assert_eq!(LockAccess::Single.as_i32(), 2);
        assert_eq!(LockAccess::from_i32(1), Some(LockAccess::Shared));
        assert_eq!(LockAccess::from_i32(3), None);
    }

    #[test]
    fn share_option_integer_values_match_c() {
        assert_eq!(ShareOption::None.as_i32(), 0);
        assert_eq!(ShareOption::Share.as_i32(), 1);
        assert_eq!(ShareOption::Unshare.as_i32(), 2);
        assert_eq!(ShareOption::LockFunc.as_i32(), 3);
        assert_eq!(ShareOption::UnlockFunc.as_i32(), 4);
        assert_eq!(ShareOption::UserData.as_i32(), 5);
        for raw in 0..=5 {
            assert_eq!(
                ShareOption::from_i32(raw).map(ShareOption::as_i32),
                Some(raw)
            );
        }
        // The FFI maps an unknown CURLSHoption to CURLSHE_BAD_OPTION.
        assert_eq!(ShareOption::from_i32(6), None);
        assert_eq!(ShareOption::from_i32(99), None);
    }

    // -- construction --------------------------------------------------------

    #[test]
    fn new_share_has_only_the_internal_share_bit() {
        let share = Share::new();
        // curl_share_init sets `specifier |= 1 << CURL_LOCK_DATA_SHARE`.
        assert_eq!(share.specifier(), LockData::Share.bit());
        assert!(share.is_sharing(LockData::Share));
        assert!(!share.is_sharing(LockData::Cookie));
        assert!(!share.is_sharing(LockData::Dns));
        assert!(!share.is_in_use());
        assert_eq!(share.user_count(), 0);
        assert_eq!(share.lock_function(), None);
        assert_eq!(share.unlock_function(), None);
        assert_eq!(share.user_data(), 0);
    }

    #[test]
    fn default_equals_new() {
        assert_eq!(Share::default().specifier(), Share::new().specifier());
    }

    // -- sharing the bit-only data types (DNS / SSL_SESSION / CONNECT) -------

    #[test]
    fn share_and_unshare_bit_only_types() {
        for data in [LockData::Dns, LockData::SslSession, LockData::Connect] {
            let share = Share::new();
            assert_eq!(share.share_data(data), Ok(()));
            assert!(share.is_sharing(data), "{data:?} should be shared");
            assert_ne!(share.specifier() & data.bit(), 0);

            assert_eq!(share.unshare_data(data), Ok(()));
            assert!(!share.is_sharing(data), "{data:?} should be unshared");
            assert_eq!(share.specifier() & data.bit(), 0);
        }
    }

    // -- non-settable / unknown selectors -> BAD_OPTION ----------------------

    #[test]
    fn sharing_none_or_internal_share_is_bad_option() {
        let share = Share::new();
        assert_eq!(
            share.share_data(LockData::None),
            Err(CurlShError::BadOption)
        );
        assert_eq!(
            share.share_data(LockData::Share),
            Err(CurlShError::BadOption)
        );
        // The internal SHARE bit set at construction must be untouched by the
        // rejected attempt.
        assert!(share.is_sharing(LockData::Share));
    }

    #[test]
    fn sharing_unknown_type_is_bad_option() {
        let share = Share::new();
        let err = share.setopt(ShareSetting::Share(99)).unwrap_err();
        assert_eq!(err, CurlShError::BadOption);
        assert_eq!(err.code(), 1); // CURLSHE_BAD_OPTION
                                   // No spurious bit was set.
        assert_eq!(share.specifier(), LockData::Share.bit());
    }

    #[test]
    fn unsharing_unknown_type_is_bad_option() {
        let share = Share::new();
        assert_eq!(
            share.setopt(ShareSetting::Unshare(99)),
            Err(CurlShError::BadOption)
        );
    }

    #[test]
    fn unsharing_psl_is_bad_option_but_clears_the_bit() {
        // curl quirk: CURLSHOPT_UNSHARE has no CURL_LOCK_DATA_PSL case, so it
        // hits `default: CURLSHE_BAD_OPTION` — yet the specifier bit is cleared
        // *before* the switch. We reproduce both halves exactly.
        let share = Share::new();
        assert_eq!(share.share_data(LockData::Psl), Ok(()));
        assert!(share.is_sharing(LockData::Psl));

        assert_eq!(
            share.unshare_data(LockData::Psl),
            Err(CurlShError::BadOption)
        );
        assert!(
            !share.is_sharing(LockData::Psl),
            "PSL bit must be cleared despite BAD_OPTION"
        );
    }

    // -- user lock callbacks & user data -------------------------------------

    #[test]
    fn lock_callbacks_and_user_data_are_stored() {
        let share = Share::new();
        assert_eq!(share.set_lock_function(Some(0xDEAD_BEEF)), Ok(()));
        assert_eq!(share.set_unlock_function(Some(0xFEED_FACE)), Ok(()));
        assert_eq!(share.set_user_data(0x1234), Ok(()));

        assert_eq!(share.lock_function(), Some(0xDEAD_BEEF));
        assert_eq!(share.unlock_function(), Some(0xFEED_FACE));
        assert_eq!(share.user_data(), 0x1234);

        // Clearing a callback (NULL function pointer) is honored.
        assert_eq!(share.set_lock_function(None), Ok(()));
        assert_eq!(share.lock_function(), None);
    }

    // -- in-use ("dirty") gating ---------------------------------------------

    #[test]
    fn setopt_and_cleanup_refuse_while_in_use() {
        let share = Share::new();
        assert_eq!(share.cleanup(), Ok(())); // not in use yet

        share.add_user();
        assert!(share.is_in_use());
        assert_eq!(share.user_count(), 1);

        // Every option is refused while a handle is attached (curl's dirty check).
        assert_eq!(share.share_data(LockData::Dns), Err(CurlShError::InUse));
        assert_eq!(share.set_user_data(7), Err(CurlShError::InUse));
        assert_eq!(share.cleanup(), Err(CurlShError::InUse));

        // Detaching restores configurability and allows cleanup.
        share.remove_user();
        assert!(!share.is_in_use());
        assert_eq!(share.share_data(LockData::Dns), Ok(()));
        assert_eq!(share.cleanup(), Ok(()));
    }

    #[test]
    fn remove_user_saturates_at_zero() {
        let share = Share::new();
        share.remove_user(); // unbalanced detach must not underflow
        assert_eq!(share.user_count(), 0);
        share.add_user();
        share.add_user();
        share.remove_user();
        assert_eq!(share.user_count(), 1);
    }

    // -- clone semantics (Arc sharing) ---------------------------------------

    #[test]
    fn clone_shares_the_same_state() {
        let a = Share::new();
        let b = a.clone(); // Arc bump — the way a share is attached to many handles

        // A change made through one clone is visible through the other.
        assert_eq!(a.share_data(LockData::Dns), Ok(()));
        assert!(b.is_sharing(LockData::Dns));

        b.add_user();
        assert!(a.is_in_use());
        assert_eq!(a.user_count(), 1);
    }

    // -- capability-gated resources: cookies ---------------------------------

    #[cfg(feature = "cookies")]
    #[test]
    fn cookie_sharing_allocates_and_releases_the_jar() {
        let share = Share::new();
        assert!(share.cookies().is_none());

        assert_eq!(share.share_data(LockData::Cookie), Ok(()));
        assert!(share.is_sharing(LockData::Cookie));
        let jar = share.cookies().expect("jar allocated when shared");
        // The shared jar is usable behind its own Mutex.
        assert_eq!(jar.lock().unwrap().num_cookies(), 0);

        // A second attach is idempotent and hands back the SAME jar.
        let jar2 = share.cookies().expect("still shared");
        assert!(Arc::ptr_eq(&jar, &jar2));

        assert_eq!(share.unshare_data(LockData::Cookie), Ok(()));
        assert!(!share.is_sharing(LockData::Cookie));
        assert!(share.cookies().is_none());
    }

    #[cfg(not(feature = "cookies"))]
    #[test]
    fn cookie_sharing_not_built_in_without_feature() {
        let share = Share::new();
        assert_eq!(
            share.share_data(LockData::Cookie),
            Err(CurlShError::NotBuiltIn)
        );
    }

    // -- capability-gated resources: HSTS ------------------------------------

    #[cfg(feature = "hsts")]
    #[test]
    fn hsts_sharing_allocates_and_releases_the_store() {
        let share = Share::new();
        assert!(share.hsts().is_none());

        assert_eq!(share.share_data(LockData::Hsts), Ok(()));
        let store = share.hsts().expect("store allocated when shared");
        assert_eq!(store.lock().unwrap().count(), 0);

        assert_eq!(share.unshare_data(LockData::Hsts), Ok(()));
        assert!(share.hsts().is_none());
    }

    #[cfg(not(feature = "hsts"))]
    #[test]
    fn hsts_sharing_not_built_in_without_feature() {
        let share = Share::new();
        assert_eq!(
            share.share_data(LockData::Hsts),
            Err(CurlShError::NotBuiltIn)
        );
    }

    // -- capability-gated resources: PSL -------------------------------------

    #[cfg(feature = "psl")]
    #[test]
    fn psl_sharing_allocates_the_list() {
        let share = Share::new();
        assert!(share.psl().is_none());

        assert_eq!(share.share_data(LockData::Psl), Ok(()));
        assert!(share.psl().is_some());
        // (Unshare-PSL behavior is covered by `unsharing_psl_is_bad_option_*`.)
    }

    #[cfg(not(feature = "psl"))]
    #[test]
    fn psl_sharing_not_built_in_without_feature() {
        let share = Share::new();
        assert_eq!(
            share.share_data(LockData::Psl),
            Err(CurlShError::NotBuiltIn)
        );
    }

    // -- thread safety under concurrency -------------------------------------

    #[test]
    fn concurrent_attach_detach_and_access_is_race_free() {
        // Configure sharing up front (single-threaded), then hammer the handle
        // from many threads. With std `Mutex`/`RwLock` providing the mutual
        // exclusion, this must complete without deadlock, panic, or data race,
        // and the balanced add/remove must leave the use-count at zero.
        let share = Share::new();
        #[cfg(feature = "cookies")]
        share.share_data(LockData::Cookie).unwrap();
        share.share_data(LockData::Dns).unwrap();

        let threads: Vec<_> = (0..8)
            .map(|_| {
                let s = share.clone();
                std::thread::spawn(move || {
                    for _ in 0..200 {
                        s.add_user();
                        // Read-side accessors run concurrently with the writes.
                        assert!(s.is_sharing(LockData::Dns));
                        let _ = s.specifier();
                        #[cfg(feature = "cookies")]
                        if let Some(jar) = s.cookies() {
                            // Exercise the per-resource Mutex from many threads.
                            let mut guard = jar.lock().unwrap();
                            let _ = guard.num_cookies();
                            guard.clear_all();
                        }
                        s.remove_user();
                    }
                })
            })
            .collect();

        for t in threads {
            t.join().expect("worker thread must not panic");
        }

        assert_eq!(
            share.user_count(),
            0,
            "every add_user was balanced by a remove_user"
        );
        assert!(share.is_sharing(LockData::Dns));
    }
}
