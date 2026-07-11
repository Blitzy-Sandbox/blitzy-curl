// SPDX-License-Identifier: curl
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

//! `CURLOPT_OPENSOCKETFUNCTION` (Linux MPTCP) and `CURLOPT_SOCKOPTFUNCTION`
//! (`--ip-tos` / `--vlan-priority`) callbacks.
//!
//! Rust rewrite of curl 8.19.0-DEV `src/tool_cb_soc.c` plus the socket-option handler
//! (`sockopt_callback` and its `get_address_family` helper) lifted out of
//! `src/config2setopts.c`. Per the workspace plan the *implementation* of both callbacks
//! lives here, while the sibling `curl-rs/src/setopt.rs` (the port of `config2setopts.c`)
//! *installs* them on the easy handle via `CURLOPT_OPENSOCKETFUNCTION` /
//! `CURLOPT_SOCKOPTFUNCTION` + `CURLOPT_SOCKOPTDATA`.
//!
//! This is the one module in `callbacks/` that must reach the operating system's socket
//! primitives directly, so it is the only one containing substantial `unsafe`. That is
//! expressly permitted for "narrow OS-integration primitives" by AAP §0.6.2 / §0.7.2, and —
//! exactly as in the C tool and the sibling `xattr.rs` / `terminal.rs` modules — every
//! `unsafe` block carries a mandatory `// SAFETY:` comment stating the invariant it upholds.
//! The behavior, the platform split, and the two warning strings are preserved byte-for-byte
//! from curl 8.x (the Minimal Change Mandate, §0.7.3).

use core::ffi::{c_int, c_void};

use curl_rs_ffi::easy::{
    curl_sockaddr, curl_socket_t, curlsocktype, CURL_SOCKET_BAD, CURL_SOCKOPT_OK,
};

use crate::args::{Diag, OperationConfig};
use crate::callbacks::userdata_mut;
use crate::operate::warnf;

/// IPv4 socket-option level. curl mirrors the C header quirk
/// `#ifndef SOL_IP #define SOL_IP IPPROTO_IP`: Linux exposes `SOL_IP`, whereas macOS (and the
/// BSDs) only define `IPPROTO_IP`. Both name the same protocol level used for `IP_TOS`.
#[cfg(target_os = "linux")]
const SOL_IP: c_int = libc::SOL_IP;
#[cfg(not(target_os = "linux"))]
const SOL_IP: c_int = libc::IPPROTO_IP;

/// `CURLOPT_OPENSOCKETFUNCTION` callback that upgrades a plain-TCP socket request to
/// Multipath TCP (MPTCP) on Linux. Rust rewrite of `tool_socket_open_mptcp_cb`
/// (`src/tool_cb_soc.c`).
///
/// Matches the `curl_opensocket_callback` typedef exactly:
/// `curl_socket_t (*)(void *clientp, curlsocktype purpose, struct curl_sockaddr *address)`.
/// `clientp` and `purpose` are unused (curl casts them to `void`); only the requested address
/// tuple matters. MPTCP is a Linux-only kernel feature, so on every other target this returns
/// [`CURL_SOCKET_BAD`] for a TCP request, exactly as curl 8.x does — and because the callback
/// is installed only when `--mptcp` is given, that failure is the intended behavior.
///
/// # Safety
/// `addr` must be a valid, non-null `*mut curl_sockaddr` supplied by libcurl (the
/// `CURLOPT_OPENSOCKETFUNCTION` contract).
#[allow(dead_code)]
pub unsafe extern "C" fn tool_socket_open_mptcp_cb(
    _clientp: *mut c_void,
    _purpose: curlsocktype,
    addr: *mut curl_sockaddr,
) -> curl_socket_t {
    // SAFETY: `addr` is the valid, non-null `curl_sockaddr` libcurl hands the opensocket
    // callback; its `family` / `socktype` / `protocol` are plain `c_int`s read in one deref.
    let (family, socktype, protocol) =
        unsafe { ((*addr).family, (*addr).socktype, (*addr).protocol) };

    // A plain-TCP request becomes an MPTCP request on Linux; on other targets MPTCP is
    // unavailable and the request fails with `CURL_SOCKET_BAD`, matching `tool_cb_soc.c`.
    // (Written as cfg-gated shadowing so neither leg needs a `mut` binding.)
    #[cfg(target_os = "linux")]
    let protocol = if protocol == libc::IPPROTO_TCP {
        // `IPPROTO_MPTCP` is frequently missing from libc; curl hardcodes its value (262).
        const IPPROTO_MPTCP: c_int = 262;
        IPPROTO_MPTCP
    } else {
        protocol
    };
    #[cfg(not(target_os = "linux"))]
    if protocol == libc::IPPROTO_TCP {
        return CURL_SOCKET_BAD;
    }

    // SAFETY: `family`, `socktype`, and `protocol` are plain integers copied out of the
    // libcurl-owned `curl_sockaddr`; `socket()` allocates a fresh descriptor and touches no
    // caller memory. This is exactly curl's `CURL_SOCKET(family, socktype, protocol)` macro.
    let fd = unsafe { libc::socket(family, socktype, protocol) };
    // `socket()` returns -1 on failure, which is `CURL_SOCKET_BAD` on Unix; normalize so the
    // sentinel is explicit.
    if fd < 0 {
        CURL_SOCKET_BAD
    } else {
        fd
    }
}

/// Return the address family (`AF_*`) of the socket behind `sockfd`, or [`libc::AF_UNSPEC`]
/// when it cannot be determined. Rust rewrite of the `get_address_family` helper in
/// `src/config2setopts.c`, used to pick the right IP option level in [`sockopt_callback`].
#[allow(dead_code)]
fn get_address_family(sockfd: curl_socket_t) -> c_int {
    // SAFETY: `addr` is a zeroed `sockaddr` whose writable capacity is described by `addrlen`;
    // `getsockname` writes at most `addrlen` bytes into it (updating `addrlen`) and touches no
    // memory we do not own. An invalid `sockfd` merely makes the call fail, and we fall
    // through to `AF_UNSPEC` — identical to the C helper.
    unsafe {
        let mut addr: libc::sockaddr = core::mem::zeroed();
        let mut addrlen = core::mem::size_of::<libc::sockaddr>() as libc::socklen_t;
        if libc::getsockname(sockfd, &mut addr, &mut addrlen) == 0 {
            addr.sa_family as c_int
        } else {
            libc::AF_UNSPEC
        }
    }
}

/// `CURLOPT_SOCKOPTFUNCTION` callback applying the `--ip-tos` and `--vlan-priority` socket
/// options to each new IP-connection socket. Rust rewrite of `sockopt_callback`
/// (`src/config2setopts.c`).
///
/// Matches the `curl_sockopt_callback` typedef exactly:
/// `int (*)(void *clientp, curl_socket_t curlfd, curlsocktype purpose)`. `clientp` is the
/// [`OperationConfig`] libcurl was handed through `CURLOPT_SOCKOPTDATA`. Only real
/// IP-connection sockets (`CURLSOCKTYPE_IPCXN`) are tuned; sockets produced by `accept()` are
/// left untouched. The function always returns [`CURL_SOCKOPT_OK`] — a failed `setsockopt`
/// only emits a warning, never an error, exactly as curl 8.x behaves.
///
/// # Safety
/// `clientp` must be the `*mut OperationConfig` (the config-bearing context) libcurl was given
/// via `CURLOPT_SOCKOPTDATA`, or null.
#[allow(dead_code)]
pub unsafe extern "C" fn sockopt_callback(
    clientp: *mut c_void,
    curlfd: curl_socket_t,
    purpose: curlsocktype,
) -> c_int {
    // SAFETY: `clientp` is the `*mut OperationConfig` installed via CURLOPT_SOCKOPTDATA (see
    // `setopt.rs`); on the single-threaded CLI runtime it is validly and uniquely borrowed for
    // the duration of this call. A null / absent pointer yields `None` and we no-op.
    let config = match unsafe { userdata_mut::<OperationConfig>(clientp) } {
        Some(c) => c,
        None => return CURL_SOCKOPT_OK,
    };

    // Only touch sockets opened for a specific IP connection, never `accept()`ed ones.
    if purpose != curlsocktype::CURLSOCKTYPE_IPCXN {
        return CURL_SOCKOPT_OK;
    }

    // COORDINATION NOTE (shared by every CLI callback): curl's C `warnf` reads the process-
    // global config for the `--silent` gate, but this callback's userdata is an
    // `OperationConfig`, which does not carry the diagnostic-gating snapshot. We therefore emit
    // through the shared `operate::warnf` path (never a new one, so the `"Warning: "` prefix
    // and terminal word-wrap stay identical to curl 8.x) using the default `Diag` — i.e.
    // warnings enabled, which is curl's non-silenced default. When a future integration threads
    // the shared `GlobalConfig` / `Diag` through `CURLOPT_SOCKOPTDATA`, these sites should read
    // it.

    // --- `--ip-tos`: IPv4 IP_TOS or IPv6 IPV6_TCLASS, chosen by the socket's family ---
    if config.ip_tos > 0 {
        let tos: c_int = config.ip_tos as c_int;
        let result = match get_address_family(curlfd) {
            libc::AF_INET => {
                // SAFETY: `setsockopt` reads exactly `size_of::<c_int>()` bytes from `&tos`;
                // `curlfd` is the live connection socket libcurl passed to the callback.
                unsafe {
                    libc::setsockopt(
                        curlfd,
                        SOL_IP,
                        libc::IP_TOS,
                        (&tos as *const c_int).cast::<libc::c_void>(),
                        core::mem::size_of::<c_int>() as libc::socklen_t,
                    )
                }
            }
            libc::AF_INET6 => {
                // SAFETY: `setsockopt` reads exactly `size_of::<c_int>()` bytes from `&tos`;
                // `curlfd` is the live connection socket libcurl passed to the callback.
                unsafe {
                    libc::setsockopt(
                        curlfd,
                        libc::IPPROTO_IPV6,
                        libc::IPV6_TCLASS,
                        (&tos as *const c_int).cast::<libc::c_void>(),
                        core::mem::size_of::<c_int>() as libc::socklen_t,
                    )
                }
            }
            _ => 0,
        };
        if result < 0 {
            let e = std::io::Error::last_os_error();
            let errno = e.raw_os_error().unwrap_or(0);
            warnf(
                Diag::default(),
                &format!("Setting type of service to {tos} failed with errno {errno}: {e}"),
            );
        }
    }

    // --- `--vlan-priority`: SO_PRIORITY. Linux-only: the C guards it with `#ifdef SO_PRIORITY`
    //     and macOS has no such option, so the whole block is gated to Linux. ---
    #[cfg(target_os = "linux")]
    if config.vlan_priority > 0 {
        let priority: c_int = config.vlan_priority as c_int;
        // SAFETY: `setsockopt` reads exactly `size_of::<c_int>()` bytes from `&priority`;
        // `curlfd` is the live connection socket libcurl passed to the callback.
        let r = unsafe {
            libc::setsockopt(
                curlfd,
                libc::SOL_SOCKET,
                libc::SO_PRIORITY,
                (&priority as *const c_int).cast::<libc::c_void>(),
                core::mem::size_of::<c_int>() as libc::socklen_t,
            )
        };
        if r != 0 {
            let e = std::io::Error::last_os_error();
            let errno = e.raw_os_error().unwrap_or(0);
            warnf(
                Diag::default(),
                &format!("VLAN priority {priority} failed with errno {errno}: {e}"),
            );
        }
    }

    CURL_SOCKOPT_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A freshly created IPv4 socket reports `AF_INET` via `getsockname`.
    #[test]
    fn address_family_of_ipv4_socket_is_af_inet() {
        // SAFETY: `socket()` is called with valid constant arguments and the returned
        // descriptor is closed below.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0, "socket(AF_INET) should succeed");
        assert_eq!(get_address_family(fd), libc::AF_INET);
        // SAFETY: `fd` is the descriptor created just above.
        unsafe {
            libc::close(fd);
        }
    }

    /// An invalid descriptor makes `getsockname` fail, yielding `AF_UNSPEC`.
    #[test]
    fn address_family_of_bad_fd_is_af_unspec() {
        assert_eq!(get_address_family(-1), libc::AF_UNSPEC);
    }

    /// A null userdata pointer is tolerated: the callback no-ops with `CURL_SOCKOPT_OK`.
    #[test]
    fn sockopt_callback_null_clientp_is_ok() {
        // SAFETY: the callback explicitly handles a null `clientp` (yields `None` → OK).
        let rc = unsafe {
            sockopt_callback(core::ptr::null_mut(), -1, curlsocktype::CURLSOCKTYPE_IPCXN)
        };
        assert_eq!(rc, CURL_SOCKOPT_OK);
    }

    /// Non-IP-connection sockets (e.g. `accept()`ed) are left untouched even when a TOS is set.
    #[test]
    fn sockopt_callback_ignores_non_ipcxn() {
        let mut cfg = OperationConfig::new();
        // A non-zero TOS would trigger setsockopt, but the purpose gate short-circuits first.
        cfg.ip_tos = 8;
        // SAFETY: `cfg` outlives the call; the pointer is valid and uniquely borrowed.
        let rc = unsafe {
            sockopt_callback(
                core::ptr::addr_of_mut!(cfg).cast::<c_void>(),
                -1,
                curlsocktype::CURLSOCKTYPE_ACCEPT,
            )
        };
        assert_eq!(rc, CURL_SOCKOPT_OK);
    }

    /// With curl's defaults (`ip_tos == 0`, `vlan_priority == 0`) nothing is set and the
    /// callback returns OK without ever touching the (here invalid) descriptor.
    #[test]
    fn sockopt_callback_defaults_are_noop() {
        let mut cfg = OperationConfig::new();
        assert_eq!(cfg.ip_tos, 0);
        assert_eq!(cfg.vlan_priority, 0);
        // SAFETY: `cfg` outlives the call; the pointer is valid and uniquely borrowed.
        let rc = unsafe {
            sockopt_callback(
                core::ptr::addr_of_mut!(cfg).cast::<c_void>(),
                -1,
                curlsocktype::CURLSOCKTYPE_IPCXN,
            )
        };
        assert_eq!(rc, CURL_SOCKOPT_OK);
    }

    /// Applying `--ip-tos` to a real IPv4 socket succeeds and the callback returns OK.
    #[test]
    fn sockopt_callback_sets_ip_tos_on_ipv4() {
        // SAFETY: `socket()` is called with valid constant arguments.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0, "socket(AF_INET) should succeed");
        let mut cfg = OperationConfig::new();
        // A low TOS value settable without extra privilege.
        cfg.ip_tos = 8;
        // SAFETY: `cfg` outlives the call; `fd` is the socket created above.
        let rc = unsafe {
            sockopt_callback(
                core::ptr::addr_of_mut!(cfg).cast::<c_void>(),
                fd,
                curlsocktype::CURLSOCKTYPE_IPCXN,
            )
        };
        assert_eq!(rc, CURL_SOCKOPT_OK);
        // SAFETY: `fd` is the descriptor created above.
        unsafe {
            libc::close(fd);
        }
    }

    /// A non-TCP protocol bypasses the MPTCP substitution and opens the socket directly.
    #[test]
    fn mptcp_cb_non_tcp_opens_socket_directly() {
        // SAFETY: `curl_sockaddr` is plain-old-data; zeroing then setting the integer fields
        // yields a fully valid value.
        let mut sa: curl_sockaddr = unsafe { core::mem::zeroed() };
        sa.family = libc::AF_INET;
        sa.socktype = libc::SOCK_DGRAM;
        sa.protocol = libc::IPPROTO_UDP;
        // SAFETY: `sa` is a valid, fully-initialized `curl_sockaddr` on the stack that
        // outlives the call.
        let fd = unsafe {
            tool_socket_open_mptcp_cb(
                core::ptr::null_mut(),
                curlsocktype::CURLSOCKTYPE_IPCXN,
                core::ptr::addr_of_mut!(sa),
            )
        };
        assert!(fd >= 0, "a UDP socket request should succeed");
        // SAFETY: `fd` is the descriptor just created.
        unsafe {
            libc::close(fd);
        }
    }

    /// A TCP request exercises the MPTCP path: on a kernel with MPTCP it yields a live socket;
    /// without it, `socket()` fails and the callback reports `CURL_SOCKET_BAD`. Either is a
    /// valid outcome, so the test only asserts the contract, not the environment.
    #[test]
    fn mptcp_cb_tcp_request_is_handled() {
        // SAFETY: `curl_sockaddr` is plain-old-data; zeroing then setting the integer fields
        // yields a fully valid value.
        let mut sa: curl_sockaddr = unsafe { core::mem::zeroed() };
        sa.family = libc::AF_INET;
        sa.socktype = libc::SOCK_STREAM;
        sa.protocol = libc::IPPROTO_TCP;
        // SAFETY: `sa` is a valid, fully-initialized `curl_sockaddr` on the stack that
        // outlives the call.
        let fd = unsafe {
            tool_socket_open_mptcp_cb(
                core::ptr::null_mut(),
                curlsocktype::CURLSOCKTYPE_IPCXN,
                core::ptr::addr_of_mut!(sa),
            )
        };
        if fd >= 0 {
            // SAFETY: `fd` is the descriptor just created.
            unsafe {
                libc::close(fd);
            }
        } else {
            assert_eq!(fd, CURL_SOCKET_BAD);
        }
    }
}
