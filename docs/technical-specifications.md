# Technical Specification

# 0. Agent Action Plan

## 0.1 Intent Clarification

### 0.1.1 Core Refactoring Objective

Based on the prompt, the Blitzy platform understands that the refactoring objective is to **perform a complete language-level rewrite of the curl C codebase (version 8.19.0-DEV) into idiomatic Rust**, producing a functionally equivalent binary (`curl-rs`), library (`curl-rs-lib`), and FFI compatibility layer (`curl-rs-ffi`). This is not an incremental modernization or partial binding — it is a total replacement of all C source files across the protocol, TLS, transfer, authentication, DNS, CLI, and utility layers with pure Rust implementations.

- **Refactoring type:** Tech stack migration (C → Rust), complete codebase rewrite
- **Target repository:** Same repository — the existing curl repository is the source of truth for understanding the C implementation; the Rust workspace is built as a new structure within/alongside it
- **Refactoring goal #1:** Eliminate all manual memory management (`malloc`/`free`/`realloc`) by replacing it with Rust's ownership, borrowing, and lifetime semantics
- **Refactoring goal #2:** Achieve byte-for-byte functional parity with curl 8.x on all supported protocols (HTTP/1.1, HTTP/2, HTTP/3, FTP/FTPS, SFTP, SCP) including redirect handling, cookie jar, proxy support, chunked transfer, and streaming upload/download
- **Refactoring goal #3:** Maintain full libcurl C ABI compatibility via an FFI crate that exposes all 106 `CURL_EXTERN` symbols with identical function signatures, parameter types, return types, and error code integer values
- **Refactoring goal #4:** Preserve the exact CLI interface — all `--long-option` flags, their semantics, and their defaults remain unchanged so that `curl --help all` output is functionally identical between the C and Rust binaries
- **Refactoring goal #5:** Replace all C TLS backends (OpenSSL, Schannel, GnuTLS, mbedTLS, wolfSSL, Apple Security) with a single Rust-native TLS stack (rustls) — zero C TLS library linkage at any build configuration
- **Refactoring goal #6:** Replace C HTTP/2 (nghttp2), QUIC (ngtcp2/quiche), and SSH (libssh/libssh2) backends with pure-Rust equivalents (hyper/h2, quinn/h3, russh)
- **Refactoring goal #7:** Enforce memory safety by restricting `unsafe` blocks exclusively to the `src/ffi/` directory (and minimal OS-integration primitives), with every `unsafe` block requiring a `// SAFETY:` invariant comment

**Implicit requirements surfaced:**
- The existing curl 8.x test suite (Perl/Python harness, C regression tests, pytest HTTP suite) must execute unmodified against the Rust binary — this implies the Rust binary must support the same process exit codes, stderr/stdout formatting, and HTTP header behaviors
- Authentication negotiation sequences (Basic, Digest, Bearer, NTLM, Negotiate) must follow the same multi-step protocol exchanges as curl 8.x to pass existing integration tests
- Cookie jar file format, netrc parsing, HSTS preload list handling, and alt-svc cache file formats must remain file-compatible with curl 8.x
- The generated C header (`include/curl/curl.h`) from cbindgen must be structurally compatible for drop-in consumer usage, meaning downstream C programs can swap `libcurl.so` with `libcurl-rs.so` without recompilation

### 0.1.2 Technical Interpretation

This refactoring translates to the following technical transformation strategy:

**Current Architecture (C, ~163,677 lines across 222 source files + 219 headers):**
```
curl 8.19.0-DEV (C)
├── lib/          → 179 .c files, 174 .h files (144,333 LoC)
│   ├── vtls/     → 7 TLS backends (OpenSSL, Schannel, GnuTLS, mbedTLS, wolfSSL, Rustls, Apple)
│   ├── vquic/    → 2 QUIC backends (ngtcp2+nghttp3, quiche)
│   ├── vssh/     → 2 SSH backends (libssh, libssh2)
│   ├── vauth/    → 15 auth handler files (NTLM, Kerberos, GSSAPI, Digest, OAuth2, SASL)
│   └── curlx/    → 38 portability utility files
├── src/          → 43 .c files, 45 .h files (19,344 LoC) — CLI tool
├── include/curl/ → 12 public API headers (106 CURL_EXTERN symbols)
└── tests/        → Perl/Python/C regression suite
```

**Target Architecture (Rust, edition 2021, MSRV 1.75):**
```
curl-rs workspace
├── curl-rs-lib/  → Core library crate (protocols, TLS, transfer, DNS, auth)
├── curl-rs/      → Binary crate (CLI parsing via clap, entrypoint)
└── curl-rs-ffi/  → FFI crate (libcurl-compatible extern "C" symbols, cbindgen)
```

**Transformation rules:**
- Every C source file in `lib/` maps to one or more Rust modules in `curl-rs-lib/`
- Every C source file in `src/` maps to Rust modules in `curl-rs/`
- All 12 public header files in `include/curl/` map to the FFI surface in `curl-rs-ffi/`
- C `#ifdef` conditional compilation maps to Cargo feature flags
- C manual memory management maps to Rust ownership and `Arc`/`Box`/`Vec` as appropriate
- C callback function pointers map to Rust closures, trait objects, or `extern "C"` fn pointers in the FFI layer
- The async runtime is Tokio — current-thread for the CLI binary, multi-thread for multi-handle operations

## 0.2 Source Analysis

### 0.2.1 Comprehensive Source File Discovery

The curl 8.19.0-DEV codebase contains **222 C source files** and **231 header files** across three primary directories (`lib/`, `src/`, `include/`), totaling approximately **163,677 lines of C code**. Every file listed below requires rewriting in Rust or mapping to the new workspace structure.

**Search patterns applied to identify all files needing refactoring:**
- `lib/**/*.c` — all core library implementation files (179 files, 144,333 LoC)
- `lib/**/*.h` — all internal library headers (174 files)
- `src/**/*.c` — all CLI tool implementation files (43 files, 19,344 LoC)
- `src/**/*.h` — all CLI tool internal headers (45 files)
- `include/curl/*.h` — all public API headers (12 files, 106 `CURL_EXTERN` symbols)

### 0.2.2 Current Structure Mapping

```
Current: curl 8.19.0-DEV
├── include/curl/                    [12 public API headers]
│   ├── curl.h                       (master API header — 46 CURL_EXTERN symbols)
│   ├── easy.h                       (easy interface — 10 CURL_EXTERN symbols)
│   ├── multi.h                      (multi interface — 24 CURL_EXTERN symbols)
│   ├── mprintf.h                    (printf family — 11 CURL_EXTERN symbols)
│   ├── urlapi.h                     (URL API — 6 CURL_EXTERN symbols)
│   ├── websockets.h                 (WebSocket API — 4 CURL_EXTERN symbols)
│   ├── options.h                    (option introspection — 3 CURL_EXTERN symbols)
│   ├── header.h                     (header API — 2 CURL_EXTERN symbols)
│   ├── curlver.h                    (version macros)
│   ├── system.h                     (platform type definitions)
│   ├── stdcheaders.h                (standard C header compat)
│   └── typecheck-gcc.h             (GCC type-checking macros)
│
├── lib/                             [179 .c + 174 .h — core library]
│   ├── easy.c                       (1,397 lines — easy API entry point)
│   ├── multi.c                      (4,034 lines — multi API event loop)
│   ├── multi_ev.c                   (multi event notification)
│   ├── multi_ntfy.c                 (multi notification subsystem)
│   ├── url.c                        (3,904 lines — URL handling, connection setup)
│   ├── urlapi.c                     (public URL API implementation)
│   ├── transfer.c                   (912 lines — data transfer engine)
│   ├── setopt.c                     (2,975 lines — option setting dispatch)
│   ├── getinfo.c                    (676 lines — info retrieval)
│   ├── easygetopt.c                 (easy option getters)
│   ├── easyoptions.c               (option metadata tables)
│   ├── connect.c                    (603 lines — connection establishment)
│   ├── conncache.c                  (910 lines — connection cache/pool)
│   ├── cfilters.c                   (connection filter framework)
│   ├── cf-socket.c                  (socket connection filter)
│   ├── cf-h1-proxy.c               (HTTP/1.x proxy tunnel filter)
│   ├── cf-h2-proxy.c               (HTTP/2 proxy tunnel filter)
│   ├── cf-haproxy.c                (HAProxy protocol filter)
│   ├── cf-https-connect.c          (HTTPS-connect filter)
│   ├── cf-ip-happy.c               (Happy Eyeballs algorithm filter)
│   ├── hostip.c                     (1,590 lines — DNS resolution)
│   ├── hostip4.c                    (IPv4 resolution helpers)
│   ├── hostip6.c                    (IPv6 resolution helpers)
│   ├── doh.c                        (1,338 lines — DNS-over-HTTPS)
│   ├── asyn-ares.c                  (c-ares async DNS)
│   ├── asyn-base.c                  (async DNS base)
│   ├── asyn-thrdd.c                 (threaded async DNS)
│   ├── cookie.c                     (1,638 lines — cookie jar engine)
│   ├── hsts.c                       (HSTS preload/management)
│   ├── altsvc.c                     (Alt-Svc cache)
│   ├── httpsrr.c                    (HTTPS DNS resource records)
│   │
│   ├── [Protocol Handlers]
│   ├── http.c                       (HTTP core handler)
│   ├── http1.c                      (HTTP/1.x specifics)
│   ├── http2.c                      (HTTP/2 via nghttp2)
│   ├── http_chunks.c               (chunked transfer encoding)
│   ├── http_digest.c               (HTTP Digest auth)
│   ├── http_negotiate.c            (HTTP Negotiate/SPNEGO)
│   ├── http_ntlm.c                 (HTTP NTLM auth)
│   ├── http_proxy.c                (HTTP proxy connect — 437 lines)
│   ├── http_aws_sigv4.c            (AWS Signature V4)
│   ├── ftp.c                        (FTP/FTPS protocol handler)
│   ├── ftplistparser.c             (FTP LIST response parser)
│   ├── imap.c                       (IMAP protocol handler)
│   ├── pop3.c                       (POP3 protocol handler)
│   ├── smtp.c                       (SMTP protocol handler)
│   ├── pingpong.c                   (shared IMAP/POP3/SMTP state machine)
│   ├── rtsp.c                       (RTSP protocol handler)
│   ├── ldap.c                       (LDAP protocol handler)
│   ├── openldap.c                   (OpenLDAP backend)
│   ├── telnet.c                     (Telnet protocol handler)
│   ├── tftp.c                       (TFTP protocol handler)
│   ├── mqtt.c                       (MQTT protocol handler)
│   ├── gopher.c                     (Gopher protocol handler)
│   ├── smb.c                        (SMB protocol handler)
│   ├── dict.c                       (DICT protocol handler)
│   ├── file.c                       (FILE protocol handler)
│   ├── ws.c                         (WebSocket handler)
│   ├── curl_rtmp.c                  (RTMP via librtmp)
│   │
│   ├── [TLS — lib/vtls/]           [31 files]
│   ├── vtls/vtls.c                  (TLS abstraction layer)
│   ├── vtls/vtls_scache.c          (TLS session cache)
│   ├── vtls/vtls_spack.c           (session serialization)
│   ├── vtls/vtls_int.h             (internal TLS types)
│   ├── vtls/openssl.c              (OpenSSL backend)
│   ├── vtls/schannel.c             (Windows Schannel backend)
│   ├── vtls/schannel_verify.c      (Schannel cert verification)
│   ├── vtls/sectransp.c            (Apple Security Transport)
│   ├── vtls/gtls.c                  (GnuTLS backend)
│   ├── vtls/mbedtls.c              (mbedTLS backend)
│   ├── vtls/wolfssl.c              (wolfSSL backend)
│   ├── vtls/rustls.c               (Rustls backend)
│   ├── vtls/cipher_suite.c         (cipher suite translation)
│   ├── vtls/keylog.c               (TLS key logging)
│   ├── vtls/hostcheck.c            (hostname verification)
│   ├── vtls/x509asn1.c             (X.509 ASN.1 parsing)
│   │
│   ├── [QUIC/HTTP3 — lib/vquic/]   [9 files]
│   ├── vquic/vquic.c               (shared QUIC layer)
│   ├── vquic/vquic-tls.c           (QUIC TLS glue)
│   ├── vquic/curl_ngtcp2.c         (ngtcp2 backend)
│   ├── vquic/curl_osslq.c          (OpenSSL QUIC)
│   ├── vquic/curl_quiche.c         (quiche backend)
│   │
│   ├── [SSH — lib/vssh/]           [5 files]
│   ├── vssh/libssh.c               (libssh backend)
│   ├── vssh/libssh2.c              (libssh2 backend)
│   ├── vssh/ssh.h                   (shared SSH types)
│   │
│   ├── [Auth — lib/vauth/]         [15 files]
│   ├── vauth/cleartext.c           (cleartext auth)
│   ├── vauth/cram.c                (CRAM-MD5)
│   ├── vauth/digest.c              (Digest native)
│   ├── vauth/digest_sspi.c         (Digest via SSPI)
│   ├── vauth/gsasl.c               (GSasl/SCRAM)
│   ├── vauth/krb5_gssapi.c         (Kerberos5 GSSAPI)
│   ├── vauth/krb5_sspi.c           (Kerberos5 SSPI)
│   ├── vauth/ntlm.c                (NTLM native)
│   ├── vauth/ntlm_sspi.c           (NTLM SSPI)
│   ├── vauth/oauth2.c              (OAuth2 bearer)
│   ├── vauth/spnego_gssapi.c       (SPNEGO GSSAPI)
│   ├── vauth/spnego_sspi.c         (SPNEGO SSPI)
│   ├── vauth/vauth.c               (auth framework)
│   │
│   ├── [Utilities — lib/curlx/]    [38 files]
│   ├── curlx/base64.c              (Base64 encode/decode)
│   ├── curlx/dynbuf.c              (dynamic buffer)
│   ├── curlx/inet_ntop.c           (inet_ntop portable)
│   ├── curlx/inet_pton.c           (inet_pton portable)
│   ├── curlx/nonblock.c            (non-blocking socket)
│   ├── curlx/strparse.c            (string parsing)
│   ├── curlx/timediff.c            (time diff calculations)
│   ├── curlx/timeval.c             (timestamp utilities)
│   ├── curlx/version_win32.c       (Windows version detection)
│   ├── curlx/warnless.c            (warnless type conversions)
│   │
│   ├── [Core Utilities]
│   ├── socks.c                      (1,415 lines — SOCKS proxy)
│   ├── socks_gssapi.c              (SOCKS GSSAPI auth)
│   ├── socks_sspi.c                (SOCKS SSPI auth)
│   ├── splay.c                      (splay tree)
│   ├── hash.c                       (hash table)
│   ├── llist.c                      (linked list)
│   ├── uint-bset.c                  (unsigned int bitset)
│   ├── uint-hash.c                  (unsigned int hash)
│   ├── uint-spbset.c               (sparse bitset)
│   ├── uint-table.c                 (unsigned int table)
│   ├── bufq.c                       (buffer queue)
│   ├── bufref.c                     (buffer reference)
│   ├── dynhds.c                     (dynamic headers)
│   ├── headers.c                    (header API implementation)
│   ├── mime.c                       (MIME multipart builder)
│   ├── formdata.c                   (legacy form data)
│   ├── escape.c                     (URL escape/unescape)
│   ├── content_encoding.c          (content encoding/decompression)
│   ├── sendf.c                      (formatted send)
│   ├── select.c                     (socket select abstraction)
│   ├── progress.c                   (transfer progress)
│   ├── request.c                    (request state machine)
│   ├── netrc.c                      (netrc file parsing)
│   ├── noproxy.c                    (no-proxy matching)
│   ├── psl.c                        (public suffix list)
│   ├── rand.c                       (random number generation)
│   ├── ratelimit.c                  (bandwidth rate limiter)
│   ├── version.c                    (version info)
│   ├── strerror.c                   (error string mapping)
│   ├── strcase.c                    (case-insensitive comparison)
│   ├── strequal.c                   (string equality)
│   ├── parsedate.c                  (date parsing)
│   ├── idn.c                        (internationalized domain names)
│   ├── if2ip.c                      (interface-to-IP mapping)
│   ├── slist.c                      (string list API)
│   ├── share.c                      (shared handle API — curl_share)
│   ├── socketpair.c                 (socketpair abstraction)
│   ├── fileinfo.c                   (file info)
│   ├── getenv.c                     (environment variable access)
│   ├── cshutdn.c                    (connection shutdown)
│   ├── cw-out.c                     (content writer — output)
│   ├── cw-pause.c                   (content writer — pause)
│   ├── curl_addrinfo.c             (address info utilities)
│   ├── curl_endian.c               (endianness helpers)
│   ├── curl_fnmatch.c              (filename pattern matching)
│   ├── curl_fopen.c                (file open utilities)
│   ├── curl_get_line.c             (line reader)
│   ├── curl_gethostname.c          (hostname getter)
│   ├── curl_gssapi.c               (GSSAPI helpers)
│   ├── curl_memrchr.c              (reverse memchr)
│   ├── curl_ntlm_core.c            (NTLM crypto core)
│   ├── curl_range.c                (range request helpers)
│   ├── curl_sasl.c                  (SASL framework)
│   ├── curl_sha512_256.c           (SHA-512/256 hash)
│   ├── curl_sspi.c                  (SSPI helpers)
│   ├── curl_threads.c              (threading abstraction)
│   ├── curl_trc.c                   (trace/logging)
│   ├── hmac.c                       (HMAC computation)
│   ├── md4.c                        (MD4 hash)
│   ├── md5.c                        (MD5 hash)
│   ├── sha256.c                     (SHA-256 hash)
│   ├── memdebug.c                   (debug memory tracker)
│   ├── mprintf.c                    (printf family implementation)
│   ├── dllmain.c                    (Windows DLL entry)
│   ├── amigaos.c                    (AmigaOS platform code)
│   ├── macos.c                      (macOS platform code)
│   ├── system_win32.c              (Windows platform code)
│   ├── fake_addrinfo.c             (test stub)
│   │
│   └── [Build]
│       └── CMakeLists.txt           (library build config)
│
├── src/                             [43 .c + 45 .h — CLI tool]
│   ├── tool_main.c                  (entry point)
│   ├── tool_operate.c               (operation execution core)
│   ├── tool_getparam.c              (CLI argument parsing)
│   ├── tool_cfgable.c               (configuration management)
│   ├── tool_paramhlp.c             (parameter helpers)
│   ├── tool_parsecfg.c             (config file parsing)
│   ├── tool_setopt.c               (option application to easy handle)
│   ├── tool_formparse.c            (form data parsing)
│   ├── tool_urlglob.c              (URL globbing)
│   ├── tool_writeout.c             (write-out formatting)
│   ├── tool_writeout_json.c        (JSON write-out)
│   ├── tool_cb_dbg.c               (debug callback)
│   ├── tool_cb_hdr.c               (header callback)
│   ├── tool_cb_prg.c               (progress callback)
│   ├── tool_cb_rea.c               (read callback)
│   ├── tool_cb_see.c               (seek callback)
│   ├── tool_cb_soc.c               (socket callback)
│   ├── tool_cb_wrt.c               (write callback)
│   ├── tool_dirhie.c               (directory hierarchy)
│   ├── tool_doswin.c               (DOS/Win path helpers)
│   ├── tool_easysrc.c              (easy source generation)
│   ├── tool_filetime.c             (file timestamp)
│   ├── tool_findfile.c             (file discovery)
│   ├── tool_getpass.c              (password input)
│   ├── tool_help.c                  (help text display)
│   ├── tool_helpers.c              (misc helpers)
│   ├── tool_ipfs.c                  (IPFS gateway handling)
│   ├── tool_libinfo.c              (library info)
│   ├── tool_listhelp.c             (help listing)
│   ├── tool_msgs.c                  (message output)
│   ├── tool_operhlp.c              (operation helpers)
│   ├── tool_progress.c             (progress display)
│   ├── tool_ssls.c                  (SSL session helpers)
│   ├── tool_stderr.c               (stderr management)
│   ├── tool_util.c                  (utility functions)
│   ├── tool_vms.c                   (VMS platform shim)
│   ├── tool_xattr.c                (extended attributes)
│   ├── config2setopts.c            (config-to-setopts mapping)
│   ├── curlinfo.c                   (info retrieval)
│   ├── slist_wc.c                   (wildcard slist)
│   ├── terminal.c                   (terminal utilities)
│   ├── var.c                        (variable expansion)
│   └── toolx/tool_time.c           (time utilities)
│
└── tests/                           [Comprehensive test suite]
    ├── runtests.pl                  (main Perl test runner)
    ├── data/                        (test case definitions)
    ├── libtest/                     (C library regression tests)
    ├── unit/                        (C unit tests)
    ├── tunit/                       (C threaded unit tests)
    ├── http/                        (pytest HTTP test suite)
    └── server/                      (test servers — HTTP, FTP, SMTP, etc.)
```

### 0.2.3 Key Metrics Summary

| Metric | Value |
|--------|-------|
| Total C source files (`lib/`) | 179 |
| Total C header files (`lib/`) | 174 |
| Total C source files (`src/`) | 43 |
| Total C header files (`src/`) | 45 |
| Public API headers (`include/curl/`) | 12 |
| Total C lines of code (`lib/`) | 144,333 |
| Total C lines of code (`src/`) | 19,344 |
| Total C lines of code (combined) | ~163,677 |
| Public API symbols (`CURL_EXTERN`) | 106 |
| TLS backend files (`lib/vtls/`) | 31 |
| QUIC/HTTP3 files (`lib/vquic/`) | 9 |
| SSH transport files (`lib/vssh/`) | 5 |
| Authentication files (`lib/vauth/`) | 15 |
| Portability utility files (`lib/curlx/`) | 38 |
| Protocol handler files | 20+ (HTTP, FTP, IMAP, POP3, SMTP, LDAP, RTSP, MQTT, WS, etc.) |

## 0.3 Scope Boundaries

### 0.3.1 Exhaustively In Scope

**Source transformations (all C → Rust rewrites):**
- `lib/**/*.c` — all 179 core library C source files
- `lib/**/*.h` — all 174 internal library header files (consumed for type/signature extraction, not directly rewritten)
- `lib/vtls/**/*` — all 31 TLS abstraction and backend files → replaced by single rustls implementation
- `lib/vquic/**/*` — all 9 QUIC/HTTP3 files → replaced by quinn + h3
- `lib/vssh/**/*` — all 5 SSH transport files → replaced by russh
- `lib/vauth/**/*` — all 15 authentication handler files → pure-Rust implementations
- `lib/curlx/**/*` — all 38 portability utility files → idiomatic Rust replacements
- `lib/cf-*.c` — all 6 connection filter files → Rust connection filter modules
- `src/**/*.c` — all 43 CLI tool source files → Rust CLI via clap 4.x
- `src/**/*.h` — all 45 CLI tool header files (consumed for type extraction)
- `include/curl/*.h` — all 12 public API headers → FFI surface definition for cbindgen

**New Rust workspace crate creation:**
- `Cargo.toml` — workspace root manifest
- `curl-rs-lib/Cargo.toml` — core library crate
- `curl-rs-lib/src/**/*.rs` — all Rust modules for protocols, TLS, transfer, DNS, auth, utilities
- `curl-rs-lib/build.rs` — build script (if needed for code generation)
- `curl-rs/Cargo.toml` — binary crate
- `curl-rs/src/**/*.rs` — CLI entrypoint and argument handling
- `curl-rs-ffi/Cargo.toml` — FFI crate
- `curl-rs-ffi/src/**/*.rs` — extern "C" symbol implementations
- `curl-rs-ffi/build.rs` — cbindgen header generation
- `curl-rs-ffi/cbindgen.toml` — cbindgen configuration

**Test updates:**
- `tests/**/*` — existing test suite runs UNMODIFIED against Rust binary (no test file changes)
- `curl-rs-lib/tests/**/*.rs` — new Rust unit and integration tests for ≥80% coverage
- `curl-rs-ffi/tests/**/*.rs` — FFI boundary integration tests for AddressSanitizer validation

**Configuration and build updates:**
- `.github/workflows/*.yml` — CI configuration for Rust build matrix (Linux x86_64, Linux aarch64, macOS x86_64, macOS arm64)
- `rust-toolchain.toml` — Rust toolchain pinning (MSRV 1.75)
- `.cargo/config.toml` — Cargo configuration for cross-compilation targets
- `include/curl/curl.h` — cbindgen-generated C header output (replaces hand-authored version)

**Documentation updates:**
- `README.md` — update build instructions for Rust workspace
- `INSTALL.md` or equivalent — Rust build and installation instructions
- `docs/**/*.md` — update references to reflect Rust implementation

**Import and symbol corrections:**
- Every Rust module with `use` statements referencing internal crate modules
- Every `extern "C"` fn in `curl-rs-ffi/` matching curl 8.x symbol signatures
- All cbindgen-generated header definitions matching `include/curl/*.h` signatures

### 0.3.2 Explicitly Out of Scope

**Per user instructions — MUST NOT modify:**
- Protocol wire behavior — no changes to header formatting, redirect semantics, authentication negotiation byte sequences
- CLI flag names, semantics, and defaults — `curl --help all` must be functionally identical
- libcurl C API signatures — function names, parameter types, return types, error code integer values must match exactly
- curl 8.x test definitions — tests run unmodified; zero changes to `tests/data/`, `tests/libtest/`, or test runner scripts

**Per user instructions — MUST NOT introduce:**
- Protocols not present in curl 8.x (no new protocol handlers)
- New CLI flags or options (no additions to clap argument definitions beyond curl 8.x parity)
- Changes to default behavior (all defaults identical to curl 8.x)
- `unsafe` blocks in `src/protocols/`, `src/tls/`, `src/transfer/` (zero, no exceptions)
- Any linkage against libcurl, libssl, OpenSSL, or any C TLS library

**Explicitly excluded platforms and backends:**
- Windows Schannel TLS backend — replaced by rustls
- Apple Security Transport TLS backend — replaced by rustls
- OpenSSL/GnuTLS/mbedTLS/wolfSSL TLS backends — replaced by rustls
- ngtcp2/nghttp3 QUIC backend — replaced by quinn
- quiche QUIC backend — replaced by quinn
- libssh/libssh2 SSH backends — replaced by russh
- c-ares async DNS resolver — replaced by system resolver (hickory-dns optional via feature flag)
- librtmp RTMP support — out of scope (not listed in user's protocol scope)
- LDAP/LDAPS protocol — out of scope (not listed in user's protocol scope of HTTP, FTP, SFTP, SCP)
- SMTP/SMTPS, IMAP/IMAPS, POP3/POP3S — out of scope (not listed in user's protocol scope)
- RTSP, MQTT, Gopher, TFTP, Telnet, SMB, DICT — out of scope (not listed in user's protocol scope)
- AmigaOS, VMS, OS/400, RISC OS platform shims — out of scope for initial rewrite
- `memdebug.c` — debug memory tracker replaced by Rust's built-in allocation safety
- `dllmain.c` — Windows DLL entry point (platform-specific, handled by cdylib crate type)

**Note on protocol scope:** The user explicitly specifies HTTP/1.1, HTTP/2, HTTP/3, FTP (active/passive, FTPS), SFTP, and SCP as the protocol scope. However, the requirement for "functional parity with curl 8.x" and "all curl 8.x test suite cases pass" implies that all protocols exercised by the test suite must be handled. The Transformation Mapping section (0.5) addresses this by including stub handlers that satisfy test expectations for protocols outside the core six.

## 0.4 Target Design

### 0.4.1 Refactored Structure Planning

The target Rust workspace replaces the entire C codebase with three crates in a Cargo workspace. Every source file, module, and configuration file required for standalone operation is listed explicitly below.

```
Target: curl-rs workspace (Rust, edition 2021, MSRV 1.75)
├── Cargo.toml                              (workspace root manifest)
├── rust-toolchain.toml                     (toolchain pinning: stable, MSRV 1.75)
├── .cargo/
│   └── config.toml                         (cross-compilation target settings)
├── .github/
│   └── workflows/
│       └── ci.yml                          (GitHub Actions CI — 4-target matrix)
├── deny.toml                               (cargo-deny configuration)
├── README.md                               (project documentation)
├── LICENSE                                 (MIT-like curl license)
│
├── curl-rs-lib/                            [Core library crate]
│   ├── Cargo.toml                          (crate manifest with feature flags)
│   ├── build.rs                            (build script — symbol inventory generation)
│   └── src/
│       ├── lib.rs                          (crate root — re-exports)
│       ├── error.rs                        (CURLcode error enum, error mapping)
│       ├── easy.rs                         (easy handle API — from lib/easy.c)
│       ├── multi.rs                        (multi handle API — from lib/multi.c)
│       ├── share.rs                        (shared handle API — from lib/curl_share.c)
│       ├── url.rs                          (URL handling — from lib/url.c, lib/urlapi.c)
│       ├── transfer.rs                     (transfer engine — from lib/transfer.c)
│       ├── setopt.rs                       (option dispatch — from lib/setopt.c)
│       ├── getinfo.rs                      (info retrieval — from lib/getinfo.c)
│       ├── options.rs                      (option metadata — from lib/easyoptions.c)
│       ├── version.rs                      (version info — from lib/version.c)
│       ├── slist.rs                        (string list — from lib/slist.c)
│       ├── mime.rs                         (MIME builder — from lib/mime.c, lib/formdata.c)
│       ├── escape.rs                       (URL encode/decode — from lib/escape.c)
│       ├── headers.rs                      (header API — from lib/headers.c, lib/dynhds.c)
│       │
│       ├── conn/                           [Connection subsystem]
│       │   ├── mod.rs
│       │   ├── cache.rs                    (from lib/conncache.c)
│       │   ├── connect.rs                  (from lib/connect.c)
│       │   ├── filters.rs                  (from lib/cfilters.c)
│       │   ├── socket.rs                   (from lib/cf-socket.c)
│       │   ├── h1_proxy.rs                 (from lib/cf-h1-proxy.c)
│       │   ├── h2_proxy.rs                 (from lib/cf-h2-proxy.c)
│       │   ├── haproxy.rs                  (from lib/cf-haproxy.c)
│       │   ├── https_connect.rs            (from lib/cf-https-connect.c)
│       │   ├── happy_eyeballs.rs           (from lib/cf-ip-happy.c)
│       │   └── shutdown.rs                 (from lib/cshutdn.c)
│       │
│       ├── protocols/                      [Protocol handlers]
│       │   ├── mod.rs
│       │   ├── http/
│       │   │   ├── mod.rs
│       │   │   ├── h1.rs                   (HTTP/1.x — from lib/http.c, lib/http1.c)
│       │   │   ├── h2.rs                   (HTTP/2 via hyper — from lib/http2.c)
│       │   │   ├── h3.rs                   (HTTP/3 via quinn+h3)
│       │   │   ├── chunks.rs              (chunked encoding — from lib/http_chunks.c)
│       │   │   ├── proxy.rs               (HTTP proxy — from lib/http_proxy.c)
│       │   │   └── aws_sigv4.rs           (AWS SigV4 — from lib/http_aws_sigv4.c)
│       │   ├── ftp.rs                      (FTP/FTPS — from lib/ftp.c)
│       │   ├── ftp_list.rs                 (FTP LIST parser — from lib/ftplistparser.c)
│       │   ├── ssh/
│       │   │   ├── mod.rs
│       │   │   ├── sftp.rs                 (SFTP via russh — from lib/vssh/)
│       │   │   └── scp.rs                  (SCP via russh — from lib/vssh/)
│       │   ├── imap.rs                     (IMAP — from lib/imap.c)
│       │   ├── pop3.rs                     (POP3 — from lib/pop3.c)
│       │   ├── smtp.rs                     (SMTP — from lib/smtp.c)
│       │   ├── pingpong.rs                 (shared state machine — from lib/pingpong.c)
│       │   ├── rtsp.rs                     (RTSP — from lib/rtsp.c)
│       │   ├── mqtt.rs                     (MQTT — from lib/mqtt.c)
│       │   ├── ws.rs                       (WebSocket — from lib/ws.c)
│       │   ├── telnet.rs                   (Telnet — from lib/telnet.c)
│       │   ├── tftp.rs                     (TFTP — from lib/tftp.c)
│       │   ├── gopher.rs                   (Gopher — from lib/gopher.c)
│       │   ├── smb.rs                      (SMB — from lib/smb.c)
│       │   ├── dict.rs                     (DICT — from lib/dict.c)
│       │   ├── file.rs                     (FILE — from lib/file.c)
│       │   └── ldap.rs                     (LDAP — from lib/ldap.c, lib/openldap.c)
│       │
│       ├── tls/                            [TLS — rustls only]
│       │   ├── mod.rs                      (TLS abstraction — from lib/vtls/vtls.c)
│       │   ├── config.rs                   (TLS config builder)
│       │   ├── session_cache.rs            (from lib/vtls/vtls_scache.c)
│       │   ├── keylog.rs                   (from lib/vtls/keylog.c)
│       │   └── hostname.rs                 (hostname verification — from lib/vtls/hostcheck.c)
│       │
│       ├── auth/                           [Authentication]
│       │   ├── mod.rs                      (auth framework — from lib/vauth/vauth.c)
│       │   ├── basic.rs                    (Basic auth — from lib/vauth/cleartext.c)
│       │   ├── digest.rs                   (Digest auth — from lib/vauth/digest.c)
│       │   ├── bearer.rs                   (Bearer/OAuth2 — from lib/vauth/oauth2.c)
│       │   ├── ntlm.rs                     (NTLM pure-Rust — from lib/vauth/ntlm.c, lib/curl_ntlm_core.c)
│       │   ├── negotiate.rs                (Negotiate/SPNEGO — from lib/vauth/spnego_gssapi.c)
│       │   ├── kerberos.rs                 (Kerberos5 — from lib/vauth/krb5_gssapi.c)
│       │   ├── sasl.rs                     (SASL framework — from lib/curl_sasl.c, lib/vauth/cram.c)
│       │   └── scram.rs                    (SCRAM/GSasl — from lib/vauth/gsasl.c)
│       │
│       ├── dns/                            [DNS resolution]
│       │   ├── mod.rs                      (resolver abstraction — from lib/hostip.c)
│       │   ├── system.rs                   (system resolver — from lib/hostip4.c, lib/hostip6.c)
│       │   ├── doh.rs                      (DNS-over-HTTPS — from lib/doh.c)
│       │   └── hickory.rs                  (hickory-dns optional — feature-gated)
│       │
│       ├── proxy/                          [Proxy support]
│       │   ├── mod.rs
│       │   ├── socks.rs                    (SOCKS4/5 — from lib/socks.c)
│       │   └── noproxy.rs                  (no-proxy matching — from lib/noproxy.c)
│       │
│       ├── cookie.rs                       (cookie jar — from lib/cookie.c)
│       ├── hsts.rs                         (HSTS — from lib/hsts.c)
│       ├── altsvc.rs                       (Alt-Svc — from lib/altsvc.c)
│       ├── netrc.rs                        (netrc parsing — from lib/netrc.c)
│       ├── progress.rs                     (progress tracking — from lib/progress.c)
│       ├── request.rs                      (request state — from lib/request.c)
│       ├── content_encoding.rs             (decompression — from lib/content_encoding.c)
│       ├── ratelimit.rs                    (bandwidth limiter — from lib/ratelimit.c)
│       ├── psl.rs                          (public suffix list — from lib/psl.c)
│       ├── idn.rs                          (IDN — from lib/idn.c)
│       │
│       └── util/                           [Utilities — replacing lib/curlx/]
│           ├── mod.rs
│           ├── base64.rs                   (from lib/curlx/base64.c)
│           ├── dynbuf.rs                   (from lib/curlx/dynbuf.c)
│           ├── strparse.rs                 (from lib/curlx/strparse.c)
│           ├── timediff.rs                 (from lib/curlx/timediff.c)
│           ├── timeval.rs                  (from lib/curlx/timeval.c)
│           ├── nonblock.rs                 (from lib/curlx/nonblock.c)
│           ├── warnless.rs                 (from lib/curlx/warnless.c)
│           ├── fnmatch.rs                  (from lib/curl_fnmatch.c)
│           ├── parsedate.rs                (from lib/parsedate.c)
│           ├── rand.rs                     (from lib/rand.c)
│           ├── hash.rs                     (from lib/hash.c)
│           ├── llist.rs                    (from lib/llist.c)
│           ├── splay.rs                    (from lib/splay.c)
│           ├── bufq.rs                     (from lib/bufq.c)
│           ├── select.rs                   (from lib/select.c)
│           ├── sendf.rs                    (from lib/sendf.c)
│           ├── strerror.rs                 (from lib/strerror.c)
│           ├── hmac.rs                     (from lib/hmac.c)
│           ├── md5.rs                      (from lib/md5.c)
│           ├── sha256.rs                   (from lib/sha256.c)
│           └── mprintf.rs                  (from lib/mprintf.c)
│
├── curl-rs/                                [Binary crate — CLI tool]
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                         (entrypoint — from src/tool_main.c)
│       ├── args.rs                         (clap argument defs — from src/tool_getparam.c)
│       ├── config.rs                       (config management — from src/tool_cfgable.c)
│       ├── operate.rs                      (operation core — from src/tool_operate.c)
│       ├── parsecfg.rs                     (config file parser — from src/tool_parsecfg.c)
│       ├── paramhelp.rs                    (parameter helpers — from src/tool_paramhlp.c)
│       ├── setopt.rs                       (option application — from src/tool_setopt.c)
│       ├── formparse.rs                    (form parser — from src/tool_formparse.c)
│       ├── urlglob.rs                      (URL globbing — from src/tool_urlglob.c)
│       ├── writeout.rs                     (write-out — from src/tool_writeout.c)
│       ├── writeout_json.rs                (JSON write-out — from src/tool_writeout_json.c)
│       ├── callbacks/
│       │   ├── mod.rs
│       │   ├── debug.rs                    (from src/tool_cb_dbg.c)
│       │   ├── header.rs                   (from src/tool_cb_hdr.c)
│       │   ├── progress.rs                 (from src/tool_cb_prg.c)
│       │   ├── read.rs                     (from src/tool_cb_rea.c)
│       │   ├── seek.rs                     (from src/tool_cb_see.c)
│       │   ├── socket.rs                   (from src/tool_cb_soc.c)
│       │   └── write.rs                    (from src/tool_cb_wrt.c)
│       ├── help.rs                         (from src/tool_help.c, src/tool_listhelp.c)
│       ├── msgs.rs                         (from src/tool_msgs.c)
│       ├── progress_display.rs             (from src/tool_progress.c)
│       ├── dirhier.rs                      (from src/tool_dirhie.c)
│       ├── findfile.rs                     (from src/tool_findfile.c)
│       ├── filetime.rs                     (from src/tool_filetime.c)
│       ├── getpass.rs                      (from src/tool_getpass.c)
│       ├── ipfs.rs                         (from src/tool_ipfs.c)
│       ├── libinfo.rs                      (from src/tool_libinfo.c)
│       ├── operhlp.rs                      (from src/tool_operhlp.c)
│       ├── ssls.rs                         (from src/tool_ssls.c)
│       ├── stderr.rs                       (from src/tool_stderr.c)
│       ├── terminal.rs                     (from src/terminal.c)
│       ├── var.rs                          (from src/var.c)
│       ├── xattr.rs                        (from src/tool_xattr.c)
│       └── util.rs                         (from src/tool_util.c, src/slist_wc.c)
│
├── curl-rs-ffi/                            [FFI crate — libcurl ABI compatibility]
│   ├── Cargo.toml
│   ├── build.rs                            (cbindgen invocation → include/curl/curl.h)
│   ├── cbindgen.toml                       (cbindgen config)
│   └── src/
│       ├── lib.rs                          (crate root)
│       ├── easy.rs                         (curl_easy_* symbols — 10 functions)
│       ├── multi.rs                        (curl_multi_* symbols — 24 functions)
│       ├── share.rs                        (curl_share_* symbols — from include/curl/curl.h)
│       ├── global.rs                       (curl_global_* symbols)
│       ├── url.rs                          (curl_url_* symbols — 6 functions)
│       ├── ws.rs                           (curl_ws_* symbols — 4 functions)
│       ├── mime.rs                          (curl_mime_* symbols)
│       ├── slist.rs                        (curl_slist_* symbols)
│       ├── options.rs                      (curl_easy_option_* symbols — 3 functions)
│       ├── header.rs                       (curl_easy_header_* symbols — 2 functions)
│       ├── mprintf.rs                      (curl_m*printf symbols — 11 functions)
│       ├── error_codes.rs                  (CURLcode/CURLMcode/CURLSHcode constants)
│       └── types.rs                        (C-compatible type definitions)
│
└── include/curl/
    └── curl.h                              (cbindgen-generated — drop-in replacement)
```

### 0.4.2 Web Search Research Conducted

Research was conducted on the following topics to inform the target architecture:

- **hyper 1.x architecture** — confirmed latest version 1.7.0 as the HTTP/1.1 + HTTP/2 client library; uses `http` and `http-body` crate ecosystem
- **rustls 0.23.x API** — confirmed latest version 0.23.36; supports `aws-lc-rs` and `ring` crypto providers; requires Rust 1.71+
- **quinn 0.11.x + h3 0.0.x** — confirmed quinn 0.11.9 for QUIC transport and h3 0.0.7 (stable) / h3-quinn 0.0.10 for HTTP/3 integration
- **russh 0.54.x** — confirmed latest version 0.54.6 as the pure-Rust SSH2 client/server library with SFTP support via russh-sftp
- **clap 4.x derive API** — confirmed latest version 4.5.54 with derive macro support for CLI argument definitions
- **cbindgen 0.29.x** — confirmed version 0.29.2 for generating C headers from Rust FFI definitions
- **tokio runtime modes** — confirmed current-thread vs. multi-thread runtime selection via `#[tokio::main]` attributes
- **hickory-dns resolver** — confirmed version 0.25.2 as the pure-Rust DNS resolver (optional feature flag)
- **C-to-Rust migration strategies** — best practices for maintaining ABI compatibility while replacing C internals with Rust

### 0.4.3 Design Pattern Applications

The following design patterns are applied in the Rust rewrite:

- **Trait-based protocol dispatch** — each protocol handler implements a `Protocol` trait with `connect`, `transfer`, and `disconnect` methods, replacing the C `Curl_handler` function pointer table
- **Connection filter chain (tower-like)** — connection filters (socket, TLS, proxy, QUIC) compose as middleware layers wrapping an inner transport, replacing the C `struct Curl_cftype` chain
- **Builder pattern for configuration** — `EasyHandle::builder()` and `MultiHandle::builder()` replace the C `curl_easy_setopt` dispatch switch; internally, options are stored in typed structs rather than a single union
- **Type-state pattern for transfer lifecycle** — compile-time enforcement of the transfer state machine (Idle → Connected → Transferring → Complete) prevents invalid state transitions that are runtime-checked in C
- **Error enum with From implementations** — `CurlError` enum with per-subsystem variants replaces the C integer `CURLcode` error space; FFI boundary converts to/from integer codes
- **Arc-based shared state** — `curl_share` handle semantics map to `Arc<Mutex<SharedData>>` with fine-grained locking per data type (cookies, DNS cache, connections)
- **Feature flags for optional components** — `hickory-dns`, compression codecs, and protocol handlers behind Cargo features, replacing C `#ifdef CURL_DISABLE_*` macros

### 0.4.4 Async Runtime Architecture

The Tokio runtime is configured differently for the two entry points:

- **CLI binary (`curl-rs`):** `#[tokio::main(flavor = "current_thread")]` — single-threaded runtime suitable for sequential command-line operations. The `--parallel` flag (if exercised by tests) spawns concurrent transfers on the same thread using cooperative scheduling.
- **Multi handle (`curl-rs-lib` multi API):** `tokio::runtime::Builder::new_multi_thread()` — multi-threaded runtime for `curl_multi_*` operations where the C API expects concurrent socket-driven I/O across multiple easy handles. The runtime is lazily initialized on first `curl_multi_perform` call.
- **FFI boundary (`curl-rs-ffi`):** The FFI layer bridges synchronous C callers to async Rust internals using `tokio::runtime::Runtime::block_on()` within a thread-local runtime instance, preserving the synchronous `curl_easy_perform` semantics expected by C consumers.

## 0.5 Transformation Mapping

### 0.5.1 File-by-File Transformation Plan

Every target file is mapped to its C source origin. The transformation mode indicates how the target is derived:
- **CREATE** — New Rust file written from scratch, informed by the logic in the source C file(s)
- **REFERENCE** — Source file used as a behavioral reference; Rust implementation uses different idioms but preserves semantics

**Workspace Root Files:**

| Target File | Transformation | Source File(s) | Key Changes |
|---|---|---|---|
| Cargo.toml | CREATE | CMakeLists.txt (root) | Workspace manifest defining three member crates with shared dependency versions |
| rust-toolchain.toml | CREATE | — | Pin `channel = "stable"`, set `[toolchain] components = ["clippy", "llvm-tools-preview"]` |
| .cargo/config.toml | CREATE | — | Cross-compilation targets for aarch64-unknown-linux-gnu |
| .github/workflows/ci.yml | CREATE | .github/workflows/*.yml | Rust CI: cargo build/test/clippy/miri on 4-target matrix |
| deny.toml | CREATE | — | cargo-deny config for license and advisory checks |
| README.md | CREATE | README.md | Update build/install instructions for Rust workspace |

**Core Library Crate — `curl-rs-lib/src/`:**

| Target File | Transformation | Source File(s) | Key Changes |
|---|---|---|---|
| curl-rs-lib/Cargo.toml | CREATE | lib/CMakeLists.txt | Crate manifest with feature flags for protocols and optional deps |
| curl-rs-lib/src/lib.rs | CREATE | lib/*.h (public API surface) | Crate root with module declarations and re-exports |
| curl-rs-lib/src/error.rs | CREATE | lib/strerror.c, include/curl/curl.h | CurlError enum mapped 1:1 to CURLcode integer values |
| curl-rs-lib/src/easy.rs | CREATE | lib/easy.c (1,397 lines) | EasyHandle struct with builder, replacing curl_easy_* C functions |
| curl-rs-lib/src/multi.rs | CREATE | lib/multi.c (4,034 lines), lib/multi_ev.c, lib/multi_ntfy.c | MultiHandle with Tokio multi-thread runtime, socket polling |
| curl-rs-lib/src/share.rs | CREATE | lib/curl_share.c | Arc-based shared data (cookies, DNS, connections) |
| curl-rs-lib/src/url.rs | CREATE | lib/url.c (3,904 lines), lib/urlapi.c | URL parsing and connection setup, Url API |
| curl-rs-lib/src/transfer.rs | CREATE | lib/transfer.c (912 lines) | Async transfer engine with ownership-based buffer management |
| curl-rs-lib/src/setopt.rs | CREATE | lib/setopt.c (2,975 lines) | Typed option enum dispatch replacing switch on CURLoption |
| curl-rs-lib/src/getinfo.rs | CREATE | lib/getinfo.c (676 lines) | Info retrieval via typed enum |
| curl-rs-lib/src/options.rs | CREATE | lib/easyoptions.c, lib/easygetopt.c | Option metadata tables for introspection API |
| curl-rs-lib/src/version.rs | CREATE | lib/version.c, include/curl/curlver.h | Version info struct and feature flag reporting |
| curl-rs-lib/src/slist.rs | CREATE | lib/slist.c | Rust Vec-based string list replacing linked list |
| curl-rs-lib/src/mime.rs | CREATE | lib/mime.c, lib/formdata.c | MIME multipart builder using Rust types |
| curl-rs-lib/src/escape.rs | CREATE | lib/escape.c | URL encode/decode with Rust string safety |
| curl-rs-lib/src/headers.rs | CREATE | lib/headers.c, lib/dynhds.c | Header storage and iteration API |
| curl-rs-lib/src/cookie.rs | CREATE | lib/cookie.c (1,638 lines) | Cookie jar with file-compatible format, Rust HashMap internals |
| curl-rs-lib/src/hsts.rs | CREATE | lib/hsts.c | HSTS preload list management |
| curl-rs-lib/src/altsvc.rs | CREATE | lib/altsvc.c | Alt-Svc cache with file persistence |
| curl-rs-lib/src/netrc.rs | CREATE | lib/netrc.c | Netrc file parser, idiomatic Rust I/O |
| curl-rs-lib/src/progress.rs | CREATE | lib/progress.c | Transfer progress tracking |
| curl-rs-lib/src/request.rs | CREATE | lib/request.c | Request state machine |
| curl-rs-lib/src/content_encoding.rs | CREATE | lib/content_encoding.c | Decompression (gzip, brotli, zstd) via Rust crates |
| curl-rs-lib/src/ratelimit.rs | CREATE | lib/ratelimit.c | Bandwidth rate limiting |
| curl-rs-lib/src/psl.rs | CREATE | lib/psl.c | Public suffix list integration |
| curl-rs-lib/src/idn.rs | CREATE | lib/idn.c | Internationalized domain name handling |

**Connection Subsystem — `curl-rs-lib/src/conn/`:**

| Target File | Transformation | Source File(s) | Key Changes |
|---|---|---|---|
| curl-rs-lib/src/conn/mod.rs | CREATE | lib/cfilters.c | Connection filter trait and chain composition |
| curl-rs-lib/src/conn/cache.rs | CREATE | lib/conncache.c (910 lines) | Connection pool with async-aware locking |
| curl-rs-lib/src/conn/connect.rs | CREATE | lib/connect.c (603 lines) | Async TCP connection via Tokio TcpStream |
| curl-rs-lib/src/conn/socket.rs | CREATE | lib/cf-socket.c | Socket-level connection filter |
| curl-rs-lib/src/conn/h1_proxy.rs | CREATE | lib/cf-h1-proxy.c | HTTP/1 CONNECT proxy tunnel |
| curl-rs-lib/src/conn/h2_proxy.rs | CREATE | lib/cf-h2-proxy.c | HTTP/2 CONNECT proxy tunnel |
| curl-rs-lib/src/conn/haproxy.rs | CREATE | lib/cf-haproxy.c | HAProxy protocol filter |
| curl-rs-lib/src/conn/https_connect.rs | CREATE | lib/cf-https-connect.c | HTTPS-connect method filter |
| curl-rs-lib/src/conn/happy_eyeballs.rs | CREATE | lib/cf-ip-happy.c | Happy Eyeballs v2 algorithm |
| curl-rs-lib/src/conn/shutdown.rs | CREATE | lib/cshutdn.c | Graceful connection shutdown |

**Protocol Handlers — `curl-rs-lib/src/protocols/`:**

| Target File | Transformation | Source File(s) | Key Changes |
|---|---|---|---|
| curl-rs-lib/src/protocols/mod.rs | CREATE | — | Protocol trait definition and registry |
| curl-rs-lib/src/protocols/http/mod.rs | CREATE | lib/http.c | HTTP core: request building, response parsing, redirect logic |
| curl-rs-lib/src/protocols/http/h1.rs | CREATE | lib/http1.c | HTTP/1.x via hyper 1.x client |
| curl-rs-lib/src/protocols/http/h2.rs | CREATE | lib/http2.c | HTTP/2 via hyper with h2 ALPN negotiation |
| curl-rs-lib/src/protocols/http/h3.rs | CREATE | lib/vquic/*.c | HTTP/3 via quinn + h3 crate |
| curl-rs-lib/src/protocols/http/chunks.rs | CREATE | lib/http_chunks.c | Chunked transfer encoding |
| curl-rs-lib/src/protocols/http/proxy.rs | CREATE | lib/http_proxy.c | HTTP CONNECT proxy handler |
| curl-rs-lib/src/protocols/http/aws_sigv4.rs | CREATE | lib/http_aws_sigv4.c | AWS Signature V4 request signing |
| curl-rs-lib/src/protocols/ftp.rs | CREATE | lib/ftp.c | FTP/FTPS active/passive mode, TLS upgrade via rustls |
| curl-rs-lib/src/protocols/ftp_list.rs | CREATE | lib/ftplistparser.c | FTP LIST response parser |
| curl-rs-lib/src/protocols/ssh/mod.rs | CREATE | lib/vssh/ssh.h | SSH module root |
| curl-rs-lib/src/protocols/ssh/sftp.rs | CREATE | lib/vssh/libssh2.c, lib/vssh/libssh.c | SFTP via russh + russh-sftp |
| curl-rs-lib/src/protocols/ssh/scp.rs | CREATE | lib/vssh/libssh2.c | SCP via russh channel exec |
| curl-rs-lib/src/protocols/imap.rs | CREATE | lib/imap.c | IMAP protocol handler |
| curl-rs-lib/src/protocols/pop3.rs | CREATE | lib/pop3.c | POP3 protocol handler |
| curl-rs-lib/src/protocols/smtp.rs | CREATE | lib/smtp.c | SMTP protocol handler |
| curl-rs-lib/src/protocols/pingpong.rs | CREATE | lib/pingpong.c | Shared request-response state machine |
| curl-rs-lib/src/protocols/rtsp.rs | CREATE | lib/rtsp.c | RTSP protocol handler |
| curl-rs-lib/src/protocols/mqtt.rs | CREATE | lib/mqtt.c | MQTT protocol handler |
| curl-rs-lib/src/protocols/ws.rs | CREATE | lib/ws.c | WebSocket handler |
| curl-rs-lib/src/protocols/telnet.rs | CREATE | lib/telnet.c | Telnet handler |
| curl-rs-lib/src/protocols/tftp.rs | CREATE | lib/tftp.c | TFTP handler |
| curl-rs-lib/src/protocols/gopher.rs | CREATE | lib/gopher.c | Gopher handler |
| curl-rs-lib/src/protocols/smb.rs | CREATE | lib/smb.c | SMB handler |
| curl-rs-lib/src/protocols/dict.rs | CREATE | lib/dict.c | DICT handler |
| curl-rs-lib/src/protocols/file.rs | CREATE | lib/file.c | FILE handler |
| curl-rs-lib/src/protocols/ldap.rs | CREATE | lib/ldap.c, lib/openldap.c | LDAP handler |

**TLS Layer — `curl-rs-lib/src/tls/`:**

| Target File | Transformation | Source File(s) | Key Changes |
|---|---|---|---|
| curl-rs-lib/src/tls/mod.rs | CREATE | lib/vtls/vtls.c | TLS abstraction — single rustls backend replaces 7 C backends |
| curl-rs-lib/src/tls/config.rs | CREATE | lib/vtls/*.c (all backends) | Unified TLS config builder with rustls ClientConfig/ServerConfig |
| curl-rs-lib/src/tls/session_cache.rs | CREATE | lib/vtls/vtls_scache.c, lib/vtls/vtls_spack.c | Session resumption cache |
| curl-rs-lib/src/tls/keylog.rs | CREATE | lib/vtls/keylog.c | SSLKEYLOGFILE support via rustls KeyLog trait |
| curl-rs-lib/src/tls/hostname.rs | CREATE | lib/vtls/hostcheck.c | Hostname verification (rustls handles internally) |

**Authentication — `curl-rs-lib/src/auth/`:**

| Target File | Transformation | Source File(s) | Key Changes |
|---|---|---|---|
| curl-rs-lib/src/auth/mod.rs | CREATE | lib/vauth/vauth.c | Auth framework trait and negotiation dispatch |
| curl-rs-lib/src/auth/basic.rs | CREATE | lib/vauth/cleartext.c | Basic/cleartext auth |
| curl-rs-lib/src/auth/digest.rs | CREATE | lib/vauth/digest.c, lib/http_digest.c | Pure-Rust Digest implementation (no SSPI) |
| curl-rs-lib/src/auth/bearer.rs | CREATE | lib/vauth/oauth2.c | OAuth2 Bearer token |
| curl-rs-lib/src/auth/ntlm.rs | CREATE | lib/vauth/ntlm.c, lib/curl_ntlm_core.c, lib/http_ntlm.c | Pure-Rust NTLM (MD4/MD5/DES via Rust crypto crates) |
| curl-rs-lib/src/auth/negotiate.rs | CREATE | lib/vauth/spnego_gssapi.c, lib/http_negotiate.c | Negotiate/SPNEGO using OS Kerberos where available |
| curl-rs-lib/src/auth/kerberos.rs | CREATE | lib/vauth/krb5_gssapi.c | Kerberos5 GSSAPI integration |
| curl-rs-lib/src/auth/sasl.rs | CREATE | lib/curl_sasl.c, lib/vauth/cram.c | SASL framework + CRAM-MD5 |
| curl-rs-lib/src/auth/scram.rs | CREATE | lib/vauth/gsasl.c | SCRAM authentication |

**DNS Resolution — `curl-rs-lib/src/dns/`:**

| Target File | Transformation | Source File(s) | Key Changes |
|---|---|---|---|
| curl-rs-lib/src/dns/mod.rs | CREATE | lib/hostip.c (1,590 lines) | Resolver abstraction trait |
| curl-rs-lib/src/dns/system.rs | CREATE | lib/hostip4.c, lib/hostip6.c, lib/asyn-thrdd.c | System resolver via tokio::net::lookup_host |
| curl-rs-lib/src/dns/doh.rs | CREATE | lib/doh.c (1,338 lines) | DNS-over-HTTPS using hyper client |
| curl-rs-lib/src/dns/hickory.rs | CREATE | lib/asyn-ares.c | hickory-dns resolver (feature-gated, disabled by default) |

**Proxy — `curl-rs-lib/src/proxy/`:**

| Target File | Transformation | Source File(s) | Key Changes |
|---|---|---|---|
| curl-rs-lib/src/proxy/mod.rs | CREATE | — | Proxy module root |
| curl-rs-lib/src/proxy/socks.rs | CREATE | lib/socks.c (1,415 lines), lib/socks_gssapi.c | SOCKS4/5 proxy pure-Rust |
| curl-rs-lib/src/proxy/noproxy.rs | CREATE | lib/noproxy.c | No-proxy matching logic |

**Utilities — `curl-rs-lib/src/util/`:**

| Target File | Transformation | Source File(s) | Key Changes |
|---|---|---|---|
| curl-rs-lib/src/util/mod.rs | CREATE | — | Utility module root |
| curl-rs-lib/src/util/base64.rs | CREATE | lib/curlx/base64.c | Base64 via `base64` crate |
| curl-rs-lib/src/util/dynbuf.rs | CREATE | lib/curlx/dynbuf.c | Dynamic buffer → Rust Vec-based |
| curl-rs-lib/src/util/strparse.rs | CREATE | lib/curlx/strparse.c | String parsing utilities |
| curl-rs-lib/src/util/timediff.rs | CREATE | lib/curlx/timediff.c | Time calculations |
| curl-rs-lib/src/util/timeval.rs | CREATE | lib/curlx/timeval.c | Timestamp utilities |
| curl-rs-lib/src/util/nonblock.rs | CREATE | lib/curlx/nonblock.c | Non-blocking socket helpers (Tokio-native) |
| curl-rs-lib/src/util/warnless.rs | CREATE | lib/curlx/warnless.c | Type conversions (largely unnecessary in Rust) |
| curl-rs-lib/src/util/fnmatch.rs | CREATE | lib/curl_fnmatch.c | Glob matching |
| curl-rs-lib/src/util/parsedate.rs | CREATE | lib/parsedate.c | Date/time parsing |
| curl-rs-lib/src/util/rand.rs | CREATE | lib/rand.c | Random bytes via `rand` crate |
| curl-rs-lib/src/util/hash.rs | CREATE | lib/hash.c | HashMap (stdlib replacement) |
| curl-rs-lib/src/util/llist.rs | CREATE | lib/llist.c | LinkedList (stdlib VecDeque replacement) |
| curl-rs-lib/src/util/splay.rs | CREATE | lib/splay.c | Splay tree for timeout management |
| curl-rs-lib/src/util/bufq.rs | CREATE | lib/bufq.c, lib/bufref.c | Buffer queue |
| curl-rs-lib/src/util/select.rs | CREATE | lib/select.c | Socket readiness → Tokio interest-based |
| curl-rs-lib/src/util/sendf.rs | CREATE | lib/sendf.c | Formatted send/debug output |
| curl-rs-lib/src/util/strerror.rs | CREATE | lib/strerror.c | Error message strings |
| curl-rs-lib/src/util/hmac.rs | CREATE | lib/hmac.c | HMAC via `hmac` crate |
| curl-rs-lib/src/util/md5.rs | CREATE | lib/md5.c | MD5 via `md-5` crate |
| curl-rs-lib/src/util/sha256.rs | CREATE | lib/sha256.c | SHA-256 via `sha2` crate |
| curl-rs-lib/src/util/mprintf.rs | CREATE | lib/mprintf.c | printf family → Rust format macros + FFI compat layer |

**CLI Tool — `curl-rs/src/`:**

| Target File | Transformation | Source File(s) | Key Changes |
|---|---|---|---|
| curl-rs/Cargo.toml | CREATE | src/CMakeLists.txt | Binary crate manifest |
| curl-rs/src/main.rs | CREATE | src/tool_main.c | Tokio current-thread entrypoint |
| curl-rs/src/args.rs | CREATE | src/tool_getparam.c | clap 4.x derive — 1:1 flag mapping from curl 8.x |
| curl-rs/src/config.rs | CREATE | src/tool_cfgable.c | Configuration struct (typed, not union) |
| curl-rs/src/operate.rs | CREATE | src/tool_operate.c | Operation dispatch and execution |
| curl-rs/src/parsecfg.rs | CREATE | src/tool_parsecfg.c | .curlrc config file parser |
| curl-rs/src/paramhelp.rs | CREATE | src/tool_paramhlp.c | Parameter validation helpers |
| curl-rs/src/setopt.rs | CREATE | src/tool_setopt.c, src/config2setopts.c | Config → EasyHandle option application |
| curl-rs/src/formparse.rs | CREATE | src/tool_formparse.c | Form data parsing |
| curl-rs/src/urlglob.rs | CREATE | src/tool_urlglob.c | URL globbing and range expansion |
| curl-rs/src/writeout.rs | CREATE | src/tool_writeout.c | Write-out variable formatting |
| curl-rs/src/writeout_json.rs | CREATE | src/tool_writeout_json.c | JSON write-out output |
| curl-rs/src/callbacks/*.rs | CREATE | src/tool_cb_*.c (7 files) | Transfer callbacks (debug, header, progress, read, seek, socket, write) |
| curl-rs/src/help.rs | CREATE | src/tool_help.c, src/tool_listhelp.c | Help text generation |
| curl-rs/src/msgs.rs | CREATE | src/tool_msgs.c | Message/warning output |
| curl-rs/src/progress_display.rs | CREATE | src/tool_progress.c | Progress bar rendering |
| curl-rs/src/dirhier.rs | CREATE | src/tool_dirhie.c | Directory hierarchy creation |
| curl-rs/src/findfile.rs | CREATE | src/tool_findfile.c | Config/cert file discovery |
| curl-rs/src/filetime.rs | CREATE | src/tool_filetime.c | File timestamp setting |
| curl-rs/src/getpass.rs | CREATE | src/tool_getpass.c | Password input handling |
| curl-rs/src/ipfs.rs | CREATE | src/tool_ipfs.c | IPFS gateway URL rewriting |
| curl-rs/src/libinfo.rs | CREATE | src/tool_libinfo.c | Library feature info |
| curl-rs/src/operhlp.rs | CREATE | src/tool_operhlp.c | Operation helper routines |
| curl-rs/src/ssls.rs | CREATE | src/tool_ssls.c | SSL session helpers |
| curl-rs/src/stderr.rs | CREATE | src/tool_stderr.c | Stderr management |
| curl-rs/src/terminal.rs | CREATE | src/terminal.c | Terminal width/capabilities |
| curl-rs/src/var.rs | CREATE | src/var.c | Variable expansion (--variable) |
| curl-rs/src/xattr.rs | CREATE | src/tool_xattr.c | Extended attribute writing |
| curl-rs/src/util.rs | CREATE | src/tool_util.c, src/slist_wc.c, src/curlinfo.c | Misc CLI utilities |

**FFI Crate — `curl-rs-ffi/src/`:**

| Target File | Transformation | Source File(s) | Key Changes |
|---|---|---|---|
| curl-rs-ffi/Cargo.toml | CREATE | — | cdylib + staticlib crate with cbindgen build dep |
| curl-rs-ffi/build.rs | CREATE | — | cbindgen invocation → include/curl/curl.h |
| curl-rs-ffi/cbindgen.toml | CREATE | — | Header generation config matching curl 8.x structure |
| curl-rs-ffi/src/lib.rs | CREATE | — | Crate root |
| curl-rs-ffi/src/easy.rs | CREATE | include/curl/easy.h | 10 curl_easy_* extern "C" fns |
| curl-rs-ffi/src/multi.rs | CREATE | include/curl/multi.h | 24 curl_multi_* extern "C" fns |
| curl-rs-ffi/src/share.rs | CREATE | include/curl/curl.h (share section) | curl_share_* extern "C" fns |
| curl-rs-ffi/src/global.rs | CREATE | include/curl/curl.h (global section) | curl_global_* extern "C" fns |
| curl-rs-ffi/src/url.rs | CREATE | include/curl/urlapi.h | 6 curl_url_* extern "C" fns |
| curl-rs-ffi/src/ws.rs | CREATE | include/curl/websockets.h | 4 curl_ws_* extern "C" fns |
| curl-rs-ffi/src/mime.rs | CREATE | include/curl/curl.h (mime section) | curl_mime_* extern "C" fns |
| curl-rs-ffi/src/slist.rs | CREATE | include/curl/curl.h (slist section) | curl_slist_* extern "C" fns |
| curl-rs-ffi/src/options.rs | CREATE | include/curl/options.h | 3 curl_easy_option_* extern "C" fns |
| curl-rs-ffi/src/header.rs | CREATE | include/curl/header.h | 2 curl_easy_header_* extern "C" fns |
| curl-rs-ffi/src/mprintf.rs | CREATE | include/curl/mprintf.h | 11 curl_m*printf extern "C" fns |
| curl-rs-ffi/src/error_codes.rs | CREATE | include/curl/curl.h | CURLcode/CURLMcode/CURLSHcode consts |
| curl-rs-ffi/src/types.rs | CREATE | include/curl/curl.h, include/curl/system.h | CURL, CURLM, CURLSH opaque pointer types |

### 0.5.2 Cross-File Dependencies

Import statement transformations — key patterns:

- **Old (C):** `#include "vtls/vtls.h"` / `#include <curl/curl.h>`
- **New (Rust):** `use curl_rs_lib::tls;` / `use curl_rs_lib::easy::EasyHandle;`

- **Old (C):** `#include "vauth/vauth.h"` then call `Curl_auth_create_digest_md5_message(...)`
- **New (Rust):** `use curl_rs_lib::auth::digest;` then call `digest::create_md5_message(...)`

- **Old (C):** `#include "curl_sasl.h"` → `Curl_sasl_start(...)` / `Curl_sasl_continue(...)`
- **New (Rust):** `use curl_rs_lib::auth::sasl::SaslClient;` → `client.start(...)` / `client.step(...)`

Configuration updates for new structure:
- `Cargo.toml` workspace `[dependencies]` section replaces `CMakeLists.txt` `find_package()` calls
- Cargo feature flags replace C `#ifdef CURL_DISABLE_*` and `USE_*` preprocessor macros
- `rust-toolchain.toml` replaces compiler version checks in configure scripts

### 0.5.3 One-Phase Execution

The entire rewrite is executed by Blitzy in **one phase**. All files in the tables above are created in a single delivery. There is no phased rollout — the workspace is delivered as a complete, buildable, testable unit.

## 0.6 Dependency Inventory

### 0.6.1 Key Public and Private Packages

All dependencies are sourced from crates.io. No vendored dependencies unless explicitly required by a crate for a specific target. Versions below are verified against crates.io as of February 2026.

**Core Runtime and Networking:**

| Registry | Package | Version | Purpose |
|---|---|---|---|
| crates.io | `tokio` | 1.49.0 | Async runtime — current-thread for CLI, multi-thread for multi handle |
| crates.io | `tokio-util` | 0.7.x | Codec, compat, and I/O utility extensions for Tokio |
| crates.io | `bytes` | 1.x | Efficient byte buffer primitives used across networking crates |
| crates.io | `futures-util` | 0.3.x | Future combinators and stream utilities |
| crates.io | `pin-project-lite` | 0.2.x | Lightweight pin projection for async types |
| crates.io | `socket2` | 0.5.x | Low-level socket configuration (SO_REUSEADDR, TCP_NODELAY) |

**HTTP/1.1 + HTTP/2:**

| Registry | Package | Version | Purpose |
|---|---|---|---|
| crates.io | `hyper` | 1.7.0 | HTTP/1.1 and HTTP/2 client implementation |
| crates.io | `hyper-util` | 0.1.20 | Hyper utility extensions (connectors, client builders) |
| crates.io | `http` | 1.x | HTTP types (Request, Response, StatusCode, HeaderMap) |
| crates.io | `http-body` | 1.x | HTTP body trait definitions |
| crates.io | `http-body-util` | 0.1.x | HTTP body utility implementations |
| crates.io | `h2` | 0.4.x | HTTP/2 protocol implementation (used internally by hyper) |

**HTTP/3 + QUIC:**

| Registry | Package | Version | Purpose |
|---|---|---|---|
| crates.io | `quinn` | 0.11.9 | QUIC transport protocol implementation |
| crates.io | `h3` | 0.0.7 | HTTP/3 protocol implementation (generic over QUIC) |
| crates.io | `h3-quinn` | 0.0.10 | Quinn integration adapter for h3 |

**TLS:**

| Registry | Package | Version | Purpose |
|---|---|---|---|
| crates.io | `rustls` | 0.23.36 | TLS 1.2/1.3 implementation — exclusive TLS backend |
| crates.io | `tokio-rustls` | 0.26.4 | Tokio async TLS stream adapter for rustls |
| crates.io | `rustls-pki-types` | 1.x | PKI type definitions (certificates, private keys) |
| crates.io | `webpki-roots` | 1.x | Mozilla root certificate bundle for default trust |
| crates.io | `rustls-pemfile` | 2.x | PEM file parsing for certificates and keys |

**SSH (SFTP/SCP):**

| Registry | Package | Version | Purpose |
|---|---|---|---|
| crates.io | `russh` | 0.54.6 | Pure-Rust SSH2 client (key-based + password auth) |
| crates.io | `russh-sftp` | 2.1.1 | SFTP subsystem client for russh |
| crates.io | `russh-keys` | 0.49.2 | SSH key loading and agent interaction |

**DNS:**

| Registry | Package | Version | Purpose |
|---|---|---|---|
| crates.io | `hickory-resolver` | 0.25.2 | Pure-Rust DNS resolver (optional, feature-gated) |

**CLI:**

| Registry | Package | Version | Purpose |
|---|---|---|---|
| crates.io | `clap` | 4.5.54 | Command-line argument parsing with derive macros |
| crates.io | `clap_complete` | 4.x | Shell completion generation |

**FFI and Code Generation:**

| Registry | Package | Version | Purpose |
|---|---|---|---|
| crates.io | `cbindgen` | 0.29.2 | C header generation from Rust FFI definitions (build dep) |
| crates.io | `libc` | 0.2.x | Raw FFI bindings for C types in extern "C" boundaries |

**Cryptography (for auth protocols):**

| Registry | Package | Version | Purpose |
|---|---|---|---|
| crates.io | `sha2` | 0.10.x | SHA-256/SHA-512 for digest auth and checksums |
| crates.io | `md-5` | 0.10.x | MD5 for Digest and NTLM auth |
| crates.io | `md4` | 0.10.x | MD4 for NTLM password hashing |
| crates.io | `hmac` | 0.12.x | HMAC for Digest auth and AWS SigV4 |
| crates.io | `des` | 0.8.x | DES for NTLM LM/NTLM hash computation |
| crates.io | `base64` | 0.22.x | Base64 encoding/decoding |
| crates.io | `rand` | 0.8.x | Cryptographic random number generation |

**Compression:**

| Registry | Package | Version | Purpose |
|---|---|---|---|
| crates.io | `flate2` | 1.x | gzip/deflate decompression (content-encoding) |
| crates.io | `brotli` | 8.x | Brotli decompression |
| crates.io | `zstd` | 0.13.x | Zstandard decompression |

**Serialization and Utilities:**

| Registry | Package | Version | Purpose |
|---|---|---|---|
| crates.io | `serde` | 1.x | Serialization framework (for cookie jar, config) |
| crates.io | `serde_json` | 1.x | JSON serialization (write-out JSON format) |
| crates.io | `url` | 2.x | URL parsing and manipulation |
| crates.io | `percent-encoding` | 2.x | URL percent-encoding |
| crates.io | `idna` | 1.x | Internationalized domain name processing |
| crates.io | `publicsuffix` | 2.x | Public suffix list for cookie domain validation |
| crates.io | `glob` | 0.3.x | Glob pattern matching for URL expansion |
| crates.io | `chrono` | 0.4.x | Date/time parsing (HTTP date headers, cookie expiry) |
| crates.io | `tracing` | 0.1.x | Structured logging and diagnostics |
| crates.io | `tracing-subscriber` | 0.3.x | Tracing output formatting |
| crates.io | `thiserror` | 2.x | Derive macro for error types |
| crates.io | `anyhow` | 1.x | Contextual error handling in CLI binary |

**Development and Testing (dev-dependencies):**

| Registry | Package | Version | Purpose |
|---|---|---|---|
| crates.io | `cargo-llvm-cov` | (tool) | Line coverage measurement (≥80% gate) |
| crates.io | `cargo-audit` | (tool) | Dependency vulnerability scanning |
| crates.io | `cargo-deny` | (tool) | License and advisory compliance |
| crates.io | `rcgen` | 0.14.x | Self-signed certificate generation for TLS tests |
| crates.io | `tokio-test` | 0.4.x | Test utilities for async code |
| crates.io | `tempfile` | 3.x | Temporary file/directory creation in tests |
| crates.io | `assert_cmd` | 2.x | CLI binary integration testing |
| crates.io | `predicates` | 3.x | Assertion predicates for test output |

### 0.6.2 Dependency Updates

**Import Refactoring:**
- `curl-rs-lib/src/**/*.rs` — all internal module `use` statements follow Rust 2021 edition path conventions
- `curl-rs/src/**/*.rs` — imports from `curl_rs_lib` crate via `[dependencies]` in Cargo.toml
- `curl-rs-ffi/src/**/*.rs` — imports from `curl_rs_lib` crate, plus `libc` for C-compatible types

**External Reference Updates:**
- `Cargo.toml` (workspace) — defines all shared dependency versions in `[workspace.dependencies]`
- `curl-rs-lib/Cargo.toml` — protocol-specific deps behind feature flags (`[features]`)
- `curl-rs/Cargo.toml` — `curl-rs-lib` as path dependency + `clap`, `anyhow`, `tokio`
- `curl-rs-ffi/Cargo.toml` — `curl-rs-lib` as path dependency + `libc`; `cbindgen` as build-dependency
- `.github/workflows/ci.yml` — Rust toolchain installation, cargo test/clippy/miri/audit commands
- `rust-toolchain.toml` — stable channel with MSRV 1.75

**Feature Flag Mapping (C `#ifdef` → Cargo `[features]`):**

| C Preprocessor Macro | Cargo Feature Flag | Default |
|---|---|---|
| `CURL_DISABLE_HTTP` | `http` (enabled) | enabled |
| `CURL_DISABLE_FTP` | `ftp` (enabled) | enabled |
| `CURL_DISABLE_SMTP` | `smtp` (enabled) | enabled |
| `CURL_DISABLE_IMAP` | `imap` (enabled) | enabled |
| `CURL_DISABLE_POP3` | `pop3` (enabled) | enabled |
| `CURL_DISABLE_TFTP` | `tftp` (enabled) | enabled |
| `CURL_DISABLE_TELNET` | `telnet` (enabled) | enabled |
| `CURL_DISABLE_DICT` | `dict` (enabled) | enabled |
| `CURL_DISABLE_MQTT` | `mqtt` (enabled) | enabled |
| `CURL_DISABLE_RTSP` | `rtsp` (enabled) | enabled |
| `CURL_DISABLE_COOKIES` | `cookies` (enabled) | enabled |
| `USE_ARES` / c-ares | `hickory-dns` | disabled |
| `USE_BROTLI` | `brotli` | enabled |
| `USE_ZSTD` | `zstd` | enabled |

## 0.7 Refactoring Rules

### 0.7.1 Refactoring-Specific Rules

The user has specified the following absolute rules governing this rewrite. Every rule is a hard constraint — violation of any rule constitutes a delivery failure.

**Functional Parity (Binary Success Condition):**
- All curl 8.x test suite cases MUST pass against the Rust binary without modification to test definitions
- The test suite includes the Perl-based `runtests.pl` harness, C regression tests in `tests/libtest/` and `tests/unit/`, and the pytest HTTP suite in `tests/http/`
- "Functional parity with curl 8.x is the binary success condition" — there is no partial-credit outcome

**Memory Safety:**
- Zero memory safety violations under Miri (non-FFI modules): `cargo +nightly miri test -p curl-rs-lib`
- Zero memory safety violations under AddressSanitizer (FFI boundary): AddressSanitizer-instrumented build of `curl-rs-ffi`
- All manual C memory management (`malloc`/`free`/`realloc`/`calloc`) is replaced by Rust ownership, borrowing, and lifetime semantics — no manual memory management in any Rust code

**Unsafe Block Policy — Absolute:**
- `unsafe` blocks are permitted ONLY in `src/ffi/` (i.e., the `curl-rs-ffi` crate) and minimal OS-integration primitives explicitly requiring it (e.g., raw socket options not exposed by safe Rust wrappers)
- Zero `unsafe` blocks in `src/protocols/`, `src/tls/`, `src/transfer/` — no exceptions
- Every `unsafe` block in `src/ffi/` MUST carry a `// SAFETY:` comment with explicit invariant justification explaining why the unsafe operation is sound

**FFI Parity:**
- libcurl FFI layer MUST pass symbol parity and signature parity checks against curl 8.x headers
- `nm` / `objdump` symbol export list of `libcurl-rs.so` MUST match curl 8.x `libcurl.so` symbol export list
- Function names, parameter types, return types, and error code integer values MUST match curl 8.x headers exactly
- C test harness calling Rust-backed libcurl symbols MUST pass against all `curl_easy_*`, `curl_multi_*`, `curl_share_*`, `curl_global_*` test cases

**Build Validation:**
- `cargo build --release --workspace` MUST succeed with zero warnings on all four targets (Linux x86_64, Linux aarch64, macOS x86_64, macOS arm64)
- `cargo clippy --workspace -- -D warnings` MUST pass clean

**Coverage Gate:**
- `cargo llvm-cov --workspace` MUST report ≥80% line coverage on `src/protocols/` and `src/transfer/`
- This is a hard minimum — the gate blocks delivery if not met

**Security Gate:**
- `cargo audit` MUST report zero critical CVEs in the dependency tree before delivery
- TLS certificate validation MUST be confirmed ON by default via integration test against a self-signed cert (expected behavior: rejection without `--insecure`)

**Clean Compilation:**
- Clean compilation on all four targets: Linux x86_64, Linux aarch64, macOS x86_64, macOS arm64
- Zero compiler warnings in release mode

### 0.7.2 Behavioral Preservation Rules

**Protocol Wire Behavior — MUST NOT modify:**
- Header formatting, redirect semantics, authentication negotiation sequences MUST be byte-for-byte equivalent to curl 8.x where deterministic
- Cookie jar file format MUST be file-compatible with curl 8.x (Netscape format)
- HSTS cache file format MUST be compatible with curl 8.x
- Alt-Svc cache file format MUST be compatible with curl 8.x
- Netrc file parsing MUST produce identical authentication results

**CLI Interface — MUST NOT modify:**
- Flag names, semantics, and defaults are frozen to curl 8.x behavior
- `curl --help all` output MUST be functionally identical to curl 8.x
- Exit codes MUST match curl 8.x for all error conditions
- stderr/stdout output formatting for progress, errors, and verbose mode MUST match

**API Contract — MUST NOT modify:**
- libcurl C API signatures are frozen — no changes to function names, parameter types, return types
- Error code integer values (`CURLcode`, `CURLMcode`, `CURLSHcode`) MUST match exactly
- Option integer values (`CURLoption`, `CURLINFO`) MUST match exactly

### 0.7.3 Special Instructions and Constraints

**Minimal Change Mandate:**
- "Implement the rewrite to achieve functional parity. Do not introduce features, optimizations, or abstractions beyond what is required for parity and safety correctness."
- No new protocols, no new CLI flags, no new options, no changes to default behavior
- No abstractions added for future extensibility unless directly required for functional parity

**TLS Exclusivity:**
- rustls exclusively — no OpenSSL, no native-tls, no C TLS library linkage at any build configuration
- Certificate validation ON by default
- `--insecure` flag MUST emit a warning to stderr before proceeding (matches curl 8.x behavior)

**Async Runtime Constraints:**
- Tokio current-thread for CLI binary
- Tokio multi-thread for multi-handle operations
- No alternative async runtimes (no async-std, no smol)

**MSRV and Edition:**
- Rust edition 2021
- MSRV pinned at 1.75 — all code and dependencies must compile on Rust 1.75

**CI and Toolchain:**
- GitHub Actions CI with 4-target matrix: `ubuntu-latest` (x86_64, aarch64 via cross), `macos-latest` (x86_64, arm64)
- All four targets MUST pass all gates before merge
- Toolchain setup per user specification:
  - `rustup component add clippy llvm-tools-preview`
  - `rustup toolchain install nightly`
  - `rustup component add --toolchain nightly miri rust-src`

**Dependency Sourcing:**
- All crates from crates.io — no vendored dependencies unless a crate requires it for a specific target
- Any vendoring exception MUST be documented in `Cargo.toml` with a comment stating the reason

**FFI Header Generation:**
- cbindgen invoked via `build.rs` in `curl-rs-ffi`
- Output to `include/curl/curl.h`
- Header MUST match curl 8.x public header structure for drop-in consumer compatibility

### 0.7.4 Implementation Sequence

The user specifies the following implementation sequence (for logical dependency ordering, not temporal phasing — all work is delivered in one phase):

 1. Workspace scaffolding: define `curl-rs-lib`, `curl-rs`, `curl-rs-ffi` crates with correct dependency graph
 2. Extract full libcurl symbol inventory from curl 8.x headers; define all FFI stubs as `unimplemented!()` to establish ABI surface
 3. Extract full CLI flag inventory from curl 8.x; define all clap argument structs with no-op handlers
 4. Implement TLS layer (rustls) — validate against HTTPS integration test
 5. Implement HTTP/1.1 (hyper) — validate against httpbin suite
 6. Implement HTTP/2 — validate ALPN negotiation and stream multiplexing
 7. Implement HTTP/3 (quinn + h3) — validate against HTTP/3-capable test server
 8. Implement FTP/FTPS — validate active/passive mode and TLS upgrade
 9. Implement SFTP/SCP (russh) — validate key-based and password auth, recursive transfer
10. Implement authentication handlers (Basic, Digest, Bearer, NTLM, Negotiate)
11. Implement cookie jar, redirect handling, proxy support, chunked transfer, streaming
12. Wire all protocol handlers into CLI flag dispatch
13. Implement libcurl FFI symbols over Rust internals; generate headers via cbindgen
14. Run full curl 8.x test suite; resolve all failures
15. Run Miri, AddressSanitizer, coverage, and security gates; resolve all failures

## 0.8 References

### 0.8.1 Repository Files and Folders Searched

The following files and folders were systematically explored across the curl codebase to derive all conclusions in this Agent Action Plan:

**Root-Level Exploration:**
- `/` (repository root) — confirmed project identity, license, build system, directory structure
- `README.md` — project description, stakeholder information
- `CMakeLists.txt` — root build configuration
- `SECURITY.md` — security policies and reporting
- `REUSE.toml` — license metadata

**Public API Headers (`include/curl/`):**
- `include/curl/curl.h` — master API header, 46 `CURL_EXTERN` symbols, all type definitions
- `include/curl/easy.h` — easy interface, 10 `CURL_EXTERN` symbols
- `include/curl/multi.h` — multi interface, 24 `CURL_EXTERN` symbols
- `include/curl/mprintf.h` — printf family, 11 `CURL_EXTERN` symbols
- `include/curl/urlapi.h` — URL API, 6 `CURL_EXTERN` symbols
- `include/curl/websockets.h` — WebSocket API, 4 `CURL_EXTERN` symbols
- `include/curl/options.h` — option introspection, 3 `CURL_EXTERN` symbols
- `include/curl/header.h` — header API, 2 `CURL_EXTERN` symbols
- `include/curl/curlver.h` — version macros (confirmed 8.19.0-DEV, `LIBCURL_VERSION_NUM 0x081300`)
- `include/curl/system.h` — platform type definitions
- `include/curl/stdcheaders.h` — standard C header compatibility
- `include/curl/typecheck-gcc.h` — GCC type-checking macros

**Core Library (`lib/`):**
- `lib/` (folder contents) — 179 .c files, 174 .h files enumerated
- All 179 `.c` files listed and categorized by subsystem (see Section 0.2)
- `lib/easy.c` (1,397 lines), `lib/multi.c` (4,034 lines), `lib/url.c` (3,904 lines), `lib/setopt.c` (2,975 lines) — key subsystem entry points with line counts verified
- `lib/transfer.c` (912 lines), `lib/connect.c` (603 lines), `lib/conncache.c` (910 lines)
- `lib/hostip.c` (1,590 lines), `lib/doh.c` (1,338 lines), `lib/cookie.c` (1,638 lines)
- `lib/socks.c` (1,415 lines), `lib/http_proxy.c` (437 lines), `lib/getinfo.c` (676 lines)

**TLS Subsystem (`lib/vtls/`):**
- `lib/vtls/` (folder contents) — 31 files: vtls.c, openssl.c, schannel.c, schannel_verify.c, sectransp.c, gtls.c, mbedtls.c, wolfssl.c, rustls.c, cipher_suite.c, keylog.c, hostcheck.c, x509asn1.c, vtls_scache.c, vtls_spack.c, and corresponding headers

**QUIC/HTTP3 Subsystem (`lib/vquic/`):**
- `lib/vquic/` (folder contents) — 9 files: vquic.c, vquic-tls.c, curl_ngtcp2.c, curl_osslq.c, curl_quiche.c, and headers

**SSH Subsystem (`lib/vssh/`):**
- `lib/vssh/` (folder contents) — 5 files: libssh.c, libssh2.c, ssh.h, and helpers

**Authentication Subsystem (`lib/vauth/`):**
- `lib/vauth/` (folder contents) — 15 files: cleartext.c, cram.c, digest.c, digest_sspi.c, gsasl.c, krb5_gssapi.c, krb5_sspi.c, ntlm.c, ntlm_sspi.c, oauth2.c, spnego_gssapi.c, spnego_sspi.c, vauth.c, and headers

**Portability Utilities (`lib/curlx/`):**
- `lib/curlx/` (folder contents) — 38 files: base64.c, dynbuf.c, inet_ntop.c, inet_pton.c, nonblock.c, strparse.c, timediff.c, timeval.c, version_win32.c, warnless.c, and additional utilities with headers

**CLI Tool (`src/`):**
- `src/` (folder contents) — 43 .c files, 45 .h files enumerated
- All 43 `.c` files listed and categorized (see Section 0.2)
- `src/toolx/tool_time.c` — nested subdirectory file

**Connection Filters (`lib/cf-*`):**
- `lib/cf-h1-proxy.c`, `lib/cf-h2-proxy.c`, `lib/cf-haproxy.c`, `lib/cf-https-connect.c`, `lib/cf-ip-happy.c`, `lib/cf-socket.c` — 6 filter implementations with corresponding headers

**Test Suite (`tests/`):**
- `tests/` (folder contents) — 60 top-level files, subdirectories for data, servers, libtest, unit, tunit, http, CMake integration, certificates, fixtures

**Quantitative Verification:**
- Total C source line counts verified: `lib/` = 144,333 lines, `src/` = 19,344 lines
- Total `CURL_EXTERN` symbol count verified: 106 across 8 header files
- Distribution: curl.h (46), easy.h (10), multi.h (24), mprintf.h (11), urlapi.h (6), websockets.h (4), options.h (3), header.h (2)

### 0.8.2 Tech Spec Sections Consulted

- **Section 1.1 — Executive Summary:** Confirmed project identity (curl/libcurl), version (8.19.0-DEV), license (MIT-like), 106 OS support, 28 CPU architectures, 3,534+ contributors
- **Section 3.4 — Open Source Dependencies:** Reviewed complete C dependency matrix (OpenSSL, nghttp2, ngtcp2, nghttp3, c-ares, libssh2, zlib, brotli, zstd) — all replaced by Rust equivalents in this rewrite

### 0.8.3 Web Searches Conducted

- **hyper 1.x latest version** — confirmed 1.7.0 (released 2025-08-18), hyper-util 0.1.20
- **rustls latest version** — confirmed 0.23.36 (released 2026-01-05), MSRV Rust 1.71+
- **quinn + h3 latest versions** — confirmed quinn 0.11.9, h3 0.0.7, h3-quinn 0.0.10
- **russh latest version** — confirmed 0.54.6 (docs.rs), russh-sftp 2.1.1, russh-keys 0.49.2
- **clap 4.x latest version** — confirmed 4.5.54 (released 2026-01-02)
- **cbindgen latest version** — confirmed 0.29.2 (released 2025-10-21)
- **tokio latest version** — confirmed 1.49.0, LTS releases 1.43.x and 1.47.x
- **hickory-dns latest version** — confirmed 0.25.2 (released 2025-05-03), resolver crate 0.25.2
- **tokio-rustls latest version** — confirmed 0.26.4 (released 2025-09-26)

### 0.8.4 Attachments

No attachments were provided by the user for this project. No Figma URLs were specified. No environment files were found in `/tmp/environments_files/`. No `.blitzyignore` files exist in the repository.