/* SPDX-License-Identifier: curl */
/* SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al. */

/*
 * curl-rs-ffi — C-variadic ABI trampoline
 * =======================================
 * This is the ONE C translation unit of the otherwise-pure-Rust `curl-rs-ffi` crate. It exists
 * solely to satisfy an ABI obligation that stable Rust cannot: defining genuine C-variadic
 * (`...`) `extern "C"` entry points.
 *
 * WHY C IS REQUIRED HERE (and only here)
 * --------------------------------------
 * The public libcurl surface declares several entry points as C variadics in the committed
 * headers — the `curl_m*printf` family (`include/curl/mprintf.h`) and the set-option / get-info
 * family `curl_easy_setopt` / `curl_easy_getinfo` / `curl_multi_setopt` / `curl_share_setopt`
 * (`include/curl/easy.h`, `include/curl/multi.h`, `include/curl/curl.h`). Defining a C-variadic
 * function in Rust requires the `c_variadic` feature, which is nightly-only
 * (rust-lang/rust#44930). The AAP freezes the toolchain at MSRV 1.75 on the stable channel
 * (`rust-toolchain.toml`, AAP §0.7.3), so the `...` definitions cannot live in Rust without
 * breaking the MSRV/stable gate. A tiny, audited C trampoline is the standard, portable way to
 * export C-variadic symbols from a Rust library: each trampoline captures the caller's variadic
 * argument(s) with `va_start`/`va_arg` and forwards to the crate's already-implemented,
 * ABI-tested fixed-arity or `va_list` sibling in Rust. This keeps `unsafe`/C strictly at the FFI
 * boundary (AAP §0.7.2 — `unsafe` is permitted only in `curl-rs-ffi`) and introduces no linkage
 * against any external C library (AAP §0.5.2): it links only against sibling Rust symbols in this
 * same crate.
 *
 * ABI NOTE (va_list forwarding)
 * -----------------------------
 * The Rust `curl_mv*printf` implementations receive the `va_list` as an opaque pointer
 * (`*mut c_void`) and hand it to the platform `vasprintf(3)`. On every one of the four supported
 * targets (`x86_64`/`aarch64` × `linux-gnu`/`apple-darwin`) a `va_list` argument is passed as a
 * pointer to the caller's `va_list` storage (an array-to-pointer decay on the x86-64 SysV ABI; a
 * by-reference aggregate on AArch64/AAPCS64), which is ABI-identical to the `void *` the Rust
 * side declares. This is exactly the calling convention a C consumer already uses when invoking
 * the `curl_mv*printf` symbols directly through the committed `curl.h`, so these trampolines add
 * no new ABI assumption — they reuse the one already proven by the `va_list` variants.
 */

#include <stdarg.h> /* va_list, va_start, va_end */
#include <stddef.h> /* size_t */
#include <stdio.h>  /* FILE */

/*
 * The Rust `va_list` siblings (curl-rs-ffi/src/mprintf.rs). Declared here with a `va_list`
 * parameter — byte-identical to the committed `include/curl/mprintf.h` prototypes and
 * ABI-identical to the `*mut c_void` the Rust definitions use on the four supported targets.
 */
extern int curl_mvprintf(const char *format, va_list args);
extern int curl_mvfprintf(FILE *fd, const char *format, va_list args);
extern int curl_mvsprintf(char *buffer, const char *format, va_list args);
extern int curl_mvsnprintf(char *buffer, size_t maxlength, const char *format, va_list args);
extern char *curl_mvaprintf(const char *format, va_list args);

/* `int curl_mprintf(const char *format, ...);` — format to stdout. */
int curl_mprintf(const char *format, ...)
{
  va_list ap;
  int result;
  va_start(ap, format);
  result = curl_mvprintf(format, ap);
  va_end(ap);
  return result;
}

/* `int curl_mfprintf(FILE *fd, const char *format, ...);` — format to a stream. */
int curl_mfprintf(FILE *fd, const char *format, ...)
{
  va_list ap;
  int result;
  va_start(ap, format);
  result = curl_mvfprintf(fd, format, ap);
  va_end(ap);
  return result;
}

/* `int curl_msprintf(char *buffer, const char *format, ...);` — format into an unbounded buffer. */
int curl_msprintf(char *buffer, const char *format, ...)
{
  va_list ap;
  int result;
  va_start(ap, format);
  result = curl_mvsprintf(buffer, format, ap);
  va_end(ap);
  return result;
}

/*
 * `int curl_msnprintf(char *buffer, size_t maxlength, const char *format, ...);`
 * Format into at most `maxlength` bytes of `buffer` (always NUL-terminating when maxlength > 0).
 */
int curl_msnprintf(char *buffer, size_t maxlength, const char *format, ...)
{
  va_list ap;
  int result;
  va_start(ap, format);
  result = curl_mvsnprintf(buffer, maxlength, format, ap);
  va_end(ap);
  return result;
}

/* `char *curl_maprintf(const char *format, ...);` — format into a fresh heap string. */
char *curl_maprintf(const char *format, ...)
{
  va_list ap;
  char *result;
  va_start(ap, format);
  result = curl_mvaprintf(format, ap);
  va_end(ap);
  return result;
}

/*
 * The set-option / get-info family (QA F6-VARIADIC)
 * =================================================
 * `curl_easy_setopt`, `curl_easy_getinfo`, `curl_multi_setopt`, and `curl_share_setopt` are
 * declared C-variadic in the committed headers (`include/curl/easy.h`, `include/curl/multi.h`,
 * `include/curl/curl.h`): each takes a handle, an option/info id, and exactly ONE further
 * argument whose meaning depends on the id — a `long`, a `curl_off_t`, an object pointer, or a
 * function pointer. As with the `curl_m*printf` family above, stable Rust (MSRV 1.75) cannot
 * define a `...` function, so the variadic boundary lives here in C and forwards to a fixed-arity
 * Rust worker (`crs_*` in src/{easy,multi,share}.rs) that performs the id dispatch.
 *
 * Why a fixed-arity Rust export was WRONG (the bug these trampolines fix)
 * ----------------------------------------------------------------------
 * The workers were previously exported directly as `curl_easy_setopt(void*, int, size_t)` etc.
 * That happens to work on the x86-64 SysV ABI purely by register coincidence — the single
 * promoted vararg lands in RDX, exactly where a fixed third parameter is read. On
 * `aarch64-apple-darwin`, however, variadic arguments are passed on the STACK rather than in the
 * next argument register (Apple's AAPCS64 variant), so a fixed-arity callee reads register X2 —
 * which the caller never populated — and the option value is lost. Routing through a genuine
 * `...` entry point makes `va_arg` read the correct location on every target, and makes the
 * generated header conformant with the committed variadic prototypes.
 *
 * Single-slot extraction ABI note
 * --------------------------------
 * Each trampoline consumes exactly one promoted argument with `(size_t)va_arg(ap, void *)`. On
 * all four supported targets (`x86_64`/`aarch64` × `linux-gnu`/`apple-darwin`) — every one of
 * them LP64 — a `long`, `curl_off_t`, object pointer and function pointer are all 8 bytes and
 * share the same integer/pointer argument class, so they occupy the one promoted slot that
 * `va_arg(ap, void *)` reads; reinterpreting that 8-byte payload as `size_t` preserves its exact
 * bit pattern. The fixed-arity Rust worker then reinterprets the `size_t` as the concrete type
 * the id dictates — identical to how curl's own `curl_easy_setopt` promotes and reinterprets its
 * single vararg. Reading a single slot (rather than one per possible type) matches the C ABI: the
 * caller pushed exactly one argument, so exactly one is consumed.
 */

/* The fixed-arity Rust workers (curl-rs-ffi/src/{easy,multi,share}.rs). Named `crs_*` so they are
 * NOT part of the exported `curl_*` ABI surface (the cdylib version script exports only `curl_*`),
 * yet remain `#[no_mangle]` so these trampolines resolve them by name at link time. */
extern int crs_easy_setopt(void *curl, int option, size_t arg);
extern int crs_easy_getinfo(void *curl, int info, size_t arg);
extern int crs_multi_setopt(void *multi_handle, int option, size_t arg);
extern int crs_share_setopt(void *share, int option, size_t arg);

/* `CURLcode curl_easy_setopt(CURL *curl, CURLoption option, ...);` */
int curl_easy_setopt(void *curl, int option, ...)
{
  va_list ap;
  size_t arg;
  va_start(ap, option);
  arg = (size_t)va_arg(ap, void *);
  va_end(ap);
  return crs_easy_setopt(curl, option, arg);
}

/* `CURLcode curl_easy_getinfo(CURL *curl, CURLINFO info, ...);` */
int curl_easy_getinfo(void *curl, int info, ...)
{
  va_list ap;
  size_t arg;
  va_start(ap, info);
  arg = (size_t)va_arg(ap, void *);
  va_end(ap);
  return crs_easy_getinfo(curl, info, arg);
}

/* `CURLMcode curl_multi_setopt(CURLM *multi_handle, CURLMoption option, ...);` */
int curl_multi_setopt(void *multi_handle, int option, ...)
{
  va_list ap;
  size_t arg;
  va_start(ap, option);
  arg = (size_t)va_arg(ap, void *);
  va_end(ap);
  return crs_multi_setopt(multi_handle, option, arg);
}

/* `CURLSHcode curl_share_setopt(CURLSH *share, CURLSHoption option, ...);` */
int curl_share_setopt(void *share, int option, ...)
{
  va_list ap;
  size_t arg;
  va_start(ap, option);
  arg = (size_t)va_arg(ap, void *);
  va_end(ap);
  return crs_share_setopt(share, option, arg);
}
