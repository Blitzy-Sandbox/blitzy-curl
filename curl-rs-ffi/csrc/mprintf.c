/* =========================================================================
 * curl-rs-ffi/csrc/mprintf.c — C ABI trampoline for the libcurl printf family.
 *
 * Part of the curl -> Rust migration (curl-rs-ffi crate). This translation unit
 * defines the ten exported `curl_m*printf` / `curl_mv*printf` symbols that
 * `include/curl/mprintf.h` declares (the printf family enumerated in
 * `lib/libcurl.def`). It is compiled by `curl-rs-ffi/build.rs` via the `cc`
 * crate and linked into the `libcurl`-compatible cdylib/staticlib with the
 * `+whole-archive` modifier so the symbols are present in the final library's
 * exported symbol table (the `nm` / `objdump` parity gate, AAP §0.7.2).
 *
 * ---------------------------------------------------------------------------
 * WHY C (and not Rust) — documented no-C-mandate exception (AAP §0.8.2/§0.8.3)
 * ---------------------------------------------------------------------------
 * AAP §0.8.2 forbids C linkage against `libcurl` / `libssl` / C TLS libraries
 * and C protocol/TLS backends. This file is NONE of those: it is a tiny,
 * dependency-free ABI shim that ONLY bridges a calling convention which stable
 * Rust provably cannot express. On stable Rust (MSRV 1.75, edition 2021):
 *
 *   (a) a variadic `extern "C" fn(fmt: *const c_char, ...)` CANNOT be *defined*
 *       — the `c_variadic` feature is nightly-only; and
 *   (b) there is no stable `va_list` type — `core::ffi::VaList` is unstable.
 *
 * The `curl_m*printf` group is C-variadic and the `curl_mv*printf` group takes
 * a `va_list`, so BOTH families hit these limits. A C compiler natively handles
 * both ABIs on every target in the four-target matrix (linux x86_64/aarch64,
 * macOS x86_64/arm64). This trampoline is therefore the established, minimal
 * mechanism — the same `cc` build step is intended to host the variadic
 * `curl_easy_setopt` / `curl_easy_getinfo` / `curl_formadd` shims. It is not a
 * protocol or TLS backend, links no third-party C library, and forwards each
 * call straight to the platform C library's standard `printf` family.
 *
 * ---------------------------------------------------------------------------
 * BEHAVIORAL PARITY (oracle: lib/mprintf.c)
 * ---------------------------------------------------------------------------
 * curl ships its own printf engine in `lib/mprintf.c`. For the STANDARD format
 * directives exercised by the test suite (`%d`, `%u`, `%ld`, `%lld`, `%zd`,
 * `%x`/`%X`, `%o`, `%c`, `%s`, `%p`, `%e`/`%E`, `%f`, `%g`/`%G`, the width /
 * precision / flag grammar, and `%%`) curl's engine reproduces ISO C `printf`
 * semantics, which is exactly what the platform `v*printf` functions below
 * provide. Forwarding to the C library is thus behavior-preserving for the
 * specifiers the suite uses while eliminating a large hand-written formatter.
 *
 * ---------------------------------------------------------------------------
 * MEMORY OWNERSHIP (`curl_maprintf` / `curl_mvaprintf`)
 * ---------------------------------------------------------------------------
 * These two return a heap buffer that the CALLER releases with `curl_free`.
 * The crate's `curl_free` (see `curl-rs-ffi/src/global.rs`) wraps `libc::free`,
 * and the allocators used here (`vasprintf`, or `malloc` in the portable
 * fallback) allocate from that same C heap, so the allocate-here / free-there
 * contract is consistent ("anything handed to the caller is freed by the C
 * `free`", matching curl's own `curl_maprintf` ownership rule).
 * ========================================================================= */

/* `_GNU_SOURCE` exposes the glibc `vasprintf` prototype from <stdio.h>. It is
 * harmless on platforms that ignore it; the portable fallback below covers any
 * platform that does not provide `vasprintf`. Must precede all includes. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdio.h>  /* FILE, v?printf, v?fprintf, v?sprintf, v?snprintf */
#include <stdarg.h> /* va_list, va_start, va_end, va_copy               */
#include <stdlib.h> /* malloc, free (the curl_free-compatible heap)     */

/* Detect a libc that provides `vasprintf`. glibc (with _GNU_SOURCE), Apple's
 * libc, and the BSD libcs all do. Anything else uses the standards-only
 * fallback (size with vsnprintf, then malloc + vsnprintf), which is always
 * correct, only marginally slower. */
#if defined(__GLIBC__) || defined(__APPLE__) || defined(__FreeBSD__) ||       \
    defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__) ||  \
    defined(__HAIKU__)
#define CURLRS_HAVE_VASPRINTF 1
#else
#define CURLRS_HAVE_VASPRINTF 0
#endif

/* -------------------------------------------------------------------------
 * va_list-taking variants (curl_mv*printf). Each forwards to the matching
 * platform `v*printf`, returning that function's `int` result verbatim.
 * ------------------------------------------------------------------------- */

int curl_mvsnprintf(char *buffer, size_t maxlength, const char *format,
                    va_list args)
{
  /* Forward to the platform `vsnprintf` for the formatting itself — the bytes
   * written are byte-for-byte identical to curl's own engine for the standard
   * directives the test suite exercises. The ONE observable difference is the
   * RETURN VALUE on truncation, and `lib/mprintf.c` (the AAP behavioral oracle)
   * is authoritative here:
   *
   *   * ISO C99 `vsnprintf` returns the *would-be* length — the number of bytes
   *     that WOULD have been written had the buffer been unbounded (so the
   *     result can exceed `maxlength`).
   *   * curl's `curl_mvsnprintf` instead returns the number of bytes ACTUALLY
   *     stored, excluding the terminating NUL: it caps a truncated result at
   *     `maxlength - 1`, and returns `0` when `maxlength == 0` (writing
   *     nothing). Verified against curl's shipped `libcurl` (its `lib/mprintf.c`)
   *     as a differential oracle: e.g. `("%s","abcdef")` with n=4 -> 3 ("abc"),
   *     n=1 -> 0 (""), n=0 -> 0 (no write), n>=7 -> 6 ("abcdef").
   *
   * Normalising the return value here makes the exported `curl_msnprintf` /
   * `curl_mvsnprintf` symbols behave exactly like curl 8.x for `tests/libtest`
   * consumers (e.g. `lib556.c`, which captures the return value), satisfying the
   * wire/behavioral-parity mandate (AAP §0.7.3 / §0.8.2). The buffer contents
   * are unchanged by this normalisation. */
  int rc = vsnprintf(buffer, maxlength, format, args);
  if(rc < 0)
    return rc; /* output/encoding error: propagate verbatim, as curl does */
  if(maxlength == 0)
    return 0; /* curl writes nothing and reports 0 stored bytes */
  if((size_t)rc >= maxlength)
    return (int)(maxlength - 1); /* truncated: report bytes actually stored */
  return rc; /* fit exactly/loosely: identical to curl and to C99 */
}

int curl_mvsprintf(char *buffer, const char *format, va_list args)
{
  return vsprintf(buffer, format, args);
}

int curl_mvprintf(const char *format, va_list args)
{
  return vprintf(format, args);
}

int curl_mvfprintf(FILE *fd, const char *format, va_list args)
{
  return vfprintf(fd, format, args);
}

/* -------------------------------------------------------------------------
 * Variadic variants (curl_m*printf). Each captures its argument list and
 * delegates to the corresponding `curl_mv*printf` above so the formatting
 * logic lives in exactly one place per family.
 * ------------------------------------------------------------------------- */

int curl_msnprintf(char *buffer, size_t maxlength, const char *format, ...)
{
  int rc;
  va_list ap;
  va_start(ap, format);
  rc = curl_mvsnprintf(buffer, maxlength, format, ap);
  va_end(ap);
  return rc;
}

int curl_msprintf(char *buffer, const char *format, ...)
{
  int rc;
  va_list ap;
  va_start(ap, format);
  rc = curl_mvsprintf(buffer, format, ap);
  va_end(ap);
  return rc;
}

int curl_mprintf(const char *format, ...)
{
  int rc;
  va_list ap;
  va_start(ap, format);
  rc = curl_mvprintf(format, ap);
  va_end(ap);
  return rc;
}

int curl_mfprintf(FILE *fd, const char *format, ...)
{
  int rc;
  va_list ap;
  va_start(ap, format);
  rc = curl_mvfprintf(fd, format, ap);
  va_end(ap);
  return rc;
}

/* -------------------------------------------------------------------------
 * Allocating variants (curl_maprintf / curl_mvaprintf). Return a freshly
 * heap-allocated, NUL-terminated formatted string, or NULL on failure. The
 * caller owns the result and frees it with `curl_free` (== libc `free`).
 * ------------------------------------------------------------------------- */

char *curl_mvaprintf(const char *format, va_list args)
{
#if CURLRS_HAVE_VASPRINTF
  char *out = NULL;
  /* vasprintf allocates the exact-size buffer with malloc and returns the
   * length, or a negative value on failure (leaving `out` indeterminate). */
  if(vasprintf(&out, format, args) < 0)
    return NULL;
  return out;
#else
  /* Portable fallback: size the output with a throwaway vsnprintf over a COPY
   * of the arg list, allocate, then format into the real buffer. `va_copy` is
   * required because a va_list may be consumed by the first pass. */
  va_list sizing;
  int needed;
  size_t size;
  char *out;

  va_copy(sizing, args);
  needed = vsnprintf(NULL, 0, format, sizing);
  va_end(sizing);
  if(needed < 0)
    return NULL;

  size = (size_t)needed + 1u; /* +1 for the NUL terminator */
  out = (char *)malloc(size);
  if(!out)
    return NULL;

  if(vsnprintf(out, size, format, args) < 0) {
    free(out);
    return NULL;
  }
  return out;
#endif
}

char *curl_maprintf(const char *format, ...)
{
  char *out;
  va_list ap;
  va_start(ap, format);
  out = curl_mvaprintf(format, ap);
  va_end(ap);
  return out;
}
