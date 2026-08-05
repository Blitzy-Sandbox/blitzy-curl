/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

/* Standalone C shims for the curl_m*printf family, for the harness link
   that has no libcurl in it. tests/libtest/lib1560.c calls curl_mfprintf
   at 41 sites, curl_mprintf at L1952, L1960, L2013 and L2073, and
   curl_msnprintf at L71, L74 and L1940; libcurl defines all three in
   lib/mprintf.c. The drop-in link owns that object and so must not
   compile this file at all; the standalone link owns nothing and so must.
   Four declared family members are deliberately absent, for the reasons
   given below the definitions. Every format string in that test uses only
   %s, %d and %u, measured at 34, 28 and 16 uses with no length modifiers
   and no positional arguments, which is what makes forwarding to the C
   library byte-exact here. The single divergence is curl_msnprintf's
   return value, described where it is defined. Reported constraint R3:
   this harness carries no memory debugging, so the allocation ceiling at
   tests/data/test1560:L40 is honored in spirit and not counted by curl's
   own accounting. The whole chain is in ../docs/MEMORY-OWNERSHIP.md. */

#include "first.h"
#include <stdarg.h>

/* Guard the translation unit so a mistaken link fails loudly here, at
   compile time, rather than quietly duplicating symbols at link time or
   silently overriding libcurl's own formatted print. The drop-in link
   takes this family from lib/mprintf.c's object inside a real libcurl
   archive; only the standalone link, which has no libcurl, needs the
   definitions below, and only its build defines HARNESS_MODE_B.
   scripts/checksrc.pl:L670 reports #if !defined(X) as IFDEFSINGLE, so
   this single-macro test is spelled #ifndef. */
#ifndef HARNESS_MODE_B
#error "shims.c is for the standalone (Mode B) harness link only. The \
drop-in (Mode A) link resolves curl_m*printf from libcurl's own \
mprintf.c object, so compiling this file there duplicates those \
symbols. Either define HARNESS_MODE_B or drop this file from the Mode A \
source list."
#endif

/* curl_mprintf writes to stdout and curl_mfprintf honors whatever FILE *
   it is handed, exactly as lib/mprintf.c:L1194-L1202 and L1204-L1212 do.
   The split is load-bearing rather than cosmetic: the parity oracle is a
   byte-for-byte diff of stdout, tests/libtest/lib1560.c emits its lone
   success line there at L2073 to match what tests/data/test1560:L37
   expects, and sends every diagnostic to stderr instead. So no
   buffering tricks, no prefixes and no newline rewriting belong here.
   Each va_list variant does the work and the variadic sibling forwards
   to it, which is the layering lib/mprintf.c itself uses at L1102. */

int curl_mvprintf(const char *format, va_list args)
{
  return vprintf(format, args);
}

int curl_mprintf(const char *format, ...)
{
  int rc;
  va_list args;
  va_start(args, format);
  rc = curl_mvprintf(format, args);
  va_end(args);
  return rc;
}

int curl_mvfprintf(FILE *fd, const char *format, va_list args)
{
  return vfprintf(fd, format, args);
}

int curl_mfprintf(FILE *fd, const char *format, ...)
{
  int rc;
  va_list args;
  va_start(args, format);
  rc = curl_mvfprintf(fd, format, args);
  va_end(args);
  return rc;
}

/* The bytes written match lib/mprintf.c for every input. Its addbyter at
   lib/mprintf.c:L1065-L1075 stores a byte only while length < max, and
   the tail at L1088-L1098 then either overwrites the final stored byte
   with a terminator, when the buffer filled exactly, or appends one when
   it did not. That yields at most maxlength - 1 characters plus a
   terminator, which is precisely C99 vsnprintf's truncation rule. A zero
   maxlength writes nothing under either implementation.

   KNOWN DIVERGENCE, recorded rather than papered over: the return value.
   curl answers with the count it actually wrote, decremented at
   lib/mprintf.c:L1094 whenever it truncated, whereas C99 vsnprintf
   answers with the count it would have written had the buffer been big
   enough. The two answers agree unless the output was truncated. No call
   site in tests/libtest/lib1560.c can observe the difference: L71 and L74
   measure the result with strlen at L76, and L1940 discards the value
   outright. Also carried in ../docs/KNOWN-DIVERGENCES.md. */

int curl_mvsnprintf(char *buffer, size_t maxlength, const char *format,
                    va_list args)
{
  return vsnprintf(buffer, maxlength, format, args);
}

int curl_msnprintf(char *buffer, size_t maxlength, const char *format, ...)
{
  int rc;
  va_list args;
  va_start(args, format);
  rc = curl_mvsnprintf(buffer, maxlength, format, args);
  va_end(args);
  return rc;
}

/* Four members that include/curl/mprintf.h declares are left undefined on
   purpose. curl_msprintf at include/curl/mprintf.h:L60-L61 and
   curl_mvsprintf at L69-L70 write into a buffer with no bound at all, and
   the allocating pair, curl_maprintf at L74-L75 and curl_mvaprintf at
   L76-L77, hands back memory the caller must release. Nothing in this
   harness reaches for any of the four: tests/libtest/lib1560.c uses only
   the six defined above, and rust-urlapi/demo/urlapi_demo.c follows
   docs/examples/urlapi.c, which formats with the C library directly.
   Leaving them out turns any unmet need into a loud undefined-symbol link
   error instead of a quiet change in behavior, and declining to supply an
   unbounded sprintf wrapper is a deliberate hygiene choice rather than an
   oversight. Were the allocating pair ever genuinely required, the way to
   build it is to size the result with vsnprintf and then allocate, adding
   allowfunc malloc and allowfunc realloc to .checksrc; the unbounded pair
   should never be built. */

/* Opt-in, and off unless the build asks for it. The crate already exports
   curl_free under the default-on cfree feature declared in
   rust-urlapi/Cargo.toml, and the standalone link builds the crate with
   its default features, so defining curl_free here as well is a hard
   multiple-definition link error rather than a harmless unused archive
   member: that manifest's release profile sets codegen-units to one,
   which collapses the staticlib into effectively a single object defining
   curl_url and curl_free together, and the link pulls that object in
   unconditionally because it needs curl_url. This block therefore serves
   only the remaining case, a link with no libcurl against a crate built
   without cfree.

   Plain free is the faithful expansion. curl_free forwards to curlx_free
   at lib/escape.c:L189-L192, and lib/curl_setup.h resolves that name at
   compile time to the tracking curl_dbg_free under memory debugging at
   L1461, to the mutable global hook Curl_cfree under BUILDING_LIBCURL at
   L1478, or to the C library's own deallocator at L1484. first.h defines
   neither CURL_MEMDEBUG nor BUILDING_LIBCURL, so the third arm is the one
   in force, and it is also the only arm that suits buffers the crate took
   straight from the C allocator: the tracking arm would reject them or
   account for them wrongly, and the hook arm would mean importing a
   libcurl-private symbol and still not satisfying the tracking table.
   That is constraint R3, reported here and deliberately not worked
   around; the full ownership chain is in ../docs/MEMORY-OWNERSHIP.md. */
#ifdef HARNESS_SHIM_CURL_FREE
void curl_free(void *p)
{
  free(p);
}
#endif
