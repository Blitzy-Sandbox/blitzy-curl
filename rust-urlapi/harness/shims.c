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
   return value, described where it is defined. This harness also carries no
   memory debugging, so curl's allocation counter does not run and the
   ceiling at tests/data/test1560:L40 is not measured in this
   configuration; the whole chain is recorded under "Reported limitation
   R3" in ../docs/MEMORY-OWNERSHIP.md. */

/* first.h reaches <stdio.h> at its L64 and <stdlib.h> at L65, but this file
   names vprintf, vfprintf, vsnprintf and free directly, so it asks for
   their headers directly too rather than relying on a transitive include
   that a later edit to first.h could take away. scripts/checksrc.pl
   reports a repeated include as INCLUDEDUP only within one file, so
   restating them here costs nothing. */
#include "first.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

/* vsnprintf, used below, is not in C90 at all: C90 declares only vsprintf
   and vfprintf, and it was C99 that added both the function and the
   truncation rule this file relies on for byte-exact agreement with
   lib/mprintf.c. Compiled as C90 the call would therefore reach an
   implicit declaration -- assumed to return int, taking unchecked
   arguments -- which on a platform where the symbol happens to exist would
   link and silently misbehave, and which C99 made a constraint violation
   anyway. So the requirement is stated and checked instead of assumed.

   Two spellings satisfy it. __STDC_VERSION__ >= 199901L is the portable
   one. MSVC is the documented exception: it gained a conforming vsnprintf
   in Visual Studio 2015, _MSC_VER 1900, yet defines __STDC_VERSION__ only
   when /std:c11 or later is passed, so testing the standard macro alone
   would reject a compiler that is in fact fine. Windows is not validated
   here, per the porting plan, which is exactly why the arm is written to
   admit it rather than to exclude it silently. */
#if !(defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)) && \
    !(defined(_MSC_VER) && (_MSC_VER >= 1900))
#error "shims.c requires C99 or later: vsnprintf and its truncation rule \
are C99 features, and a C90 compilation would reach an implicit \
declaration instead. Compile this harness with -std=c99 or later (or, on \
MSVC, with Visual Studio 2015 or newer)."
#endif

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

/* THE REQUIRED C STANDARD FOR THIS FILE IS C99, AND ONLY FOR THIS FILE.
   docs/INTERNALS.md:15 states that curl and libcurl are written to compile
   with C89 compilers, and this harness holds to that everywhere it can:
   first.h, runner.c and main.c compile with zero diagnostics at both
   -std=c89 and -std=c99 with -Wall -Wextra -pedantic. This file is the one
   exception, and the reason is one function. curl_mvsnprintf below forwards
   to vsnprintf, which C99 added to <stdio.h> and C89 does not declare at
   all, so under strict C89 the call gets an implicit int declaration and the
   behavior is undefined -- a silent miscompile of the one shim whose whole
   job is to be bound-correct.

   Declared as a hard error rather than left to prose, because prose in a
   comment cannot stop a build. The __STDC_VERSION__ guard higher up this
   file is the whole test, and what it admits was measured with gcc 15.2.0
   rather than reasoned about:

     -std=c89     __STDC_VERSION__ undefined => rejected, which is the one
                  case that would otherwise be undefined behavior: the same
                  call compiled as C89 draws "implicit declaration of
                  function vsnprintf", measured.
     -std=gnu89   __STDC_VERSION__ undefined => rejected as well. glibc
                  does declare vsnprintf in that dialect, and the call
                  compiles clean there, measured -- so this rejection is a
                  decision rather than a necessity. A bound-correctness
                  guarantee resting on which C library happens to be in
                  front of the compiler, instead of on the language
                  standard, is not one this file is willing to make.
     -std=c99 and later, and the compiler default => accepted.
     MSVC 2015 and newer => accepted through that guard's _MSC_VER arm,
                  for the reason given above it.

   Exactly one command in this crate compiles this file, and it is the Mode B
   harness link in ../scripts/run-parity.sh, which ../GNUmakefile drives
   through its parity target. That link is also the only place
   HARNESS_MODE_B is defined, which is what unlocks the definitions below.
   It passes the options ../scripts/build-reference.sh recorded as
   HARNESS_CFLAGS, "-O2 -Wall -Wextra" by default, and deliberately no
   -std= at all: the compiler default decides, and every default this crate
   is built with satisfies the guard -- gcc and clang have defaulted to a
   C99-or-later dialect for many releases. Not naming a standard is the
   right call rather than an omission, because the reference link and the
   two Rust links have to be given one identical option list or the
   byte-for-byte diff compares two different compilations, and that list is
   recorded once in the summary file instead of being spelled out three
   times.
   So the guard is the enforcement, not the command line: a caller that
   forces -std=c89 -- a build file, or a person -- fails here loudly instead
   of silently miscompiling the one shim whose whole job is to be
   bound-correct.

   No C89 fallback is offered, and that is a decision. Bounded formatting
   without vsnprintf means formatting into an oversized buffer with vsprintf
   and hoping, which is precisely the unbounded-sprintf hazard the note below
   the definitions declines to supply. A loud error beats a quiet overflow.

   One guard, not two. An earlier revision of this file added a second
   #error keyed on __STRICT_ANSI__ here, described as a narrower test that
   let -std=gnu89 through. It never could: the guard above already rejects
   every dialect that leaves __STDC_VERSION__ below 199901L, gnu89 included,
   and a c89 compilation was measured to stop at that first guard's message.
   The second test was therefore unreachable and its description wrong, so
   it is gone rather than explained. */

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
   outright. Recorded in ../docs/KNOWN-DIVERGENCES.md under "the harness
   shim's `snprintf` return value", which also states that this applies to
   the standalone link alone: the drop-in link brings its own
   lib/mprintf.c. */

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
   harness reaches for any of the four: tests/libtest/lib1560.c calls only
   curl_mprintf, curl_mfprintf and curl_msnprintf, all three defined above,
   and rust-urlapi/demo/urlapi_demo.c calls no curl_m* name at all -- it
   formats with printf from the C library, as docs/examples/urlapi.c does,
   and ../demo/.checksrc bans all ten names include/curl/mprintf.h declares
   so that a later edit reaching for one is caught by the lint before the
   linker. Both statements were checked against those files, not assumed.
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
   That limitation is reported here and deliberately not worked around; the
   full ownership chain is recorded under "Reported limitation R3" in
   ../docs/MEMORY-OWNERSHIP.md. */
#ifdef HARNESS_SHIM_CURL_FREE
void curl_free(void *p)
{
  free(p);
}
#endif
