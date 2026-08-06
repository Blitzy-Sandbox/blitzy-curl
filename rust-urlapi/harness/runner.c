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

/* Makes the unmodified tests/libtest/lib1560.c reachable from a linker. Its
   entry point, static CURLcode test_lib1560(const char *URL) at
   tests/libtest/lib1560.c:L2034, has internal linkage, so no extern
   declaration can reach it: the symbol is not there to reach. Compiling the
   test source into this translation unit and re-exporting it is the only way
   in that leaves the test byte-unchanged. That is curl's own arrangement:
   scripts/mk-unity.pl builds the libtest bundle from #include "first.h" (its
   L60), one #include "<test>.c" per test (L68), the s_entries[] table (L76)
   and #include "first.c" (L77), so curl too compiles lib1560.c by including
   the .c file. This is that pattern by hand for a single test, s_entries[]
   replaced by the one bridge below and first.c by main.c; being tracked
   rather than generated, it carries a real licence box and needs none of the
   COPYRIGHT waiver mk-unity.pl emits at its L58. The build names the test
   source through HARNESS_TEST_SOURCE and owns the parity macros USE_LIBIDN2
   (tests/libtest/lib1560.c:L34-L36), CURL_DISABLE_WEBSOCKETS (L295) and
   _WIN32 (L361); the two blocks below say what each requires of it. */

#include "first.h"

/* Preprocessor parity. tests/libtest/lib1560.c compiles a different set of
   assertions depending on three macros -- USE_LIBIDN2 at its L34-L36,
   CURL_DISABLE_WEBSOCKETS at L295 and _WIN32 at L361 -- so the reference
   compilation and the Rust compilation have to be handed an identical set;
   otherwise the byte-for-byte diff of their output compares two different
   suites and proves nothing. The build owns all three, and each is spelled
   out below.

   USE_LIBIDN2: tests/libtest/lib1560.c:L34-L36 folds it, USE_WIN32_IDN and
   USE_APPLE_IDN into USE_IDN, the same disjunction libcurl itself uses at
   lib/idn.h:L29-L30. USE_IDN gates the IDN rows at L200-L223 and the
   punycode expectation at L629-L632, where r\xc3\xa4ksm\xc3\xb6rg\xc3\xa5s.se
   has to come back as xn--rksmrgs-5wao1o.se. The harness binds libidn2 by
   default, so the build passes -DUSE_LIBIDN2. It is deliberately not defined
   here, not even behind a guard: that would make USE_IDN unconditional and
   put the no-IDN configuration out of reach, and the build is in any case the
   only place that can keep the two compilations in step.

   CURL_DISABLE_WEBSOCKETS: L295-L304 gates the ws:// and wss:// rows. Left
   undefined, which is what an ordinary libcurl build gives them.

   _WIN32: L361-L375 gates the drive-letter and network-path rows. Never
   touched here; the platform decides it.

   Not defined here either, and not by ./first.h: CURLDEBUG, DEBUGBUILD,
   CURL_MEMDEBUG, BUILDING_LIBCURL. The crate takes the buffers it hands to
   C from the C allocator, and curl_free() releases them correctly in both
   supported link modes -- through plain free() standalone, and through
   Curl_cfree at its default free callback (lib/easy.c:L107) in a drop-in
   link.

   What must be avoided is curl's memory-debug free, and the mechanism is
   worth stating exactly, because the reassuring version of it is wrong.
   curl_dbg_free() does not look a pointer up in its allocation table before
   releasing it and does not reject anything: it subtracts the offset of the
   payload within its own header struct from the pointer it was given and
   frees that address unconditionally (lib/memdebug.c:L362-L385). A buffer
   that came from the C allocator carries no such header, so the address
   handed to the real deallocator is not the start of any allocation. The
   outcome is heap corruption, not a diagnostic. Leaving CURL_MEMDEBUG and
   its companions undefined is what keeps that path out of reach. The whole
   resolution chain, the one other unsupported case -- an application that
   substitutes its own allocators -- and the consequence that curl's
   allocation counter does not run here are recorded under "Reported
   limitation R3" in ../docs/MEMORY-OWNERSHIP.md. The substitute count is
   ../scripts/run-parity.sh --allocations. */

/* The build also names the staged test source. The arrangement it is built
   for is a staging directory under the ignored rust-urlapi/build/ tree
   holding a symlink lib1560.c -> tests/libtest/lib1560.c beside a copy of
   ./first.h, with this file then compiled as

     -DHARNESS_TEST_SOURCE='"lib1560.c"' -I <stage> -I include

   A quoted include is searched in the directory of the file holding the
   directive before any -I path, so HARNESS_TEST_SOURCE misses here -- the
   test source is never copied into this directory -- and -I<stage> supplies
   it. The compiler has then opened the test source at <stage>/lib1560.c, so
   its own lone include, "first.h" at tests/libtest/lib1560.c:L33, resolves
   against <stage>/ and finds the shim, never the real 574-line
   tests/libtest/first.h, which would pull in libcurl's private build
   environment at its L33 and L46. Nothing under tests/ is edited.

   rust-urlapi/scripts/build-reference.sh creates that staging directory and
   records it as HARNESS_STAGE_DIR, and rust-urlapi/scripts/run-parity.sh
   reuses the same one and issues the two Rust-mode compilations against it,
   so all three links compile one identical staged source. The mechanics above
   are what both callers rely on.

   Naming the source from the build instead of hard-coding a relative path
   lets one file serve the reference staging directory and the Rust one, and
   survives a rename of the build tree. A plain #include "lib1560.c" resting
   on the same -I<stage> behaves identically; the macro form is preferred only
   because the guard below fails loudly when the -D is forgotten. */
#ifndef HARNESS_TEST_SOURCE
#error "HARNESS_TEST_SOURCE undefined: compile with " \
       "-DHARNESS_TEST_SOURCE='\"lib1560.c\"' and an -I naming the " \
       "directory that holds the staged test source and first.h"
#endif

#include HARNESS_TEST_SOURCE

/* Re-export of the test's static entry point, and the whole of this file's
   symbol surface. The name carries no test number on purpose, so ./first.h,
   which declares it, and ./main.c, which calls it, need no knowledge of which
   source was compiled in; it stands in for the entry_func_t, struct entry_s
   and s_entries[] contract at tests/libtest/first.h:L35-L42 that
   mk-unity.pl fills in for the bundle.

   The result is passed back untouched. tests/libtest/lib1560.c:L2040-L2071
   short-circuits at the first failing sub-test and returns a code naming it,
   in an order that is not the numeric one. Passing it through unaltered is
   what lets a caller map the code back to the sub-test and iterate until
   clean; rust-urlapi/scripts/run-parity.sh is that caller, and it prints all
   eleven rows from the same table ../docs/PORTING-NOTES.md carries. Clamping
   the code into the range a shell can carry belongs to main.c, mirroring
   tests/libtest/first.c:L289. */
CURLcode harness_run_test(const char *URL)
{
  return test_lib1560(URL);
}
