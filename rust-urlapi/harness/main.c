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

/* main() for the standalone harness: what tests/libtest/first.c is to
   curl's libtest bundle, this file is to one test compiled on its own.
   Six of that file's behaviors are kept, each expanded at its own site
   below; the four things left behind are listed after them, with why.

   What is kept, in the order it runs:

   - the empty URL default from tests/libtest/first.c:L211, so no argument
     is ever required of this binary;
   - setlocale(LC_ALL, "") from its L231, one of three settings that gate
     the test's IDN assertions and the only one this file owns;
   - selection of the URL from the command line, reshaped from its
     L257-L258 because there is only one test here to name, so the URL
     moves up an argument;
   - invocation of the test's entry point, its L279, which the bundle
     reaches through the s_entries[] lookup instead;
   - the "Test ended with result" line on stderr, from its L280;
   - the 0..125 exit clamp from its L287-L289, which carries the
     per-sub-test exit code of tests/libtest/lib1560.c:L2040-L2071 out
     intact.

   Standard output is not this file's to write. Acceptance rests on a
   byte-for-byte diff of it, and tests/libtest/lib1560.c owns every byte:
   the success line at its L2073 that tests/data/test1560:L37 expects, and
   the failure detail at L1952, L1960 and L2013. Its other report sites go
   to stderr, several of them carrying __FILE__ and __LINE__, which differ
   between the two builds and are why stderr is not diffed. The one line
   printed here goes to stderr too, as tests/libtest/first.c:L280 does. */

/* Deliberately absent, every one of them present in
   tests/libtest/first.c:

   - the s_entries[] dispatcher and all that serves it: test_argc and
     test_argv (L234-L235), the argv[1] test-name lookup (L237-L255),
     libtest_arg2, arg3 and arg4 (L262-L269) and the CURL_TESTNUM read
     (L271-L277). A single compiled-in test needs none of it, and
     tests/libtest/lib1560.c reads none of it.
   - memory_tracking_init() (L220), which belongs to the memory-debug
     machinery that the allocator note below rules out.
   - curlx_now_init() (L222), a libcurl-private helper that neither
     harness link mode has any claim on.
   - CURL_BINMODE(stdout) (L218) and _flushall() (L284), Windows
     stdout-mode handling. Windows code paths in this port are compiled
     conditionally and are not validated here, so neither is carried over
     under a guard that nothing would exercise. */

/* The allocator note, recorded here and deliberately not worked around.
   curl_free() forwards to curlx_free() at lib/escape.c:L189-L192, which
   resolves at compile time three ways: to the tracking curl_dbg_free()
   under memory debugging (lib/curl_setup.h:L1461), whose free validates
   the pointer against its own table (lib/memdebug.c:L383); to the mutable
   global hook Curl_cfree when libcurl itself is being built (L1478); or to
   plain free() (L1484).

   The crate takes the buffers it hands back to C from the C allocator, and
   two of those three release them correctly: plain free(), and Curl_cfree
   while it holds the callback lib/easy.c:L107 initialises it to, which is
   free. That second path is the one a drop-in link takes, since escape.c is
   compiled with BUILDING_LIBCURL as part of libcurl. Only the tracking free
   is incompatible, and only one other configuration is -- an application
   that substitutes its own allocators through curl_global_init_mem()
   (lib/easy.c:L237), which this harness is not.

   So this harness defines none of CURLDEBUG, DEBUGBUILD, CURL_MEMDEBUG or
   BUILDING_LIBCURL, which is what keeps the tracking free out of the link
   and is also why memory_tracking_init() is gone. The consequence is stated
   rather than papered over: curl's allocation counter belongs to the
   memory-debug build, so it does not run here and the ceiling of
   Allocations: 3000 at tests/data/test1560:L40 is not measured in this
   configuration. The whole chain is in ../docs/MEMORY-OWNERSHIP.md. */

#include "first.h"

/* setlocale() and LC_ALL. tests/libtest/first.c reaches them at its L27,
   behind HAVE_LOCALE_H, because curl_config.h can tell it whether the
   header is there. This harness has no curl_config.h and wants none: the
   header and the function are both Standard C, so no feature test is
   needed and none is used. That is deliberate. A guard the build forgot to
   define would skip the call in silence, and a silently skipped setlocale
   is the one failure this file exists to make impossible. */
#include <locale.h>

/* The status this binary exits with when it could not put itself into the
   locale the parity run depends on. Chosen so that whatever drives the run
   can tell a harness that never started from a sub-test that failed --
   ../scripts/run-parity.sh is to be that driver and is not written yet, so
   for now the status is read by hand: every code test_lib1560() returns is
   1 through 11
   (tests/libtest/lib1560.c:L2040-L2071), every TEST_ERR_* value the real
   harness uses is a CURLE_OBSOLETE* below 57
   (tests/libtest/first.h:L106-L117), and 126 and 127 belong to the shell.
   120 is outside all three and inside the 125 clamp below. */
#define HARNESS_ERR_SETLOCALE 120

int main(int argc, const char **argv)
{
  /* Defaulted as tests/libtest/first.c:L211 defaults it, so that no
     argument is ever required of this binary. Safe to leave empty: the
     test discards it at tests/libtest/lib1560.c:L2038 with (void)URL,
     being driven entirely by its own tables. */
  const char *URL = "";
  CURLcode result;
  /* What setlocale() answered with, held so that the answer is tested
     rather than assumed away. See below. */
  const char *locale;

  /* Setup proper locale from environment, as tests/libtest/first.c:L231
     does it, and for the reason its L225-L229 gives: locale-specific
     behavior in the C library is what makes undesired side effects it
     could cause in libcurl testable.

     Here it does more. libidn2 is reached through the lookup macro at
     lib/idn.c:L35-L41, which off Windows expands to the locale-aware
     idn2_lookup_ul, so a non-ASCII host converts only while the process
     codeset is UTF-8 -- and a C program sits in the "C" locale until
     something asks for the environment's, whatever LC_ALL holds. This is
     one of three settings, and it is the only one this file can own. The
     other two are environment variables the caller has to export:
     LC_ALL=C.UTF-8, which tests/data/test1560:L14 sets, and
     CURL_TEST_HAVE_CODESET_UTF8, which tests/runtests.pl:L836-L839
     exports and tests/libtest/lib1560.c:L2036 reads into has_utf8 to gate
     the punycode rows at its L1446, L1548 and L1591. Drop any one of the
     three and those rows stop running while the harness still prints
     success -- a false green, which is worse than a failure, because the
     expectation at tests/libtest/lib1560.c:L629-L631, that
     r\xc3\xa4ksm\xc3\xb6rg\xc3\xa5s.se comes back as
     xn--rksmrgs-5wao1o.se, is exactly where a porting mistake shows.
     ../scripts/run-parity.sh is to export both variables and repeat the
     run with the codeset one set and unset; that script is a later
     deliverable and does not exist yet, so for now they are exported by
     hand on the command line that starts this binary.

     Unconditional, unlike the HAVE_SETLOCALE guard at
     tests/libtest/first.c:L230, for the reason above the include.

     The return value is checked, unlike at tests/libtest/first.c:L231,
     and the difference is the whole point rather than an embellishment.
     setlocale() answers with NULL when it cannot honor the request and
     then leaves the previous locale in force, so an unchecked call in a
     process whose LC_ALL names a locale this system does not have
     installed carries straight on in the "C" locale. That is not a
     failure the run would report: idn2_lookup_ul() would fail every
     non-ASCII name, has_utf8 would be false, the punycode rows at
     tests/libtest/lib1560.c:L1446, L1548 and L1591 would not run, and
     the harness would print success on stdout having exercised none of
     the conversion this port is most likely to get wrong. Refusing to
     start is the only honest answer, so the diagnostic goes to stderr,
     which is not diffed, and stdout stays byte-identical on every path
     that reaches the test at all.

     The status is deliberately outside the range the test itself returns.
     tests/libtest/lib1560.c:L2040-L2071 answers with a sub-test number, 1
     through 11, and the exit status is what any caller maps back to a
     sub-test name -- ../scripts/run-parity.sh is to do that mapping once it
     lands, and by hand until then. 120 cannot be mistaken for one of those
     numbers either way, so refusing to start stays distinguishable from a
     sub-test failing.

     The format string is a literal, as every format string in this
     harness is, so nothing the environment supplies is ever interpreted
     as a conversion. */
  locale = setlocale(LC_ALL, "");
  if(!locale) {
    curl_mfprintf(stderr, "harness: setlocale(LC_ALL, \"\") failed. The "
                  "locale named by the environment is unavailable, so the "
                  "IDN rows of lib1560 would silently not run. Install the "
                  "locale (C.UTF-8 is what tests/data/test1560 asks for) or "
                  "correct LC_ALL, LC_CTYPE and LANG.\n");
    return HARNESS_ERR_SETLOCALE;
  }

  /* One optional argument, so this binary can be driven the way a libtest
     program is. tests/libtest/first.c requires argv[1] to name a test, at
     its L237-L241, and reads the URL from argv[2] at its L257-L258; there
     is one test here, so the URL moves up to argv[1] and nothing is
     mandatory -- the binary can be, and today is, invoked bare, and
     ../scripts/run-parity.sh and ../GNUmakefile are to invoke it the same
     way once they land. Written across two lines because
     scripts/checksrc.pl reports a conditional body on the if() line as
     ONELINECONDITION. */
  if(argc > 1)
    URL = argv[1];

  result = harness_run_test(URL);

  /* The only output this file produces, and on stderr for the reason
     given above. Mirrors tests/libtest/first.c:L280. */
  curl_mfprintf(stderr, "Test ended with result %d\n", result);

  /* Regular program status codes are limited to 0..127, and 126 and 127
     have special meanings by the shell, so limit a normal return code to
     125. Reasoning and expression both from
     tests/libtest/first.c:L287-L289. The clamp cannot fire here, every
     code tests/libtest/lib1560.c:L2040-L2071 returns being 1 through 11,
     and it is carried over anyway because those codes are this harness's
     per-sub-test report: a caller reads the status back and names the
     sub-test that failed, which ../scripts/run-parity.sh is to automate
     once it lands. Nothing on this path is remapped, collapsed into 0 and
     1, or swallowed. */
  return (int)result <= 125 ? (int)result : 125;
}
