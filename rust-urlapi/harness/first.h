#ifndef HEADER_RUST_URLAPI_HARNESS_FIRST_H
#define HEADER_RUST_URLAPI_HARNESS_FIRST_H
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

/* The minimal replacement for tests/libtest/first.h: its one job is to let
   tests/libtest/lib1560.c compile unmodified against public headers alone.
   That source has one include, "first.h" at tests/libtest/lib1560.c:L33,
   and a quoted include resolves against the directory the compiler opened
   the including file from. The intended arrangement is therefore a staging
   directory holding a symlink to the test source beside a copy of this
   header, so that the name lands here and not on the original, which pulls
   libcurl's private build environment in at tests/libtest/first.h:L33 and
   L46. rust-urlapi/scripts/build-reference.sh creates that directory and
   records it as HARNESS_STAGE_DIR, and rust-urlapi/scripts/run-parity.sh
   reuses the same one for both Rust link modes, so all three links compile
   the identical staged source against this header. The staging lives under
   the ignored build/ tree; nothing under tests/ is edited. */

/* CURL_EXTERN has to expand to nothing. include/curl/curl.h:L122-L136 makes
   it __declspec(dllimport) on Windows unless this macro or BUILDING_LIBCURL
   is defined, and nothing in shims.c can define a function whose
   declaration claims to be imported. Both harness link modes link static
   archives. Must precede every curl header. */
#define CURL_STATICLIB

/* Mirrors tests/libtest/first.h:L26-L27, so the test source sees the same
   API surface the real harness gives it: no legacy names, and none of the
   deprecation attributes built at include/curl/curl.h:L37-L43. */
#define CURL_NO_OLDIES
#define CURL_DISABLE_DEPRECATION

/* Never defined here: BUILDING_LIBCURL, CURLDEBUG, DEBUGBUILD,
   CURL_MEMDEBUG. curl_free() forwards to curlx_free() at
   lib/escape.c:L189-L192, which resolves at compile time three ways: to the
   tracking curl_dbg_free() under memory debugging (lib/curl_setup.h:L1461),
   to the mutable global hook Curl_cfree under BUILDING_LIBCURL (L1478), or
   to plain free() (L1484).

   The crate takes its C-visible buffers from the C allocator, and TWO of
   those three release them correctly. Plain free() does, obviously. So does
   Curl_cfree while it still holds the callback lib/easy.c:L107 initialises
   it to, which is free itself -- and that is the path a drop-in link takes,
   because escape.c is compiled as part of libcurl and therefore with
   BUILDING_LIBCURL defined. Both supported link modes are covered: drop-in
   reaches libcurl's own curl_free() through the default hook, standalone
   reaches the crate's cfree-gated export.

   Exactly two configurations are incompatible, and neither is reachable
   from here. A memory-debug build, where curl_dbg_free() validates the
   pointer against its own table (lib/memdebug.c:L383) -- which is why
   CURL_MEMDEBUG and its companions are left undefined above. And an
   application that substitutes its own allocators through
   curl_global_init_mem() (lib/easy.c:L237), which replaces the hook with a
   deallocator that never saw the block.

   One consequence of leaving memory debugging off is worth stating rather
   than discovering: curl's own allocation counter belongs to that build, so
   it does not run here and the ceiling at tests/data/test1560:L40 is not
   measured. The whole chain is recorded under "Reported limitation R3" in
   ../docs/MEMORY-OWNERSHIP.md. */

/* curl.h alone covers the curl side: it reaches the URL API at its L3316
   and the curl_m*printf family at L3320. urlapi.h is named anyway, as the
   API under test; its own guard makes the second mention cost nothing. */
#include <stdbool.h>      /* bool */
#include <stdio.h>        /* stderr, sscanf; also via curl.h:L65 */
#include <stdlib.h>       /* getenv */
#include <string.h>       /* memset, memcpy, strlen, strcmp, strchr */
#include <curl/curl.h>    /* CURLcode, CURLE_OK, curl_free, curl_mfprintf */
#include <curl/urlapi.h>  /* CURLU, CURLUcode, CURLUPart, curl_url_get */

/* Part of the compatibility surface this shim owes a libtest source. The
   real tests/libtest/first.h inherits all three from lib/curl_setup.h,
   TRUE and FALSE at L1047-L1052 and CURL_ARRAYSIZE at L1287, so a source
   written against that harness may use them freely. Defining them here is
   what keeps such a source compilable without editing it, whether or not
   the particular source compiled in happens to reach for them. Each
   definition is guarded so that a genuine curl_setup.h in scope wins. */
#ifndef TRUE
#define TRUE true
#endif
#ifndef FALSE
#define FALSE false
#endif
#ifndef CURL_ARRAYSIZE
#define CURL_ARRAYSIZE(A) (sizeof(A) / sizeof((A)[0]))
#endif

/* The test's entry point, static CURLcode test_lib1560(const char *URL) at
   tests/libtest/lib1560.c:L2034, has internal linkage, so no other
   translation unit can call it. runner.c includes the test source and
   re-exports it below; main.c calls that. This one declaration stands in
   for the entry_func_t, struct entry_s and s_entries[] contract at
   tests/libtest/first.h:L36-L42, and it names no test, so neither this
   header nor main.c knows which source was compiled in. */
CURLcode harness_run_test(const char *URL);

#endif /* HEADER_RUST_URLAPI_HARNESS_FIRST_H */
