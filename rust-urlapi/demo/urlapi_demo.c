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
/* <DESC>
 * URL API parity demonstration: exercise the whole public URL API and print
 * a deterministic transcript of what every call answered.
 * </DESC>
 */

/* This program is the second of the port's two oracles. The first is
   tests/libtest/lib1560.c, run unmodified through ../harness/; this one is
   an ordinary outside consumer of the public API, and its value is that it
   is independent of that test's coverage. Its stdout, linked against the
   Rust crate, must be byte-identical to its stdout linked against the
   unmodified C implementation of lib/urlapi.c.

   Everything below follows from one fact: these output bytes are the
   oracle. So the transcript is deterministic, pure ASCII, locale-invariant
   and free of anything a second run or a second machine could change --
   there is no time, no process id, no pointer, no width-dependent
   conversion and no iteration over anything unordered. Values are printed
   rather than asserted, because a diff against the reference build is a
   stronger check than any expectation this file could hold: an expectation
   encodes what its author believed, while the diff encodes what curl does.

   Four properties earn their own note because they look like style and
   are not:

   - Every retrieved value is printed inside brackets. Several vectors here
     legitimately return the empty string, under CURLU_GET_EMPTY, or a value
     ending in a space, under CURLU_ALLOW_SPACE. Unbracketed, those would
     end a transcript line in whitespace, which scripts/spacecheck.pl
     rejects; bracketed, "empty" also stays visually distinct from
     "absent".
   - Every failure prints the numeric code as well as the message. If a
     build ever links the non-verbose curl_url_strerror at
     lib/strerror.c:L525-L530, the numbers still match and the diff names
     the cause instead of merely failing.
   - Nothing is skipped on an error. Reporting an error code is the parity
     signal, so a failing call prints and the transcript carries on. The
     one exception is an allocation failure, which cannot produce a
     comparable transcript at all; see oom() below.
   - No value is passed to a conversion before it has been shown to exist.
     curl_url_get() can answer CURLUE_OK and store nothing, and printing a
     null through %s is undefined behavior, so an oracle that did it would
     crash on a defect instead of naming it. showpart() prints a fixed
     marker line and fails the run instead; the reasoning is there. */

#include <stdio.h>

#ifdef URLAPI_DEMO_STANDALONE

/* Standalone (Mode B): no libcurl takes part in the link, so the public
   headers are not on the include path and ../include/curl_urlapi_rs.h
   stands in for them. That file is a one-for-one mirror of
   include/curl/urlapi.h:L34-L149 and therefore stops exactly where the
   real header stops. */
#include "curl_urlapi_rs.h"

/* curl_free() is declared at include/curl/curl.h:L2735, not in urlapi.h,
   which only refers to it in the prose at its L130-L131. The mirror header
   reproduces urlapi.h and so does not declare it either -- deliberately,
   because a mirror that added a declaration its original lacks would no
   longer be one. In this mode the crate exports the symbol behind its
   cfree Cargo feature, and this prototype has to match
   include/curl/curl.h:L2735 exactly, which is why it is spelled the same
   way here. */
void curl_free(void *p);

#else

/* Drop-in (Mode A): the real public headers, from the unmodified tree.
   curl.h supplies curl_free() and the version macros; urlapi.h is named
   because it is the API under test, and its own include guard makes the
   mention free. */
#include <curl/curl.h>
#include <curl/urlapi.h>

/* Only meaningful in this mode: CURL_AT_LEAST_VERSION comes from
   include/curl/curlver.h:L75 by way of curl.h, and the mirror header has no
   includes and therefore no version macros. 8.9.0 is the floor because this
   program uses CURLU_NO_GUESS_SCHEME, added then per
   docs/libcurl/curl_url_get.md:L144, having already used CURLU_GET_EMPTY
   from 8.8.0 per its L128. Form copied from
   docs/examples/urlapi.c:L31-L33. */
#if !CURL_AT_LEAST_VERSION(8, 9, 0)
#error "this program requires curl 8.9.0 or later"
#endif

#endif

/* No other header is included, and that is deliberate rather than
   incidental. <string.h>, <stdlib.h> and <locale.h> are all absent: nothing
   here copies or allocates on its own, and setlocale() belongs to
   ../harness/main.c, whose test has locale-sensitive assertions to gate.
   This program has none -- see section 9 -- so calling setlocale() here
   would introduce the very environment dependence the transcript must not
   have. Nothing from lib/ is included in either mode. */

/* The status returned when an allocation failed. Distinct from 0 so that a
   truncated transcript can never be mistaken for a passing run. */
#define DEMO_ERR_OOM 1

/* The status returned when curl_url_get() answered CURLUE_OK and stored a
   null pointer. See showpart() for why that shape is reachable and why this
   program refuses to dereference it.

   A separate bit rather than a separate number: every caller accumulates
   these statuses with |=, so two different faults in one run both survive
   into main()'s return value instead of one masking the other. */
#define DEMO_ERR_NULL_VALUE 2

/* Reports an allocation failure and asks for a non-zero exit.

   This is the only thing in the program that writes to stderr, and that is
   deliberate: stdout carries the transcript and is what gets diffed, so a
   diagnostic must never go there.

   An allocation failure is also the only condition the program reports at
   all. Every other CURLUcode is an expected line of the transcript -- the
   inputs below are chosen to produce them -- whereas out of memory means the
   transcript no longer describes what the URL API does. curl_url() and
   curl_url_dup() return NULL only on out of memory, per
   docs/libcurl/curl_url.md and docs/libcurl/curl_url_dup.md, and
   curl_url_get() and curl_url_set() report it as CURLUE_OUT_OF_MEMORY; both
   routes end here, the first at its call site and the second through
   status_of(). So on any machine that can run this program at all, stderr
   stays empty and the status stays 0.

   Called once per failing call rather than once per run, so a run that hits
   several says so several times. The status is what main() returns; the
   count is not carried, because one is already enough to fail the run.

   fputs() rather than fprintf(): scripts/checksrc.pl bans fprintf and
   ./.checksrc waives only printf, so the message is a plain literal
   string. It needs no formatting anyway. */
static int oom(void)
{
  fputs("urlapi_demo: out of memory; transcript is not trustworthy\n",
        stderr);
  return DEMO_ERR_OOM;
}

/* Maps one CURLUcode to this program's exit status.

   CURLUE_OUT_OF_MEMORY is the only code that means the transcript itself is
   unreliable; every other code -- CURLUE_NO_SCHEME on a handle that has no
   scheme, CURLUE_MALFORMED_INPUT on an input designed to be malformed, and
   the rest -- is an expected line of the transcript and part of what the
   byte-for-byte diff checks. Distinguishing them here rather than at each
   call site is what keeps the transcript's meaning in one place.

   Out of memory reaches this program two ways and both are covered. A NULL
   from curl_url() or curl_url_dup() is handled by oom() at the call site,
   because there is no handle to carry on with. A CURLUE_OUT_OF_MEMORY from
   curl_url_get() (lib/urlapi.c:L1533, L1611, L1630) or curl_url_set()
   (L1707, L1855, L1898, L1946, L1994) leaves the handle usable, so the code
   is printed like any other -- which keeps the transcript comparable for as
   long as it can be -- and this mapping then carries the status out through
   the section that produced it. Without that, a get or set that ran out of
   memory would print its code into the transcript and the process would
   still exit 0, which is exactly the false success the demo exists to make
   impossible.

   The diagnostic goes to stderr, once per failing call, and never to
   stdout. */
static int status_of(CURLUcode uc)
{
  if(uc != CURLUE_OUT_OF_MEMORY)
    return 0;
  return oom();
}

/* Retrieves one part and prints it.

   OWNERSHIP. On success curl_url_get() hands back a pointer this caller
   owns and must release with curl_free(), which include/curl/urlapi.h:L130-
   L131 and docs/libcurl/curl_url_get.md:L45 both require; L46 of that page
   adds that the string must not be altered, and nothing here alters it. The
   release happens below, once, immediately after the value is printed.

   On failure this caller owns nothing, so the failure branch frees nothing.
   lib/urlapi.c:L1552 sets *part to NULL before the switch, and
   docs/libcurl/curl_url_get.md:L249 says the contents are undefined on
   error other than that, so there is no pointer to release and no need for
   one: the local starts out NULL as well.

   Which curl_free() this resolves to differs by link mode and the
   difference does not matter. In drop-in mode it is libcurl's own, at
   lib/escape.c:L189-L192; in standalone mode it is the crate's cfree-gated
   export. Either is correct because every buffer the crate hands to C comes
   from the C allocator, which is the arrangement AAP 0.6.4 settles on and
   ../docs/MEMORY-OWNERSHIP.md records end to end.

   Two configurations are reported there as unsupported rather than worked
   around. The first is a memory-debug build of curl (AAP 0.2.4.3), where
   curl_free() becomes curl_dbg_free(). That function performs no lookup and
   rejects nothing: it subtracts the offset of the payload within its own
   header struct from the pointer it was handed and frees that address
   unconditionally (lib/memdebug.c:L362-L385), so a C-allocator buffer with
   no such header in front of it is released at an address that was never the
   start of an allocation. Heap corruption, not a refusal. The second is an
   application that installs its own allocators through the
   alternative-allocator entry point at lib/easy.c:L237 (AAP 0.2.4.4), which
   would release these buffers with a deallocator that never allocated them.

   The handle is const because curl_url_get() takes const CURLU *.

   SUCCESS DOES NOT IMPLY A POINTER, and that is why the value is tested
   before it is printed rather than after. CURLUE_OK alongside a null
   *partp is a real shape of the C implementation, not a defensive
   hypothetical: urlget_format() at lib/urlapi.c:L1391-L1398 hands the
   encoded part over as curlx_dyn_ptr(&enc), which is NULL for a dynamic
   buffer nothing was ever added to, so an empty part retrieved with
   CURLU_URLENCODE returns CURLUE_OK with nothing stored.
   docs/libcurl/curl_url_get.md:L249 leaves the contents undefined on any
   other code, and lib/urlapi.c:L1552 nulls the slot before every failing
   return, so a null is the one thing this caller can be handed at any time.
   None of the vectors below pairs CURLU_URLENCODE with an empty part, so
   the reference transcript never takes this branch -- but passing a null to
   %s is undefined behavior, and an oracle that crashes reports nothing. A
   defective implementation returning CURLUE_OK with no buffer therefore
   gets a fixed line in the transcript and a non-zero status, which the
   byte-for-byte diff names, instead of a signal that ends the run.

   Returns DEMO_ERR_OOM if the retrieval ran out of memory,
   DEMO_ERR_NULL_VALUE for the shape just described, and 0 otherwise, so
   that every caller can carry the status out to main(). See status_of() for
   why out of memory is singled out. The buffer, if there was one, is
   released before the status is computed, so no path here can return early
   and leave it behind. */
static int showpart(const CURLU *u, CURLUPart part, const char *label,
                    unsigned int flags)
{
  char *value = NULL;
  CURLUcode uc = curl_url_get(u, part, &value, flags);

  if(!uc) {
    if(!value) {
      /* Nothing was handed over, so nothing is released here: free(NULL)
         would be harmless but there is no block to name. The marker is
         plain ASCII with no trailing space and no bracket, so it is
         distinct from both of the other two line shapes this program
         prints and safe for scripts/spacecheck.pl. */
      printf("%s: rc=0 with no value\n", label);
      return DEMO_ERR_NULL_VALUE;
    }
    printf("%s: [%s]\n", label, value);
    curl_free(value);
  }
  else
    /* curl_url_strerror() returns a pointer to a static string, per
       docs/libcurl/curl_url_strerror.md, so it is never freed. */
    printf("%s: rc=%d (%s)\n", label, (int)uc, curl_url_strerror(uc));

  return status_of(uc);
}

/* Assigns one part and prints the outcome, success included, so that a
   successful assignment appears as rc=0 in the transcript and
   curl_url_strerror() is exercised on its success path too.

   Nothing is allocated here for this caller to own: curl_url_set() copies
   the value it is given, per include/curl/urlapi.h:L138-L139.

   Returns DEMO_ERR_OOM if the assignment ran out of memory and 0 otherwise,
   for the reason status_of() gives. A failed assignment still leaves the
   handle usable, which is what section 11 relies on -- but the guarantee is
   narrower than "unchanged" and the difference is worth stating rather than
   rounding off.

   Atomicity belongs to CURLUPART_URL alone. That one goes through set_url()
   at lib/urlapi.c:L1871-L1872, which parses into a zeroed temporary and swaps
   into the live handle only on success (L1197-L1209), so no partial mutation
   is ever observable. An individual part setter has no temporary: it reaches
   its switch arm, commits whatever that arm commits, and only then encodes
   and allocates, so a failure after that point leaves the earlier commit in
   place. Three arms do commit something. CURLUPART_HOST frees the zone
   identifier at L1848 before anything can fail, so a host assignment that
   then runs out of memory leaves the zone identifier already cleared.
   CURLUPART_QUERY sets query_present at L1865 and CURLUPART_FRAGMENT sets
   fragment_present at L1869, both before the encoding step, so either flag
   can end up set for a part that was never stored -- which changes what
   CURLU_GET_EMPTY reports afterwards.

   None of that is a defect of the port. It is the C's behavior, reproduced,
   and this demo never depends on it: every setpart() call here either
   succeeds or fails for a reason the transcript prints, and no later section
   reads a part whose assignment failed. */
static int setpart(CURLU *u, CURLUPart part, const char *value,
                   const char *label, unsigned int flags)
{
  CURLUcode uc = curl_url_set(u, part, value, flags);
  printf("%s: rc=%d (%s)\n", label, (int)uc, curl_url_strerror(uc));
  return status_of(uc);
}

static void section(const char *heading)
{
  printf("--- %s ---\n", heading);
}

/* Notes are part of the transcript, so their text is as fixed as any other
   line here and cannot be reworded without regenerating the golden file. */
static void note(const char *text)
{
  printf("note: %s\n", text);
}

/* Retrieves all eleven CURLUPart values, in the order
   include/curl/urlapi.h:L70-L82 declares them, under one set of flags.
   Parts a given handle does not carry report their own code rather than
   being skipped, which is the point: those codes are as much a part of the
   contract as the values.

   The eleven statuses are accumulated with |= rather than short-circuited,
   so that all eleven lines reach the transcript whatever any one of them
   reported. That is the same choice main() makes, for the same reason: a
   truncated transcript is harder to diff than a complete one. */
static int showallparts(const CURLU *u, unsigned int flags)
{
  int rc = 0;

  rc |= showpart(u, CURLUPART_URL, "url", flags);
  rc |= showpart(u, CURLUPART_SCHEME, "scheme", flags);
  rc |= showpart(u, CURLUPART_USER, "user", flags);
  rc |= showpart(u, CURLUPART_PASSWORD, "password", flags);
  rc |= showpart(u, CURLUPART_OPTIONS, "options", flags);
  rc |= showpart(u, CURLUPART_HOST, "host", flags);
  rc |= showpart(u, CURLUPART_PORT, "port", flags);
  rc |= showpart(u, CURLUPART_PATH, "path", flags);
  rc |= showpart(u, CURLUPART_QUERY, "query", flags);
  rc |= showpart(u, CURLUPART_FRAGMENT, "fragment", flags);
  rc |= showpart(u, CURLUPART_ZONEID, "zoneid", flags);
  return rc;
}

/* Parses base, applies rel to it as a relative URL and prints the result.
   One handle per case, released here, so the four branches of
   redirect_url() at lib/urlapi.c:L1214-L1284 are independent of each
   other. */
static int redirect_case(const char *base, const char *rel,
                         const char *label)
{
  CURLU *u = curl_url();
  CURLUcode uc;
  int rc;

  if(!u)
    return oom();

  uc = curl_url_set(u, CURLUPART_URL, base, 0);
  if(!uc)
    uc = curl_url_set(u, CURLUPART_URL, rel, 0);

  if(uc) {
    printf("%s: rc=%d (%s)\n", label, (int)uc, curl_url_strerror(uc));
    rc = status_of(uc);
  }
  else
    rc = showpart(u, CURLUPART_URL, label, 0);

  /* The handle is this function's to release, on the failing path as much as
     on the succeeding one, so the cleanup happens before the status is
     returned rather than after an early exit. The string showpart()
     retrieved was released by showpart() itself; curl_url_cleanup() would
     not have released it, per include/curl/urlapi.h:L116-L118. */
  curl_url_cleanup(u);
  return rc;
}

/* 1. A whole URL parsed with every part read back, and the one part an
      https URL cannot carry. */
static int s01_parse_and_all_parts(void)
{
  CURLU *u;
  CURLU *m;
  int rc = 0;

  section("1. full parse and all eleven parts");

  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_URL,
                "https://user:secret@example.com:8080/a/b/../c?x=1&y=2#frag",
                "set url", 0);
  rc |= showallparts(u, 0);
  curl_url_cleanup(u);

  /* The options part is suppressed on the whole-URL path unless the scheme
     owns PROTOPT_URLOPTIONS, lib/urlapi.c:L1477-L1478, and credentials are
     split into options at all only for such a scheme, L284-L290. That bit
     belongs to three protocols, lib/urldata.h:L545, so no https URL can
     reach the options part and imap is used instead. */
  m = curl_url();
  if(!m)
    return oom();
  rc |= setpart(m, CURLUPART_URL, "imap://user;auth=NTLM@example.com/INBOX",
                "set imap url", 0);
  rc |= showpart(m, CURLUPART_USER, "imap user", 0);
  rc |= showpart(m, CURLUPART_OPTIONS, "imap options", 0);
  rc |= showpart(m, CURLUPART_URL, "imap url", 0);
  curl_url_cleanup(m);
  return rc;
}

/* 2. The path that is never absent, and all four relative branches. */
static int s02_path_and_relative(void)
{
  CURLU *u;
  int rc = 0;

  section("2. path default and relative resolution");

  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_URL, "https://example.com", "set url", 0);
  /* lib/urlapi.c:L1605-L1607 substitutes "/" when the field is null, which
     docs/libcurl/curl_url_get.md:L196-L197 documents, so the path part
     never reports missing. */
  rc |= showpart(u, CURLUPART_PATH, "path of a URL with none", 0);
  rc |= showpart(u, CURLUPART_URL, "url", 0);
  curl_url_cleanup(u);

  rc |= redirect_case("http://example.com/path/index.html",
                      "//other.example.com/x", "protocol-relative");
  rc |= redirect_case("http://example.com/path/index.html",
                      "/rooted", "root-relative");
  rc |= redirect_case("http://example.com/path/index.html?q=1#f",
                      "#newfrag", "fragment-only");
  /* The vector docs/examples/parseurl.c:L67 uses. */
  rc |= redirect_case("http://example.com/path/index.html",
                      "../another/second.html", "default case");
  rc |= redirect_case("http://example.com/path/index.html?old#f",
                      "?new", "query-only");
  return rc;
}

/* 3. Default port injection and suppression, for a scheme whose default is
      443 and one whose default is 80. */
static int s03_default_port(void)
{
  CURLU *u;
  int rc = 0;

  section("3. default port and no default port");

  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_URL, "https://example.com/", "set url", 0);
  rc |= showpart(u, CURLUPART_PORT, "port", 0);
  /* lib/urlapi.c:L1586-L1594 injects the scheme's default when there is no
     stored port, and L1461-L1468 does the same on the whole-URL path. */
  rc |= showpart(u, CURLUPART_PORT, "port default_port", CURLU_DEFAULT_PORT);
  rc |= showpart(u, CURLUPART_URL, "url default_port", CURLU_DEFAULT_PORT);
  curl_url_cleanup(u);

  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_URL, "https://example.com:443/", "set url", 0);
  rc |= showpart(u, CURLUPART_PORT, "port", 0);
  /* lib/urlapi.c:L1595-L1602 and L1469-L1474 drop a stored port that
     equals the scheme's default. */
  rc |= showpart(u, CURLUPART_PORT, "port no_default_port",
                 CURLU_NO_DEFAULT_PORT);
  rc |= showpart(u, CURLUPART_URL, "url no_default_port",
                 CURLU_NO_DEFAULT_PORT);
  curl_url_cleanup(u);

  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_URL, "http://example.com/", "set http url", 0);
  rc |= showpart(u, CURLUPART_PORT, "http port default_port",
                 CURLU_DEFAULT_PORT);
  rc |= setpart(u, CURLUPART_URL, "http://example.com:80/", "set http url", 0);
  rc |= showpart(u, CURLUPART_PORT, "http port no_default_port",
                 CURLU_NO_DEFAULT_PORT);
  rc |= showpart(u, CURLUPART_URL, "http url no_default_port",
                 CURLU_NO_DEFAULT_PORT);
  /* A non-default port survives both flags. */
  rc |= setpart(u, CURLUPART_URL, "http://example.com:8080/",
                "set http url", 0);
  rc |= showpart(u, CURLUPART_PORT, "http port 8080 no_default_port",
                 CURLU_NO_DEFAULT_PORT);
  curl_url_cleanup(u);
  return rc;
}

/* 4. Encoding on assignment and decoding on retrieval.

      The non-ASCII vector is written as hex escapes and only ever printed
      in its percent-encoded form. docs/libcurl/curl_url_set.md describes
      that encoding as charset-unaware and byte by byte, so it is
      locale-independent and safe for a committed transcript, which the IDN
      conversions in section 9 are not. */
static int s04_encode_decode(void)
{
  CURLU *u;
  int rc = 0;

  section("4. encode on set, decode on get");

  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_URL, "https://example.com/", "set url", 0);

  /* Query mode turns a space into a plus before anything else, and
     percent-encodes everything outside the unreserved set, so both the
     ampersand and the equals sign are encoded here. */
  rc |= setpart(u, CURLUPART_QUERY, "name=hello world&x=1",
                "set query urlencode", CURLU_URLENCODE);
  rc |= showpart(u, CURLUPART_QUERY, "query raw", 0);
  /* Retrieval undoes both, and the plus-to-space half applies to the query
     part alone, lib/urlapi.c:L1612. */
  rc |= showpart(u, CURLUPART_QUERY, "query urldecode", CURLU_URLDECODE);

  /* Path mode additionally leaves eighteen characters alone -- the cases
     allowed_in_path() lists at lib/urlapi.c:L1779-L1803 -- so the plus
     survives while the space and the percent do not. */
  rc |= setpart(u, CURLUPART_PATH, "/a b+c%20d?e", "set path urlencode",
                CURLU_URLENCODE);
  rc |= showpart(u, CURLUPART_PATH, "path raw", 0);
  rc |= showpart(u, CURLUPART_PATH, "path urldecode", CURLU_URLDECODE);

  rc |= setpart(u, CURLUPART_QUERY, "na\xc3\xaf" "ve=1",
                "set query non-ascii urlencode", CURLU_URLENCODE);
  rc |= showpart(u, CURLUPART_QUERY, "query non-ascii raw", 0);

  /* The whole-URL path escapes the host when asked to encode,
     lib/urlapi.c:L1492-L1496 -- the opposite of the part encoder, which
     exempts the host deliberately at L127 so that IDN resolution can still
     work. Both are the source behaviour. */
  rc |= showpart(u, CURLUPART_URL, "url urlencode", CURLU_URLENCODE);
  curl_url_cleanup(u);

  /* Without CURLU_URLENCODE an escape already present is not re-encoded but
     is lower-cased where it stands, lib/urlapi.c:L1922-L1932. */
  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_URL, "https://example.com/", "set url", 0);
  rc |= setpart(u, CURLUPART_PATH, "/%C3%AF/%2F", "set path plain", 0);
  rc |= showpart(u, CURLUPART_PATH, "path escapes lowercased", 0);
  /* Decoding is demonstrated on escapes that decode to ASCII. Decoding the
     two bytes of %C3%AF above would put them in the transcript, and the
     transcript has to stay ASCII whatever the vector was. */
  rc |= setpart(u, CURLUPART_PATH, "/%2Fa%20b", "set path ascii escapes", 0);
  rc |= showpart(u, CURLUPART_PATH, "path raw", 0);
  rc |= showpart(u, CURLUPART_PATH, "path urldecode", CURLU_URLDECODE);
  curl_url_cleanup(u);
  return rc;
}

/* 5. Appending to the query, and the separator rule. */
static int s05_append_query(void)
{
  CURLU *u;
  int rc = 0;

  section("5. append query");

  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_URL, "https://example.com/?a=1", "set url", 0);
  rc |= setpart(u, CURLUPART_QUERY, "b=2", "append b", CURLU_APPENDQUERY);
  rc |= showpart(u, CURLUPART_QUERY, "query", 0);
  /* With encoding as well, the first equals sign is left alone so the
     appended pair stays a pair, while the space still becomes a plus. */
  rc |= setpart(u, CURLUPART_QUERY, "c=hello world", "append c encoded",
                CURLU_APPENDQUERY | CURLU_URLENCODE);
  rc |= showpart(u, CURLUPART_QUERY, "query", 0);
  rc |= showpart(u, CURLUPART_URL, "url", 0);
  curl_url_cleanup(u);

  /* An existing query already ending in the separator does not gain a
     second one, lib/urlapi.c:L1937-L1941. */
  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_URL, "https://example.com/?a=1&", "set url", 0);
  rc |= showpart(u, CURLUPART_QUERY, "query before", 0);
  rc |= setpart(u, CURLUPART_QUERY, "b=2", "append b", CURLU_APPENDQUERY);
  rc |= showpart(u, CURLUPART_QUERY, "query after", 0);
  curl_url_cleanup(u);

  /* The whole append block is guarded by a non-zero existing length, so
     appending to an empty query falls through to a plain assignment. */
  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_URL, "https://example.com/?", "set url", 0);
  rc |= showpart(u, CURLUPART_QUERY, "query before get_empty",
                 CURLU_GET_EMPTY);
  rc |= setpart(u, CURLUPART_QUERY, "b=2", "append b", CURLU_APPENDQUERY);
  rc |= showpart(u, CURLUPART_QUERY, "query after", 0);
  curl_url_cleanup(u);
  return rc;
}

/* 6. Blank queries and fragments, which are absent until asked for. */
static int s06_get_empty(void)
{
  CURLU *u;
  int rc = 0;

  section("6. get empty");

  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_URL, "https://example.com/?#", "set url", 0);
  /* lib/urlapi.c:L1613-L1615 suppresses a blank query and L1620-L1622
     reports a blank fragment only under the flag. */
  rc |= showpart(u, CURLUPART_QUERY, "query", 0);
  rc |= showpart(u, CURLUPART_FRAGMENT, "fragment", 0);
  rc |= showpart(u, CURLUPART_QUERY, "query get_empty", CURLU_GET_EMPTY);
  rc |= showpart(u, CURLUPART_FRAGMENT, "fragment get_empty", CURLU_GET_EMPTY);
  /* The whole-URL path is asymmetric between the two: L1432-L1433 tests
     the fragment's presence alone while L1434-L1435 also requires a
     non-empty first byte from the query. */
  rc |= showpart(u, CURLUPART_URL, "url", 0);
  rc |= showpart(u, CURLUPART_URL, "url get_empty", CURLU_GET_EMPTY);
  curl_url_cleanup(u);
  return rc;
}

/* Parses one input into a handle of its own and prints the whole URL that
   results. A fresh handle per case is not tidiness: assigning a whole URL to
   a handle that already holds one is a redirect, lib/urlapi.c:L1717-L1728,
   so reusing a handle would resolve the second input against the first
   instead of parsing it. */
static int parse_case(const char *input, unsigned int flags,
                      const char *label)
{
  CURLU *u = curl_url();
  int rc;

  if(!u)
    return oom();

  rc = setpart(u, CURLUPART_URL, input, label, flags);
  rc |= showpart(u, CURLUPART_URL, "url", 0);
  curl_url_cleanup(u);
  return rc;
}

/* 7. Guessing a missing scheme, and refusing the guess afterwards. */
static int s07_scheme_guessing(void)
{
  CURLU *u;
  int rc = 0;

  section("7. scheme guessing");

  /* No flag, no guess: a scheme-less input is not a URL. */
  rc |= parse_case("example.com", 0, "set scheme-less plain");

  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_URL, "example.com", "set guess_scheme",
                CURLU_GUESS_SCHEME);
  rc |= showpart(u, CURLUPART_SCHEME, "scheme", 0);
  /* The two arms of CURLU_NO_GUESS_SCHEME: an error for the scheme part,
     lib/urlapi.c:L1559-L1560, and a suppressed prefix for the whole URL,
     L1512-L1515. tests/libtest/lib1560.c asserts this very pair, at its
     L149-L152 and L583-L585. */
  rc |= showpart(u, CURLUPART_SCHEME, "scheme no_guess_scheme",
                 CURLU_NO_GUESS_SCHEME);
  rc |= showpart(u, CURLUPART_URL, "url", 0);
  rc |= showpart(u, CURLUPART_URL, "url no_guess_scheme",
                 CURLU_NO_GUESS_SCHEME);
  curl_url_cleanup(u);

  /* Three rows of the hostname-prefix guess table,
     lib/urlapi.c:L984-L1010, which docs/libcurl/curl_url_set.md lists in
     full, and the fallthrough that has no prefix to match. */
  rc |= parse_case("ftp.example.com", CURLU_GUESS_SCHEME,
                   "set ftp-prefixed");
  rc |= parse_case("imap.example.com", CURLU_GUESS_SCHEME,
                   "set imap-prefixed");
  rc |= parse_case("dict.example.com", CURLU_GUESS_SCHEME,
                   "set dict-prefixed");
  rc |= parse_case("www.example.com", CURLU_GUESS_SCHEME,
                   "set unprefixed");

  /* CURLU_DEFAULT_SCHEME supplies DEFAULT_SCHEME, lib/urlapi.c:L84, and
     takes precedence when both flags are given, which
     docs/libcurl/curl_url_set.md states and this pair shows: the same
     ftp-prefixed host that guesses ftp above becomes https here. */
  rc |= parse_case("ftp.example.com", CURLU_DEFAULT_SCHEME,
                   "set default_scheme");
  rc |= parse_case("ftp.example.com",
                   CURLU_GUESS_SCHEME | CURLU_DEFAULT_SCHEME,
                   "set both flags");
  return rc;
}

/* 8. Duplication, and the faithfully reproduced defect it carries. */
static int s08_dup_and_fb1(void)
{
  CURLU *u;
  CURLU *copy;
  int rc = 0;

  section("8. duplication and FB1");

  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_URL, "example.com", "set guess_scheme",
                CURLU_GUESS_SCHEME);

  /* OWNERSHIP. curl_url_dup() returns a new handle this caller owns and
     must pass to curl_url_cleanup() in its own right, per
     docs/libcurl/curl_url_dup.md; cleaning the original does not clean the
     copy. */
  copy = curl_url_dup(u);
  if(!copy) {
    curl_url_cleanup(u);
    return oom();
  }

  rc |= showpart(u, CURLUPART_SCHEME, "original scheme no_guess_scheme",
                 CURLU_NO_GUESS_SCHEME);
  rc |= showpart(copy, CURLUPART_SCHEME, "copy scheme no_guess_scheme",
                 CURLU_NO_GUESS_SCHEME);
  rc |= showpart(u, CURLUPART_URL, "original url no_guess_scheme",
                 CURLU_NO_GUESS_SCHEME);
  rc |= showpart(copy, CURLUPART_URL, "copy url no_guess_scheme",
                 CURLU_NO_GUESS_SCHEME);
  note("the two lines above differ because curl_url_dup at "
       "lib/urlapi.c:L1310-L1332 copies the ten strings, portnum, "
       "fragment_present and query_present but not guessed_scheme");
  note("reproduced deliberately as finding FB1; see "
       "../docs/KNOWN-DIVERGENCES.md");
  curl_url_cleanup(copy);
  curl_url_cleanup(u);

  /* With an explicit scheme there is nothing to drop, so a copy and its
     original serialise alike. */
  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_URL, "https://user@example.com:8080/p?q=1#f",
                "set url", 0);
  copy = curl_url_dup(u);
  if(!copy) {
    curl_url_cleanup(u);
    return oom();
  }
  rc |= showpart(u, CURLUPART_URL, "original url", 0);
  rc |= showpart(copy, CURLUPART_URL, "copy url", 0);
  rc |= showpart(copy, CURLUPART_USER, "copy user", 0);
  rc |= showpart(copy, CURLUPART_PORT, "copy port", 0);
  /* A copy is independent: changing it leaves the original alone. */
  rc |= setpart(copy, CURLUPART_HOST, "other.example.com", "copy set host", 0);
  rc |= showpart(copy, CURLUPART_URL, "copy url after set", 0);
  rc |= showpart(u, CURLUPART_URL, "original url after copy set", 0);
  curl_url_cleanup(copy);
  curl_url_cleanup(u);
  return rc;
}

/* 9. The punycode flag, on a host that is already in punycode form.

      WHAT IS DELIBERATELY NOT HERE, AND WHY. Neither CURLU_PUNY2IDN nor a
      non-ASCII host appears in this program. The C implementation reaches
      libidn2 through the macro at lib/idn.c:L35-L41, which off Windows
      expands to the locale-aware idn2_lookup_ul, so converting a non-ASCII
      host succeeds only while the process codeset is UTF-8 -- AAP 0.6.3
      measures both outcomes, and acceptance criterion A9 requires both to
      be exercised. One committed transcript could not match a converted
      host under LC_ALL=C.UTF-8 and CURLUE_BAD_HOSTNAME under LC_ALL=C, so
      ../scripts/run-parity.sh runs this program once, in the UTF-8
      environment its golden was captured in, and discharges A9 through the
      harness instead, which it runs over all four locale and codeset cells
      against the reference's own capture of each. IDN coverage therefore
      belongs to that other oracle, where
      tests/libtest/lib1560.c gates exactly those rows on
      CURL_TEST_HAVE_CODESET_UTF8 at its L2036 and checks them at L1446,
      L1548 and L1591. This is a boundary between the two oracles, not a
      gap in either.

      What an already-ASCII host does show, with no library and no locale
      involved, is that the flag is accepted and changes nothing. Both
      conversion sites -- lib/urlapi.c:L1497-L1503 in the whole-URL reader
      and L1402-L1411 in the part reader -- are guarded on
      !Curl_is_ASCII_name(u->host), so for the ACE host below the conversion
      is skipped outright and the host comes back exactly as it went in.
      That is worth a transcript line because it is the half of the flag's
      behaviour that is locale-independent; the conversion itself is not
      exercised here at all. */
static int s09_punycode_flag(void)
{
  CURLU *u;
  int rc = 0;

  section("9. punycode flag on an ascii host");

  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_URL, "https://xn--rksmrgs-5wao1o.se/path",
                "set ace url", 0);
  rc |= showpart(u, CURLUPART_HOST, "host", 0);
  rc |= showpart(u, CURLUPART_HOST, "host punycode", CURLU_PUNYCODE);
  rc |= showpart(u, CURLUPART_URL, "url punycode", CURLU_PUNYCODE);
  note("CURLU_PUNY2IDN and non-ascii hosts are exercised by the lib1560 "
       "oracle instead, because their result depends on the process "
       "codeset");
  curl_url_cleanup(u);
  return rc;
}

/* 10. Addresses: bracketed IPv6, a zone identifier, and the numeric
       normalisation an IPv4 host goes through. */
static int s10_addresses(void)
{
  CURLU *u;
  int rc = 0;

  section("10. ipv6, zone id and ipv4 normalisation");

  u = curl_url();
  if(!u)
    return oom();
  /* The host comes back bracketed, per
     docs/libcurl/curl_url_get.md:L179. */
  rc |= setpart(u, CURLUPART_URL, "https://[fe80::1]:8080/p",
                "set ipv6 url", 0);
  rc |= showpart(u, CURLUPART_HOST, "host", 0);
  rc |= showpart(u, CURLUPART_PORT, "port", 0);
  rc |= showpart(u, CURLUPART_URL, "url", 0);
  rc |= showpart(u, CURLUPART_ZONEID, "zoneid", 0);
  curl_url_cleanup(u);

  u = curl_url();
  if(!u)
    return oom();
  /* The delimiter is written percent-encoded in the input, and the
     whole-URL path re-emits it that way from the separate zone field,
     lib/urlapi.c:L1480-L1491. */
  rc |= setpart(u, CURLUPART_URL, "https://[fe80::1%25eth0]/p",
                "set zoned url", 0);
  rc |= showpart(u, CURLUPART_HOST, "host", 0);
  rc |= showpart(u, CURLUPART_ZONEID, "zoneid", 0);
  rc |= showpart(u, CURLUPART_URL, "url", 0);
  curl_url_cleanup(u);

  u = curl_url();
  if(!u)
    return oom();
  /* The vector tests/libtest/lib1560.c:L155 asserts. */
  rc |= setpart(u, CURLUPART_URL, "https://0.000/", "set ipv4 url", 0);
  rc |= showpart(u, CURLUPART_HOST, "host", 0);
  rc |= showpart(u, CURLUPART_URL, "url", 0);
  rc |= setpart(u, CURLUPART_URL, "https://0x7f.1/", "set ipv4 hex url", 0);
  rc |= showpart(u, CURLUPART_HOST, "host", 0);
  rc |= setpart(u, CURLUPART_URL, "https://256.256.256.256/",
                "set out-of-range ipv4", 0);
  rc |= showpart(u, CURLUPART_HOST, "host", 0);
  curl_url_cleanup(u);
  return rc;
}

/* 11. The error surface: null preconditions, rejected input, clearing a
       part, and every message curl_url_strerror can produce. */
static int s11_errors_and_strerror(void)
{
  CURLU *u;
  char *value = NULL;
  CURLUcode uc;
  int code;
  int rc = 0;

  section("11. error paths and null preconditions");

  /* lib/urlapi.c:L1548-L1549: a null handle is rejected before anything
     else. Passing NULL here is the documented precondition, not a
     mistake. */
  uc = curl_url_get(NULL, CURLUPART_URL, &value, 0);
  printf("get with null handle: rc=%d (%s)\n", (int)uc,
         curl_url_strerror(uc));

  uc = curl_url_set(NULL, CURLUPART_URL, "https://example.com/", 0);
  printf("set with null handle: rc=%d (%s)\n", (int)uc,
         curl_url_strerror(uc));

  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_URL, "https://example.com/p?a=1#f", "set url", 0);

  /* lib/urlapi.c:L1550-L1551: a null output pointer is rejected too, and
     nothing is allocated, so nothing is freed on this path. */
  uc = curl_url_get(u, CURLUPART_URL, NULL, 0);
  printf("get with null part pointer: rc=%d (%s)\n", (int)uc,
         curl_url_strerror(uc));

  /* Clearing by assigning a null value, lib/urlapi.c:L1819-L1821 into the
     clear dispatch at L1732-L1777. The query's presence bit goes with it,
     L1765-L1767, so it is absent even under CURLU_GET_EMPTY. */
  rc |= setpart(u, CURLUPART_QUERY, NULL, "clear query", 0);
  rc |= showpart(u, CURLUPART_QUERY, "query after clear", CURLU_GET_EMPTY);
  rc |= setpart(u, CURLUPART_FRAGMENT, NULL, "clear fragment", 0);
  rc |= showpart(u, CURLUPART_FRAGMENT, "fragment after clear",
                 CURLU_GET_EMPTY);
  rc |= showpart(u, CURLUPART_URL, "url after clears", 0);
  curl_url_cleanup(u);

  u = curl_url();
  if(!u)
    return oom();
  /* A port above 65535 is refused, lib/urlapi.c:L1673-L1675. */
  rc |= setpart(u, CURLUPART_URL, "https://example.com:65536/", "set bad port",
                0);
  rc |= setpart(u, CURLUPART_PORT, "70000", "set bad port part", 0);
  rc |= setpart(u, CURLUPART_PORT, "8o80", "set non-numeric port", 0);
  /* Leading zeros are stripped because the text is regenerated from the
     number, lib/urlapi.c:L1676. */
  rc |= setpart(u, CURLUPART_URL, "https://example.com:00080/",
                "set padded port", 0);
  rc |= showpart(u, CURLUPART_PORT, "port", 0);

  /* An unknown scheme is refused unless the caller allows it,
     lib/urlapi.c:L1646-L1647. */
  rc |= setpart(u, CURLUPART_URL, "custom://example.com/",
                "set unknown scheme", 0);
  rc |= setpart(u, CURLUPART_URL, "custom://example.com/",
                "set unknown scheme allowed", CURLU_NON_SUPPORT_SCHEME);
  rc |= showpart(u, CURLUPART_URL, "url", 0);
  /* Bad scheme syntax is a different code again,
     lib/urlapi.c:L1641-L1643 and L1650-L1660. */
  rc |= setpart(u, CURLUPART_SCHEME, "1nvalid", "set bad scheme syntax",
                CURLU_NON_SUPPORT_SCHEME);
  curl_url_cleanup(u);

  u = curl_url();
  if(!u)
    return oom();
  /* Embedded credentials can be refused by the caller. */
  rc |= setpart(u, CURLUPART_URL, "https://user:pass@example.com/",
                "set url disallow_user", CURLU_DISALLOW_USER);
  /* A space is refused unless allowed, and then stored as it stands --
     which is why the brackets around retrieved values matter. */
  rc |= setpart(u, CURLUPART_URL, "https://example.com/a b",
                "set url with space", 0);
  rc |= setpart(u, CURLUPART_URL, "https://example.com/a b ",
                "set url with space allowed", CURLU_ALLOW_SPACE);
  rc |= showpart(u, CURLUPART_PATH, "path with space", 0);
  /* An empty host, and a hostname with a character no host may carry. */
  rc |= setpart(u, CURLUPART_HOST, "", "set empty host", 0);
  rc |= setpart(u, CURLUPART_HOST, "exam ple.net", "set bad hostname", 0);
  curl_url_cleanup(u);

  /* Documented as taking no action, docs/libcurl/curl_url_cleanup.md, so
     the transcript records that the process carried on. */
  curl_url_cleanup(NULL);
  printf("cleanup of a null handle: [survived]\n");

  section("11b. every curl_url_strerror message");
  /* Every enumerator of include/curl/urlapi.h:L34-L68, in order. The last
     of them, CURLUE_LAST, is a sentinel the switch at
     lib/strerror.c:L520-L521 breaks out of, so it exercises the
     "CURLUcode unknown" fallthrough at L524 without this program ever
     casting a value outside the enumeration.

     The strings recorded here are the verbose ones. CURLVERBOSE is defined
     at lib/curl_setup.h:L1597 whenever C99 variadic macros are available
     and CURL_DISABLE_VERBOSE_STRINGS is not set, so it is the default and
     is what the reference build compiled; a build without it answers only
     "No error" and "Error", per lib/strerror.c:L525-L530, and the numeric
     codes printed alongside would then be what the diff turned on. */
  for(code = 0; code <= (int)CURLUE_LAST; code++)
    printf("strerror %d: [%s]\n", code,
           curl_url_strerror((CURLUcode)code));

  /* Out-of-range parts, on both dispatches. Retrieval falls out of its
     switch through the default arm at lib/urlapi.c:L1626-L1628 and reports
     the initial ifmissing; assignment has a real default arm at L1874.
     CURLUPART_ZONEID is the last enumerator, so one past it is out of
     range. */
  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_URL, "https://example.com/", "set url", 0);
  uc = curl_url_get(u, (CURLUPart)(CURLUPART_ZONEID + 1), &value, 0);
  printf("get with out-of-range part: rc=%d (%s)\n", (int)uc,
         curl_url_strerror(uc));
  uc = curl_url_set(u, (CURLUPart)(CURLUPART_ZONEID + 1), "x", 0);
  printf("set with out-of-range part: rc=%d (%s)\n", (int)uc,
         curl_url_strerror(uc));
  curl_url_cleanup(u);
  return rc;
}

/* 12. The empty whole URL: a relative URL that changes nothing, and the
       flag it is really sensitive to. */
static int s12_empty_url(void)
{
  CURLU *u;
  int rc = 0;

  section("12. the empty url rule");

  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_URL, "https://example.com/p?a=1#f", "set url", 0);
  /* lib/urlapi.c:L1697-L1710. The comment at L1698-L1699 gives the intent:
     a blank URL is accepted only because a complete one is already
     present. */
  rc |= setpart(u, CURLUPART_URL, "", "set empty url", 0);
  rc |= showpart(u, CURLUPART_URL, "url unchanged", 0);
  curl_url_cleanup(u);

  /* A guessed scheme changes nothing about the empty write, with or without
     CURLU_NO_GUESS_SCHEME. Both are printed, because this is the one
     combination a reader expects to behave differently and it does not.

     AAP 0.6.5 states that this write "fails with malformed input -- because
     the retrieval returns the no-scheme code lib/urlapi.c:L1559-L1560". It
     does not. That guard is in the CURLUPART_SCHEME arm; L1700 reads
     CURLUPART_URL, which L1624-L1625 dispatches to urlget_url, where the
     same flag is read at L1512-L1515 only to blank the scheme prefix before
     returning CURLUE_OK -- so L1701-L1706 make the write a no-op success.
     A guessed scheme also always leaves u->scheme set, L1004-L1008, so the
     CURLUE_NO_SCHEME at L1453-L1458 cannot fire on such a handle either.

     The three lines below therefore appear identically in this program
     linked against the unmodified C and linked against the Rust archive,
     which is what acceptance criterion A7 requires of every line here.
     ../docs/KNOWN-DIVERGENCES.md records the reading under "Checked and not
     a divergence: the empty whole-URL write under CURLU_NO_GUESS_SCHEME". */
  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_URL, "example.com", "set guess_scheme",
                CURLU_GUESS_SCHEME);
  rc |= showpart(u, CURLUPART_URL, "url no_guess_scheme",
                 CURLU_NO_GUESS_SCHEME);
  rc |= setpart(u, CURLUPART_URL, "", "set empty url", 0);
  rc |= setpart(u, CURLUPART_URL, "", "set empty url no_guess_scheme",
                CURLU_NO_GUESS_SCHEME);
  rc |= showpart(u, CURLUPART_URL, "url unchanged", 0);
  note("CURLU_NO_GUESS_SCHEME is a formatting choice on the read the empty "
       "write performs, not an error, so both empty writes above succeed "
       "and neither changes the handle");
  curl_url_cleanup(u);

  /* The sensitivity that is real. A handle with a host and no scheme
     cannot serialise unless CURLU_DEFAULT_SCHEME supplies one at
     L1455-L1456, and L1709 turns that failure into malformed input -- so
     the same empty value on the same handle answers two different ways. */
  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_HOST, "example.com", "set host only", 0);
  rc |= showpart(u, CURLUPART_URL, "url", 0);
  rc |= showpart(u, CURLUPART_URL, "url default_scheme", CURLU_DEFAULT_SCHEME);
  rc |= setpart(u, CURLUPART_URL, "", "set empty url", 0);
  rc |= setpart(u, CURLUPART_URL, "", "set empty url default_scheme",
                CURLU_DEFAULT_SCHEME);
  note("the caller's flags are passed into that internal read unfiltered, "
       "which is what makes one empty value answer two ways");
  curl_url_cleanup(u);

  /* And on a handle holding nothing at all there is nothing to keep. */
  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_URL, "", "set empty url on empty handle", 0);
  curl_url_cleanup(u);
  return rc;
}

/* 13. Dot segments, removed or preserved. */
static int s13_path_as_is(void)
{
  CURLU *u;
  int rc = 0;

  section("13. path as is");

  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_URL, "https://example.com/a/b/../c/./d/..",
                "set url", 0);
  rc |= showpart(u, CURLUPART_PATH, "path", 0);
  rc |= showpart(u, CURLUPART_URL, "url", 0);
  curl_url_cleanup(u);

  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_URL, "https://example.com/a/b/../c/./d/..",
                "set url path_as_is", CURLU_PATH_AS_IS);
  rc |= showpart(u, CURLUPART_PATH, "path", 0);
  rc |= showpart(u, CURLUPART_URL, "url", 0);
  curl_url_cleanup(u);

  /* The percent-encoded form of a dot segment is detected as well,
     lib/urlapi.c:L682-L695. */
  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_URL, "https://example.com/a/%2e%2e/b",
                "set url", 0);
  rc |= showpart(u, CURLUPART_PATH, "path", 0);
  curl_url_cleanup(u);
  return rc;
}

/* 14. The file scheme, which has no authority, and an unknown scheme
       allowed to have none. */
static int s14_file_and_no_authority(void)
{
  CURLU *u;
  int rc = 0;

  section("14. file scheme and no authority");

  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_URL, "file:///tmp/example.txt",
                "set file url", 0);
  rc |= showpart(u, CURLUPART_SCHEME, "scheme", 0);
  rc |= showpart(u, CURLUPART_HOST, "host", 0);
  rc |= showpart(u, CURLUPART_PATH, "path", 0);
  rc |= showpart(u, CURLUPART_PORT, "port default_port", CURLU_DEFAULT_PORT);
  /* The file branch of the serialiser is a five-argument template with no
     authority at all, lib/urlapi.c:L1440-L1447. */
  rc |= showpart(u, CURLUPART_URL, "url", 0);
  curl_url_cleanup(u);

  u = curl_url();
  if(!u)
    return oom();
  rc |= setpart(u, CURLUPART_URL, "file://localhost/tmp/example.txt",
                "set file url with host", 0);
  rc |= showpart(u, CURLUPART_HOST, "host", 0);
  rc |= showpart(u, CURLUPART_URL, "url", 0);
  curl_url_cleanup(u);

  u = curl_url();
  if(!u)
    return oom();
  /* An empty authority is accepted only under CURLU_NO_AUTHORITY,
     lib/urlapi.c:L1967. */
  rc |= setpart(u, CURLUPART_URL, "custom://", "set empty authority",
                CURLU_NON_SUPPORT_SCHEME);
  rc |= setpart(u, CURLUPART_URL, "custom://", "set empty authority allowed",
                CURLU_NON_SUPPORT_SCHEME | CURLU_NO_AUTHORITY);
  rc |= showpart(u, CURLUPART_URL, "url", 0);
  rc |= showpart(u, CURLUPART_HOST, "host", 0);
  rc |= showpart(u, CURLUPART_PATH, "path", 0);
  curl_url_cleanup(u);
  return rc;
}

int main(void)
{
  int rc = 0;

  /* The banner exists so that the licence annotation lands in the golden
     transcript. ../demo/expected-output.txt is a tracked file that reuse
     lint covers, and it cannot carry an inline annotation without corrupting
     the very bytes it asserts, so the program prints one and the golden file
     legitimately contains it. REUSE.toml:L4-L6 asks that a file be annotated
     directly unless it cannot carry comments, and this route satisfies that
     without a sidecar and without touching REUSE.toml, which is out of
     scope.

     Where those bytes come from: ../scripts/build-reference.sh runs this
     program linked against an unmodified libcurl, checks the capture against
     every rule scripts/spacecheck.pl applies to a tracked file, and only then
     writes it to that path. ../scripts/run-parity.sh reads it and never
     writes it, so the oracle is captured from the C and compared against the
     Rust rather than being produced by the thing under test.

     Printed unconditionally in both link modes. Anything conditional here
     would make the two modes' transcripts differ, and acceptance criterion
     A7 is that they do not.

     The three lines are bracketed by REUSE-IgnoreStart and REUSE-IgnoreEnd
     because reuse lint, which .github/workflows/checksrc.yml:L60-L63 runs,
     scans for the tag anywhere in a file and would otherwise try to parse
     the remainder of the printf argument as a licence expression and report
     it invalid. This is the mechanism its own diagnostic recommends, and
     scripts/managen:L662-L669, scripts/cd2cd:L131-L138 and
     scripts/cd2nroff:L288-L295 already use it to carry the tag as data
     rather than as their own annotation. This file's real annotation is the
     box at the top, which the brackets leave alone and which is what reuse
     lint reads. */
  /* REUSE-IgnoreStart */
  printf("curl URL API parity demonstration\n");
  printf("Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.\n");
  printf("SPDX-License-Identifier: curl\n");
  /* REUSE-IgnoreEnd */

  /* Accumulated rather than short-circuited, deliberately. Every section
     runs whatever the ones before it reported, so the transcript is never
     truncated and the diff always covers the whole surface; the status is
     non-zero only if some allocation failed somewhere inside.

     Each section accumulates the same way over its own calls, and showpart()
     and setpart() each answer DEMO_ERR_OOM for a CURLUE_OUT_OF_MEMORY, so
     the chain from one failing retrieval or assignment to this program's
     exit status is unbroken. Nothing swallows that code: a run that printed
     an out-of-memory line into the transcript cannot also exit 0, which is
     the whole point of returning a status from the two printers. */
  rc |= s01_parse_and_all_parts();
  rc |= s02_path_and_relative();
  rc |= s03_default_port();
  rc |= s04_encode_decode();
  rc |= s05_append_query();
  rc |= s06_get_empty();
  rc |= s07_scheme_guessing();
  rc |= s08_dup_and_fb1();
  rc |= s09_punycode_flag();
  rc |= s10_addresses();
  rc |= s11_errors_and_strerror();
  rc |= s12_empty_url();
  rc |= s13_path_as_is();
  rc |= s14_file_and_no_authority();

  /* No network call, no easy handle, no multi handle and no global init
     appears anywhere above: the URL API needs none of them, which is part
     of what keeps this transcript reproducible. */
  return rc;
}
