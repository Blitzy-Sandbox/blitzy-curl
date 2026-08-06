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
 * curl URL API parity demonstration.
 * </DESC>
 */

/*
 * WHAT THIS PROGRAM IS FOR
 *
 * It exercises the whole public URL API and prints one deterministic
 * transcript of what it observed. The transcript is the point: the same
 * source is linked twice, once against the original C implementation of
 * lib/urlapi.c and once against the Rust re-implementation that replaces
 * that object file, and the two runs' standard output must be identical
 * byte for byte. ../scripts/build-reference.sh captures the first run into
 * expected-output.txt and ../scripts/run-parity.sh diffs the second against
 * it.
 *
 * Because those bytes are a committed artifact, three properties are not
 * negotiable and every design decision below follows from them.
 *
 * 1. Determinism. Nothing time-dependent, nothing address-dependent,
 *    nothing width-dependent, nothing read from the environment. The same
 *    bytes on every run, on every machine.
 * 2. Pure ASCII. Non-ASCII vectors are written as C escapes and only ever
 *    printed in their percent-encoded or punycode form, because
 *    ../../scripts/spacecheck.pl rejects non-ASCII bytes in tracked files
 *    and expected-output.txt is tracked.
 * 3. Locale invariance. ../scripts/run-parity.sh runs this program under
 *    both LC_ALL=C.UTF-8 and LC_ALL=C, so a single golden file has to match
 *    both. Anything routed through libidn2 would not, which is why the
 *    internationalised-domain flags are deliberately out of scope here --
 *    see the punycode section for the full argument.
 *
 * No network activity of any kind takes place. The URL API neither needs
 * curl_global_init() nor performs any transfer, which is a large part of
 * what makes the transcript reproducible.
 */

#include <stdio.h>

#ifdef URLAPI_DEMO_STANDALONE
/*
 * Standalone link mode. No libcurl takes part, so the public headers are
 * not on the include path and the crate's mirror header stands in for them.
 *
 * ../include/curl_urlapi_rs.h is a one-for-one mirror of
 * include/curl/urlapi.h and therefore, deliberately, does not declare
 * curl_free(): that declaration belongs to include/curl/curl.h:2735, and
 * urlapi.h only refers to the function in prose, at its lines 130-131. A
 * mirror that added it would no longer be a mirror. This program is the
 * header's only C consumer, so the prototype is supplied here instead.
 *
 * MEMORY OWNERSHIP. In this mode curl_free() is the crate's own export,
 * compiled in behind its "cfree" Cargo feature. It releases memory the
 * crate obtained from the C allocator, which is precisely why calling it on
 * a pointer the crate handed out is correct. The prototype is transcribed
 * from include/curl/curl.h:2735 and must stay compatible with it, because
 * this same source has to link against the real libcurl in the other mode.
 */
#include "curl_urlapi_rs.h"

void curl_free(void *p);
#else
/*
 * Drop-in link mode. The real public headers supply everything, curl_free()
 * included, so no local prototype is declared here.
 *
 * MEMORY OWNERSHIP. In this mode curl_free() resolves into libcurl's
 * lib/escape.c:189-192, which forwards to whichever deallocator
 * lib/curl_setup.h:1461-1484 selected when libcurl was compiled. Two
 * consequences are documented limitations of this arrangement rather than
 * things to work around here: a memory-debug build resolves that call to a
 * tracking free that validates pointers against its own allocation table,
 * so the parity harness is built without memory debugging; and an
 * application that installs its own allocators would free the crate's
 * C-allocator buffers with its own deallocator, which is unsupported.
 */
#include <curl/curl.h>
#include <curl/urlapi.h>

/* CURLU_NO_GUESS_SCHEME, used below, arrived in 8.9.0; CURLU_GET_EMPTY, also
   used below, arrived in 8.8.0. CURL_AT_LEAST_VERSION reaches this file only
   through <curl/curl.h>, which is why the check lives in this branch alone:
   the mirror header has no includes and so has no version macros. */
#if !CURL_AT_LEAST_VERSION(8, 9, 0)
#error "this demonstration requires curl 8.9.0 or later"
#endif
#endif

/* Print a section header. Sections, rather than blank lines, separate the
   transcript: ../../scripts/spacecheck.pl rejects consecutive empty lines
   and a trailing empty line in tracked files, so this program emits no
   empty line at all. */
static void header(const char *text)
{
  printf("--- %s ---\n", text);
}

/* Print an explanatory note. Notes label the places where the API does
   something surprising, so that a reader of expected-output.txt cannot
   mistake reproduced-on-purpose behaviour for a defect in the port. */
static void note(const char *text)
{
  printf("note: %s\n", text);
}

/*
 * Retrieve one part and print it.
 *
 * MEMORY OWNERSHIP -- the three rules that govern every caller of
 * curl_url_get(), stated here once because every retrieval in this program
 * goes through this function:
 *
 * 1. On success the pointer written through the char ** argument belongs to
 *    the caller and MUST be released with curl_free(). That is stated in
 *    include/curl/urlapi.h:130-131 and again in
 *    ../../docs/libcurl/curl_url_get.md:45. The same manual page adds, at
 *    line 46, that the returned string may not be altered, and nothing here
 *    alters it.
 * 2. On failure no part is produced: curl_url_get() writes NULL through the
 *    argument (lib/urlapi.c:1552) and ../../docs/libcurl/curl_url_get.md:249
 *    says the same. The error branch below therefore frees nothing. The
 *    local pointer is still initialised to NULL, because the two
 *    null-precondition returns at lib/urlapi.c:1548-1551 come back before
 *    even that assignment is reached -- which the null-handle vector in the
 *    error section exercises directly.
 * 3. curl_url_cleanup() does NOT release strings previously handed out by
 *    the API; include/curl/urlapi.h:116-118 says so explicitly. Every
 *    retrieved string is therefore freed individually, at its point of use.
 *    Leaning on cleanup instead would leak identically on both sides of the
 *    parity diff and so would hide a genuine ownership defect in the port
 *    rather than expose it.
 *
 * The string curl_url_strerror() returns is static and must never be
 * freed; see ../../docs/libcurl/curl_url_strerror.md.
 */
static void showpart(const CURLU *u, CURLUPart part, const char *label,
                     unsigned int flags)
{
  char *value = NULL;
  CURLUcode uc = curl_url_get(u, part, &value, flags);
  if(!uc) {
    /* The brackets are load-bearing rather than decorative. CURLU_GET_EMPTY
       legitimately yields an empty string and CURLU_ALLOW_SPACE can yield a
       value that ends in a space; printed bare, either would put trailing
       whitespace into the committed golden file, which
       ../../scripts/spacecheck.pl rejects. They also keep "empty string"
       visually distinct from "absent" in a diff. */
    printf("%s: [%s]\n", label, value);
    curl_free(value);
  }
  else
    printf("%s: rc=%d (%s)\n", label, (int)uc, curl_url_strerror(uc));
}

/*
 * Assign one part and print the outcome.
 *
 * The result is printed unconditionally, success included, for two reasons:
 * it exercises curl_url_strerror() on the rc=0 path as well, and it makes a
 * behavioural divergence show up as a changed code rather than as a line
 * that quietly went missing.
 *
 * The numeric code is printed alongside the message on purpose. Should a
 * build ever link the non-verbose curl_url_strerror() variant -- the one at
 * lib/strerror.c:527-530, which returns only "No error" or "Error" -- the
 * numbers still line up and the diff points straight at the cause instead
 * of merely failing.
 *
 * MEMORY OWNERSHIP: curl_url_set() copies the string it is given
 * (include/curl/urlapi.h:141-143). Nothing is allocated here and nothing is
 * freed here.
 */
static void setpart(CURLU *u, CURLUPart part, const char *value,
                    const char *label, unsigned int flags)
{
  CURLUcode uc = curl_url_set(u, part, value, flags);
  printf("%s: rc=%d (%s)\n", label, (int)uc, curl_url_strerror(uc));
}

/*
 * 1. One fully populated URL, then every one of the eleven CURLUPart values,
 *    the two that legitimately have nothing to report included.
 *
 * The URL part comes back with the path already normalised -- /a/b/../c
 * became /a/c during parsing, because dot-segment removal happens once, at
 * parse time, and not on retrieval.
 *
 * The options part needs its own URL. Only three protocols carry the
 * URL-options capability bit, so an https URL cannot express options at all;
 * the second handle uses imap, which can. The https handle still shows the
 * halfway state that follows from where the capability is consulted:
 * curl_url_set() stores an options string for any scheme and
 * curl_url_get(CURLUPART_OPTIONS) hands it straight back, but whole-URL
 * serialisation drops it when the scheme lacks the bit (lib/urlapi.c:1477),
 * so the URL is unchanged by the assignment.
 */
static void full_parse(void)
{
  CURLU *u = curl_url();
  CURLU *m;

  header("1. full parse and all eleven parts");
  /* curl_url() returns NULL only when an allocation fails
     (../../docs/libcurl/curl_url.md). That cannot happen for a request this
     small, and there would be nothing useful to print if it ever did, so the
     section stops rather than emitting a line the reference run would not.
     This is the one and only abort this program permits itself. */
  if(!u)
    return;
  /* The credentials in this and every other vector in this file are
     placeholders, not secrets: the host is a reserved example domain that
     resolves nowhere, no network operation is ever attempted, and the values
     exist only so that CURLUPART_USER and CURLUPART_PASSWORD have something
     to return. They are printed verbatim into the committed golden file
     precisely because they carry no meaning outside it. */
  setpart(u, CURLUPART_URL,
          "https://user:secret@example.com:8080/a/b/../c?x=1&y=2#frag",
          "set url", 0);
  showpart(u, CURLUPART_URL, "url", 0);
  showpart(u, CURLUPART_SCHEME, "scheme", 0);
  showpart(u, CURLUPART_USER, "user", 0);
  showpart(u, CURLUPART_PASSWORD, "password", 0);
  showpart(u, CURLUPART_OPTIONS, "options", 0);
  showpart(u, CURLUPART_HOST, "host", 0);
  showpart(u, CURLUPART_PORT, "port", 0);
  showpart(u, CURLUPART_PATH, "path", 0);
  showpart(u, CURLUPART_QUERY, "query", 0);
  showpart(u, CURLUPART_FRAGMENT, "fragment", 0);
  showpart(u, CURLUPART_ZONEID, "zoneid", 0);
  setpart(u, CURLUPART_OPTIONS, "mode=1", "set options on https", 0);
  showpart(u, CURLUPART_OPTIONS, "options after set", 0);
  showpart(u, CURLUPART_URL, "url after options set", 0);
  note("an https handle stores and returns options but never serialises "
       "them");
  curl_url_cleanup(u);

  m = curl_url();
  if(!m)
    return;
  setpart(m, CURLUPART_URL,
          "imap://user;auth=NTLM@mail.example.com/INBOX;UID=1",
          "set imap url", 0);
  showpart(m, CURLUPART_USER, "imap user", 0);
  showpart(m, CURLUPART_OPTIONS, "imap options", 0);
  showpart(m, CURLUPART_PATH, "imap path", 0);
  showpart(m, CURLUPART_URL, "imap url", 0);
  showpart(m, CURLUPART_PORT, "imap default port", CURLU_DEFAULT_PORT);
  curl_url_cleanup(m);
}

/*
 * 2. The path part is never absent, and all four relative-URL branches.
 *
 * ../../docs/libcurl/curl_url_get.md:196-197 promises that the path is at
 * least a single slash even when the URL carried none, which
 * lib/urlapi.c:1605-1607 implements by substituting "/" on retrieval.
 *
 * The four branches are the ones lib/urlapi.c:1229-1266 switches on: a
 * leading double slash is protocol-relative and changes the host; a leading
 * single slash is root-relative; a leading hash replaces the fragment
 * alone; and the default case truncates after the last slash, which is the
 * branch ../../docs/examples/parseurl.c:67 demonstrates and whose vector is
 * reused verbatim here. A leading question mark takes the default branch too
 * but suppresses the truncation, so it is shown as a fifth step.
 */
static void path_and_relative(void)
{
  CURLU *u = curl_url();

  header("2. path default and relative resolution");
  if(!u)
    return;
  setpart(u, CURLUPART_URL, "https://example.com", "set url without path", 0);
  showpart(u, CURLUPART_PATH, "path when absent", 0);
  showpart(u, CURLUPART_URL, "url when path absent", 0);
  setpart(u, CURLUPART_URL, "http://example.com/path/index.html",
          "set base url", 0);
  setpart(u, CURLUPART_URL, "../another/second.html",
          "set dot-dot relative", 0);
  showpart(u, CURLUPART_URL, "url after dot-dot", 0);
  setpart(u, CURLUPART_URL, "//other.example.org/x",
          "set protocol relative", 0);
  showpart(u, CURLUPART_URL, "url after protocol relative", 0);
  setpart(u, CURLUPART_URL, "/rooted", "set root relative", 0);
  showpart(u, CURLUPART_URL, "url after root relative", 0);
  setpart(u, CURLUPART_URL, "#newfrag", "set fragment only", 0);
  showpart(u, CURLUPART_URL, "url after fragment only", 0);
  setpart(u, CURLUPART_URL, "?onlyquery", "set query only", 0);
  showpart(u, CURLUPART_URL, "url after query only", 0);
  curl_url_cleanup(u);
}

/*
 * 3. CURLU_DEFAULT_PORT and CURLU_NO_DEFAULT_PORT, on both sides of the
 *    two commonest default ports.
 *
 * Both flags consult the scheme table, so both are also a check that the
 * table the port compiled in agrees with libcurl's own: 443 for https and 80
 * for http, per lib/urldata.h:29-53. The suppression is conditional on the
 * stored number matching the scheme default, which is why an explicit :443
 * on an https URL disappears and an explicit port that did not match would
 * not.
 */
static void ports(void)
{
  CURLU *u = curl_url();

  header("3. default port and no default port");
  if(!u)
    return;
  setpart(u, CURLUPART_URL, "https://example.com/", "set https no port", 0);
  showpart(u, CURLUPART_PORT, "https port", 0);
  showpart(u, CURLUPART_PORT, "https port with default",
           CURLU_DEFAULT_PORT);
  showpart(u, CURLUPART_URL, "https url with default port",
           CURLU_DEFAULT_PORT);
  setpart(u, CURLUPART_URL, "https://example.com:443/",
          "set https port 443", 0);
  showpart(u, CURLUPART_PORT, "https 443 port", 0);
  showpart(u, CURLUPART_PORT, "https 443 port with no default",
           CURLU_NO_DEFAULT_PORT);
  showpart(u, CURLUPART_URL, "https 443 url with no default",
           CURLU_NO_DEFAULT_PORT);
  setpart(u, CURLUPART_URL, "http://example.com:80/x",
          "set http port 80", 0);
  showpart(u, CURLUPART_PORT, "http 80 port", 0);
  showpart(u, CURLUPART_PORT, "http 80 port with no default",
           CURLU_NO_DEFAULT_PORT);
  showpart(u, CURLUPART_URL, "http 80 url with no default",
           CURLU_NO_DEFAULT_PORT);
  showpart(u, CURLUPART_URL, "http 80 url with default",
           CURLU_DEFAULT_PORT);
  curl_url_cleanup(u);
}

/*
 * 4. CURLU_URLENCODE on assignment, CURLU_URLDECODE on retrieval, and the
 *    lower-casing that happens when neither is asked for.
 *
 * The encoder preserves the unreserved set -- alphanumerics plus - . _ ~ per
 * lib/curl_ctype.h:47-49 -- and, in path mode, seventeen more characters
 * listed at lib/urlapi.c:1779-1803, which is why the colon and the at sign
 * survive in the path below while the space does not. For a query the space
 * becomes a plus rather than %20, and an existing plus is encoded to %2B so
 * that the transformation stays reversible; retrieving with CURLU_URLDECODE
 * turns pluses back into spaces and so round-trips the original exactly.
 *
 * The non-ASCII vector is written as C escapes and only ever printed in its
 * percent-encoded form. ../../docs/libcurl/curl_url_set.md describes this
 * encoding as charset-unaware and byte-by-byte, so it is locale-independent
 * and safe for a committed golden file; the decoded form is deliberately
 * never printed, because it is not ASCII.
 *
 * The final pair shows what happens with neither flag: the value is stored
 * verbatim except that an already-present percent escape has its two hex
 * digits lower-cased in place (lib/urlapi.c:1922-1932).
 */
static void encode_decode(void)
{
  CURLU *u = curl_url();

  header("4. encode on set, decode on get");
  if(!u)
    return;
  setpart(u, CURLUPART_URL, "https://example.com/", "set base url", 0);
  setpart(u, CURLUPART_QUERY, "name=hello world&x=a+b",
          "set query encoded", CURLU_URLENCODE);
  showpart(u, CURLUPART_QUERY, "query raw", 0);
  showpart(u, CURLUPART_QUERY, "query decoded", CURLU_URLDECODE);
  setpart(u, CURLUPART_PATH, "/a b/c+d%2Fe:f@g", "set path encoded",
          CURLU_URLENCODE);
  showpart(u, CURLUPART_PATH, "path raw", 0);
  showpart(u, CURLUPART_URL, "url raw", 0);
  showpart(u, CURLUPART_URL, "url encoded", CURLU_URLENCODE);
  /* Two bytes of UTF-8, spelled as escapes so that this source file stays
     pure ASCII, and printed only in encoded form for the same reason. */
  setpart(u, CURLUPART_QUERY, "t=\xc3\xa4\xc3\xb6",
          "set non-ASCII query encoded", CURLU_URLENCODE);
  showpart(u, CURLUPART_QUERY, "non-ASCII query raw", 0);
  setpart(u, CURLUPART_PATH, "/A%2FB%3Fc%2Dd", "set path with escapes", 0);
  showpart(u, CURLUPART_PATH, "path escapes after set", 0);
  note("without CURLU_URLENCODE an existing percent escape is lower-cased "
       "in place");
  curl_url_cleanup(u);
}

/*
 * 5. CURLU_APPENDQUERY.
 *
 * Appending inserts an ampersand only when the existing query does not
 * already end in one (lib/urlapi.c:1936-1962), so the third step -- which
 * appends to a query deliberately left ending in an ampersand -- must not
 * produce a doubled separator.
 *
 * Combined with CURLU_URLENCODE the append leaves the first equals sign
 * alone and encodes every later one, which is what makes name=value pairs
 * usable: lib/urlapi.c:1899-1902 clears the allowance after the first
 * match. The space still becomes a plus and the ampersand inside the value
 * is still encoded, so the appended pair cannot be mistaken for two.
 */
static void append_query(void)
{
  CURLU *u = curl_url();

  header("5. append query");
  if(!u)
    return;
  setpart(u, CURLUPART_URL, "https://example.com/?a=1", "set base url", 0);
  setpart(u, CURLUPART_QUERY, "b=2", "append second", CURLU_APPENDQUERY);
  showpart(u, CURLUPART_QUERY, "query after append", 0);
  setpart(u, CURLUPART_QUERY, "c=x y&z", "append third encoded",
          CURLU_APPENDQUERY | CURLU_URLENCODE);
  showpart(u, CURLUPART_QUERY, "query after encoded append", 0);
  setpart(u, CURLUPART_QUERY, "d=4&", "replace query ending in ampersand",
          0);
  setpart(u, CURLUPART_QUERY, "e=5", "append after ampersand",
          CURLU_APPENDQUERY);
  showpart(u, CURLUPART_QUERY, "query after ampersand append", 0);
  showpart(u, CURLUPART_URL, "url after appends", 0);
  note("appending to a query already ending in an ampersand adds no second "
       "separator");
  curl_url_cleanup(u);
}

/*
 * 6. CURLU_GET_EMPTY.
 *
 * A URL may carry a query delimiter or a fragment delimiter with nothing
 * after it. The handle remembers the difference between "present but empty"
 * and "absent" in two dedicated flags, and without CURLU_GET_EMPTY both
 * cases report absent. With the flag the empty string comes back instead,
 * and whole-URL serialisation re-emits the bare delimiters.
 *
 * This is the section the bracketed output format exists for: an empty value
 * printed bare would end its line in a colon and a space, which
 * ../../scripts/spacecheck.pl rejects as trailing whitespace in the
 * committed golden file.
 */
static void get_empty(void)
{
  CURLU *u = curl_url();

  header("6. get empty query and fragment");
  if(!u)
    return;
  setpart(u, CURLUPART_URL, "https://example.com/p?#", "set url", 0);
  showpart(u, CURLUPART_QUERY, "query", 0);
  showpart(u, CURLUPART_QUERY, "query with get empty", CURLU_GET_EMPTY);
  showpart(u, CURLUPART_FRAGMENT, "fragment", 0);
  showpart(u, CURLUPART_FRAGMENT, "fragment with get empty",
           CURLU_GET_EMPTY);
  showpart(u, CURLUPART_URL, "url", 0);
  showpart(u, CURLUPART_URL, "url with get empty", CURLU_GET_EMPTY);
  curl_url_cleanup(u);
}

/*
 * 7. Scheme guessing, and the three flags that steer it.
 *
 * CURLU_GUESS_SCHEME accepts a URL with no scheme and picks one from the
 * hostname prefix using the six-entry table at lib/urlapi.c:989-1003, so
 * ftp. yields ftp and imap. yields imap; anything unrecognised yields http.
 * A scheme arrived at that way is marked as guessed, which is what
 * CURLU_NO_GUESS_SCHEME then reacts to on retrieval: the scheme part reports
 * that there is no scheme (lib/urlapi.c:1559-1560) and the URL part omits
 * the scheme prefix (lib/urlapi.c:1512-1515) while still returning success.
 *
 * CURLU_DEFAULT_SCHEME behaves differently in a way worth showing rather
 * than assuming. It substitutes https during parsing, at
 * lib/urlapi.c:1015-1016, and never reaches the guessing routine at all --
 * which is the only place the guessed marker is ever set. The scheme it
 * produces is therefore NOT marked as guessed, so CURLU_NO_GUESS_SCHEME has
 * nothing to suppress. When both flags are given the default wins, for the
 * same reason: the substitution happens first.
 *
 * Every vector below gets a handle of its own, and that is a correctness
 * requirement rather than tidiness. A scheme-less string is not an absolute
 * URL, so assigning one to a handle that already holds a complete URL sends
 * it down the relative-resolution path of lib/urlapi.c:1717-1725 and appends
 * it to the existing path instead of re-parsing it. Guessing is only reached
 * when the handle cannot yield an absolute URL of its own, which for these
 * vectors means a fresh handle each time.
 */
static void guessing(void)
{
  CURLU *u;

  header("7. scheme guessing");
  u = curl_url();
  if(!u)
    return;
  setpart(u, CURLUPART_URL, "ftp.example.com/pub", "set ftp host guessed",
          CURLU_GUESS_SCHEME);
  showpart(u, CURLUPART_SCHEME, "guessed scheme", 0);
  showpart(u, CURLUPART_SCHEME, "guessed scheme with no guess",
           CURLU_NO_GUESS_SCHEME);
  showpart(u, CURLUPART_URL, "guessed url", 0);
  showpart(u, CURLUPART_URL, "guessed url with no guess",
           CURLU_NO_GUESS_SCHEME);
  curl_url_cleanup(u);

  u = curl_url();
  if(!u)
    return;
  setpart(u, CURLUPART_URL, "imap.example.com/INBOX",
          "set imap host guessed", CURLU_GUESS_SCHEME);
  showpart(u, CURLUPART_SCHEME, "imap guessed scheme", 0);
  showpart(u, CURLUPART_URL, "imap guessed url", 0);
  curl_url_cleanup(u);

  u = curl_url();
  if(!u)
    return;
  setpart(u, CURLUPART_URL, "www.example.com/x", "set plain host guessed",
          CURLU_GUESS_SCHEME);
  showpart(u, CURLUPART_SCHEME, "plain guessed scheme", 0);
  showpart(u, CURLUPART_URL, "plain guessed url", 0);
  curl_url_cleanup(u);

  u = curl_url();
  if(!u)
    return;
  setpart(u, CURLUPART_URL, "example.com/x", "set host default scheme",
          CURLU_DEFAULT_SCHEME);
  showpart(u, CURLUPART_SCHEME, "default scheme", 0);
  showpart(u, CURLUPART_SCHEME, "default scheme with no guess",
           CURLU_NO_GUESS_SCHEME);
  showpart(u, CURLUPART_URL, "default scheme url", 0);
  note("CURLU_DEFAULT_SCHEME substitutes before guessing and so is never "
       "marked as guessed");
  curl_url_cleanup(u);

  u = curl_url();
  if(!u)
    return;
  setpart(u, CURLUPART_URL, "ftp.example.com/p", "set host guess and default",
          CURLU_GUESS_SCHEME | CURLU_DEFAULT_SCHEME);
  showpart(u, CURLUPART_SCHEME, "combined scheme", 0);
  showpart(u, CURLUPART_SCHEME, "combined scheme with no guess",
           CURLU_NO_GUESS_SCHEME);
  showpart(u, CURLUPART_URL, "combined url", 0);
  note("with both flags the default wins and the ftp prefix is not consulted");
  curl_url_cleanup(u);

  u = curl_url();
  if(!u)
    return;
  setpart(u, CURLUPART_URL, "example.com/x", "set host with no flags", 0);
  curl_url_cleanup(u);
}

/*
 * 8. curl_url_dup(), and finding FB1 reproduced on purpose.
 *
 * curl_url_dup() at lib/urlapi.c:1310-1332 copies the ten heap strings and
 * three of the four remaining fields -- the numeric port, and the two flags
 * recording that an empty query or an empty fragment was present -- but not
 * the fourth, the marker saying the scheme was guessed rather than parsed.
 *
 * That omission is observable, and this section observes it: asked with
 * CURLU_NO_GUESS_SCHEME, the original reports no scheme and serialises
 * without a scheme prefix, while its copy answers with the guessed scheme and
 * serialises with the prefix. The two handles disagree about a URL they are
 * supposed to represent identically.
 *
 * It is reproduced rather than repaired, per the porting rule that anything
 * resembling a defect in the original is to be carried across faithfully and
 * recorded. ../docs/KNOWN-DIVERGENCES.md catalogues it as FB1. Worth knowing
 * why it survives upstream: the duplication sub-test in
 * ../../tests/libtest/lib1560.c does include a scheme-less input parsed with
 * the guess flag, but it compares original against copy using flags of zero
 * and so never asks the one question that would expose the difference.
 *
 * The second half of the section duplicates an ordinary, fully parsed handle
 * and confirms that original and copy serialise identically, which is what
 * makes the first half a specific finding rather than a general failure.
 *
 * MEMORY OWNERSHIP: curl_url_dup() returns a new handle that must itself be
 * released with curl_url_cleanup(), exactly like the one from curl_url()
 * (include/curl/urlapi.h:122-125). Both copies below are cleaned up.
 */
static void duplication(void)
{
  CURLU *u = curl_url();
  CURLU *copy;

  header("8. duplication and faithful bug FB1");
  if(!u)
    return;
  setpart(u, CURLUPART_URL, "ftp.example.com/pub", "set ftp host guessed",
          CURLU_GUESS_SCHEME);
  copy = curl_url_dup(u);
  if(copy) {
    showpart(u, CURLUPART_SCHEME, "original scheme with no guess",
             CURLU_NO_GUESS_SCHEME);
    showpart(copy, CURLUPART_SCHEME, "duplicate scheme with no guess",
             CURLU_NO_GUESS_SCHEME);
    showpart(u, CURLUPART_URL, "original url with no guess",
             CURLU_NO_GUESS_SCHEME);
    showpart(copy, CURLUPART_URL, "duplicate url with no guess",
             CURLU_NO_GUESS_SCHEME);
    curl_url_cleanup(copy);
  }
  note("FB1 reproduced on purpose: curl_url_dup does not copy the "
       "guessed-scheme marker");
  setpart(u, CURLUPART_URL, "https://user@example.com:8080/p?q=1#f",
          "set full url", 0);
  copy = curl_url_dup(u);
  if(copy) {
    showpart(u, CURLUPART_URL, "original full url", 0);
    showpart(copy, CURLUPART_URL, "duplicate full url", 0);
    curl_url_cleanup(copy);
  }
  curl_url_cleanup(u);
}

/*
 * 9. CURLU_PUNYCODE, on a host that is already in punycode form.
 *
 * WHAT IS DELIBERATELY NOT EXERCISED HERE, AND WHY
 *
 * CURLU_PUNY2IDN and non-ASCII host input are both out of scope for this
 * program, and that is a decision rather than an oversight.
 *
 * The C implementation reaches libidn2 through a locale-aware lookup, so
 * converting a non-ASCII hostname succeeds only when the process codeset is
 * UTF-8 and fails with a bad-hostname code otherwise. ../scripts/run-parity.sh
 * runs this program under both LC_ALL=C.UTF-8 and LC_ALL=C, because behaving
 * identically in both is itself an acceptance criterion, and a single
 * committed golden file cannot match two different outcomes. A vector that
 * fed a non-ASCII host in would pass locally under a UTF-8 locale and then
 * break the moment the parity script re-ran under LC_ALL=C.
 *
 * Internationalised-domain coverage belongs to the other oracle, the
 * ../harness/ build of ../../tests/libtest/lib1560.c, which gates exactly
 * those assertions on the CURL_TEST_HAVE_CODESET_UTF8 environment variable
 * for precisely this reason.
 *
 * What remains is still worth showing. Because the host below is already
 * ASCII, the punycode branch at lib/urlapi.c:1497-1503 is a no-op: it asks
 * whether the host needs converting, finds that it does not, and leaves it
 * alone. No IDN library is called and no locale is consulted, so the three
 * retrievals are stable everywhere -- while still proving that the flag is
 * accepted, plumbed through both the part path and the whole-URL path, and
 * correctly decides to do nothing.
 */
static void punycode_flag(void)
{
  CURLU *u = curl_url();

  header("9. punycode flag on an ASCII host");
  if(!u)
    return;
  setpart(u, CURLUPART_URL, "https://xn--rksmrgs-5wao1o.se/p",
          "set punycode host", 0);
  showpart(u, CURLUPART_HOST, "host", 0);
  showpart(u, CURLUPART_HOST, "host with punycode", CURLU_PUNYCODE);
  showpart(u, CURLUPART_URL, "url with punycode", CURLU_PUNYCODE);
  note("already-ASCII host, so the punycode branch converts nothing and no "
       "locale is involved");
  curl_url_cleanup(u);
}

/*
 * 10. IPv6 literals, the zone identifier, and IPv4 normalisation.
 *
 * A bracketed IPv6 host is returned with its brackets, as
 * ../../docs/libcurl/curl_url_get.md:179 documents, and the brackets are
 * stored rather than reconstructed.
 *
 * The zone identifier is a part of its own. In a URL it is introduced by a
 * percent sign, which has to arrive percent-encoded as %25, and whole-URL
 * serialisation puts it back in that same encoded form -- but only for a
 * bracketed host, because that is the only case lib/urlapi.c:1480-1491
 * handles. The second handle shows the identifier being assigned directly to
 * a host that was parsed without one.
 *
 * IPv4 normalisation rewrites the legacy numeric forms into dotted quads
 * during parsing, so the host that comes back is not the host that went in.
 * Both a two-part form with a hexadecimal leading octet and a two-part form
 * with a hexadecimal remainder are shown, since the arity decides how the
 * remaining bits are distributed.
 */
static void addresses(void)
{
  CURLU *u = curl_url();
  CURLU *z;

  header("10. ipv6, zone identifier and ipv4 normalisation");
  if(!u)
    return;
  setpart(u, CURLUPART_URL, "https://[2001:db8::1]:8443/p?q=1",
          "set ipv6 url", 0);
  showpart(u, CURLUPART_HOST, "ipv6 host", 0);
  showpart(u, CURLUPART_PORT, "ipv6 port", 0);
  showpart(u, CURLUPART_URL, "ipv6 url", 0);
  setpart(u, CURLUPART_URL, "http://[fe80::1%25eth0]:8080/p",
          "set ipv6 zone url", 0);
  showpart(u, CURLUPART_HOST, "zoned host", 0);
  showpart(u, CURLUPART_ZONEID, "zone identifier", 0);
  showpart(u, CURLUPART_URL, "zoned url", 0);
  setpart(u, CURLUPART_URL, "http://0x7f.1/p", "set ipv4 hex leading", 0);
  showpart(u, CURLUPART_HOST, "ipv4 hex leading host", 0);
  showpart(u, CURLUPART_URL, "ipv4 hex leading url", 0);
  setpart(u, CURLUPART_URL, "http://192.0x00A80001/p",
          "set ipv4 hex trailing", 0);
  showpart(u, CURLUPART_HOST, "ipv4 hex trailing host", 0);
  curl_url_cleanup(u);

  z = curl_url();
  if(!z)
    return;
  setpart(z, CURLUPART_URL, "http://[fe80::20c:29ff:fe9c:409b]/p",
          "set plain ipv6 url", 0);
  showpart(z, CURLUPART_ZONEID, "zone before assignment", 0);
  setpart(z, CURLUPART_ZONEID, "eth0", "assign zone identifier", 0);
  showpart(z, CURLUPART_ZONEID, "zone after assignment", 0);
  showpart(z, CURLUPART_URL, "url after zone assignment", 0);
  curl_url_cleanup(z);
}

/*
 * 11. Error paths, the two null preconditions, clearing a part, and
 *     curl_url_strerror() at both ends of its range.
 *
 * Every one of these is reported and the transcript continues. Reporting the
 * code IS the parity signal here, so bailing out on a failure would throw
 * away the very information the diff exists to compare.
 *
 * MEMORY OWNERSHIP: curl_url_cleanup(NULL) is documented to return at once
 * having done nothing (../../docs/libcurl/curl_url_cleanup.md), which the
 * call below relies on. curl_url_strerror() returns a pointer into static
 * storage and must never be freed.
 */
static void error_paths(void)
{
  CURLU *u = curl_url();
  CURLU *w;
  CURLUcode uc;

  header("11. error paths, null preconditions and error strings");
  /* The null handle is rejected at lib/urlapi.c:1548-1549 and the null part
     pointer immediately after, at 1550-1551. Neither return has written
     anything through the part pointer by then -- the *part = NULL at line
     1552 comes later -- which is exactly why showpart() initialises its own
     pointer rather than trusting the callee to, and why neither branch frees
     anything. */
  showpart(NULL, CURLUPART_URL, "get with null handle", 0);
  if(!u)
    return;
  uc = curl_url_get(u, CURLUPART_URL, NULL, 0);
  printf("get with null part pointer: rc=%d (%s)\n", (int)uc,
         curl_url_strerror(uc));
  setpart(NULL, CURLUPART_URL, "https://example.com/",
          "set with null handle", 0);
  setpart(u, CURLUPART_URL, "https://example.com/", "set base url", 0);
  setpart(u, CURLUPART_PORT, "99999", "set port out of range", 0);
  setpart(u, CURLUPART_PORT, "80x", "set port with trailing junk", 0);
  setpart(u, CURLUPART_SCHEME, "custom", "set unsupported scheme", 0);
  setpart(u, CURLUPART_SCHEME, "custom", "set scheme allowing unsupported",
          CURLU_NON_SUPPORT_SCHEME);
  showpart(u, CURLUPART_SCHEME, "scheme after set", 0);
  setpart(u, CURLUPART_URL, "https://user:secret@example.com/",
          "set url disallowing user", CURLU_DISALLOW_USER);
  setpart(u, CURLUPART_FRAGMENT, "f", "set fragment", 0);
  showpart(u, CURLUPART_FRAGMENT, "fragment before clear", 0);
  /* Passing NULL as the value clears the part rather than assigning to it;
     the dispatch is at lib/urlapi.c:1732-1777. */
  setpart(u, CURLUPART_FRAGMENT, NULL, "clear fragment", 0);
  showpart(u, CURLUPART_FRAGMENT, "fragment after clear", 0);
  curl_url_cleanup(u);

  w = curl_url();
  if(!w)
    return;
  setpart(w, CURLUPART_URL, "https://example.com/a b/c?q=1 2",
          "set url with space", 0);
  setpart(w, CURLUPART_URL, "https://example.com/a b/c?q=1 2",
          "set url with space allowed", CURLU_ALLOW_SPACE);
  showpart(w, CURLUPART_PATH, "path with space", 0);
  showpart(w, CURLUPART_QUERY, "query with space", 0);
  showpart(w, CURLUPART_URL, "url with space", 0);
  curl_url_cleanup(w);

  curl_url_cleanup(NULL);
  printf("cleanup of null handle: [returned]\n");
  printf("strerror of CURLUE_OK: [%s]\n", curl_url_strerror(CURLUE_OK));
  /* CURLUE_LAST is a sentinel with no message of its own: the verbose
     implementation breaks out of its switch at lib/strerror.c:518-519 and
     falls through to the catch-all below it. These golden bytes therefore
     assume the verbose variant, which is what lib/curl_setup.h:1595-1597
     selects unless verbose strings were explicitly disabled. */
  printf("strerror of CURLUE_LAST: [%s]\n", curl_url_strerror(CURLUE_LAST));
  note("CURLUE_LAST has no message of its own and reaches the catch-all");
}

/*
 * 12. Setting the whole URL to the empty string, and the flag sensitivity
 *     that comes with it.
 *
 * An empty string is a valid relative URL that changes nothing. The
 * implementation decides that at lib/urlapi.c:1697-1710 by asking the handle
 * for its own whole URL: if that succeeds the empty assignment is a no-op and
 * returns success, an allocation failure is propagated as itself, and any
 * other failure becomes a malformed-input error.
 *
 * The consequence is that the caller's flags are passed straight into that
 * internal retrieval, so whether an empty assignment succeeds depends on
 * flags that appear to have nothing to do with it. The second handle below is
 * the demonstration: it has a host but no scheme, so the internal retrieval
 * fails with a no-scheme code and the empty assignment is rejected -- yet the
 * identical call with CURLU_DEFAULT_SCHEME succeeds, because that flag lets
 * the retrieval substitute a scheme and return successfully.
 *
 * ONE COMBINATION IS DELIBERATELY NOT DEMONSTRATED HERE, and this is the
 * place to say why, because its absence would otherwise look like an
 * oversight. An empty assignment carrying CURLU_NO_GUESS_SCHEME on a handle
 * whose scheme was GUESSED is the port's one intentional behavioural
 * divergence from lib/urlapi.c: the plan requires a malformed-input error
 * there, while the reference returns success, because that flag only blanks
 * the scheme prefix on the whole-URL path (lib/urlapi.c:1512-1515) and the
 * guard that turns it into a no-scheme code belongs to the scheme PART path
 * (lib/urlapi.c:1559-1560). This program's whole purpose is that its output be
 * byte-identical to the same program linked against the unmodified C, so it
 * exercises only what the two agree on. The divergence, its measurements and
 * its bounds are recorded in ../docs/KNOWN-DIVERGENCES.md under "The
 * empty-string rule and its hidden flag sensitivity".
 *
 * What the third handle below does show is the half that is common ground: on
 * a guessed-scheme handle, an empty assignment with NO flags is a successful
 * no-op, and CURLU_NO_GUESS_SCHEME still suppresses the scheme prefix on
 * RETRIEVAL exactly as it does in the reference. Both are transcribed from the
 * reference implementation rather than predicted from it.
 */
static void empty_url_rule(void)
{
  CURLU *u = curl_url();
  CURLU *h;
  CURLU *g;

  header("12. the empty url rule and its flag sensitivity");
  if(!u)
    return;
  setpart(u, CURLUPART_URL, "https://user@example.com:8080/p?q=1#f",
          "set full url", 0);
  setpart(u, CURLUPART_URL, "", "set url to empty string", 0);
  showpart(u, CURLUPART_URL, "url after empty assignment", 0);
  note("an empty relative url on a complete handle is a successful no-op");
  curl_url_cleanup(u);

  h = curl_url();
  if(!h)
    return;
  setpart(h, CURLUPART_HOST, "example.com", "set host only", 0);
  showpart(h, CURLUPART_URL, "url of host-only handle", 0);
  setpart(h, CURLUPART_URL, "", "set empty with no flags", 0);
  setpart(h, CURLUPART_URL, "", "set empty with default scheme",
          CURLU_DEFAULT_SCHEME);
  showpart(h, CURLUPART_URL, "url with default scheme",
           CURLU_DEFAULT_SCHEME);
  note("the empty assignment forwards the caller flags into an internal "
       "url retrieval");
  curl_url_cleanup(h);

  g = curl_url();
  if(!g)
    return;
  setpart(g, CURLUPART_URL, "ftp.example.com/pub", "set guessed host",
          CURLU_GUESS_SCHEME);
  showpart(g, CURLUPART_URL, "guessed url, no guess scheme",
           CURLU_NO_GUESS_SCHEME);
  setpart(g, CURLUPART_URL, "", "set empty with no flags", 0);
  showpart(g, CURLUPART_URL, "guessed url after empty assignment", 0);
  note("on retrieval CURLU_NO_GUESS_SCHEME blanks the scheme prefix without "
       "failing, and an empty assignment with no flags stays a no-op");
  curl_url_cleanup(g);
}

/*
 * 13. CURLU_PATH_AS_IS.
 *
 * Dot-segment removal happens once, while parsing, so the flag has to be
 * given to the assignment that parses the URL rather than to the retrieval
 * that reads the path back. Without it, . and .. segments are resolved and
 * the path that comes back is shorter than the path that went in; with it,
 * every byte is preserved.
 *
 * The percent-encoded spellings %2e and %2E count as dot segments too and
 * are removed along with the literal ones, which the second vector shows. A
 * %2f inside a final segment is not a separator, so a trailing ..%2fd is not
 * a dot segment at all and survives normalisation.
 */
static void path_as_is(void)
{
  CURLU *u = curl_url();
  CURLU *v;

  header("13. path as is");
  if(!u)
    return;
  setpart(u, CURLUPART_URL, "https://example.com/a/./b/../c/..%2fd",
          "set url with dot segments", 0);
  showpart(u, CURLUPART_PATH, "path normalised", 0);
  setpart(u, CURLUPART_URL, "https://example.com/a/%2e%2e/b/%2e/c",
          "set url with encoded dots", 0);
  showpart(u, CURLUPART_PATH, "path with encoded dots removed", 0);
  curl_url_cleanup(u);

  v = curl_url();
  if(!v)
    return;
  setpart(v, CURLUPART_URL, "https://example.com/a/./b/../c/..%2fd",
          "set same url as is", CURLU_PATH_AS_IS);
  showpart(v, CURLUPART_PATH, "path as is", 0);
  curl_url_cleanup(v);
}

/*
 * 14. The file scheme, and CURLU_NO_AUTHORITY.
 *
 * A file URL has no authority to speak of, so the host part reports that
 * there is none while serialisation still emits the three slashes: the file
 * branch at lib/urlapi.c:1441-1447 formats the path directly and never
 * consults a host at all.
 *
 * CURLU_NO_AUTHORITY relaxes the rule that a host must be non-empty, but only
 * for a scheme the library does not know, so the two flags are needed
 * together. The final vector drops the flag to show what the same URL does
 * without it.
 */
static void file_and_no_authority(void)
{
  CURLU *u = curl_url();
  CURLU *c;

  header("14. file scheme and no authority");
  if(!u)
    return;
  setpart(u, CURLUPART_URL, "file:///tmp/dir/file.txt", "set file url", 0);
  showpart(u, CURLUPART_SCHEME, "file scheme", 0);
  showpart(u, CURLUPART_HOST, "file host", 0);
  showpart(u, CURLUPART_PATH, "file path", 0);
  showpart(u, CURLUPART_URL, "file url", 0);
  curl_url_cleanup(u);

  c = curl_url();
  if(!c)
    return;
  setpart(c, CURLUPART_URL, "custom-x://", "set custom scheme no authority",
          CURLU_NON_SUPPORT_SCHEME | CURLU_NO_AUTHORITY);
  showpart(c, CURLUPART_SCHEME, "custom scheme", 0);
  showpart(c, CURLUPART_HOST, "custom host", 0);
  showpart(c, CURLUPART_PATH, "custom path", 0);
  showpart(c, CURLUPART_URL, "custom url", 0);
  setpart(c, CURLUPART_URL, "custom-x://", "set custom scheme with authority",
          CURLU_NON_SUPPORT_SCHEME);
  curl_url_cleanup(c);
}

int main(void)
{
  /*
   * The first three lines carry this program's own licence annotation into
   * its output, and that is deliberate rather than incidental.
   *
   * expected-output.txt is a tracked file and the licence linter covers it,
   * yet it cannot carry an inline annotation of its own: any header text
   * added to it would corrupt the very bytes it exists to assert. Two routes
   * out of that were available. This one was taken -- the program prints the
   * annotation, so the golden file legitimately contains it, which is what
   * ../../REUSE.toml:4-6 asks for when it says a file should be annotated
   * directly wherever it can be. The alternative, an
   * expected-output.txt.license sidecar, was rejected because the repository
   * tracks no such file anywhere and adopting one here would be a first;
   * adding an entry to ../../REUSE.toml was not available at all, that file
   * being out of scope.
   *
   * The banner is unconditional in both link modes. Were it conditional the
   * two modes' output would differ and the parity comparison, whose whole
   * premise is that they do not, would fail.
   *
   * The markers around the three calls are required, not stylistic. The
   * licence linter scans for the annotation tag anywhere in a file, so
   * without them it reads the third string literal as a second annotation
   * OF THIS SOURCE FILE and rejects the trailing escape and punctuation as
   * an unparsable licence expression -- measured, not assumed. The markers
   * are the mechanism the tool itself prescribes for a tag that is data
   * rather than metadata. This file's own annotation remains the one in the
   * header box above, at line 21, which sits well before the ignored range.
   */
  /* REUSE-IgnoreStart */
  printf("curl URL API parity demonstration\n");
  printf("Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.\n");
  printf("SPDX-License-Identifier: curl\n");
  /* REUSE-IgnoreEnd */

  full_parse();
  path_and_relative();
  ports();
  encode_decode();
  append_query();
  get_empty();
  guessing();
  duplication();
  punycode_flag();
  addresses();
  error_paths();
  empty_url_rule();
  path_as_is();
  file_and_no_authority();

  return 0;
}
