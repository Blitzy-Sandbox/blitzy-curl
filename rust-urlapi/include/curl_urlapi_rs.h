#ifndef CURLINC_URLAPI_RS_H
#define CURLINC_URLAPI_RS_H
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

/*
 * A one-for-one mirror of the public declarations in
 * include/curl/urlapi.h:34-149, provided for the standalone link mode, in
 * which no libcurl takes part and the real header is therefore not on the
 * include path. Everything from the CURLUcode enumeration down is
 * transcribed from that file verbatim, cosmetic details included, because a
 * mirror that improves on its original is no longer a mirror.
 *
 * This header neither shadows the real one nor can be shadowed by it: the
 * file name, the directory and the include guard opened above all differ
 * deliberately, so a shared guard can never make one of the two silently
 * vanish. Each link mode uses exactly one of them, and that is the
 * supported arrangement -- a translation unit including both is rejected,
 * because the two would declare the same enumerators and typedefs twice.
 * The CURL_EXTERN block below is guarded all the same, so that the macro
 * at least cannot collide in either include order.
 *
 * WHY THIS FILE HAS NO INCLUDE DIRECTIVE AT ALL
 *
 * include/curl/urlapi.h:27 includes "curl.h", and that is the only reason
 * it does so: "curl.h" is where it obtains CURL_EXTERN, the linkage
 * decoration its six declarations carry. That line is deliberately not
 * reproduced. A standalone link contains no libcurl, and drawing in the
 * whole of "curl.h" to obtain one macro would defeat the purpose of a
 * self-contained mirror. The decoration is resolved locally instead, by the
 * block below, which is guarded by ifndef so that a translation unit
 * including both this mirror and the real "curl.h" cannot redefine it, in
 * either include order.
 *
 * Nothing further is required. The six declarations close over CURLU,
 * CURLUcode, CURLUPart, char, void, unsigned int and const char * alone --
 * there is no size_t, no curl_off_t and no CURL anywhere in the surface --
 * so this file needs no header of its own and includes none.
 *
 * WHAT IS DELIBERATELY ABSENT
 *
 * curl_free() belongs to include/curl/curl.h:2735, not to urlapi.h, which
 * refers to it only in the prose below at its lines 130-131. A one-for-one
 * mirror therefore does not declare it, and a standalone consumer needing
 * it must obtain that prototype elsewhere.
 *
 * The three entry points declared at lib/urlapi-int.h:28-33, and the
 * unit-test-only one at lines 36-37, are exported by the object file this
 * crate replaces, yet they form no part of the public contract, so they are
 * absent here as well.
 *
 * curl_url_strerror() is declared below with an unnamed parameter, exactly
 * as at include/curl/urlapi.h:149, even though its manual page names one.
 * The omission is reproduced on purpose and must not be repaired;
 * ../docs/KNOWN-DIVERGENCES.md records it as finding FB5.
 */

#ifndef CURL_EXTERN
#ifdef CURL_STATICLIB
#define CURL_EXTERN
#elif defined(_WIN32)
#ifdef BUILDING_LIBCURL
#define CURL_EXTERN __declspec(dllexport)
#else
#define CURL_EXTERN __declspec(dllimport)
#endif
#else
#define CURL_EXTERN
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* the error codes for the URL API */
typedef enum {
  CURLUE_OK,
  CURLUE_BAD_HANDLE,          /* 1 */
  CURLUE_BAD_PARTPOINTER,     /* 2 */
  CURLUE_MALFORMED_INPUT,     /* 3 */
  CURLUE_BAD_PORT_NUMBER,     /* 4 */
  CURLUE_UNSUPPORTED_SCHEME,  /* 5 */
  CURLUE_URLDECODE,           /* 6 */
  CURLUE_OUT_OF_MEMORY,       /* 7 */
  CURLUE_USER_NOT_ALLOWED,    /* 8 */
  CURLUE_UNKNOWN_PART,        /* 9 */
  CURLUE_NO_SCHEME,           /* 10 */
  CURLUE_NO_USER,             /* 11 */
  CURLUE_NO_PASSWORD,         /* 12 */
  CURLUE_NO_OPTIONS,          /* 13 */
  CURLUE_NO_HOST,             /* 14 */
  CURLUE_NO_PORT,             /* 15 */
  CURLUE_NO_QUERY,            /* 16 */
  CURLUE_NO_FRAGMENT,         /* 17 */
  CURLUE_NO_ZONEID,           /* 18 */
  CURLUE_BAD_FILE_URL,        /* 19 */
  CURLUE_BAD_FRAGMENT,        /* 20 */
  CURLUE_BAD_HOSTNAME,        /* 21 */
  CURLUE_BAD_IPV6,            /* 22 */
  CURLUE_BAD_LOGIN,           /* 23 */
  CURLUE_BAD_PASSWORD,        /* 24 */
  CURLUE_BAD_PATH,            /* 25 */
  CURLUE_BAD_QUERY,           /* 26 */
  CURLUE_BAD_SCHEME,          /* 27 */
  CURLUE_BAD_SLASHES,         /* 28 */
  CURLUE_BAD_USER,            /* 29 */
  CURLUE_LACKS_IDN,           /* 30 */
  CURLUE_TOO_LARGE,           /* 31 */
  CURLUE_LAST
} CURLUcode;

typedef enum {
  CURLUPART_URL,
  CURLUPART_SCHEME,
  CURLUPART_USER,
  CURLUPART_PASSWORD,
  CURLUPART_OPTIONS,
  CURLUPART_HOST,
  CURLUPART_PORT,
  CURLUPART_PATH,
  CURLUPART_QUERY,
  CURLUPART_FRAGMENT,
  CURLUPART_ZONEID /* added in 7.65.0 */
} CURLUPart;

#define CURLU_DEFAULT_PORT (1 << 0)       /* return default port number */
#define CURLU_NO_DEFAULT_PORT (1 << 1)    /* act as if no port number was set,
                                             if the port number matches the
                                             default for the scheme */
#define CURLU_DEFAULT_SCHEME (1 << 2)     /* return default scheme if
                                             missing */
#define CURLU_NON_SUPPORT_SCHEME (1 << 3) /* allow non-supported scheme */
#define CURLU_PATH_AS_IS (1 << 4)         /* leave dot sequences */
#define CURLU_DISALLOW_USER (1 << 5)      /* no user+password allowed */
#define CURLU_URLDECODE (1 << 6)          /* URL decode on get */
#define CURLU_URLENCODE (1 << 7)          /* URL encode on set */
#define CURLU_APPENDQUERY (1 << 8)        /* append a form style part */
#define CURLU_GUESS_SCHEME (1 << 9)       /* legacy curl-style guessing */
#define CURLU_NO_AUTHORITY (1 << 10)      /* Allow empty authority when the
                                             scheme is unknown. */
#define CURLU_ALLOW_SPACE (1 << 11)       /* Allow spaces in the URL */
#define CURLU_PUNYCODE (1 << 12)          /* get the hostname in punycode */
#define CURLU_PUNY2IDN (1 << 13)          /* punycode => IDN conversion */
#define CURLU_GET_EMPTY (1 << 14)         /* allow empty queries and fragments
                                             when extracting the URL or the
                                             components */
#define CURLU_NO_GUESS_SCHEME (1 << 15)   /* for get, do not accept a guess */

typedef struct Curl_URL CURLU;

/*
 * curl_url() creates a new CURLU handle and returns a pointer to it.
 * Must be freed with curl_url_cleanup().
 */
CURL_EXTERN CURLU *curl_url(void);

/*
 * curl_url_cleanup() frees the CURLU handle and related resources used for
 * the URL parsing. It will not free strings previously returned with the URL
 * API.
 */
CURL_EXTERN void curl_url_cleanup(CURLU *handle);

/*
 * curl_url_dup() duplicates a CURLU handle and returns a new copy. The new
 * handle must also be freed with curl_url_cleanup().
 */
CURL_EXTERN CURLU *curl_url_dup(const CURLU *in);

/*
 * curl_url_get() extracts a specific part of the URL from a CURLU
 * handle. Returns error code. The returned pointer MUST be freed with
 * curl_free() afterwards.
 */
CURL_EXTERN CURLUcode curl_url_get(const CURLU *handle, CURLUPart what,
                                   char **part, unsigned int flags);

/*
 * curl_url_set() sets a specific part of the URL in a CURLU handle. Returns
 * error code. The passed in string will be copied. Passing a NULL instead of
 * a part string, clears that part.
 */
CURL_EXTERN CURLUcode curl_url_set(CURLU *handle, CURLUPart what,
                                   const char *part, unsigned int flags);

/*
 * curl_url_strerror() turns a CURLUcode value into the equivalent human
 * readable error string. This is useful for printing meaningful error
 * messages.
 */
CURL_EXTERN const char *curl_url_strerror(CURLUcode);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* CURLINC_URLAPI_RS_H */
