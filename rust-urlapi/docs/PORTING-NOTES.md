<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Porting notes

`lib/urlapi.c` is a single C translation unit of 1,998 lines. The
`curl-urlapi-rs` port spreads the same behavior across 26 Rust modules.
This document is the map between the two. A reviewer checking a Rust module
against the C it came from finds the line numbers here instead of
re-deriving the correspondence, and a reader asking which module owns a
given piece of C behavior finds the answer here as well.

Completeness is the point. A map that leaves a region of the C file
unattributed sends a reader hunting through the wrong module, so the two
places where the fixed plan and the source disagree are recorded below
rather than quietly smoothed over.

Build steps, the feature table, prerequisites and script ordering are
deliberately absent. They belong to `../README.md`, which is the short
entry point to the same material. This file is the long one.

## Reading this document

Every claim about the existing C code carries a path and a line number.
Line numbers refer to the tree this file lives in, at
`LIBCURL_VERSION "8.19.0-DEV"`. A citation that fails to resolve is a
defect in this file rather than a blemish: the document is almost entirely
citations, and one bad citation teaches a reader to distrust the rest.

Two conventions keep the tables and the prose narrow.

- A bare `Lnnn` refers to the file most recently named in the same
  sentence, list item, table row or section heading, and to `lib/urlapi.c`
  when no other file is named. Numbers above L1998 are never
  `lib/urlapi.c`, which ends there, and every one of them sits in a passage
  that names its own file.
- Paths beginning `src/`, `tests/`, `harness/`, `demo/` or `include/` with
  no repository directory in front of them are relative to `rust-urlapi/`.
  Every other path is relative to the repository root.

No user rules were supplied for this work, so no rule is cited anywhere
below. The standard applied instead is the enterprise-standard best
practice baseline the Agent Action Plan sets out at 0.7.2: an inline SPDX
header, prose that passes the repository gates, read-only treatment of
every file cited here, and a citation on every factual claim.

## The C translation unit, re-counted

The Agent Action Plan describes `lib/urlapi.c` as holding "39 functions and
macros". That phrase covers two different populations, and the function
count on its own is 38. The inventory below was re-derived from the source
rather than copied forward, and it was checked two ways that share no
failure mode.

The first way scans for signatures:

    grep -nE '^(static |UNITTEST |size_t |void |CURLU |CURLUcode |const char )' \
      lib/urlapi.c | grep -vE ';$'

That reports 39 matching lines and 38 after the trailing-semicolon filter.
The line the filter drops is L715, a forward declaration:

    UNITTEST int dedotdotify(const char *input, size_t clen, char **outp);

L716 then defines the same function. One declaration plus one definition of
`dedotdotify` accounts for the extra entry exactly.

The second way ignores signatures and counts opening braces in column
zero, each of which starts a function body. That also reports 38. Two
independent methods agreeing on 38 is the basis for using that figure here.

### The 38 function definitions

The third column names the Rust module that absorbs each function, so the
inventory and the module map in the next section can be checked against
each other without cross-referencing by hand. Two entries name two modules
because the C function splits into an exported entry point and the logic
behind it; both are explained under the module map.

| Line | Function | Rust module |
|---|---|---|
| L86 | `free_urlhandle` | `src/handle.rs` |
| L104 | `find_host_sep` | `src/encode.rs` |
| L130 | `urlencode_str` | `src/encode.rs` |
| L182 | `Curl_is_absolute_url` | `src/parse/scheme.rs` |
| L223 | `Curl_junkscan` | `src/parse/junk.rs` |
| L248 | `parse_hostname_login` | `src/parse/authority.rs` |
| L335 | `Curl_parse_port` | `src/parse/port.rs` |
| L390 | `ipv6_parse` | `src/parse/ipv6.rs` |
| L444 | `hostname_check` | `src/parse/host.rs` |
| L483 | `ipv4_normalize` | `src/parse/host.rs` |
| L578 | `urldecode_host` | `src/parse/host.rs` |
| L604 | `parse_authority` | `src/parse/authority.rs` |
| L658 | `Curl_url_set_authority` | `src/parse/authority.rs` |
| L682 | `is_dot` | `src/parse/path.rs` |
| L716 | `dedotdotify` | `src/parse/path.rs` |
| L823 | `parse_file` | `src/parse/file.rs` |
| L935 | `parse_scheme` | `src/parse/scheme.rs` |
| L984 | `guess_scheme` | `src/parse/scheme.rs` |
| L1012 | `handle_fragment` | `src/parse/query.rs` |
| L1036 | `handle_query` | `src/parse/query.rs` |
| L1066 | `handle_path` | `src/parse/path.rs` |
| L1110 | `parseurl` | `src/parse/mod.rs` |
| L1197 | `parseurl_and_replace` | `src/parse/mod.rs` |
| L1214 | `redirect_url` | `src/parse/redirect.rs` |
| L1288 | `curl_url` | `src/ffi.rs` |
| L1293 | `curl_url_cleanup` | `src/ffi.rs` |
| L1310 | `curl_url_dup` | `src/ffi.rs`, `src/handle.rs` |
| L1338 | `host_decode` | `src/idn.rs` |
| L1347 | `host_encode` | `src/idn.rs` |
| L1357 | `urlget_format` | `src/getset.rs` |
| L1425 | `urlget_url` | `src/getset.rs` |
| L1541 | `curl_url_get` | `src/ffi.rs` |
| L1636 | `set_url_scheme` | `src/getset.rs` |
| L1666 | `set_url_port` | `src/getset.rs` |
| L1685 | `set_url` | `src/getset.rs` |
| L1732 | `urlset_clear` | `src/getset.rs` |
| L1779 | `allowed_in_path` | `src/encode.rs` |
| L1805 | `curl_url_set` | `src/ffi.rs`, `src/getset.rs` |

Two of the 38 carry the `UNITTEST` marker: `Curl_parse_port` at L335 and
`dedotdotify` at L716. The marker matters to the export surface and is
picked up again there.

### The macros, counted separately

Macros are the other half of the "39" phrase, and each one carries behavior
that needs a home in the crate. The file holds 14 `#define` directives.
Seven are function-like:

| Line | Macro |
|---|---|
| L40 | `STARTS_WITH_DRIVE_PREFIX` |
| L48 | `STARTS_WITH_URL_DRIVE_PREFIX` |
| L121 | `cc2cu` |
| L699 | `ISSLASH` |
| L1301 | `DUP` |
| L1335 | `host_decode`, no-support form |
| L1336 | `host_encode`, no-support form |

Seven are object-like:

| Line | Macro | Value |
|---|---|---|
| L55 | `MAX_SCHEME_LEN` | 40 |
| L63 | `AF_INET6` | `AF_INET + 1` |
| L84 | `DEFAULT_SCHEME` | `"https"` |
| L477 | `HOST_ERROR` | `-1` |
| L479 | `HOST_NAME` | 1 |
| L480 | `HOST_IPV4` | 2 |
| L481 | `HOST_IPV6` | 3 |

Four of these are conditional and read as such. `STARTS_WITH_DRIVE_PREFIX`
sits inside a `#ifdef _WIN32` opened at L38 and closed at L44. `AF_INET6`
at L63 is a portability fallback guarded at L62 by
`#if !defined(USE_IPV6) && !defined(AF_INET6)`, present so that IPv6
addresses parse even where IPv6 support is compiled out. The no-support
`host_decode` and `host_encode` forms at L1335 and L1336 sit in the
`#ifndef USE_IDN` arm opened at L1334, whose `#else` at L1337 introduces
the two real functions and whose `#endif` closes at L1355; both forms
expand to `CURLUE_LACKS_IDN`.

The homes follow the call sites rather than the definitions, and the two
drive-prefix macros part company as a result. `STARTS_WITH_DRIVE_PREFIX` has
one caller, at L191 inside `Curl_is_absolute_url`, so it belongs to
`src/parse/scheme.rs`. `STARTS_WITH_URL_DRIVE_PREFIX` is called at L871,
L917, L918 and L924, every one of them inside `parse_file`, so it belongs to
`src/parse/file.rs`. `ISSLASH` is called at L737, L749, L758, L769 and L779,
all inside `dedotdotify`, which puts it in `src/parse/path.rs`, and the four
`HOST_*` markers go with `ipv4_normalize` in `src/parse/host.rs`.
`MAX_SCHEME_LEN` and `DEFAULT_SCHEME` join the other constants in
`src/abi.rs`, `cc2cu` goes to `src/error.rs` with the rest of the numeric
conversion, and `DUP` goes to `src/handle.rs`. `AF_INET6` needs no home:
`src/inet.rs` carries its own address-family constants and never depends on
a platform header.

## The module map

The correspondence below is fixed by the Agent Action Plan at 0.4.1.3 and
0.4.1.4. It is reproduced rather than reinvented, so a module agent reading
only this file learns the same boundaries the plan set.

### Top-level modules, fifteen

| Module | C source |
|---|---|
| `src/lib.rs` | crate root: module tree, lint policy, ABI assertions |
| `src/ffi.rs` | L1288, L1293, L1310, L1541, L1805; `lib/urlapi-int.h`:L28-L33 |
| `src/abi.rs` | `include/curl/urlapi.h`:L34-L105 |
| `src/error.rs` | `lib/strerror.c`:L420-L531; L121-L122 |
| `src/alloc.rs` | `lib/escape.c`:L189-L192; `lib/curl_setup.h`:L1309, L1461-L1484 |
| `src/dynbuf.rs` | `lib/curlx/dynbuf.c`:L162 |
| `src/ctype.rs` | `lib/curl_ctype.h`:L47-L49; `lib/escape.c`:L222; `lib/strcase.c`:L106 |
| `src/strparse.rs` | `lib/curlx/strparse.c`:L195 |
| `src/inet.rs` | `lib/curlx/inet_pton.c`:L207; `lib/curlx/inet_ntop.c`:L210 |
| `src/encode.rs` | L104-L180, L1779-L1803; `lib/escape.c`:L50 |
| `src/decode.rs` | `lib/escape.c`:L105 |
| `src/idn.rs` | `lib/idn.c`:L223-L344; L1334-L1355 |
| `src/scheme.rs` | `lib/url.c`:L1469-L1471; `lib/urldata.h`:L29-L53, L515-L524, L545 |
| `src/handle.rs` | L67-L102, L1301-L1332 |
| `src/getset.rs` | L1357-L1539, L1636-L1777 |

### Parser stage modules, eleven

Every span in this table is inside `lib/urlapi.c`, except for the one
outside citation on `src/parse/authority.rs`.

| Module | C source |
|---|---|
| `src/parse/mod.rs` | L1110-L1212 |
| `src/parse/junk.rs` | L223-L246 |
| `src/parse/scheme.rs` | L182-L221, L935-L1010 |
| `src/parse/authority.rs` | L248-L333, L604-L680; `lib/url.c`:L2466 |
| `src/parse/host.rs` | L444-L602 |
| `src/parse/ipv6.rs` | L390-L442 |
| `src/parse/port.rs` | L335-L388 |
| `src/parse/path.rs` | L682-L821, L1066-L1108 |
| `src/parse/query.rs` | L1012-L1064 |
| `src/parse/file.rs` | L823-L933 |
| `src/parse/redirect.rs` | L1214-L1286 |

## Where the spans meet the inventory

A reader matching the spans above against the function inventory notices
that several spans cover more than one function, and that two functions
appear under a module whose span does not visibly contain them. Each
resolution below was checked against the source.

- `src/parse/query.rs` covers two functions, not one:
  `handle_fragment` at L1012-L1034 and `handle_query` at L1036-L1064. The
  span reads as one block because the two sit adjacent with a single blank
  line between them, and the fragment stage runs immediately before the
  query stage in the pipeline.
- `src/parse/path.rs` covers `is_dot` at L682-L697, the `ISSLASH` macro at
  L699, `dedotdotify` at L716-L821 and `handle_path` at L1066-L1108. The
  comment block at L701-L714 documents `dedotdotify` and its forward
  declaration at L715 precedes the definition.
- `src/parse/host.rs` covers `hostname_check` at L444-L462,
  `ipv4_normalize` at L483-L575 and `urldecode_host` at L578-L602, plus
  the four classification markers at L477-L481. `ipv4_normalize` returns
  one of those markers rather than a `CURLUcode`, which is why they belong
  with it.
- `src/parse/mod.rs` covers `parseurl` at L1110-L1192 and
  `parseurl_and_replace` at L1197-L1209, with the comment at L1194-L1196
  between them.
- `src/parse/authority.rs` covers `parse_hostname_login` at L248-L333,
  `parse_authority` at L604-L655 and `Curl_url_set_authority` at
  L658-L675. It also absorbs `Curl_parse_login_details`, which lives
  outside the module at `lib/url.c`:L2466.
- `src/encode.rs` covers `find_host_sep` at L104-L118, the `cc2cu` macro
  at L121-L122, `urlencode_str` at L130-L172 and `allowed_in_path` at
  L1779-L1803. `cc2cu` appears inside this span for position only; its
  implementation belongs to `src/error.rs`, which owns every numeric
  conversion.
- `src/handle.rs` covers `struct Curl_URL` at L67-L82, the
  `DEFAULT_SCHEME` definition at L84, `free_urlhandle` at L86-L98, the
  `DUP` macro at L1301-L1308 and `curl_url_dup` at L1310-L1332. The
  structure holds ten heap strings at L68-L77 plus `portnum` at L78 and the
  three bit fields `query_present`, `fragment_present` and
  `guessed_scheme` at L79-L81.
- `src/getset.rs` covers `urlget_format` at L1357-L1423, `urlget_url` at
  L1425-L1539, `set_url_scheme` at L1636-L1664, `set_url_port` at
  L1666-L1683, `set_url` at L1685-L1730 and `urlset_clear` at
  L1732-L1777.

Two functions carry a second module because the C function is both an
exported symbol and a body of logic. `curl_url_dup` at L1310 is exported
from `src/ffi.rs` and implemented in `src/handle.rs`, which is where the
`DUP` macro it invokes ten times at L1314-L1323 also lives.
`curl_url_set` at L1805 is exported from `src/ffi.rs` and dispatched from
`src/getset.rs`; the next heading takes its body apart in full, because the
fixed table says nothing about it.

## Two corrections to the map

The fixed correspondence disagrees with the source in two places. Both are
recorded here rather than inherited in silence, because a reader checking a
boundary against `lib/urlapi.c` finds the discrepancy in under a minute and
then has no way to tell whether the rest of the map is trustworthy.

### `Curl_junkscan` ends at L239

The `src/parse/junk.rs` span reads L223-L246. The function itself runs
L223-L239: the comment introducing it sits at L222, the body opens at L224,
the length ceiling test against `CURL_MAX_INPUT_LENGTH` is at L229-L230,
the control-byte threshold is chosen at L232 as `0x1f` when spaces are
allowed and `0x20` otherwise, the rejecting loop runs L233-L236, and the
closing brace is L239.

The span therefore overshoots by seven lines. L240 is blank and L241-L247
is the comment block introducing `parse_hostname_login`, whose definition
begins at L248 and belongs to `src/parse/authority.rs`. Nothing is lost by
the overshoot, since the lines it reaches are a blank line and prose, but a
reviewer who reads L246 expecting junk-scan code deserves to know why the
numbers look wrong.

### The body of `curl_url_set` has no row of its own

This one matters more. The module map anchors `src/ffi.rs` at L1805 and
gives `src/getset.rs` only L1357-L1539 and L1636-L1777. Nothing claims
L1806 through L1998. That region is 193 lines of behavior, not boilerplate,
and it holds the entire assignment-side encoder.

Region by region, with its owner:

| C region | Behavior | Owner |
|---|---|---|
| L1808-L1815 | local mode flags | `src/getset.rs` |
| L1817-L1818 | null handle to `CURLUE_BAD_HANDLE` | `src/ffi.rs` |
| L1819-L1821 | null part clears, via `urlset_clear` | `src/getset.rs` |
| L1823-L1826 | input length ceiling | `src/getset.rs` |
| L1828-L1875 | per-part dispatch | `src/getset.rs` |
| L1880-L1886 | buffer sizing, leading slash | `src/getset.rs` |
| L1887-L1915 | percent encoder | `src/encode.rs` |
| L1916-L1933 | escape lower-casing | `src/encode.rs` |
| L1936-L1963 | query append rule | `src/getset.rs` |
| L1965-L1992 | hostname validation | `src/parse/host.rs` |
| L1994-L1995 | release old value, store new | `src/handle.rs` |

The details worth naming, because each is observable:

- The dispatch at L1828-L1875 does more than select a destination pointer.
  Setting the scheme delegates to `set_url_scheme` at L1830 and then
  disables encoding unconditionally at L1834. Setting the host releases any
  stored zone identifier at L1848, which is the one path that clears it.
  Setting the port delegates to `set_url_port` at L1854 and returns
  immediately. Setting the path turns on path mode and forces a leading
  slash at L1856-L1857. Setting the query turns on plus-encoding, reads
  `CURLU_APPENDQUERY`, arms the first-equals rule and records
  `query_present` at L1861-L1865. Setting the fragment records
  `fragment_present` at L1869. Setting the whole URL delegates to `set_url`
  at L1872. Anything else returns `CURLUE_UNKNOWN_PART` at L1874.
- The encoder at L1887-L1915 turns a space into `+` at L1892-L1896 when
  plus-encoding applies, copies a byte unchanged at L1903 when the
  preserved-set test at L1897-L1899 accepts it, and otherwise emits a
  percent escape through `Curl_hexbyte` at L1908-L1910. The preserved set
  is the unreserved characters, extended in path mode by `allowed_in_path`
  and by the first `=` only; the first-equals rule disarms itself at
  L1900-L1902 so that later equals signs encode.
- The alternative branch at L1916-L1933 runs when encoding is off, and it
  is not a plain copy. After appending the value at L1918 it walks the
  buffer at L1922-L1932 and lower-cases the two hexadecimal digits of every
  percent escape already present, using the test at L1924-L1925 so that an
  escape already in lower case costs nothing.
- The query append rule at L1936-L1963 inserts a separator only when one is
  needed. L1941 computes that condition as a non-empty existing query whose
  last byte is not already `&`.
- The hostname validation at L1965-L1992 decodes the value with
  `Curl_urldecode` at L1980 when encoding was off, then runs
  `hostname_check` at L1981 or L1985 and answers `CURLUE_BAD_HOSTNAME` at
  L1989 on failure. An empty value passes only under `CURLU_NO_AUTHORITY`,
  tested at L1967.
- The store at L1994-L1995 releases the previous value before overwriting
  the pointer. Getting that order wrong leaks on every repeated set, which
  is why `src/handle.rs` owns it rather than each call site.

## Stage ordering is behavior, not style

`parseurl` at L1110-L1192 runs seven stages in a fixed order:

| Order | Stage | Call site |
|---|---|---|
| 1 | junk scan | L1124 |
| 2 | absolute-URL detection | L1128 |
| 3 | scheme | L1138, or `parse_file` at L1134 |
| 4 | authority | L1149, with `guess_scheme` at L1152 |
| 5 | fragment | L1168 |
| 6 | query | L1177 |
| 7 | path | L1183 |

The order is load-bearing rather than cosmetic, and the reason is that
earlier stages mutate the buffer later stages read. Stage 1 writes the
measured length through `*urllen` at L237, which every later stage uses in
place of a fresh `strlen`. Stage 2 writes the scheme into a caller-supplied
buffer and returns its length at L1128-L1130, and stage 3 consumes both.
Stage 4 accumulates the hostname into the `host` dynamic buffer initialized
at L1122 and hands ownership of it to the handle at L1185, after which the
buffer is no longer the parser's to grow.

Stages 5, 6 and 7 share one shrinking length, and that is the clearest case
of the three. The fragment stage locates `#` at L1165, computes the tail
length at L1167, consumes it at L1168 and then shortens `pathlen` by that
much at L1170. The query stage searches for `?` at L1174 with `memchr`
bounded by the `pathlen` the fragment stage already reduced, consumes its
own tail at L1177 and shortens `pathlen` again at L1178. The path stage at
L1183 receives only what neither claimed. Reverse stages 5 and 6 and the
query search runs against the full length, so the query swallows the
fragment along with it. The comment at L1169 records the dependency in the
source itself.

`src/parse/mod.rs` preserves the order exactly. A later tidy-up that
reorders the pipeline is a correctness regression rather than a refactor,
which is the reason this record states the mechanism and not merely the
instruction.

### Atomic replacement

The other half of the pipeline contract is that a failed parse leaves the
caller's handle untouched. `parseurl_and_replace` at L1197-L1209 declares a
local `CURLU` at L1201, zeroes it with `memset` at L1202, and parses into
that temporary at L1203. Only on success does it release the live handle at
L1205 and move the temporary into place at L1206. On failure the caller's
handle is never written at all, and `parseurl` itself releases everything
the temporary acquired through the `fail` label at L1188: the host dynamic
buffer at L1189 and every string in the temporary at L1190.

No partial mutation is observable from outside. In Rust the same property
comes from constructing a fresh handle and swapping it in, which the borrow
checker enforces structurally instead of by discipline.

This is also why finding `FB2` in `KNOWN-DIVERGENCES.md` is harmless on the
ordinary parse path and harmful only on the live-handle authority path. The
credential exit label `out` at L323 releases its three local pointers at
L325-L327 and then sets the three handle fields to null at L328-L330
without releasing those. On the parse path the fields are already null,
because the handle is the zeroed temporary from L1202, so the assignments
discard nothing. `Curl_url_set_authority` at L658-L675 has no temporary, so
the same three assignments discard whatever the live handle held.

## Borrowed helpers are re-implemented, not imported

`lib/urlapi.c` leans on roughly twenty helpers defined in sibling
translation units. The crate re-implements each of them internally so that
one archive can stand in for one object file without dragging the rest of
libcurl behind it. The list below names each source and the module that
absorbs it.

- `lib/curlx/dynbuf.c`, the dynamic buffer that grows on demand, into
  `src/dynbuf.rs`. Two behaviors have to survive the port. Exceeding the
  configured maximum releases the buffer and returns the too-large code, at
  L82-L84, and an allocation failure releases it as well, at L106-L108. A
  caller that treats either as recoverable and appends again is appending
  to a released buffer. Note also that `curlx_dyn_ptr` at L237-L242 returns
  the buffer pointer without clearing the structure, so the ownership
  handover at `lib/urlapi.c`:L1185 is a convention the caller honors rather
  than something the buffer enforces. `MEMORY-OWNERSHIP.md` carries that in
  full.
- `lib/curlx/strparse.c`, the numeric scanners, into `src/strparse.rs`.
  `curlx_str_number` at L195 is the decimal entry point, and the port keeps
  the exact overflow and trailing-junk semantics rather than substituting a
  Rust integer parser, whose acceptance set differs.
- `lib/curlx/inet_pton.c` and `lib/curlx/inet_ntop.c`, address conversion,
  into `src/inet.rs`. `curlx_inet_pton` at L207 and `curlx_inet_ntop` at
  L210 are the pair used for the IPv6 normalization at
  `lib/urlapi.c`:L433-L435, where an address is parsed to bytes and
  formatted back so that the stored form is canonical.
- `lib/escape.c`, four helpers into four modules. `curl_easy_escape` at L50
  into `src/encode.rs`, `Curl_urldecode` at L105 into `src/decode.rs`,
  `curl_free` at L189-L192 into `src/alloc.rs`, and `Curl_hexbyte` at L222
  into `src/ctype.rs`. `Curl_hexbyte` emits uppercase hexadecimal, which is
  why the lower-casing pass at `lib/urlapi.c`:L1922-L1932 exists at all.
- `lib/strcase.c`, `Curl_strntolower` at L106, into `src/ctype.rs`.
- `lib/url.c`, two helpers into two modules. `Curl_get_scheme` at
  L1469-L1471 into `src/scheme.rs`, and `Curl_parse_login_details` at
  `lib/url.c`:L2466 into `src/parse/authority.rs`.
- `lib/idn.c`, the internationalized-domain conversions at L223-L344, into
  `src/idn.rs`. `Curl_is_ASCII_name` at L223-L236 is the gate: a null input
  counts as ASCII at L228-L229 and the first byte with the high bit set
  ends the scan at L232-L233. The call sequence inside `idn_decode` at
  L247 is reproduced step for step, including the version check at L252,
  the normalizing flag at L253 and the non-transitional flag at L258 behind
  the version test at L254, and the retry with the transitional flag at
  L261-L265 that runs on any failure of the first attempt.
- `lib/curl_ctype.h`, the unreserved-character predicate, into
  `src/ctype.rs`. `ISURLPUNTCS` at L47-L48 accepts `-`, `.`, `_` and `~`,
  and `ISUNRESERVED` at L49 adds the alphanumeric characters.
- `lib/mprintf.c`, formatted allocation, absorbed at each site where the C
  code calls into the family. `curl_maprintf` allocates at L381, L1441,
  L1517 and L1676, and `curl_msnprintf` fills a fixed buffer at L1465,
  L1513 and L1591. The whole-URL template at L1517 takes fifteen `%s`
  conversions in one call, so the port keeps the assembly order rather than
  concatenating piece by piece. In the standalone configuration the harness
  supplies C shims for the family instead, because no libcurl participates
  in that link.
- `lib/strerror.c`, the message strings at L420-L531, into `src/error.rs`
  behind the `strerror` feature. The verbose arm carries a case label for
  every one of the 33 `CURLUcode` values and falls through to
  `"CURLUcode unknown"` at L524; the non-verbose arm at L525-L530 answers
  with one of two strings.

### The one place C layout still matters

In the drop-in configuration `src/scheme.rs` declares `Curl_get_scheme` as
an external function rather than compiling a table, and it reads three
fields of the descriptor the function returns: the capability flags at
`lib/urldata.h`:L522, the default port at L523 and the implementation
marker at L517, tested against null to detect a protocol compiled out. A
C-representation structure that names those fields has to reproduce the
field order of `struct Curl_scheme` at `lib/urldata.h`:L515-L524 exactly,
including the two fields the module never reads, because the offsets depend
on them. That constraint applies in that configuration only. With the
`scheme-table` feature on, the table is compiled in Rust from the port
constants at `lib/urldata.h`:L29-L53 and the capability bit
`PROTOPT_URLOPTIONS` at L545, and no C structure is described anywhere.

### Why layout freedom exists at all

Everywhere else the port is free of layout constraints, and the reason is
one line of the public header. `include/curl/urlapi.h`:L107 declares

    typedef struct Curl_URL CURLU;

without ever defining `struct Curl_URL`. The type is incomplete, so no
caller outside `lib/urlapi.c` can take its size, read a field or copy it by
value; every caller holds only a `CURLU *`. The Rust structure behind that
pointer therefore chooses its own field order, its own padding and its own
representation. Transformation rule `T3` in the Agent Action Plan at 0.1.2.3
names this as the property that makes the port tractable, and the
observation earns its place: had the structure been public, the port would
have had to match a C layout field for field before a single line of
behavior could be ported.

The exception proves the rule. The one C structure that does cross the
boundary by layout is the scheme descriptor above, and the one test that
would have forced a second such structure is out of scope for exactly that
reason, as the export surface records next.

## The export surface

The object file being replaced defines eight global symbols, not the six
public functions a reader of the header expects. Verified by extracting
`urlapi.c.o` from an archive of unmodified libcurl built from this tree and
listing it:

    ar x libcurl.a urlapi.c.o
    nm -g --defined-only urlapi.c.o

| Symbol | Declared | Defined |
|---|---|---|
| `curl_url` | `include/curl/urlapi.h`:L113 | L1288 |
| `curl_url_cleanup` | `include/curl/urlapi.h`:L120 | L1293 |
| `curl_url_dup` | `include/curl/urlapi.h`:L126 | L1310 |
| `curl_url_get` | `include/curl/urlapi.h`:L133 | L1541 |
| `curl_url_set` | `include/curl/urlapi.h`:L141 | L1805 |
| `Curl_is_absolute_url` | `lib/urlapi-int.h`:L28-L29 | L182 |
| `Curl_url_set_authority` | `lib/urlapi-int.h`:L31 | L658 |
| `Curl_junkscan` | `lib/urlapi-int.h`:L33 | L223 |

The last three are internal to libcurl and have real consumers elsewhere in
the library, so a crate exporting only the five public ones cannot replace
the object file in a full link. Only `src/ffi.rs` carries the export
attributes; every other module is crate-internal, which is what keeps the
archive free of collisions with the rest of libcurl.

### Two symbols that stay behind a feature

`curl_url_strerror` is declared in the public header at
`include/curl/urlapi.h`:L149 and is not in the object file being replaced.
It is defined at `lib/strerror.c`:L420-L531, which is out of scope and
beyond reach of any edit, and the same listing that shows eight symbols in
`urlapi.c.o` shows `curl_url_strerror` in `strerror.c.o`. The crate exports
it only behind the `strerror` feature, which has to be off in the drop-in
configuration or the link acquires a duplicate definition.

`curl_free` follows the same reasoning from a different starting point. It
is defined at `lib/escape.c`:L189-L192 and appears in `escape.c.o`, so the
crate exports it only behind the `cfree` feature, on for the standalone
configuration where nothing else supplies it and off for the drop-in one.
This is the Agent Action Plan's conflict `C3` at 0.8.3, and
`MEMORY-OWNERSHIP.md` carries the ownership half of it: a buffer the crate
hands to C is released by the caller through whichever of the two
definitions the link resolved.

### One test beyond drop-in reach

A second URL API test exists and cannot be satisfied by a drop-in
replacement. `tests/unit/unit1653.c` declares a `struct dynbuf` of its own
at L32, initializes it at L34, and calls
`Curl_parse_port(url, &host, has_scheme)` directly at L37, passing that
structure by address alongside a `CURLU *`.

Two things stand in the way. `Curl_parse_port` is a ninth symbol, exported
only from unit-test builds through the `#ifdef UNITTESTS` guard opened at
`lib/urlapi-int.h`:L35 and closed at L38. Satisfying it would also require
the Rust side to interoperate with the C dynamic-buffer structure bit for
bit, which is the layout constraint the port otherwise escapes entirely.
That is a materially harder contract than anything the public API asks for,
and the named success criteria cover `lib1560` and `test1560` only. The test
is out of scope, recorded here as a documented limitation of the drop-in
rather than passed over, per the Agent Action Plan at 0.2.4.2.

## The behavioral oracle

The map is checked, not asserted. The primary oracle is
`tests/libtest/lib1560.c`, 2,075 lines, consumed read-only and
byte-unchanged: the port is validated by running that source against the
Rust-backed library and comparing the result with the same source run
against the unmodified C. Every bare `Lnnn` in this section and its tables
refers to that file rather than to `lib/urlapi.c`.

The single include directive is `"first.h"` at L33, which is the reason the
crate carries a harness shim. A relative include of the real header pulls in
libcurl's private build environment, and editing the test to avoid that is
not permitted.

The entry point `test_lib1560` at L2034-L2075 reads
`CURL_TEST_HAVE_CODESET_UTF8` at L2036, calls each sub-test in turn, and
prints its single success line at L2073 only when every one passes.

The Agent Action Plan at 0.10.4 lists thirteen line numbers as sub-tests.
Only eleven are. The two extras are helpers rather than sub-tests:
`checkparts` at L38 takes a handle and an expected description and compares
the parts one by one, and `checkurl` at L848 compares two URL strings with
`strcmp` at L850. Neither appears anywhere in the entry point, and neither
has an exit code.

The eleven, each with the code the entry point returns when it fails:

| Code | Sub-test | Defined at | Returned at |
|---|---|---|---|
| 1 | `set_url` | L1383 | L2062 |
| 2 | `set_parts` | L1485 | L2065 |
| 3 | `get_url` | L1537 | L2047 |
| 4 | `get_parts` | L1580 | L2068 |
| 5 | `append` | L1631 | L2059 |
| 6 | `scopeid` | L1681 | L2056 |
| 7 | `get_nothing` | L1811 | L2053 |
| 8 | `clear_url` | L1876 | L2071 |
| 9 | `huge` | L1916 | L2050 |
| 10 | `setget_parts` | L1434 | L2044 |
| 11 | `urldup` | L1970 | L2041 |

Two properties of the entry point shape how results are reported. The
invocation order differs from the order of definition in the file: reading
L2040 downward it runs `urldup`, `setget_parts`, `get_url`, `huge`,
`get_nothing`, `scopeid`, `append`, `set_url`, `set_parts`, `get_parts` and
`clear_url`. Each call also sits in its own `if` that returns immediately,
so the run short-circuits at the first failure and reports one code however
many sub-tests are broken.

The consequence for reporting is that a single exit code names one failing
sub-test rather than summarizing the run. The parity script maps the code
back to the name in the table above and iterates, so a report covers every
sub-test instead of stopping at whichever failed first.

Three sub-tests take the codeset flag read at L2036 as a parameter and gate
part of their table on it: `setget_parts` at L1446, `get_url` at L1548 and
`get_parts` at L1591, each of which skips its `CURLU_PUNY2IDN` cases when
the flag is clear. The parity run therefore repeats with the variable both
set and unset, since a run with it unset exercises none of those cases and
still reports success.

## The unsafe boundary is a module boundary

`src/ffi.rs` is the only module in the crate that contains `unsafe`. The
Agent Action Plan fixes this at 0.3.3 and the technical specification
forbids `unsafe` outside FFI code at 1.3.2.1; every block carries a safety
comment, per 3.2.1.2. The facade validates preconditions, converts
representations and delegates, and it holds no parsing logic of its own.

That arrangement is why the module map can attribute two C functions to two
modules each without ambiguity. `curl_url_dup` and `curl_url_set` are
exported symbols that dereference caller-supplied pointers, so their entry
points belong in the facade; their behavior belongs in `src/handle.rs` and
`src/getset.rs`, which never see a raw pointer. Reading the map with that
split in mind, a module agent working on parsing or serialization writes no
`unsafe` at all.

## See also

- [MEMORY-OWNERSHIP.md][ownership] records the ownership chain behind the
  boundary: how `curl_free()` resolves, every allocation site in the
  module, and the rules the crate follows at each one.
- [KNOWN-DIVERGENCES.md][divergences] records the six behaviors reproduced
  on purpose, `FB1` through `FB6`, and names the module that carries each.
- `../README.md` is the short entry point, with the feature table,
  prerequisites, targets and script ordering this file leaves out.

[ownership]: MEMORY-OWNERSHIP.md
[divergences]: KNOWN-DIVERGENCES.md
