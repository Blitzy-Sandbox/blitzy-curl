<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Porting notes

`lib/urlapi.c` is a single C translation unit of 1,998 lines. The
`curl-urlapi-rs` port spreads the same behavior across 26 Rust modules, and
all 26 are in the tree. This document is the map between the two. A reviewer
checking a Rust module against the C it came from finds the line numbers here
instead of re-deriving the correspondence, and a reader asking which module
owns a given piece of C behavior finds the answer here as well. What is not
in the tree yet is named exactly, in "What exists today" below, so that no
sentence here has to be taken on trust in either direction.

Completeness is the point. A map that leaves a region of the C file
unattributed sends a reader hunting through the wrong module, so every
region is attributed below, and the two spans that need a word of
explanation get one rather than being left to a reader to puzzle out.

Build steps, the feature table, prerequisites and script ordering are
deliberately absent. They belong to `rust-urlapi/README.md`, the short entry
point to the same material. This file is the long one.

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
  that names its own file. A row or sentence that names two files spells out
  which file each span belongs to rather than relying on this rule.
- **A path is relative to the repository root unless it takes one of the two
  crate-local forms below.** In particular `lib/`, `src/`, `tests/`,
  `include/`, `docs/`, `scripts/` and `.github/` always mean the repository's
  own directories, never this crate's. The crate has directories of five of
  those names -- `src/`, `tests/`, `include/`, `docs/` and `scripts/` -- which
  is exactly why a bare one is never crate-relative here. The two sibling
  documents, `rust-urlapi/docs/KNOWN-DIVERGENCES.md` and
  `rust-urlapi/docs/MEMORY-OWNERSHIP.md`, allow themselves no crate-local form
  at all; this file needs one because its tables have to fit 79 columns.
- **Crate-local form one: a Rust module is named by its file leaf.**
  `getset.rs` means `rust-urlapi/src/getset.rs`, and `parse/host.rs` means
  `rust-urlapi/src/parse/host.rs`. No repository-root path takes either
  shape -- there is no bare `*.rs` and no `parse/` directory at the root --
  so neither can be misread.
- **Crate-local form two: everything else under this crate is written out in
  full.** `rust-urlapi/harness/main.c`, `rust-urlapi/demo/urlapi_demo.c`,
  `rust-urlapi/include/curl_urlapi_rs.h`, `rust-urlapi/Cargo.toml`,
  `rust-urlapi/README.md`.

### What exists today, and what remains

A reader must be able to tell a claim about code from a requirement on code,
so the inventory is stated rather than left to be inferred.

`rust-urlapi/src/` holds all 26 modules this map describes. The fifteen
top-level ones are `abi.rs`, `alloc.rs`, `ctype.rs`, `decode.rs`,
`dynbuf.rs`, `encode.rs`, `error.rs`, `ffi.rs`, `getset.rs`, `handle.rs`,
`idn.rs`, `inet.rs`, `lib.rs`, `scheme.rs` and `strparse.rs`; the eleven
parser stages are `parse/mod.rs`, `parse/junk.rs`, `parse/scheme.rs`,
`parse/authority.rs`, `parse/host.rs`, `parse/ipv6.rs`, `parse/port.rs`,
`parse/path.rs`, `parse/query.rs`, `parse/file.rs` and
`parse/redirect.rs`.

`ffi.rs` is complete, including the half that once was not, and the
distinction is worth stating because earlier revisions of this file recorded
it as outstanding. It holds the crate's C-boundary primitives -- the
allocator entry points and the raw block that owns their result, the address
conversion pair, the drop-in scheme lookup and the libidn2 bindings -- which
is what makes it the single unsafe island the Agent Action Plan requires at
0.3.3. It also holds the exported C-linkage surface: ten
`#[no_mangle] extern "C"` functions, in the plain spelling that edition 2021
takes. Eight are unconditional and are the drop-in set of 0.4.2.3 --
`curl_url`, `curl_url_cleanup`, `curl_url_dup`, `curl_url_get`,
`curl_url_set`, `Curl_is_absolute_url`, `Curl_junkscan` and
`Curl_url_set_authority` -- and two are feature-gated, `curl_url_strerror`
behind `strerror` and `curl_free` behind `cfree`, both of them off in the
drop-in configuration where libcurl's own objects define them. Sentences
below about the exported functions therefore describe code rather than
requirements.

Outside `rust-urlapi/src/`, `rust-urlapi/harness/` is complete: `first.h`,
`runner.c`, `main.c`, `shims.c` and `.checksrc`.
`rust-urlapi/include/curl_urlapi_rs.h` exists. `rust-urlapi/demo/` holds
`.checksrc` and `urlapi_demo.c`; what it does not hold is
`expected-output.txt`, the golden capture from the reference link.
`rust-urlapi/tests/` holds all five integration suites -- `abi_constants.rs`,
`encode_decode.rs`, `path_dedot.rs`, `host_ip.rs` and `ffi_surface.rs` -- so
sentences below about them describe tests a reader can run. What is not in the
tree is a `rust-urlapi/scripts/`, a `rust-urlapi/README.md` or a
`rust-urlapi/GNUmakefile`.

Those four are the whole of what is outstanding, and wherever one of them
appears below the sentence states a requirement on work still to be done and
is worded as one. Present tense is reserved for what a reader can open
today.

### The scope boundary this work does not cross

Success criterion `G4` in the Agent Action Plan at 0.1.1.1 is a definition
of success rather than a preference, and it is absolute: **no pre-existing
file anywhere in this repository is created, edited, moved or deleted, and
every new artifact lives under `rust-urlapi/`.** That covers
`lib/urlapi.c` and `include/curl/urlapi.h`, which stay untouched so that
they remain available as the comparison baseline; the whole of `lib/`,
`src/`, `include/`, `tests/`, `docs/` and `.github/`; and the entire build
system, `Makefile.am`, `lib/Makefile.inc`, `CMakeLists.txt` and
`configure.ac` included. `AAP` 0.2.3 enumerates the exclusions in full.

Every file this document cites outside `rust-urlapi/` is therefore
read-only: consulted as a contract, a behavioral specification or a style
template, and never modified. Where meeting a goal would require an edge
outside that boundary, the constraint is reported rather than taken, which
is what the reported constraints `R1` through `R4` below are.

No user rules were supplied for this work, so no rule is cited anywhere
below. The standard applied instead is enterprise-standard best practice as
this repository already enforces it: an inline SPDX header on every file,
prose that passes the repository gates, read-only treatment of every file
cited here, and a citation on every factual claim.

## The C translation unit

`lib/urlapi.c` defines **38 functions** in 1998 lines. That figure is
derived from the source and checked two ways that share no failure mode, so
it can be re-checked rather than taken on trust.

The first way scans for signatures:

    grep -nE '^(static |UNITTEST |size_t |void |CURLU |CURLUcode )' \
      lib/urlapi.c | grep -vE ';$'

The alternation also needs `const char ` for the one function returning
that type; it is split out here only so the line fits.

That reports 39 matching lines and 38 after the trailing-semicolon filter.
The line the filter drops is L715, a forward declaration -- shown here with a
trailing spell-checker marker that the C source does not carry, so that the
parameter name can stay verbatim:

    UNITTEST int dedotdotify(const char *input, size_t clen, char **outp); /* spellchecker:disable-line */

L716 then defines the same function, so one declaration plus one definition
of `dedotdotify` accounts for the difference exactly.

The second way ignores signatures and counts opening braces in column zero,
each of which starts a function body. That also reports 38. Note that a
count of "functions and macros" is a larger population than a count of
function definitions, so the two figures are not interchangeable; this file
uses 38 throughout and means function definitions by it.

### The 38 function definitions

Every module named in the third and fourth columns is under
`rust-urlapi/src/`, stated here once so the rows stay narrow. The third
column names the module that absorbs the function's logic; the fourth names
`ffi.rs` for each of the eight functions that becomes an exported C symbol,
because every one of those needs an entry point in the facade as well as a
body behind it. A dash means the function is crate-internal and has no
exported entry point.

The third column names fifteen distinct modules across the 38 rows, and all
fifteen are in the tree: `encode.rs`, `getset.rs`, `handle.rs`, `idn.rs` and
the eleven parser stages `parse/mod.rs`, `parse/junk.rs`, `parse/scheme.rs`,
`parse/authority.rs`, `parse/host.rs`, `parse/ipv6.rs`, `parse/port.rs`,
`parse/path.rs`, `parse/query.rs`, `parse/file.rs` and `parse/redirect.rs`.
Ten further modules appear in no third-column cell at all -- `abi.rs`,
`alloc.rs`, `ctype.rs`, `decode.rs`, `dynbuf.rs`, `error.rs`, `ffi.rs`,
`inet.rs`, `scheme.rs` and `strparse.rs` -- and their absence is by design
rather than an omission: they carry the ABI constants and the helpers
`lib/urlapi.c` borrows from sibling translation units, so there is no line of
that file for a row to list them against. `ffi.rs` is named by the fourth
column instead. The module map below is where all ten are accounted for.

Every fourth-column entry describes code. `ffi.rs` holds each of the eight
exported C-linkage symbols the column names, as *What exists today* records.

Splitting the ownership into two columns is what makes the inventory
open to checking against the module map without cross-referencing by hand, and
it is also what stops the three internal exports from looking crate-private.
`Curl_is_absolute_url`, `Curl_url_set_authority` and `Curl_junkscan` are
declared in `lib/urlapi-int.h` and consumed elsewhere in libcurl, so they
carry export attributes exactly as the five public functions do; the export
surface section below lists their consumers.

| Line | Function | Logic module | Exported from |
|---|---|---|---|
| L86 | `free_urlhandle` | `handle.rs` | -- |
| L104 | `find_host_sep` | `encode.rs` | -- |
| L130 | `urlencode_str` | `encode.rs` | -- |
| L182 | `Curl_is_absolute_url` | `parse/scheme.rs` | `ffi.rs` |
| L223 | `Curl_junkscan` | `parse/junk.rs` | `ffi.rs` |
| L248 | `parse_hostname_login` | `parse/authority.rs` | -- |
| L335 | `Curl_parse_port` | `parse/port.rs` | -- |
| L390 | `ipv6_parse` | `parse/ipv6.rs` | -- |
| L444 | `hostname_check` | `parse/host.rs` | -- |
| L483 | `ipv4_normalize` | `parse/host.rs` | -- |
| L578 | `urldecode_host` | `parse/host.rs` | -- |
| L604 | `parse_authority` | `parse/authority.rs` | -- |
| L658 | `Curl_url_set_authority` | `parse/authority.rs` | `ffi.rs` |
| L682 | `is_dot` | `parse/path.rs` | -- |
| L716 | `dedotdotify` | `parse/path.rs` | -- |
| L823 | `parse_file` | `parse/file.rs` | -- |
| L935 | `parse_scheme` | `parse/scheme.rs` | -- |
| L984 | `guess_scheme` | `parse/scheme.rs` | -- |
| L1012 | `handle_fragment` | `parse/query.rs` | -- |
| L1036 | `handle_query` | `parse/query.rs` | -- |
| L1066 | `handle_path` | `parse/path.rs` | -- |
| L1110 | `parseurl` | `parse/mod.rs` | -- |
| L1197 | `parseurl_and_replace` | `parse/mod.rs` | -- |
| L1214 | `redirect_url` | `parse/redirect.rs` | -- |
| L1288 | `curl_url` | `handle.rs` | `ffi.rs` |
| L1293 | `curl_url_cleanup` | `handle.rs` | `ffi.rs` |
| L1310 | `curl_url_dup` | `handle.rs` | `ffi.rs` |
| L1338 | `host_decode` | `idn.rs` | -- |
| L1347 | `host_encode` | `idn.rs` | -- |
| L1357 | `urlget_format` | `getset.rs` | -- |
| L1425 | `urlget_url` | `getset.rs` | -- |
| L1541 | `curl_url_get` | `getset.rs` | `ffi.rs` |
| L1636 | `set_url_scheme` | `getset.rs` | -- |
| L1666 | `set_url_port` | `getset.rs` | -- |
| L1685 | `set_url` | `getset.rs` | -- |
| L1732 | `urlset_clear` | `getset.rs` | -- |
| L1779 | `allowed_in_path` | `encode.rs` | -- |
| L1805 | `curl_url_set` | `getset.rs` | `ffi.rs` |

Three rows changed owner relative to the plan's own wording, and each is
explained where it belongs. `curl_url` at L1288 and `curl_url_cleanup` at
L1293 allocate and release the handle, so their bodies sit with the handle
in `handle.rs` alongside `free_urlhandle`, which L1298 calls. `curl_url_get`
at L1541 is the substantial one: the plan's module map anchors `ffi.rs` at
L1541 and stops there, but the function body runs to L1634 and holds the
whole per-part read dispatch. The next section takes that region apart
line by line, because it is 94 lines of behavior rather than a forward to
somewhere else.

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
`parse/scheme.rs`. `STARTS_WITH_URL_DRIVE_PREFIX` is called at L871,
L917, L918 and L924, every one of them inside `parse_file`, so it belongs to
`parse/file.rs`. `ISSLASH` is called at L737, L749, L758, L769 and L779,
all inside `dedotdotify`, which puts it in `parse/path.rs`, and the four
`HOST_*` markers go with `ipv4_normalize` in `parse/host.rs`.
`MAX_SCHEME_LEN` and `DEFAULT_SCHEME` join the other constants in
`abi.rs`, `cc2cu` goes to `error.rs` with
the rest of the numeric conversion, and `DUP` goes to
`handle.rs`. `AF_INET6` needs no home:
`inet.rs` carries its own address-family constants and never
depends on a platform header.

Three of those four are cited twice in this document, once here as a named
item and once inside a module span in the next section, and the two readings
are not the same claim. **Ownership is what this paragraph states; a span
that encloses a line states only where that line sits in
`lib/urlapi.c`.** `DEFAULT_SCHEME` at L84 is the clearest case:
`abi.rs` owns it, because it is an ABI-adjacent constant and
that module owns every one of those, while
`handle.rs`'s L67-L102 span happens to enclose L84 because
the definition sits between the structure and `free_urlhandle`. Nothing is
declared twice. `cc2cu` at L121-L122 and `MAX_SCHEME_LEN` are the same
pattern, and each is flagged again at its span.

## The module map

The correspondence below is the crate's module boundary contract: every
Rust module names the C source it absorbs, so a reader of one module can see
what it owns and what it does not without deriving the split again.

### Top-level modules, fifteen

A list rather than a table, because several of these rows name three files
and a table row cannot be wrapped inside this document's 79-column
convention.

- `lib.rs` -- crate root: module tree, lint policy, ABI assertions. No C
  antecedent.
- `ffi.rs` -- `lib/urlapi.c`:L1288, L1293, L1310, L1541 and L1805, plus the
  three internal declarations at `lib/urlapi-int.h`:L28-L33.
- `abi.rs` -- `include/curl/urlapi.h`:L34-L105.
- `error.rs` -- `lib/strerror.c`:L420-L531, plus `cc2cu` at
  `lib/urlapi.c`:L121-L122.
- `alloc.rs` -- `lib/escape.c`:L189-L192, plus `lib/curl_setup.h`:L1309 and
  L1461-L1484.
- `dynbuf.rs` -- `lib/curlx/dynbuf.c`:L162.
- `ctype.rs` -- `lib/curl_ctype.h`:L47-L49, plus `lib/escape.c`:L222 and
  `lib/strcase.c`:L106.
- `strparse.rs` -- `lib/curlx/strparse.c`:L195.
- `inet.rs` -- `lib/curlx/inet_pton.c`:L207 and
  `lib/curlx/inet_ntop.c`:L210.
- `encode.rs` -- `lib/urlapi.c`:L104-L180 and L1779-L1803, plus
  `curl_easy_escape` at `lib/escape.c`:L50.
- `decode.rs` -- `lib/escape.c`:L105.
- `idn.rs` -- `lib/idn.c`:L223-L344, plus the two wrappers at
  `lib/urlapi.c`:L1334-L1355.
- `scheme.rs` -- `lib/url.c`:L1469-L1471, plus `lib/urldata.h`:L29-L53,
  L515-L524 and L545.
- `handle.rs` -- `lib/urlapi.c`:L67-L102 and L1301-L1332.
- `getset.rs` -- `lib/urlapi.c`:L1357-L1539, L1541-L1634 and L1636-L1777.

The `getset.rs` row carries one span the plan's table does not: L1541-L1634,
the body of `curl_url_get`. The plan anchors that line to `ffi.rs` and
attributes nothing to the 94 lines behind it, which is the gap the function
inventory above corrects and which the corrections section below explains.

One row needs reading twice. `ffi.rs` is the crate's only `unsafe`
module, so besides the exported entry points it also holds the *call* at the
bottom of four rows above it: the C allocator behind `alloc.rs`, the
platform `inet_pton` and `inet_ntop` behind `inet.rs`, the libidn2
binding behind `idn.rs`, and the imported `Curl_get_scheme` behind
`scheme.rs`. The rows are attributed to the modules that own the
*interface*, because that is where a reader looking for the behavior should
go; the foreign call is one level below each of them and is documented at its
own site.

### Parser stage modules, eleven

Every module named is under `rust-urlapi/src/parse/`, and every span is
inside `lib/urlapi.c` except the one outside citation on `authority.rs`,
which spells its own file out. All eleven are in the tree.

| Module | C source |
|---|---|
| `mod.rs` | L1110-L1212 |
| `junk.rs` | L223-L246 |
| `scheme.rs` | L182-L221, L935-L1010 |
| `authority.rs` | L248-L333, L604-L680; `lib/url.c`:L2466 |
| `host.rs` | L444-L602 |
| `ipv6.rs` | L390-L442 |
| `port.rs` | L335-L388 |
| `path.rs` | L682-L821, L1066-L1108 |
| `query.rs` | L1012-L1064 |
| `file.rs` | L823-L933 |
| `redirect.rs` | L1214-L1286 |

## Where the spans meet the inventory

A reader matching the spans above against the function inventory notices
that several spans cover more than one function, and that two functions
appear under a module whose span does not visibly contain them. Each
resolution below was checked against the source.

- `parse/query.rs` covers two functions, not one:
  `handle_fragment` at L1012-L1034 and `handle_query` at L1036-L1064. The
  span reads as one block because the two sit adjacent with a single blank
  line between them, and the fragment stage runs immediately before the
  query stage in the pipeline.
- `parse/path.rs` covers `is_dot` at L682-L697, the `ISSLASH` macro at
  L699, `dedotdotify` at L716-L821 and `handle_path` at L1066-L1108. The
  comment block at L701-L714 documents `dedotdotify` and its forward
  declaration at L715 precedes the definition.
- `parse/host.rs` covers `hostname_check` at L444-L462,
  `ipv4_normalize` at L483-L575 and `urldecode_host` at L578-L602, plus
  the four classification markers at L477-L481. `ipv4_normalize` returns
  one of those markers rather than a `CURLUcode`, which is why they belong
  with it.
- `parse/mod.rs` covers `parseurl` at L1110-L1192 and
  `parseurl_and_replace` at L1197-L1209, with the comment at L1194-L1196
  between them.
- `parse/authority.rs` covers `parse_hostname_login` at L248-L333,
  `parse_authority` at L604-L655 and `Curl_url_set_authority` at
  L658-L675. It also absorbs `Curl_parse_login_details`, which lives
  outside the module at `lib/url.c`:L2466.
- `encode.rs` covers `find_host_sep` at L104-L118, the `cc2cu` macro
  at L121-L122, `urlencode_str` at L130-L172 and `allowed_in_path` at
  L1779-L1803. `cc2cu` appears inside this span for position only; its
  implementation belongs to `error.rs`, which owns every numeric
  conversion. Two further spans reach it from elsewhere in the file, the
  assignment-side encoder at L1887-L1915 and the escape lower-casing pass at
  L1916-L1933, both of which the region table further down attributes to it,
  and one from outside the module, `curl_easy_escape` at `lib/escape.c`:L50.

  That last one is the reason to read the module rather than assume it. Three
  distinct encoding rule sets live in it and they disagree with each other on
  purpose. `urlencode_str` copies everything up to the end of the host
  **verbatim** -- L124-L128 says why, an encoded host would not resolve --
  and then encodes only spaces and bytes outside `0x20..0x7e`, so `/`, `?`,
  `&` and `=` pass through untouched. The whole-URL retrieval path at L1492-
  L1496 does the opposite for the same host: it hands `u->host` to
  `curl_easy_escape`, which preserves only the unreserved set. In turn the
  assignment-side encoder preserves the unreserved set plus the eighteen
  bytes of `allowed_in_path` in path mode plus the first `=` when appending
  to a query. Neither of the first two is a bug and both are reachable, so
  the port carries both; merging them, or "fixing" the host exemption, would
  change behavior in one direction or the other.
- `handle.rs` covers `struct Curl_URL` at L67-L82, the
  `DEFAULT_SCHEME` definition at L84, `free_urlhandle` at L86-L98, the
  `DUP` macro at L1301-L1308 and `curl_url_dup` at L1310-L1332. The
  structure holds ten heap strings at L68-L77 plus `portnum` at L78 and the
  three bit fields `query_present`, `fragment_present` and
  `guessed_scheme` at L79-L81.
- `getset.rs` covers `urlget_format` at L1357-L1423, `urlget_url` at
  L1425-L1539, `set_url_scheme` at L1636-L1664, `set_url_port` at
  L1666-L1683, `set_url` at L1685-L1730 and `urlset_clear` at
  L1732-L1777.

Two functions carry a second module because the C function is both an
exported symbol and a body of logic. `curl_url_dup` at L1310 is exported
from `ffi.rs` and implemented in `handle.rs`, which is where the
`DUP` macro it invokes ten times at L1314-L1323 also lives.
`curl_url_set` at L1805 is exported from `ffi.rs` and dispatched from
`getset.rs`; the next heading takes its body apart in full, because a
single row cannot express how it divides.

## Two spans that need stating exactly

Two rows of the map above are easy to read wrongly against the source, so
both are pinned here.

### `Curl_junkscan` is L223-L239

The function body ends at L239, not at L246: the comment introducing it sits
at L222, the body opens at L224, the length ceiling test against
`CURL_MAX_INPUT_LENGTH` is at L229-L230, the control-byte threshold is
chosen at L232 as `0x1f` when spaces are allowed and `0x20` otherwise, the
rejecting loop runs L233-L236, and the closing brace is L239. L240 is blank
and L241-L247 is the comment block introducing `parse_hostname_login`, whose
definition begins at L248 and belongs to `parse/authority.rs`. A
reviewer reading L246 expecting junk-scan code is past the end of it.

### The body of `curl_url_set`, L1806-L1998, is split across four modules

`ffi.rs` owns the exported entry point at L1805. The 193 lines of its
body that follow are behavior rather than boilerplate -- they hold the whole
assignment-side encoder -- and no single module owns them.

Region by region, with its owner:

| C region | Behavior | Owner |
|---|---|---|
| L1808-L1815 | local mode flags | `getset.rs` |
| L1817-L1818 | null handle to `CURLUE_BAD_HANDLE` | `ffi.rs` |
| L1819-L1821 | null part clears, via `urlset_clear` | `getset.rs` |
| L1823-L1826 | input length ceiling | `getset.rs` |
| L1828-L1875 | per-part dispatch | `getset.rs` |
| L1880-L1886 | buffer sizing, leading slash | `getset.rs` |
| L1887-L1915 | percent encoder | `encode.rs` |
| L1916-L1933 | escape lower-casing | `encode.rs` |
| L1936-L1963 | query append rule | `getset.rs` |
| L1965-L1992 | hostname validation | `parse/host.rs` |
| L1994-L1995 | release old value, store new | `handle.rs` |

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
  is why `handle.rs` owns it rather than each call site.

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

`parse/mod.rs` preserves that order exactly, and it is checkable today: its
pipeline runs the junk scan, the absolute-URL test, the scheme stage, the
authority stage, then the fragment, query and path stages in that sequence,
which is the sequence above. A later tidy-up that reorders the pipeline is a
correctness regression rather than a refactor, which is the reason this
record states the mechanism and not merely the instruction.

### Atomic replacement

The other half of the pipeline contract is that a failed parse leaves the
caller's handle untouched. `parseurl_and_replace` at L1197-L1209 declares a
local `CURLU` at L1201, zeroes it with `memset` at L1202, and parses into
that temporary at L1203. Only on success does it release the live handle at
L1205 and move the temporary into place at L1206. On failure the caller's
handle is never written at all, and `parseurl` itself releases everything
the temporary acquired through the `fail` label at L1188: the host dynamic
buffer at L1189 and every string in the temporary at L1190.

No partial mutation is observable from outside. In Rust the same property is
to come from constructing a fresh handle and swapping it in, which the borrow
checker then enforces structurally instead of by discipline.

This is also why finding `FB2` in `KNOWN-DIVERGENCES.md` is harmless on the
ordinary parse path and harmful only on the live-handle authority path. The
credential exit label `out` at L323 releases its three local pointers at
L325-L327 and then sets the three handle fields to null at L328-L330
without releasing those. On the parse path the fields are already null,
because the handle is the zeroed temporary from L1202, so the assignments
discard nothing. `Curl_url_set_authority` at L658-L675 has no temporary, so
the same three assignments discard whatever the live handle held.

## Borrowed helpers, and how each one is satisfied

`lib/urlapi.c` leans on helpers defined in sibling translation units, and an
object file standing in for `lib/urlapi.o` cannot borrow them back. Most are
re-implemented inside the crate so that one archive can stand in for one
object file without dragging the rest of libcurl behind it -- but *most* is
not *all*, and the difference matters to anyone reasoning about the link
line, so the table below grades each one:

- **reimplemented** -- written in Rust inside the crate, with no external
  symbol and no C dependency.
- **imported** -- declared as an external symbol and resolved by whatever
  the link supplies. This is a real C dependency of that configuration.
- **shimmed** -- supplied by a small C file under `rust-urlapi/harness/` in
  the standalone configuration, and by libcurl in the drop-in one.
- **bound** -- a system library is called directly, reproducing the C's own
  call sequence.

The inventory is exhaustive over the helpers `lib/urlapi.c` actually calls,
counted from the source rather than estimated. It is grouped by grade rather
than tabulated, because several entries name three files and a table row
cannot be wrapped inside this document's 79-column convention. Where a
locator has no file in front of it, the file is the one named at the start of
its entry.

**Reimplemented in Rust, with no external symbol and no C dependency.**

- `lib/curlx/dynbuf.c` -- the whole family: `curlx_dyn_init`, `_addn`,
  `_add`, `_addf`, `_ptr`, `_len`, `_setlen`, `_reset` and `_free`. Into
  `dynbuf.rs`.
- `lib/curlx/strdup.h`:L30 `curlx_strdup` and `lib/curlx/strdup.c`:L85
  `curlx_memdup0`, the two duplication helpers `lib/urlapi.c` calls at
  L418, L815, L838, L977, L1004, L1028, L1052, L1059, L1086, L1304 and
  L1367. Into `alloc.rs`, whose owned-buffer type replaces both.
- `lib/curl_setup.h`:L1461-L1484 `curlx_free`, called 32 times. Into
  `alloc.rs`. Its resolution chain is the subject of
  `MEMORY-OWNERSHIP.md`.
- `lib/curlx/strparse.c` -- `curlx_str_number` at L195, `curlx_str_hex` at
  L202 and `curlx_str_octal` at L209. Into `strparse.rs`. The hexadecimal
  and octal scanners are reached only from `ipv4_normalize`, at
  `lib/urlapi.c`:L500 and L503.
- `lib/curlx/inet_pton.c`:L207 and `lib/curlx/inet_ntop.c`:L210. Into
  `inet.rs`.
- `lib/escape.c` -- `curl_easy_escape` at L50 into `encode.rs`,
  `Curl_urldecode` at L105 into `decode.rs`, `curl_free` at L189-L192 into
  `alloc.rs`, and `Curl_hexbyte` at L222 into `ctype.rs`.
- `lib/strcase.c` -- `Curl_strntolower` at L106 and `Curl_raw_tolower` at
  L81, the latter reached from the escape lower-casing pass at
  `lib/urlapi.c`:L1926-L1927. Into `ctype.rs`.
- `include/curl/curl.h`:L2424 `curl_strequal`, called once at
  `lib/urlapi.c`:L1440, and `lib/strcase.h`:L33 `checkprefix`, called at
  L874, L875 and the six scheme-guess sites L989-L999. Into `ctype.rs`.
- `lib/curl_ctype.h`:L38-L50 -- `ISUNRESERVED` and the classifiers around
  it. Into `ctype.rs`.
- `memrchr`, from the platform or curl's own fallback, called three times
  inside `redirect_url`. Into `parse/redirect.rs`.
- `lib/url.c`:L2466 `Curl_parse_login_details`. Into
  `parse/authority.rs`.
- `lib/idn.c`:L223 `Curl_is_ASCII_name`. Into `idn.rs`.
- `lib/strerror.c`:L420-L531 -- the 33 message strings. Into `error.rs`,
  behind the `strerror` feature.

**Bound to a system library, reproducing the C's own call sequence.**

- `lib/idn.c` -- `Curl_idn_decode` at L247 and `Curl_idn_encode` at L326,
  which `idn.rs` satisfies by calling libidn2 directly under the default
  `idn-libidn2` feature. That is a real C dependency of the crate, and it is
  deliberate: it is what makes bit-for-bit parity attainable, libidn2's
  locale sensitivity included. The `idn-pure` alternative removes the
  dependency and is not bit-for-bit; `KNOWN-DIVERGENCES.md` records the
  difference.

**Imported as an external symbol in one configuration.**

- `lib/url.c`:L1469-L1471 `Curl_get_scheme`, consulted at
  `lib/urlapi.c`:L284, L951, L1460, L1465, L1472, L1589, L1591, L1598,
  L1599, L1645 and L1646. With the `scheme-table` feature off,
  `scheme.rs` declares it `extern "C"` and the link supplies it; with the
  feature on, the table is compiled in Rust and nothing is imported. The
  imported form carries the one remaining C layout dependency, described in
  the next subsection.

**Shimmed in the standalone configuration.**

- `lib/mprintf.c` -- `curl_maprintf` at `lib/urlapi.c`:L381, L1441, L1517
  and L1676, and `curl_msnprintf` at L1465, L1513 and L1591. In the drop-in
  configuration libcurl supplies both. In the standalone configuration
  `rust-urlapi/harness/shims.c` does, forwarding to the C library, and its
  return value diverges from curl's in the truncating case, which
  `KNOWN-DIVERGENCES.md` records. On the Rust side the formatting itself is
  absorbed at each call site through `alloc.rs` and `dynbuf.rs` rather than
  through a printf-alike, so the whole-URL template at L1517 -- fifteen
  `%s` conversions in one call -- keeps its assembly order.

The old heading's claim, that every borrowed helper is re-implemented
internally, was therefore too strong in three places, and each is a real
property of the build rather than a wording quibble.

### Behavior a reader has to know, not merely a location

Five of the entries above carry semantics that a naive re-implementation
loses. They are expanded here so that the inventory stays easy to scan.

- **The dynamic buffer releases itself on failure.** Exceeding the
  configured maximum releases the buffer and returns the too-large code, at
  L82-L84, and an allocation failure releases it as well, at L106-L108. A
  caller that treats either as recoverable and appends again is appending
  to a released buffer. Note also that `curlx_dyn_ptr` at L237-L242 returns
  the buffer pointer without clearing the structure, so the ownership
  handover at `lib/urlapi.c`:L1185 is a convention the caller honors rather
  than something the buffer enforces. `MEMORY-OWNERSHIP.md` carries that in
  full.
- `lib/curlx/strparse.c`, the numeric scanners, into `strparse.rs`.
  `curlx_str_number` at L195 is the decimal entry point, and the port keeps
  the exact overflow and trailing-junk semantics rather than substituting a
  Rust integer parser, whose acceptance set differs.
- `lib/curlx/inet_pton.c` and `lib/curlx/inet_ntop.c`, address conversion,
  into `inet.rs`. `curlx_inet_pton` at L207 and `curlx_inet_ntop` at
  L210 are the pair used for the IPv6 normalization at
  `lib/urlapi.c`:L433-L435, where an address is parsed to bytes and
  formatted back so that the stored form is canonical.
- `lib/escape.c`, four helpers into four modules. `curl_easy_escape` at L50
  into `encode.rs`, `Curl_urldecode` at L105 into `decode.rs`,
  `curl_free` at L189-L192 into `ffi.rs`, whose `cfree`-gated export
  is the only place it can live because it is both an exported symbol and a
  foreign call, and `Curl_hexbyte` at L222
  into `ctype.rs`. `Curl_hexbyte` emits uppercase hexadecimal, which is
  why the lower-casing pass at `lib/urlapi.c`:L1922-L1932 exists at all.
- `lib/strcase.c`, `Curl_strntolower` at L106, into `ctype.rs`.
- `lib/url.c`, two helpers into two modules. `Curl_get_scheme` at
  L1469-L1471 into `scheme.rs`, and `Curl_parse_login_details` at
  `lib/url.c`:L2466 into `parse/authority.rs`.
- `lib/idn.c`, the internationalized-domain conversions at L223-L344, into
  `idn.rs`. `Curl_is_ASCII_name` at L223-L236 is the gate: a null input
  counts as ASCII at L228-L229 and the first byte with the high bit set
  ends the scan at L232-L233. The call sequence inside `idn_decode` at
  L247 is reproduced step for step, including the version check at L252,
  the normalizing flag at L253 and the non-transitional flag at L258 behind
  the version test at L254, and the retry with the transitional flag at
  L261-L265 that runs on any failure of the first attempt.
- `lib/curl_ctype.h`, the unreserved-character predicate, into
  `ctype.rs`. `ISURLPUNTCS` at L47-L48 accepts `-`, `.`, `_` and `~`,
  and `ISUNRESERVED` at L49 adds the alphanumeric characters.
- `lib/mprintf.c`, formatted allocation, absorbed at each site where the C
  code calls into the family. `curl_maprintf` allocates at L381, L1441,
  L1517 and L1676, and `curl_msnprintf` fills a fixed buffer at L1465,
  L1513 and L1591. The whole-URL template at L1517 takes fifteen `%s`
  conversions in one call, so the port keeps the assembly order rather than
  concatenating piece by piece. In the standalone configuration the harness
  supplies C shims for the family instead, because no libcurl participates
  in that link.
- `lib/strerror.c`, the message strings at L420-L531, into `error.rs`
  behind the `strerror` feature. The verbose arm carries a case label for
  every one of the 33 `CURLUcode` values and falls through to
  `"CURLUcode unknown"` at L524; the non-verbose arm at L525-L530 answers
  with one of two strings.

### The one place C layout still matters

In the drop-in configuration the crate declares `Curl_get_scheme` as an
external function rather than compiling a table, and reads three fields of
the descriptor the function returns. The declaration and the read live in
`crate::ffi::scheme_import`, since both are foreign work, and `scheme.rs`
receives an owned copy of the three values. The fields are: the capability
flags at `lib/urldata.h`:L522, the default port at L523 and the
implementation marker at L517, tested against null to detect a protocol
compiled out. A C-representation structure that names those fields has to
reproduce the field order of `struct Curl_scheme` at
`lib/urldata.h`:L515-L524 exactly, including the fields the module never
reads, because the offsets depend on them.

`struct Curl_scheme` at `lib/urldata.h`:L515-L524 has six fields, in this
order:

| Offset order | Field | Type | Read by the port |
|---|---|---|---|
| 1 | `name` | `const char *` | no |
| 2 | `run` | `const struct Curl_protocol *` | yes, the null test |
| 3 | `protocol` | `curl_prot_t` | no |
| 4 | `family` | `curl_prot_t` | no |
| 5 | `flags` | `uint32_t` | yes |
| 6 | `defport` | `uint16_t` | yes |

That makes **three** unread fields, not two: `name`, `protocol` and
`family`. A C-representation structure that names the three the port does
read has to reproduce all six in order anyway, because the offsets of
`flags` and `defport` depend on everything in front of them.

That is where the precondition hides, and it is worth stating as one.
`curl_prot_t` is `uint32_t` only because `PROTO_TYPE_SMALL` is defined at
`lib/urldata.h`:L82; the `#else` arm at L84-L86 types it `curl_off_t`
instead, which is 64 bits on the platforms this port targets. Two of the six
fields carry that type, so if the macro is ever removed the mirror's `flags`
and `defport` offsets shift by eight bytes and it silently reads the wrong
memory. The comment at L81 says the macro should be undefined "once we need
bit 32 or higher", which is not hypothetical: L71 already defines
`CURLPROTO_WSS` as bit 31.

No single assertion catches that, because the compiled crate cannot read
`lib/urldata.h` and the header cannot read the crate. Two checks divide the
work, and both are worth naming exactly.

- `ffi.rs` pins the Rust side. The `#[repr(C)]` mirror `CurlScheme` is
  declared there, and the `LAYOUT_PROOF` block just below it asserts at
  compile time that the mirror is the size a 32-bit `curl_prot_t` implies --
  32 bytes where a pointer is 8, 24 where it is 4, and 0 for any other
  pointer width, which fails the assertion deliberately rather than guessing
  -- that it is pointer-aligned, and that `u32` and `u16` really are 4 and 2
  bytes. Its test module re-derives every one of the six field offsets at run
  time besides. What all of that establishes is that nobody edited the Rust
  side out of shape; it cannot see the C side at all.
- `build.rs` covers the C side, textually. `check_scheme_layout_precondition`
  reads `../lib/urldata.h` and requires both a `#define PROTO_TYPE_SMALL`
  line and a `typedef uint32_t curl_prot_t` line. Reading is not compiling,
  and the difference is deliberate: compiling that header would need
  libcurl's private build environment, `curl_config.h` included, which this
  crate does not have and does not want. If either line is gone the build
  panics with a message naming both remedies -- widen the mirrored fields, or
  build with `scheme-table` and describe no C structure at all. If the header
  cannot be found, which is the ordinary case outside a curl checkout, it
  emits a note and continues, because refusing to build standalone would
  trade a real capability for a check with nothing to check.

A residual risk survives both, which is why the precondition is documented
as well as checked. The text of a header is not the preprocessed header: the
check requires the two lines to be present, not to be reached, so an edit
that moved either inside a conditional that does not hold would still satisfy
it. And it reads the header of the tree this crate sits in, which is the
right tree for a drop-in link against a libcurl built from that tree and the
wrong one for a link against an archive built somewhere else. **A 32-bit
`curl_prot_t` therefore remains a documented precondition of drop-in mode**,
recorded as such in `KNOWN-DIVERGENCES.md`. The live cross-check is the
parity run, which reads `defport` through the assertions at
`tests/libtest/lib1560.c`:L592-L594 and L786-L788, so a shifted mirror fails
the first sub-test rather than subtly.

The whole constraint applies in that configuration only. With the
`scheme-table` feature on, the table is compiled in Rust from the port
constants at `lib/urldata.h`:L29-L53 and the capability bit
`PROTOPT_URLOPTIONS` at L545, no C structure is described anywhere, and the
precondition does not arise.

### Why layout freedom exists at all

Everywhere else the port is free of layout constraints, and the reason is
one line of the public header. `include/curl/urlapi.h`:L107 declares

    typedef struct Curl_URL CURLU;

without ever defining `struct Curl_URL`. The type is incomplete, so no
caller outside `lib/urlapi.c` can take its size, read a field or copy it by
value; every caller holds only a `CURLU *`. The Rust structure behind that
pointer therefore chooses its own field order, its own padding and its own
representation. That opacity is the property that makes the port tractable:
had the structure been public, the port would have had to match a C layout
field for field before a single line of behavior could be ported.

The exception proves the rule. The one C structure that does cross the
boundary by layout is the scheme descriptor above, and the one test that
would have forced a second such structure is out of scope for exactly that
reason, as the export surface records next.

## Three encoders, and no two of them agree

`lib/urlapi.c` percent-encodes in three places, and each place uses a
different rule. The map above attributes all three to `encode.rs`, so
this section says what distinguishes them, because merging them would erase
the differences and the differences are the behavior.

| C function | C locator | Preserved set | A space becomes | The host |
|---|---|---|---|---|
| `urlencode_str` | L130-L172 | everything printable below `0x7f` | `%20`, then `+` after a `?` | copied verbatim |
| `curl_easy_escape` | `lib/escape.c`:L50-L87 | the unreserved set | `%20` | escaped |
| the `urlencode` arm of `curl_url_set` | L1887-L1915 | unreserved, plus `allowed_in_path` in path mode, plus the first `=` | `+` when plus-encoding | not applicable |

Three consequences are worth naming, because each is observable through the
public API and none is a defect.

The host is treated two ways on the same retrieval path. `urlencode_str`
never encodes it, and the in-source rationale at L126-L128 states it
outright:

    URL encoding should be skipped for hostnames, otherwise IDN resolution
    will fail.

Yet the whole-URL retrieval at L1492-L1496 hands the host to
`curl_easy_escape`, which escapes everything outside the unreserved set.
Both paths are reachable from `curl_url_get`, and neither can be reconciled
with the other, so the port carries both under transformation rule `T6`.

The plus rule is positional rather than per-part. `urlencode_str` negates
its `query` argument into the variable the C calls `left` at L135, and only
encountering a `?` in the input clears it at L166, so the rule applies to
everything *after* a query delimiter; a part the caller flags as the query
starts with `left` already clear and turns every space into `+` whether or
not a `?` appears.

The case of an escape depends on which direction it traveled. Escapes the
crate emits are uppercase, because `Curl_hexbyte` indexes `Curl_udigits`;
escapes already present in a value handed to `curl_url_set` without
`CURLU_URLENCODE` are lower-cased in place by the walk at L1922-L1932. The
same three characters therefore come out in different cases depending on the
side they entered through.

## The export surface

The object file being replaced defines eight global symbols, not the six
public functions a reader of the header expects. Verified against an archive
of unmodified libcurl built from this tree.

The reading is non-destructive: `nm` accepts an archive directly and prefixes
each block of symbols with the member it came from, so nothing is extracted
and nothing is written anywhere.

    nm -g --defined-only libcurl.a | sed -n '/^urlapi\\.c\\.o:/,/^$/p'

If a separate copy of the member really is wanted, note that `ar x`
**creates or overwrites `urlapi.c.o` in the current directory**, which is
easy to run by accident in a source tree. Do it in a scratch directory made
for the purpose, and remove it afterwards:

    mkdir -p /tmp/urlapi-symbols && cd /tmp/urlapi-symbols
    ar x /path/to/libcurl.a urlapi.c.o
    nm -g --defined-only urlapi.c.o
    cd - && rm -rf /tmp/urlapi-symbols

`ar p libcurl.a urlapi.c.o` streams the member to standard output instead,
for a reader who wants the bytes without a file at all.

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
the object file in a full link. Their consumers are, source-verified:
`Curl_is_absolute_url` at `lib/http1.c`:L220, `lib/url.c`:L1661 and
`lib/http.c`:L1177; `Curl_url_set_authority` at `lib/http2.c`:L739; and
`Curl_junkscan` at `lib/doh.c`:L1127.

`ffi.rs` is the only module carrying the export attributes, with every other
module crate-internal, which is what keeps the archive free of collisions with
the rest of libcurl.

### The canonical static artifact

Cargo's `staticlib` output is an **input**, not the deliverable. It carries
the whole Rust standard library, the allocator and the unwinder, so
`nm -g --defined-only` reports thousands of distinct globals where
`urlapi.c.o` reports 8. No count is quoted here on purpose: it moves with the
toolchain, and `build.rs` reports the measured figure in the build log at the
moment it matters rather than leaving a literal to go stale.

**The canonical drop-in artifact is `libcurl_urlapi_rs_dropin.a`**, and it is
the only static artifact this port offers for a C link line. `build.rs`
produces it with the localization pass -- `ld -r --whole-archive`, then
`objcopy --keep-global-symbol` for the ABI set, then `ar rcs` -- and validates
it in both directions. Measured: exactly the eight names above in the drop-in
configuration, and exactly ten in the standalone one, where `curl_url_strerror`
and `curl_free` are real exports. That archive is what `check-abi` compares,
what the parity link names, and what the cargo-c install path ships; the raw
Cargo archive is never presented as the drop-in.

The validation is two-sided, and the second side is what makes it a provenance
check rather than a rename. Before localizing anything the pass inspects the
**raw** archive:

- every name the requested feature combination must export has to be defined,
  and the two feature-gated exports have to be defined **if and only if** their
  feature is on -- so a default-feature archive, which defines
  `curl_url_strerror` and `curl_free`, is refused by a drop-in invocation;
- the **undefined** set has to name the providers that combination implies --
  `Curl_get_scheme` and `Curl_getn_scheme` in the drop-in configuration and in
  no other, the three unconditional `idn2_*` entry points plus exactly one of
  the two lookup spellings under the libidn2 backend and none under any other;
- the archive has to be no older than every file it was built from, which is a
  different failure from feature incompatibility and no symbol test can see.

The undefined side is the one that earns its keep. An archive built with
`scheme-table` wrongly left on defines the *same eight globals* as a correct
drop-in archive, so nothing after `objcopy` can tell the two apart -- but it
carries no reference to `Curl_get_scheme` at all, and that is what the check
reads. All of these refusals were exercised deliberately rather than reasoned
about.

A provenance record is written beside the artifact -- feature set, target,
profile, the measured raw global count, the exported set, the imported provider
set, and a content tag for the input, the output and the source inventory -- so
a certification can be compared with a later one instead of being taken on
trust. The tag is FNV-1a and is a change detector rather than a cryptographic
digest; the checks that actually gate the certification are the exact ones
above.

### The shared artifact belongs to one configuration

The `cdylib` needs no localization step, because it exposes symbols the way an
executable does and only an annotated `#[no_mangle] pub extern "C" fn` is
exported at all. It does need a **closure** check, and the reason is the
scheme provider.

With `scheme-table` off, the crate references `Curl_get_scheme` and
`Curl_getn_scheme`, declared at `lib/url.h`:L76-L77. Both are libcurl-private,
and libcurl's visibility rules keep them out of a shared libcurl's dynamic
symbol table, so an undefined reference to either resolves in exactly one
situation: a static link in which `url.c.o` takes part. That is the drop-in
link. A shared object built from that configuration would carry both names
undefined, with no `libcurl` NEEDED entry and no prospect of one, and would
fail at `dlopen` every time.

So the rule is that **a shared object is a deliverable only where the crate is
self-contained**, which is the standalone configuration, and `build.rs`
`emit_shared_artifact_gate` applies it in the two ways the two configurations
allow. In the standalone one the **release** cdylib link on an ELF target gets
`-Wl,-z,defs`, so the object is proved closed on every release build -- its
undefined set is libc, libgcc and libidn2, each a real NEEDED entry -- and the
proof costs nothing because the link succeeds. In the drop-in one the same
directive would cost the deliverables: `crate-type` is a property of the
package, so `cargo build --release` asks for the archive, the rlib and the
cdylib together, Cargo stops at the first failing link, and a refused cdylib
means no archive and no rlib either -- exit 101 with nothing written, against a
plan that requires that command to succeed at 0.9.2 `A1`. So the drop-in
release build records a notice instead, naming
`libcurl_urlapi_rs.so` a non-deliverable, why it cannot load, and the archive
to consume in its place. The notice goes to the build script's captured output
and to `DROP-IN-CDYLIB-NOTICE.txt` in OUT_DIR rather than to `cargo:warning`,
because a diagnostic that fires on every build of a supported configuration is
one nobody can clear and 0.9.2 `A1` asks both configurations to build cleanly;
`docs/KNOWN-DIVERGENCES.md` argues that at length under "Why the notice is not
a `cargo:warning`". `CURL_URLAPI_STRICT_CDYLIB=1` restores the refusal for a
caller who would rather have it than a record.

`cargo check` and `cargo clippy` are unaffected by the directive, which Cargo
applies to the cdylib link alone.

The archive a drop-in `cargo build --release` writes is an input rather than
the artifact a consumer is given, for a reason that has nothing to do with the
gate: Cargo cannot apply link-time optimisation while an rlib is among the
crate types, so the three-type archive is several times larger and still
carries the Rust standard library's globals. The publishable static artifact is
the localized one, and it starts from asking for the archive alone:

    cargo rustc --release --no-default-features --features idn-libidn2 \
      --lib --crate-type staticlib

`--crate-type` on `cargo rustc` has been stable since 1.64, below the crate's
declared 1.75 floor. "The canonical static artifact" above carries the
localization pass that turns that archive into the eight-symbol one.

The gate stops at the release profile deliberately. Cargo builds every crate
type of a lib target whenever it builds that target, and an integration test
under `tests/` needs the lib target built, so gating the dev profile as well
would stop `cargo test` from running in the drop-in configuration whenever the
strict opt-in was set. Release is the profile that produces deliverables and
the profile every documented build command names; a debug shared object, which
nobody installs, is recorded in the build log instead.

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
`MEMORY-OWNERSHIP.md` carries the ownership half of this: a buffer the
crate hands to C is released by the caller through whichever of the two
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
is out of scope, and it is recorded here as a documented limitation of the
drop-in rather than passed over in silence.

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

There are **eleven sub-tests**. Two other static functions in the file look
like sub-tests and are not: `checkparts` at L38 takes a handle and an
expected description and compares the parts one by one, and `checkurl` at
L848 compares two URL strings with `strcmp` at L850. Neither is called from
the entry point and neither has an exit code, so neither can fail a run on
its own.

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
sub-test rather than summarizing the run. Whatever drives the comparison has
to map the code back to the name in the table above and iterate, so that a
report covers every sub-test instead of stopping at whichever failed first.
`rust-urlapi/scripts/run-parity.sh` is to be that driver and is not written
yet, so until it lands the mapping is done by reading the table.

Three sub-tests take the codeset flag read at L2036 as a parameter and gate
part of their table on it: `setget_parts` at L1446, `get_url` at L1548 and
`get_parts` at L1591, each of which skips its `CURLU_PUNY2IDN` cases when
the flag is clear. A parity run therefore has to repeat with the variable
both set and unset, since a run with it unset exercises none of those cases
and still reports success.

## The unsafe boundary

`ffi.rs` is the only module in the crate that contains `unsafe`, and every
block in it carries a safety comment. The facade validates preconditions,
converts representations and delegates, and it holds no parsing logic of its
own.

That is not a convention and it is not asserted by inspection. Of the 26
files under `rust-urlapi/src/`, the 24 that are neither the crate root nor
the facade each open with `#![forbid(unsafe_code)]`, so an `unsafe` block
added to any of them is a compile error rather than a review finding, and
`forbid` rather than `deny` means an inner `allow` cannot buy an exception
back. The two that do not carry it are the two that cannot. `ffi.rs` cannot
forbid what it exists to contain. `lib.rs` cannot either, because an inner
attribute on the crate root reaches every module including the facade; what
the crate root carries instead is `deny(clippy::missing_safety_doc)`,
`deny(clippy::undocumented_unsafe_blocks)` and
`deny(unsafe_op_in_unsafe_fn)` in its lint block -- named by symbol rather than
by line so the claim cannot drift -- which do not ban `unsafe`
anywhere but do make an undocumented block, an undocumented `unsafe fn` or
an implicitly unsafe `unsafe fn` body a build failure. The property the Agent
Action Plan states at 0.3.3 and 0.7.2, and which specification 1.3.2.1
requires, is therefore enforced by the compiler on every build in every
feature configuration.

Three provisions of the plan look at first like they put `unsafe` elsewhere,
and reconciling them is what the design turns on. 0.4.1.3 assigns the
C-allocator adapter to `alloc.rs`, the libidn2 bindings to `idn.rs` and the
external `Curl_get_scheme` declaration to `scheme.rs`; 0.3.3 calls `alloc.rs`
"the sole producer of C-visible memory"; and calling `malloc`, calling
`idn2_to_ascii_lz` and calling any `extern "C"` function are each `unsafe`
operations in Rust. The resolution is that *producing* C-visible memory and
*holding the `unsafe` keyword* are two different responsibilities:

- `alloc.rs` is still the C-allocator adapter and still the only module that
  constructs a C-visible buffer. Every such buffer is a `CBuf` built there.
  What it no longer contains is a raw pointer operation: `CBuf` is a thin
  wrapper over `ffi::cheap::CBlock`, and every method it needs on that block
  -- allocate, resize, write at an offset, borrow as a slice, hand the pointer
  to C, release -- is a safe method whose preconditions are `CBlock`'s own
  documented invariants rather than a caller's promise.
- `idn.rs` still owns the libidn2 *behavior*: the version guard, the exact
  flag set, the transitional retry, the zero-length rejection and the
  re-duplication order, all of which are the parity-critical part. What moved
  to `ffi.rs` is the five `extern "C"` declarations and the two platform
  lookup arms, behind wrappers that take a `&CBuf` and return an owned
  result, so the `NUL`-termination precondition is a type invariant rather
  than a promise.
- `scheme.rs` still owns scheme resolution in both feature arms. What moved
  is the two `extern "C"` declarations and the one dereference of the
  descriptor libcurl returns; the facade hands back an owned `SchemeInfo`
  carrying the three fields the module reads, so no C structure is
  interpreted outside `ffi.rs`.

`dynbuf.rs` and `inet.rs` follow the same shape: the buffer that grows is a
thin wrapper over `CBlock`, and the address conversion pair is called from the
facade behind slice-based wrappers.

The other half of the boundary is unchanged and is what the module map
depends on: the exported entry points and the logic behind them are separate.
`ffi.rs` validates preconditions, converts representations and delegates; it
holds no parsing logic of its own. That is why the inventory can give every
exported function both a logic module and `ffi.rs` without ambiguity -- the
entry point dereferences the caller's pointer, and the body never sees one.
A module agent working on parsing or serialization writes no `unsafe` at all,
and now cannot.

## The C-ABI panic and unwind posture

A Rust panic that reaches a C caller is the one failure mode a C-ABI port
can introduce that has no counterpart in the original, so the posture is
fixed deliberately rather than left to chance. It has three layers, and each
is a distinct decision.

**Layer one: the ABI already makes it defined behavior.** Every exported
function is declared `extern "C"`, which is the plain C ABI rather than
`C-unwind`. Under the unwinding runtime a panic that would otherwise escape
such a function aborts the process instead, which RFC 2945 specifies and
which the language reference's panic table states for exactly this
combination. The worst case is therefore a defined abort rather than
undefined behavior, and that is the floor rather than the plan.

**Layer two: the release profile removes unwinding altogether.**
`rust-urlapi/Cargo.toml` sets `panic = "abort"` in `[profile.release]`, so
the artifacts a C consumer links carry no landing pads and no unwind tables. A
panic terminates immediately. This also keeps the archive free of the
personality routine a C link would otherwise have to resolve.

**Layer three, and the one that matters: panics are designed out rather than
caught.** The crate root denies the panicking constructs -- `unwrap`,
`expect`, explicit `panic!`, direct indexing and slicing, and arithmetic
with side effects -- so a construct that could panic fails the build rather
than reaching a caller. All 26 modules are clean under those denials, and
`cargo clippy --all-targets -- -D warnings` is what keeps them so in every
feature configuration. In practice that means `get` and `get_mut` in place of
indexing,
slice patterns in place of indexing, `checked_*` and `saturating_*` in
place of bare operators, and an explicit fallback in place of every
`unwrap`. Where a case is genuinely unreachable, the code takes the safe
branch and says so in a comment instead of asserting.

The one deliberate relaxation is inside `#[cfg(test)] mod tests` blocks,
where the denials are lifted item by item rather than blanket, because an
assertion's whole job is to panic and a test never crosses the boundary.

Catching panics at the boundary with `catch_unwind` was considered and
rejected. Converting a panic into an error code would hide the class of bug
the parity diff exists to expose: a panic in this port means the port is
wrong about something, and the parity run should report that loudly rather
than answer `CURLUE_OUT_OF_MEMORY` and continue.

## Reported constraint `R1`: the distribution check fails

`AAP` 0.2.4.1 reports this and declines to fix it; the same position is
recorded here, because a reader who commits this crate and watches CI go red
deserves to find the reason in the porting notes rather than only in the
plan.

`.github/scripts/distfiles.sh` compares the output of `git ls-files` against
the contents of the generated release tarball, subtracts a fixed exception
list, and exits non-zero for anything reported as missing from the tarball.
It runs as the `missing-files` job in `.github/workflows/distcheck.yml`, and
that workflow triggers on every push to the default branch and every pull
request against it with no path filter.

Committing `rust-urlapi/**` therefore makes that job report the new files as
missing from the tarball and fail. The exception list is a fixed literal and
cannot accommodate a new directory.

**The remedy is a one-line edit to `Makefile.am`** -- adding the directory to
`EXTRA_DIST`, or to the distributed subdirectory lists -- **and this work
does not make it.** `Makefile.am` is out of scope under `G4` and enumerated
among the exclusions at `AAP` 0.2.3, and the escalation rule at 0.8.1 says to
report such a case rather than expand scope into it. Downstream owners should
treat the addition as a follow-up decision outside this work item. Nothing in
the crate works around it, and no CI file is edited to suppress it.

### The other three reported constraints, and where each is recorded

`R1` completes the set of four, so they are listed together once:

- `R1`, above: the distribution check fails until an out-of-scope
  `Makefile.am` edit is made.
- `R2`: `tests/unit/unit1653.c` is beyond drop-in reach, recorded under
  "One test beyond drop-in reach" in this file.
- `R3`: memory-debug builds are incompatible with the crate's C-allocator
  buffers, recorded in `MEMORY-OWNERSHIP.md`.
- `R4`: alternative memory functions installed at runtime are not
  supported, recorded in `MEMORY-OWNERSHIP.md`.

None of the four is worked around. Each is reported with its remedy named and
the remedy deliberately not applied.

## See also

- [MEMORY-OWNERSHIP.md][ownership] records the ownership chain behind the
  boundary: how `curl_free()` resolves, every allocation site in the
  module, and the rules the crate follows at each one.
- [KNOWN-DIVERGENCES.md][divergences] records the six behaviors reproduced
  on purpose, `FB1` through `FB6`, and names the module that carries each.
- `rust-urlapi/README.md` is the deliverable that carries the feature table,
  prerequisites, targets and script ordering this file leaves out.

[ownership]: MEMORY-OWNERSHIP.md
[divergences]: KNOWN-DIVERGENCES.md
