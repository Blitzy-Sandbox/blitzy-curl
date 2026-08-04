<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Known divergences

`lib/urlapi.c` does a handful of things that look wrong, that read as
inconsistent with the contract documented in `include/curl/urlapi.h`, or
that are merely surprising. The `curl-urlapi-rs` port reproduces every one
of them on purpose. This file records what each one is, what a caller can
observe because of it, and which Rust module carries it.

Reproducing them is a directive rather than a preference. The Agent Action
Plan (`AAP`) states it at 0.8.1: where the implementation does something
that looks wrong or inconsistent with the documented contract, reproduce it
and record it, never fix it quietly. Transformation rule `T6` at 0.1.2.3
compresses the same principle to "faithful over correct". A quiet fix costs
twice.
The parity diff against the reference build fails, because the reference
keeps the old behavior. The next reader of the odd-looking Rust then has no
way to learn that the oddity was deliberate.

Every claim below cites a path and a line number. A reader is meant to open
the cited line and confirm for themselves that odd Rust matches odd C, so a
citation that does not resolve defeats the purpose of the file. Where a
claim rests on a measurement instead of on source, the measurement and the
configuration it was taken under are stated with it.

Several findings carry a measurement, and each of those was taken the same
way: a small C program calling the API through `include/curl/urlapi.h`,
linked against an archive of unmodified libcurl built from this tree, run
under `LC_ALL=C.UTF-8`. Numbers shown as `rc=` are `CURLUcode` values. One
probe also calls `Curl_url_set_authority()`, which the public header does
not declare, so it declares the entry point itself against the symbol the
archive already exports.

Paths that start with `src/`, `tests/` or `include/` and no repository
directory in front of them are relative to `rust-urlapi/`. Every other path
is relative to the repository root.

Build steps, feature tables and script ordering are deliberately absent.
They belong to `../README.md`, which is the short entry point to the same
material.

## How to read this catalog

The findings are graded. A record that calls everything a bug is less
useful than one that says which is which.

- `FB1`, a defect: handle duplication drops the guessed-scheme flag.
- `FB2`, a defect that also leaks: the credential exit path sets three
  handle fields to null without releasing what they held.
- `FB3`, a defect that also leaks: the zone identifier is stored over an
  existing value, and no path clears it.
- `FB4`, intentional: a colon with no digits after it is accepted, though
  only when the URL has a scheme.
- `FB5`, cosmetic: one declaration in the public header names no parameter.
  Harmless in itself, it still constrains a generated file.
- `FB6`, neither a bug nor cosmetic: two writes land one byte past the
  logical length, which the Rust buffer has to allow for.

Two further entries follow the six. Neither is a reproduced oddity. The
`idn-pure` backend is a real divergence in an optional configuration, and
the empty-string rule is documented behavior with an undocumented
sensitivity to flags.

## `FB1`: duplication drops the guessed-scheme flag

### What the C code does

`curl_url_dup()` begins at `lib/urlapi.c:L1310`. It allocates a zeroed
handle at L1312 through `curlx_calloc()`, then copies exactly ten strings
at L1314-L1323 with the `DUP` macro defined at L1301-L1308, in this order:
`scheme`, `user`, `password`, `options`, `host`, `port`, `path`, `query`,
`fragment` and `zoneid`. Three scalar members follow: `portnum` at L1324,
`fragment_present` at L1325 and `query_present` at L1326. The function
returns the new handle at L1328.

`struct Curl_URL` has one more member than that. `lib/urlapi.c:L81`
declares `BIT(guessed_scheme)`, described in the same line as set when a
URL without a scheme is parsed. It sits alongside the two bits that L1325
and L1326 do copy, at L79 and L80, and it is a member the parser really
sets: `guess_scheme()` assigns it at L1008 after choosing a scheme from the
hostname, falling back to `http` at L1002. Nothing in `curl_url_dup()`
copies it, so the copy always reports a scheme that came from the input
even when the original knows it guessed one.

### What follows from it

Two consequences are observable on the copy, and both need
`CURLU_NO_GUESS_SCHEME` to show up.

Asking the copy for the scheme returns the guessed scheme rather than the
no-scheme error. The guard at `lib/urlapi.c:L1559` tests
`(flags & CURLU_NO_GUESS_SCHEME) && u->guessed_scheme` before returning
`CURLUE_NO_SCHEME` at L1560. On the copy the second half of that condition
is false, so the guard does not fire.

Asking the copy for the whole URL emits the scheme prefix rather than
suppressing it. The condition at `lib/urlapi.c:L1512` writes `"%s://"` into
the scheme buffer at L1513 unless the caller passed the flag and the handle
recorded a guess, and clears the buffer at L1515 otherwise. On the copy it
takes the first branch and the prefix appears.

Both were measured against the reference build rather than reasoned about.
A handle parsed from `example.com:1234` with `CURLU_GUESS_SCHEME`, then
duplicated, answers like this:

Reading `CURLUPART_URL`:

    original, flags 0                 http://example.com:1234/
    copy,     flags 0                 http://example.com:1234/
    original, CURLU_NO_GUESS_SCHEME   example.com:1234/
    copy,     CURLU_NO_GUESS_SCHEME   http://example.com:1234/

Reading `CURLUPART_SCHEME` with the same flag:

    original, CURLU_NO_GUESS_SCHEME   rc=10
    copy,     CURLU_NO_GUESS_SCHEME   http

Return code 10 is `CURLUE_NO_SCHEME`. The prefix is `http` and not `https`
because L1002 is the fallback for a hostname matching none of the six
prefixes L989-L1000 test, and `https` at L84 belongs to
`CURLU_DEFAULT_SCHEME` instead.

### Why the test suite cannot catch it

Anyone can notice that a member is not copied. What makes the finding worth
trusting is that curl's own duplication test cannot see it, by
construction rather than by luck.

`urldup()` at `tests/libtest/lib1560.c:L1970` walks a table of inputs that
includes `"example.com:1234"` at L1985, which carries no scheme. It parses
each input with `CURLU_GUESS_SCHEME` at L1998-L1999, so for that entry the
original handle really does have the bit set. It duplicates the handle at
L2002.

Then it reads the whole URL back from both handles with a literal flag
argument of `0`: from the original at L2004 and from the copy at L2008, and
compares the two strings at L2012. With no flags, the condition at L1512
takes its first branch on both handles, both strings carry the `http://`
prefix the guess produced, and they match, which the first row of the table
above shows. The one flag that would expose the difference is the one the
test never passes.

### What the port does

The port reproduces it. `src/handle.rs` copies the ten strings and the
three scalar members and leaves the guessed-scheme flag clear on the copy,
which reproduces both consequences above.

## `FB2`: the credential exit path sets fields to null without freeing

### What the C code does

`parse_hostname_login()` spans `lib/urlapi.c:L248-L333`. Its shared exit
label `out:` sits at L323. Three lines there release the three local
pointers the function owns: `userp` at L325, `passwdp` at L326 and
`optionsp` at L327. The next three lines assign null to members of the
handle: `u->user` at L328, `u->password` at L329 and `u->options` at L330.
Nothing releases the values those three members held.

The contrast with the same function's success path is sharp. Where it
stores a parsed credential it releases the old value first: L305 frees
`u->user` before L306 stores the new one, and L310-L311 and L315-L316 do
the same for the password and the options. The handling is correct
everywhere except at the label.

The label is reached three ways, and one of them is a success:

- L273 looks for an `@` in the authority with `memchr()`. L274-L275 jump to
  the label when there is none, with `result` still holding the
  `CURLUE_OK` it was given at L254. Every URL without credentials in it
  takes this path.
- L292-L296 arrive after `Curl_parse_login_details()` fails, with `result`
  set to `CURLUE_OUT_OF_MEMORY`. The comment at L293-L294 records that
  running out of memory is the only failure that call can report.
- L300-L303 arrive when the caller passed `CURLU_DISALLOW_USER` and the
  input carried a username, with `result` set to
  `CURLUE_USER_NOT_ALLOWED`.

### Why it is harmless in one place and not the other

On the ordinary parse path nothing is lost. `parseurl_and_replace()` at
`lib/urlapi.c:L1197` declares a local `CURLU` at L1201, zeroes it at L1202
with `memset()`, and parses into that temporary at L1203. Only on success
does it release the live handle at L1205 and move the temporary into place
at L1206. The three members that L328-L330 overwrite are therefore already
null when the label runs, so setting them to null discards nothing.

The authority setter has no such temporary. `Curl_url_set_authority()` at
`lib/urlapi.c:L658-L675`, declared for the rest of libcurl at
`lib/urlapi-int.h:L31` and marked at L657 as being for HTTP/2 server push,
hands the caller's own handle to `parse_authority()` at L666-L667 together
with `CURLU_DISALLOW_USER`. Any credential the handle already held is
dropped at L328-L330 without being released.

How reachable that is deserves stating precisely rather than left as a
warning. The one caller in the tree, `lib/http2.c:L739`, creates a fresh
handle at L723 and sets only the scheme on it at L730 before calling the
setter, so nothing leaks there today. The leak is available to any caller
that hands over a handle already carrying credentials, which the signature
permits and nothing in the module prevents.

### What the port does

The port reproduces the observable behavior: the three parts read back as
absent after any of the three exits. `src/parse/authority.rs` carries it.
Rust ownership means the port cannot leak the previous values the way the C
code does, and dropping them instead of leaking them is not observable
through the API. `MEMORY-OWNERSHIP.md` holds the ownership context.

## `FB3`: the zone identifier is stored over an existing value

### What the C code does

`ipv6_parse()` spans `lib/urlapi.c:L390-L442`. Its zone branch runs from
L405 to L423 and ends by storing a fresh copy: L418 assigns
`curlx_strdup(zoneid)` to `u->zoneid`, with no release of an existing value
in front of it. Supporting detail from the same branch: the scratch buffer
is `char zoneid[16]` at L407, the copy loop at L413 stops at `i < 15`, and
L411 steps over a `25` pair when the percent sign arrived percent-encoded.

No path in the function clears the member. The whole branch is nested inside
the test at L403, which fires only when the address contains something
outside the character set L401 accepts, so a well-formed bracketed address
with no zone on it skips L403-L427 and leaves `u->zoneid` exactly as it was.
The `else` at L424 is not a clearing branch either: it returns
`CURLUE_BAD_IPV6` at L425.

### What follows from it

Two consequences, and the second is visible through the API. Both need the
live-handle path described under `FB2`, because the ordinary parse path
fills a zeroed temporary whose zone member starts out empty.

The first is the leak: a zone identifier already on the handle is dropped
without being released when a new address arrives.

The second is a stale read. Once a host carrying a zone has been replaced
through the authority setter by a plain hostname, the old zone identifier
stays readable even though it can no longer appear in the URL the handle
serializes. Serialization emits the zone only for a bracketed host:
`lib/urlapi.c:L1480` tests `u->host[0] == '['` and L1481 tests `u->zoneid`
before L1486 builds the `[ host %25 zone ]` form. Reading `CURLUPART_ZONEID`
goes through no such test, so the stale value comes back.

Measured against the reference build, starting from
`http://[fe80::a%25eth0]:80/path`:

    read ZONEID                    rc=0   eth0
    set authority to a plain name  rc=0
    read ZONEID                    rc=0   eth0
    read URL                       rc=0   http://plain.example.com:80/path

The zone survives a host that can no longer carry it, and it is absent from
the URL the same handle produces.

### The asymmetry worth recording

The public host setter does clear it. In `curl_url_set()` the
`CURLUPART_HOST` case at `lib/urlapi.c:L1846-L1849` calls
`Curl_safefree(u->zoneid)` at L1848 on the way to storing a new host, on the
reasoning that a zone belongs to the address it was written with. The
`CURLUPART_ZONEID` case at L1850-L1852 does nothing of the kind. Repeating
the measurement above through that setter instead of through the authority
setter reads the zone back as `rc=18`, which is `CURLUE_NO_ZONEID`. The same
replacement, two answers, decided by which entry point performed it.

The same contrast appears inside `Curl_url_set_authority()`, which handles
the host correctly and the zone not at all: L671 releases the previous
`u->host` before L672 stores the replacement. `MEMORY-OWNERSHIP.md` cites
that same L671 as the contrast case for this finding.

### What the port does

The port reproduces it. `src/parse/ipv6.rs` stores the zone identifier
without clearing a previous one and adds no clearing path, so a stale zone
stays readable after a host change and stays invisible in the serialized
URL.

## `FB4`: a colon with no digits is accepted, with a scheme

### What the C code does

`Curl_parse_port()` spans `lib/urlapi.c:L335-L387`. Having found a colon,
it records the length of the name in front of it at L361, cuts the name
there with `curlx_dyn_setlen()` at L370, and steps past the colon at L371.
When nothing follows, L372-L373 return
`has_scheme ? CURLUE_OK : CURLUE_BAD_PORT_NUMBER`.

A trailing colon with no port after it is therefore accepted. The colon goes
away with the cut at L370, no port is recorded at all, and the default port
for the scheme is available on request. Only the host is shortened: the cut
applies to the host buffer, so a path after the colon survives untouched.
Without a scheme the same input is rejected with `CURLUE_BAD_PORT_NUMBER`.

The rationale is in the source, as a comment at L363-L369. Paraphrased,
because the original ends in an exclamation mark: browsers behave this way,
so curl adapts to them and ignores the empty port, and the condition on the
scheme is there to stop a long run of characters followed by a colon from
being taken for a scheme.

### Which flag supplies the scheme decides the outcome

The `has_scheme` argument is not the caller's flag word. `parse_authority()`
receives it at `lib/urlapi.c:L1149-L1150` as `u->scheme != NULL`, evaluated
at that moment. Two flags both supply a scheme for input that carries none,
and they act at different moments. `CURLU_DEFAULT_SCHEME` stores one during
scheme parsing, at L967-L968 into the variable that L977 duplicates onto the
handle, which is before the authority is parsed. `CURLU_GUESS_SCHEME` runs
`guess_scheme()` at L1151-L1152, which is after. One input therefore lands
on both sides of L373. Measured against the reference build, each on a fresh
handle:

    input                       flags                  result
    "http://example.com:"       0                      rc=0
    "http://example.com:/path"  0                      rc=0
    "example.com:"              CURLU_DEFAULT_SCHEME   rc=0
    "example.com:"              CURLU_GUESS_SCHEME     rc=4
    "http://[fe80::a]:"         0                      rc=0
    "[fe80::a]:"                CURLU_GUESS_SCHEME     rc=4

Return code 4 is `CURLUE_BAD_PORT_NUMBER`. The four accepted rows read their
URL back with the colon gone, in the same order:
`http://example.com/`, `http://example.com/path`, `https://example.com/` and
`http://[fe80::a]/`. None of them stores a port, so reading `CURLUPART_PORT`
answers `rc=15`, which is `CURLUE_NO_PORT`, while the same read with
`CURLU_DEFAULT_PORT` answers `80`.

The two bracketed rows are there because the leniency covers addresses as
well as names. The bracket arm at L343-L354 accepts a colon after the
closing bracket at L350 and falls through to L359 with `portptr` pointing at
it, which is the same path a name takes.

### What the port does

This one is intentional rather than a bug, and it is listed here because it
surprises readers rather than because it is wrong. The port reproduces it
exactly, including the ordering above, which means it has to compute
`has_scheme` at the same point in the pipeline rather than from the flags.
`src/parse/port.rs` carries the leniency and `src/parse/mod.rs` the ordering
that feeds it.

## `FB5`: one declaration names no parameter

`include/curl/urlapi.h:L149` declares the error-string function as

    CURL_EXTERN const char *curl_url_strerror(CURLUcode);

with no name on the parameter. Its man page names one:
`docs/libcurl/curl_url_strerror.md:L28` gives the synopsis as
`const char *curl_url_strerror(CURLUcode errornum);`. Every other
declaration in that header that takes a parameter names it, which is what
makes L149 stand out: `curl_url_cleanup()` at L120, `curl_url_dup()` at
L126, `curl_url_get()` at L133-L134 and `curl_url_set()` at L141-L142.

The mismatch changes no behavior at all. It constrains a deliverable
instead. The generated mirror header, `include/curl_urlapi_rs.h`, exists so
that a consumer with no libcurl in the link still sees the same
declarations, and it has to leave the parameter unnamed as well rather than
improve on the original. A generator left to its own devices emits a name,
so this is a case where fidelity means matching a cosmetic detail on
purpose.

## `FB6`: two writes land one byte past the logical length

`ipv6_parse()` writes a terminator one byte beyond the length it is
tracking, in two places. Neither write leaves the allocation, and saying
where they do land is the whole content of the finding.

The function shifts its view of the string first: L397 advances `hostname`
past the opening bracket and L398 takes two off `hlen` for the pair of
brackets. From then on `hostname[0]` is the first byte of the address and
`hlen` counts the address alone, so index `hlen` is the closing bracket and
index `hlen + 1` is the byte holding the terminator for the string as a
whole.

The first write is in the zone branch. `lib/urlapi.c:L421` puts the closing
bracket back at `hostname[len]` and L422 terminates the string at
`hostname[len + 1]`. Room is guaranteed here because `len` stopped short of
the zone text that follows in the input.

The second write follows normalization and is the tight one. L432 ends the
address at `hostname[hlen]` for the benefit of `curlx_inet_pton()` at L433,
L435 writes the address back through `curlx_inet_ntop()` with room for
`hlen + 1` bytes, and L436 recomputes `hlen` with `strlen()` because the
normalized form can come out shorter. L437 then terminates at
`hostname[hlen + 1]` before L439 restores the closing bracket at
`hostname[hlen]`. When normalization shortens nothing, that terminator write
lands exactly on the last byte of the string, one past the closing bracket.

### What the port does

The port keeps that byte addressable rather than trimming the host to its
logical length, which is what makes this a constraint on the port instead of
a note about the original. A host modeled as a byte slice of exactly the
logical length has nowhere to put the write, and trimming instead would
change behavior for input at the maximum length, so it is not an option.
`src/parse/ipv6.rs` and `src/dynbuf.rs` carry the requirement between them:
the buffer provides the writable terminator byte, and the parser is the only
thing that uses it.

## Residual divergence: the `idn-pure` backend

The six findings above are oddities kept on purpose. This one is different.
It is a genuine divergence, it exists only in an optional configuration, and
saying so plainly is the whole point of listing it.

The default backend, `idn-libidn2`, binds the same C library curl binds and
replays the sequence in `lib/idn.c` call for call, so parity with the
reference build costs nothing extra. The alternative backend, `idn-pure`,
uses the `idna` crate and no C library. It is not equivalent. Five
differences are known.

### No transitional retry

`idn_decode()` at `lib/idn.c:L247` builds its flag word at L253 from
`IDN2_NFC_INPUT`, adding `IDN2_NONTRANSITIONAL` at L258 only inside the
version test at L254-L259 that requires `IDN2_VERSION_NUMBER` to be at
least `0x00140000`. It calls the lookup with those flags at L261. When that
call reports anything other than `IDN2_OK`, L262-L265 call the lookup a
second time with `IDN2_TRANSITIONAL` instead, which the comment at
L263-L264 explains as a fallback for better `IDNA2003` compatibility. Only
if the retry also fails does L267 produce an error.

The `idna` crate offers no equivalent second attempt. A name that the C
path converts only on the retry fails under `idn-pure`.

### Locale independence, which inverts the usual direction

This is the sharp one, and it runs the opposite way from what a reader
expects: the Rust path succeeds where the C path fails.

curl reaches the library through a macro. `lib/idn.c:L39-L40` defines
`IDN2_LOOKUP` as `idn2_lookup_ul`, the entry point that interprets its
input in the encoding of the process locale, and only a Windows build with
wide characters gets the byte-oriented `idn2_lookup_u8` at L36-L37 instead.
Conversion of a non-ASCII hostname therefore succeeds only when the codeset
of the process locale is UTF-8. Under any other codeset the library
converts nothing, and the module turns that failure into
`CURLUE_BAD_HOSTNAME`. The `idna` crate reads its input as Rust text, which
is UTF-8 by definition, so it is indifferent to the locale and converts the
same name either way.

That was measured rather than taken on trust. The probe was a C program
calling `idn2_lookup_ul` with `IDN2_NFC_INPUT | IDN2_NONTRANSITIONAL`,
followed by the `IDN2_TRANSITIONAL` retry, after `setlocale(LC_ALL, "")`,
linked against `libidn2` 2.3.8, whose `IDN2_VERSION_NUMBER` of `0x02030008`
clears the version test at L254 so that the non-transitional flag is live.
The same three non-ASCII names went in under both settings, in the same
order, and are written here only as the punycode that came out:

    LC_ALL=C.UTF-8   rc=0     became xn--rksmrgs-5wao1o.se
                     rc=0     became xn--fa-hia.de
                     rc=0     became xn--fiq228c.tw
    LC_ALL=C         rc=-102  could not convert string to UTF-8
                     rc=-102  could not convert string to UTF-8
                     rc=-102  could not convert string to UTF-8

An ASCII name passed through unchanged with `rc=0` under both, so the
codeset governs non-ASCII input alone. The first result is the one curl's
own suite expects:
`tests/libtest/lib1560.c:L630-L631` asserts that host, guarded by
`#ifdef USE_IDN` at L629, against the punycode form
`https://xn--rksmrgs-5wao1o.se/path?q#frag` with `CURLU_PUNYCODE`.

Reproducing the C failure under `idn-pure` would take an explicit check of
the locale codeset before conversion, deliberately failing input the crate
could convert. The backend does not do that, and the divergence stands
recorded instead.

### Different Unicode tables

Each backend brings its own copy of the Unicode data that case mapping and
normalization consult, and the two copies are versioned independently. On
the C side the tables belong to whichever `libidn2` the link found. On the
Rust side they arrive as data packages of their own, named in
`rust-urlapi/Cargo.lock` as `icu_normalizer_data` and
`icu_properties_data`. Nothing keeps the two
in step, so a name near the edge of a mapping table can convert one way
under one backend and another way, or not at all, under the other.

### Dependency weight

The default configuration has one dependency, `libc`. Turning on `idn-pure`
adds `idna` and everything `idna` needs, which takes the crate from one
dependency to thirty. That count is the transitive closure of `libc` and
`idna` over the committed `rust-urlapi/Cargo.lock`, so a reader can
recompute it from the file rather than trust it.

### A higher compiler floor, which is the deciding factor

Size is not what settles this. Under a release profile with link-time
optimization, one code-generation unit, abort-on-panic, and the alternative
path reachable from an exported symbol so that it cannot be optimized away,
the measurement recorded in the `AAP` at 0.5.1.2 is 7,526,790 bytes of
archive by default against 7,739,832 bytes with the feature on. The
difference of 213,042 bytes is too small to decide anything.

The compiler floor settles it. Eight packages in that dependency closure
declare `rust-version = "1.86"` in their own manifests: `idna_adapter`
1.2.2, and `icu_collections`, `icu_locale_core`, `icu_normalizer`,
`icu_normalizer_data`, `icu_properties`, `icu_properties_data` and
`icu_provider`, all at 2.2.0. Six of those are the components the `AAP`
counts at 0.5.1.2; the two generated data packages declare the same floor.
Cargo refuses to build a package whose dependency asks for a newer compiler
than the one in use, so the whole crate inherits 1.86 the moment the
feature goes on.

That is above both floors this work is held to. `rust-urlapi/Cargo.toml:L46`
declares `rust-version = "1.75"`, and curl's own documented floor is the
1.73 toolchain at `docs/RUSTLS.md:L59`. Moving the requirement eleven minor
releases past the crate's own declared floor, to avoid one C library, is a
poor trade, which is why `idn-pure` is off by default and why the default
backend is the one these parity claims cover.

### The locale chain a reader needs

Anyone chasing this divergence through the test suite needs to know that
the assertions it touches are gated, and that the gate has four moving
parts. Miss any one and the assertions still pass while exercising
nothing.

- The harness entry point calls the locale initializer, exactly as the real
  one does at `tests/libtest/first.c:L231` inside the `HAVE_SETLOCALE`
  guard at L230. Without that call the process keeps the C locale, whose
  codeset is not UTF-8, and every conversion above fails.
- The test definition sets the locale for the run:
  `tests/data/test1560:L14` carries `LC_ALL=C.UTF-8` inside the `setenv`
  block opened at L13.
- The runner exports the marker. `tests/runtests.pl:L837-L839` sets
  `CURL_TEST_HAVE_CODESET_UTF8` in the environment when the codeset
  feature it computes at L836 is available.
- The test source reads that marker at `tests/libtest/lib1560.c:L2036` and
  passes the result into three sub-tests, which use it at L1446, L1548 and
  L1591 to run their punycode cases only when it is set:
  `setget_parts()` at L1434, `get_url()` at L1537 and `get_parts()` at
  L1580.

State it plainly: the parity claims apply to the default backend.
`idn-pure` is supported, and it is not bit-for-bit.

## The empty-string rule and its hidden flag sensitivity

Setting the whole URL to an empty string on a handle that already holds one
is a success that changes nothing, rather than an error. That much is
intended and stated. What no reading of the API documentation reveals is
that the outcome depends on the flags the caller passed.

### The documented half

`set_url()` spans `lib/urlapi.c:L1685-L1730`. L1697 tests the length of the
supplied value, and for a length of zero the comment at L1698-L1699
records the intent: an empty URL is not valid on its own, and is accepted
only because a complete URL is already present and this is a redirect.
L1700 reads the whole URL back out of the handle. On success L1704 releases
that copy and L1705 returns `CURLUE_OK`, having changed nothing. Running
out of memory passes through unaltered at L1707-L1708. Anything else
becomes `CURLUE_MALFORMED_INPUT` at L1709.

### The undocumented half

The read at L1700 is handed the caller's own `flags`, unfiltered. Whether
the empty string is a success therefore depends on whether the handle can
produce a whole URL under exactly those flags. Two of the ways that read can
fail sit close together in `urlget_url()`: L1448-L1449 returns
`CURLUE_NO_HOST` when the handle has no host, and L1453-L1458 returns
`CURLUE_NO_SCHEME` when the handle has no scheme and the caller did not pass
`CURLU_DEFAULT_SCHEME`, which L1455-L1456 would otherwise substitute. L1709
turns either one into `CURLUE_MALFORMED_INPUT`.

A handle with a host and no scheme is reachable through the public API:
parse any absolute URL, then clear the scheme, which `urlset_clear()` does
at L1739-L1742. Measured against the reference build, starting from
`http://example.com/path` with the scheme cleared:

    read  URL,  flags 0                rc=10
    read  URL,  CURLU_DEFAULT_SCHEME   rc=0   https://example.com/path
    write "",   flags 0                rc=3
    write "",   CURLU_DEFAULT_SCHEME   rc=0

Return code 10 is `CURLUE_NO_SCHEME` and 3 is `CURLUE_MALFORMED_INPUT`. One
handle, one empty string, opposite outcomes decided by a flag that describes
how to read a URL rather than how to write one.

### A neighboring flag that does not behave this way

`CURLU_NO_GUESS_SCHEME` looks like it belongs in the paragraph above and
does not. On a handle whose scheme was guessed, writing an empty string
returns `CURLUE_OK` whether that flag is passed or not, which was measured
alongside the table above.

The reason is that the flag has two unrelated effects, in two different
branches of the reader. In the `CURLUPART_SCHEME` branch it is an error:
L1559-L1560 return `CURLUE_NO_SCHEME`. In the whole-URL branch it is only a
formatting choice: L1512-L1515 blank the scheme prefix and carry on
returning `CURLUE_OK`. L1700 asks for `CURLUPART_URL`, so it meets the
second behavior and never the first.

A port that reused one guard for both branches would fail here where the C
code succeeds, and the parity diff would report it as a difference in
`set_url()` rather than in the reader where the mistake actually lives.

For completeness on the surrounding dispatch: a value that is not empty goes
to the absolute-URL test at L1713-L1714, which is passed the caller's flags
narrowed to the bitwise or of `CURLU_GUESS_SCHEME` and
`CURLU_DEFAULT_SCHEME`, and an absolute value replaces the contents through
`parseurl_and_replace()` at L1715.

### What the port does

`src/getset.rs` carries the empty-string rule, passes the caller's flags
into the read exactly as L1700 does, and keeps the two effects of
`CURLU_NO_GUESS_SCHEME` apart so that the whole-URL branch blanks a prefix
where the part branch reports an error.

## Why every one of these stays

Each finding above is reproduced deliberately, under the directive in the
`AAP` at 0.8.1 and transformation rule `T6` at 0.1.2.3. None of them is an
accident of the port, and none is a defect to be filed against it.

The catalog is kept honest by a test rather than by good intentions.
`tests/ffi_surface.rs` asserts these behaviors through the C entry points,
so a later attempt to tidy one of them up breaks a test instead of passing
unnoticed, and whoever hits that test arrives here to find out why.

Acceptance criterion `A10` in the `AAP` at 0.9.2 requires all six findings
to be preserved and recorded in this file, which is why the record and the
code are expected to move together. A finding that stops being true belongs
in a commit that removes it from both.

### Two claims corrected against the source

Writing this file meant checking each claim against `lib/urlapi.c` and
against the reference build, and two claims carried in the `AAP` did not
survive that check. They are recorded here so that nobody restores them from
the plan and so that no module is built to match them.

The first is the mechanism behind the empty-string flag sensitivity. The
`AAP` at 0.6.5 attributes it to `CURLU_NO_GUESS_SCHEME` reaching the guard
at L1559-L1560. Measurement puts that at `CURLUE_OK`, because L1700 reads
`CURLUPART_URL` and that guard belongs to the `CURLUPART_SCHEME` branch. The
sensitivity is real and runs through `CURLU_DEFAULT_SCHEME` and L1455-L1458
instead, which the table above demonstrates. A port built to the original
wording would return `CURLUE_MALFORMED_INPUT` where the C code returns
success.

The second is smaller. A scheme produced by guessing is `http`, from L1002,
and not the `https` of L84, which belongs to `CURLU_DEFAULT_SCHEME`. Both
appear in `FB1` above with the measurement that settles them.

## See also

- [MEMORY-OWNERSHIP.md][ownership] holds the ownership context behind
  `FB2` and `FB3`: how `curl_free()` resolves, every allocation site in the
  module, and the rules the crate follows at the boundary.
- [PORTING-NOTES.md][porting] maps the C functions onto the Rust modules,
  and so names the owner of each finding above in its wider context.

[ownership]: MEMORY-OWNERSHIP.md
[porting]: PORTING-NOTES.md
