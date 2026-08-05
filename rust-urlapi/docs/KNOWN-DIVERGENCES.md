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

Reproducing them is a requirement of the port rather than a preference:
where `lib/urlapi.c` does something that looks wrong or inconsistent with
the documented contract, this crate does the same thing and records it here.
Faithful beats correct, because a quiet fix costs twice.
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

**Every path in this file is relative to the repository root, with no
exceptions.** Files belonging to this crate are therefore written out in
full, `rust-urlapi/src/handle.rs` rather than `src/handle.rs`, so that a
citation can be pasted into an editor or a `git` command without a reader
first having to work out which of two roots it hangs from. The earlier
convention here made a bare `tests/` or `include/` crate-relative,
which collided with the repository's own `tests/` and `include/`
directories; it is gone.

Two statements about state, so that nothing below is read as a completion
claim. The crate is under construction: at the time of writing,
`rust-urlapi/src/` holds `abi.rs`, `alloc.rs`, `ctype.rs`, `decode.rs`,
`dynbuf.rs`, `encode.rs`, `error.rs`, `handle.rs`, `idn.rs`, `inet.rs`,
`scheme.rs`, `strparse.rs` and `parse/junk.rs`, and nothing else. Wherever
this file cites a module, a test, a script or a generated file absent from
that list -- the parser stages beyond the junk scan,
`rust-urlapi/src/getset.rs`, `rust-urlapi/src/ffi.rs`,
`rust-urlapi/include/curl_urlapi_rs.h`, `rust-urlapi/tests/ffi_surface.rs`,
`rust-urlapi/README.md` -- the sentence is a requirement on work still to be
done and is worded as one. Present tense is reserved for what a reader can
open today.

Build steps, feature tables and script ordering are deliberately absent.
They belong to `rust-urlapi/README.md`.

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

Nine further entries follow the six, and none of them is a reproduced oddity.
Four are residual divergences of the port itself, in configurations the plan
permits rather than in the reproduced behavior:

- the `idn-pure` backend, a real divergence in an optional configuration;
- the generated mirror header, which `cbindgen` cannot be made to emit
  byte-identically to a hand-authored one;
- the harness shim's `snprintf` return value, which differs from curl's own
  while the bytes it writes do not, recorded twice because two files point at
  it under two names;
- the same shim's `curl_msnprintf` face, for the same reason.

Three are neither divergences nor defects but constraints the plan requires to
be reported rather than worked around: the libidn2 version guard needs the
installed header and the build refuses rather than guessing without it;
`cargo-c` demands a seventh feature the plan does not permit; and drop-in mode
reads libcurl's scheme descriptors through a mirror that assumes a 32-bit
`curl_prot_t`, which no assertion written in Rust can check.

One records a claim that was checked and found untrue -- there is no
dynamic-buffer cleanup omission in `lib/urlapi.c` -- because two comments in
the port used to say there was, and a reader following them deserves to land
on the correction rather than on nothing.

The last is the empty-string rule: documented behavior with an undocumented
sensitivity to flags.

Then comes a third class, four entries headed `Integration limitation`. These
are not things `lib/urlapi.c` does at all. They are places where the port's
own packaging cannot reproduce the original exactly -- where the *drop-in* is
imperfect rather than the *behavior* -- and where a reader told nothing would
reasonably file the difference as a bug. They are listed here because four
in-scope files send readers to this document expecting to find them, and one
of those pointers reaches the end user's terminal verbatim, in a warning
Cargo prints.

- The generated mirror header cannot be byte-equal to the committed one.
  Four `cbindgen` limitations, one claim that turned out to be unreachable,
  and the three implementation constants that had to be excluded by name.
- The standalone scheme table models one build's protocol set, because a
  build with no protocol implementations of its own has to model the one the
  parity harness compares against. This is the one link-mode feature whose
  misuse is silent rather than a link error.
- Drop-in mode presumes a 32-bit `curl_prot_t`, and no assertion written in
  Rust can check the C side of that.
- The standalone `snprintf` shim returns the C99 count rather than curl's,
  and is compiled to C99 where the rest of the harness holds to C89.

Twenty-three entries in total: six graded findings, nine further entries, four
integration limitations, and four closing sections -- why they all stay, the
drop-in mirror's private-layout limitation, the architecture record, and the
index of what points here. Three topics are deliberately recorded twice, under
the name each pointing file uses for it: the generated header, the shim's
return value, and the 32-bit `curl_prot_t` precondition. A pointer that does
not resolve is as much a defect as an unrecorded divergence, so the duplicates
stay until the pointers are unified. The count is stated so that a gap reads as
a gap: if something is missing from this file, the file is wrong.

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

The port reproduces it. `rust-urlapi/src/handle.rs` copies the ten strings
and the three scalar members and leaves the guessed-scheme flag clear on the
copy, which reproduces both consequences above.

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

### What the port does, and the half it does not reproduce

`FB2` has two halves, and the port reproduces one of them. Saying so plainly
matters more than a tidy claim of fidelity, because the plan's acceptance
criterion `A10` at `AAP` 0.9.2 asks for all six findings to be preserved,
and a reviewer checking that against a blanket "reproduced" would be
checking against the wrong statement.

**Reproduced -- the API-visible half.** The three parts read back as absent
after any of the three exits, including the success exit that every URL
without credentials takes. `rust-urlapi/src/parse/authority.rs` is to carry
that; the module is not written yet.

**Not reproduced, and reported here as a residual divergence -- the leak.**
The C discards the previous `u->user`, `u->password` and `u->options`
without releasing them, as L328-L330 show. The port cannot: the fields are
owned buffers, so replacing them with the absent value runs `Drop` and
releases the old ones. Reproducing the leak would mean deliberately
constructing a leak in Rust -- suppressing `Drop` on three live
allocations -- and this port does not do that. The divergence is therefore
real and is recorded rather than hidden:

| Aspect | C | This port |
|---|---|---|
| The three parts after any exit | absent | absent, identical |
| The previous values | leaked | released |
| Observable through the public API | no | no |

The last row is why the divergence is safe rather than why it does not
exist. No sequence of `curl_url_get()`, `curl_url_set()` or
`curl_url_dup()` calls can distinguish a leaked buffer from a released one;
only an allocation counter or a leak checker can, and `AAP` 0.2.4.3 already
records that the parity harness runs without curl's counter. A reader
measuring allocations across `Curl_url_set_authority()` on a handle that
carried credentials finds the two implementations differ, and this
paragraph is the reason.

`MEMORY-OWNERSHIP.md` holds the ownership context, and points back here for
exactly this entry.

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

The port is to reproduce it: `rust-urlapi/src/parse/ipv6.rs`, when written,
stores the zone identifier without clearing a previous one and adds no
clearing path, so a stale zone stays readable after a host change and stays
invisible in the serialized URL.

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
URL back with the colon gone, and none of them stores a port, so reading
`CURLUPART_PORT` answers `rc=15`, which is `CURLUE_NO_PORT`. The same read
with `CURLU_DEFAULT_PORT` answers the default for whichever scheme the row
ended up with, which is not one number for all four:

    input                       URL read back           default port
    "http://example.com:"       http://example.com/      80
    "http://example.com:/path"  http://example.com/path  80
    "example.com:"              https://example.com/     443
    "http://[fe80::a]:"         http://[fe80::a]/        80

The third row is the one that differs, and the reason is worth naming rather
than leaving to be rediscovered: `CURLU_DEFAULT_SCHEME` supplies
`DEFAULT_SCHEME`, which is `"https"` at `lib/urlapi.c:L84`, so that row
serializes as HTTPS and its default port is 443 per
`lib/urldata.h:L29-L53`. Only the three rows that carry `http` answer `80`.
A guessed scheme would have given `http` and therefore 80; `FB1` above
carries the measurement that separates the two mechanisms.

The two bracketed rows are there because the leniency covers addresses as
well as names. The bracket arm at L343-L354 accepts a colon after the
closing bracket at L350 and falls through to L359 with `portptr` pointing at
it, which is the same path a name takes.

### What the port does

This one is intentional rather than a bug, and it is listed here because it
surprises readers rather than because it is wrong. The port reproduces it
exactly, including the ordering above, which means it has to compute
`has_scheme` at the same point in the pipeline rather than from the flags.
`rust-urlapi/src/parse/port.rs` is to carry the leniency and
`rust-urlapi/src/parse/mod.rs` the ordering that feeds it. Neither module
exists yet.

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
instead. The generated mirror header,
`rust-urlapi/include/curl_urlapi_rs.h`, is to exist so that a consumer with
no libcurl in the link still sees the same declarations, and it has to leave
the parameter unnamed as well rather than improve on the original. A
generator left to its own devices emits a name, so this is a case where
fidelity means matching a cosmetic detail on purpose. That header is not
written yet; the constraint is recorded here in advance of it.

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
`rust-urlapi/src/dynbuf.rs` and `rust-urlapi/src/parse/ipv6.rs` are to carry
the requirement between them: the buffer provides the writable terminator
byte, and the parser is the only thing that uses it. The buffer half exists
today and documents the capacity it guarantees; the parser half does not.

## Residual divergence: the `idn-pure` backend

The six findings above are oddities kept on purpose. This one is different.
It is a genuine divergence, it exists only in an optional configuration, and
saying so plainly is the whole point of listing it.

The default backend, `idn-libidn2`, binds the same C library curl binds and
replays the sequence in `lib/idn.c` call for call, so parity with the
reference build costs nothing extra. The alternative backend, `idn-pure`,
uses the `idna` crate and no C library. It is not equivalent. Six
differences are known, and the fourth of them is the one that decides the
default: an allocation failure inside that backend does not produce curl's
out-of-memory code, it ends the process.

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

### An allocation failure is reported, and the residue is `idna`'s own

This entry used to record an abort. It no longer does, and the change is worth
stating because the reasoning that justified the abort was wrong on a point of
fact.

`idn_decode()` and `idn_encode()` under `idn-pure` do not call
`idna::domain_to_ascii` and `idna::domain_to_unicode`. Those build a `String`
through Rust's global allocator, whose failure handler aborts the process,
where `docs/libcurl/curl_url_set.md` documents `CURLUE_OUT_OF_MEMORY` as the
answer to an allocation failure and `lib/idn.c:L286-L288` maps libidn2's own
`IDNA_MALLOC_ERROR` onto `CURLE_OUT_OF_MEMORY`. For a library linked into
someone else's program, an abort there is a denial of service rather than an
inconvenience.

The `idna` crate does expose a fallible entry point: `Uts46::process` writes
into a caller-supplied sink and reports `ProcessingError::SinkError` when the
sink refuses. `src/idn.rs` supplies one. `CSink` accumulates into a
[`DynBuf`], which is curl's own buffer that grows over the **C** allocator, so
the bytes are in the right allocator from the first write rather than being
copied into it at the end; the ceiling is `CURL_MAX_INPUT_LENGTH`
(`lib/urldata.h:L131`), which is the ceiling `Curl_junkscan()` already holds
the whole URL to at `lib/urlapi.c:L229-L230`; and a refused write sets a
sticky flag that `CSink::finish` turns into `CURLE_OUT_OF_MEMORY`. The
conversion itself is unchanged -- the same option set the crate's own
convenience entry points use for these two operations -- so only the
allocation path is different.

What remains is not this crate's to guard. `Uts46::process` allocates
internally while it normalizes, through Rust's global allocator, and no API
makes those allocations fallible, which narrows the abort from "every result
string" to "the crate's internal working set", which is smaller and no longer
proportional to the input, but it is not zero. That is the residue, and it is
one of the reasons parity is claimed for the libidn2 backend alone.

The configuration is also no longer refused. `idn-pure` is one of the six
features the manifest offers, so a build that selects it is using the manifest
as designed, and making it fail would turn a documented opt-in into a broken
one. Instead `build.rs` emits a `cargo:warning` on every build that selects
the backend, naming the four divergences and pointing here, and `src/idn.rs`
still carries a `compile_error!` for the one configuration that is genuinely
contradictory -- both backends at once.

### Dependency weight

Turning on `idn-pure` adds `idna` and everything `idna` needs. The exact
figures, and the convention they are counted under, because a bare number
here has been got wrong before:

| Configuration | Distinct names | Lock entries |
|---|---|---|
| Default or drop-in, `libc` only | 1 | 1 |
| With `idn-pure` | 30 | 31 |
| Added by `idn-pure` | +29 | +30 |

Two conventions, because a bare number here has been got wrong before. The
first column counts distinct package *names*; the second counts `[[package]]`
entries in the committed `rust-urlapi/Cargo.lock`, which is one higher because
`syn` is resolved at two versions and both are real entries in the closure.
Either column is reproducible from the tree rather than taken on trust:

    cargo tree --locked --no-default-features --features idn-pure \
      --prefix none --no-dedupe | sed 's/ v[0-9].*//' | sort -u

The `genheader` closure adds one more name, `cbindgen` itself, and nothing
else: its own default features -- the command-line front end and the whole
`clap` chain behind it -- are switched off in `Cargo.toml`, which both
reduces the supply chain and keeps that configuration inside the declared
minimum toolchain.

A caution about a shortcut that gives a different answer. Counting the whole
lock file,

    grep -c '^\[\[package\]\]' rust-urlapi/Cargo.lock

reports every package any configuration can reach, `cbindgen`'s generator tree
included, and so overstates what an `idn-pure` build compiles. The per-feature
`cargo tree` recipe above is the one to quote, and the two columns of the table
are what it produces.

Substituting `--no-default-features --features idn-libidn2` for the feature
selection gives the other one. The whole lock file pins 75 dependency
packages, which is larger than either closure because it is the union over
every feature and every target: `genheader` reaches 31 packages of its own
through `cbindgen`, and the `windows-*` and `wasi` packages `getrandom` names
are locked for platforms this work does not build for.

### The dependency closure the compiler floor pins

Size is not what settles this, and neither, on its own, is the compiler
floor. Under a release profile with link-time optimization, one
code-generation unit, abort-on-panic, and the alternative path reachable from
an exported symbol so that it cannot be optimized away, the measurement
recorded in the `AAP` at 0.5.1.2 is 7,526,790 bytes of archive by default
against 7,739,832 bytes with the feature on. The difference of 213,042 bytes
is too small to decide anything. The abort described above is what decides
it.

The compiler floor is still a real constraint on which versions may be
locked, and it is the reason the closure is pinned rather than left to float.
`rust-urlapi/Cargo.toml` declares `rust-version = "1.75"`, curl's own
documented floor is the 1.73 toolchain at `docs/RUSTLS.md:L59`, and Cargo
refuses to build a package whose dependency asks for a newer compiler than
the one in use -- so a closure containing a single package that declares a
higher floor makes the whole crate impossible to build at the version this
work is held to. The `icu` line that `idna` reaches through `idna_adapter` has
releases on both sides of that boundary: the 2.x series declares
`rust-version = "1.86"`, eleven minor releases past this crate's own floor,
while the 1.5 series builds at 1.75. `rust-urlapi/Cargo.lock` therefore has
to pin the closure that satisfies the declared minimum, and
`cargo +1.75.0 check --locked --no-default-features --features idn-pure` is
the check that keeps it honest.

Three mechanical details decide whether that check passes, and none of them
can be read off the lock file alone.

- Regeneration needs the resolver told which compiler it is resolving for.
  A plain `cargo generate-lockfile` under a current toolchain selects the
  newest compatible release of every package and lands squarely on the `icu`
  2.x line. Setting `CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback`
  makes the resolver prefer versions whose declared `rust-version` the
  crate's own floor satisfies, which is what produces the pinned closure.
- A manifest can break the floor without contributing a single line of
  compiled code. `getrandom` 0.3.4 names `wasip2`, which names
  `wit-bindgen`, whose manifest uses an edition a 1.75 Cargo cannot parse.
  Those packages are selected only for `wasm32-wasip2` and are never built
  here, yet Cargo still reads their manifests, so the lock file pins
  `getrandom` 0.3.1 instead. Regenerating without that pin reintroduces the
  chain, which is why the constraint is written down rather than left to be
  rediscovered.
- The `genheader` closure is deliberately narrow. `cbindgen` is declared with
  `default-features = false`, because its default feature set builds a
  command-line front end and pulls `clap` and the terminal-styling chain
  behind it. `build.rs` uses the library API alone, so those twelve packages
  would be supply chain surface and nothing else, and dropping them is also
  what brings the `genheader` closure inside the declared floor. The reason
  they mattered at all is worth naming: `cbindgen`'s generator shells out to
  `cargo metadata`, which parses every locked manifest whether the build
  needs it or not, so with `genheader` on, an out-of-floor manifest anywhere
  in the lock file is a build failure rather than a dormant entry.

Pinning an older `icu` line has a consequence of its own, and it belongs
with the Unicode-table divergence above rather than hidden here: the data
those packages carry is older than what a current `libidn2` was built with,
so the two backends are further apart on names near the edge of a mapping
table, not closer. That is another reason the parity claims cover the default
backend only.

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

## Residual divergence: the generated mirror header

`include/curl_urlapi_rs.h` is the standalone consumer's copy of the public
declarations, a one-for-one mirror of `include/curl/urlapi.h:34-149`. It is
**hand-authored and committed**, and the `genheader` feature compares rather
than writes. This entry records why the two can never be byte-identical, so
that a reported difference is read modulo a known list instead of being
mistaken for drift.

Five differences are imposed by `cbindgen` 0.29.4 itself. Four are
unconditional; the fifth depends on how one parameter is spelled in Rust.
`cbindgen.toml` carries the same list beside the keys that were tried against
it, and every key there was checked against that version's own `config.rs`.

1. A trailing comma after every enumerator, the last one included, because
   `clike.rs` writes it unconditionally. `urlapi.h` has none, and
   `cc -std=c89 -pedantic` reports "comma at end of enumerator list".
2. `#endif // __cplusplus` and `}  // extern "C"` around the `extern "C"`
   block, hard-coded with `//` comments. Under C89 those are not comments at
   all, so the compiler reports "extra tokens at end of `#endif` directive"
   twice and `scripts/checksrc.pl` reports `CPPCOMMENTS` three times. The
   wrapper itself is wanted, so `cpp_compat` stays on.
3. The opaque tag is `struct CURLU`, taken from the Rust item name, where
   `include/curl/urlapi.h:107` writes `typedef struct Curl_URL CURLU;`. ABI
   irrelevant: the type is incomplete either way and is only ever reached
   through a pointer, which is what makes the whole port tractable.
4. The license box precedes the include guard, where `urlapi.h` opens the
   guard at L1-L2 above the box at L3-L25.
5. Conditional, and listed because no configuration key can repair it:
   `curl_url_dup`'s parameter is spelled `in` at
   `include/curl/urlapi.h:126`, which is a Rust keyword, and `rename_args`
   cannot turn a name back into a reserved word. Writing it as `r#in` in
   `src/ffi.rs` does reproduce it exactly; spelling it anything else is a
   divergence created there rather than here. `FB5` above is the same
   constraint seen from the other end.

Items 1 and 2 are the load-bearing pair, because they make the generated
output fail gates the committed header passes. A generator that installed its
output would therefore replace a compliant header with a non-compliant one on
every run, which is exactly why `build.rs` does not do that.

Measured rather than assumed, on a generated header whose declarations are
all exercised: `cc -std=c89 -Wall -Wextra -pedantic` reports exactly four
warnings, two from item 1 and two from item 2, and `scripts/checksrc.pl`
reports exactly three warnings and zero errors, all three from item 2. There
is no over-length line, no tab, no trailing whitespace, no non-ASCII byte and
no consecutive blank line, so the output satisfies `scripts/spacecheck.pl`
unaided. Nothing else diverges.

### What the port does

The committed header stays authoritative. Under `genheader`, `build.rs`
generates into `OUT_DIR`, byte-compares, and reports: a match is a note, a
difference is a warning naming both paths, and a missing committed header is
a warning naming the generated one as the material for writing it. Nothing in
the source tree is written, and `include/curl/urlapi.h` is neither generated
over nor shadowed.

Generation reads `src/ffi.rs` and `src/abi.rs` by name rather than the crate
root, which keeps two unrelated problems out of the way. `cargo metadata`,
which the whole-crate entry point runs, cannot parse the `idn-pure`
dependency graph under a 1.75 Cargo; and a whole-crate parse also emits an
`extern` declaration for every prototype the crate *imports* -- the five
libidn2 entry points, the two address converters, the two scheme lookups and
the `struct Curl_scheme` mirror -- none of which a mirror of `urlapi.h` may
carry. Those ten names are excluded by name in `cbindgen.toml` as well, so
neither mechanism alone is relied on.

## Residual divergence: the harness shim's `snprintf` return value

`rust-urlapi/harness/shims.c` supplies the `curl_mprintf` family for the
standalone link, where no libcurl participates and nothing else defines it.
The shims forward to the C library's `printf` family. For one function the
**bytes agree and the return value does not**.

`curl_mvsnprintf` at `lib/mprintf.c:L1077-L1099` answers with the count it
actually wrote, decremented at L1094 whenever it truncated. C99 `vsnprintf`
answers with the count it would have written had the buffer been large
enough. The two agree unless the output was truncated.

The bytes are identical for every input, and that is worth stating because it
is the half that matters. `addbyter` at `lib/mprintf.c:L1065-L1075` stores a
byte only while `length < max`, and the tail at L1088-L1098 either overwrites
the final stored byte with a terminator, when the buffer filled exactly, or
appends one when it did not. That is precisely C99's truncation rule, and a
zero `maxlength` writes nothing under either implementation.

No call site in `tests/libtest/lib1560.c` can observe the difference: L71 and
L74 measure the result with `strlen` at L76, and L1940 discards the value
outright. The oracle therefore cannot observe the divergence at all, and it
is recorded rather than papered over because the next consumer of the shim
may not be `lib1560.c`.

It applies to the standalone configuration alone. The drop-in configuration
links a real libcurl, which brings its own `lib/mprintf.c`, and
`harness/shims.c` takes no part in that link.

## Reported constraint: the libidn2 version guard needs the header

`lib/idn.c:L252` opens `idn_decode` with
`if(idn2_check_version(IDN2_VERSION))`, where `IDN2_VERSION` is the version
string of the **header the C was compiled against**. The guard asks one
question: is the runtime library at least as new as the header?

The port asks the same question, from the same source. `build.rs` locates the
`idn2.h` this artifact will link against -- `CURL_URLAPI_IDN2_H`, then
`LIBIDN2_INCLUDE_DIR`, then the `pkg-config` tool's own `-I` list, then the
conventional roots -- parses `IDN2_VERSION` and `IDN2_VERSION_NUMBER` out of
it, and emits both for `src/ffi.rs`, which hands the string to
`idn2_check_version` exactly as the C hands its own. On the machine this port
was developed against that is `2.3.8` with `IDN2_VERSION_NUMBER` `0x02030008`,
matching `/usr/include/idn2.h`. The flag word is decided from that number in
`build.rs`, where the header actually is, and delivered as
`cfg(idn2_nontransitional)` -- the `#if` at `lib/idn.c:L254` written as a
`#[cfg]`.

What is reported rather than worked around is what happens when the header
cannot be found: **the build stops**, naming every candidate it tried and the
two environment variables that override the search. It does not guess a
version, and that is deliberate. A guessed floor is the one outcome that is
silently wrong in both directions -- too low and the guard passes against a
library that cannot honor these declarations, too high and it fails against
one that can -- and either way the flag word `lib/idn.c:L253-L260` builds
would be decided by this crate rather than by the installation. Refusing is
also the only answer that keeps a cross build honest: the host's `idn2.h`
describes the host's library, so reading it would be worse than not reading
it. A cross build therefore has to name the target's header explicitly through
`CURL_URLAPI_IDN2_H` or `LIBIDN2_INCLUDE_DIR`.

The floor `build.rs` additionally enforces on the version it finds is
`2.2.0`, and it is a security floor rather than a compatibility one: below it
the library carries the heap overflow fixed in 2.2.0, CVE-2019-12290, in the
same lookup entry points this crate calls, and `lib/idn.c` gates
`IDN2_NONTRANSITIONAL` on the compile-time version, so an older library also
changes which flags reach the lookup. A build against an older libidn2 is
refused with both reasons stated.

The `2.2.0` constant that `src/ffi.rs` names as its own last-resort fallback
is therefore unreachable whenever the libidn2 backend is selected. It is
written out rather than unwrapped because the crate denies `unwrap`, and a
constant with a stated fallback is easier to audit than one that cannot fail
for reasons stated in another file.

## Reported constraint: `cargo-c` and the absent `capi` feature

The `AAP` fixes the feature surface at six -- `strerror`, `cfree`,
`scheme-table`, `idn-libidn2`, `idn-pure` and `genheader` -- and the crate
declares exactly those. `cargo-c` 0.10.24 appends `--features capi` to every
invocation whether or not the package declares such a feature, so
`cargo cbuild` stops with "the package `curl-urlapi-rs` does not contain
this feature: `capi`". Measured against the installed 0.10.24.

That is a constraint of the tool rather than of the crate, and it is recorded
here rather than worked around, because working around it would mean adding a
seventh feature the plan does not permit. The supported path is a plain
`cargo build`, which produces the same archive and shared object, alongside
the committed header. The `[package.metadata.capi]` blocks in `Cargo.toml`
still describe the packaging shape, so a `cargo-c` that stops imposing the
requirement, or a wrapper that supplies it out of tree, needs no change here.

## Reported precondition: a 32-bit `curl_prot_t` in drop-in mode

Drop-in mode reads libcurl's own scheme descriptors through a `#[repr(C)]`
mirror of `struct Curl_scheme`, `lib/urldata.h:L515-L524`, held in
`crate::ffi::scheme_import`. Of its six fields the URL API reads three: `flags`,
`defport` and whether `run` is null. The mirror describes all six, because
the three that are read sit after the three that are not and cannot be
located otherwise.

`protocol` and `family` are `curl_prot_t`, and that type is **conditional**.
`lib/urldata.h:L81-L87` defines `PROTO_TYPE_SMALL` and makes `curl_prot_t` a
`uint32_t` while it is defined, a `curl_off_t` if it is ever undefined. Were
it to widen, every field after those two would shift -- which is the pair
this port reads. Getting it wrong does not fail to compile; it silently
returns one field's bytes as those of another.

This is not hypothetical. `lib/urldata.h:L71` already defines
`CURLPROTO_WSS` as `((curl_prot_t)1 << 31)`, so bit 31 is taken and the
header is one protocol away from the condition its own comment describes.

Two things guard it, and it is worth being exact about what each one can do.
`LAYOUT_PROOF` pins the *Rust* mirror to the shape the port assumes, at
compile time, and catches a reordered field, a widened integer or a dropped
`#[repr(C)]`. It cannot observe the C side at all: no assertion written in
Rust can read `lib/urldata.h`. So the 32-bit `curl_prot_t` is a documented
**precondition** of drop-in mode rather than a checked one, which is why it
is recorded here.

The live cross-check is the parity run. `tests/libtest/lib1560.c` asserts
default ports directly -- `https://127.0.0.1` with `CURLU_DEFAULT_PORT` must
yield `443` at L592-L594, and `http://example.com:80` with
`CURLU_NO_DEFAULT_PORT` must serialize without the port at L786-L788 -- and
both readings come through `defport`. A shifted mirror fails those on the
first sub-test rather than subtly.

Standalone mode is unaffected. It compiles its own table in `src/scheme.rs`
and describes no C structure at all, so there is no layout to get wrong.

## Checked and not a divergence: dynamic-buffer cleanup in `lib/urlapi.c`

This entry records a claim that did **not** survive checking, because two
comments in `src/dynbuf.rs` used to assert that this file listed places where
`lib/urlapi.c` fails to reach `curlx_dyn_free()`. It does not, and it should
not: there are none.

The mechanism is in the dynamic buffer rather than in its callers.
`dyn_nappend` at `lib/curlx/dynbuf.c:L67-L112` calls `curlx_dyn_free(s)` on
both of its failure paths, at L83 when the request exceeds the ceiling and at
L107 when the reallocation fails. `curlx_dyn_addn`, `curlx_dyn_add` and
`curlx_dyn_addf` all route through it, so **a failed append has already
released the buffer** and a `return` immediately after one is not a leak.
That is contract 1 in `src/dynbuf.rs`'s own module documentation, and it is
what makes the C's terse error handling correct.

All eleven `curlx_dyn_init` sites in the module were then read individually.
Each one either frees on every failing exit or hands the pointer over on
success:

- L664 in `Curl_url_set_authority`, freed at L669 or handed to `u->host`.
- L726 in `dedotdotify`, where every failure came from an append and the
  success path either hands the pointer to `*outp` or has no allocation to
  release, the two `goto end` sites both preceding the first append.
- L1021, L1044 and L1072 in `handle_fragment`, `handle_query` and
  `handle_path`, where the only failure is `urlencode_str`'s, and that
  function returns non-`CURLUE_OK` only for a code an append produced.
- L1122 in `parseurl`, freed at the `fail:` label at L1189 or handed to
  `u->host`.
- L1272 in `redirect_url`, freed unconditionally at L1282.
- L1394 in `urlget_format` and L1485 in `urlget_url`, both failing only
  through an append.
- L1880 and L1944 in `urlset_part`, freed explicitly at L1955, L1960 and
  L1988 and otherwise handed to `*storep`.

The module does leak, and `FB2` and `FB3` above are where. Both are string
fields overwritten or set to null without a free, not dynamic buffers, and
conflating the two would have sent a reader looking for a defect that is not
there.

### What the port does

`DynBuf` has no `Drop` of its own. It holds a `crate::ffi::CBlock`, and the
block releases itself, so the release happens on every path out of every
function and there is no path to miss. `DynBuf::into_cbuf` and
`DynBuf::into_raw` are the two ways to suppress it, and both consume the
value, so suppression is visible at the type level.

That is a structural simplification and not a bug fix. The C is already
correct here; what the port removes is the *possibility* of getting it wrong
as this module gains call sites the C does not have.
## Residual divergence: the harness `curl_msnprintf` return value

This one lives in the standalone harness rather than in the crate, and it is
recorded because `harness/shims.c` promises it is recorded.

`harness/shims.c` implements `curl_msnprintf()` and `curl_mvsnprintf()` by
forwarding to the C library's `vsnprintf()`, because the standalone link has
no libcurl to supply `lib/mprintf.c`. **The bytes written are identical for
every input.** curl's `addbyter()` at `lib/mprintf.c:L1065-L1075` stores a
byte only while `length < max`, and the tail at L1088-L1098 either overwrites
the last stored byte with a terminator, when the buffer filled exactly, or
appends one when it did not -- at most `maxlength - 1` characters plus a
terminator, which is C99 `vsnprintf`'s truncation rule exactly. A zero
`maxlength` writes nothing under either implementation.

The **return value** differs, and only when the output was truncated. curl
answers with the count it actually wrote, decremented at
`lib/mprintf.c:L1094` on truncation. C99 `vsnprintf` answers with the count
it *would* have written had the buffer been large enough. Where nothing was
truncated the two answers agree.

Nothing in either oracle can observe the difference.
`tests/libtest/lib1560.c` calls the function three times: L71 and L74 build
a buffer whose result is then measured with `strlen()` at L76, and L1940
discards the return value outright. `demo/urlapi_demo.c` follows
`docs/examples/urlapi.c` and formats with the C library directly, so it
never reaches the shim at all.

The drop-in link is unaffected, because there the real `lib/mprintf.c`
object supplies both functions and the shim is not compiled.

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

### REPORTED BLOCKER: `CURLU_NO_GUESS_SCHEME` and `AAP` 0.6.5

**This subsection reports an unresolved conflict between the frozen Agent
Action Plan and `lib/urlapi.c`. It does not resolve it, and nothing in it
redefines what acceptance means.** Escalating rather than deciding is what
`AAP` 0.8.1 requires -- "if something in scope requires touching something
out of scope to work, stop and report that instead of expanding scope" --
and transformation rule `T7` at 0.1.2.3 repeats it as "escalate rather than
expand". The plan is out of scope for edit, so the conflict is reported
here and left open for its owner.

**What the plan requires.** `AAP` 0.6.5 states the empty-string flag
sensitivity in these terms:

> Setting the whole URL to the empty string with the no-guess-scheme flag
> on a handle whose scheme was guessed **fails** with malformed input --
> because the retrieval returns the no-scheme code `lib/urlapi.c:L1559-L1560`
> -- while the identical call with no flags **succeeds** as a no-op.

**What the source says.** `CURLU_NO_GUESS_SCHEME` has two unrelated effects,
in two different branches of the reader. In the `CURLUPART_SCHEME` branch it
is an error: L1559-L1560 return `CURLUE_NO_SCHEME`. In the whole-URL branch
it is only a formatting choice: L1512-L1515 blank the scheme prefix and
carry on returning `CURLUE_OK`. L1700 asks for `CURLUPART_URL`, so on the
face of the source it meets the second behavior and never the first, and
writing an empty string to a handle whose scheme was guessed then returns
`CURLUE_OK` with or without the flag. Measurement against the reference
build agrees with that reading.

**Why this cannot be settled inside this file.** Two of the plan's own
provisions pull in opposite directions and only its owner can say which
governs.

- 0.2.2 designates `lib/urlapi.c` "the behavioral source of truth", 0.8.1
  directs that behavior "be read from `lib/urlapi.c` rather than inferred",
  and acceptance criteria `A5` and `A7` at 0.9.2 are measured by running the
  unmodified `tests/libtest/lib1560.c` and by diffing a demo against the
  same demo linked against the unmodified C. Under those provisions the
  implementation must match the source, or `A5` and `A7` fail by
  construction.
- 0.6.5 states the behavior above, and it is frozen text.

**What is required, and what is deliberately not being done.** The
requirement is a decision by the plan's owner: either 0.6.5 is corrected, or
the discrepancy is explained. Until then this file records the conflict and
takes no position on which of the two is the specification. It does not
substitute a different mechanism for the one 0.6.5 names, it does not
declare 0.6.5 superseded, and it does not narrow any acceptance criterion.
The `CURLU_DEFAULT_SCHEME` sensitivity documented in the subsection above is
a separate, independently measured finding, and citing it here is not an
argument that it replaces 0.6.5.

Whoever implements `rust-urlapi/src/getset.rs` inherits this open item and
should not close it by choosing quietly. The two candidate behaviors differ
observably -- `CURLUE_OK` against `CURLUE_MALFORMED_INPUT` for one specific
call -- so the choice is visible in the parity diff either way, which is the
right place for it to surface.

### The surrounding dispatch

For completeness: a value that is not empty goes to the absolute-URL test at
L1713-L1714, which is passed the caller's flags narrowed to the bitwise or
of `CURLU_GUESS_SCHEME` and `CURLU_DEFAULT_SCHEME`, and an absolute value
replaces the contents through `parseurl_and_replace()` at L1715.

### What the port is to do

`rust-urlapi/src/getset.rs` is to carry the empty-string rule and pass the
caller's flags into the read exactly as L1700 does. The module is not
written yet. Its treatment of `CURLU_NO_GUESS_SCHEME` is governed by the
reported blocker above and is not settled here.

## Integration limitation: the generated header cannot match the committed one

The entries above are things `lib/urlapi.c` does. This one and the ones that
follow it are different in kind: they are places where the *port's own
packaging* cannot reproduce the original exactly, and where a reader who is
told nothing would reasonably conclude that a difference is a bug. They are
graded separately in "How to read this catalog" for that reason.

`rust-urlapi/include/curl_urlapi_rs.h` mirrors
`include/curl/urlapi.h:L34-L149` for standalone consumers, the ones with no
libcurl in the link and therefore no real header to include. It is
**hand-authored and stays authoritative**. `rust-urlapi/cbindgen.toml`
configures `cbindgen` 0.29.4 to generate the same declarations, and
`rust-urlapi/build.rs` runs that generation under the optional `genheader`
feature so that the two can be diffed. The diff is never empty, and four of
the differences cannot be configured away.

Every count below was measured against `cbindgen` 0.29.4 on this crate.

### The four differences

1. **`//` comments on the `extern "C"` wrapper.** With `cpp_compat = true`,
   `cbindgen` hard-codes `#endif // __cplusplus` and `}  // extern "C"`. In
   C89 those are not comments, so `cc -std=c89 -Wall -Wextra -pedantic`
   reports "extra tokens at end of `#endif` directive" twice -- once per
   `#endif` -- and `scripts/checksrc.pl` reports `CPPCOMMENTS` three times,
   once per `//` line. Those five are the *only* findings on the generated
   header. The wrapper is still wanted, so the setting stays on and the
   committed header writes the same wrapper with `/* */` comments instead.
2. **The opaque tag is `struct CURLU`,** taken from the Rust item name, where
   `include/curl/urlapi.h:L107` writes `typedef struct Curl_URL CURLU;`. ABI
   irrelevant: the type is incomplete either way and is only ever reached
   through a pointer, which is exactly what makes this port tractable.
3. **The licence box precedes the include guard,** where
   `include/curl/urlapi.h` opens the guard at L1-L2 above the box at L3-L25.
4. **`curl_url_dup`'s parameter name.** `include/curl/urlapi.h:L126` spells
   it `in`, which is a Rust keyword, and `cbindgen`'s `rename_args` cannot
   turn a name back into a reserved word. Writing the parameter as `r#in` in
   `src/ffi.rs` does reproduce it exactly; spelling it anything else would be
   a divergence created in the Rust source rather than by the generator.

### One difference that was claimed and does not exist

`cbindgen.toml` used to head that list with "a trailing comma after every
enumerator". It is true of `cbindgen` in general and unreachable here.
`src/abi.rs:L70` and `L81` declare `CURLUcode` and `CURLUPart` as `c_int`
type aliases rather than as Rust enums, deliberately, because C numbers its
enumerators implicitly and a Rust `enum` numbers its variants implicitly too,
so a reordering would break the ABI with no compiler error. `cbindgen`
therefore emits `typedef int CURLUcode;` and `typedef int CURLUPart;` plus one
`#define` per value, and produces **no** `typedef enum` block at all:
measured, 0 enumerations and 61 `#define` lines. With no enumerator there
can be no trailing comma after one. The same measurement is why `"enums"` no
longer appears in that file's `item_types`.

### What the port does

Three things, and the first is the one that matters.

`build.rs` writes the generated header into `OUT_DIR` and **never** into the
source tree. An earlier version wrote over the committed file whenever the
bytes differed, which -- given that they can never be equal, per the four
differences above -- meant an ordinary `cargo check --features genheader`
destroyed hand-authored work on every fresh checkout, with a warning as the
only trace. `.gitignore` cannot mitigate that, because the file is tracked.
The check now reports and a person decides.

`cbindgen.toml` names three implementation constants in `[export] exclude`.
`item_types` includes `"constants"` for the sixteen `CURLU_*` flag bits, and
that reaches every `pub const` in the crate, so without the entries the
mirror also carried `MAX_SCHEME_LEN`, `CURL_MAX_INPUT_LENGTH` and
`PROTOPT_URLOPTIONS`. The first of those carries no prefix and would occupy a
global macro name in every consumer; the other two restate private values
from `lib/urldata.h:L131` and `L545` in a public header.

Two constants that `cbindgen` cannot represent in C, `DEFAULT_SCHEME` at
`src/abi.rs:L407` and `DEFAULT_SCHEME_CSTR` at `L424`, are skipped by the
generator itself and are therefore absent from that exclude list. Naming
them would not even quiet the log: the skip message is emitted while
`cbindgen` parses, before the export filter runs, so exclusion removes an item
from the output but not a complaint from the log. Verified by trying it.

## Integration limitation: the standalone table models one build

Scheme lookup has two backends, selected by the `scheme-table` feature. In
drop-in mode the feature is **off** and `crate::ffi::scheme_import` calls
`Curl_get_scheme` in the linked libcurl, so the real and complete table is
used. In standalone mode the feature is **on** and the crate compiles its own
33-row table, because there is no libcurl in that link to ask.

`lib/urlapi.c` reads three fields of the descriptor `Curl_get_scheme` returns,
and one of the three is a property of *a build* rather than of the scheme.
`lib/urlapi.c` L1646 tests `h->run` for null and answers
`CURLUE_UNSUPPORTED_SCHEME` when it is null; `run` is `ZERO_NULL` exactly when
the protocol was compiled out, the `#ifdef CURL_DISABLE_FILE` around the
initializer at `lib/file.c:L628-L632` being the pattern.

A standalone build has no protocol implementations of its own, so it has to
*model* a build, and the build it models is the reference build the parity
harness compares against: `scripts/build-reference.sh` configures OpenSSL,
libidn2, OpenLDAP and nghttp2, and disables nothing. `src/scheme.rs` writes
that model out as `mod capability`, one constant per `USE_*` and per
`CURL_DISABLE_*`, and every one of the 33 rows spells its own condition in
terms of those constants, next to the `#if` line in the C it reproduces. So
`https` and `imaps` report an implementation, while the six `rtmp*` rows and
`scp`/`sftp` do not -- librtmp is not installed and no SSH backend is built.

### What follows from it

The disabled-protocol path is **reachable** in both modes, which is the point:
in standalone mode it is reached for the protocols the modeled build does not
carry, and in drop-in mode -- which is the authoritative configuration -- it is
reached exactly when the linked libcurl does not carry them. What remains a
limitation is that the standalone answer is a model: a differently configured
libcurl disagrees with it, and only the constants in `mod capability` have to
change to model that one instead.

No assertion in `tests/libtest/lib1560.c` depends on any of this. The only
scheme it sets is `imaps`, at L1085, and the only ones it rejects are names no
table holds at all, so the parity oracle cannot see it, which is precisely why
it is written down here.

### Why this is listed at all

It is the **one** feature of the three link-mode features whose misuse is
silent, and that is worth separating from the other two. `strerror` and `cfree`
left on in Mode A give the linker two definitions of one symbol and the link
stops. `scheme-table` left on in Mode A gives a **clean link**, because the
crate defines no `Curl_get_scheme` for anything to collide with -- and then
answers capability questions from the modeled table rather than from the
linked libcurl's own. Nothing in a Cargo build can detect that: `build.rs`
cannot see which archive a later C link line names.
`rust-urlapi/Cargo.toml` states the distinction where the three features are
declared, and this entry is the other half of that control.

### What the port does

`src/scheme.rs` keeps both backends behind one interface, and a test pins the
per-row model: `https` and `imaps` implemented, `rtmp` and `sftp` not, so
neither answer can quietly become blanket. `rust-urlapi/Cargo.toml` sets the
defaults for Mode B and names Mode A's inversion
(`--no-default-features --features idn-libidn2`) next to the reason it matters.

## Integration limitation: drop-in mode presumes a 32-bit `curl_prot_t`

In drop-in mode `crate::ffi::scheme_import` describes `struct Curl_scheme`
from `lib/urldata.h:L515-L524` so that `src/scheme.rs` can read the three
fields `lib/urlapi.c` consults from the descriptor `Curl_get_scheme` returns.
Reading the last of those three requires knowing the offsets of the ones
before it, so the mirror has to describe all six fields even though only
three are read, and every field's width has to be right.

One width is not knowable from Rust. `flags` is a `curl_prot_t`, which
`lib/urldata.h:L82-L87` resolves to `uint32_t` normally and to a narrower
type when `PROTO_TYPE_SMALL` is defined. The mirror assumes 32 bits.

### Why it cannot be checked

`LAYOUT_PROOF` at `src/scheme.rs:L1274-L1294` pins *the Rust side* at compile
time. It catches an edit made here -- a reordered field, a widened integer, a
`#[repr(C)]` accidentally dropped -- and it says so itself. What it cannot do
is observe the C side: no assertion written in Rust can read
`lib/urldata.h`, and `lib/urldata.h` is out of scope and cannot be edited, so
there is no place to put a matching assertion on the other side either.

This is therefore a **precondition** of drop-in mode rather than a checked
invariant, and an unenforceable one. A libcurl built with
`PROTO_TYPE_SMALL` would shift `defport` and `run` under the mirror's feet
and the crate would read the wrong bytes, silently.

### What stands in for the check

The parity run. `tests/libtest/lib1560.c` asserts default ports directly --
`https://127.0.0.1` with `CURLU_DEFAULT_PORT` must yield `443` at
L592-L594, and `http://example.com:80` with `CURLU_NO_DEFAULT_PORT` must
serialize without the port at L786-L788 -- and both readings come through
`defport`. A shifted mirror fails those on the first sub-test rather than
subtly, which is the outcome to want from an unenforceable precondition.

Standalone mode describes no C structure at all and is unaffected.

## Integration limitation: the standalone `snprintf` shim returns the C99 count

`tests/libtest/lib1560.c` calls three members of the `curl_m*printf` family,
which libcurl defines in `lib/mprintf.c`. The drop-in link takes them from
that object. The standalone link has no libcurl in it, so
`rust-urlapi/harness/shims.c` supplies six of them by forwarding to the C
library. Five forward exactly. The sixth, `curl_msnprintf`, agrees on every
byte it writes and disagrees on what it returns.

### The bytes agree

`addbyter` at `lib/mprintf.c:L1065-L1075` stores a byte only while
`length < max`, and the tail at `L1088-L1098` then either overwrites the last
stored byte with a terminator, when the buffer filled exactly, or appends
one when it did not. That is at most `maxlength - 1` characters plus a
terminator, which is C99 `vsnprintf`'s truncation rule stated differently. A
zero `maxlength` writes nothing under either implementation.

### The return value does not

curl answers with the count it **actually wrote**, decremented at
`lib/mprintf.c:L1094` whenever it truncated. C99 `vsnprintf` answers with the
count it **would have written** had the buffer been big enough. The two agree
unless the output was truncated, and diverge without bound when it was.

### Why it is safe here, stated rather than assumed

No call site in the test can observe the difference, and the reason is worth
naming because a wrong answer here could easily have been a buffer overrun
rather than a wrong number. `tests/libtest/lib1560.c:L71` and `L74` call
`curl_msnprintf` and then advance with `n = strlen(bufp); bufp += n;
len -= n;` at `L76-L78` -- that is, by the bytes **actually stored**, taken
from the buffer itself and not from the return value, so neither pointer
arithmetic nor the remaining-length subtraction can be driven past the end by
an inflated count, and no `size_t` can wrap. The third call site, `L1940`,
discards the value outright.

### What the port does

Nothing, deliberately. Reproducing curl's count would mean re-implementing
`lib/mprintf.c`'s storage loop inside a shim whose entire purpose is to be
the C library, and the difference cannot be observed by the one program the
shim exists for. It is written down here instead, so that a future consumer
who does read the return value knows to check this first.

The same file's other constraint belongs with it: the standalone shim is
compiled to C99 rather than to the C89 `docs/INTERNALS.md:15` states for
curl, because C89 does not declare `vsnprintf` at all. `shims.c` enforces
that with an `#error` narrow enough to accept `-std=gnu89`, where glibc still
declares it. The three other harness C files are C89-clean.

## Why every one of these stays

Each finding above is reproduced deliberately. None of them is an accident
of the port, and none is a defect to be filed against it.

The catalog is kept honest by a test rather than by good intentions.
`tests/ffi_surface.rs` asserts these behaviors through the C entry points,
so a later attempt to tidy one of them up breaks a test instead of passing
unnoticed, and whoever hits that test arrives here to find out why. The
record and the code therefore move together: a finding that stops being
true belongs in a commit that removes it from both.

Two points invite a wrong summary of this file and are worth stating
plainly, because a port built to either of them would diverge from the C.
The empty-string flag sensitivity runs through `CURLU_DEFAULT_SCHEME` and
L1455-L1458, **not** through `CURLU_NO_GUESS_SCHEME`: L1700 reads
`CURLUPART_URL`, and the `CURLUE_NO_SCHEME` guard at L1559-L1560 belongs to
the `CURLUPART_SCHEME` branch, so passing `CURLU_NO_GUESS_SCHEME` leaves the
result at `CURLUE_OK`. And a scheme produced by guessing is `http`, from
L1002, **not** the `https` of L84, which belongs to
`CURLU_DEFAULT_SCHEME`.

### Why the other eight entries stay, which is a different reason

The four residual divergences and the four integration limitations are not
reproduced oddities and `A10` does not cover them, so they need their own
justification and it is not "faithfulness".

They stay because a reader who does not know about them cannot use this port
correctly. Every one of them is a place where something *outside* the ported
behavior can go wrong quietly: a Mode A integrator gets a clean link and the
wrong capability table; a `PROTO_TYPE_SMALL` libcurl shifts a structure the
crate reads and nothing says so; a generated header carries constants a
public header should not; a shim returns a number that would be wrong if
anyone read it. None of these produces a failing assertion, and three of them
produce no diagnostic at all, so a document is the only mechanism available.

That is also why four in-scope files point here by name. The pointers and
these sections are one control, not two, and a pointer that does not resolve
disables it: `rust-urlapi/cbindgen.toml`, `rust-urlapi/build.rs` (twice, once
in a comment and once in the text Cargo actually prints),
`rust-urlapi/Cargo.toml` and `rust-urlapi/harness/shims.c` each name the
heading they mean. Moving or renaming a heading in this file means fixing
them.
The same rule governs the entries after the six, in both directions. Every
comment in the crate that points a reader here names the entry it means, and
every entry here exists because something points at it. Two of the entries
were added for exactly that reason: `src/dynbuf.rs` and `harness/shims.c` each
promised a record that was not present, and one of the two promises was itself
wrong about the C. A cross-reference that does not resolve is as much a defect
as an unrecorded divergence, since both leave the next reader guessing.

### Two behaviors worth stating precisely

Both of the behaviors below are easy to describe loosely, and a module built
on a loose description behaves differently from the C. Each is stated here
with the line that decides it, and each was measured against the reference
build rather than reasoned about.

**Which flag makes the empty-string case flag-sensitive.** L1700 retrieves
`CURLUPART_URL`, so the guard at L1559-L1560 does not run. That guard, the
one that turns `CURLU_NO_GUESS_SCHEME` into `CURLUE_NO_SCHEME`, sits in the
`CURLUPART_SCHEME` arm of the same `switch`, and this call is in the
`CURLUPART_URL` arm. What the whole-URL retrieval consults instead is
L1455-L1458, where a handle carrying no scheme at all needs
`CURLU_DEFAULT_SCHEME` to avoid `CURLUE_NO_SCHEME`, while a handle whose
scheme was guessed has `u->scheme` set and takes the first branch at
L1453-L1454. The sensitivity is real, and the table above demonstrates it;
it runs through `CURLU_DEFAULT_SCHEME`, and a module that placed it on
`CURLU_NO_GUESS_SCHEME` would answer `CURLUE_MALFORMED_INPUT` where the C
answers success.

**Which scheme guessing produces.** It is `http`, from L1002, and it is not
the `https` of L84. That second string is `DEFAULT_SCHEME` and belongs to
`CURLU_DEFAULT_SCHEME`, which reaches it at L1456. The two are separate
mechanisms that happen to meet in the same `switch`, and `FB1` above carries
the measurement that distinguishes them.

## Reported limitation: the drop-in scheme mirror rests on a private layout

This is neither a reproduced oddity nor a behavioral divergence. It is a
precondition that drop-in mode carries and that no assertion inside this
crate can fully discharge, so it is written down here, which is where
`rust-urlapi/src/ffi.rs` says it belongs, in the hazard note on its
`CurlScheme` mirror.

### What the precondition is

With the `scheme-table` feature off -- the drop-in and authoritative
configuration -- `crate::ffi::scheme_import` declares `Curl_get_scheme()`
and `Curl_getn_scheme()`, and `src/scheme.rs` reads three fields of the
descriptor they return: the capability `flags`, tested for
`PROTOPT_URLOPTIONS`; `defport`, the
scheme's default port; and `run`, tested only for null to detect a protocol
compiled out. It reads them through a `#[repr(C)]` mirror of
`struct Curl_scheme`, `lib/urldata.h:L515-L524`. The `AAP` mandates exactly
that arrangement at 0.4.2.4, and it is what keeps the real and complete
table in play instead of a copy.

The mirror locates `flags` and `defport` after two `curl_prot_t` members,
`protocol` and `family`, which nothing here reads. Their *width* is
load-bearing anyway, and it is conditional:

```text
lib/urldata.h:81   /* This should be undefined once we need bit 32 or higher */
lib/urldata.h:82   #define PROTO_TYPE_SMALL
lib/urldata.h:84   #ifndef PROTO_TYPE_SMALL
lib/urldata.h:85   typedef curl_off_t curl_prot_t;
lib/urldata.h:87   typedef uint32_t curl_prot_t;
```

Build without `PROTO_TYPE_SMALL` and both members widen from four bytes to
eight, which moves `flags` and `defport` by eight bytes each. That does not
fail to compile. It silently reads another field's bytes and returns them as
a scheme's default port.

The header is one protocol away from that condition. `lib/urldata.h:L71`
already defines `CURLPROTO_WSS` as `((curl_prot_t)1 << 31)`, so bit 31 is
taken and the comment at L81 describes the next addition rather than a
distant one.

### What is checked, and by what

- `src/scheme.rs` carries a compile-time proof of the *Rust* shape: the
  mirror's size against the size a 32-bit `curl_prot_t` implies, its
  alignment, and the widths of the two fixed-width members. It catches an
  edit to the mirror. It cannot read a C header.
- `rust-urlapi/build.rs` checks the *C* side in drop-in mode, by reading
  `../lib/urldata.h` -- the header of the tree this crate sits in, which is
  the tree whose libcurl the drop-in link uses -- and requiring both a live
  `#define PROTO_TYPE_SMALL` and the `typedef uint32_t
  curl_prot_t`. A header that says otherwise fails the build, naming the two
  remedies: widen the mirrored fields, or build `--features scheme-table` and
  describe no C structure at all.
- The parity run is the live cross-check. `tests/libtest/lib1560.c` asserts
  default ports directly, `443` for `https://127.0.0.1` with
  `CURLU_DEFAULT_PORT` at its L592-L594 and a suppressed `:80` at
  L786-L788, and both readings come through `defport`. A shifted mirror
  fails on the first sub-test rather than subtly.

### What remains unchecked

Two things, both narrow and both deliberate.

Reading the header text is not compiling it. Compiling `lib/urldata.h` would
need libcurl's private build environment, `curl_config.h` included, which
this crate does not have and does not want. What the text settles is exactly
the condition that decides the width, so the gap is a header whose
preprocessor state differs from its literal text -- a `-DPROTO_TYPE_SMALL`
removed on a command line, say.

A link against a *different* libcurl from the tree this crate sits in is
likewise outside what either check can see. Nothing forces the two to be the
same libcurl; the parity scripts use the tree's own, which is why they are the
configuration these claims cover.

## Residual divergences from the plan's architecture

The findings above are behaviors. What follows is a property of the port
rather than of the URL API, recorded here because `AAP` 0.4.1.5 assigns "any
residual divergence" to this file. One entry; an earlier revision of this file
carried two, and the first of them is now closed. It is kept, marked as
closed, because a divergence this file once asserted should be answered here
rather than silently dropped.

### CLOSED: `unsafe` is confined to one module

**This is no longer a divergence.** An earlier revision of this file recorded
that `AAP` 0.3.3 and 0.7.2 state `rust-urlapi/src/ffi.rs` "is the only module
containing `unsafe`" and that the port did not satisfy it. The port now does,
and the compiler enforces it: every module of the crate except
`rust-urlapi/src/ffi.rs` carries `#![forbid(unsafe_code)]`, so an `unsafe`
block added to any of them is a compile error rather than a review finding.
Measured over the fourteen modules that exist today, occurrences of the
`unsafe` keyword outside `rust-urlapi/src/ffi.rs`: **zero**.

The reasoning that made the old entry look unavoidable is worth keeping,
because it is what the design had to answer. Three other provisions of the
same plan appear to require `unsafe` elsewhere: 0.4.1.3 assigns the
C-allocator adapter to `rust-urlapi/src/alloc.rs`, the libidn2 bindings to
`rust-urlapi/src/idn.rs` and the external `Curl_get_scheme` declaration to
`rust-urlapi/src/scheme.rs`, and 0.3.3 itself calls
`rust-urlapi/src/alloc.rs` "the sole producer of C-visible memory". Calling
`malloc`, calling `idn2_to_ascii_lz` and calling an `extern "C"` function are
each `unsafe` operations in Rust, and no arrangement of modules makes them
safe.

What resolves the apparent conflict is that *producing* C-visible memory and
*holding the `unsafe` keyword* are different responsibilities, and the plan
assigns them separately:

A list rather than a table, because the entries do not fit this document's
79-column convention as rows. Every module named is under `rust-urlapi/src/`.

- `alloc.rs` keeps the C-allocator adapter, and every C-visible buffer is
  still a `CBuf` built there. What moved is the allocator entry points and
  the raw block that owns their result.
- `dynbuf.rs` keeps curl's dynamic-buffer semantics, `FB6` included. It had
  nothing of its own to move; it is now a thin wrapper over that block.
- `idn.rs` keeps the version guard, the exact flag set, the transitional
  retry, the zero-length rejection and the re-duplication order -- the
  parity-critical part. What moved is the five `extern "C"` declarations and
  the two platform lookup arms.
- `scheme.rs` keeps scheme resolution in both feature arms. What moved is the
  two `extern "C"` declarations and the one dereference of the descriptor
  libcurl returns.
- `inet.rs` keeps the fallback conversion and every caller-facing check. What
  moved is the platform `inet_pton`/`inet_ntop` pair.

Each relocated operation is reached through a safe wrapper whose preconditions
hold by construction rather than by caller promise: the raw block guarantees
its own capacity and initialization, the libidn2 wrappers take a `&CBuf` so
`NUL`-termination is not a promise, and the scheme wrapper returns an owned
snapshot of the three fields the module reads so no C structure is interpreted
outside the facade. Every `unsafe` block in `rust-urlapi/src/ffi.rs` carries a
safety comment, per specification 3.2.1.2.

The technical specification's weaker requirement at 1.3.2.1 -- no `unsafe`
outside FFI code -- is satisfied outright. `MEMORY-OWNERSHIP.md` states the
same property in its rules and points here.

### `FB2` is reproduced only in its API-visible half

Recorded at the finding itself, where the reasoning and the measurement sit
together. It is listed here so that a reader scanning for residual
divergences finds both of them in one place.

## See also

- [MEMORY-OWNERSHIP.md][ownership] holds the ownership context behind
  `FB2` and `FB3`: how `curl_free()` resolves, every allocation site in the
  module, and the rules the crate follows at the boundary. It also holds the
  authoritative `unsafe` inventory the entry above defers to.
- [PORTING-NOTES.md][porting] maps the C functions onto the Rust modules,
  and so names the owner of each finding above in its wider context.
- `rust-urlapi/cbindgen.toml` carries the generator configuration the first
  integration limitation is about, with the same four differences stated at
  the keys that cause them.
- `rust-urlapi/Cargo.toml` declares the three link-mode features and
  separates the two whose misuse is a link error from the one whose misuse is
  silent, which is the second integration limitation.

[ownership]: MEMORY-OWNERSHIP.md
[porting]: PORTING-NOTES.md
