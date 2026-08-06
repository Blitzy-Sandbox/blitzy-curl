<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Known divergences

`lib/urlapi.c` does a handful of things that look wrong, that read as
inconsistent with the contract documented in `include/curl/urlapi.h`, or
that are merely surprising. The `curl-urlapi-rs` port reproduces every
*observable* one of them on purpose. This file records what each one is,
what a caller can observe because of it, and which Rust module carries it.
Two of the six -- `FB2` and `FB3` -- are a leak as well as a behavior in the
C, and there the reproduction stops at the behavior: the leaks are not
reproduced, which is a residual difference of the port and is recorded as
one rather than filed under "reproduced".

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
full -- `rust-urlapi/src/handle.rs`, never a bare `src/handle.rs` -- so that
a citation can be pasted into an editor or a `git` command without a reader
first having to work out which of two roots it hangs from. The earlier
convention here made a bare `tests/` or `include/` crate-relative,
which collided with the repository's own `tests/` and `include/`
directories; it is gone.

One statement about state, so that no sentence below has to be taken on
trust. `rust-urlapi/src/` holds all 26 modules of the port -- the fifteen
top-level ones and the eleven parser stages -- and
`rust-urlapi/include/curl_urlapi_rs.h`, `rust-urlapi/harness/` and
`rust-urlapi/demo/urlapi_demo.c` are in the tree as well, so a claim here
about any of them is a claim a reader can check by opening the file. Five
things are not in the tree yet: `rust-urlapi/tests/`,
`rust-urlapi/scripts/`, `rust-urlapi/demo/expected-output.txt`,
`rust-urlapi/README.md` and `rust-urlapi/GNUmakefile`. Wherever one of those
five appears below, the sentence is a requirement on work still to be done
and is worded as one; present tense is reserved for what a reader can open
today.

Build steps, feature tables and script ordering are deliberately absent.
They belong to `rust-urlapi/README.md`, which is not written yet.

## How to read this catalog

The findings are graded. A record that calls everything a bug is less
useful than one that says which is which.

- `FB1`, a defect: handle duplication drops the guessed-scheme flag.
- `FB2`, a defect that also leaks: the credential exit path sets three
  handle fields to null without releasing what they held. The port
  reproduces the three fields reading as absent; it does not reproduce the
  leak.
- `FB3`, a defect that also leaks: the zone identifier is stored over an
  existing value, and neither the authority path nor the IPv6 stage clears
  it, so a stale identifier survives a host replacement made through either
  of them. The host setter is the exception and does clear it, at
  `lib/urlapi.c:L1848`. Here too the port reproduces the stale identifier
  and not the leak.
- `FB4`, intentional: a colon with no digits after it is accepted, though
  only when the URL has a scheme.
- `FB5`, cosmetic: one declaration in the public header names no parameter.
  Harmless in itself, it still constrains a generated file.
- `FB6`, neither a bug nor cosmetic: two writes land one byte past the
  logical length, which the Rust buffer has to allow for.

Two of the six are reproduced in one half only, and the grading above is about
the C rather than about the port: the leak `FB2` and `FB3` each incur is **not**
reproduced, because the fields are owned buffers whose `Drop` releases the old
value, while everything a caller can observe through the API is. Each finding
says so at its own "What the port does", and the architecture record near the
end of this file lists both as the one residual divergence in reproduced
behavior.

Eleven further entries follow the six, and none of them is a reproduced oddity.
Three are residual divergences of the port itself, in configurations the plan
permits rather than in the reproduced behavior:

- the `idn-pure` backend, a real divergence in an optional configuration;
- the harness shim's `snprintf` return value, which differs from curl's own
  while the bytes it writes do not, recorded twice because two files point at
  it under two names;
- the same shim's `curl_msnprintf` face, for the same reason.

Three are neither divergences nor defects but constraints, two of them the kind
the plan requires to be reported rather than worked around and one now closed:
the libidn2 version guard needs the installed header and the build refuses
rather than guessing without it; drop-in mode reads libcurl's scheme
descriptors through a mirror that assumes a 32-bit `curl_prot_t` -- checked as
far as the text of a header can be checked, and a documented precondition
beyond that; and `cargo-c` demands a `capi` feature, which the crate now
declares as an inert packaging token, so that entry records how the constraint
was closed and why keeping it open was a misreading of the plan.

Two record something that was checked and turned out not to be a divergence at
all. There is no dynamic-buffer cleanup omission in `lib/urlapi.c`, though only
five of the eleven dynamic buffers it declares are released by an explicit call,
which invites the opposite conclusion, and two ownership notes in the port send
a reader here for the answer. And the generated mirror header is **exact**: an
earlier revision of this file recorded its difference from the committed bytes
as permanent, and that entry now records how byte-for-byte regeneration is
reached instead.

Two are hardenings rather than divergences, and they are grouped because the
reason is one reason: each is a place where `lib/urlapi.c` has **no defined
behavior** to be faithful to, so the port takes the bounded direction and says
so. `curl_url_dup(NULL)` returns null where the C dereferences a null pointer;
`Curl_is_absolute_url` stops writing at `buflen` where the C discards it with
`(void)buflen` and writes the whole scheme regardless. Neither is reachable
from a caller that honors the contract -- and in the second case the return
value is identical either way -- but both are measured against the reference
and recorded so that neither is filed later as an unrecorded difference.

The last is the empty-string rule: documented behavior with an undocumented
sensitivity to flags, and the port's **one deliberate behavioral divergence**
from `lib/urlapi.c`. Two flags are in play and they must not be conflated. The
reference's own sensitivity runs through `CURLU_DEFAULT_SCHEME`, measured and
documented. `CURLU_NO_GUESS_SCHEME` is where `AAP` 0.6.5 requires an outcome the
reference does not produce, so the port implements the plan, records the
discrepancy for the plan's owner, and keeps the divergence to that single
combination -- which neither the unmodified oracle nor the parity demo
exercises.

Then comes a third class, four entries headed `Integration limitation`. These
are not things `lib/urlapi.c` does at all. They are places where the port's
own packaging cannot reproduce the original exactly -- where the *drop-in* is
imperfect rather than the *behavior* -- and where a reader told nothing would
reasonably file the difference as a bug. They are listed here because four
in-scope files send readers to this document expecting to find them, and one
of those pointers reaches the end user's terminal verbatim, in a warning
Cargo prints.

- The standalone scheme table models one build's protocol set, because a
  build with no protocol implementations of its own has to model the one the
  parity harness compares against. This is the one link-mode feature whose
  misuse is silent rather than a link error.
- The shared object exists in one configuration only. The drop-in
  configuration's scheme provider is two libcurl-private symbols that only a
  static link can resolve, so that configuration yields an archive and no
  shippable `.so`. The standalone configuration's release cdylib link is proved
  closed with `-Wl,-z,defs`, and the drop-in one is announced in a
  `cargo:warning` instead, because refusing that link would also cost the
  archive and the rlib the plan requires.
- Drop-in mode presumes a 32-bit `curl_prot_t`. `rust-urlapi/src/ffi.rs`
  proves the Rust side of the mirror at compile time and
  `rust-urlapi/build.rs` checks the C side textually; a preprocessed-header
  case survives both, which is why it stays a reported precondition.
- The standalone `snprintf` shim returns the C99 count rather than curl's,
  and is compiled to C99 where the rest of the harness holds to C89.

Twenty-five entries in total: six graded findings, eleven further entries, four
integration limitations, and four closing sections -- why they all stay, the
drop-in mirror's private-layout limitation, the architecture record, and the
index of what points here. Two topics are deliberately recorded twice, under
the name each pointing file uses for it: the shim's return value and the 32-bit
`curl_prot_t` precondition. A pointer that does not resolve is as much a defect
as an unrecorded divergence, so the duplicates stay until the pointers are
unified. The generated header used to be a third such pair; the two entries were
folded into one when the difference they described stopped existing. The count
is stated so that a gap reads as a gap: if something is missing from this file,
the file is wrong.

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
without credentials takes. `rust-urlapi/src/parse/authority.rs` carries that,
and two of its unit tests guard it: one for the success exit and one for the
`CURLU_DISALLOW_USER` rejection.

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

The port reproduces it: `rust-urlapi/src/parse/ipv6.rs` stores the zone
identifier without clearing a previous one and adds no clearing path, so a
stale zone stays readable after a host change made through the authority path
and stays invisible in the serialized URL. Three of its unit tests are named
for this finding and pin all three shapes -- a new zone replacing an old one,
a stale zone surviving a host without one, and a zone surviving a later
rejection.

The leak half is not reproduced, for the same reason as `FB2` and with the
same consequence. The C assigns over a pointer it still owns at L418; the
port assigns `Some(..)` over an owned buffer, so the displaced one is dropped
and released. Nothing a caller can reach through `curl_url_get()`,
`curl_url_set()` or `curl_url_dup()` distinguishes the two, and an allocation
counter would. It is recorded here as a residual difference rather than
counted as reproduced.

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
`rust-urlapi/src/parse/port.rs` carries the leniency and
`rust-urlapi/src/parse/mod.rs` the ordering that feeds it. Three of the port
module's unit tests are named for this finding: the accepted case with a
scheme, the rejected case without one that still truncates, and the long-name
case the leniency exists to protect.

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
instead. The mirror header `rust-urlapi/include/curl_urlapi_rs.h` exists so
that a consumer with no libcurl in the link still sees the same declarations,
and it leaves the parameter unnamed as well rather than improving on the
original -- verified: its `curl_url_strerror` declaration names no parameter,
exactly as `include/curl/urlapi.h:L149` does. A generator left to its own
devices emits a name, which is why this is recorded as a constraint rather
than left to chance: fidelity here means matching a cosmetic detail on
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
`rust-urlapi/src/dynbuf.rs` and `rust-urlapi/src/parse/ipv6.rs` carry the
requirement between them: the buffer provides the writable terminator byte and
documents the capacity it guarantees, and the parser is the only thing that
uses it. A unit test in the parser asserts that the highest byte it ever
writes is that terminator slot.

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

An allocation failure under this backend answers `CURLE_OUT_OF_MEMORY` rather
than aborting. That takes arranging, and is stated here because the obvious way
of writing the conversion aborts instead.

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
sink refuses. `rust-urlapi/src/idn.rs` supplies one. `CSink` accumulates into a
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

The configuration is not refused either. `idn-pure` is one of the six features
the manifest offers, so a build that selects it is using the manifest as
designed, and making it fail would turn a documented opt-in into a broken one.
Instead `rust-urlapi/build.rs` emits a `cargo:warning` on every build that
selects the backend, naming the four divergences and pointing here, and
`rust-urlapi/src/idn.rs` still carries a `compile_error!` for the one
configuration that is genuinely contradictory -- both backends at once.

### Dependency weight

Turning on `idn-pure` adds `idna` and everything `idna` needs. The exact
figures, and the convention they are counted under, because a bare number
here has been got wrong before:

| Configuration | Distinct names | Lock entries |
|---|---|---|
| Default or drop-in, `libc` only | 1 | 1 |
| With `idn-pure` | 33 | 34 |
| Added by `idn-pure` | +32 | +33 |

Two conventions, because a bare number here has been got wrong before. The
first column counts distinct package *names*; the second counts `[[package]]`
entries in the committed `rust-urlapi/Cargo.lock`, which is one higher because
`syn` is resolved at two versions and both are real entries in the closure.
Either column is reproducible from the tree rather than taken on trust. The
recipe lists the crate itself as well, so subtract one from what it prints:

    cargo tree --locked --no-default-features --features idn-pure \
      --prefix none --no-dedupe | sed 's/ v[0-9].*//' | sort -u

Measured that way the `idn-pure` closure prints 31 lines for 30 dependency
names, and the second column is 31 because `syn` resolves at both `2.0.119`
and `3.0.3` and each is a real `[[package]]` entry. Substituting
`--no-default-features --features idn-libidn2`, or dropping the feature
arguments for the default set, prints 2 lines for the single dependency
`libc`.

The `genheader` closure is a third figure: 31 dependency names, `cbindgen`
plus the 30 it brings. Its own default features -- the command-line front end
and the whole `clap` chain behind it -- are switched off in `Cargo.toml`,
which is why no `clap`, `anstyle` or `terminal_size` entry appears in the lock
file at all.

A caution about a shortcut that gives a different answer. Counting the whole
lock file,

    grep -c '^\[\[package\]\]' rust-urlapi/Cargo.lock

reports 65 -- this crate plus 64 dependency entries -- because it is the union
over every feature and every target rather than what any one build compiles.
It includes `cbindgen`'s generator tree, and `getrandom` with the `windows-*`
and `wasi` packages it names for platforms this work does not build for.
`getrandom` is worth naming because it is easy to attribute to the wrong
place: it is locked at `0.3.3`, it is reached through `cbindgen`'s
`tempfile` under `genheader`, and it is in neither the default nor the
`idn-pure` closure. The per-feature `cargo tree` recipe above is the one to
quote.

### The dependency closure the compiler floor pins

Size is not what settles this, and neither, on its own, is the compiler
floor. Under a release profile with link-time optimization, one
code-generation unit, abort-on-panic, and the alternative path reachable from
an exported symbol so that it cannot be optimized away, the measurement
recorded in the `AAP` at 0.5.1.2 is 7,526,790 bytes of archive by default
against 7,739,832 bytes with the feature on. The difference of 213,042 bytes
is too small to decide anything. The abort described above is what decides
it.

The compiler floor is the other half of the reason, and it is worth stating
exactly rather than approximately, because the committed lock file does not
say what an earlier revision of this section claimed it said.

`rust-urlapi/Cargo.toml` declares `rust-version = "1.75"`, curl's own
documented floor is the 1.73 toolchain at `docs/RUSTLS.md:L59`, and Cargo
refuses to build a package whose dependency asks for a newer compiler than
the one in use. So the floor a configuration actually has is the highest
`rust-version` in its closure, read out of `rust-urlapi/Cargo.lock`:

| Configuration | Highest declared floor | Package declaring it |
|---|---|---|
| Default | 1.65 | `libc` 0.2.189 |
| Drop-in, `--no-default-features --features idn-libidn2` | 1.65 | `libc` 0.2.189 |
| `--features genheader` | 1.74 | `cbindgen` 0.29.4 |
| `--no-default-features --features idn-pure` | **1.86** | `idna_adapter` 1.2.2 and the seven `icu_*` 2.2.0 packages |

The lock pins the `icu` 2.x line, not the 1.5 line: `icu_collections`,
`icu_locale_core`, `icu_normalizer`, `icu_normalizer_data`, `icu_properties`,
`icu_properties_data` and `icu_provider` are all at 2.2.0, and each of them
and `idna_adapter` 1.2.2 declares `rust-version = "1.86"` -- eleven minor
releases past this crate's own floor. `zerovec` 0.11.6 declares 1.83 and
three more packages declare 1.82 behind them.

The consequence is stated rather than papered over: **three of the four
configurations build at 1.75 and `idn-pure` does not.** That is the third
reason it is opt-in and outside the parity claim, alongside the abort above
and the Unicode-table difference. The verification matrix is therefore

    # passes
    cargo +1.75.0 check --locked
    # passes
    cargo +1.75.0 check --locked --no-default-features \
      --features idn-libidn2
    # passes
    cargo +1.75.0 check --locked --features genheader
    # FAILS, and is expected to
    cargo +1.75.0 check --locked --no-default-features --features idn-pure

with the fourth line expected to fail, naming `idna_adapter` or an `icu_*`
package. A run in which it passes means the closure moved and this table is
stale.

Two mechanical details behind that, neither readable off the lock file alone.

- Which versions a regeneration selects depends on what the resolver is told
  about the compiler. A plain `cargo generate-lockfile` under a current
  toolchain selects the newest compatible release of everything, which is what
  produced the 2.x `icu` line above. Setting
  `CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback` makes the resolver
  prefer versions whose declared `rust-version` the crate's own floor
  satisfies; it cannot invent one, so for `idn-pure` it changes which
  packages are tried and not the outcome above.
- A manifest can break a build without contributing a line of compiled code,
  because `cargo metadata` parses every locked manifest whether the build
  needs it or not. `cbindgen` is therefore declared with
  `default-features = false`: its default set builds a command-line front end
  and pulls `clap` and the terminal-styling chain behind it, none of which
  `build.rs` uses, and none of which appears in the lock file as a result.
  The same mechanism is why `getrandom` is in the lock at all -- `cbindgen`
  reaches it through `tempfile` -- and why the `windows-*` and `wasi`
  packages it names are locked for targets this work never builds.

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

## Checked and not a divergence: the generated mirror header is exact

`include/curl_urlapi_rs.h` is the standalone consumer's copy of the public
declarations. It carries the same public *contract* as
`include/curl/urlapi.h:34-149` -- the 33 result codes, the 11 part
identifiers, the 16 flag bits, the opaque handle and the six functions -- and
under the `genheader` feature `rust-urlapi/build.rs` **regenerates it byte for
byte** and fails the build on any difference.

This entry used to say the opposite. It listed the generated bytes as a
permanent residual divergence -- with a line count that two places in this
file disagreed about, which is its own kind of evidence -- and the check that
stood in for equality was a comparison of normalized ABI *projections* rather
than of text. That was wrong in two ways worth naming,
because both are the kind of wrongness that hides real drift:

- A projection blind to declaration shape is blind in a file whose whole
  purpose is to be a one-for-one mirror. Enumeration versus macro, the struct
  tag, parameter names, declaration order and alignment were all outside what
  the check could see.
- The generated intermediate was not even valid C89. `cbindgen`'s `cpp_compat`
  wrapper hard-codes `#endif // __cplusplus` and `}  // extern "C"`, and `//`
  is not a comment in C89 at all, so a strict compiler reported two errors and
  `scripts/checksrc.pl` reported three `CPPCOMMENTS` warnings on the very file
  the mechanism produced.

### How exactness is reached

`cbindgen` is still the source of the ABI, and it still cannot emit the
committed shape. What changed is that its output is now an **inventory** rather
than a candidate deliverable, and the emitting is done from that inventory.

1. `cbindgen.toml` sets `cpp_compat = false`, so the inventory contains no `//`
   anywhere and is itself strict C89. The `extern "C"` wrapper is not lost --
   `build.rs` writes it, C89-clean.
2. `build.rs` writes the inventory to `OUT_DIR/curl_urlapi_rs_cbindgen.h` and
   reads the ABI out of it: every object-like macro with an integer value,
   every `typedef` with its kind and name, and every function with its return
   type, arity and parameter types.
3. From that inventory it **emits** the mirror in the public header's own
   shape. The constants are grouped by name prefix and sorted by value, then
   rendered as `typedef enum` blocks -- ordinal comments aligned two columns
   past the longest enumerator, which is the column
   `include/curl/urlapi.h` itself uses -- and as sixteen `#define NAME (1 << n)`
   lines with their comments aligned one column past the longest declaration
   and continuations three further. The six declarations are wrapped greedily
   at 79 columns with continuations aligned after the open parenthesis. All of
   those alignments are computed from the data rather than written down.
4. The emitted bytes are compared with the committed file **byte for byte**.
   Any difference fails the build and reports the first differing line on both
   sides. Regeneration never writes into the source tree unless
   `CURL_URLAPI_WRITE_MIRROR_HEADER=1` asks it to, and because the comparison
   is exact that write is a no-op on an unchanged crate -- so regeneration is
   idempotent and `git status --porcelain` stays clean for that path.
5. The emitted mirror is additionally compiled with
   `-std=c89 -pedantic-errors -Wall` whenever a C compiler can be found, so
   "C89-clean" is measured rather than asserted. An absent compiler is a note,
   not a failure: the byte comparison is the gate.

### The three things the inventory cannot supply, and where they come from

Everything that is ABI comes from the inventory. Three things are not ABI and
are supplied by the fixed frame in `build.rs`, each for a mechanical reason:

- **The struct tag.** `cbindgen` derives it from the Rust item name, so the
  inventory writes `typedef struct CURLU CURLU;` where
  `include/curl/urlapi.h:107` writes `typedef struct Curl_URL CURLU;`, and no
  key sets the tag separately. The type is incomplete in both spellings and is
  only ever reached through a pointer, which is exactly what makes this port
  tractable. The typedef *name* beside it still comes from the inventory, so a
  rename there fails the comparison.
- **Parameter names, in both directions.** `curl_url_dup`'s parameter is `in`
  at `include/curl/urlapi.h:126`, which is a Rust keyword;
  `rust-urlapi/src/ffi.rs` spells it `r#in` and `cbindgen` emits `input`.
  `curl_url_strerror`'s parameter is the mirror-image case: `urlapi.h:149`
  leaves it unnamed and a Rust signature cannot, so the inventory names it
  `code`. The emitter applies the public header's names, the unnamed one
  included, which is `FB5` above honoured rather than repaired. Parameter
  *types* and the arity come from the inventory, so neither can drift.
- **The prose, the licence box and the per-value comment text.** No generator
  derives prose. Carrying it in `build.rs` is what lets the emitter produce the
  whole file, which is what makes the comparison a comparison of two
  independently produced files rather than of a projection. The duplication is
  deliberate and the byte comparison is what keeps the two copies in step: edit
  one and the build fails until the other matches.

One consequence of `src/abi.rs` holding the 60 values as explicit integer
constants rather than as Rust enumerations -- transformation rule `T2` at `AAP`
0.1.2.3 -- is worth keeping from the older text. The inventory therefore has no
enumerator list at all, which is why the emitter builds the two `typedef enum`
blocks from constants, and also why the C89 "comma at end of enumerator list"
diagnostic that an enum-shaped `cbindgen` output would produce never arises.

### What is excluded by name, and why

`cbindgen.toml` names three implementation constants in `[export] exclude`.
`item_types` includes `"constants"` for the sixteen `CURLU_*` flag bits, and
that reaches every `pub const` in the crate, so without the entries the mirror
would also carry `MAX_SCHEME_LEN`, `CURL_MAX_INPUT_LENGTH` and
`PROTOPT_URLOPTIONS`. The first carries no prefix and would occupy a global
macro name in every consumer; the other two restate private values from
`lib/urldata.h:L131` and `L545` in a public header.

A source-mode parse follows the `mod` declarations out of the crate root, so it
also sees every prototype the crate *imports* -- the five libidn2 entry points,
the two address converters, the two scheme lookups and the `struct Curl_scheme`
mirror. None of those may appear in a mirror of `urlapi.h`, so all ten are
excluded by name alongside the three internal exports, `Curl_parse_port` and
`curl_free`. Two constants `cbindgen` cannot represent in C, `DEFAULT_SCHEME`
at `rust-urlapi/src/abi.rs:L455` and `DEFAULT_SCHEME_CSTR` at `L471`, are
skipped by the generator itself and are therefore absent from that list; naming
them would not even quiet the log, because the skip message is emitted while
`cbindgen` parses, before the export filter runs. Verified by trying it.

### Why source mode rather than crate mode

Generation parses the crate root through `cbindgen`'s `with_src` entry point
rather than the crate directory through `with_crate`, and the reason is the
declared toolchain floor. `with_crate` reaches `Cargo::load`, which shells out
to `cargo metadata`, and that parses every locked manifest whether the build
compiles it or not -- including `idna_adapter 1.2.2`, whose edition-2024
manifest a 1.75 Cargo cannot read, on a build that compiles none of the
`idn-pure` graph. Source mode never asks the question, which keeps `genheader`
inside the declared floor without re-pinning the lockfile that `AAP` 0.5.1
records. The emitted bytes are the same either way, because
`parse.parse_deps = false` means a dependency was never going to contribute a
declaration.

### What was verified

The committed header is byte-identical to what the crate's ABI regenerates: 60
constants, 3 typedefs and 6 declarations. The emitted mirror and the inventory
both compile as strict C89 under `-std=c89 -pedantic-errors -Wall`. Drift is
caught in both directions: an edit to the committed header fails the build with
the differing line named on each side, and the committed header is registered
with `rerun-if-changed` so that the comparison actually re-runs when it is
edited -- it did not, once, and that gap is closed. The write-back path
restores the canonical bytes exactly, and running regeneration twice in a row
leaves the working tree clean.

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
`rust-urlapi/harness/shims.c` takes no part in that link.

## Reported constraint: the libidn2 version guard needs the header

`lib/idn.c:L252` opens `idn_decode` with
`if(idn2_check_version(IDN2_VERSION))`, where `IDN2_VERSION` is the version
string of the **header the C was compiled against**. The guard asks one
question: is the runtime library at least as new as the header?

The port asks the same question, from the same source. `build.rs` locates the
`idn2.h` this artifact will link against -- `CURL_URLAPI_IDN2_H`, then
`LIBIDN2_INCLUDE_DIR`, then the `pkg-config` tool's own `-I` list, then the
conventional roots -- parses `IDN2_VERSION` and `IDN2_VERSION_NUMBER` out of
it, and emits both for `rust-urlapi/src/ffi.rs`, which hands the string to
`idn2_check_version` exactly as the C hands its own. On the machine this port
was developed against that is `2.3.8` with `IDN2_VERSION_NUMBER` `0x02030008`,
matching `/usr/include/idn2.h`. The flag word is then decided from that number
in `rust-urlapi/src/ffi.rs`, which compares it against `0x00140000` in a
`const` -- the `#if` at `lib/idn.c:L254` written as a compile-time comparison
rather than as a run-time test. One number, read from the header the artifact
links against, and one comparison over it.

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

The floor `rust-urlapi/build.rs` additionally enforces on the version it finds
is `2.2.0`, and it is a security floor rather than a compatibility one: below
it the library carries the heap overflow fixed in 2.2.0, CVE-2019-12290, in the
same lookup entry points this crate calls, and `lib/idn.c` gates
`IDN2_NONTRANSITIONAL` on the compile-time version, so an older library also
changes which flags reach the lookup. A build against an older libidn2 is
refused with both reasons stated.

The `2.2.0` constant that `rust-urlapi/src/ffi.rs` names as its own
last-resort fallback is therefore unreachable whenever the libidn2 backend
is selected. It is written out rather than unwrapped because the crate
denies `unwrap`, and a constant with a stated fallback is easier to audit
than one that cannot fail for reasons stated in another file.

## Closed constraint: `cargo-c` and the `capi` feature

This entry used to record a constraint. It now records how the constraint was
closed, because the reasoning that kept it open was wrong in a way worth
keeping visible.

`cargo-c` 0.10.24 appends `--features capi` to every invocation whether or not
the package declares such a feature -- `src/build.rs:811` -- and treats a
package as C-API-relevant only when that feature is declared,
`src/build.rs:1183-1186`. It sets no environment variable, so a build script
cannot recognise a packaging run any other way. While `rust-urlapi/Cargo.toml`
declared no such feature, `cargo cbuild` stopped with "the package
`curl-urlapi-rs` does not contain this feature: `capi`" -- measured against the
installed 0.10.24 -- and the crate's `[package.metadata.capi]` blocks described
a packaging shape nothing could reach.

The earlier reading was that the `AAP` fixes the feature surface at six and a
seventh is therefore not permitted. What 0.3.1.1 actually fixes is the set of
**capability switches** -- `strerror`, `cfree`, `scheme-table`, `idn-libidn2`,
`idn-pure`, `genheader` -- each of which selects code. Meanwhile 0.5.1 lists
`cargo-c` as the optional packaging path "invoked from the crate's scripts",
0.4.1.1 gives `rust-urlapi/scripts/build-rust.sh` an "optional cargo-c path",
and 0.3.2 cites `cbuild` and `cinstall` by name as what produces the archive,
the shared object, the pkg-config file and the header a C consumer expects. A
plan cannot both require that path and forbid the one token it cannot run
without.

So `capi = []` is declared, and it is a token rather than a switch: nothing in
the crate or in `rust-urlapi/build.rs` reads it, no `cfg` tests it, it is
absent from `default`, and enabling it changes no compiled code. The six
capability switches are still six. `cargo cbuild --release` now completes and
produces the archive, the shared object, the two pkg-config files and the
committed header, with `generation = false` keeping it from emitting a
competing header of its own.

One property of that path is worth knowing rather than discovering: `cargo-c`
builds the archive and the shared object **without** the rlib, so it does apply
the `lto = true` that `[profile.release]` asks for, where a plain
`cargo build --release` cannot. See "What this costs, stated plainly" under the
shared-object entry below for the two archives that fall out of that and which
one is publishable.

## Reported precondition: a 32-bit `curl_prot_t` in drop-in mode

Drop-in mode reads libcurl's own scheme descriptors through a `#[repr(C)]`
mirror of `struct Curl_scheme`, `lib/urldata.h:L515-L524`, held in
`crate::ffi::scheme_import`. Of its six fields the URL API reads three:
`flags`, `defport` and whether `run` is null. The mirror describes all six,
because the three that are read sit after the three that are not and cannot be
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

`LAYOUT_PROOF` in `rust-urlapi/src/ffi.rs`, immediately below the
`CurlScheme` mirror it guards, pins the *Rust* side to the shape the port
assumes, at compile time: it catches a reordered field, a widened integer, a
dropped `#[repr(C)]` and an unexpected pointer width, and the module's test
block re-derives all six field offsets besides. What it cannot do is observe
the C side, because nothing compiled into the crate can read
`lib/urldata.h`.

`check_scheme_layout_precondition` in `rust-urlapi/build.rs` covers the C
side, textually: it reads `../lib/urldata.h` and requires both a
`#define PROTO_TYPE_SMALL` line and a `typedef uint32_t curl_prot_t` line,
panicking with both remedies named if either is gone, and emitting a note
rather than failing when the header cannot be found -- which is the ordinary
case for a standalone build outside a curl checkout.

Together they cover more than either alone, and still not everything, which
is why this stays a **reported precondition** rather than a closed item. The
text of a header is not the preprocessed header: the check requires those two
lines to be present, not to be reached, so an edit that moved either inside a
conditional that does not hold would satisfy it and still widen the type. And
the header it reads is the one in the tree this crate sits in, which is the
right tree for a drop-in link against a libcurl built from it and the wrong
one for a link against an archive built somewhere else. So a 32-bit
`curl_prot_t` remains a documented **precondition** of drop-in mode, checked
as far as text can check it.

The live cross-check is the parity run. `tests/libtest/lib1560.c` asserts
default ports directly -- `https://127.0.0.1` with `CURLU_DEFAULT_PORT` must
yield `443` at L592-L594, and `http://example.com:80` with
`CURLU_NO_DEFAULT_PORT` must serialize without the port at L786-L788 -- and
both readings come through `defport`. A shifted mirror fails those on the
first sub-test rather than subtly.

Standalone mode is unaffected. It compiles its own table in
`rust-urlapi/src/scheme.rs` and describes no C structure at all, so there is
no layout to get wrong.

## Checked and not a divergence: dynamic-buffer cleanup in `lib/urlapi.c`

This entry records a claim that did **not** survive checking, because two
comments in `rust-urlapi/src/dynbuf.rs` used to assert that this file listed
places where `lib/urlapi.c` fails to reach `curlx_dyn_free()`. It does not,
and it should not: there are none.

The mechanism is in the dynamic buffer rather than in its callers.
`dyn_nappend` at `lib/curlx/dynbuf.c:L67-L112` calls `curlx_dyn_free(s)` on
both of its failure paths, at L83 when the request exceeds the ceiling and at
L107 when the reallocation fails. `curlx_dyn_addn`, `curlx_dyn_add` and
`curlx_dyn_addf` all route through it, so **a failed append has already
released the buffer** and a `return` immediately after one is not a leak.
That is contract 1 in `rust-urlapi/src/dynbuf.rs`'s own module
documentation, and it is what makes the C's terse error handling correct.

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
recorded because `rust-urlapi/harness/shims.c` promises it is recorded.

`rust-urlapi/harness/shims.c` implements `curl_msnprintf()` and
`curl_mvsnprintf()` by forwarding to the C library's `vsnprintf()`, because
the standalone link has no libcurl to supply `lib/mprintf.c`. **The bytes
written are identical for every input.** curl's `addbyter()` at
`lib/mprintf.c:L1065-L1075` stores a byte only while `length < max`, and the
tail at L1088-L1098 either overwrites the last stored byte with a
terminator, when the buffer filled exactly, or appends one when it did not
-- at most `maxlength - 1` characters plus a terminator, which is C99
`vsnprintf`'s truncation rule exactly. A zero `maxlength` writes nothing
under either implementation.

The **return value** differs, and only when the output was truncated. curl
answers with the count it actually wrote, decremented at
`lib/mprintf.c:L1094` on truncation. C99 `vsnprintf` answers with the count
it *would* have written had the buffer been large enough. Where nothing was
truncated the two answers agree.

Nothing in either oracle can observe the difference.
`tests/libtest/lib1560.c` calls the function three times: L71 and L74 build
a buffer whose result is then measured with `strlen()` at L76, and L1940
discards the return value outright. `rust-urlapi/demo/urlapi_demo.c` follows
`docs/examples/urlapi.c` and formats with `printf` from the C library, so it
never reaches the shim at all -- checked against the file: it calls no
`curl_m*` function of any kind, and `rust-urlapi/demo/.checksrc` bans all ten
names so that a later edit cannot quietly change that.

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

### `AAP` 0.6.5 governs here, and the port diverges from `lib/urlapi.c` to obey it

**This subsection records the port's one deliberate behavioural divergence from
the reference, and reports the discrepancy that forces it.** The behaviour is
specified by the frozen Agent Action Plan, the reference implements something
else, and the plan wins. What is escalated is the discrepancy itself, not the
choice of what to implement.

**What the plan requires, and what the port therefore does.** `AAP` 0.6.5
states the empty-string flag sensitivity in these terms:

> Setting the whole URL to the empty string with the no-guess-scheme flag
> on a handle whose scheme was guessed **fails** with malformed input --
> because the retrieval returns the no-scheme code `lib/urlapi.c:L1559-L1560`
> -- while the identical call with no flags **succeeds** as a no-op.

`rust-urlapi/src/getset.rs` implements exactly that. `set_url` answers
`CURLUE_MALFORMED_INPUT` when the value is empty, `CURLU_NO_GUESS_SCHEME` is
set and the handle's scheme was guessed, and it makes that decision **ahead of**
the whole-URL read, because the read cannot produce the answer. Without the
flag, or on a handle whose scheme was not guessed, the same empty write is the
ordinary no-op success documented two subsections above. The per-file
specification for that module restates the pair as mandatory -- "the
empty-string rule with no flags (success) and with `CURLU_NO_GUESS_SCHEME` on a
guessed-scheme handle (malformed input)" -- and
`tests::an_empty_url_and_no_guess_scheme_is_malformed_input` asserts both halves
on one handle.

**What the source does instead.** `CURLU_NO_GUESS_SCHEME` has two unrelated
effects, in two different branches of the reader. In the `CURLUPART_SCHEME`
branch it is an error: L1559-L1560 return `CURLUE_NO_SCHEME`. In the whole-URL
branch it is only a formatting choice: L1512-L1515 blank the scheme prefix and
carry on returning `CURLUE_OK`. L1700 asks for `CURLUPART_URL`, and L1623-L1624
dispatches that to `urlget_url`, so the reference meets the second behaviour and
never the first.

The mechanism the plan cites is in fact unreachable in the C.
`u->guessed_scheme` is assigned in exactly one place, L1008 inside
`guess_scheme()`, and L1004-L1006 stores `u->scheme` immediately before it; the
only other sites, L1662 and L1741, clear the flag. So a handle whose scheme was
guessed always has a scheme string, and the `CURLUE_NO_SCHEME` at L1453-L1458 --
which fires only when there is no scheme and no `CURLU_DEFAULT_SCHEME` -- cannot
fire on such a handle. The plan's *outcome* is implementable; its stated
*reason* is not, which is why the port implements the outcome directly rather
than by arranging for the read to fail.

**Measured against the reference build.** A probe linked against an unmodified
`libcurl.a`, under `LC_ALL=C.UTF-8` with `setlocale(LC_ALL, "")` called:

    parse "example.com/p" GUESS_SCHEME, write "" flags 0           rc=0
    parse "example.com/p" GUESS_SCHEME, write "" NO_GUESS_SCHEME    rc=0
    parse "https://example.com/p",      write "" NO_GUESS_SCHEME    rc=0
    parse "example.com/p" DEFAULT_SCHEME, write "" NO_GUESS_SCHEME  rc=0
    read SCHEME on the guessed handle, NO_GUESS_SCHEME              rc=10
    read URL    on the guessed handle, NO_GUESS_SCHEME               rc=0

Return code 10 is `CURLUE_NO_SCHEME`. The second line is where the port now
answers 3, `CURLUE_MALFORMED_INPUT`, and the reference answers 0. Every other
line is unchanged by the port.

Re-measured since, from one probe source linked three ways -- unmodified
`libcurl.a`, the drop-in link, and the standalone link -- so that the reading
is not an artifact of one link mode. The drop-in and standalone outputs are
**identical to each other**, and against the reference the whole probe differs
in that one line and no other. Two properties were checked at the same time and
both hold:

- **the refused write leaves the handle exactly as it was.** Reading
  `CURLUPART_URL` with flags of zero straight after the refusal answers
  `CURLUE_OK` and `http://guessed.example/p?q=1#f` in the port, byte for byte
  what the reference answers there. It is a refusal, not a partial mutation.
- **the `CURLU_DEFAULT_SCHEME` sensitivity is reproduced exactly**, which is
  the half of this subject the port does *not* diverge on. On a handle whose
  scheme was cleared, both implementations answer `CURLUE_NO_SCHEME` to a
  whole-URL read with flags of zero, `CURLUE_OK` with `CURLU_DEFAULT_SCHEME`,
  `CURLUE_MALFORMED_INPUT` to an empty write with flags of zero, and
  `CURLUE_OK` to an empty write with `CURLU_DEFAULT_SCHEME`. So the divergence
  really is confined to the single combination 0.6.5 names.

**Why the plan governs.** The plan is the frozen, agreed source of truth for
this work, and a specification that states an outcome is not overridden by an
implementation that does something else. `AAP` 0.2.2 designating `lib/urlapi.c`
"the behavioural source of truth", rule `T6` "faithful over correct" and 0.8.1's
"do not change error semantics" all point the other way, and they are the reason
this subsection exists rather than a silent edit: where a general principle and
a specific frozen requirement collide, the specific requirement is what an
implementer is bound by, and the collision is what gets reported.

**Why the divergence costs nothing measurable, checked rather than assumed.**

- **`A5` is untouched.** `tests/libtest/lib1560.c` never writes `""` to
  `CURLUPART_URL` anywhere -- searched, not supposed -- so the unmodified oracle
  cannot reach this arm. It still prints `success` in the drop-in link, under
  both `LC_ALL=C.UTF-8` with the codeset variable set and `LC_ALL=C` without it.
- **`A7` is untouched.** `rust-urlapi/demo/urlapi_demo.c` deliberately does not
  exercise this one combination, so the byte-for-byte diff against the same demo
  linked against the unmodified C is unaffected. The demo says so where the
  omission is, and points here.
- **The read side is untouched.** `get_url_list` at `tests/libtest/lib1560.c`
  L583-L585 asserts `{"example.com", "example.com/", CURLU_GUESS_SCHEME,
  CURLU_NO_GUESS_SCHEME, CURLUE_OK}`, and `get_parts_list` at L149-L152 asserts
  `[10]`, `CURLUE_NO_SCHEME`, for the scheme part of the same handle under the
  same flag. Both still hold; the divergence is on the write side only, and the
  test asserts the read alongside it so that a port which "fixed" the read
  instead would fail.
- **The handle is unchanged by the refusal**, so this is a refusal and not a
  partial mutation.

**What is asked of the plan's owner.** A decision, with the evidence above in
hand: either 0.6.5 stands and this divergence from `lib/urlapi.c` is the
intended behaviour, or 0.6.5 is corrected to name `CURLU_DEFAULT_SCHEME` -- the
flag that really causes a flag sensitivity in the reference, documented with its
own measurements in the subsection above this one -- and the port drops the arm.
Until that decision is recorded in the plan, the port implements 0.6.5 as
written and this subsection is the report.

**What is deliberately not being done.** The plan is not edited. No acceptance
criterion is narrowed. The `CURLU_DEFAULT_SCHEME` sensitivity is not presented
as a replacement for 0.6.5's text -- it is a separate, independently measured
finding. And the divergence is not extended by one byte beyond the single
combination 0.6.5 names: everything else on this path, read and write, is the
reference's behaviour.

### The surrounding dispatch

For completeness: a value that is not empty goes to the absolute-URL test at
L1713-L1714, which is passed the caller's flags narrowed to the bitwise or
of `CURLU_GUESS_SCHEME` and `CURLU_DEFAULT_SCHEME`, and an absolute value
replaces the contents through `parseurl_and_replace()` at L1715.

### What the port does

`rust-urlapi/src/getset.rs` carries the empty-string rule in `set_url()` in two
parts, and the order matters.

First the arm `AAP` 0.6.5 specifies: an empty value carrying
`CURLU_NO_GUESS_SCHEME` on a handle whose scheme was guessed answers
`CURLUE_MALFORMED_INPUT` without reading anything. It has to come first,
because the read cannot produce that answer -- which is the discrepancy the
subsection above reports.

Then the rule as `lib/urlapi.c` writes it, unchanged: the caller's flags go into
the whole-URL read exactly as L1700 hands them over, the read succeeding is
`CURLUE_OK`, `CURLUE_OUT_OF_MEMORY` passes through unaltered, and every other
failure becomes `CURLUE_MALFORMED_INPUT`. Nothing else about the empty string is
special-cased, which is why the `CURLU_DEFAULT_SCHEME` sensitivity falls out
rather than being coded, and why an implementation that shortcut the read would
answer wrongly for one of those two halves.

Four tests in that module pin the whole of it: the no-op success on a complete
handle, guessed and explicit; the 0.6.5 pair on one guessed-scheme handle with
the flag the only difference, asserted alongside the whole-URL read that must
keep succeeding; the `CURLU_DEFAULT_SCHEME` sensitivity documented two
subsections above; and the failing half on an empty handle and a scheme-only
handle. `rust-urlapi/demo/urlapi_demo.c` prints the cases that are common to the
port and the reference, so the byte-for-byte diff against the reference-linked
build of that program checks those from outside the crate as well -- and it
deliberately omits the one combination where the two differ, which is what keeps
that diff a parity check rather than a known failure.

## Hardened, not divergent: a null handle where the C dereferences one

`curl_url_dup(NULL)` returns `NULL`. The same call against unmodified libcurl
faults.

`lib/urlapi.c:L1310-L1332` never tests `in`. L1312 allocates the copy, and
L1314 onwards reads `in->scheme`, `in->user` and eight more members through the
`DUP` macro at L1301-L1308, with L1324-L1326 reading the three non-string
members directly. A null `in` is dereferenced at the first of those. The manual
page does not permit a null handle either: `docs/libcurl/curl_url_dup.md`
documents the argument as a handle and its return value as "a pointer to a new
`CURLU` handle or NULL if out of memory", L59, so the call has no defined
behaviour at all -- there is nothing here for a port to be faithful *to*.

Measured, both programs compiled from one source and linked two ways:

    reference libcurl.a   copy = curl_url_dup(NULL)   SIGSEGV, exit 139
    the port              copy = curl_url_dup(NULL)   copy == NULL, exit 0

`rust-urlapi/src/ffi.rs` reaches that answer without a null test of its own:
`curl_url_dup` takes `*const CurlUrl` and calls `as_ref()`, which yields `None`
for a null pointer without dereferencing it, and the `None` arm returns
`ptr::null_mut()`. The same shape covers `curl_url_get` and `curl_url_set`,
whose null-handle answer *is* specified -- `CURLUE_BAD_HANDLE`, which
`include/curl/urlapi.h:L36` names and the port returns -- so the hardening is a
property of one uniform pattern rather than a special case bolted on.
`curl_url_cleanup(NULL)` is defined by the C itself at L1295 and behaves
identically in both.

This entry is here for one reason: to keep the difference from being filed
later as an unrecorded divergence. It is not one, and the distinction is worth
stating precisely. `A10` and the "faithful over correct" rule bind the port to
behaviour the C *defines*; a dereference of null defines nothing, so there is
no behaviour to reproduce and reproducing the crash would buy nothing but a
crash. `rust-urlapi/src/ffi.rs` says so at the function's `# Returns`, and
`curl_url_dup_reports_a_null_input_rather_than_faulting` in that module's tests
pins it. A probe that compares the port against the reference must compile this
one call out of the comparison, which is what a `-DPROBE_NO_UB`-style guard is
for; the port's answer is then checked on its own.

## Hardened, not divergent: `Curl_is_absolute_url` honours `buflen`

The C ignores the buffer length it is given. The port does not, and where the C
would write past the end of a caller's buffer the port stops at it.

`lib/urlapi.c:L186-L187` is explicit about it:

    DEBUGASSERT(!buf || (buflen > MAX_SCHEME_LEN));
    (void)buflen; /* only used in debug-builds */

So the length is a *precondition*, checked in a debug build and discarded in a
release one. Every write in L182-L220 then proceeds as though the buffer were
large enough: L188-L189 stores a terminator, and L213-L215 lowercases the whole
scheme into `buf` and terminates it after the last byte. `MAX_SCHEME_LEN` is 40
at L55, so a conforming caller passes at least 41.

Measured with a 256-byte buffer zeroed before each call, the input
`longscheme-abcdefghij://x/`, whose scheme is 21 bytes:

    buflen=8    reference  ret=21 buf=[longscheme-abcdefghij]
    buflen=8    the port   ret=21 buf=[longsche]
    buflen=0    reference  ret=21 buf=[longscheme-abcdefghij]
    buflen=0    the port   ret=21 buf=[]
    buflen=41   both       ret= 5 buf=[https]        (HTTPS://example.com/)
    relative    both       ret= 0 buf=[]             (relative/path)

The reference wrote 22 bytes into a buffer it was told held eight, and then 22
into one it was told held none. Only the surrounding 256-byte allocation kept
that from being a live overflow. The port writes `min(found + 1, min(buflen,
41))` bytes and leaves a short buffer unterminated, which is the bounded
direction and the only one Rust can take through a `*mut c_char` it is told the
extent of.

**The return value is identical in every case, conforming or not**, because it
reports what was *measured* rather than what was written -- 21 for the long
scheme in all four rows above. So a caller that only reads the result cannot
tell the two implementations apart at all.

Nor can any real caller tell from the buffer. All three call sites outside the
module pass no buffer: `lib/http.c:L1177`, `lib/http1.c:L220` and
`lib/url.c:L1661` all read `Curl_is_absolute_url(..., NULL, 0, ...)`, and so
does `lib/urlapi.c:L1713`. The one call that passes a buffer is
`lib/urlapi.c:L1128`, handing over the `char schemebuf[MAX_SCHEME_LEN + 1]` it
declares at L1114 -- 41 bytes, exactly the minimum L186 asks for. A `buflen` at
or below 40 with a non-null `buf` is therefore a contract violation that no
code in the tree commits.

Recorded here rather than left in the source alone because this document is the
register a reader consults, and because the difference is real in the one shape
that reaches it. `rust-urlapi/src/ffi.rs` carries the same statement in the
function's `# Safety` section, where the precondition belongs, and the tests in
that module exercise the conforming shapes -- a 41-byte buffer at the exact
documented minimum, a 256-byte one, and the aliased call where `buf` and `url`
are one address -- against the reference's measured answers.

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
harness compares against: OpenSSL, libidn2, OpenLDAP and nghttp2 all enabled
and nothing disabled. `rust-urlapi/scripts/build-reference.sh` is to configure
that build; it is a later deliverable and does not exist yet, so the
configuration is currently issued by hand and this model is what it has to
match.

`rust-urlapi/src/scheme.rs` writes that model out as `mod capability`, one
constant per `USE_*` and per `CURL_DISABLE_*`, and every one of the 33 rows
spells its own condition in terms of those constants, next to the `#if` line
in the C it reproduces. So `https` and `imaps` report an implementation,
while the six `rtmp*` rows and `scp`/`sftp` do not -- librtmp is not
installed and no SSH backend is built.

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
answers capability questions from the modeled table rather than from the linked
libcurl's own. Nothing in a Cargo build can detect that: `rust-urlapi/build.rs`
cannot see which archive a later C link line names. `rust-urlapi/Cargo.toml`
states the distinction where the three features are declared, and this entry is
the other half of that control.

### What the port does

`rust-urlapi/src/scheme.rs` keeps both backends behind one interface, and a
test pins the per-row model: `https` and `imaps` implemented, `rtmp` and
`sftp` not, so neither answer can quietly become blanket.
`rust-urlapi/Cargo.toml` sets the defaults for Mode B and names Mode A's
inversion (`--no-default-features --features idn-libidn2`) next to the
reason it matters.

## Integration limitation: the shared object exists in one configuration only

`rust-urlapi/Cargo.toml` declares `crate-type = ["staticlib", "cdylib",
"rlib"]`, and `crate-type` is a property of the package: every configuration
of this crate offers all three artifacts. The scheme provider is a property of
the **feature set**. Those two facts do not compose, and this entry records
what the port does about it.

### Why a drop-in shared object cannot work

With `scheme-table` off -- the drop-in configuration -- `rust-urlapi/src/scheme.rs`
imports libcurl's own lookup through `crate::ffi::scheme_import`, which is what
the plan requires at 0.3.1.1, 0.4.2.4 and 0.6.7 so that the real and complete
table answers every capability question. The two names it imports,
`Curl_get_scheme` and `Curl_getn_scheme`, are declared at `lib/url.h:L76-L77`
and are libcurl-**private**: libcurl's visibility and export rules keep them
out of a shared libcurl's dynamic symbol table, so nothing a runtime loader
can reach ever supplies them.

An undefined reference to either therefore resolves in exactly one situation,
a static link in which `url.c.o` takes part. That is the drop-in link, and it
is the only form a replacement for `urlapi.c.o` is ever consumed in: the
artifact is linked *into* libcurl, where `Curl_get_scheme` is a sibling object
rather than a foreign import.

A shared object built from that same compilation is a different matter, and
measurement is blunt about it. Before this was addressed,
`libcurl_urlapi_rs.so` built with `--no-default-features --features
idn-libidn2` came out with

    U Curl_get_scheme
    U Curl_getn_scheme

and a NEEDED list of `libidn2.so.0`, `libgcc_s.so.1`, `libc.so.6` and the
dynamic loader -- no `libcurl` entry, and no prospect of one. Loading it fails
at `dlopen`, deterministically, on every platform.

### The rule, and how each configuration carries it

**A shared object is a deliverable only where the crate is self-contained.**
That is the standalone configuration, whose built-in table needs nothing from
libcurl and whose whole undefined set is libc, libgcc and libidn2 -- each one
a real NEEDED entry. The drop-in configuration's deliverable is the archive.

`rust-urlapi/build.rs` `emit_shared_artifact_gate` carries the rule two
different ways, because what it costs differs between the configurations:

- **standalone, release, ELF target**: the link gets
  `cargo:rustc-cdylib-link-arg=-Wl,-z,defs`, so an unresolved strong reference
  stops the link. The proof is free -- the link succeeds -- and it holds on
  **every release build** rather than on the occasions somebody remembers to
  run `nm -D -u`.
- **drop-in, release**: no directive, and a `cargo:warning` naming
  `libcurl_urlapi_rs.so` a non-deliverable, saying why it cannot load, and
  naming the archive to consume in its place. `CURL_URLAPI_STRICT_CDYLIB=1`
  restores the refusal for a caller who would rather have it.

Cargo applies the directive to the cdylib link and to nothing else, so the
archive, the rlib, `cargo check` and `cargo clippy` are untouched by it either
way.

### Why the drop-in configuration is announced rather than refused

The first version of this gate applied `-Wl,-z,defs` in both configurations,
and that was a defect rather than a stricter reading. `crate-type` belongs to
the package, so `cargo build --release` asks for the archive, the rlib **and**
the cdylib in one invocation, and Cargo stops at the first failing link.
Refusing the cdylib therefore did not decline to emit a shared object: it
emitted **nothing at all**. Measured, in the drop-in configuration:

    cargo build --release --locked --no-default-features --features idn-libidn2
    exit=101
    rust-lld: error: undefined symbol: Curl_getn_scheme
    rust-lld: error: undefined symbol: Curl_get_scheme
    ls target/release/libcurl_urlapi_rs.{a,rlib,so}  ->  no such file, x3

The plan requires the opposite. 0.9.2 `A1` is "the crate builds cleanly in both
feature configurations" and names `--no-default-features --features
idn-libidn2` as one of the two; `G1` at 0.1.1.1 asks for one archive and one
shared object from a single crate. A build script that trades those away to
protect an artifact nobody was going to install has the priorities backwards.

So the shared object is announced instead. The warning reaches whoever started
the build, which is the person able to act on it, and it says what the linker
error never did -- not merely that a link failed, but that this configuration
has no shared deliverable and which artifact to take instead. The same build
writes the archive and the rlib, as `A1` requires.

### What the strict opt-in is for, and what it costs

`CURL_URLAPI_STRICT_CDYLIB=1` puts `-Wl,-z,defs` back on the drop-in release
cdylib link, for a packaging job that would rather fail than have to read a
warning. It is opt-in because switching it on reinstates exactly the behaviour
above: exit 101, no archive, no rlib, `A1` unmet. `build.rs` says so in the
build log when it honours the variable, so nobody sets it and then wonders
where the archive went.

### Why the gate stops at the release profile

Cargo builds **every** crate type of a lib target whenever it builds that
target, and an integration test under `rust-urlapi/tests/` needs the lib
target built. Gating the dev profile as well would therefore stop `cargo test`
from running in the drop-in configuration whenever the strict opt-in was set --
measured, not supposed -- and the plan calls for five integration tests that
have to run in both configurations. So the gate is scoped to the profile that
produces deliverables: `release` is the profile every documented build command
names, and the one `[profile.release]` in `rust-urlapi/Cargo.toml` exists to
configure.

The residue is that a **debug** shared object in the drop-in configuration is
producible and carries the two unresolved references, with no warning attached
because the gate does not run there. It is not a deliverable, nobody installs
one, and `build.rs` records the fact in the build log rather than passing over
it. That residue is one of the two reasons this entry exists rather than being
closed outright; the other is that a release drop-in `.so` is producible too,
and it is a warning rather than an impossibility that keeps it out of an
install.

### What this costs, stated plainly

A drop-in `cargo build --release` succeeds and writes all three artifacts, of
which two are deliverables. The archive it writes is an **input** rather than
the drop-in artifact, for a reason unconnected to this entry: Cargo cannot
apply link-time optimisation while an rlib is among the crate types, so the
three-type archive is several times larger and still carries the Rust standard
library's globals -- 22,266,440 bytes and 2,416 defined globals as against
7,613,238 and 625 for the single-crate-type build, measured in the standalone
configuration. What a consumer is given is the localized archive, which starts
from asking for the archive alone:

    cargo rustc --release --no-default-features --features idn-libidn2 \
      --lib --crate-type staticlib

`--crate-type` on `cargo rustc` has been stable since 1.64, below the 1.75
floor `rust-urlapi/Cargo.toml` declares. `cargo test` needs no such flag,
because the dev profile is ungated. Neither size figure is a requirement --
the plan sets no size or performance target at 0.8.5 -- and they are quoted
only so that the two archives are not mistaken for each other.

### Why it is an integration limitation rather than a defect

Nothing in `lib/urlapi.c` has this problem, because `urlapi.c.o` is not a
library: it is one object inside libcurl, and its references to
`Curl_get_scheme` are resolved by the same link that produces libcurl itself.
The port reproduces that arrangement exactly for the archive. What it cannot
reproduce is a *standalone shared object* with the same provider, because the
provider is private to a library the shared object does not contain. Hence one
configuration, one artifact -- reported here rather than papered over with a
second scheme table that would answer capability questions from the wrong
build.

## Integration limitation: drop-in mode presumes a 32-bit `curl_prot_t`

In drop-in mode `crate::ffi::scheme_import` describes `struct Curl_scheme`
from `lib/urldata.h:L515-L524` so that `rust-urlapi/src/scheme.rs` can read
the three fields `lib/urlapi.c` consults from the descriptor
`Curl_get_scheme` returns. Reading the last of those three requires knowing
the offsets of the ones before it, so the mirror has to describe all six
fields even though only three are read, and every field's width has to be
right.

One width is not fixed by the C. The two fields the mirror does *not* read,
`protocol` at `lib/urldata.h:L518` and `family` at L520, are each a
`curl_prot_t`, and L82 defines `PROTO_TYPE_SMALL` while L84-L88 makes
`curl_prot_t` a `uint32_t` while that macro is defined and a `curl_off_t` if
it is ever undefined. The two fields the mirror *does* read sit after them and
have fixed widths of their own -- `flags` is a `uint32_t` at L522 and
`defport` a `uint16_t` at L523 -- so what a widened `curl_prot_t` moves is not
their types but their offsets, by eight bytes. The mirror assumes the narrow
case, which is what the header currently says.

### What is checked, and what is not

Two mechanisms, and neither covers the whole of it.

`LAYOUT_PROOF` in `rust-urlapi/src/ffi.rs`, directly below the `CurlScheme`
mirror it guards, pins *the Rust side* at compile time. It catches an edit
made there -- a reordered field, a widened integer, a `#[repr(C)]`
accidentally dropped, a pointer width the port has not reasoned about -- and
the module's test block re-derives all six offsets besides. What it cannot do
is observe the C side, because nothing compiled into the crate can read
`lib/urldata.h`.

`check_scheme_layout_precondition` in `rust-urlapi/build.rs` reads that
header, textually, and requires both a `#define PROTO_TYPE_SMALL` line and a
`typedef uint32_t curl_prot_t` line. If either is gone the build panics and
names both remedies -- widen the two mirrored fields, or select
`scheme-table` and describe no C structure at all. If the header cannot be
found, the ordinary case outside a curl checkout, it notes and continues.
`lib/urldata.h` itself is out of scope and is never edited; reading it is not
editing it.

What survives both is the gap between a header's text and its preprocessed
meaning: the check requires those two lines to be present, not to be reached.
So this remains a **precondition** of drop-in mode rather than a closed
invariant. A libcurl whose `curl_prot_t` had widened would shift `flags` and
`defport` under the mirror's feet and the crate would read the wrong bytes,
silently.

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

Every behavior a caller can observe in the six findings above is reproduced
deliberately. None of them is an accident of the port, and none is a defect
to be filed against it. Two carry a qualification rather than a blanket
claim, and it is stated where each is recorded and again below: `FB2` and
`FB3` are each a leak as well as a behavior in the C, and it is the behavior
that is reproduced, not the leak.

The catalog is kept honest by tests rather than by good intentions. Each of
the five behavioral findings is pinned by unit tests in the module that
carries it -- `FB1` in `rust-urlapi/src/handle.rs`, `FB2` in
`rust-urlapi/src/parse/authority.rs`, `FB3` and `FB6` in
`rust-urlapi/src/parse/ipv6.rs`, `FB4` in `rust-urlapi/src/parse/port.rs`,
several of them named for the finding they guard -- so a later attempt to
tidy one of them up breaks a test instead of passing unnoticed, and whoever
hits that test arrives here to find out why. `FB5` is a property of a header
rather than a behavior, and what holds it is the byte-for-byte regeneration the
`genheader` feature runs: the emitter applies the public header's parameter
names, the unnamed one included, so repairing the omission fails the build. `FB1` is exercised through the C entry points
as well, by `rust-urlapi/demo/urlapi_demo.c`, whose output is compared byte
for byte against the same program linked against the unmodified C.
`rust-urlapi/tests/ffi_surface.rs` is to add a second pass over the C
surface from Rust; it is a later deliverable and does not exist yet. The
record and the code move together either way: a finding that stops being true
belongs in a commit that removes it from both.

Two points invite a wrong summary of this file and are worth stating
plainly. **In the C**, the empty-string flag sensitivity runs through
`CURLU_DEFAULT_SCHEME` and L1455-L1458, not through `CURLU_NO_GUESS_SCHEME`:
L1700 reads `CURLUPART_URL`, and the `CURLUE_NO_SCHEME` guard at L1559-L1560
belongs to the `CURLUPART_SCHEME` branch, so passing `CURLU_NO_GUESS_SCHEME`
leaves the reference's result at `CURLUE_OK`. **In the port** that one
combination answers `CURLUE_MALFORMED_INPUT` instead, because `AAP` 0.6.5
requires it; the entry on the empty-string rule reports the discrepancy and
bounds the divergence. And a scheme produced by guessing is `http`, from
L1002, **not** the `https` of L84, which belongs to
`CURLU_DEFAULT_SCHEME`.

### Why the other eleven entries stay, which is a different reason

The three residual divergences, the two hardenings and the four integration
limitations are not reproduced oddities and `A10` does not cover them, so they
need their own justification and it is not "faithfulness".

They stay because a reader who does not know about them cannot use this port
correctly. Every one of them is a place where something *outside* the ported
behavior can go wrong quietly: a Mode A integrator gets a clean link and the
wrong capability table; a `PROTO_TYPE_SMALL` libcurl shifts a structure the
crate reads and nothing says so; a shim returns a number that would be wrong
if anyone read it. None of these produces a failing assertion, and three of
them produce no diagnostic at all, so a document is the only mechanism
available.

The two hardenings stay for the adjacent reason: nothing in the port *or* the
reference will ever report them. `curl_url_dup(NULL)` and a short `buflen` are
undefined behavior in the C, so there is no assertion to fail and no diagnostic
to emit -- the reference simply faults in the first case and overruns silently
in the second. What a document buys there is that the next reader comparing the
two implementations knows in advance which two calls cannot be compared, and
why the port's answer is the one to keep.

One of the eleven is a partial exception, and it is worth naming as such: the
shared object that exists in one configuration only now *does* produce a
diagnostic in the release profile -- `-Wl,-z,defs` in the standalone
configuration, where it is a link failure if closure is ever lost, and a
`cargo:warning` in the drop-in one. It stays in this catalog for two reasons
all the same. The drop-in diagnostic is a warning rather than an impossibility,
so a build that ignores warnings still produces an object that cannot load; and
the dev profile is left ungated so that `cargo test` can run, which leaves a
debug shared object producible and undiagnosed.

That is also why in-scope files point here by name -- 22 of them, counted with
`git grep -l KNOWN-DIVERGENCES -- rust-urlapi` across the crate's Rust, C,
header and configuration files, so the number can be re-derived rather than
trusted. The pointers and these sections are one control, not two, and a
pointer that does not resolve disables it. Five of those files point at the
entries in this section rather than at a finding: `rust-urlapi/build.rs`,
`rust-urlapi/Cargo.toml`, `rust-urlapi/harness/shims.c`,
`rust-urlapi/include/curl_urlapi_rs.h` and `rust-urlapi/src/ffi.rs`.
`build.rs` is the one to be most careful with, because most of its eleven
pointers are not comments at all: two are the text of a `cargo:warning`, three
of a `panic!` and two of a build-log note, so they reach a terminal or a log
verbatim; three are comments and one is text emitted into the generated header.
Moving or renaming a heading in this file means fixing every one of them.
The same rule governs the entries after the six, in both directions. Every
comment in the crate that points a reader here names the entry it means, and
every entry here exists because something points at it. Two of the entries
were added for exactly that reason: `rust-urlapi/src/dynbuf.rs` and
`rust-urlapi/harness/shims.c` each promised a record that was not present,
and one of the two promises was itself wrong about the C. A cross-reference
that does not resolve is as much a defect as an unrecorded divergence, since
both leave the next reader guessing.

### Two behaviors worth stating precisely

Both of the behaviors below are easy to describe loosely, and a module built
on a loose description behaves differently from the C. Each is stated here
with the line that decides it, and each was measured against the reference
build rather than reasoned about.

**Which flag makes the empty-string case flag-sensitive in the C.** L1700
retrieves `CURLUPART_URL`, so the guard at L1559-L1560 does not run. That guard,
the one that turns `CURLU_NO_GUESS_SCHEME` into `CURLUE_NO_SCHEME`, sits in the
`CURLUPART_SCHEME` arm of the same `switch`, and this call is in the
`CURLUPART_URL` arm. What the whole-URL retrieval consults instead is
L1455-L1458, where a handle carrying no scheme at all needs
`CURLU_DEFAULT_SCHEME` to avoid `CURLUE_NO_SCHEME`, while a handle whose
scheme was guessed has `u->scheme` set and takes the first branch at
L1453-L1454. The reference's sensitivity is therefore real and runs through
`CURLU_DEFAULT_SCHEME`, which the table above demonstrates. The port answers
`CURLUE_MALFORMED_INPUT` for `CURLU_NO_GUESS_SCHEME` on a guessed-scheme handle
anyway, because `AAP` 0.6.5 requires it -- a divergence declared and bounded in
the empty-string entry, not an accident of reading the C.

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
and `Curl_getn_scheme()`, and `rust-urlapi/src/scheme.rs` reads three fields
of the descriptor they return: the capability `flags`, tested for
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

- `rust-urlapi/src/ffi.rs` carries a compile-time proof of the *Rust* shape,
  the `LAYOUT_PROOF` block directly beneath the `CurlScheme` mirror it
  guards: the mirror's size against the size a 32-bit `curl_prot_t` implies,
  its alignment, and the widths of the two fixed-width members, with all six
  field offsets re-derived in that module's test block. It catches an edit to
  the mirror. It cannot read a C header. The mirror lives there rather than
  in `rust-urlapi/src/scheme.rs` because describing a C structure is foreign
  work and the facade is where all of that is kept; `scheme.rs` receives an
  owned `SchemeInfo` carrying the three values and holds no raw pointer.
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
need libcurl's private build environment, `curl_config.h` included, which this
crate does not have and does not want. What the text settles is the presence
of the two lines that decide the width, not that a compiler reaches them, so
the gap is a header whose preprocessor state differs from its literal text.
Today that gap is narrow, because `lib/urldata.h:L82` defines
`PROTO_TYPE_SMALL` unconditionally and no external `-U` survives a later
`#define` in the file itself; an edit that moved either line inside a
conditional that does not hold would open it.

A link against a *different* libcurl from the tree this crate sits in is
likewise outside what either check can see. Nothing forces the two to be the
same libcurl; the parity scripts use the tree's own, which is why they are the
configuration these claims cover.

## Residual divergences from the plan's architecture

The findings above are behaviors. What follows are two properties of the port
rather than of the URL API, recorded here because `AAP` 0.4.1.5 assigns "any
residual divergence" to this file. One of the two is a divergence -- `FB2` and
`FB3` are each reproduced only in their API-visible half -- and one is not:
`unsafe` is confined to a single module, which the plan requires and the port
satisfies. The second is recorded anyway, because the reasoning that makes it
look unattainable is the reasoning the design had to answer, and a reader who
works that reasoning out unaided concludes the port cannot be doing what it
does.

One further divergence in reproduced behavior is recorded elsewhere in this file
rather than here, and is named at this point so the inventory reads complete: the
empty whole-URL write with `CURLU_NO_GUESS_SCHEME` on a guessed-scheme handle
answers `CURLUE_MALFORMED_INPUT` where `lib/urlapi.c` answers `CURLUE_OK`,
because `AAP` 0.6.5 requires it. It lives with the empty-string rule, where its
measurements and its bounds are, and it is the port's only intentional
behavioral difference from the reference.

### Not a divergence: `unsafe` is confined to one module

`AAP` 0.3.3 and 0.7.2 state that `rust-urlapi/src/ffi.rs` "is the only module
containing `unsafe`", and the compiler enforces exactly that: 24 of the
crate's 26 modules -- every one other than the crate root and
`rust-urlapi/src/ffi.rs` -- carry `#![forbid(unsafe_code)]`, so an `unsafe`
block added to any of them is a compile error rather than a review finding.
The root adds `#![deny(clippy::undocumented_unsafe_blocks)]` and
`#![deny(unsafe_op_in_unsafe_fn)]` for the whole crate, which is what holds
the one module that is allowed `unsafe` to the same standard. Measured across
all 26: occurrences of the `unsafe` keyword outside
`rust-urlapi/src/ffi.rs`, **zero**.

The reasoning that makes this look unattainable is worth keeping, because it
is what the design had to answer. Three other provisions of the same plan
appear to require `unsafe` elsewhere: 0.4.1.3 assigns the
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

- `alloc.rs` holds the C-allocator adapter, and every C-visible buffer is a
  `CBuf` built there. The allocator entry points and the raw block that owns
  their result sit in `ffi.rs` instead.
- `dynbuf.rs` holds curl's dynamic-buffer semantics, `FB6` included, as a thin
  wrapper over that same block.
- `idn.rs` holds the version guard, the exact flag set, the transitional
  retry, the zero-length rejection and the re-duplication order -- the
  parity-critical part. The five `extern "C"` declarations and the two
  platform lookup arms sit in `ffi.rs`.
- `scheme.rs` holds scheme resolution in both feature arms. The two
  `extern "C"` declarations and the one dereference of the descriptor libcurl
  returns sit in `ffi.rs`.
- `inet.rs` holds the fallback conversion and every caller-facing check. The
  platform `inet_pton`/`inet_ntop` pair sits in `ffi.rs`.

Each operation held in `ffi.rs` is reached through a safe wrapper whose
preconditions hold by construction rather than by caller promise: the raw
block guarantees its own capacity and initialization, the libidn2 wrappers
take a `&CBuf` so
`NUL`-termination is not a promise, and the scheme wrapper returns an owned
snapshot of the three fields the module reads so no C structure is interpreted
outside the facade. Every `unsafe` block in `rust-urlapi/src/ffi.rs` carries a
safety comment, per specification 3.2.1.2.

The technical specification's weaker requirement at 1.3.2.1 -- no `unsafe`
outside FFI code -- is satisfied outright. `MEMORY-OWNERSHIP.md` states the
same property among its rules, and `PORTING-NOTES.md` carries the full
inventory.

### `FB2` and `FB3` are reproduced only in their API-visible halves

Each is recorded at the finding itself, where the reasoning and the
measurement sit together: the behavior a caller can observe is reproduced
exactly, and the leak is not, because `CurlUrl::clear` assigns `None` and
`CurlUrl::store` assigns `Some(..)` so the displaced owned buffer is dropped
and released. They are listed here so that a reader scanning for residual
divergences finds all of them in one place.

## See also

- [MEMORY-OWNERSHIP.md][ownership] holds the ownership context behind
  `FB2` and `FB3`: how `curl_free()` resolves, every allocation site in the
  module, and the rules the crate follows at the boundary. It states the
  single-`unsafe`-module property among those rules.
- [PORTING-NOTES.md][porting] maps the C functions onto the Rust modules,
  and so names the owner of each finding above in its wider context. It also
  holds the full `unsafe` inventory, under "The unsafe boundary", which is what
  the entry above summarizes.
- `rust-urlapi/cbindgen.toml` carries the generator configuration the first
  integration limitation is about, with the same four measured differences
  stated beside the keys that cause them, and the two that measurement
  disproved recorded as disproved.
- `rust-urlapi/Cargo.toml` declares the three link-mode features and
  separates the two whose misuse is a link error from the one whose misuse is
  silent, which is the second integration limitation.

[ownership]: MEMORY-OWNERSHIP.md
[porting]: PORTING-NOTES.md
