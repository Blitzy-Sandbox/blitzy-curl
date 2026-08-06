<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Memory ownership across the C boundary

This document records the C-side memory-ownership assumptions that the
`curl-urlapi-rs` port inherits from `lib/urlapi.c`, and the rules the crate
follows to honor them. Memory ownership is the highest-risk area of this
port, so the record is kept at two levels: a safety comment at every site
that touches the boundary, and this file. A comment explains one line. This
file explains the whole chain. Neither one replaces the other.

One statement about state, so that nothing below is read as more, or less,
than it is. Every file this document names is in the tree, `rust-urlapi/`
being complete at 55 files, so every claim here about what a file contains or
enforces is a claim about something a reader can open. That includes
`rust-urlapi/src/alloc.rs` and `rust-urlapi/src/ffi.rs`, which carry the safety
comments described here, and `rust-urlapi/README.md`, which is where the build
material this file deliberately leaves out actually lives.

Every path in this file is relative to the repository root, with no
exceptions, so a file belonging to this crate is written out in full --
`rust-urlapi/src/alloc.rs`, never a bare `src/alloc.rs`, which at the
repository root is the command-line tool's directory instead.

Every claim below about existing code cites a path so that a reader can open
the source and confirm it rather than take it on trust. **Every path is
relative to the repository root, with no exceptions**, so a file of this
crate's is written out in full as `rust-urlapi/src/alloc.rs` and never as a
bare `src/alloc.rs`: the crate and the repository both have a `src/`, a
`tests/`, an `include/`, a `docs/` and a `scripts/`, and a bare one would be
ambiguous rather than merely terse. `rust-urlapi/docs/KNOWN-DIVERGENCES.md`
follows the same rule; `rust-urlapi/docs/PORTING-NOTES.md` states a narrower
one at its top, because its tables have to be narrower. Build steps, feature
tables, prerequisites and script ordering are deliberately absent; they belong
to `rust-urlapi/README.md`.

## The documented contract

Two documents state the caller side of the contract, and they agree.

The manual page states it for the reader of the API. Quoted from
`docs/libcurl/curl_url_get.md:L45`:

    The returned content pointer must be freed with curl_free(3) after use.

The next line, L46, adds that the pointed string may not be altered even
though its type does not prevent it. `include/curl/urlapi.h:L130-L131`
repeats the same requirement in the comment above the `curl_url_get()`
declaration.

The matching statement about cleanup sits at
`include/curl/urlapi.h:L116-L118`. It records that `curl_url_cleanup()`
frees the `CURLU` handle and the resources used for parsing, and then adds
that it does not free strings previously returned through the URL API.
Quoted from L117-L118 with the original wording kept:

    It will not free strings previously returned with the URL API.

One consequence follows, and every later section depends on it: the
lifetime of a handle and the lifetime of a buffer obtained from that handle
are independent. A returned buffer outlives its handle unless the caller
releases it first, and cleanup reclaims nothing on the caller's behalf. The
crate therefore cannot treat handle cleanup as a net for anything it has
handed out. Each returned buffer is released exactly once, by the caller,
through `curl_free()`.

## How the free function resolves

`curl_free()` is a one-line forward. `lib/escape.c:L189` declares
`void curl_free(void *p)` and L191 calls `curlx_free(p)`. The comment above
it at L186-L188 gives the reason the function exists at all: some operating
systems and environments use a different memory system in the application
than in the library, so the library exposes a free that uses its own.

`curlx_free` is not a function. It is a macro that `lib/curl_setup.h`
resolves at compile time, three ways. Summarized, with the source locations
of each branch:

    #ifdef CURL_MEMDEBUG    /* L1453 */
    curlx_free(ptr) -> curl_dbg_free(ptr, __LINE__, __FILE__)  /* L1461 */
    #elif defined(BUILDING_LIBCURL)    /* L1471 and L1473 */
    curlx_free -> Curl_cfree    /* L1478 */
    #else
    curlx_free -> free    /* L1484 */
    #endif

The middle branch matters most, because `Curl_cfree` is a **mutable** global
function pointer rather than a fixed symbol. `lib/curl_setup.h:L1309`
declares it as `extern curl_free_callback Curl_cfree;`, one of the five
memory-function pointers declared together at L1308-L1312, whose types are
defined at L1300-L1304.

`lib/easy.c:L107` gives that pointer its initial value,
`(curl_free_callback)free`, at load time rather than inside an
initialization function, because `lib/easy.c:L102-L105` records that a
memory-using function may run before `curl_global_init()` does.
`global_init()` restores the same default at `lib/easy.c:L132` when asked
to. The value also changes at runtime: `curl_global_init_mem()` assigns the
function that an application supplies, at `lib/easy.c:L237`.

Read as one chain, a `curl_free()` call inside a normal libcurl build
reaches whatever function pointer `Curl_cfree` holds at that moment. Every
limitation recorded further down traces back to that single mutable pointer.

## Allocation sites in `lib/urlapi.c`

The value of an ownership record rests on its inventory being complete, so
the inventory below is derived from the source and the command that derives
it is given, allowing it to be re-checked at any time:

    grep -nE 'curlx_(calloc|strdup|memdup0|dyn_ptr)|curl_maprintf' \
      lib/urlapi.c

That command reports 36 matches against the 1998 lines of `lib/urlapi.c`.
Of those, 27 allocate memory that the module then owns. The other 9 read a
dynamic buffer without taking ownership of it, and are listed separately
below so that the count closes.

| Mechanism                                  | Count |
|--------------------------------------------|-------|
| Zeroing allocation, `curlx_calloc`         |     2 |
| String duplication, `curlx_strdup`         |     7 |
| Bounded duplication, `curlx_memdup0`       |     4 |
| Formatted allocation, `curl_maprintf`      |     4 |
| Dynamic-buffer handover, `curlx_dyn_ptr`   |    10 |

The exact locations, all in `lib/urlapi.c`:

    curlx_calloc     L1290 L1312
    curlx_strdup     L418 L815 L838 L977 L1004 L1059 L1304
    curlx_memdup0    L1028 L1052 L1086 L1367
    curl_maprintf    L381 L1441 L1517 L1676
    curlx_dyn_ptr    L672 L813 L1025 L1049 L1077 L1185 L1399
                     L1489 L1934 L1957

The 9 reads that transfer nothing, kept here so the count can be checked:

    L339 L487 L581 L638 L643 L783 L986 L1276 L1921

These five mechanisms are the complete set of direct allocation in the
module. A search for `curlx_malloc`, `curlx_realloc`, or a bare `malloc`,
`calloc`, `realloc` or `strdup` in `lib/urlapi.c` returns nothing at all.

### Four sites that are easy to miss

Each of the four below is reached from an inner branch or a shared exit
label rather than from a function's main path, so they are named
individually and each can be confirmed against the source.

- `lib/urlapi.c:L672`, `u->host = curlx_dyn_ptr(&host);` in
  `Curl_url_set_authority()`, which begins at L658. L671 frees the previous
  host first, and L669 releases the dynamic buffer on the failure path. That
  free at L671 is the contrast case for finding `FB3` in
  `KNOWN-DIVERGENCES.md`, where the zone identifier receives no such free.
- `lib/urlapi.c:L813`, `*outp = curlx_dyn_ptr(&out);` in `dedotdotify()`,
  reached at the `end:` label on L810 under the guards at L811 and L812.
  L815 covers the zero-length case with `curlx_strdup("")` instead.
- `lib/urlapi.c:L838`, `u->scheme = curlx_strdup("file");` in
  `parse_file()`, with its null check at L839-L840.
- `lib/urlapi.c:L1059`, `u->query = curlx_strdup("");` in `handle_query()`,
  under the comment at L1058 that marks the single-byte query case.

### Two clarifications about the dynamic buffer

`lib/urlapi.c:L1921` is not a handover. The `p = curlx_dyn_ptr(&enc);`
there starts the in-place walk at L1922-L1932 that converts percent escapes
already present in the input to lower case, through `Curl_raw_tolower()` at
L1926-L1927. The pointer that survives the function is taken at L1934 as
`newp`, and L1995 stores it after L1994 frees the previous value.

Handover through `curlx_dyn_ptr()` is a convention rather than a mechanism.
`lib/curlx/dynbuf.c:L237` defines it over a `const struct dynbuf *` and
returns `s->bufr` at L242 without clearing anything, and the `const`
receiver makes clearing impossible by construction. The C code transfers
ownership only by never calling `curlx_dyn_free()` on that buffer
afterwards. Nothing in the type system marks the handover, and nothing
detects a double free if a later edit adds one.

The contrast is available in the same file. `curlx_dyn_take()` at L245-L255
performs a real transfer: it sets `s->bufr` to NULL at L251 and zeros the
two lengths at L252-L253, so a second use finds an empty buffer.
`lib/urlapi.c` never calls it. This is the class of implicit contract that
the port makes explicit, and it is the clearest argument for an owned-buffer
type: a Rust type carries the handover in its own signature, so the compiler
rejects the second use that C accepts.

### A failed append releases the buffer

`dyn_nappend()` in `lib/curlx/dynbuf.c` releases the buffer it was given
before it reports failure. Exceeding the configured ceiling calls
`curlx_dyn_free()` and returns `CURLE_TOO_LARGE`, at L82-L84, and a failed
reallocation does the same at L107 before returning `CURLE_OUT_OF_MEMORY` at
L108. After a failed append the caller must not release the buffer again.

That rule is load-bearing rather than incidental, and `lib/urlapi.c` relies
on it twice. The `nomem:` label at L1959-L1961 releases `enc` and never
touches `qbuf`, because the failed append on `qbuf` at L1946, L1950 or L1953
released it already. The same reasoning holds at L1486-L1488, where a failed
`curlx_dyn_addf()` returns `CURLUE_OUT_OF_MEMORY` with no free of its own.
`rust-urlapi/src/dynbuf.rs` reproduces this, and it is a statement about
ownership rather than about error codes.

### Every buffer carries a ceiling, and the ceiling is not decoration

`dyn_nappend()` computes `fit = len + idx + 1` at `lib/curlx/dynbuf.c:L72`,
which is the new bytes, the bytes already there, and the terminator. It
releases the buffer and returns `CURLE_TOO_LARGE` at L82-L84 when `fit`
exceeds the ceiling the buffer was initialized with. The `+ 1` is the reason
a ceiling is a limit on content and not on capacity, and the port reproduces
the arithmetic rather than approximating it.

Three ceilings reach this module, and they are different numbers for
different reasons:

| Ceiling | Value | C locator | Where it applies |
|---|---:|---|---|
| `DYN_APRINTF` | 8,000,000 | `lib/curlx/dynbuf.h:L70`, used at `lib/mprintf.c:L1144` | anything built by `curl_maprintf()`, so the formatting and concatenating helpers of `rust-urlapi/src/alloc.rs` |
| `CURL_MAX_INPUT_LENGTH` | 8,000,000 | `lib/urldata.h:L131` | the input a caller hands to `curl_url_set`, and the junk scan |
| `length * 3 + 1` | derived | `lib/escape.c:L66` | one call of the escape helper, sized from its own input |

The first of these is the one most easily lost in a port, because in C it
arrives implicitly: a caller writes `curl_maprintf()` and inherits the
ceiling without naming it. `rust-urlapi/src/alloc.rs` names it, so its
formatting and concatenating helpers refuse an oversize result exactly where
`curl_maprintf()` would rather than allocating past it.

The third is worth contrasting with the other two. It is not a policy limit
at all but a computed exact size, and `lib/escape.c:L63` guards the
multiply that produces it with `length > SIZE_MAX / 16`.
`rust-urlapi/src/encode.rs` reproduces both the guard and the size, and
computes the product with checked arithmetic besides, because the crate root
denies arithmetic that could panic.

Independently of all three, `rust-urlapi/src/ffi.rs` refuses any allocation
above `isize::MAX` before it reaches the C allocator. That is not a curl
rule but a language one: a slice or a pointer offset beyond `isize::MAX` is
undefined behavior regardless of whether the allocator would have obliged.

### One owner, four sources

`urlget_url()`, defined at `lib/urlapi.c:L1425`, declares `allochost` at
L1431 and fills it from four different allocation paths: the dynamic-buffer
handover at L1489, the escape helper at L1493, `host_decode()` at L1499 and
`host_encode()` at L1506. A single `curlx_free(allochost)` at L1533 releases
whichever one ran. All four therefore have to agree on the free function.
The port keeps that property by giving all four the same owned-buffer type
from `rust-urlapi/src/alloc.rs`.

In the port the four sit in three modules. `rust-urlapi/src/getset.rs`
performs the handover, `rust-urlapi/src/encode.rs` owns the escape helper,
and `rust-urlapi/src/idn.rs` owns both internationalized-domain paths, and
the shared type is what makes the single release at L1533 portable across
all three. The escape helper is the one of the four that returns its buffer
rather than writing into a caller's, so it is also the one whose signature
carries the transfer.

### Buffers the module owns without allocating them

Three helpers outside the module hand it heap pointers that it then owns.
Every locator in this subsection is a line of `lib/urlapi.c`:
`Curl_urldecode()` at L590, L1385 and L1980; `curl_easy_escape()` at L1493;
and the two internationalized-domain wrappers `host_decode()` and
`host_encode()` at L1338-L1354, which forward to `Curl_idn_decode()` at
L1340 and `Curl_idn_encode()` at L1349. Each result is released with
`curlx_free()`: at L596 once its bytes are copied into a dynamic buffer, at
L1983 after the check that used it, and at L1533 in the `allochost` case.

The result at L1385 is different in kind. L1386 releases the previous
`part` and L1389 moves ownership of the decoded buffer into `part`, which
the same variable carries onward. On the encoding path L1396 releases it
again before L1399 replaces it with a fresh dynamic buffer. The port models
that chain as a sequence of moves, which is what it already is in C.

### What the handle itself owns

`struct Curl_URL` owns ten heap strings, and `free_urlhandle()` at
`lib/urlapi.c:L86-L98` releases each of them with `curlx_free()`.
`curl_url_cleanup()` at L1293-L1299 calls that helper at L1296, frees the
handle itself at L1297 and does nothing further, which is the implementation
behind the header statement quoted earlier. `curl_url()` allocates the
handle with `curlx_calloc()` at L1290 and `curl_url_dup()` does the same at
L1312; the `fail:` label at L1329-L1331 routes a partial copy back through
`curl_url_cleanup()`, so a duplication that runs out of memory releases what
it had built.

The same `curlx_free` macro releases both the strings inside the handle and
the buffers handed to callers. One allocator has to serve both, which is the
constraint the next section turns into a rule. The point at which the
documented contract attaches is `lib/urlapi.c:L1537`, `*part = url;`, after
the null check at L1535-L1536.

## Rules the crate follows

These bind every module of the crate, and every module in the tree is
written against them today. Each rule names the file that realizes it, so a
reader can check the rule rather than trust it.

1. **Every buffer whose ownership transfers to C originates in
   `rust-urlapi/src/alloc.rs`**, which allocates through the C allocator: it
   asks `rust-urlapi/src/ffi.rs` for an owned block, and that module makes
   the `libc` call. The split keeps every foreign call in one module open to
   audit without moving the memory adapter, and the property it buys is the
   same either way -- a caller's `curl_free()` is correct by construction
   rather than correct by discipline at each of the 27 sites listed above.
2. **`CString::into_raw` is banned crate-wide.** A pointer produced that way
   has to come back to Rust to be released, because the allocator behind it
   belongs to Rust rather than to C. Published guidance is explicit that the
   C free function must not be called on such a pointer, and the documented
   contract requires exactly that call, so the conversion cannot appear
   anywhere in the crate.
3. **Allocating C-visible buffers with the C allocator is the accepted
   remedy, and it carries one caveat.** An allocator mismatch across a
   library boundary stays possible depending on how the pieces are linked.
   The parity harness therefore links exactly one C library, which removes
   the configuration in which such a mismatch could arise.
4. **Every assumption above is commented at its site** in
   `rust-urlapi/src/alloc.rs` and
   `rust-urlapi/src/ffi.rs`. This file is the companion record, not a
   replacement: a reader at one line needs the comment, and a reviewer
   checking the whole chain needs the record.
5. **`rust-urlapi/src/ffi.rs` is the only module that contains `unsafe`**,
   and every
   block in it carries a safety comment. What makes that mechanical rather
   than a convention is a count that is worth stating exactly: of the 26
   files under `rust-urlapi/src/`, the 24 that are neither the crate root
   nor the facade each open with `#![forbid(unsafe_code)]`, so an `unsafe`
   block added to any of them is a compile error rather than a review
   finding. The two exceptions are deliberate. `rust-urlapi/src/ffi.rs`
   cannot forbid what it exists to contain. `rust-urlapi/src/lib.rs` cannot
   either, because an inner attribute on the crate root reaches every module
   including the facade; the crate root carries a different policy instead --
   `deny(clippy::missing_safety_doc)`,
   `deny(clippy::undocumented_unsafe_blocks)` and
   `deny(unsafe_op_in_unsafe_fn)` in the crate root's lint block, named by
   symbol rather than by line so the claim cannot drift -- which does not ban
   `unsafe` but does require every
   block and every `unsafe fn` in the facade to justify itself, and stops
   an `unsafe fn` body from being implicitly unsafe throughout. Ownership
   crosses the boundary in that one file, so the reasoning stays in one
   place.

## How the cleanup contract is evidenced, and why not by reading the buffer

`include/curl/urlapi.h:L116-L118` says `curl_url_cleanup()` frees the handle
and the resources used for the URL parsing, and states in as many words that it
`will not free strings previously returned with the URL API`.
That is the contract the whole arrangement above
exists to satisfy: the getter's buffers come from the C allocator through
`rust-urlapi/src/alloc.rs` and are owned by the caller, not by the handle.

Two shapes of test were tried and rejected, and both are recorded because both
look reasonable and both are **fail-unsafe exactly when the contract is
broken**. A test that is unsound in the presence of the defect it hunts is
worth less than no test: it reports undefined behavior instead of a violation,
and under a hardened or sanitizing allocator it aborts with a diagnostic about
the *test*.

*Rejected: read the buffer back afterwards.* Retrieve a part, clean the handle
up, then read the buffer. If cleanup did release that block, the read is a
use-after-free.

*Rejected: prove liveness by releasing something else first.* Release the
*buffer* and then read the handle, on the reasoning that independence is
symmetric. It is -- but the reasoning is about the conclusion, not about the
operation: if the getter had handed out a pointer into the handle's own storage,
that release frees memory the handle still uses and every read after it is a
use-after-free. Freeing something and then asking whether that was allowed is
never a sound order.

*Rejected: probe for recycling.* Replay the identical request after the cleanup
and check the block is not handed back. This avoids the dereference, and it is
what an earlier revision of this file described, but it has two faults. It is
evidence rather than proof -- an allocator may satisfy a request without reusing
the most recently freed block, so a wrongly freed block can go unnoticed -- and
it leaves the final release of that block resting on the probe's verdict, so a
probe that missed the defect ends in a double free.

**What the crate does instead: ask the allocator, and touch nothing.**
`rust-urlapi/tests/ffi_surface.rs` interposes `malloc`, `calloc`, `realloc` and `free` in
the test binary -- the same `count` module the allocation ceiling is measured
with -- and records, for a watched window, the *address* of every block created
and every block destroyed. An address is taken as an integer and is never
dereferenced, so the record stays valid evidence whatever happens to the block
it names. Three properties follow, and together they are what makes the two
tests below sound rather than merely passing:

**One, independence, established positively.**
`a_returned_buffer_is_independent_of_the_handle_that_produced_it` watches the
`curl_url_get()` call itself and asserts that the pointer it returned is a block
the allocator handed out **during** that call. A block that came into existence
inside the call cannot be interior storage of a handle that existed before it,
which is what "independent allocation" means. The bytes and all eleven parts of
the still-live handle are then read with nothing released; the buffer is
released last, its release is watched and must give back exactly one block, and
only then -- with the provenance already established -- is the handle read
again. That final read is sound *because* of the evidence, which is the whole
difference between this shape and the second rejected one.

**Two, the cleanup's frees, observed directly.**
`cleanup_does_not_recycle_a_previously_returned_string` records the buffer's
address, watches the `curl_url_cleanup()` call, and asserts the address is
**not** among the blocks the cleanup gave back. That is the contract's own
question answered by direct observation rather than inference, and it holds
whatever the allocator does afterwards. It also asserts the cleanup released
more than one block, because a cleanup that released almost nothing would
satisfy the first assertion without meaning anything.

**Three, the release cannot be skipped, repeated or mis-ordered.** Every buffer
kept past the call that produced it is held in an owning wrapper whose `Drop`
performs the single release. An assertion firing between the retrieval and the
release therefore does not abandon the block, ownership being unique means no
ordering can release it twice, and tying the release to the end of the scope is
what makes "read the handle, *then* let the buffer go" the default rather than
something each test has to remember. Both tests check the return code before the
pointer is looked at, and the helpers that release a getter buffer assert the
null-on-error contract -- `lib/urlapi.c:L1552` writes null into the caller's
slot ahead of every failing return -- rather than assuming it.

**The instrument is calibrated, not trusted.**
`the_address_ledgers_report_what_the_allocator_did` drives the two ledgers with
blocks it owns outright, through `libc::malloc` and `libc::free` directly rather
than through the crate, so that a failure there is unambiguously the
instrument's. It asserts that a creation inside a window is seen, that a release
inside a window is seen, that a block which existed before the window and is
still alive after it appears on neither ledger, and that a window with more
events than the ledger holds sets its overflow flag. The last two are the ones
that matter: "absent from the destroyed ledger" is the answer the ownership
tests read as "the contract held", so it has to mean "nothing happened to this
block" and not "the ledger was empty or full". Both tests assert the overflow
flag is clear before reading anything else.

**And an external memory checker, for the direction no test can observe
safely.** The raw sequence the first rejected shape describes -- retrieve, clean
up, read, then release -- was run under Valgrind's Memcheck against the crate.
Memcheck intercepts the allocator, so it judges the read on its own account:

    retrieve, cleanup, read, release   ERROR SUMMARY: 0 errors from 0 contexts
    control: release, then read        Invalid read of size 1  (exit code 42)

The control line is the same read with the buffer deliberately released first,
and it is there because an instrument that reports nothing is only evidence once
it has been shown able to report something. Cleanup leaves the buffer intact; a
genuinely freed buffer is flagged. That probe is a throwaway and is not part of
the crate -- committing it would commit the unsound sequence -- which is why the
result is recorded here instead.

curl's own allocation counter is not available as a further instrument, for
the reason the next section gives.

## Reported limitation R3: memory-debug builds

A memory-debug build of libcurl resolves `curlx_free` to `curl_dbg_free()`,
per `lib/curl_setup.h:L1461`. That function spans `lib/memdebug.c:L362-L385`
and its body is the problem. L368 logs the free, which is what feeds the
allocation accounting. L376 then computes

    mem = (void *)((char *)ptr - offsetof(struct memdebug, mem));

and L383 releases that address through `(Curl_cfree)(mem)`. The back-offset
at L376 is unconditional. `curl_dbg_free()` assumes without checking that
the pointer it received sits immediately after a `struct memdebug` header
that `curl_dbg_malloc()` wrote.

A buffer from a plain C allocator carries no such header. Because the
subtraction at L376 happens either way, handing such a buffer to
`curl_dbg_free()` releases an address a few bytes below the real
allocation. That is a wild free rather than a rejected one, so the failure
mode is silent corruption instead of a diagnostic. Routing the crate through
`Curl_cfree` directly would mean importing a libcurl-private symbol, and it
would still leave the accounting wrong, because the matching allocation was
never logged.

The parity harness is therefore built without the memory-debug
configuration. The visible cost is that curl's own allocation counter, which
belongs to that build, does not run -- so the ceiling
`tests/data/test1560:L38-L40` asserts, `Allocations: 3000`, cannot be
checked by the mechanism that wrote it.

## The allocation ceiling, measured independently

`AAP` 0.9.4 names the substitute for exactly this situation: "an independent
allocation count via the platform's own tooling". Two of them exist, and
together they are what discharges implicit requirement I11. Both are
reproducible from committed tooling, which is the property that matters: a
number in a document that nobody can re-derive is an assertion, not evidence.

**Around the parity harness.** One command:

    rust-urlapi/scripts/run-parity.sh --allocations

That step relinks each of the three harnesses -- the reference one and one per
link mode -- with `-Wl,--wrap` over `malloc`, `calloc`, `realloc`, `strdup` and
`free`, against a counter the script generates into the ignored
`rust-urlapi/build/parity/` tree, and runs the unmodified
`tests/libtest/lib1560.c` under each. The metric column is the accounting
`tests/memanalyzer.pm:L439` performs, `mallocs + callocs + reallocs +
strdups`, and the created and destroyed columns are kept separately for the
reason the paragraph after the table gives.

The linker's own `--wrap` is used rather than a preloaded library, and that is
not a preference: the harnesses are statically linked against archives, so a
preloaded shared object would never be consulted for calls the static link had
already resolved. `--wrap` redirects the call sites at link time instead and
hands the real entry point back as `__real_*`.

Measured on the environment `rust-urlapi/build/reference-build.env` records:

    reference libcurl.a         metric 2,840   created 2,732   destroyed 2,732
    the port, drop-in link      metric 2,772   created 2,732   destroyed 2,732
    the port, standalone link   metric 2,772   created 2,732   destroyed 2,732

The port is **68 metric allocations cheaper** than the C for the identical
test, and identical in both link modes, which is what I11's "not materially
more allocation-hungry than the original" asks about. The composition differs
more than the total does -- the reference spends 809 mallocs, 410 callocs,
1,146 reallocs and 475 strdups, where the port spends 2,322 mallocs, 410
callocs, 40 reallocs and no strdups -- and that is expected: the port grows a
buffer where curl's dynamic buffer reallocates, and it has no `strdup` call at
all because `rust-urlapi/src/alloc.rs` allocates and copies in one place.
Created equals destroyed in all three, so nothing is outstanding at exit under
any of them.

The absolute figures are a property of that environment rather than of the
port, so they are stated with it. What is a property of the port is the
comparison, and re-deriving it takes one command.

**Inside the crate's own suite.** `rust-urlapi/tests/ffi_surface.rs` reproduces
the same accounting without any external tooling: its `count` module defines
`malloc`, `calloc`, `realloc` and `free` in the test binary and forwards them
to the same glibc aliases, so the crate's own `libc::malloc` calls are counted
**with nothing added to the library**. That last point is the design
constraint, not an aside. The crate ships no counter of its own: an instrument
compiled into `rust-urlapi/src/ffi.rs` would put a Rust API and permanent
bookkeeping into a drop-in replacement for one C object file, and it would
observe nothing that interposition does not. Two tests read the interposed
counters, and both are kept because their workloads answer different questions.

`the_allocation_count_stays_within_the_test1560_ceiling` runs a fixed workload
of twenty-four `lib1560` vectors, each parsed, read part by part, serialized
under two codec flag sets, duplicated and amended. It costs **575
allocations** and leaves nothing outstanding -- identical in all four feature
configurations and in both profiles -- and it asserts three things: at most
3,000 allocations, the literal ceiling; at most forty per cycle, which is the
sharp guard, since twenty-four cycles against 3,000 would let the
per-operation cost grow five-fold unnoticed; and that every block created was
destroyed.

`the_allocation_count_stays_under_the_test1560_ceiling` is calibrated instead
of broad. Its twenty rows and six rounds are sized so that the same sequence
of C calls, run against `libcurl.a` from the unmodified tree with
`-Wl,--wrap=malloc,calloc,realloc,strdup`, costs exactly 3,000 -- measured at
500, 1,000, 1,500, 3,000 and 3,500 for one, two, three, six and seven rounds.
The port costs 475 per round, so 2,850 at the calibration point: 5% of margin
against the point at which the original spends its whole budget, rather than an
unquantified "under the limit". The test also asserts that two rounds cost
exactly twice one and six exactly six times one, which is what makes the
extrapolation sound and what a per-handle regression would break first.

For scale, the real thing, and it is the same figure the table above reports
because it is the same measurement:
`rust-urlapi/scripts/run-parity.sh --allocations` relinks the reference harness
with these wrappers, and `lib1560` prints `success` at a metric cost of 2,840
-- 809 mallocs, 410 callocs, 1,146 reallocs and 475 strdups -- against the same
3,000. The ceiling in curl's own suite therefore runs at 95% utilization, and a
workload calibrated to sit exactly at it measures on the same scale rather than
a generous one.

That last assertion needs one distinction to be meaningful, and getting it
wrong was a real defect in the first version of the counter. A `realloc` is
one allocation by `memanalyzer`'s reckoning, but it *replaces* a block rather
than adding one, and glibc releases the old extent itself without calling
`free`. The metric and the outstanding-block balance therefore need separate
counters: the workload's 575 allocations comprise 574 blocks created and one
`realloc`, and 574 blocks were destroyed. Read through one pair of counters it
looked like a one-block leak, and it is not one.

What is still **not** claimed: this is not a re-measurement of `lib1560`
under curl's counter, because that counter cannot run here for the reason
above. `tests/data/test1560` is read-only for this work; it is cited here and
never edited.

## Reported limitation R4: alternative memory functions

An application can replace curl's memory functions at runtime through a
supported entry point. `Curl_cfree` is a mutable global at
`lib/curl_setup.h:L1309`, and `curl_global_init_mem()` assigns to it at
`lib/easy.c:L237`. In a build where `curlx_free` resolves to that pointer,
per `lib/curl_setup.h:L1478`, a `curl_free()` call reaches the function the
application installed.

A buffer this crate allocated through the C allocator is then released by a
function that never allocated it. Nothing in the crate detects the
substitution, because the pointer carries no record of its origin. The
configuration is unsupported. It is reported here rather than worked
around, because working around it would mean either importing a
libcurl-private symbol or tracking the origin of every returned buffer,
and neither is available to a drop-in replacement for one object file.

## Conflict C3: the free function lives outside this scope

The URL API returns a pointer that the caller releases with the library free
function, and that function is defined outside the boundary of this work.
`curl_free()` lives in `lib/escape.c:L189`, which is read-only here, and
`curl_url_strerror()` is the same shape of problem one file over, in
`lib/strerror.c`. In a standalone link neither one is present at all.

The resolution has two halves. Every buffer the crate returns is allocated
with the C allocator, so a plain `free()` on it is correct, and a plain
`free` is what `curlx_free` resolves to outside a libcurl build, per
`lib/curl_setup.h:L1484`. In addition the crate exports
its own `curl_free()` under the `cfree` feature, for the standalone
configuration where no libcurl supplies one.

The drop-in configuration has to leave that feature off, because the symbol
is already defined in the object built from `lib/escape.c:L189`, and a
second definition in the Rust archive turns a clean link into a
duplicate-symbol link. A reference build of this repository shows that
directly: listing the archive reports an `escape.c.o` member, and reading
the symbols it defines reports `curl_free` among them.

    ar t libcurl.a | grep escape
    nm -g --defined-only libcurl.a

The same reasoning applies to the `strerror` feature and
`curl_url_strerror()`, which the same reading finds in `strerror.c.o`.

## See also

- [KNOWN-DIVERGENCES.md][divergences] records the reproduced findings,
  among them `FB2` and `FB3`, whose ownership context this file supplies.
  Both are a leak as well as a behavior in the C, and the split matters
  here: the behavior is reproduced exactly -- three credential parts reading
  as absent, and a zone identifier that survives a host replacement -- while
  neither leak is. `CurlUrl::clear` assigns `None` and `CurlUrl::store`
  assigns `Some(..)`, so in both cases the displaced owned buffer is dropped
  and its block released through the C allocator it came from. That is
  invisible to the URL API and moves no answer the parity diff compares, and
  it is still a real difference, recorded there as a residual divergence
  rather than filed under "reproduced". The same document records, marked
  closed, the confinement of `unsafe` to one module that rule 5 above
  states.
- [PORTING-NOTES.md][porting] maps the C functions onto the Rust modules.

[divergences]: KNOWN-DIVERGENCES.md
[porting]: PORTING-NOTES.md
