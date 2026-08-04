<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Memory ownership across the C boundary

This document records the C-side memory-ownership assumptions that the
`curl-urlapi-rs` port inherits from `lib/urlapi.c`, and the rules the crate
follows to honor them. Memory ownership is the highest-risk area of this
port, so the record exists at two levels: a safety comment at every site in
`src/alloc.rs` and `src/ffi.rs`, and this file. A comment explains one line.
This file explains the whole chain. Neither one replaces the other.

Every claim below cites a path and a line number so that a reader can open
the source and confirm it rather than take it on trust. Build steps, feature
tables, prerequisites and script ordering are deliberately absent; they
belong to `../README.md`, which is the short entry point to the same
material.

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

The inventory below was re-derived from the source rather than copied from
the plan, because the value of an ownership record rests on the inventory
being complete. The command was:

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

### The four sites the plan omits

The table in the Agent Action Plan (`AAP`) at 0.6.4 lists 23 sites.
Re-deriving it produced 27. The four extra ones are named individually so
that a reviewer can confirm each.

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
`src/dynbuf.rs` reproduces this, and it is a statement about ownership
rather than about error codes.

### One owner, four sources

`get_url()` declares `allochost` at `lib/urlapi.c:L1431` and fills it from
four different allocation paths: the dynamic-buffer handover at L1489, the
escape helper at L1493, `host_decode()` at L1499 and `host_encode()` at
L1506. A single `curlx_free(allochost)` at L1533 releases whichever one ran.
All four therefore have to agree on the free function. The port keeps that
property by giving all four the same owned-buffer type from `src/alloc.rs`.

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

These bind every module of the crate, and downstream work implements against
them.

1. **Every buffer that crosses into C originates in `src/alloc.rs`**, which
   allocates through the C allocator by way of the `libc` crate. That is
   what makes a caller's `curl_free()` correct by construction rather than
   correct by discipline at each of the 27 sites listed above.
2. **`CString::into_raw` is banned crate-wide.** A pointer produced that way
   has to come back to Rust to be released, because the allocator behind it
   belongs to Rust rather than to C. Published guidance is explicit that the
   C free function must not be called on such a pointer, and the documented
   contract requires exactly that call, so the conversion cannot appear
   anywhere in the crate. `AAP` 0.3.2 and 0.6.4 record the decision.
3. **Allocating C-visible buffers with the C allocator is the accepted
   remedy, and it carries one caveat.** An allocator mismatch across a
   library boundary stays possible depending on how the pieces are linked.
   The parity harness therefore links exactly one C library, which removes
   the configuration in which such a mismatch could arise.
4. **Every assumption above is commented at its site** in `src/alloc.rs` and
   `src/ffi.rs`. This file is the companion record, not a replacement: a
   reader at one line needs the comment, and a reviewer checking the whole
   chain needs the record.
5. **`src/ffi.rs` is the only module that contains `unsafe`**, per `AAP`
   0.3.3 and specification 1.3.2.1, and every block in it carries a safety
   comment, per specification 3.2.1.2. Ownership crosses the boundary in
   that one file, so the reasoning stays in one place.

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
configuration, as `AAP` 0.2.4.3 reports. The visible cost is the ceiling
that `tests/data/test1560:L40` asserts, `Allocations: 3000`. That ceiling is
honored in spirit, in that the port does not allocate materially more than
the C original, rather than counted by curl's own counter. An independent
count through the platform's own tooling is the available substitute.
`tests/data/test1560` is read-only for this work; it is cited here and never
edited.

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
configuration is unsupported. It is reported here rather than worked around,
per `AAP` 0.2.4.4, and it is the same gap that the technical specification
records in 1.3.2.5.

## Conflict C3: the free function lives outside this scope

The URL API returns a pointer that the caller releases with the library free
function, and that function is defined outside the boundary of this work.
`curl_free()` lives in `lib/escape.c:L189`, which is read-only here, and
`curl_url_strerror()` is the same shape of problem one file over, in
`lib/strerror.c`. In a standalone link neither one is present at all.

The resolution recorded in `AAP` 0.8.3 has two halves. Every buffer the
crate returns is allocated with the C allocator, so a plain `free()` on it
is correct, and a plain `free` is what `curlx_free` resolves to outside a
libcurl build, per `lib/curl_setup.h:L1484`. In addition the crate exports
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
  among them the two leaks `FB2` and `FB3` whose ownership context this
  file supplies.
- [PORTING-NOTES.md][porting] maps the C functions onto the Rust modules.

[divergences]: KNOWN-DIVERGENCES.md
[porting]: PORTING-NOTES.md
