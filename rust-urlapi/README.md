<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# curl URL API in Rust

`curl-urlapi-rs` is a Rust re-implementation of curl's URL API. The
crate is a binary-compatible, drop-in replacement for the object file
built from `lib/urlapi.c`, and it exports the identical C ABI declared
in `include/curl/urlapi.h`. The package is named `curl-urlapi-rs` and
the library `curl_urlapi_rs`.

## What this is

One C translation unit of 1,998 lines becomes one Cargo crate of 26 Rust
modules. Nothing about the observable behavior changes, and nothing about
the linkage surface changes either: every exported symbol keeps its name,
its C calling convention, its parameter types and its return type.

Two independent oracles decide whether that holds.

The first is curl's own URL API test, `tests/libtest/lib1560.c`,
compiled **unmodified** and linked against the port. Its expected output
is the single line `success`, which is what `tests/data/test1560`
asserts.

The second is `demo/urlapi_demo.c`, a standalone demonstration program
that exercises all six public functions and performs no transfer. Its
standard output has to match, byte for byte, the output of the same
program linked against the original C implementation. That reference
transcript is captured and committed as `demo/expected-output.txt`.

## The hard boundary

Not one pre-existing file anywhere in the repository is created, edited,
moved or deleted. Every new file lives under `rust-urlapi/`, and
`git status --porcelain` shows additions under that directory and nothing
else.

Five files are read strictly read-only, and each of them earns that
status:

- `lib/urlapi.c` and `lib/urlapi-int.h` are the behavioral source of
  truth. Both stay in the tree on purpose, so the C implementation
  remains available as the comparison baseline.
- `include/curl/urlapi.h` is the ABI contract. No `CURLUPart` value, no
  `CURLUcode` value, no `CURLU_*` flag and no signature is added or
  changed.
- `tests/libtest/lib1560.c` and `tests/data/test1560` are the behavioral
  oracle. Neither is edited to make anything pass.

curl's build system is untouched as well, which is why this directory
carries its own manifest, its own `Cargo.lock`, its own build script and
its own build driver, and behaves as a standalone project nested inside
the existing tree. That boundary has one consequence, reported as `R1`
below.

## Prerequisites

Two sets, and they are not the same set.

**For the crate:** a stable Rust toolchain. `rust-toolchain.toml` pins
the stable channel together with the `clippy` and `rustfmt` components,
so `rustup` provides what is needed on first use. The declared minimum
supported version is 1.75, above curl's own documented floor of 1.73.
The default internationalized-domain backend also needs the libidn2
development package.

**For the C reference baseline** that the parity run compares against: a
C compiler, GNU Make, pkg-config, CMake, autoconf, automake, an SSL
library, libidn2, an LDAP library and a compression library. These are
prerequisites for producing the comparison baseline rather than runtime
dependencies of the deliverable.

`scripts/build-reference.sh` records the exact versions it found in
`build/reference-build.env`, so a parity result can be traced back to
the toolchain that produced it. This environment resolved cc 15.2.0, GNU
Make 4.4.1, CMake 3.31.6, pkg-config 1.8.1, OpenSSL 3.5.3, libidn2
2.3.8, OpenLDAP 2.6.10 and zlib 1.3.1, with `rustc` and `cargo` at
1.97.1.

SSL, internationalized domains and LDAP are mandatory rather than
recommended. Without those three the reference protocol set comes out
as:

    dict file ftp gopher http imap ipfs ipns mqtt pop3 rtsp smtp
    telnet tftp ws

There is no https and no ldap in that list, while `tests/data/test1560`
declares nine required features at lines 17 to 25:

    file https http pop3 smtp imap ldap dict ftp

A reference built without those three options diverges on
scheme-dependent assertions for reasons that have nothing to do with the
port, which is the one kind of failure a parity run must never invent.

## Features

Six features, and the set is closed. Each stands in for a C preprocessor
switch, or for a choice the C module resolves at link time.

| Feature | Default | Effect |
|---|---|---|
| `strerror` | on | Exports `curl_url_strerror` and its 33 message strings. That function is not implemented in `lib/urlapi.c` at all: it lives in `lib/strerror.c`, which is out of scope, so exporting it beside a real libcurl defines the symbol twice |
| `cfree` | on | Exports `curl_free`, which `lib/escape.c` already defines in a real libcurl. Needed where nothing else supplies it, because the documented contract that a buffer from `curl_url_get` is released with `curl_free` still has to hold |
| `scheme-table` | on | Compiles a built-in scheme table: the default ports, the URL-options capability bit and the protocol-enabled marker. With the feature off, `Curl_get_scheme` is imported from libcurl instead, so the real and complete table answers every lookup |
| `idn-libidn2` | on | Binds libidn2 directly, replicating the call sequence of `lib/idn.c` including the version guard, the exact flag set and the transitional retry. This is what makes byte-for-byte parity attainable |
| `idn-pure` | off | Uses the `idna` crate instead. **Not** byte-for-byte: no transitional retry, locale-independent where libidn2 is not, different Unicode tables, and a dependency closure that raises the effective minimum toolchain to 1.86 |
| `genheader` | off | Regenerates `include/curl_urlapi_rs.h` from `build.rs` with `cbindgen`, so the mirror header cannot drift away from the code |

The two internationalized-domain backends are mutually exclusive in
intent. Cargo features are additive, so the manifest has no way to say
so: `build.rs` fails the build when both are requested, and
`src/idn.rs` rejects the combination at compile time as well.

## Building

Two configurations decide behavior, and which one applies follows from
whether a real libcurl takes part in the link. A third names the shared
deliverable, and it differs from the first only in that its scheme table
is its own.

**Mode A, the drop-in and authoritative configuration.** The crate links
beside a real libcurl, so it must not define a single symbol that
libcurl already defines: `strerror`, `cfree` and `scheme-table` are all
off.

    % cargo build --release --no-default-features --features idn-libidn2

**Mode B, standalone.** No libcurl takes part, so the crate supplies
`curl_url_strerror`, `curl_free` and a built-in scheme table itself,
alongside the small C shims for the `curl_mprintf` family in
`harness/shims.c`.

    % cargo build --release

Run one after the other and Cargo rebuilds each time, because a change
of feature set invalidates the cache. `scripts/build-rust.sh` avoids
that by giving each configuration a target directory of its own, so
switching between them costs nothing.

Cargo writes `libcurl_urlapi_rs.a`, `libcurl_urlapi_rs.so` and an
`rlib`. The archive is an *input* to the deliverable rather than the
deliverable itself: it holds this crate's code together with every
upstream Rust dependency, which means the whole standard library, the
allocator and the unwinding runtime, and each of those contributes
global symbols of its own. The count reaches the hundreds, against eight
for the C object file.

The canonical static artifact is therefore
`libcurl_urlapi_rs_dropin.a`, produced from the Cargo archive by a
localization pass. `ld -r` combines every member into one relocatable
object, `objcopy` localizes every global except the ABI set, and `ar`
re-archives the result. `build.rs` implements the pass and
`scripts/build-rust.sh` drives it, because Cargo has no post-build hook:
a build script runs before the crate is compiled, so it cannot
post-process an archive that does not exist until after it has run. A
link line names that archive, never the raw one.

**Mode C, the shared drop-in.** With `scheme-table` off,
`src/scheme.rs` imports `Curl_get_scheme` and `Curl_getn_scheme` from
libcurl, and undefined references to those resolve in exactly one
situation: a static link in which `url.c.o` takes part. A shared object
built that way therefore cannot load on its own, and `build.rs` records
that beside the artifact in a notice instead of failing the link, so the
archive and the `rlib` the same build produces are still delivered.
`CURL_URLAPI_STRICT_CDYLIB=1` puts `-Wl,-z,defs` back on that link for a
packaging job that would rather fail than read a notice, at the cost of
those two artifacts.

    % cargo build --release --no-default-features \
        --features idn-libidn2,scheme-table

That configuration is the shared deliverable: it exports exactly the
eight names and imports nothing in the `curl_` or `Curl_` namespaces, so
`build.rs` proves it closed with `-Wl,-z,defs` and it loads under
`dlopen`. Together with Mode A's `libcurl_urlapi_rs_dropin.a` it is the
pair goal G1 asks for -- one archive and one shared object from a single
crate. `scripts/build-rust.sh` builds all three configurations and
`scripts/check-abi.sh` holds every archive and every shared object to its
own export set and, for the shared ones, to its import contract as well.
The standalone shared object exports ten, the two extra names being
`curl_url_strerror` and `curl_free`.

The build driver reaches everything else:

    % make            reference, rust, abi, parity, test
    % make lint       cargo clippy -D warnings, and cargo fmt --check
    % make test       cargo test in both feature configurations
    % make help       every target with a one-line description
    % make clean      remove build/ and target/ under this directory

A bare `make` finds `GNUmakefile`, which GNU make prefers over
`Makefile`. That name is deliberate: the repository root `.gitignore`
carries a bare `Makefile` entry at line 35, and with no slash in it the
pattern matches at every depth, so a file named `Makefile` here would
never be tracked by git and would vanish from the deliverable.

## The exported symbol set

Eight symbols, not six. Compiling `lib/urlapi.c` and inspecting the
result with `nm -g --defined-only` yields eight defined global symbols:

    Curl_is_absolute_url  Curl_junkscan  Curl_url_set_authority
    curl_url  curl_url_cleanup  curl_url_dup  curl_url_get
    curl_url_set

Five of the eight are the public functions that `lib/urlapi.c` defines.
The other three are declared in `lib/urlapi-int.h` at lines 28 to 33 and
consumed elsewhere in libcurl: `Curl_is_absolute_url` by
`lib/http1.c:220`, `lib/url.c:1661` and `lib/http.c:1177`;
`Curl_junkscan` by `lib/doh.c:1127`; and `Curl_url_set_authority` by
`lib/http2.c:739`. A crate exporting only the six public functions
therefore cannot replace the object file in a full libcurl link.

`curl_url_strerror` and `curl_free` have to be **absent** in Mode A.
Neither is defined in `lib/urlapi.c`: the first lives in
`lib/strerror.c` and the second in `lib/escape.c`, so a second
definition from the crate collides at link time. Each sits behind its own
feature for that reason, and both are real exports in Mode B, where
nothing else supplies them.

`scripts/check-abi.sh` measures this rather than asserting it. Here it
reports the Mode A canonical archive defining exactly those eight
global symbols, and the Mode B canonical archive defining ten, the
extra two being `curl_free` and `curl_url_strerror`.

## The parity workflow

Four scripts, in this order, then the crate's own suites. Each script
takes `--help`.

    % scripts/build-reference.sh
    % scripts/build-rust.sh
    % scripts/check-abi.sh
    % scripts/run-parity.sh
    % cargo test

1. `scripts/build-reference.sh` builds libcurl out of tree from the
   unmodified repository with SSL, internationalized domains and LDAP
   all on, links the harness and the demo against it, and captures the
   output of both as the golden files. It writes
   `build/reference-build.env`.
2. `scripts/build-rust.sh` builds both feature configurations, runs the
   drop-in localization pass over each archive, checks both with
   `clippy`, records the resolved dependency versions and writes
   `build/rust-build-summary.txt`.
3. `scripts/check-abi.sh` compares the symbol sets and writes
   `build/abi-check-summary.txt`. Run it **before** any behavioral step.
   A symbol mismatch makes every behavioral result meaningless, so a
   clean diff over a mismatched surface proves nothing at all.
4. `scripts/run-parity.sh` stages the test source and the shim header
   into the ignored `build/` directory, links both modes, runs each
   binary beside the reference under every environment that changes what
   the test asserts, diffs standard output byte for byte, maps exit
   codes back to sub-test names and writes `build/parity-summary.txt`.
5. `cargo test` runs the five integration suites under `tests/`.
   `scripts/run-parity.sh` leaves them to `make test`, which runs them
   in both feature configurations because some of the cases are
   feature-gated, so a single configuration leaves the other's rows out
   of the build entirely.

A bare `make` runs that whole chain in that order, and each step reads
the fact file the step before it wrote. The four narrower targets
`harness-a`, `harness-b`, `demo-a` and `demo-b` hand
`scripts/run-parity.sh` one mode at a time.

Mode A is what demonstrates the drop-in claim, and it does so by
subtraction. The script copies the reference archive, deletes
`urlapi.c.o` from the copy, and links the harness against the remainder
plus the Rust archive. Here the copy went from 178 members to 177, and
the control link without the Rust archive failed with seven undefined
references, one for each of the port's symbols that the pulled-in
objects reference. `Curl_junkscan` is not among the seven, because
`doh.c.o` is not pulled in by this configuration.

## The environment the parity run reproduces

Three settings together gate the internationalized-domain assertions,
and dropping any one of them leaves those assertions silently not
running. An early proof of concept did that and passed while exercising
none of them.

- `LC_ALL=C.UTF-8`, as `tests/data/test1560` sets it at line 14, and a
  second run under `LC_ALL=C`. The libidn2 lookup is locale-aware, so
  under `LC_ALL=C` every non-ASCII host fails and the reference itself
  reports `CURLUE_BAD_HOSTNAME`. The port reproduces that rather than
  improving on it.
- `CURL_TEST_HAVE_CODESET_UTF8`, set and unset both.
  `tests/runtests.pl` exports it at lines 837 to 839, and
  `tests/libtest/lib1560.c` reads it at line 2036 to gate assertions in
  three of the sub-tests.
- `setlocale(LC_ALL, "")`, called by `harness/main.c` exactly as the
  real entry point does at `tests/libtest/first.c:231`. Without that
  call even `LC_ALL=C.UTF-8` yields a libidn2 failure and a
  `CURLUE_BAD_HOSTNAME` for every non-ASCII host.

Crossing the first two settings gives the four labels the script uses:
`utf8-codeset`, `utf8-nocodeset`, `c-codeset` and `c-nocodeset`.
`PARITY_ARGS='--env LABEL'` narrows the matrix to one label, which is
for investigating a failure and never for declaring parity.

The reference and both modes agreed on all four labels here. Three of
them ended at exit status 0, and `c-codeset` ended at 3 for the
reference and for both modes alike, which is the locale sensitivity
reproduced rather than papered over.

Non-ASCII examples appear in this file in their punycode form, as
`xn--rksmrgs-5wao1o.se` and `xn--fiq228c.tw`, because
`scripts/spacecheck.pl` rejects non-ASCII bytes in a tracked file. The
Unicode forms live in `tests/libtest/lib1560.c`, which is where the
assertions on them live too.

## Per-sub-test reporting

Expected standard output is the single line `success`, printed at
`tests/libtest/lib1560.c:2073`. The entry point short-circuits at the
first failure, so one exit status names one sub-test and says nothing
about the other ten. `scripts/run-parity.sh` therefore prints a row for
each of the eleven and iterates until the run comes back clean.

Execution order differs from numeric order, which matters when reading
an exit status:

| Order | Sub-test | Exit code |
|---|---|---|
| 1 | `urldup` | 11 |
| 2 | `setget_parts` | 10 |
| 3 | `get_url` | 3 |
| 4 | `huge` | 9 |
| 5 | `get_nothing` | 7 |
| 6 | `scopeid` | 6 |
| 7 | `append` | 5 |
| 8 | `set_url` | 1 |
| 9 | `set_parts` | 2 |
| 10 | `get_parts` | 4 |
| 11 | `clear_url` | 8 |

The same mapping in numeric order: `set_url` 1, `set_parts` 2,
`get_url` 3, `get_parts` 4, `append` 5, `scopeid` 6, `get_nothing` 7,
`clear_url` 8, `huge` 9, `setget_parts` 10, `urldup` 11.

## Packaging with cargo-c

`cargo-c` produces what a C consumer expects of a Rust crate: an
archive, a shared object, a pkg-config file and a header. `cbuild`
builds that set and `cinstall` installs it. curl's own `docs/RUSTLS.md`
already directs developers to that tool for consuming Rust as a C
library, so the precedent belongs to the project rather than to this
crate.

This is packaging support and nothing more. No curl build file is
touched. Pointing `lib/Makefile.inc` or the root `CMakeLists.txt` at a
`cargo-c` artifact appears in the plan as a stretch goal and is resolved
as out of scope, because "no other part of curl is modified" is a stated
definition of success while that wiring is labeled as not the core
deliverable. Where a definition of success collides with an optional
extra, the definition governs.

`Cargo.toml` carries the `[package.metadata.capi]` block describing the
shape that path would install, and `scripts/build-rust.sh --capi`
invokes it. The path does not run today, and the reason is the fifth
reported constraint below.

## Reported constraints

Each of these is reported together with its remedy, and each remedy is
deliberately **not** applied. Where something in scope needs an
out-of-scope change to work, the constraint is recorded instead of the
scope being widened.

**R1, the distribution check fails once this directory is committed.**
`.github/scripts/distfiles.sh` compares the output of `git ls-files`
against the contents of the generated release tarball, subtracts a fixed
exception list, and exits non-zero for anything reported as missing. It
runs as the `missing-files` job of `.github/workflows/distcheck.yml` at
lines 210 to 224, and that workflow triggers on every push to the
default branch and every pull request against it with no path filter at
all, at lines 7 to 14. Every file under `rust-urlapi/` is therefore
reported as missing from the tarball. The exception list is a fixed
literal and cannot accommodate a new directory, so the only remedy is
adding this directory to `EXTRA_DIST` at `Makefile.am:67` or to the
distributed subdirectory lists at lines 73 and 74. That is an edit to
`Makefile.am`, which is out of scope. Downstream owners should treat the
one-line `EXTRA_DIST` addition as a follow-up decision outside this
work.

**R2, a second URL API test is beyond drop-in reach.**
`tests/unit/unit1653.c`, driven by `tests/data/test1653` and named
`urlapi port number parsing`, calls `Curl_parse_port` directly at line
37, and hands it a `CURLU *` together with a C `struct dynbuf` it
constructed itself. That function is exported only in unit-test builds,
through the conditional marker at `lib/urlapi-int.h:36`. Satisfying it
from Rust needs a ninth exported symbol, and it needs to read and write
the exact memory layout of C's dynamic buffer, a materially harder
contract than anything the public API demands. The stated success
criteria name `lib1560` and `test1560` only, so this second test is out
of scope, and it is recorded here rather than passed over in silence.

**R3, memory-debug builds are incompatible.** `curl_free` is a one-line
forward at `lib/escape.c:189-192` to a macro resolved at compile time.
Under the memory-debug configuration that macro becomes
`curl_dbg_free` at `lib/curl_setup.h:1461`. That function performs no
lookup and no validation: it subtracts its own `struct memdebug` header
from the pointer and frees that address instead
(`lib/memdebug.c:362-385`). This crate allocates the buffers it hands to
C with the C allocator directly, so handing one to that free corrupts
the heap rather than being refused, and the paired counter never saw the
block at all. Routing through libcurl's internal free hook instead means
importing a private symbol and still leaves the accounting wrong. The harness is therefore
built without memory debugging, and the ceiling `tests/data/test1560`
asserts at line 40, `Allocations: 3000`, is honored in spirit rather
than counted by curl's own counter. Passing `--valgrind` to
`scripts/run-parity.sh` reports an independent count without asserting
on it.

**R4, alternative memory functions are unsupported.** curl's free hook
is a mutable global function pointer at `lib/curl_setup.h:1309`,
initialized to `free` at `lib/easy.c:107`, and the entry point at
`lib/easy.c:237` reassigns it at runtime. An application that installs
its own memory functions releases the crate's C-allocator buffers with
its own free function. `docs/MEMORY-OWNERSHIP.md` records the whole
chain.

**R5, the `cargo-c` path cannot run against a six-feature manifest.**
`cargo-c` appends `--features capi` to every invocation whether or not
the package declares such a feature, and it treats a package as
C-API-relevant only when that feature is declared. It sets no
environment variable, so a build script has no other way to recognize a
packaging run, and Cargo rejects `--features capi` for a feature the
package does not declare. Measured against cargo-c 0.10.24, both
`cargo cbuild` and `cargo cinstall` stop with an error naming the
missing feature. The remedy is one line, `capi = []`, and it is not
taken, because that puts a seventh feature into a manifest whose design
tables six. Nothing else is affected: both configurations above build,
both parity modes run, and no acceptance criterion invokes the tool.

## The faithful-port posture

Where the C implementation does something surprising, the Rust
implementation does the same surprising thing and records it. Nothing is
quietly corrected, because a quiet correction is a behavior change in
the costume of a bug fix, and observable behavior is the one thing this
port may not change.

Six findings carry identifiers, `FB1` through `FB6`.
`docs/KNOWN-DIVERGENCES.md` states each one, what a caller can observe
because of it, and which Rust module carries it. Two of the six, `FB2`
and `FB3`, are a leak as well as a behavior in the C, and there the
reproduction stops at the behavior: the leaks are not reproduced, which
that document records as a residual difference of the port rather than
filing under "reproduced".

The demonstration program exercises `FB1` directly, in section 8 of
`demo/expected-output.txt`, so the finding is visible in the golden
transcript instead of being described and left there.

## Further reading

- [PORTING-NOTES.md][porting] maps the C functions onto the Rust
  modules, function by function, with line references into
  `lib/urlapi.c`.
- [MEMORY-OWNERSHIP.md][ownership] records every C-side ownership
  assumption: how `curl_free` resolves, every allocation site in the
  module, and the rule the crate follows at each one.
- [KNOWN-DIVERGENCES.md][divergences] catalogs `FB1` through `FB6`
  along with every residual divergence, the `idn-pure` backend among
  them.

[porting]: docs/PORTING-NOTES.md
[ownership]: docs/MEMORY-OWNERSHIP.md
[divergences]: docs/KNOWN-DIVERGENCES.md
