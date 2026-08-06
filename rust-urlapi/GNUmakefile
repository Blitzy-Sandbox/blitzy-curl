#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
###########################################################################
# The parity build driver for curl-urlapi-rs, the Rust re-implementation of
# curl's URL API.
#
# One command covers the whole of it. A bare "make" in this directory builds
# the C reference baseline from the unmodified repository, builds the crate
# in both feature configurations, compares the exported symbol sets against
# the object built from lib/urlapi.c, links the unmodified
# tests/libtest/lib1560.c against the port in both link modes, runs it beside
# the reference under every environment that changes what it asserts, diffs
# the demo transcript against the committed golden, and runs the crate's own
# test suites.
#
# This file exists because curl's build system may not be modified, so this
# directory has to behave like a standalone project nested inside the
# existing tree. It is deliberately not wired into curl's own build, and it
# cannot be reached from there even by accident: the root CMakeLists.txt
# names its subdirectories with explicit add_subdirectory() calls (docs at
# 1913, scripts 1916, lib 1918, src 1921, docs/examples 1926, tests 1930),
# and Makefile.am lists them explicitly too (EXTRA_DIST at 67, SUBDIRS at
# 73, DIST_SUBDIRS at 74). None of them can see this directory, and none of
# them may be edited. That boundary has one real consequence, recorded as R1
# in the reported-constraints section at the end of this file.
#
# Reading order for anyone new to the crate: README.md for the workflow,
# docs/PORTING-NOTES.md for the function-by-function mapping,
# docs/MEMORY-OWNERSHIP.md for the allocator contract, and
# docs/KNOWN-DIVERGENCES.md for the oddities the port reproduces on purpose.
#
# THIS FILE IS NAMED GNUmakefile, AND NOT Makefile, ON PURPOSE
#
# The repository root .gitignore carries a bare "Makefile" entry at line 35.
# With no slash in it, that pattern matches at every depth, so a file named
# Makefile here would be silently untracked and would simply vanish from the
# deliverable. Measured rather than assumed:
#
#   git check-ignore -v rust-urlapi/Makefile     -> .gitignore:35:Makefile
#   git check-ignore -v rust-urlapi/GNUmakefile  -> no output, so trackable
#
# GNU make prefers GNUmakefile over makefile and Makefile anyway, so a bare
# "make" in this directory finds this file with no extra flags and the name
# costs nothing. Please do not tidy it away. The alternative, a "!Makefile"
# negation in the root ignore file, would change repository-wide behavior to
# suit one directory, and that file is out of scope besides.
#
# WHY THE RECIPE PREFIX BELOW IS ">" AND NOT A TAB
#
# scripts/spacecheck.pl rejects a tab character anywhere in a tracked file
# unless the path matches its allowlist, and that list holds exactly
# m4/zz40-xc-ovr.m4, Makefile.am, Makefile.example, any .sln file,
# tests/data/data1706-stdout.txt and tests/data/test*. This path matches none
# of them, so the ordinary tab-indented recipe is not available here.
# .RECIPEPREFIX replaces it; it has been in GNU make since 3.82, and the
# toolchain here is 4.4.1.
#
# Two things follow, and both bite. Every recipe line has to begin with the
# prefix character, continuation lines included, or make reports "missing
# separator" and stops. And a tab introduced anywhere later, even inside a
# comment, fails the style gate rather than the build, which is the harder
# failure to connect back to its cause. The check is one line:
#
#   grep -n -P '\t' rust-urlapi/GNUmakefile   (must print nothing)
.RECIPEPREFIX := >

# WHY THE RECIPES ARE THIN
#
# Every substantive step lives in scripts/, and the recipes below do nothing
# but name one of those scripts with its arguments. That is not tidiness.
# The repository shell check, .github/scripts/shellcheck.sh, selects what it
# examines by shebang line, so scripts/*.sh are covered and this file is not:
# logic placed here would be logic no linter ever reads. The unusual recipe
# prefix is the second reason, since a long recipe body here is unusually
# easy to break.

# --------------------------------------------------------------------------
# Where everything is
# --------------------------------------------------------------------------

# The directory holding this file, absolute and with no trailing slash. Every
# path below is anchored to it rather than to the directory make happened to
# start in, and that is a safety requirement rather than a convenience: with
# relative paths, "make -f rust-urlapi/GNUmakefile clean" run from the
# repository root would delete the repository's own ./build and ./target
# instead of this crate's, and the one boundary this work may not cross is
# touching anything outside rust-urlapi/. firstword rather than lastword
# because MAKEFILE_LIST grows with every include; this file includes nothing,
# so the first entry is and stays this file.
CRATE_DIR := $(abspath $(dir $(firstword $(MAKEFILE_LIST))))

# Belt and braces for the clean target below, which expands CRATE_DIR into an
# rm. An empty value there would name the filesystem root, so refuse to parse
# at all rather than offer a target that could do harm.
ifeq ($(CRATE_DIR),)
$(error could not determine the directory holding this GNUmakefile)
endif

# The four scripts that do the actual work. Each one derives its own location
# from the path it was invoked with and changes to the crate directory
# itself, so naming them absolutely here is enough: they behave identically
# however make was started.
SCRIPTS := $(CRATE_DIR)/scripts
BUILD_REFERENCE := $(SCRIPTS)/build-reference.sh
BUILD_RUST := $(SCRIPTS)/build-rust.sh
CHECK_ABI := $(SCRIPTS)/check-abi.sh
RUN_PARITY := $(SCRIPTS)/run-parity.sh

# The scratch tree, and the four key=value fact files the scripts hand to one
# another through it. Named here because the target comments below refer to
# them, and because they are the first place to look when a step fails.
BUILD := $(CRATE_DIR)/build
REFERENCE_FACTS := $(BUILD)/reference-build.env
RUST_FACTS := $(BUILD)/rust-build-summary.txt
ABI_FACTS := $(BUILD)/abi-check-summary.txt
PARITY_FACTS := $(BUILD)/parity-summary.txt

# There is deliberately no BUILD_DIR knob. Three of the four scripts honor
# that variable, but scripts/build-rust.sh fixes its own scratch tree at
# <crate>/build (line 96), so pointing the other three elsewhere would leave
# check-abi.sh and run-parity.sh reading fact files the rust build never
# wrote. The tree is therefore fixed, and the .gitignore beside this file
# covers it, which is why a full run leaves "git status" clean.

# --------------------------------------------------------------------------
# Cargo
# --------------------------------------------------------------------------

CARGO ?= cargo

# Every cargo command runs from the crate directory instead of naming
# --manifest-path, because rustup resolves rust-toolchain.toml relative to
# the current directory: invoked from anywhere else, the pinned stable
# channel and its clippy and rustfmt components would silently not apply.
# scripts/build-rust.sh changes directory for the same reason.
CARGO_RUN := cd $(CRATE_DIR) && $(CARGO)

# Cargo.lock is committed, so a resolution that drifts should be a loud
# failure rather than a silent update. Override with CARGO_LOCKED= to let
# Cargo re-resolve.
CARGO_LOCKED ?= --locked

# The two feature configurations, spelled exactly as the two link modes need
# them. Mode A is the drop-in: strerror, cfree and scheme-table are all off,
# because in that link a real libcurl already defines curl_url_strerror,
# curl_free and the scheme table. Mode B is standalone and takes the default
# feature set, where the crate supplies all three itself.
FEATURES_A := --no-default-features --features idn-libidn2
FEATURES_B :=

# One target directory per configuration, so that switching between them does
# not invalidate the other's cache and neither disturbs the directories
# scripts/build-rust.sh uses (target/mode-a, target/mode-b, target/clippy-a,
# target/clippy-b). Relative, because the recipes have already changed to the
# crate directory by the time cargo reads them.
TEST_DIR_A := --target-dir target/test-mode-a
TEST_DIR_B := --target-dir target/test-mode-b
LINT_DIR := --target-dir target/lint
CLIPPY_DENY := -- -D warnings

# --------------------------------------------------------------------------
# Knobs
# --------------------------------------------------------------------------
#
# One pass-through per script, empty by default, so every option those
# scripts already document is reachable without adding a target for it. Run
# any of them with --help for the full list. The environment variables they
# read -- CC, JOBS, HARNESS_DEFINES, HARNESS_CFLAGS, REFERENCE_BUILD_DIR,
# CARGO_TARGET_DIR and the rest -- need nothing here, because make passes its
# own environment through to every recipe unchanged.
#
#   make reference REFERENCE_ARGS='--jobs 4'
#   make rust      RUST_ARGS=--capi
#   make abi       ABI_ARGS=--strict
#   make parity    PARITY_ARGS='--mode a --env utf8-codeset'
#
REFERENCE_ARGS ?=
RUST_ARGS ?=
ABI_ARGS ?=
PARITY_ARGS ?=

# --------------------------------------------------------------------------
# Make policy
# --------------------------------------------------------------------------

.DEFAULT_GOAL := all

# The four scripts share the one scratch tree and hand facts to each other
# through the files named above, so two of them running at once would
# interleave writers and produce a result that describes neither. Parallelism
# belongs inside the reference build, which REFERENCE_ARGS='--jobs N'
# reaches, and inside cargo, which parallelizes by itself.
.NOTPARALLEL:

# Every target here names a step, never a file, so every one of them is
# phony. The stamps that would otherwise be file targets are the fact files
# above, and they are deliberately not used as such: each script decides for
# itself what is already current, and a makefile guess at the prerequisites
# of a whole libcurl build would be a guess that reports "nothing to be
# done" for work that in fact needs redoing.
.PHONY: all reference rust abi harness-a harness-b demo-a demo-b parity \
  test lint clean help

# --------------------------------------------------------------------------
# all: the whole chain, in the only order that means anything
# --------------------------------------------------------------------------
#
# reference and rust produce the two things being compared. abi compares
# their symbol sets before any behavior is measured at all, because a symbol
# mismatch makes every behavioral result meaningless. parity then links and
# runs the unmodified test in both modes and diffs the demo transcripts. test
# runs the crate's own suites, which scripts/run-parity.sh explicitly leaves
# to this file.
#
# The harness and demo steps sit inside parity rather than beside it, and
# that is a decision rather than an omission: scripts/run-parity.sh is a
# single orchestrated pass that stages the test source, compiles the harness
# translation units, links both modes, links and runs both demos, and
# reports. Its only granularity is --mode and --no-demo, which is exactly
# what the four narrower targets below hand it. Naming those four here as
# well would run the same script five times over.
all: reference rust abi parity test
> @echo 'make: chain complete. The four summaries:'
> @echo '  $(REFERENCE_FACTS)'
> @echo '  $(RUST_FACTS)'
> @echo '  $(ABI_FACTS)'
> @echo '  $(PARITY_FACTS)'

# --------------------------------------------------------------------------
# reference: the C baseline everything is compared against
# --------------------------------------------------------------------------
#
# An out-of-tree CMake build of the unmodified repository with SSL,
# internationalized domains and LDAP all on, then the harness and the demo
# linked against it and their output captured as the golden files.
#
# Those three options are not optional. Without them the protocol set comes
# out as dict file ftp gopher http imap ipfs ipns mqtt pop3 rtsp smtp telnet
# tftp ws -- no https and no ldap -- while tests/data/test1560 declares nine
# required features at lines 17 to 25: file, https, http, pop3, smtp, imap,
# ldap, dict and ftp. A reference built without them would diverge on
# scheme-dependent assertions for reasons that have nothing to do with the
# port, which is the one kind of failure a parity run must never invent.
#
# Everything it writes lands in build/ or out of tree. The only tracked file
# it can touch is demo/expected-output.txt, and it leaves that alone unless
# the newly captured transcript matches it or --force is given, so this
# target never dirties the working tree.
reference:
> $(BUILD_REFERENCE) $(REFERENCE_ARGS)

# --------------------------------------------------------------------------
# rust: the crate, in both feature configurations
# --------------------------------------------------------------------------
#
# Builds Mode A and Mode B, runs the drop-in localization pass that turns
# each Cargo archive into libcurl_urlapi_rs_dropin.a, checks both with
# clippy, records the resolved dependency versions, and writes the fact file
# the next two steps read. Cargo has no post-build hook, which is why that
# localization pass is a second invocation driven by the script rather than
# something build.rs could do on its own.
rust:
> $(BUILD_RUST) $(RUST_ARGS)

# --------------------------------------------------------------------------
# abi: the symbol-set gate, which runs before any behavior is measured
# --------------------------------------------------------------------------
#
# reference and rust are real prerequisites and not a convenience:
# scripts/check-abi.sh reads both fact files. It compares the exported
# symbols of the Rust archive with those of the object built from
# lib/urlapi.c, and that set is exactly eight: Curl_is_absolute_url,
# Curl_junkscan, Curl_url_set_authority, curl_url, curl_url_cleanup,
# curl_url_dup, curl_url_get and curl_url_set. curl_url_strerror and
# curl_free must be absent in Mode A, because strerror.c.o and escape.c.o
# already define those two and a second definition would collide.
#
# Run this before any behavioral target. A symbol mismatch makes every
# behavioral result meaningless, so parity depends on it below rather than
# trusting the order a developer happens to type. To repeat only the
# comparison without rebuilding either side, call the script directly: it
# keeps no state beyond the files it reads.
abi: reference rust
> $(CHECK_ABI) $(ABI_ARGS)

# --------------------------------------------------------------------------
# harness-a, harness-b, demo-a, demo-b: one link mode at a time
# --------------------------------------------------------------------------
#
# Narrowings of the same driver, for working on a single mode. The harness
# targets pass --no-demo and so stop once the eleven sub-tests have run in
# every environment; the demo targets additionally diff the demo transcript
# against demo/expected-output.txt.
#
# Mode A is the authoritative drop-in, and the one that actually demonstrates
# "linkable in place of the object file built from lib/urlapi.c": the script
# copies the reference libcurl archive, deletes the urlapi member from the
# copy, and links the harness and the demo against that copy together with
# the Rust archive. The port therefore has to satisfy the real internal
# callers and coexist with the real free function, formatted-print family,
# scheme table and error-string function. The control link against the same
# copy without the Rust archive is the evidence: it fails with undefined
# references to exactly the symbols urlapi.c used to define. The script
# reports that set and its size rather than this file asserting a number,
# because which of the eight actually surface depends on the reference
# build's own feature set. With HTTP/2 enabled, http2.c.o is pulled in and
# Curl_url_set_authority surfaces alongside the six that always do, and with
# DNS-over-HTTPS enabled doh.c.o brings Curl_junkscan with it.
#
# Mode B is the standalone link. There the crate's default features supply
# curl_url_strerror, curl_free and a built-in scheme table, and the C shims
# in harness/shims.c supply the curl_mprintf family, so no libcurl takes part
# at all. Each link line names its own system libraries explicitly, since a
# Rust static library's dynamic dependencies are not recorded anywhere the
# linker can find them, and exactly one Rust archive appears on either line,
# since several of them are likely to conflict. The script asserts both of
# those itself rather than leaving them to the reader.
#
# Neither mode is built with curl's memory-debug configuration. That is
# reported constraint R3 at the end of this file, not an oversight.
harness-a: abi
> $(RUN_PARITY) --mode a --no-demo $(PARITY_ARGS)

harness-b: abi
> $(RUN_PARITY) --mode b --no-demo $(PARITY_ARGS)

demo-a: abi
> $(RUN_PARITY) --mode a $(PARITY_ARGS)

demo-b: abi
> $(RUN_PARITY) --mode b $(PARITY_ARGS)

# --------------------------------------------------------------------------
# parity: both modes, every environment, and a verdict per sub-test
# --------------------------------------------------------------------------
#
# The environment matrix belongs to the script, and it matters. Three
# settings together gate the internationalized-domain assertions, and
# dropping any one of them leaves those assertions silently not running,
# which is exactly what an early proof of concept did:
#
#   LC_ALL                       C.UTF-8, as tests/data/test1560 sets it at
#                                line 14, and C as well. The libidn2 lookup
#                                is locale-aware, so under LC_ALL=C every
#                                non-ASCII host fails and the reference
#                                itself reports CURLUE_BAD_HOSTNAME. The port
#                                has to reproduce that, not improve on it.
#   CURL_TEST_HAVE_CODESET_UTF8  set and unset both. tests/runtests.pl
#                                exports it at lines 837 to 839 and
#                                tests/libtest/lib1560.c reads it at line
#                                2036 to gate assertions in three sub-tests.
#   setlocale(LC_ALL, "")        called by harness/main.c exactly as the real
#                                entry point does at tests/libtest/first.c
#                                line 231.
#
# The four labels the script crosses are utf8-codeset, utf8-nocodeset,
# c-codeset and c-nocodeset. PARITY_ARGS='--env LABEL' narrows to one, which
# is for investigating a failure and never for declaring parity.
#
# Reporting is per sub-test, not per run. tests/libtest/lib1560.c short
# circuits at the first failure, so one exit status names one sub-test and
# says nothing about the other ten. The script therefore prints a row for
# each of the eleven, in the order the test runs them, with the exit code
# each produces and a verdict of pass, fail or blocked for the reference and
# for each mode:
#
#    1 urldup 11        5 get_nothing 7    9 set_parts 2
#    2 setget_parts 10  6 scopeid 6       10 get_parts 4
#    3 get_url 3        7 append 5        11 clear_url 8
#    4 huge 9           8 set_url 1
#
# Expected stdout is the single line "success", which lib1560.c prints at
# line 2073 and tests/data/test1560 asserts at line 37.
parity: abi
> $(RUN_PARITY) $(PARITY_ARGS)

# --------------------------------------------------------------------------
# test: the crate's own suites, in both feature configurations
# --------------------------------------------------------------------------
#
# cargo test twice, because the five suites under tests/ are feature-gated:
# tests/encode_decode.rs compiles one block only when scheme-table is off
# (line 158) and its internationalized-domain rows only when a backend is on,
# so a single configuration leaves the other's rows uncompiled. The two
# feature sets here are the two link modes, so the pair covers what the
# parity run links. scripts/run-parity.sh deliberately leaves these suites to
# this target and says so where it lists the limits of what it measures.
test:
> $(CARGO_RUN) test $(CARGO_LOCKED) $(FEATURES_B) $(TEST_DIR_B)
> $(CARGO_RUN) test $(CARGO_LOCKED) $(FEATURES_A) $(TEST_DIR_A)

# --------------------------------------------------------------------------
# lint: clippy with warnings denied, and a formatting check
# --------------------------------------------------------------------------
#
# --all-targets so the five integration suites are linted and not only the
# library, which is more than scripts/build-rust.sh does: its clippy pass
# covers the library, in both configurations. Between the two, everything
# that compiles is linted.
lint:
> $(CARGO_RUN) clippy $(CARGO_LOCKED) --all-targets $(LINT_DIR) $(CLIPPY_DENY)
> $(CARGO_RUN) fmt --all --check

# --------------------------------------------------------------------------
# clean: this directory's two generated trees, and nothing else
# --------------------------------------------------------------------------
#
# target/ is cargo's and build/ is the scripts' scratch tree, and the
# .gitignore beside this file covers both. Both paths are absolute and
# derived from this file's own location, so this target cannot reach outside
# rust-urlapi/ even when make was started from the repository root with -f,
# and CRATE_DIR is proved non-empty at parse time above. If CARGO_TARGET_DIR
# points at a tree outside this directory, that tree is deliberately left
# alone for the same reason. Nothing tracked is removed: after a clean,
# "git status --porcelain" reports nothing for this directory.
clean:
> rm -rf $(CRATE_DIR)/build $(CRATE_DIR)/target

# --------------------------------------------------------------------------
# help
# --------------------------------------------------------------------------
help:
> @echo 'curl-urlapi-rs parity driver. Targets:'
> @echo '  all         reference, rust, abi, parity, test. The default.'
> @echo '  reference   build the C baseline from the unmodified repository'
> @echo '  rust        build the crate in both feature configurations'
> @echo '  abi         compare the exported symbol sets. Run before parity.'
> @echo '  harness-a   link and run the unmodified lib1560.c, Mode A only'
> @echo '  harness-b   the same, Mode B only'
> @echo '  demo-a      Mode A, and diff the demo against its golden'
> @echo '  demo-b      Mode B, and diff the demo against its golden'
> @echo '  parity      both modes, four environments, per-sub-test report'
> @echo '  test        cargo test in both feature configurations'
> @echo '  lint        cargo clippy -D warnings, and cargo fmt --check'
> @echo '  clean       remove build/ and target/ under this directory only'
> @echo 'Knobs: REFERENCE_ARGS, RUST_ARGS, ABI_ARGS, PARITY_ARGS, CARGO,'
> @echo 'CARGO_LOCKED. Each script also takes --help.'

# --------------------------------------------------------------------------
# Reported constraints: recorded here, and deliberately not remedied
# --------------------------------------------------------------------------
#
# R1, THE DISTRIBUTION CHECK WILL FAIL ONCE THIS DIRECTORY IS COMMITTED.
# .github/scripts/distfiles.sh compares the output of git ls-files against
# the contents of the generated release tarball, subtracts a fixed exception
# list, and exits non-zero for anything reported as missing. It runs as the
# missing-files job of .github/workflows/distcheck.yml (lines 210 to 224),
# and that workflow triggers on every push to the default branch and every
# pull request against it with no path filter at all (lines 7 to 14). Every
# file under rust-urlapi/ will therefore be reported as missing from the
# tarball and that job will fail. The exception list is a fixed literal and
# cannot accommodate a new directory, so the only remedy is to add this
# directory to EXTRA_DIST (Makefile.am line 67) or to the distributed
# subdirectory lists (lines 73 and 74). That is an edit to Makefile.am, which
# is out of scope, so it is not made here. Downstream owners should treat the
# one-line EXTRA_DIST addition as a follow-up decision outside this work.
#
# R3, THE HARNESS IS BUILT WITHOUT CURL'S MEMORY-DEBUG CONFIGURATION.
# curl_free is a one-line forward (lib/escape.c lines 189 to 192) to a macro
# resolved at compile time. Under the memory-debug configuration it becomes
# curl_dbg_free (lib/curl_setup.h line 1461), which performs no lookup and no
# validation: it subtracts its own struct memdebug header from the pointer and
# frees that address instead (lib/memdebug.c lines 362 to 385). This crate
# allocates the buffers it hands to C with the C allocator directly, so handing
# one to that free corrupts the heap rather than being refused, and the paired
# counter never saw the block; routing through libcurl's internal free hook
# would mean importing a private symbol and would still leave the accounting
# wrong. So the ceiling tests/data/test1560
# asserts at line 40, "Allocations: 3000", is honored in spirit -- the port
# is not materially more allocation-hungry than the original -- but it is not
# counted by curl's own counter. PARITY_ARGS=--valgrind reports an
# independent count without asserting on it. This is a documented limitation,
# not something to work around.
#
# Two further limits of this driver, for completeness. tests/unit/unit1653.c
# is not run: it calls Curl_parse_port directly with a C dynamic-buffer
# structure it built itself, which would need a ninth exported symbol and
# bit-compatible interoperation with that structure (R2). And the
# Windows-only paths in the port are compiled conditionally and are not
# exercised here at all.
