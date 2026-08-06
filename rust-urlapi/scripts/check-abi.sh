#!/usr/bin/env bash
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

# Compare the exported symbol set of the Rust archive against the exported
# symbol set of the object file built from lib/urlapi.c, and refuse to agree
# that anything is a drop-in replacement until the two sets are equal.
#
# THIS RUNS BEFORE ANY BEHAVIOURAL CHECK, and that ordering is the whole
# point rather than a convenience: a symbol mismatch makes every behavioural
# result meaningless. A crate missing one of the eight names produces an
# undefined reference at link time and no test runs at all; a crate exporting
# one name too many produces a duplicate definition, or -- worse, because it
# is silent -- lets the linker pick whichever definition it reached first and
# then reports a pass for code that is not the code under test. Either way
# the diff that run-parity.sh performs afterwards would be comparing
# something other than what it claims to compare. So the surface is settled
# here, first, and the behaviour is settled afterwards.
#
# WHAT IS COMPARED
#
# The C side is the oracle. lib/urlapi.c defines exactly eight globals, and
# that number was established by reading the source rather than assumed:
# every other definition in the file is static, and the two that are marked
# UNITTEST are static as well unless the library is built with UNITTESTS
# defined, because lib/curl_setup.h:1505-1509 expands UNITTEST to nothing in
# that build and to "static" in every other. The eight are listed in
# EXPECTED_SYMBOLS below, each with the line that defines it.
#
# The Rust side is whichever of the crate's archives is being certified. Both
# are checked when both are present, because they are different artifacts
# with different properties:
#
#   libcurl_urlapi_rs_dropin.a  the canonical drop-in archive, which build.rs
#                               manufactures from Cargo's output with ld -r
#                               --whole-archive, objcopy --keep-global-symbol
#                               and ar rcs. It defines the ABI and nothing
#                               else, so it is compared UNFILTERED. This is
#                               the artifact a link actually consumes.
#
#   libcurl_urlapi_rs.a         Cargo's own staticlib. A staticlib carries
#                               the whole Rust standard library with it, so
#                               it defines thousands of globals rather than
#                               eight and is compared through the filter
#                               described at rust_exports() below. No count is
#                               quoted here on purpose: it moves with the
#                               toolchain and with the standard library, so a
#                               literal would go stale without anything
#                               breaking. build.rs measures it at the moment
#                               it matters and records it in the provenance
#                               file beside the canonical archive, as
#                               raw-defined-globals.
#
# For the ARCHIVES, only DEFINED symbols take part, and that is deliberate. A
# drop-in archive is SUPPOSED to have undefined references: that is what makes
# it a drop-in rather than a standalone library. In the drop-in configuration
# it imports Curl_get_scheme and Curl_getn_scheme from lib/url.c:1469-1472,
# inet_pton and inet_ntop for the address handling in src/inet.rs, four
# libidn2 entry points for src/idn.rs, and the C allocator entry points for
# src/alloc.rs. nm --defined-only excludes every one of them, which is exactly
# right for an archive, and nothing in the archive checks treats an undefined
# reference as a finding.
#
# For the SHARED OBJECTS the undefined side is checked too, because there it
# is a contract rather than a link-time detail: a shared object with an
# unresolved reference either resolves it from the link it is part of or does
# not load at all. The section headed "The shared objects, import contracts"
# asserts that mode A imports exactly the two scheme entry points and that
# both are names lib/urlapi.o itself leaves undefined, and that mode C imports
# nothing in either namespace, which is what makes mode C loadable.
#
# THE TWO DIRECTIONS
#
# Set equality is asserted, not containment, and both directions fail:
#
#   missing from the Rust archive        an undefined reference at link time
#   unexpectedly exported by the Rust    a duplicate definition, or a silent
#   archive                              substitution for a libcurl symbol
#
# A one-directional check would pass a crate that exports too much, which is
# precisely the collision hazard, so both lists are printed and either one
# being non-empty fails the run.
#
# THE THREE CONFIGURATIONS, CHECKED IN OPPOSITE DIRECTIONS
#
# Mode A, the static drop-in configuration -- built with --no-default-features
# --features idn-libidn2 -- must export the eight and must NOT export
# curl_url_strerror or curl_free, because a real libcurl already defines both
# (lib/strerror.c:420 and lib/escape.c:189).
#
# Mode B, the standalone configuration -- the manifest defaults -- must
# export those same two IN ADDITION to the eight, because nothing else in a
# standalone link supplies them. Checking mode B is not symmetry for its own
# sake: it catches a mis-specified feature set, such as a mode B archive
# accidentally built with --no-default-features, which would then fail to
# link the standalone demo for a reason no behavioural test would explain.
#
# Mode C, the shared drop-in configuration -- --no-default-features --features
# idn-libidn2,scheme-table -- must export exactly the same eight as mode A,
# and its shared object must additionally import nothing in the curl_ or
# Curl_ namespace. That pair of properties is what makes it the shared half of
# G1: one shared object from this crate, exporting the complete symbol set
# lib/urlapi.o exports and no more, and loadable.
#
# WHAT IT PRODUCES
#
#   build/abi-check-summary.txt   key=value verdicts, for run-parity.sh
#
# Nothing else is written. The scratch directory is created with mktemp and
# removed by an EXIT trap, the archive member and the symbol lists live inside
# it, and no path outside build/ or the system temporary directory is touched.
# lib/urlapi.c and every other pre-existing file are read only, which is goal
# G4 and acceptance criterion A12.
#
# THE SUMMARY FILE IS DATA, NOT SHELL. Its keys are lowercase with dashes,
# which are deliberately not valid shell identifiers, so the file cannot be
# sourced even by accident. Every value is validated before it is written --
# no carriage return, no newline, no other control byte -- and every key is
# written at most once. run-parity.sh parses it with sed.
#
# EXIT STATUS. This is a GATE, so completeness is the default: a check that
# could not run is a failure, exactly like a check that ran and disagreed.
# Exit status is 0 only when every check ran and passed. --allow-partial
# relaxes that to "no check disagreed", which is for somebody working through
# a single symbol by hand and is never what a workflow wants -- a gate that
# reports success because it could not find the artifact it was meant to
# inspect is worse than no gate, because the next script proceeds on the
# strength of it.
#
# FRESHNESS. Every path this script consumes from a summary file is checked
# against the schema, the generator, the verdict and the recorded sha256 of
# the producing run, and the two producing runs are checked against each other
# for source revision. Without that, "the file at the recorded path" and "the
# file that run produced" are two different claims that coincide most of the
# time, and the scratch tree is deliberately reusable.

set -eu

# pipefail, so that a failure anywhere in a pipeline is the pipeline's failure.
# Every symbol list below is produced by a pipeline whose first stage is nm or
# ar; without pipefail the status belongs to the last stage, which is sort or
# awk and which succeeds on empty input. An empty symbol list compared against
# an empty expectation is a check that passes without having looked at
# anything. The places where a non-zero status is genuinely expected guard
# themselves explicitly.
set -o pipefail

# Every file this script creates is created for this user only. The summary is
# a predictable path by design -- run-parity.sh has to find it -- so the
# protection against another user planting a symlink there first is the
# permission mask plus the remove-before-write discipline fresh_path() applies.
umask 077

# Run from the crate root whatever directory the caller was in, so that every
# relative path below means one thing and so that an invocation through the
# abi target of ../GNUmakefile, from inside scripts/, or with an absolute
# path all behave identically.
#
# Derived with parameter expansion rather than with dirname, deliberately, and
# for the same reason build-reference.sh does it: this is the one place where
# an external command cannot be checked for first, because the prerequisite
# table has not run yet. A missing or shadowed dirname would make the command
# substitution expand to nothing and the cd would then land on the filesystem
# root instead of failing. Parameter expansion is a shell builtin and cannot
# fail that way.
SCRIPT_DIR="${0%/*}"
if [ "${SCRIPT_DIR}" = "${0}" ]; then
  SCRIPT_DIR='.'
elif [ -z "${SCRIPT_DIR}" ]; then
  SCRIPT_DIR='/'
fi
cd "${SCRIPT_DIR}/.."

# pwd -P, not pwd: the physical path with every symlink resolved is what the
# containment check in resolve_output_root() compares against, and comparing a
# logical path with a physical one is a comparison a symlink can defeat.
CRATE_DIR="$(pwd -P)"

# The unmodified repository. Needed by the compile fallback and by the
# containment rule below, and taken as the parent directory rather than from
# git so that the script still works in an exported tree with no .git in it.
REPO_ROOT="$(cd .. && pwd -P)"

# Where an output tree is allowed to be, and why the question needs asking.
#
# BUILD_DIR is environment-controlled, and the summary this script publishes,
# the scratch directory it creates and the staged reference object it keeps all
# go underneath it. An unvalidated value therefore lets the environment aim
# those writes at any directory on the machine, lib/ and tests/ and the
# repository root among them, where the result would be modifications to
# pre-existing files. That is goal G4 and acceptance criterion A12 broken by an
# environment variable, so the value is checked rather than trusted.
#
# The rule is the same one build-reference.sh and build-rust.sh apply, stated
# in full here as well because each script has to stand on its own:
#
#   - inside the repository, only <crate>/build and <crate>/target and their
#     descendants are allowed. Those two are what ../.gitignore covers, so
#     they are the only places inside the tree where writing cannot show up in
#     "git status --porcelain";
#   - outside the repository, anything is allowed except the filesystem root;
#   - the repository root itself and the empty string are refused outright.
#
# The path is canonicalized with cd + pwd -P before any of that is decided,
# which is what makes a symlink harmless rather than an escape: a build
# directory that is a symlink to lib/ resolves to lib/ and is refused on the
# resolved name. Judging the name as given would refuse nothing.
#
#   $1  label used in the diagnostic
#   $2  the path to resolve
#
# Prints the canonical path. Never returns on a refusal.
resolve_output_root() {
  local label="${1}"
  local raw="${2}"
  local canonical

  if [ -z "${raw}" ]; then
    printf 'check-abi.sh: error: %s\n' \
      "${label} is set but empty. Unset it to accept the default, or give it \
a directory" >&2
    exit 2
  fi

  if ! mkdir -p -- "${raw}" 2> /dev/null; then
    printf 'check-abi.sh: error: %s\n' \
      "${label}=${raw} could not be created" >&2
    exit 2
  fi

  if ! canonical="$(cd -- "${raw}" && pwd -P)"; then
    printf 'check-abi.sh: error: %s\n' \
      "${label}=${raw} exists but could not be entered, so its real location \
cannot be established" >&2
    exit 2
  fi

  if [ "${canonical}" = '/' ]; then
    printf 'check-abi.sh: error: %s\n' \
      "${label} resolves to the filesystem root, and this script writes a \
summary and a scratch directory underneath it" >&2
    exit 2
  fi

  if [ "${canonical}" = "${REPO_ROOT}" ]; then
    printf 'check-abi.sh: error: %s\n' \
      "${label}=${raw} resolves to the repository root ${REPO_ROOT}. Writing \
there would modify pre-existing files, which goal G4 forbids" >&2
    exit 2
  fi

  case "${canonical}" in
    "${CRATE_DIR}/build" | "${CRATE_DIR}/build/"* | \
    "${CRATE_DIR}/target" | "${CRATE_DIR}/target/"*)
      # Inside the crate's own ignored output. The allowed in-repository case.
      ;;
    "${REPO_ROOT}/"*)
      printf 'check-abi.sh: error: %s\n' \
        "${label}=${raw} resolves to ${canonical}, which is inside the \
repository but outside the crate's ignored output. Only ${CRATE_DIR}/build \
and ${CRATE_DIR}/target are writable inside the tree -- everything else would \
leave modifications that acceptance criterion A12 forbids. Point it at one of \
those, or at a directory outside ${REPO_ROOT} entirely" >&2
      exit 2
      ;;
    *)
      # Outside the repository. Allowed, and the parallel-clone case.
      ;;
  esac

  printf '%s\n' "${canonical}"
}

# Removes whatever occupies a path so that the next write creates it fresh.
#
# The summary is a predictable path underneath the scratch tree, because
# run-parity.sh has to find it without being told. That predictability is what
# a symlink attack needs: plant build/abi-check-summary.txt as a link to
# something else and a plain ">" redirection follows it and truncates the
# target. rm removes the LINK rather than what it points at, so removing first
# and creating second turns the whole class of problem into a no-op. Real
# directories are left alone, and an absent path is not an error.
#
#   $1  the path to clear
fresh_path() {
  if [ -e "${1}" ] || [ -L "${1}" ]; then
    if [ -d "${1}" ] && [ ! -L "${1}" ]; then
      return 0
    fi
    rm -f -- "${1}"
  fi
}

# BUILD_DIR is honoured because the other three scripts honour it: a caller who
# moved the scratch tree elsewhere, or who parameterised it per clone for a
# parallel run, must be able to point all four at the same place without
# editing anything.
#
# The colon-less expansion is deliberate: the default applies when BUILD_DIR is
# UNSET, and a value that is set and empty is handed to resolve_output_root()
# to be refused there.
BUILD="$(resolve_output_root BUILD_DIR "${BUILD_DIR-${CRATE_DIR}/build}")"

LIBRARY='curl_urlapi_rs'
ARCHIVE="lib${LIBRARY}.a"
DROPIN="lib${LIBRARY}_dropin.a"
SHARED="lib${LIBRARY}.so"

# The two summary files this script reads instead of re-deriving their
# contents. They use different formats, which is why read_fact() takes the
# format as an argument: build-rust.sh writes bare key=value with dashes in
# the keys, build-reference.sh writes KEY='value' with the value quoted.
RUST_FACTS="${BUILD}/rust-build-summary.txt"
REFERENCE_FACTS="${BUILD}/reference-build.env"

# The one file this script writes, so that run-parity.sh can read the verdict
# and the discovered member name rather than deriving either again. Two
# scripts deriving the same fact independently is two chances to disagree.
SUMMARY="${BUILD}/abi-check-summary.txt"

# ------------------------------------------------------------------------
# The expected and forbidden sets
#
# Literal lists rather than anything derived, because they are the contract.
# Every name was verified against the definitions in lib/urlapi.c and against
# the symbol table of a real reference object.
# ------------------------------------------------------------------------

# The eight globals lib/urlapi.c defines. Three are internal to libcurl and
# declared in lib/urlapi-int.h:28-33; five are the public API declared in
# include/curl/urlapi.h. Sorted in the order LC_ALL=C gives, because every
# comparison below is against a C-sorted list.
#
#   Curl_is_absolute_url    lib/urlapi.c:182   consumed by lib/http1.c:220,
#                                              lib/url.c:1661, lib/http.c:1177
#   Curl_junkscan           lib/urlapi.c:223   consumed by lib/doh.c:1127
#   Curl_url_set_authority  lib/urlapi.c:658   consumed by lib/http2.c:739
#   curl_url                lib/urlapi.c:1288
#   curl_url_cleanup        lib/urlapi.c:1293
#   curl_url_dup            lib/urlapi.c:1310
#   curl_url_get            lib/urlapi.c:1541
#   curl_url_set            lib/urlapi.c:1805
EXPECTED_SYMBOLS=(
  'Curl_is_absolute_url'
  'Curl_junkscan'
  'Curl_url_set_authority'
  'curl_url'
  'curl_url_cleanup'
  'curl_url_dup'
  'curl_url_get'
  'curl_url_set'
)

# Names that must NOT be exported by the drop-in archive. Each one has its
# own diagnostic, in forbidden_reason() below, because the four are forbidden
# for three different reasons and a single message would explain none of them.
FORBIDDEN_SYMBOLS=(
  'curl_url_strerror'
  'curl_free'
  'Curl_parse_port'
  'dedotdotify'
)

# The two the standalone configuration adds, under the strerror and cfree
# features respectively. In C-sort order.
STANDALONE_EXTRA=(
  'curl_free'
  'curl_url_strerror'
)

# The two UNITTEST-marked names in lib/urlapi.c. Their appearance on the C
# side is not a port defect but a reference-build misconfiguration, and it is
# caught separately so that the diagnostic can say so.
UNITTEST_SYMBOLS=(
  'Curl_parse_port'
  'dedotdotify'
)

# ------------------------------------------------------------------------
# Options
# ------------------------------------------------------------------------

# Completeness is the DEFAULT, and the reason is what this script is for.
#
# It is a gate: run-parity.sh links the Rust archive in place of the object
# built from lib/urlapi.c and then diffs behaviour, and neither the link nor
# the diff means anything while the surface disagrees. A gate that reports
# success because it could not find the artifact it was meant to inspect is
# worse than no gate at all, because the next script proceeds on the strength
# of it. So a check that could not run counts as a failure, exactly like a
# check that ran and disagreed.
#
# ALLOW_PARTIAL is the deliberate, manual escape hatch for somebody working
# through a single symbol by hand, who has built one configuration and knows
# it. It is never what a workflow wants and the closing summary says so out
# loud.
#
# STRICT is retained as the inverse of ALLOW_PARTIAL so that --strict, which is
# what the make target and any existing caller pass, keeps working and keeps
# meaning what it says. It now merely restates the default.
ALLOW_PARTIAL="${ALLOW_PARTIAL:-0}"
if [ "${ALLOW_PARTIAL}" != '0' ]; then
  STRICT=0
else
  STRICT="${STRICT:-1}"
fi
CHECK_COLLISION="${CHECK_COLLISION:-1}"
ALLOW_COMPILE_FALLBACK="${ALLOW_COMPILE_FALLBACK:-0}"
CC_BIN="${CC:-cc}"

usage() {
  cat <<'EOF'
Usage: scripts/check-abi.sh [options]

Compares the exported symbol set of the Rust archive with the exported
symbol set of the object built from lib/urlapi.c, in both feature
configurations, and reports a per-check verdict. Run this before
run-parity.sh: a symbol mismatch makes every behavioural result
meaningless.

Every check must RUN and PASS, and every artifact must have established
provenance. A check that could not run -- a missing archive, a missing
shared object, an unreadable artifact -- is a failure, because a gate that
reports success without having looked is worse than no gate. A build
summary that is absent, malformed or records a run that did not succeed is
also a failure, because the artifacts it would name cannot then be shown to
be the ones this workflow produced. Use --allow-partial to relax both
deliberately.

Options:
  -h, --help          show this text and exit
  --allow-partial     turn this from a gate into a by-hand instrument. A
                      check that could not run becomes a skip instead of a
                      failure; a missing or failed build summary is worked
                      around instead of refused; the environment overrides
                      and Cargo's own target/release directory are consulted
                      for artifacts, with no provenance established for what
                      is found there. For working through a single symbol
                      when only one configuration has been built. Never
                      appropriate in a workflow, and the closing summary
                      says so.
  --strict            treat a skipped check as a failure. This is now the
                      default and the option is retained so that existing
                      callers keep working; it is the inverse of
                      --allow-partial.
  --no-collision      skip the link collision pre-check, which is the one
                      step that reads every member of the reference
                      archive and so the one that takes noticeable time
  --allow-compile-fallback
                      when no reference archive can be found, compile
                      lib/urlapi.c directly instead of giving up. Off by
                      default, and the reason is printed when it is used:
                      the archive route certifies the object a real
                      libcurl link would consume, this one certifies an
                      object assembled here from a guessed preprocessor
                      state.

Environment variables, each overriding what the summary files say:
  BUILD_DIR           the scratch tree, default ./build
  REFERENCE_ARCHIVE   the libcurl archive holding the urlapi member
  REFERENCE_URLAPI_OBJECT
                      an already extracted urlapi object, used as is
  MODE_A_DROPIN       the canonical drop-in archive of mode A
  MODE_A_ARCHIVE      Cargo's own staticlib for mode A
  MODE_A_SHARED       the mode A shared object, eight exports plus two imports
  MODE_B_DROPIN       the canonical drop-in archive of mode B
  MODE_B_ARCHIVE      Cargo's own staticlib for mode B
  MODE_B_SHARED       the mode B shared object, ten exports
  MODE_C_SHARED       the mode C shared object, eight exports and closed
  STRICT=1            --strict, which is the default
  ALLOW_PARTIAL=1     --allow-partial
  CHECK_COLLISION=0   --no-collision
  ALLOW_COMPILE_FALLBACK=1
                      --allow-compile-fallback
  KEEP_SCRATCH        1 keeps the scratch tree of symbol lists whatever the
                      outcome, 0 removes it whatever the outcome. Unset,
                      which is the default, keeps it only on a failure,
                      where it is the evidence
  CC                  the C compiler for the compile fallback, default cc
  CURL_CONFIG_H       an existing curl_config.h for the compile fallback
  REFERENCE_FALLBACK_DEFINES
                      extra preprocessor arguments for the compile fallback,
                      whitespace separated, empty by default. They are added
                      after the fixed set this script derives
                      (-DHAVE_CONFIG_H -DBUILDING_LIBCURL, plus
                      -D_GNU_SOURCE on the platforms curl's own CMake build
                      defines it for), so they can add to that set but not
                      remove from it. Read only on the fallback path, which
                      --allow-compile-fallback has to enable, and ignored
                      entirely when a reference archive was found.
                      ABI-affecting: what lib/urlapi.c compiles to depends on
                      its preprocessor state, so a value here changes the
                      symbol set this script certifies against. -DUNITTESTS
                      in particular would add Curl_parse_port and dedotdotify
                      to the C side and make the comparison fail against a
                      Rust archive that correctly does not export them. Leave
                      it unset unless a platform's reference build genuinely
                      needs something else, and prefer running
                      scripts/build-reference.sh, which certifies the object
                      a real libcurl link consumes instead of one assembled
                      here from a guessed state.
                      It carries several arguments in one value, so it IS
                      split on whitespace -- deliberately, with read -a
                      rather than by leaving an expansion unquoted -- which
                      means a define whose value contains a space cannot be
                      passed this way.

Exit status is 0 only when every check ran and passed. With
--allow-partial it is 0 when no check that ran disagreed.
EOF
}

while [ "$#" -gt 0 ]; do
  case "${1}" in
    -h|--help)
      usage
      exit 0
      ;;
    --strict)
      STRICT=1
      ALLOW_PARTIAL=0
      ;;
    --allow-partial)
      STRICT=0
      ALLOW_PARTIAL=1
      ;;
    --no-collision)
      CHECK_COLLISION=0
      ;;
    --allow-compile-fallback)
      ALLOW_COMPILE_FALLBACK=1
      ;;
    *)
      printf 'check-abi.sh: error: unknown option %s\n\n' "${1}" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

# ------------------------------------------------------------------------
# Reporting
#
# Progress and verdicts go to stdout so that the transcript reads in order
# and can be redirected whole. Only the closing diagnostic goes to stderr,
# because duplicating every failure on both streams makes a terminal
# transcript unreadable without making a redirected one any more useful.
# ------------------------------------------------------------------------

say() {
  printf '%s\n' "$*"
}

step() {
  printf '\n== %s\n' "$*"
}

note() {
  printf '  %s\n' "$*"
}

warn() {
  printf 'check-abi.sh: warning: %s\n' "$*" >&2
}

die() {
  printf 'check-abi.sh: error: %s\n' "$*" >&2
  exit 1
}

# Per-check verdicts. Counted as well as printed, because the exit status is
# a function of the counts and a reader has to be able to see the arithmetic.
CHECKS_PASSED=0
CHECKS_FAILED=0
CHECKS_SKIPPED=0
VERDICTS=()

pass() {
  CHECKS_PASSED=$((CHECKS_PASSED + 1))
  VERDICTS+=("PASS  ${1}")
  printf '  PASS  %s\n' "${1}"
}

fail() {
  CHECKS_FAILED=$((CHECKS_FAILED + 1))
  VERDICTS+=("FAIL  ${1}")
  printf '  FAIL  %s\n' "${1}"
}

# A skip is a real outcome and is reported as one, never as a pass. --strict
# turns the tally into a failure at the end rather than here, so that a run
# still reports everything it managed to check.
skip() {
  CHECKS_SKIPPED=$((CHECKS_SKIPPED + 1))
  VERDICTS+=("SKIP  ${1}")
  printf '  SKIP  %s\n' "${1}"
}

# Why a particular name may not be exported by the drop-in archive. Four
# names, three distinct reasons, so each gets its own sentence: a single
# message covering all of them would explain none of them.
forbidden_reason() {
  case "${1}" in
    curl_url_strerror)
      printf '%s' "not implemented in lib/urlapi.c at all -- it lives in \
lib/strerror.c:420-531, so exporting it here defines a symbol that \
strerror.c.o already defines. Feature strerror must be off in mode A"
      ;;
    curl_free)
      printf '%s' "defined at lib/escape.c:189-192 and already present in \
escape.c.o. Feature cfree must be off in mode A"
      ;;
    Curl_parse_port)
      printf '%s' "UNITTEST-gated at lib/urlapi.c:335 and declared only \
under #ifdef UNITTESTS at lib/urlapi-int.h:35-38. Reported constraint R2: \
out of scope, see the closing section"
      ;;
    dedotdotify)
      printf '%s' "UNITTEST-gated at lib/urlapi.c:715-716, the second such \
name in the file, consumed by tests/unit/unit1395.c. Out of scope for the \
same reason as Curl_parse_port"
      ;;
    *)
      printf '%s' "not part of the drop-in symbol set"
      ;;
  esac
}

# ------------------------------------------------------------------------
# Reading the summary files
# ------------------------------------------------------------------------

# One value from one summary file, or the empty string when the file or the
# key is absent. Absence is not an error here: every caller has a fallback,
# and a missing summary file is the ordinary state before the corresponding
# build script has been run.
#
# Both producers now write the identical format: bare key=value, keys lowercase
# with dashes. Dashes in the keys are what makes either file impossible to
# source, since a dash is not allowed in a shell identifier, and that is the
# reason the format was chosen rather than a side effect of it. Values carry no
# control byte, because the producers refuse to write one.
# The reference summary additionally repeats a dozen of its records under an
# upper-case underscored spelling, because scripts/run-parity.sh reads that
# one; its fact() accepts either shape and refuses a repeated key, so the two
# spellings are aliases. Reading either from here works.
read_fact() {
  local file="${1}"
  local key="${2}"
  local line

  if [ ! -f "${file}" ]; then
    return 0
  fi

  # The key is interpolated into a sed expression. Every key used below is a
  # literal in this file, so an unexpected character would be a programming
  # error rather than untrusted input, but a sed expression assembled from an
  # unchecked string is worth refusing on principle.
  case "${key}" in
    *[!A-Za-z0-9_-]*)
      die "read_fact: refusing to look up the key '${key}'"
      ;;
  esac

  # The last occurrence wins. Neither writer repeats a key -- both refuse a
  # duplicate outright -- and taking the last is what makes an appended
  # correction behave the way a reader would expect if one ever did.
  line="$(sed -n "s/^${key}=//p" "${file}" | tail -n 1)"

  printf '%s\n' "${line}"
}

# ------------------------------------------------------------------------
# Trusting a summary file
#
# WHY THIS SECTION EXISTS. Every artifact path this script inspects comes out
# of a summary file written by another script, minutes or hours earlier, into a
# scratch tree that is deliberately reusable. Reading a path out of such a file
# and inspecting whatever now sits there conflates two different claims: "the
# file at the recorded path" and "the file that run produced". They coincide
# most of the time. When they do not, this script declares a symbol set correct
# on the strength of bytes nobody built in this workflow, run-parity.sh links
# them, and the parity result that follows describes something no one can
# name.
#
# Five things are therefore checked before any recorded path is used, and each
# one closes a different way of being wrong:
#
#   schema      -- the file is the kind of file this script thinks it is, and
#                  not an older or a hand-written one;
#   generated-by-- it was written by the script it claims, so an unrelated
#                  key=value file cannot stand in;
#   result=pass -- the producing run actually SUCCEEDED. A failed or
#                  interrupted run leaves result=fail or result=in-progress,
#                  and its paths must not be consumed at all;
#   sha256      -- the bytes at the path are the bytes that run produced;
#   source-revision across the two producers -- the reference build and the
#                  Rust build came from one checkout, so a symbol set is not
#                  compared against an oracle from a different revision.
# ------------------------------------------------------------------------

# Validates one summary file and reports why it cannot be trusted, if it
# cannot.
#
#   $1  the file
#   $2  the schema it must declare
#   $3  the generator it must name
#
# Returns 0 when the file is present, well formed and records a successful run.
# Prints nothing on success; on failure prints one line saying why. Never
# exits, because a missing summary is an ordinary state -- the corresponding
# build script has simply not run -- and the caller decides whether that is
# fatal.
summary_is_trustworthy() {
  local file="${1}"
  local want_schema="${2}"
  local want_generator="${3}"
  local got

  if [ ! -f "${file}" ]; then
    printf '%s is not there\n' "${file}"
    return 1
  fi
  if [ ! -r "${file}" ]; then
    printf '%s cannot be read\n' "${file}"
    return 1
  fi

  got="$(read_fact "${file}" 'schema')"
  if [ "${got}" != "${want_schema}" ]; then
    printf '%s declares schema "%s" rather than "%s"\n' \
      "${file}" "${got:-none}" "${want_schema}"
    return 1
  fi

  got="$(read_fact "${file}" 'generated-by')"
  if [ "${got}" != "${want_generator}" ]; then
    printf '%s says it was written by "%s" rather than by %s\n' \
      "${file}" "${got:-nothing}" "${want_generator}"
    return 1
  fi

  got="$(read_fact "${file}" 'result')"
  if [ "${got}" != 'pass' ]; then
    printf '%s records result=%s, so the run that wrote it did not succeed\n' \
      "${file}" "${got:-none}"
    return 1
  fi

  return 0
}

# Confirms that the bytes at a path are the bytes a summary recorded.
#
#   $1  the artifact
#   $2  the summary file
#   $3  the key holding the expected digest
#
# Returns 0 when the digest matches, or when the summary records no digest for
# it -- an override the caller named by hand has no recorded digest and must
# not be refused for lacking one. Prints one line on a mismatch.
artifact_matches_digest() {
  local artifact="${1}"
  local file="${2}"
  local key="${3}"
  local expected
  local actual

  expected="$(read_fact "${file}" "${key}")"
  case "${expected}" in
    '' | unavailable | not-produced | not-measured | not-a-deliverable | \
    not-found | unknown)
      return 0
      ;;
  esac

  actual="$(sha256sum "${artifact}" | awk '{ print $1 }')"
  if [ "${actual}" != "${expected}" ]; then
    printf '%s does not match the sha256 in %s (%s, expected %s)\n' \
      "${artifact}" "${file}" "${actual}" "${expected}"
    return 1
  fi
  return 0
}

# The first of an environment override, a summary-file fact, and a default
# that names an existing readable file. Prints nothing when none of them
# does, which every caller treats as "not built yet".
#
#   $1  the override value, possibly empty
#   $2  the summary file to consult
#   $3  the key in that file
#   $4  the fallback path
first_existing_artifact() {
  local override="${1}"
  local file="${2}"
  local key="${3}"
  local fallback="${4}"
  local candidate
  local digest_complaint

  if [ -n "${override}" ]; then
    # An explicit override is used even when it does not exist, so that a
    # typo in it is reported as a missing file the caller named rather than
    # being silently replaced by something else.
    printf '%s\n' "${override}"
    return 0
  fi

  # A summary that does not record a successful producing run is not consulted
  # at all. Its facts are exactly as trustworthy as the run that wrote them,
  # and a path out of a failed run is how this gate ends up inspecting bytes
  # nobody built.
  case "${file}" in
    "${RUST_FACTS}")
      if [ "${RUST_FACTS_TRUST}" != 'trusted' ]; then
        candidate=''
      else
        candidate="$(read_fact "${file}" "${key}")"
      fi
      ;;
    "${REFERENCE_FACTS}")
      if [ "${REFERENCE_FACTS_TRUST}" != 'trusted' ]; then
        candidate=''
      else
        candidate="$(read_fact "${file}" "${key}")"
      fi
      ;;
    *)
      candidate="$(read_fact "${file}" "${key}")"
      ;;
  esac

  # build-rust.sh writes the literal not-produced, not-measured and
  # not-a-deliverable for artifacts a configuration deliberately does not
  # have. Those are facts, not paths, and must not be treated as filenames.
  case "${candidate}" in
    ''|not-produced|not-measured|not-a-deliverable|not-found|unknown)
      candidate=''
      ;;
  esac
  if [ -n "${candidate}" ] && [ -r "${candidate}" ]; then
    # The bytes must be the bytes that run recorded. build-rust.sh writes an
    # sha256 beside every artifact path it publishes, so a file that has been
    # replaced since -- by a later partial run, by a hand-edit, by a build in a
    # different configuration -- is refused here rather than inspected and
    # certified. A path with no recorded digest passes: an override the caller
    # named by hand has none and must not be refused for lacking one.
    if ! digest_complaint="$(artifact_matches_digest "${candidate}" \
         "${file}" "${key}-sha256")"; then
      warn "${digest_complaint}"
      warn "refusing to inspect it. Rerun the build that produced it so that \
the recorded digest and the file agree"
      return 0
    fi
    printf '%s\n' "${candidate}"
    return 0
  fi

  if [ -n "${fallback}" ] && [ -r "${fallback}" ]; then
    printf '%s\n' "${fallback}"
    return 0
  fi

  return 0
}

# ------------------------------------------------------------------------
# Symbol extraction
# ------------------------------------------------------------------------

# The defined global symbols of an object, archive or shared library, one per
# line, C-sorted and de-duplicated, written to the named file.
#
#   $1  the file to inspect
#   $2  where to write the list
#   $3  optional, the string 'dynamic' to read the dynamic symbol table
nm_defined() {
  local object="${1}"
  local out="${2}"
  local mode="${3:-static}"
  local raw="${out}.nm"
  local err="${out}.err"
  local -a nm_command=(nm -g --defined-only -P)

  if [ "${mode}" = 'dynamic' ]; then
    # A cdylib exposes symbols the way an executable does, so its dynamic
    # symbol table holds only the #[no_mangle] extern "C" items. Reading it
    # is therefore an independent confirmation that nothing was exported by
    # accident, arrived at through a different mechanism than the archive
    # check rather than by repeating it.
    nm_command+=(--dynamic)
  fi

  : > "${out}"
  if ! "${nm_command[@]}" "${object}" > "${raw}" 2> "${err}"; then
    warn "nm could not read ${object}: $(tr '\n' ' ' < "${err}")"
    return 1
  fi

  # -P is the POSIX output format, "name type value size", so the symbol name
  # is field one whatever the address width. build-reference.sh reads it the
  # same way and for the same reason.
  #
  # Two kinds of line are dropped. A line ending in a colon is nm's archive
  # member header, "path/to/lib.a[member.o]:", which carries no symbol; a C
  # identifier can never end in a colon, so the test cannot misfire. A line
  # with fewer than three fields is an undefined symbol, "name U", which
  # --defined-only has already excluded and which is excluded again here
  # because the cost is nothing.
  #
  # LC_ALL=C is not decoration. Every comparison below is between sorted
  # lists, and only in the C locale do the Curl_-prefixed names sort ahead of
  # the curl_-prefixed ones. Under a locale that folds case the two sides
  # would be ordered differently and comm would report differences that are
  # not there.
  awk '/:$/ { next } NF >= 3 { print $1 }' "${raw}" |
    LC_ALL=C sort -u > "${out}"
  return 0
}

# Write the named symbols to a file, C-sorted, so that an expected set built
# from an array can be compared with comm.
write_symbol_list() {
  local out="${1}"
  shift

  : > "${out}"
  if [ "$#" -eq 0 ]; then
    return 0
  fi
  printf '%s\n' "$@" | LC_ALL=C sort -u > "${out}"
}

# Restrict a symbol list to the names that could possibly matter to a C
# consumer of this crate.
#
# WHY THIS FILTER EXISTS, so that nobody later mistakes it for hiding a
# problem: Cargo's staticlib carries the entire Rust standard library inside
# the same archive, which is thousands of defined globals rather than eight --
# core, alloc, std, the panic machinery, the compiler builtins -- none of
# which is part of any contract with C, and every one of which would show up
# as "unexpectedly exported" against a set of eight. The exact number is
# deliberately not written here: it moves with the toolchain, so a literal
# would go stale silently. build.rs measures it per build and records it in the
# provenance file beside the canonical archive.
#
# The filter keeps three things: every name in the expected set, every name
# in the forbidden set, and every name in the curl_ and Curl_ namespaces.
# That last clause is the important one. It is what makes the filter safe:
# the namespace where a collision with libcurl could actually matter is
# exactly the one the filter never removes from, so no collision can hide
# behind it. A Rust standard library symbol cannot be spelled curl_something
# and therefore cannot slip through in the other direction either.
#
# The canonical drop-in archive is not filtered at all -- it has already been
# reduced to the ABI by objcopy, so filtering it would be the thing that
# hides a defect.
rust_exports() {
  local input="${1}"
  local out="${2}"
  local keep="${SCRATCH}/relevant-names.txt"

  write_symbol_list "${keep}" \
    "${EXPECTED_SYMBOLS[@]}" "${FORBIDDEN_SYMBOLS[@]}"

  awk -v keepfile="${keep}" '
    BEGIN {
      while((getline name < keepfile) > 0) {
        keep[name] = 1
      }
    }
    /^curl_/ || /^Curl_/ { print; next }
    ($0 in keep) { print }
  ' "${input}" | LC_ALL=C sort -u > "${out}"
}

# Compare two symbol lists for equality and report both directions.
#
#   $1  the check name, used in the verdict line
#   $2  a tag, used to name the difference files inside the scratch tree
#   $3  the file holding the required set
#   $4  the file holding the observed set
#
# Returns 0 on equality. Never calls pass() or fail() itself: some callers
# add further conditions before deciding.
compare_symbol_sets() {
  local name="${1}"
  local tag="${2}"
  local required="${3}"
  local observed="${4}"
  local missing="${SCRATCH}/${tag}-missing.txt"
  local extra="${SCRATCH}/${tag}-extra.txt"
  local symbol
  local status=0

  # comm needs both inputs sorted the same way, which nm_defined and
  # write_symbol_list both guarantee by sorting under LC_ALL=C, and comm
  # itself is run under LC_ALL=C so that its own idea of order agrees.
  LC_ALL=C comm -23 "${required}" "${observed}" > "${missing}"
  LC_ALL=C comm -13 "${required}" "${observed}" > "${extra}"

  if [ -s "${missing}" ]; then
    status=1
    say "  ${name}: missing from the Rust archive --"
    while read -r symbol; do
      if [ -z "${symbol}" ]; then
        continue
      fi
      say "      ${symbol}    an undefined reference at link time"
    done < "${missing}"
  fi

  if [ -s "${extra}" ]; then
    status=1
    say "  ${name}: unexpectedly exported by the Rust archive --"
    while read -r symbol; do
      if [ -z "${symbol}" ]; then
        continue
      fi
      say "      ${symbol}    $(forbidden_reason "${symbol}")"
    done < "${extra}"
  fi

  return "${status}"
}

# Print the two symbol lists next to each other, on success as well as on
# failure, so that a passing transcript is itself the evidence for the pass
# rather than an assertion about it.
#
# The rows are the UNION of the two lists, with a column per side saying
# whether that side carries the name. Two lists printed in parallel columns
# would go out of step at the first difference and then misalign every row
# after it, which is exactly the situation a reader most needs the table to be
# readable in.
side_by_side() {
  local left_label="${1}"
  local right_label="${2}"
  local left="${3}"
  local right="${4}"
  local rule

  # A rule as wide as the label rather than a fixed run of dashes, so the
  # table still lines up whatever the artifact is called.
  rule="$(printf '%*s' "${#right_label}" '' | tr ' ' '-')"
  printf '    %-24s  %-10s  %s\n' 'symbol' "${left_label}" "${right_label}"
  printf '    %-24s  %-10s  %s\n' '------------------------' \
    '----------' "${rule}"

  LC_ALL=C sort -u "${left}" "${right}" |
    awk -v lfile="${left}" -v rfile="${right}" '
      BEGIN {
        while((getline name < lfile) > 0) { left[name] = 1 }
        while((getline name < rfile) > 0) { right[name] = 1 }
      }
      {
        printf "    %-24s  %-10s  %s\n", $0, \
          (($0 in left) ? "yes" : "NO"), (($0 in right) ? "yes" : "NO")
      }
    '
}

# ------------------------------------------------------------------------
# Prerequisites
#
# Every missing tool is reported, then the run stops. Reporting the first one
# and exiting makes a caller with three missing packages install them one run
# at a time, which is three times the work for no extra information.
# ------------------------------------------------------------------------

step 'Prerequisites'

MISSING=()

# command -v, never which: .github/scripts/shellcheck.sh enables
# deprecate-which, and command -v is a shell builtin that needs nothing
# installed in order to answer.
#
# The claim this table makes is that it is COMPLETE, and the claim is meant
# literally: it was built by extracting every command position from this file
# rather than by recollection, because a table that is merely nearly complete
# produces the failure it exists to prevent -- a missing tool discovered in the
# middle of a comparison rather than here.
#
# Two commands necessarily escape it, and both are named rather than left as
# silent gaps: mkdir and rm ran a moment ago, creating and clearing the output
# root, and are listed anyway; and git is deliberately NOT required, being
# consulted by neither this script nor its consumers here -- the source
# revision it compares comes out of the two summary files rather than from git.
#
# uname is required rather than optional even though only the compile fallback
# reads it, because it costs nothing to check and a caller who reaches that
# fallback has already had one thing go wrong.
#
# Shell builtins are absent by definition: printf, cd, pwd, read, command,
# trap, umask and the pattern-matching constructs need nothing installed.
REQUIRED_TOOLS=(
  'nm:binutils'
  'ar:binutils'
  'awk:mawk or gawk'
  'sed:sed'
  'sort:coreutils'
  'comm:coreutils'
  'cat:coreutils'
  'cp:coreutils'
  'dirname:coreutils'
  'mkdir:coreutils'
  'mv:coreutils'
  'rm:coreutils'
  'sha256sum:coreutils'
  'tail:coreutils'
  'tr:coreutils'
  'uname:coreutils'
  'wc:coreutils'
  'mktemp:coreutils'
  'find:findutils'
  'grep:grep'
)

for entry in "${REQUIRED_TOOLS[@]}"; do
  tool="${entry%%:*}"
  package="${entry#*:}"
  if ! command -v "${tool}" > /dev/null 2>&1; then
    MISSING+=("tool ${tool} -- install the ${package} package")
  fi
done

# The C compiler is a prerequisite of the compile fallback and of nothing
# else, so it is only required when that fallback has been asked for.
if [ "${ALLOW_COMPILE_FALLBACK}" = '1' ] &&
   ! command -v "${CC_BIN}" > /dev/null 2>&1; then
  MISSING+=("C compiler ${CC_BIN} -- needed by --allow-compile-fallback; \
set CC to name a different one")
fi

if [ "${#MISSING[@]}" -gt 0 ]; then
  for entry in "${MISSING[@]}"; do
    printf 'check-abi.sh: missing prerequisite: %s\n' "${entry}" >&2
  done
  die "${#MISSING[@]} prerequisite(s) missing, listed above"
fi

note "${#REQUIRED_TOOLS[@]} required tools present"

# ------------------------------------------------------------------------
# Scratch space and cleanup
#
# Everything this script creates goes either into the scratch directory or
# into build/. Nothing is written anywhere else in the repository, which is
# acceptance criterion A12, and the scratch directory is removed on every
# exit path including a failure.
# ------------------------------------------------------------------------

mkdir -p "${BUILD}"
fresh_path "${SUMMARY}"

# Declared before the trap is installed so that the trap can never read an
# unset variable under set -u. That is not a stylistic preference: a handler
# that fails leaves no verdict at all, which is the one outcome this
# arrangement exists to make impossible.
SCRATCH=''
SUMMARY_INPROGRESS=''
RESULT='fail'

# A run that stops part-way through must not leave a summary file that reads
# like a finished one, because run-parity.sh has no other way to tell. Every
# exit from here on records a verdict.
#
# The scratch tree is removed on a pass and KEPT on a failure. That asymmetry
# is deliberate: the symbol lists and the two difference files are the
# evidence for a failure, and several diagnostics name them, so deleting them
# on the way out would leave a reader with a path that no longer resolves.
# KEEP_SCRATCH=1 keeps it either way, KEEP_SCRATCH=0 removes it either way.
KEEP_SCRATCH="${KEEP_SCRATCH:-}"

finish() {
  local status=$?
  local keep="${KEEP_SCRATCH}"

  if [ -z "${keep}" ]; then
    if [ "${RESULT}" = 'pass' ]; then
      keep=0
    else
      keep=1
    fi
  fi

  if [ -n "${SCRATCH}" ] && [ -d "${SCRATCH}" ]; then
    if [ "${keep}" = '1' ]; then
      printf 'check-abi.sh: the symbol lists were kept in %s\n' \
        "${SCRATCH}" >&2
    else
      # The :? guard makes an empty variable stop the removal rather than
      # widen it, and the path is always one this script created with mktemp.
      rm -rf "${SCRATCH:?}"
    fi
  fi
  publish_summary "${RESULT}" || true
  if [ -n "${SUMMARY_INPROGRESS}" ]; then
    rm -f -- "${SUMMARY_INPROGRESS}"
  fi
  return "${status}"
}
trap 'finish' EXIT

# Preferred inside build/, so that a caller inspecting a failure finds the
# lists beside everything else the workflow produced, with the system
# temporary directory as the fallback for a read-only or absent build tree.
SCRATCH="$(mktemp -d "${BUILD}/check-abi.XXXXXX" 2> /dev/null || mktemp -d)"
note "scratch: ${SCRATCH}"

# ------------------------------------------------------------------------
# The summary file
#
# One fact per line, in the same shape build-rust.sh uses, so that
# run-parity.sh can read this file with the reader it already has -- and with
# the same three guarantees, for the same reasons.
# ------------------------------------------------------------------------

# Facts accumulate here and the published path is only ever REPLACED, never
# appended to.
if ! SUMMARY_INPROGRESS="$(mktemp "${BUILD}/abi-check-summary.txt.XXXXXX")"
then
  die "could not create a temporary summary file in ${BUILD}"
fi

printf '%s\n' \
  '# curl-urlapi-rs ABI gate summary. DATA, NOT SHELL: the keys contain' \
  '# dashes and are therefore not valid shell identifiers, so this file' \
  '# cannot be sourced. Parse it with sed, the way run-parity.sh does.' \
  '# Do not act on it unless result=pass.' \
  > "${SUMMARY_INPROGRESS}"

# Append one fact, having first established that both halves are fit to be
# written.
#
#   the key must be lowercase letters, digits and dashes. A dash is not allowed
#   in a shell identifier, so a file of these keys cannot be sourced by
#   anything -- which is the point;
#
#   the value must contain no control byte. A newline would let one value forge
#   a second key on the following line, which is the whole injection; a
#   carriage return would leave an invisible trailing byte in the value
#   run-parity.sh reads back. This matters more here than anywhere else,
#   because several values are symbol lists and artifact paths that arrived
#   from another summary file or from an environment override;
#
#   the key must not have been written already, because a consumer taking the
#   last occurrence would silently read the second one.
SUMMARY_KEYS=' '
summary() {
  local key="${1}"
  local value="${2}"

  case "${key}" in
    '' | *[!a-z0-9-]* | [!a-z]*)
      die "summary: refusing the key '${key}'. Summary keys are lowercase \
letters, digits and dashes, starting with a letter, deliberately: a dash \
makes the key invalid as a shell identifier, which is what keeps this file \
from ever being sourceable"
      ;;
  esac

  case "${SUMMARY_KEYS}" in
    *" ${key} "*)
      die "summary: the key '${key}' has already been written. A duplicate \
key is a programming error here: a consumer that takes the last occurrence \
would read the wrong one of the two"
      ;;
  esac

  case "${value}" in
    *[[:cntrl:]]*)
      die "summary: refusing the value of '${key}' because it contains a \
control character. A newline in a value forges a key on the next line, a \
carriage return leaves an invisible byte in what run-parity.sh reads back, \
and no legitimate value here -- a path, a symbol list, a verdict, a count -- \
contains either"
      ;;
  esac

  SUMMARY_KEYS="${SUMMARY_KEYS}${key} "
  printf '%s=%s\n' "${key}" "${value}" >> "${SUMMARY_INPROGRESS}"
}

# Replaces the published summary with the in-progress file plus one verdict
# line, atomically.
#
# Atomic matters because run-parity.sh can legitimately be started while this
# script is still running, and rename() is the only way to guarantee it reads
# either the whole old file or the whole new one.
#
#   $1  the verdict to record
publish_summary() {
  local verdict="${1}"
  local staged

  if [ -z "${SUMMARY_INPROGRESS}" ] || [ ! -f "${SUMMARY_INPROGRESS}" ]; then
    return 0
  fi

  if ! staged="$(mktemp "${BUILD}/abi-check-summary.txt.XXXXXX")"; then
    warn "could not stage the summary file, so ${SUMMARY} was left alone"
    return 1
  fi

  cat "${SUMMARY_INPROGRESS}" > "${staged}"
  printf 'result=%s\n' "${verdict}" >> "${staged}"
  if ! mv -f -- "${staged}" "${SUMMARY}"; then
    rm -f -- "${staged}"
    warn "could not publish the summary to ${SUMMARY}"
    return 1
  fi
  return 0
}

summary 'schema' 'curl-urlapi-rs/check-abi/1'
summary 'generated-by' 'rust-urlapi/scripts/check-abi.sh'

# Published the moment those two literal keys are in place, and no later.
# Everything after this line can fail, and each of those failures has to leave
# a file that says so rather than the previous run's verdict.
publish_summary 'in-progress' || true

summary 'generated-at' "${EPOCHSECONDS:-0}"
summary 'crate-root' "${CRATE_DIR}"
summary 'build-root' "${BUILD}"
summary 'strict' "${STRICT}"
summary 'allow-partial' "${ALLOW_PARTIAL}"

# ------------------------------------------------------------------------
# The C side: the oracle
#
# The object built from lib/urlapi.c is what the Rust archive has to match.
# The module has exactly two build references anywhere in curl -- its source
# at lib/Makefile.inc:267 and its internal header at its 394 -- so there is
# no other place a definitive list of its exports could come from.
# ------------------------------------------------------------------------

step 'The C side'

# Whether each summary file may be consulted at all. Established once, here,
# rather than at each read: a file that records a failed run has to be refused
# as a whole, because the individual facts inside it are exactly as
# untrustworthy as the run that wrote them.
REFERENCE_FACTS_TRUST='untrusted'
REFERENCE_FACTS_WHY="$(summary_is_trustworthy "${REFERENCE_FACTS}" \
  'curl-urlapi-rs/build-reference/1' \
  'rust-urlapi/scripts/build-reference.sh')" && \
  REFERENCE_FACTS_TRUST='trusted'

RUST_FACTS_TRUST='untrusted'
RUST_FACTS_WHY="$(summary_is_trustworthy "${RUST_FACTS}" \
  'curl-urlapi-rs/build-rust/1' \
  'rust-urlapi/scripts/build-rust.sh')" && RUST_FACTS_TRUST='trusted'

if [ "${REFERENCE_FACTS_TRUST}" = 'trusted' ]; then
  note "reference summary: ${REFERENCE_FACTS} (result=pass)"
else
  note "reference summary: not usable -- ${REFERENCE_FACTS_WHY}"
fi
if [ "${RUST_FACTS_TRUST}" = 'trusted' ]; then
  note "Rust summary:      ${RUST_FACTS} (result=pass)"
else
  note "Rust summary:      not usable -- ${RUST_FACTS_WHY}"
fi

summary 'reference-facts' "${REFERENCE_FACTS}"
summary 'reference-facts-trust' "${REFERENCE_FACTS_TRUST}"
summary 'rust-facts' "${RUST_FACTS}"
summary 'rust-facts-trust' "${RUST_FACTS_TRUST}"

# In the default mode BOTH summaries must be trustworthy, and this is where
# that is enforced.
#
# The reasoning follows from what the two modes are for. In the default mode
# this script is a gate on a workflow: its job is to certify that the artifacts
# THAT WORKFLOW produced export the right surface, and it cannot certify
# anything of the sort about files whose provenance it is unable to establish.
# Falling back to a conventional path and inspecting whatever is there produces
# the worst possible outcome -- a confident pass over bytes nobody in this run
# built -- which is precisely the failure mode this check exists to close.
#
# Under --allow-partial the script is a by-hand instrument instead. Then a
# missing or failed summary is a fact to work around rather than a fault, the
# conventional locations and the environment overrides are honoured, and every
# resulting verdict is qualified in the closing summary.
if [ "${ALLOW_PARTIAL}" != '1' ]; then
  if [ "${REFERENCE_FACTS_TRUST}" != 'trusted' ]; then
    die "the reference summary cannot be trusted: ${REFERENCE_FACTS_WHY}. \
Every verdict below would be a comparison against an oracle whose provenance \
this script cannot establish, so it refuses to produce one. Run \
scripts/build-reference.sh, which builds libcurl out of tree from the \
unmodified repository and records what it built. To inspect artifacts by hand \
instead, pass --allow-partial and read the qualified verdict it prints"
  fi
  if [ "${RUST_FACTS_TRUST}" != 'trusted' ]; then
    die "the Rust build summary cannot be trusted: ${RUST_FACTS_WHY}. The \
archives this script would otherwise inspect have no established provenance \
-- the scratch tree is reusable, so a file at the conventional path may be \
from any earlier run in any configuration -- and certifying those would be \
worse than not checking at all. Run scripts/build-rust.sh, which builds both \
configurations and records an sha256 for each artifact. To inspect artifacts \
by hand instead, pass --allow-partial"
  fi
fi

# One checkout, or two? Both producers record the commit they built from, so a
# disagreement means an oracle from one revision is about to be compared with
# an archive from another -- a comparison whose result describes neither.
# Refused rather than warned about, because the whole value of this gate is
# that a mismatch it reports is a real one.
#
# Either side recording "unknown" is the exported-tree case, where there is no
# git to ask. That is reported and allowed: a check that cannot be made is not
# the same as a check that failed, and the summary records which it was so that
# a reader is never left to assume.
REVISION_STATE='not-compared'
if [ "${REFERENCE_FACTS_TRUST}" = 'trusted' ] &&
   [ "${RUST_FACTS_TRUST}" = 'trusted' ]; then
  REFERENCE_REVISION="$(read_fact "${REFERENCE_FACTS}" 'source-revision')"
  RUST_REVISION="$(read_fact "${RUST_FACTS}" 'source-revision')"
  if [ "${REFERENCE_REVISION}" = 'unknown' ] ||
     [ "${RUST_REVISION}" = 'unknown' ] ||
     [ -z "${REFERENCE_REVISION}" ] || [ -z "${RUST_REVISION}" ]; then
    REVISION_STATE='unknown'
    note 'source revision: not recorded by one of the two builds, so the two'
    note '                 could not be confirmed to come from one checkout'
  elif [ "${REFERENCE_REVISION}" = "${RUST_REVISION}" ]; then
    REVISION_STATE='agree'
    note "source revision:   ${REFERENCE_REVISION} (both builds)"
  else
    REVISION_STATE='disagree'
    summary 'source-revision-state' "${REVISION_STATE}"
    die "the reference build was made from ${REFERENCE_REVISION} and the Rust \
build from ${RUST_REVISION}. Comparing a symbol set from one checkout against \
an oracle from another describes neither: rebuild both from the same tree. \
scripts/build-reference.sh followed by scripts/build-rust.sh does that"
  fi
fi
summary 'source-revision-state' "${REVISION_STATE}"

# The already-extracted object, when scripts/build-reference.sh produced one.
# Preferring it is not a shortcut: that script extracted the member from the
# archive it certified and asserted the eight-symbol contract against it, so
# consuming its result is what keeps the two scripts from disagreeing about
# which object is the oracle.
REFERENCE_URLAPI_OBJECT="${REFERENCE_URLAPI_OBJECT:-}"
REFERENCE_ARCHIVE="${REFERENCE_ARCHIVE:-}"
REFERENCE_MEMBER=''
REFERENCE_SOURCE=''
digest_complaint=''

# Read from the summary only when the summary may be consulted. The keys are
# the lowercase-dashed names build-reference.sh writes.
if [ "${REFERENCE_FACTS_TRUST}" = 'trusted' ]; then
  if [ -z "${REFERENCE_URLAPI_OBJECT}" ]; then
    REFERENCE_URLAPI_OBJECT="$(read_fact "${REFERENCE_FACTS}" \
      'reference-urlapi-object')"

    # And the bytes at that path must be the bytes that run recorded. This is
    # the oracle: every verdict below is a comparison against its symbol table,
    # so an object that has been replaced since would make the whole run
    # describe something nobody built. Refused rather than inspected.
    if [ -n "${REFERENCE_URLAPI_OBJECT}" ] &&
       [ -r "${REFERENCE_URLAPI_OBJECT}" ]; then
      if ! digest_complaint="$(artifact_matches_digest \
           "${REFERENCE_URLAPI_OBJECT}" "${REFERENCE_FACTS}" \
           'reference-urlapi-object-sha256')"; then
        warn "${digest_complaint}"
        die "the oracle object does not match the digest \
${REFERENCE_FACTS} recorded for it, so it is not the object that run \
extracted. Every verdict this script produces is a comparison against its \
symbol table, so nothing here would mean anything. Rerun \
scripts/build-reference.sh"
      fi
    fi
  fi
  if [ -z "${REFERENCE_ARCHIVE}" ]; then
    REFERENCE_ARCHIVE="$(read_fact "${REFERENCE_FACTS}" 'reference-archive')"

    # The archive is used by the collision pre-check, which asks what the mode
    # A link would resolve. Same reasoning, same refusal.
    if [ -n "${REFERENCE_ARCHIVE}" ] && [ -r "${REFERENCE_ARCHIVE}" ]; then
      if ! digest_complaint="$(artifact_matches_digest \
           "${REFERENCE_ARCHIVE}" "${REFERENCE_FACTS}" \
           'reference-archive-sha256')"; then
        warn "${digest_complaint}"
        die "the reference archive does not match the digest \
${REFERENCE_FACTS} recorded for it. The collision pre-check asks what the \
mode A link would resolve, and an archive nobody in this workflow built \
cannot answer that. Rerun scripts/build-reference.sh"
      fi
    fi
  fi
fi

# Whether the Rust build used the two configurations acceptance criteria A1 and
# A2 name. The symbol sets compared below -- eight in mode A, ten in mode B --
# are the sets those two configurations produce; a build with a different IDN
# backend or an extra feature is a different contract, and comparing it against
# these numbers tests the wrong thing.
#
# Refused by default, permitted under --allow-partial with the consequence
# stated, because somebody deliberately checking a non-canonical configuration
# is a legitimate thing to be doing and the gate should say what it is looking
# at rather than pretend.
CANONICAL_STATE='not-recorded'
if [ "${RUST_FACTS_TRUST}" = 'trusted' ]; then
  CANONICAL_STATE="$(read_fact "${RUST_FACTS}" 'canonical-configurations')"
  case "${CANONICAL_STATE}" in
    yes)
      note 'Rust configurations: the two canonical ones A1 and A2 name'
      ;;
    *)
      if [ "${ALLOW_PARTIAL}" = '1' ]; then
        warn "${RUST_FACTS} records canonical-configurations=\
${CANONICAL_STATE:-none}, so the archives below were not built in the two \
configurations acceptance criteria A1 and A2 name. --allow-partial permits \
that; the eight and ten symbol counts checked here are the counts those two \
configurations produce, so a disagreement may be the configuration rather \
than the port"
      else
        summary 'canonical-configurations' "${CANONICAL_STATE:-none}"
        die "${RUST_FACTS} records canonical-configurations=\
${CANONICAL_STATE:-none}. The symbol sets this script compares -- eight in \
mode A, ten in mode B -- are the sets the two canonical configurations \
produce, so comparing a build made with another IDN backend or an extra \
feature against them tests the wrong contract. Run scripts/build-rust.sh \
with no --idn-backend and no --features, or pass --allow-partial to check a \
non-canonical build deliberately"
      fi
      ;;
  esac
fi
summary 'canonical-configurations' "${CANONICAL_STATE:-none}"

# The archive, when neither an override nor the summary file named a readable
# one. Searched for rather than assumed: the CMake build puts it at
# build/reference/lib/libcurl.a, but a caller who set STATIC_LIB_SUFFIX, or
# who pointed REFERENCE_BUILD_DIR somewhere else, would move it, and a
# hard-coded path would then fail with a diagnostic about the wrong thing.
#
# The archive that matters is the one holding a urlapi member; any other
# libcurl archive under the same tree is not what the drop-in link needs.
if [ -z "${REFERENCE_ARCHIVE}" ] || [ ! -r "${REFERENCE_ARCHIVE}" ]; then
  REFERENCE_ARCHIVE=''
  if [ -d "${BUILD}" ]; then
    while read -r candidate; do
      if [ -z "${candidate}" ]; then
        continue
      fi
      if ar t "${candidate}" 2> /dev/null |
         grep -q -E '^(lib.*_la-)?urlapi(\.c)?\.o$'; then
        REFERENCE_ARCHIVE="${candidate}"
        break
      fi
    done <<< "$(find "${BUILD}" -name 'libcurl*.a' -type f 2> /dev/null |
                LC_ALL=C sort)"
  fi
fi

# The member name is DISCOVERED, never hard-coded, because the spelling
# depends on the build system that produced the archive. CMake assembles the
# archive from the libcurl_object OBJECT library (lib/CMakeLists.txt:102 and
# its 140) and names each member after its source file, giving urlapi.c.o,
# whereas an autotools build gives urlapi.o and a libtool one
# libcurl_la-urlapi.o. Exactly one match is required, and both zero and
# several are reported with the full candidate list, because either means the
# archive is not the archive this script thinks it is.
discover_member() {
  local archive="${1}"
  local members="${SCRATCH}/archive-members.txt"
  local matches="${SCRATCH}/archive-urlapi-members.txt"
  local count

  if ! ar t "${archive}" > "${members}" 2> "${SCRATCH}/ar-t.err"; then
    die "ar could not list ${archive}: \
$(tr '\n' ' ' < "${SCRATCH}/ar-t.err")"
  fi

  # The pattern is deliberately wider than the anchored one used to find the
  # archive: a member whose name merely contains urlapi is still a candidate
  # worth reporting, and reporting it is the whole value of this function.
  #
  # It is wider in one direction only. A candidate must still be a BARE FILE
  # NAME: letters, digits, dot, underscore, plus and dash, with no slash and no
  # dot-dot anywhere in it. That is not decoration. The name discovered here
  # was previously handed straight to "ar x", which writes into the current
  # directory using the member name as a relative path -- so a member called
  # ../../lib/urlapi.c, in an archive an environment override pointed this
  # script at, would have been extracted OUTSIDE the scratch directory and over
  # a pre-existing file. The anchored pattern refuses that shape outright, and
  # the extraction below no longer uses the name as a path at all.
  grep -E '^[A-Za-z0-9._+-]*urlapi[A-Za-z0-9._+-]*$' "${members}" \
    > "${matches}" || true
  count="$(wc -l < "${matches}" | tr -d ' ')"

  # A name that contains urlapi but is not a bare file name is reported rather
  # than silently dropped, because "no member matched" and "a member matched
  # and was refused" want different reactions from a reader.
  if [ "${count}" -eq 0 ] && grep -q -E 'urlapi' "${members}"; then
    printf 'check-abi.sh: %s\n' \
      "members of ${archive} contain urlapi but none is a bare file name:" >&2
    grep -E 'urlapi' "${members}" | sed 's/^/  /' >&2
    die "a member name with a slash or a dot-dot in it is refused rather than \
extracted: ar uses the member name as a relative path, so such a name would \
write outside the scratch directory. A libcurl archive built from \
lib/Makefile.inc:267 names its members after their source files, giving \
urlapi.c.o, urlapi.o or libcurl_la-urlapi.o, none of which has either"
  fi

  if [ "${count}" -ne 1 ]; then
    printf 'check-abi.sh: %s members of %s match urlapi:\n' \
      "${count}" "${archive}" >&2
    if [ "${count}" -eq 0 ]; then
      printf '  (none)\n' >&2
    else
      sed 's/^/  /' "${matches}" >&2
    fi
    printf 'check-abi.sh: the %s members of that archive are in %s\n' \
      "$(wc -l < "${members}" | tr -d ' ')" "${members}" >&2
    die "exactly one urlapi member is required and ${count} were found. \
CMake names the member urlapi.c.o, autotools urlapi.o and libtool \
libcurl_la-urlapi.o; none of those spellings is assumed here, so a count \
other than one means this is not a libcurl archive built from \
lib/Makefile.inc:267"
  fi

  cat "${matches}"
}

# Compile lib/urlapi.c directly. The fallback, and opt-in for a reason that
# is printed rather than left implicit.
compile_reference_object() {
  local object="${1}"
  local config_dir=''
  local candidate
  local log="${SCRATCH}/compile-reference.log"

  say ''
  say '  Using the compile fallback. The archive route is better and this is'
  say '  why: extracting the member certifies the exact object a real'
  say '  libcurl link would consume, built with the preprocessor state that'
  say '  build produced. Compiling here certifies an object assembled from a'
  say '  curl_config.h found on disk and an include path guessed from the'
  say '  source layout, so a configuration difference between that state and'
  say '  the real one is invisible and would be attributed to the port.'
  say ''

  # lib/urlapi.c includes curl_setup.h, which needs a generated
  # curl_config.h when HAVE_CONFIG_H is defined. It is searched for rather
  # than generated, because generating one means configuring libcurl, which
  # is what scripts/build-reference.sh is for.
  if [ -n "${CURL_CONFIG_H:-}" ]; then
    config_dir="$(dirname "${CURL_CONFIG_H}")"
  else
    while read -r candidate; do
      if [ -n "${candidate}" ]; then
        config_dir="$(dirname "${candidate}")"
        break
      fi
    done <<< "$(find "${BUILD}" -name 'curl_config.h' -type f 2> /dev/null |
                LC_ALL=C sort)"
  fi

  if [ -z "${config_dir}" ]; then
    die "no curl_config.h was found under ${BUILD} and CURL_CONFIG_H names \
none, so lib/urlapi.c cannot be compiled here. Run \
scripts/build-reference.sh, which configures libcurl and generates one, and \
then this script needs no fallback at all"
  fi
  note "curl_config.h from ${config_dir}"

  # _GNU_SOURCE, on the platforms where curl's own build defines it.
  # CMakeLists.txt:254-256 appends it as a directory-wide compile definition
  # for Cygwin, Linux and GNU, and it is not optional here: with
  # HAVE_MEMRCHR set in curl_config.h, lib/urlapi.c reaches memrchr at its
  # 784 and its 1261, and without the feature macro glibc does not declare
  # it, which a modern compiler treats as an error rather than a warning.
  # Measured: omitting it fails the compile with exactly that diagnostic.
  local -a defines=(-DHAVE_CONFIG_H -DBUILDING_LIBCURL)
  case "$(uname -s 2> /dev/null || printf 'unknown')" in
    Linux|GNU|GNU/*|CYGWIN*)
      defines+=(-D_GNU_SOURCE)
      ;;
  esac

  # An escape hatch for a platform whose reference build needs something else
  # again. It carries several arguments, so it has to be split -- with read -a
  # rather than by leaving the expansion unquoted, which is the same operation
  # done deliberately instead of accidentally and needs no suppression.
  local -a extra=()
  if [ -n "${REFERENCE_FALLBACK_DEFINES:-}" ]; then
    read -r -a extra <<< "${REFERENCE_FALLBACK_DEFINES}"
    defines+=("${extra[@]}")
  fi

  # UNITTESTS is deliberately NOT among them, which is the whole point of the
  # assertion that follows this function.
  #
  # The object is written into the scratch tree. lib/urlapi.c and every other
  # pre-existing file are inputs only -- goal G4 and acceptance criterion
  # A12.
  if ! "${CC_BIN}" -c "${REPO_ROOT}/lib/urlapi.c" -o "${object}" \
       "${defines[@]}" \
       -I"${config_dir}" \
       -I"${REPO_ROOT}/lib" \
       -I"${REPO_ROOT}/include" \
       > "${log}" 2>&1; then
    printf 'check-abi.sh: the compile of lib/urlapi.c failed:\n' >&2
    tail -n 30 "${log}" >&2
    die "could not compile ${REPO_ROOT}/lib/urlapi.c; see ${log}. This is \
the fragility the fallback was described with: run \
scripts/build-reference.sh instead"
  fi
}

C_OBJECT="${SCRATCH}/urlapi-reference.o"

if [ -n "${REFERENCE_URLAPI_OBJECT}" ] && [ -r "${REFERENCE_URLAPI_OBJECT}" ]
then
  C_OBJECT="${REFERENCE_URLAPI_OBJECT}"
  REFERENCE_SOURCE='extracted-by-build-reference'
  REFERENCE_MEMBER="$(read_fact "${REFERENCE_FACTS}" \
    'reference-urlapi-member')"
  note "object:  ${C_OBJECT}"
  note "member:  ${REFERENCE_MEMBER:-not recorded, the object was named \
directly}"
elif [ -n "${REFERENCE_ARCHIVE}" ] && [ -r "${REFERENCE_ARCHIVE}" ]; then
  REFERENCE_SOURCE='archive-member'
  note "archive: ${REFERENCE_ARCHIVE}"
  REFERENCE_MEMBER="$(discover_member "${REFERENCE_ARCHIVE}")"
  note "member:  ${REFERENCE_MEMBER}"

  # ar p, not ar x, and the difference is a safety property rather than a
  # convenience.
  #
  # ar x writes into the CURRENT directory using the MEMBER NAME as a relative
  # path, which is why the old form had to cd into the scratch directory in a
  # subshell first -- and why a member called ../../lib/urlapi.c would have
  # landed outside that directory and over a pre-existing file. ar p writes the
  # member to standard output instead, so THIS script chooses the destination
  # and the member name never reaches the filesystem. The name is also required
  # to be a bare file name by discover_member() above; the two together mean
  # there is no path for a hostile name to travel down.
  #
  # The destination is fixed rather than named after the member, so that
  # everything downstream refers to one path whatever the archive called its
  # member.
  C_OBJECT="${SCRATCH}/urlapi-reference.o"
  fresh_path "${C_OBJECT}"
  if ! ar p "${REFERENCE_ARCHIVE}" "${REFERENCE_MEMBER}" > "${C_OBJECT}"; then
    die "could not read ${REFERENCE_MEMBER} out of ${REFERENCE_ARCHIVE}"
  fi

  if [ ! -s "${C_OBJECT}" ]; then
    die "ar reported success but ${C_OBJECT} is empty, so ${REFERENCE_MEMBER} \
carried no content"
  fi
elif [ "${ALLOW_COMPILE_FALLBACK}" = '1' ]; then
  REFERENCE_SOURCE='compiled-here'
  compile_reference_object "${C_OBJECT}"
  note "object:  ${C_OBJECT} (compiled by this script)"
else
  die "no reference libcurl archive and no extracted urlapi object were \
found under ${BUILD}, and neither REFERENCE_ARCHIVE nor \
REFERENCE_URLAPI_OBJECT names one. Run scripts/build-reference.sh first -- \
it builds libcurl out of tree from the unmodified repository, extracts the \
urlapi member and records both in ${REFERENCE_FACTS}. Failing that, \
--allow-compile-fallback compiles lib/urlapi.c here instead, with the \
caveats that option prints"
fi

C_SYMBOLS="${SCRATCH}/c-symbols.txt"
if ! nm_defined "${C_OBJECT}" "${C_SYMBOLS}"; then
  die "could not read the symbol table of ${C_OBJECT}"
fi

C_COUNT="$(wc -l < "${C_SYMBOLS}" | tr -d ' ')"
note "defined globals: ${C_COUNT}"

# An empty list is the link-time-optimization signature rather than an
# object with no exports: a member built with LTO carries intermediate
# representation instead of a symbol table, and nm reports nothing for it.
# Comparing against an empty oracle would make every Rust archive look wrong
# for a reason that has nothing to do with the port.
if [ "${C_COUNT}" -eq 0 ]; then
  die "${C_OBJECT} defines no global symbols at all. That is what an object \
built with link-time optimization looks like -- the member carries \
intermediate representation and nm has no symbol table to read -- so the \
reference must be rebuilt with it off. scripts/build-reference.sh \
configures the build that way"
fi

# The UNITTESTS assertion, and a genuine trap rather than a formality.
# lib/curl_setup.h:1505-1509 expands UNITTEST to nothing when UNITTESTS is
# defined and to "static" otherwise, and lib/urlapi.c carries two
# UNITTEST-marked definitions: Curl_parse_port at its 335 and dedotdotify at
# its 715-716. A reference built with unit tests enabled therefore defines
# TEN globals, not eight, and set equality would then fail for a reason that
# has nothing to do with the Rust port.
UNITTEST_FOUND=()
for symbol in "${UNITTEST_SYMBOLS[@]}"; do
  if LC_ALL=C grep -q -x -F "${symbol}" "${C_SYMBOLS}"; then
    UNITTEST_FOUND+=("${symbol}")
  fi
done

if [ "${#UNITTEST_FOUND[@]}" -gt 0 ]; then
  for symbol in "${UNITTEST_FOUND[@]}"; do
    printf 'check-abi.sh: the C side defines %s, which is UNITTEST-gated\n' \
      "${symbol}" >&2
  done
  die "the reference object was built with UNITTESTS defined, so it exports \
${#UNITTEST_FOUND[@]} name(s) the drop-in contract does not contain. Rebuild \
the reference with unit tests off: -DENABLE_UNIT_TESTS=OFF for CMake, no \
--enable-unit-tests for configure, and no -DUNITTESTS in CFLAGS. \
scripts/build-reference.sh already configures it that way. Reported \
constraint R2 is the reason this is a misconfiguration rather than \
something to accommodate: tests/unit/unit1653.c calls Curl_parse_port \
directly, handing it a CURLU * together with a struct dynbuf it built \
itself, so satisfying it from Rust would need a ninth exported symbol AND \
bit-compatible interoperation with libcurl's private dynamic-buffer \
structure. Only lib1560 and test1560 are named as success criteria, so that \
test is out of scope and its symbol must not be in the comparison"
fi

# The eight, as the contract. Written out so that comm has a sorted file to
# work with and so that the expected side of every listing below is the same
# file rather than a re-derivation of it.
EXPECTED_LIST="${SCRATCH}/expected-symbols.txt"
write_symbol_list "${EXPECTED_LIST}" "${EXPECTED_SYMBOLS[@]}"

# Self-checks on the encoded contract itself. A gate that can be quietly
# weakened by an edit to its own constants is not a gate, and the way it would
# be weakened is specific: drop a name from EXPECTED_SYMBOLS and every archive
# missing that name starts passing. These three assertions cost nothing and
# close that off.
if [ "${#EXPECTED_SYMBOLS[@]}" -ne 8 ]; then
  die "EXPECTED_SYMBOLS holds ${#EXPECTED_SYMBOLS[@]} names but lib/urlapi.c \
defines exactly eight globals -- Curl_is_absolute_url at its 182, \
Curl_junkscan at its 223, Curl_url_set_authority at its 658, curl_url at its \
1288, curl_url_cleanup at its 1293, curl_url_dup at its 1310, curl_url_get \
at its 1541 and curl_url_set at its 1805. Every other definition in that \
file is static, and the two marked UNITTEST are static too unless UNITTESTS \
is defined. If the C module really did gain or lose an export, this list is \
the right place to change -- but it is a change to the drop-in contract and \
has to be made deliberately"
fi

if [ "$(LC_ALL=C sort -u "${EXPECTED_LIST}" | wc -l | tr -d ' ')" -ne 8 ]; then
  die "EXPECTED_SYMBOLS contains a duplicate: eight entries that reduce to \
fewer than eight distinct names would make the count above pass while the \
comparison silently required less"
fi

for symbol in "${STANDALONE_EXTRA[@]}"; do
  # The two names the standalone configuration adds must be exactly two of
  # the four the drop-in configuration forbids. If they ever diverge, one
  # configuration would be requiring a name the other has no opinion about,
  # and the mirror-image check of mode B would stop being a mirror.
  if ! printf '%s\n' "${FORBIDDEN_SYMBOLS[@]}" |
       LC_ALL=C grep -q -x -F "${symbol}"; then
    die "STANDALONE_EXTRA names ${symbol}, which is not in \
FORBIDDEN_SYMBOLS. The two sets have to agree: a name mode B requires is a \
name mode A must refuse, because the only difference between them is which \
side of the link supplies it"
  fi
  if LC_ALL=C grep -q -x -F "${symbol}" "${EXPECTED_LIST}"; then
    die "STANDALONE_EXTRA names ${symbol}, which is also in \
EXPECTED_SYMBOLS. The eight are the names lib/urlapi.c itself defines; \
curl_url_strerror lives in lib/strerror.c:420-531 and curl_free in \
lib/escape.c:189-192, so neither can be in both sets"
  fi
done

if ! compare_symbol_sets 'the C side against the eight-symbol contract' \
     'c-contract' "${EXPECTED_LIST}" "${C_SYMBOLS}"; then
  die "the C oracle itself does not match the eight globals lib/urlapi.c \
defines, listed with their line numbers at EXPECTED_SYMBOLS above. Either \
the reference was built from a modified lib/urlapi.c or it was configured \
differently from what this script expects; in neither case would comparing \
the Rust archive against it mean anything"
fi
note 'the C side matches the eight-symbol drop-in contract'

# The oracle object is staged out of the scratch tree before it is recorded,
# because the scratch tree does not survive a passing run and a fact naming a
# path that no longer exists is worse than no fact at all. An object that was
# already outside the scratch tree -- the one build-reference.sh extracted, or
# one named by REFERENCE_URLAPI_OBJECT -- is recorded where it already is.
case "${C_OBJECT}" in
  "${SCRATCH}"/*)
    mkdir -p "${BUILD}/abi"
    # Cleared before the copy: the destination is a predictable path, and cp
    # onto an existing symlink writes through it. See fresh_path().
    fresh_path "${BUILD}/abi/urlapi-reference.o"
    if cp "${C_OBJECT}" "${BUILD}/abi/urlapi-reference.o"; then
      C_OBJECT_RECORDED="${BUILD}/abi/urlapi-reference.o"
    else
      warn "could not stage ${C_OBJECT} into ${BUILD}/abi/"
      C_OBJECT_RECORDED="${C_OBJECT}"
    fi
    ;;
  *)
    C_OBJECT_RECORDED="${C_OBJECT}"
    ;;
esac

summary 'reference-source' "${REFERENCE_SOURCE}"
summary 'reference-archive' "${REFERENCE_ARCHIVE:-none}"
summary 'reference-urlapi-member' "${REFERENCE_MEMBER:-unknown}"
summary 'reference-urlapi-object' "${C_OBJECT_RECORDED}"
summary 'reference-symbol-count' "${C_COUNT}"
summary 'reference-symbols' "$(tr '\n' ' ' < "${C_SYMBOLS}" | sed 's/ $//')"
summary 'reference-unittests' 'off'

# ------------------------------------------------------------------------
# The Rust side
# ------------------------------------------------------------------------

# Locate one of the crate's artifacts.
#
#   $1  the environment override, possibly empty
#   $2  the key in build/rust-build-summary.txt
#   $3  the mode tag, a or b
#   $4  the file name inside the staging directory
#
# Three places are tried, in this order: the override, the fact
# scripts/build-rust.sh recorded, and the conventional location. The last one
# matters because it lets this script work against a plain
# "cargo build --release" that never went through build-rust.sh at all, which
# is what somebody debugging a single symbol will actually have on disk.
rust_artifact() {
  local override="${1}"
  local key="${2}"
  local tag="${3}"
  local name="${4}"
  local found

  found="$(first_existing_artifact "${override}" "${RUST_FACTS}" "${key}" \
    "${BUILD}/rust/mode-${tag}/${name}")"
  if [ -n "${found}" ]; then
    printf '%s\n' "${found}"
    return 0
  fi

  # Cargo's own output directory, the last resort -- and only when the caller
  # accepted an unverified inspection. Only Cargo's archive and shared object
  # can ever be there: the canonical drop-in archive is produced by a second,
  # explicitly driven pass, so its absence from target/release is not an
  # oversight.
  #
  # Gated on --allow-partial because a file at this path has no provenance at
  # all: the target tree is reusable and persistent, so it may hold an artifact
  # from any earlier build in any configuration. That is exactly what somebody
  # debugging a single symbol by hand wants to look at, and exactly what a gate
  # must not silently certify.
  if [ "${ALLOW_PARTIAL}" = '1' ] &&
     [ -r "${CRATE_DIR}/target/release/${name}" ]; then
    printf '%s\n' "${CRATE_DIR}/target/release/${name}"
    return 0
  fi

  return 0
}

# Assert one artifact's exported symbol set against a required set.
#
#   $1  the check name for the verdict line
#   $2  a tag for the scratch file names
#   $3  the artifact
#   $4  the file holding the required set
#   $5  'raw' to apply the rust_exports() filter, 'canonical' not to,
#       'dynamic' to read the dynamic symbol table of a shared object
#   $6  the label for the required column of the side-by-side listing
#
# Returns 0 when the artifact's set equals the required set.
check_artifact() {
  local name="${1}"
  local tag="${2}"
  local artifact="${3}"
  local required="${4}"
  local kind="${5}"
  local required_label="${6}"
  local all="${SCRATCH}/${tag}-all.txt"
  local observed="${SCRATCH}/${tag}-observed.txt"
  local nm_mode='static'
  local total
  local count
  local status=0

  if [ "${kind}" = 'dynamic' ]; then
    nm_mode='dynamic'
  fi

  if ! nm_defined "${artifact}" "${all}" "${nm_mode}"; then
    fail "${name}: nm could not read ${artifact}"
    return 1
  fi

  total="$(wc -l < "${all}" | tr -d ' ')"

  if [ "${kind}" = 'raw' ]; then
    rust_exports "${all}" "${observed}"
    count="$(wc -l < "${observed}" | tr -d ' ')"
    note "${artifact}"
    note "  ${total} defined globals, ${count} of them relevant to C"
  else
    cp "${all}" "${observed}"
    count="${total}"
    note "${artifact}"
    note "  ${count} defined globals, compared unfiltered"
  fi

  # An artifact with no exported symbols at all is not a passing artifact
  # even when the required set happens to be empty, and it is worth its own
  # message because the cause -- a link-time-optimized archive, or a build
  # that produced a placeholder -- is different from a symbol mismatch.
  if [ "${count}" -eq 0 ]; then
    fail "${name}: ${artifact} exports nothing at all. An archive built with \
link-time optimization looks exactly like this, because its members carry \
intermediate representation rather than a symbol table"
    return 1
  fi

  if ! compare_symbol_sets "${name}" "${tag}" "${required}" "${observed}"; then
    status=1
  fi

  # Each of the four forbidden names is asserted explicitly, by name, as well
  # as being covered by the set comparison above. The two mechanisms are
  # independent on purpose: this loop reaches its verdict from the observed
  # list alone and does not depend on comm, on the sort order, or on the
  # required list having been assembled correctly, so a fault in any of those
  # cannot make a forbidden export pass unnoticed.
  #
  # It prints only what the extras listing did not already print, because
  # saying the same thing twice about the same symbol buries the second
  # symbol. Redundant reporting, not redundant checking.
  local symbol
  for symbol in "${FORBIDDEN_SYMBOLS[@]}"; do
    if LC_ALL=C grep -q -x -F "${symbol}" "${required}"; then
      # Required in this configuration, so not forbidden in it: mode B
      # requires curl_url_strerror and curl_free.
      continue
    fi
    if LC_ALL=C grep -q -x -F "${symbol}" "${observed}"; then
      status=1
      if ! LC_ALL=C grep -q -x -F "${symbol}" \
           "${SCRATCH}/${tag}-extra.txt"; then
        say "  ${name}: ${symbol} must not be exported here -- \
$(forbidden_reason "${symbol}")"
      fi
    fi
  done

  # Printed on success as well as on failure, so that a passing transcript is
  # the evidence for the pass rather than a claim about it.
  side_by_side "${required_label}" "${artifact##*/}" "${required}" \
    "${observed}"

  if [ "${status}" -eq 0 ]; then
    pass "${name} (${count} symbols, set equality both ways)"
  else
    fail "${name}"
  fi
  return "${status}"
}

step 'Mode A, the drop-in configuration'
say '  Built with --no-default-features --features idn-libidn2. The eight'
say '  globals lib/urlapi.c defines, and not one name more: a real libcurl'
say '  already defines curl_url_strerror (lib/strerror.c:420) and curl_free'
say '  (lib/escape.c:189), so exporting either here would define it twice.'

MODE_A_DROPIN="$(rust_artifact "${MODE_A_DROPIN:-}" 'mode-a-dropin-archive' \
  'a' "${DROPIN}")"
MODE_A_ARCHIVE="$(rust_artifact "${MODE_A_ARCHIVE:-}" 'mode-a-archive' 'a' \
  "${ARCHIVE}")"

if [ -z "${MODE_A_DROPIN}" ] && [ -z "${MODE_A_ARCHIVE}" ]; then
  die "no mode A archive was found. Neither MODE_A_DROPIN nor \
MODE_A_ARCHIVE names one, ${RUST_FACTS} records none, and neither \
${BUILD}/rust/mode-a/ nor ${CRATE_DIR}/target/release/ holds one. Run \
scripts/build-rust.sh, which builds both configurations and runs the drop-in \
localization pass over each archive. Without a mode A archive there is \
nothing to certify: mode A is the configuration that actually demonstrates \
'linkable in place of lib/urlapi.c's object file', because it is the only \
one in which the Rust code has to satisfy real internal callers and coexist \
with libcurl's own free function, formatted-print family, scheme table and \
error-string function"
fi

# The canonical archive first, because it is the artifact a link consumes.
# build.rs manufactures it from Cargo's staticlib with ld -r --whole-archive,
# objcopy --keep-global-symbol for each name of the ABI, and ar rcs, so it is
# expected to contain the ABI exactly and is therefore compared UNFILTERED.
# Filtering it would be the thing that hid a defect.
MODE_A_CANONICAL_VERDICT='skip'
if [ -n "${MODE_A_DROPIN}" ]; then
  if [ ! -r "${MODE_A_DROPIN}" ]; then
    fail "mode A canonical archive: ${MODE_A_DROPIN} cannot be read"
    MODE_A_CANONICAL_VERDICT='fail'
  elif check_artifact 'mode A canonical drop-in archive' 'mode-a-canonical' \
       "${MODE_A_DROPIN}" "${EXPECTED_LIST}" 'canonical' 'C oracle'; then
    MODE_A_CANONICAL_VERDICT='pass'
  else
    MODE_A_CANONICAL_VERDICT='fail'
  fi
else
  skip "mode A canonical drop-in archive: not produced. \
scripts/build-rust.sh --no-dropin skips the localization pass, and without \
its result only Cargo's own staticlib can be checked"
fi

# Cargo's own staticlib, through the filter. Checking it as well as the
# canonical archive is not duplication: the two are different artifacts, and a
# fault in the localization pass itself would show up as a disagreement
# between them rather than in either one alone.
MODE_A_RAW_VERDICT='skip'
if [ -n "${MODE_A_ARCHIVE}" ]; then
  if [ ! -r "${MODE_A_ARCHIVE}" ]; then
    fail "mode A staticlib: ${MODE_A_ARCHIVE} cannot be read"
    MODE_A_RAW_VERDICT='fail'
  elif check_artifact "mode A staticlib, curl_ and Curl_ namespaces" \
       'mode-a-raw' "${MODE_A_ARCHIVE}" "${EXPECTED_LIST}" 'raw' \
       'C oracle'; then
    MODE_A_RAW_VERDICT='pass'
  else
    MODE_A_RAW_VERDICT='fail'
  fi
else
  skip "mode A staticlib: not found"
fi

summary 'mode-a-canonical-archive' "${MODE_A_DROPIN:-none}"
summary 'mode-a-canonical-verdict' "${MODE_A_CANONICAL_VERDICT}"
summary 'mode-a-staticlib' "${MODE_A_ARCHIVE:-none}"
summary 'mode-a-staticlib-verdict' "${MODE_A_RAW_VERDICT}"

# ------------------------------------------------------------------------
# Mode B, the standalone configuration: the same check in the opposite
# direction
#
# This is not symmetry for its own sake. Mode B is the configuration the
# standalone demo and the standalone harness link against, and it has to
# supply curl_url_strerror and curl_free itself because nothing else in that
# link does. The failure this catches is a mis-specified feature set -- a mode
# B archive accidentally built with --no-default-features, say -- which would
# then fail to link the standalone demo for a reason no behavioural test could
# explain, because no behavioural test would ever run.
#
# A missing mode B archive is a SKIP rather than a failure, so that the script
# stays useful to somebody who built only the drop-in configuration. --strict
# turns that skip into a failure, which is what a continuous integration run
# wants, because there a check that silently did not run is the thing to worry
# about.
# ------------------------------------------------------------------------

step 'Mode B, the standalone configuration'
say '  Built with the manifest defaults. The eight, plus curl_url_strerror'
say '  under feature strerror and curl_free under feature cfree, because in'
say '  a standalone link nothing else supplies either and the documented'
say '  contract that a buffer from curl_url_get() is released with'
say '  curl_free() still has to hold.'

MODE_B_DROPIN="$(rust_artifact "${MODE_B_DROPIN:-}" 'mode-b-dropin-archive' \
  'b' "${DROPIN}")"
MODE_B_ARCHIVE="$(rust_artifact "${MODE_B_ARCHIVE:-}" 'mode-b-archive' 'b' \
  "${ARCHIVE}")"

# The required set of this configuration: the eight and the two the features
# add. Assembled from the same two literal arrays the self-checks above have
# already agreed with each other, so the ten cannot drift from the eight.
STANDALONE_LIST="${SCRATCH}/standalone-symbols.txt"
write_symbol_list "${STANDALONE_LIST}" \
  "${EXPECTED_SYMBOLS[@]}" "${STANDALONE_EXTRA[@]}"

STANDALONE_COUNT="$(wc -l < "${STANDALONE_LIST}" | tr -d ' ')"
if [ "${STANDALONE_COUNT}" -ne 10 ]; then
  die "the standalone required set came to ${STANDALONE_COUNT} names rather \
than ten. Eight from EXPECTED_SYMBOLS and two from STANDALONE_EXTRA is ten, \
so a different total means the two arrays overlap -- which the self-checks \
above are meant to have ruled out"
fi

MODE_B_CANONICAL_VERDICT='skip'
if [ -n "${MODE_B_DROPIN}" ]; then
  if [ ! -r "${MODE_B_DROPIN}" ]; then
    fail "mode B canonical archive: ${MODE_B_DROPIN} cannot be read"
    MODE_B_CANONICAL_VERDICT='fail'
  elif check_artifact 'mode B canonical drop-in archive' 'mode-b-canonical' \
       "${MODE_B_DROPIN}" "${STANDALONE_LIST}" 'canonical' 'standalone'; then
    MODE_B_CANONICAL_VERDICT='pass'
  else
    MODE_B_CANONICAL_VERDICT='fail'
  fi
else
  skip "mode B canonical drop-in archive: not built. Run \
scripts/build-rust.sh, which builds both configurations, or accept that the \
standalone feature set is unverified in this run"
fi

MODE_B_RAW_VERDICT='skip'
if [ -n "${MODE_B_ARCHIVE}" ]; then
  if [ ! -r "${MODE_B_ARCHIVE}" ]; then
    fail "mode B staticlib: ${MODE_B_ARCHIVE} cannot be read"
    MODE_B_RAW_VERDICT='fail'
  elif check_artifact 'mode B staticlib, curl_ and Curl_ namespaces' \
       'mode-b-raw' "${MODE_B_ARCHIVE}" "${STANDALONE_LIST}" 'raw' \
       'standalone'; then
    MODE_B_RAW_VERDICT='pass'
  else
    MODE_B_RAW_VERDICT='fail'
  fi
else
  skip 'mode B staticlib: not built'
fi

summary 'mode-b-canonical-archive' "${MODE_B_DROPIN:-none}"
summary 'mode-b-canonical-verdict' "${MODE_B_CANONICAL_VERDICT}"
summary 'mode-b-staticlib' "${MODE_B_ARCHIVE:-none}"
summary 'mode-b-staticlib-verdict' "${MODE_B_RAW_VERDICT}"
summary 'standalone-symbol-count' "${STANDALONE_COUNT}"

# ------------------------------------------------------------------------
# The shared objects, as a second and independent confirmation
#
# Symbol visibility differs between crate types. A cdylib exposes symbols the
# way an executable does, so only the #[no_mangle] extern "C" items reach its
# dynamic symbol table: an ordinary `pub fn` does not. That makes a shared
# object a confirmation arrived at through a DIFFERENT mechanism than the
# archive check rather than a repetition of it -- the archive check reads what
# the compiler emitted, this reads what the linker decided to publish.
#
# EVERY shared object is checked, in all three configurations, because every
# one of them has an export set that has to be exactly right:
#
#   mode A, static drop-in  eight names, the drop-in list, and it additionally
#                           IMPORTS Curl_get_scheme and Curl_getn_scheme
#   mode B, standalone      ten names, the standalone list
#   mode C, shared drop-in  eight names, the drop-in list, and closed
#
# Mode A's imports are the part that used to go unchecked, and they are the
# reason this section grew a second assertion. Those two names are
# libcurl-private (lib/url.h:76-77) and resolve only in a link where url.c.o
# takes part, so that object does not load on its own -- but it is not
# therefore unverifiable. Its contract is the one lib/urlapi.o already has,
# narrowed: the reference object leaves seventeen Curl_*/curl_* names
# undefined and this one leaves two, both of them in that seventeen. Both
# halves are asserted below against the reference object rather than taken on
# trust, and mode C is the configuration that closes the link while keeping
# the same eight exports, which is the shared half of G1.
# ------------------------------------------------------------------------

step 'The shared objects'

# The non-system imports of a shared object: every undefined dynamic symbol in
# the curl_ or Curl_ namespace. Everything else an undefined dynamic symbol can
# be here is a real NEEDED dependency -- libc, libgcc, libidn2 -- and those are
# not the crate's business.
#
#   $1  the shared object
#   $2  the file to write the C-sorted list to
#
# Returns non-zero only when nm could not read the object.
shared_curl_imports() {
  local object="${1}"
  local out="${2}"
  local raw="${out}.nm"
  local err="${out}.err"

  : > "${out}"
  if ! nm -g --undefined-only -PD "${object}" > "${raw}" 2> "${err}"; then
    warn "nm could not read the dynamic symbols of ${object}: \
$(tr '\n' ' ' < "${err}")"
    return 1
  fi

  # -P prints "name type value size" and an undefined symbol has type U, so
  # the name is field one. A versioned name arrives as sym@VER, and the @ and
  # everything after it is dropped so that idn2_free@IDN2_0.0.0 and a bare
  # idn2_free compare equal; a C identifier cannot contain @, so the cut
  # cannot truncate a real name. LC_ALL=C for the same reason as everywhere
  # else here: only in the C locale do Curl_ names sort ahead of curl_ ones.
  awk '/:$/ { next } { sub(/@.*$/, "", $1); print $1 }' "${raw}" |
    LC_ALL=C grep -E '^(curl_|Curl_)' | LC_ALL=C sort -u > "${out}" || true
  return 0
}

# One shared object's dynamic export set.
#
#   $1  the mode tag, a, b or c
#   $2  the required symbol list file
#   $3  the label for the required column
#
# Reports through pass/fail/skip and leaves the verdict in SHARED_VERDICT and
# the resolved path in SHARED_OBJECT. Two globals rather than a printed value,
# deliberately: pass(), fail(), skip() and check_artifact() all write the
# listing a reader needs to stdout, and capturing this function's output in a
# command substitution would swallow every one of those lines.
SHARED_VERDICT=''
SHARED_OBJECT=''
check_shared() {
  local tag="${1}"
  local required="${2}"
  local required_label="${3}"
  local variable="MODE_${tag^^}_SHARED"

  SHARED_VERDICT='skip'
  SHARED_OBJECT="$(rust_artifact "${!variable:-}" \
    "mode-${tag}-shared-object" "${tag}" "${SHARED}")"
  summary "mode-${tag}-shared-object" "${SHARED_OBJECT:-none}"

  if [ -z "${SHARED_OBJECT}" ] || [ ! -r "${SHARED_OBJECT}" ]; then
    skip "mode ${tag^^} shared object: not found. Every configuration builds \
one, so this means that configuration has not been built here yet"
    return 0
  fi

  if check_artifact "mode ${tag^^} shared object, dynamic symbol table" \
     "mode-${tag}-shared" "${SHARED_OBJECT}" "${required}" 'dynamic' \
     "${required_label}"; then
    SHARED_VERDICT='pass'
  else
    SHARED_VERDICT='fail'
  fi
}

check_shared 'a' "${EXPECTED_LIST}" 'C oracle'
summary 'mode-a-shared-verdict' "${SHARED_VERDICT}"
MODE_A_SHARED_PATH="${SHARED_OBJECT}"

check_shared 'b' "${STANDALONE_LIST}" 'standalone'
summary 'mode-b-shared-verdict' "${SHARED_VERDICT}"

check_shared 'c' "${EXPECTED_LIST}" 'C oracle'
summary 'mode-c-shared-verdict' "${SHARED_VERDICT}"
MODE_C_SHARED_PATH="${SHARED_OBJECT}"

# ------------------------------------------------------------------------
# The import contracts of the two drop-in shared objects
#
# The export sets above say what each object publishes. These say what each
# one still needs, which is the half the earlier version of this script left
# unchecked and the half G1's "linkable in place of lib/urlapi.o" turns on.
#
# Mode A must import exactly the two scheme entry points, and each of them
# must be DEFINED by the reference libcurl archive -- otherwise a drop-in link
# against that archive would leave the reference unresolved. Mode C must import
# nothing in either namespace at all, which is what makes it loadable.
# ------------------------------------------------------------------------

step 'The shared objects, import contracts'

SCHEME_IMPORT_LIST="${SCRATCH}/scheme-imports.txt"
write_symbol_list "${SCHEME_IMPORT_LIST}" Curl_get_scheme Curl_getn_scheme

EMPTY_IMPORT_LIST="${SCRATCH}/no-imports.txt"
: > "${EMPTY_IMPORT_LIST}"

IMPORT_A_VERDICT='skip'
if [ -n "${MODE_A_SHARED_PATH}" ] && [ -r "${MODE_A_SHARED_PATH}" ]; then
  OBSERVED_A="${SCRATCH}/mode-a-imports.txt"
  if shared_curl_imports "${MODE_A_SHARED_PATH}" "${OBSERVED_A}"; then
    if compare_symbol_sets 'mode A shared object, curl imports' \
       'mode-a-imports' "${SCHEME_IMPORT_LIST}" "${OBSERVED_A}"; then
      IMPORT_A_VERDICT='pass'
    else
      IMPORT_A_VERDICT='fail'
    fi
  else
    fail "mode A shared object: its dynamic imports could not be read"
    IMPORT_A_VERDICT='fail'
  fi
else
  skip 'mode A shared object: not found, so its import contract is unchecked'
fi
summary 'mode-a-shared-import-verdict' "${IMPORT_A_VERDICT}"

IMPORT_C_VERDICT='skip'
if [ -n "${MODE_C_SHARED_PATH}" ] && [ -r "${MODE_C_SHARED_PATH}" ]; then
  OBSERVED_C="${SCRATCH}/mode-c-imports.txt"
  if shared_curl_imports "${MODE_C_SHARED_PATH}" "${OBSERVED_C}"; then
    if compare_symbol_sets 'mode C shared object, curl imports' \
       'mode-c-imports' "${EMPTY_IMPORT_LIST}" "${OBSERVED_C}"; then
      IMPORT_C_VERDICT='pass'
    else
      IMPORT_C_VERDICT='fail'
    fi
  else
    fail "mode C shared object: its dynamic imports could not be read"
    IMPORT_C_VERDICT='fail'
  fi
else
  skip 'mode C shared object: not found, so its import contract is unchecked'
fi
summary 'mode-c-shared-import-verdict' "${IMPORT_C_VERDICT}"

# The property mode A's contract actually rests on, asserted rather than
# asserted-about: every name that object imports is DEFINED by the reference
# libcurl archive, so the link a drop-in is consumed in resolves it. Both names
# are declared side by side at lib/url.h:76-77 and defined in lib/url.c, the
# NUL-terminated entry point at its 1469-1472 and the length-bounded sibling it
# forwards to at its 1477.
#
# This is a different claim from "the predecessor leaves it undefined too", and
# the difference is worth stating because only one of the two is true of both
# names. lib/urlapi.c reaches the scheme table through Curl_get_scheme only,
# always having a NUL-terminated scheme string to hand; the port also reaches
# Curl_getn_scheme, because it has places where the scheme is a bounded slice
# and passing a length is what avoids materialising a copy. So Curl_get_scheme
# is among the names the C object leaves to the link and Curl_getn_scheme is
# not -- while both are supplied by the same libcurl, from the same file, and
# the port's two-name import set is far smaller than the seventeen-name one it
# replaces. The counted comparison below reports both figures.
PROVIDER_VERDICT='skip'
if [ -n "${REFERENCE_ARCHIVE:-}" ] && [ -r "${REFERENCE_ARCHIVE:-}" ]; then
  REFERENCE_DEFINED="${SCRATCH}/reference-archive-defined.txt"
  if nm_defined "${REFERENCE_ARCHIVE}" "${REFERENCE_DEFINED}"; then
    PROVIDER_VERDICT='pass'
    while IFS= read -r symbol; do
      if ! LC_ALL=C grep -q -x -F "${symbol}" "${REFERENCE_DEFINED}"; then
        fail "mode A shared object imports ${symbol}, which \
${REFERENCE_ARCHIVE} does not define. A drop-in link against that archive \
would leave the reference unresolved, so the import contract does not hold"
        PROVIDER_VERDICT='fail'
      fi
    done < "${SCHEME_IMPORT_LIST}"
    if [ "${PROVIDER_VERDICT}" = 'pass' ]; then
      pass "both names mode A imports are defined by ${REFERENCE_ARCHIVE}, so \
the drop-in link resolves them"
    fi
  else
    fail "mode A import provider check: the symbol table of \
${REFERENCE_ARCHIVE} could not be read"
    PROVIDER_VERDICT='fail'
  fi
else
  skip 'no reference archive, so the import provider check is skipped'
fi
summary 'shared-import-provider-verdict' "${PROVIDER_VERDICT}"

# The counted comparison, reported and not asserted. It is the figure that
# makes "narrowed" a measurement rather than a claim: how many curl_/Curl_
# names the C object being replaced leaves to the link, against the two this
# object does. No verdict, because a change in either count is a fact about
# libcurl's internals rather than a defect in this crate.
if [ -n "${C_OBJECT:-}" ] && [ -r "${C_OBJECT:-}" ]; then
  REFERENCE_UNDEFINED="${SCRATCH}/reference-undefined.txt"
  nm -g --undefined-only -P "${C_OBJECT}" 2> /dev/null |
    awk '/:$/ { next } { print $1 }' |
    LC_ALL=C grep -E '^(curl_|Curl_)' |
    LC_ALL=C sort -u > "${REFERENCE_UNDEFINED}" || true
  REFERENCE_UNDEFINED_COUNT="$(wc -l < "${REFERENCE_UNDEFINED}" | tr -d ' ')"
  note "${C_OBJECT} leaves ${REFERENCE_UNDEFINED_COUNT} curl_/Curl_ names to"
  note '  the link; the mode A shared object leaves 2, and the crate'
  note '  re-implements the rest internally. Full list:'
  note "  ${REFERENCE_UNDEFINED}"
  summary 'reference-object-curl-imports' "${REFERENCE_UNDEFINED_COUNT}"
else
  summary 'reference-object-curl-imports' 'not-measured'
fi
# ------------------------------------------------------------------------
# The link collision pre-check
#
# What run-parity.sh does in mode A is copy the reference archive, delete the
# urlapi member from the copy, and link the harness against that copy together
# with the Rust archive. That link fails on any symbol both sides define. The
# check here is the same question asked cheaply: is there a name defined both
# by the Rust archive and by the reference archive with the urlapi member
# taken out?
#
# The answer should be none, and it is worth asking here rather than
# discovering it from a linker diagnostic three steps later, because the
# linker's message names the symbol but not which of the two artifacts should
# not have had it.
# ------------------------------------------------------------------------

step 'The mode A link collision pre-check'

COLLISION_VERDICT='skip'

# Named before the chain below, because the nm invocation that writes them is
# one of that chain's conditions and a condition cannot declare its own
# variables.
COLLISION_NM_OUT="${SCRATCH}/reference-all.nm"
COLLISION_NM_ERR="${SCRATCH}/reference-all.nm.err"

if [ "${CHECK_COLLISION}" != '1' ]; then
  skip 'link collision pre-check: --no-collision was given'
elif [ -z "${REFERENCE_ARCHIVE}" ] || [ ! -r "${REFERENCE_ARCHIVE}" ]; then
  skip "link collision pre-check: it needs the whole reference archive, and \
only the urlapi object is available in this run"
elif ! nm -g --defined-only -P "${REFERENCE_ARCHIVE}" \
     > "${COLLISION_NM_OUT}" 2> "${COLLISION_NM_ERR}"; then
  # THE STATUS IS CHECKED, and the reason is arithmetic rather than caution.
  # This used to read "|| true", which turned an unreadable archive or a broken
  # nm into an empty symbol list -- and the comparison below is an
  # intersection, which is empty whenever either side is. So the check reported
  # "nothing is defined on both sides", the single most reassuring answer it
  # has, for the one input where it had established nothing at all.
  #
  # A failure, therefore, and not a skip: a skip says "this could not be
  # checked", which is true but leaves the exit status to the skip policy,
  # whereas an unreadable reference archive is a broken workflow whatever the
  # policy. stderr is kept and quoted, because "nm failed" is not actionable
  # and "nm said the file format is not recognised" is.
  fail "link collision pre-check: nm could not read ${REFERENCE_ARCHIVE}: \
$(tr '\n' ' ' < "${COLLISION_NM_ERR}")"
  COLLISION_VERDICT='fail'
else
  # The member name, discovered here if it is not already known.
  #
  # THIS IS NOT REDUNDANT with the discovery on the archive-member branch
  # above, and the case it covers used to produce a confident, wrong answer.
  # When the oracle object arrives from REFERENCE_URLAPI_OBJECT -- an override,
  # or a summary that recorded the already-extracted object -- that branch
  # never runs, so REFERENCE_MEMBER could still be empty here. The awk filter
  # below then had nothing to exclude, so every symbol of the urlapi member
  # stayed in the "everything else" set, and the comparison reported the eight
  # names the port is REQUIRED to define as collisions and exited 1. A gate
  # that fails on correct input is as useless as one that passes on incorrect
  # input.
  #
  # The archive is what this check reads, so the member has to be discovered
  # from the archive whenever the archive is used, whatever supplied the
  # object.
  if [ -z "${REFERENCE_MEMBER}" ]; then
    note 'the urlapi member was not recorded, so it is discovered from the'
    note 'archive now: this comparison has to exclude that member, and'
    note 'excluding nothing would report the drop-in symbols themselves'
    REFERENCE_MEMBER="$(discover_member "${REFERENCE_ARCHIVE}")"
    note "member:  ${REFERENCE_MEMBER}"
    summary 'collision-member-source' 'discovered-here'
  else
    summary 'collision-member-source' 'already-known'
  fi

  # Every global defined by the reference archive EXCEPT those defined by the
  # urlapi member. nm's own archive member headers are what makes this possible
  # in one pass: each header names the member the following symbols belong to,
  # so the urlapi member's block can be stepped over without invoking nm once
  # per member. The listing was produced -- successfully, which the chain above
  # established -- by the nm invocation in the elif.
  OTHERS="${SCRATCH}/reference-others.txt"

  awk -v skip="[${REFERENCE_MEMBER}]:" '
    /:$/ {
      # A member header. From here to the next header the symbols belong to
      # this member, so decide once whether to keep them.
      skipping = (index($0, skip) > 0)
      next
    }
    NF >= 3 && !skipping { print $1 }
  ' "${COLLISION_NM_OUT}" | LC_ALL=C sort -u > "${OTHERS}"

  OTHERS_COUNT="$(wc -l < "${OTHERS}" | tr -d ' ')"
  note "the reference archive without ${REFERENCE_MEMBER:-the urlapi member} \
defines ${OTHERS_COUNT} globals"

  if [ "${OTHERS_COUNT}" -eq 0 ]; then
    # nm succeeded and still reported nothing outside the urlapi member, which
    # cannot be true of a 178-member libcurl archive. A failure for the same
    # arithmetic reason as the nm failure above: the intersection below would
    # be empty and would read as "no collisions", which is the reassuring
    # answer arrived at from no evidence.
    fail "link collision pre-check: nm read ${REFERENCE_ARCHIVE} but reported \
no globals outside ${REFERENCE_MEMBER:-the urlapi member}. A libcurl archive \
defines thousands, so either the archive is not a libcurl archive or every \
member carries intermediate representation rather than a symbol table, which \
is what link-time optimization produces. Comparing against nothing would \
report no collisions from no evidence"
    COLLISION_VERDICT='fail'
  else
    # The Rust side of the comparison. The canonical archive is used whole,
    # because it has already been reduced to the ABI. For Cargo's staticlib
    # only the curl_ and Curl_ namespaces are considered, for the reason
    # rust_exports() sets out: the Rust standard library it carries is
    # irrelevant to a libcurl link and comparing it would report thousands of
    # names that no link would ever resolve against each other.
    COLLIDE_INPUT=''
    COLLIDE_SET="${SCRATCH}/collision-rust.txt"
    if [ -n "${MODE_A_DROPIN}" ] && [ -r "${MODE_A_DROPIN}" ]; then
      COLLIDE_INPUT="${MODE_A_DROPIN}"
      if nm_defined "${COLLIDE_INPUT}" "${COLLIDE_SET}"; then
        note "comparing ${COLLIDE_INPUT##*/} whole"
      else
        COLLIDE_INPUT=''
      fi
    elif [ -n "${MODE_A_ARCHIVE}" ] && [ -r "${MODE_A_ARCHIVE}" ]; then
      COLLIDE_INPUT="${MODE_A_ARCHIVE}"
      if nm_defined "${COLLIDE_INPUT}" "${SCRATCH}/collision-all.txt"; then
        rust_exports "${SCRATCH}/collision-all.txt" "${COLLIDE_SET}"
        note "comparing the curl_ and Curl_ names of \
${COLLIDE_INPUT##*/}"
      else
        COLLIDE_INPUT=''
      fi
    fi

    if [ -z "${COLLIDE_INPUT}" ]; then
      skip 'link collision pre-check: no readable mode A archive'
    else
      COLLISIONS="${SCRATCH}/collisions.txt"
      LC_ALL=C comm -12 "${OTHERS}" "${COLLIDE_SET}" > "${COLLISIONS}"
      if [ -s "${COLLISIONS}" ]; then
        say '  these names are defined on BOTH sides of the mode A link --'
        while read -r symbol; do
          if [ -n "${symbol}" ]; then
            say "      ${symbol}    $(forbidden_reason "${symbol}")"
          fi
        done < "${COLLISIONS}"
        fail "link collision pre-check: \
$(wc -l < "${COLLISIONS}" | tr -d ' ') name(s) are defined by both the Rust \
archive and the reference archive with ${REFERENCE_MEMBER:-the urlapi \
member} removed, so the mode A link run-parity.sh performs would fail on \
each of them"
        COLLISION_VERDICT='fail'
      else
        pass 'link collision pre-check: nothing is defined on both sides'
        COLLISION_VERDICT='pass'
      fi
    fi
  fi
fi

summary 'collision-verdict' "${COLLISION_VERDICT}"

# ------------------------------------------------------------------------
# Reported constraints
#
# Both of these are reported and deliberately NOT remedied. The directive is
# explicit: where something in scope would require touching something out of
# scope in order to work, report it instead of expanding scope. They are
# printed on every run rather than buried in a document, because both change
# how a reader should interpret what this script just said.
# ------------------------------------------------------------------------

step 'Reported constraints'

printf '%s\n' \
  "R1 -- the distribution check will fail once rust-urlapi/ is committed." \
  "" \
  "  .github/scripts/distfiles.sh compares the output of git ls-files" \
  "  against the contents of the generated release tarball, subtracts a" \
  "  fixed literal exception list with no entry able to match rust-urlapi," \
  "  and exits 1 for anything reported missing. It runs as the" \
  "  missing-files job of .github/workflows/distcheck.yml (its L210 and" \
  "  L225), in a workflow that triggers on every push to the default branch" \
  "  and every pull request against it with no path filter. Committing" \
  "  rust-urlapi/** therefore makes that job report the new files as" \
  "  missing from the tarball and fail." \
  "" \
  "  The only remedies are adding the directory to EXTRA_DIST at" \
  "  Makefile.am:L67 or to the distributed subdirectory lists at its" \
  "  L73-L74. Both are edits to Makefile.am, which is out of scope. This" \
  "  script does not make them and neither should anything else in this" \
  "  work item; the one-line addition is a follow-up decision for the" \
  "  owners of curl's build system." \
  "" \
  "R2 -- a second URL API test is out of reach, and its symbol is" \
  "     deliberately absent from the comparison above." \
  "" \
  "  tests/unit/unit1653.c, driven by tests/data/test1653 and named" \
  "  \"urlapi port number parsing\", calls Curl_parse_port(url, &host," \
  "  has_scheme) directly at its L37, handing it a CURLU * together with a" \
  "  struct dynbuf it constructed itself at its L33-L38. That function is" \
  "  exported only in unit-test builds, through the conditional marker at" \
  "  lib/urlapi-int.h:L35-L38, and lib/curl_setup.h:L1505-L1509 is what" \
  "  makes UNITTEST expand to nothing there and to static everywhere else." \
  "" \
  "  Satisfying it from Rust would require a ninth exported symbol AND" \
  "  bit-compatible interoperation with libcurl's private dynamic-buffer" \
  "  structure -- a materially harder contract than anything the public API" \
  "  demands, since the public API never exposes that structure at all. The" \
  "  success criteria name only lib1560 and test1560, so unit1653 is out of" \
  "  scope. It is recorded here rather than passed over in silence, and it" \
  "  is why a reference object exporting Curl_parse_port is treated above" \
  "  as a misconfiguration to fix rather than as a set to match." \
  "" \
  "  The same applies to dedotdotify, the second UNITTEST-gated name in" \
  "  lib/urlapi.c (its L715-L716), which tests/unit/unit1395.c calls at" \
  "  its L115."

# ------------------------------------------------------------------------
# Verdict
# ------------------------------------------------------------------------

step 'Summary'

for entry in "${VERDICTS[@]}"; do
  printf '  %s\n' "${entry}"
done

say ''
note "${CHECKS_PASSED} passed, ${CHECKS_FAILED} failed, \
${CHECKS_SKIPPED} skipped"
note "facts: ${SUMMARY}"

summary 'checks-passed' "${CHECKS_PASSED}"
summary 'checks-failed' "${CHECKS_FAILED}"
summary 'checks-skipped' "${CHECKS_SKIPPED}"

# --strict makes a skip fail. A skipped check is a real outcome and is worth
# distinguishing from a passed one when a person is working through a single
# symbol by hand, but in continuous integration a check that silently did not
# run is the failure mode to worry about, so there the two collapse.
if [ "${CHECKS_FAILED}" -gt 0 ]; then
  say ''
  die "${CHECKS_FAILED} check(s) failed. The exported symbol set is part of \
the specification, not an implementation detail: run-parity.sh links the \
Rust archive in place of ${REFERENCE_MEMBER:-the urlapi object} and then \
diffs behaviour, and neither the link nor the diff means anything while the \
surface disagrees. Fix the symbol set first"
fi

if [ "${CHECKS_SKIPPED}" -gt 0 ] && [ "${STRICT}" = '1' ]; then
  say ''
  die "${CHECKS_SKIPPED} check(s) could not run. This is a GATE, so that is a \
failure and not a footnote: run-parity.sh links the Rust archive in place of \
${REFERENCE_MEMBER:-the urlapi object} and diffs behaviour on the strength of \
what this script says, and a check that did not run has agreed to nothing. \
Each skip is named above with what would make it run; \
scripts/build-reference.sh producing the archive and scripts/build-rust.sh \
building both configurations is what makes every check here run. Pass \
--allow-partial to accept an incomplete gate deliberately"
fi

# The verdict, decided here and nowhere else: after every check has had its
# chance to fail and after the skip tally has been judged. publish_summary() is
# the only writer of the result line, so the file carries exactly one verdict.
RESULT='pass'
publish_summary "${RESULT}" || die "could not publish ${SUMMARY}"

say ''
if [ "${CHECKS_SKIPPED}" -gt 0 ]; then
  # Reachable only under --allow-partial, since otherwise a skip has already
  # failed the run above. The wording is deliberately not reassuring: the
  # sentence a reader must not be able to take away from a partial run is "the
  # symbol sets agree", because the sets that were not compared are exactly the
  # ones nobody looked at.
  say "check-abi.sh: PARTIAL. ${CHECKS_PASSED} check(s) passed and \
${CHECKS_SKIPPED} could not run, which --allow-partial permitted. The \
surface is verified only as far as the checks that ran: what the skipped \
ones cover is unknown, not agreed. Run scripts/build-reference.sh and \
scripts/build-rust.sh and then this script without --allow-partial before \
drawing any conclusion from run-parity.sh."
else
  say "check-abi.sh: the symbol sets agree, all ${CHECKS_PASSED} checks ran \
and passed. The Rust archive exports exactly what the object built from \
lib/urlapi.c exports, so run-parity.sh can now link it and compare \
behaviour."
fi
