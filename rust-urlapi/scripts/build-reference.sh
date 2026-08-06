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

# Build the C baseline that the Rust port of lib/urlapi.c is judged against.
#
# Everything downstream of this script -- the symbol-set comparison in
# check-abi.sh, the byte-for-byte stdout diff and per-sub-test report in
# run-parity.sh -- is only as trustworthy as the reference build produced
# here, so this script configures that build explicitly rather than relying
# on any default, and then verifies that the configuration actually took.
#
# What it does, in order:
#
#   1. checks every prerequisite and reports ALL missing ones at once, before
#      starting any build, naming the Debian/Ubuntu package for each;
#   2. configures and builds libcurl out of tree from the UNMODIFIED
#      repository with SSL, IDN and LDAP on, static archive on, and both
#      memory debugging and link-time optimization off;
#   3. verifies the result: the nine protocols tests/data/test1560 declares
#      are present, the archive exists and holds a real urlapi object with
#      exactly the eight globals the port has to match, and memory debugging
#      is off;
#   4. stages the unmodified tests/libtest/lib1560.c beside the harness shim
#      header so that the shim wins the quoted include;
#   5. compiles the reference harness (harness/runner.c + harness/main.c);
#   6. compiles the reference demo (demo/urlapi_demo.c) in drop-in form;
#   7. captures the golden files: demo/expected-output.txt, and the harness
#      stdout, stderr and exit status under all four combinations of locale
#      and codeset that gate the IDN assertions;
#   8. writes a machine-readable summary of every fact the other scripts
#      need, and reports the two constraints this work deliberately does not
#      remedy.
#
# Outputs, all inside the crate directory:
#
#   build/reference/                 the out-of-tree CMake build tree
#   build/reference/lib/libcurl.a    the reference archive
#   build/harness/                   staged lib1560.c symlink + first.h shim
#   build/ref/harness-ref            reference harness binary
#   build/ref/demo-ref               reference demo binary
#   build/ref/urlapi-reference.o     urlapi member extracted for check-abi.sh
#   build/golden/                    harness captures, per environment
#   build/build-reference.log        full transcript of this run
#   build/reference-build.env        key=value summary for the other scripts
#   demo/expected-output.txt         the committed parity oracle (tracked)
#
# Everything except that last one lives under build/, which ../.gitignore
# covers. The repository root .gitignore carries "/build/" with a leading
# slash, which anchors it to the repository root and never reaches this
# subdirectory -- which is exactly why the sibling ignore file exists.
# Nothing under tests/, lib/, include/, src/ or docs/ is written or changed.
#
# THE SUMMARY FILE IS DATA, NOT SHELL. Its keys are lowercase with dashes,
# which are deliberately not valid shell identifiers, so the file cannot be
# sourced even by accident: "reference-archive=..." is a command name to a
# shell, not an assignment. Every value is validated before it is written --
# no carriage return, no newline, no other control byte -- and every key is
# written at most once. Consumers parse it with sed, which is what
# check-abi.sh and run-parity.sh do. The name kept the .env suffix it has
# always had; the format is the one described here.
#
# THE SUMMARY FILE IS ALSO A VERDICT. It carries result=pass only when every
# check in this script passed, and a run that stops part-way through leaves
# result=fail behind rather than the previous run's summary, so that no
# downstream script can certify artifacts a failed run produced. The
# invalidation happens at startup, before any expensive work, and the passing
# file is published by atomic rename.
#
# Usage: build-reference.sh [--force] [--valgrind] [--jobs N]

set -eu
set -o pipefail

# Every file this script creates is created for this user only. The scratch
# tree is a predictable path by design -- the other scripts have to find it --
# so the protection against another user planting a symlink or a file there
# first is the permission mask plus the remove-before-write discipline that
# fresh_path() below applies to every predictable destination.
umask 077

# Working directory: the crate root. "$0" may be absolute or relative and the
# script has to behave identically either way, so the location is derived from
# it. Invoked as rust-urlapi/scripts/build-reference.sh, as
# ./build-reference.sh from inside scripts/, or through the reference target of
# ../GNUmakefile, all three land here.
#
# Derived with parameter expansion rather than with dirname, deliberately.
# This is the one place where an external command cannot be checked for first
# -- the prerequisite table has not run yet, and cannot, because it needs the
# build log, which needs this directory. A missing or shadowed dirname would
# make the command substitution expand to nothing, and the script would then
# quietly resolve both directories to the filesystem root instead of failing.
# Parameter expansion is a shell builtin and cannot fail that way. Measured:
# with dirname absent from PATH the earlier form did exactly that.
SCRIPT_DIR="${0%/*}"
if [ "${SCRIPT_DIR}" = "${0}" ]; then
  # No slash in "$0" at all, so it was run from the directory holding it.
  SCRIPT_DIR="."
elif [ -z "${SCRIPT_DIR}" ]; then
  # "$0" was "/name", so the directory is the root.
  SCRIPT_DIR="/"
fi
cd "${SCRIPT_DIR}/.."

# pwd -P, not pwd. The physical path -- every symlink resolved -- is what the
# containment check in resolve_output_root() below compares against, and a
# comparison between a logical path and a physical one is a comparison that
# can be defeated by a symlink. Both sides are therefore physical.
CRATE_DIR="$(pwd -P)"

# The unmodified repository, needed separately from the crate directory: the
# public headers, the CMake source tree and tests/libtest/lib1560.c all come
# from it, and every one of them is read only. Taken as the parent rather than
# from git so that the script works in an exported tree with no .git at all.
REPO_ROOT="$(cd .. && pwd -P)"

# Both resolutions are checked immediately, and with plain printf because none
# of the helpers below exist yet. The full landmark table in the prerequisite
# section is the thorough check; this one exists so that a script started from
# somewhere unexpected says so in one line instead of reporting nine missing
# files whose paths are the real clue.
if [ ! -f "${CRATE_DIR}/Cargo.toml" ] ||
   [ ! -f "${REPO_ROOT}/CMakeLists.txt" ]; then
  printf 'build-reference.sh: error: %s\n' \
    "resolved the crate directory as ${CRATE_DIR} and the repository root \
as ${REPO_ROOT}, but Cargo.toml is not in the first or CMakeLists.txt is not \
in the second. This script has to be run from the scripts directory of the \
curl-urlapi-rs crate inside a curl checkout" >&2
  exit 1
fi

# Where an output tree is allowed to be, and why the question needs asking.
#
# BUILD_DIR and REFERENCE_BUILD_DIR are environment-controlled, and everything
# this script writes -- the CMake build tree, the staged harness directory, the
# binaries, the golden captures, the log, the summary -- goes underneath one of
# them. An unvalidated value therefore lets the environment aim a CMake
# configure and a dozen redirections at any directory on the machine, including
# lib/, include/, tests/ and the repository root itself, where the result would
# be modifications to pre-existing files. That is goal G4 and acceptance
# criterion A12 broken by an environment variable, so the value is checked
# rather than trusted.
#
# The rule is narrow and stated in full:
#
#   - inside the repository, only <crate>/build and <crate>/target and their
#     descendants are allowed. Those two are what ../.gitignore covers, so
#     they are the only places inside the tree where writing cannot show up
#     in "git status --porcelain";
#   - outside the repository, anything is allowed except the filesystem root.
#     That is the parallel-clone case the setup notes describe, where each
#     clone points its scratch at /tmp/<something>-$CLONE_INDEX;
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
    printf 'build-reference.sh: error: %s\n' \
      "${label} is set but empty. Unset it to accept the default, or give it \
a directory" >&2
    exit 2
  fi

  # Created before it is resolved, because cd cannot resolve a path that does
  # not exist yet and the ordinary first run has to work. mkdir -p on an
  # existing directory succeeds and changes nothing.
  if ! mkdir -p -- "${raw}" 2> /dev/null; then
    printf 'build-reference.sh: error: %s\n' \
      "${label}=${raw} could not be created" >&2
    exit 2
  fi

  if ! canonical="$(cd -- "${raw}" && pwd -P)"; then
    printf 'build-reference.sh: error: %s\n' \
      "${label}=${raw} exists but could not be entered, so its real location \
cannot be established" >&2
    exit 2
  fi

  if [ "${canonical}" = "/" ]; then
    printf 'build-reference.sh: error: %s\n' \
      "${label} resolves to the filesystem root. This script writes a build \
tree, binaries, captures and a log underneath it" >&2
    exit 2
  fi

  if [ "${canonical}" = "${REPO_ROOT}" ]; then
    printf 'build-reference.sh: error: %s\n' \
      "${label}=${raw} resolves to the repository root ${REPO_ROOT}. Writing \
there would modify pre-existing files, which goal G4 forbids" >&2
    exit 2
  fi

  case "${canonical}" in
    "${CRATE_DIR}/build" | "${CRATE_DIR}/build/"* | \
    "${CRATE_DIR}/target" | "${CRATE_DIR}/target/"*)
      # Inside the crate's own ignored output. The allowed inside-repository
      # case.
      ;;
    "${REPO_ROOT}/"*)
      printf 'build-reference.sh: error: %s\n' \
        "${label}=${raw} resolves to ${canonical}, which is inside the \
repository but outside the crate's ignored output. Only ${CRATE_DIR}/build \
and ${CRATE_DIR}/target are writable inside the tree -- everything else \
would leave modifications that acceptance criterion A12 forbids. Point it at \
one of those, or at a directory outside ${REPO_ROOT} entirely" >&2
      exit 2
      ;;
    *)
      # Outside the repository. Allowed, and the parallel-clone case.
      ;;
  esac

  printf '%s\n' "${canonical}"
}

# Scratch and output locations. BUILD_DIR exists so that a caller can move
# the whole scratch tree elsewhere -- out of the repository entirely, or into
# a per-clone directory when several clones build in parallel -- without
# editing anything here.
# The colon-less expansion, deliberately: the default applies when BUILD_DIR is
# UNSET, and a value that is set and empty is handed to resolve_output_root()
# so that it is refused there with a diagnostic. ${VAR:-default} would silently
# treat "BUILD_DIR=" as "no BUILD_DIR", which is a guess about what the caller
# meant, and the two possible meanings -- the default tree, or a value some
# earlier step failed to compute -- want opposite answers.
BUILD="$(resolve_output_root BUILD_DIR "${BUILD_DIR-${CRATE_DIR}/build}")"

# The CMake build tree. Overridable on its own because it is by far the most
# expensive artifact here: pointing several runs at one already-configured
# tree turns the build into an incremental no-op.
REFERENCE_DIR="$(resolve_output_root REFERENCE_BUILD_DIR \
  "${REFERENCE_BUILD_DIR-${BUILD}/reference}")"

STAGE_DIR="${BUILD}/harness"
BIN_DIR="${BUILD}/ref"
GOLDEN_DIR="${BUILD}/golden"
LOG_FILE="${BUILD}/build-reference.log"

# The published summary, and the in-progress file every fact is accumulated
# into before it. Nothing ever appends to the published one: it is replaced
# whole, by rename, so that a consumer opening it always sees a complete file
# from one run rather than a partially-written one from this one. See
# publish_facts().
FACTS_FILE="${BUILD}/reference-build.env"
FACTS_INPROGRESS=''

# The verdict the summary will carry. Set to pass at the very end and only
# when every check in this run passed; the EXIT trap publishes whatever it
# holds at that moment, so a run that dies anywhere -- a failed CMake
# configure, a missing library, an interrupt -- leaves result=fail behind
# rather than the previous run's result=pass.
RESULT='fail'

# True when the second path is the first one or lies underneath it. Both are
# already canonical here, because resolve_output_root() canonicalizes what it
# returns and every path below is built from one of its results, so this is a
# prefix test rather than a filesystem walk. The trailing slash is stripped
# from the parent first, or "/tmp" would fail to contain "/tmp/x" whenever the
# caller wrote "/tmp/".
#
#   $1  the containing path
#   $2  the path to test
path_within() {
  local parent="${1%/}"
  local candidate="${2}"

  if [ "${candidate}" = "${1}" ] || [ "${candidate}" = "${parent}" ]; then
    return 0
  fi
  case "${candidate}" in
    "${parent}"/*) return 0 ;;
  esac
  return 1
}

# Rule 5. The CMake tree may sit outside the scratch root -- that is what
# REFERENCE_BUILD_DIR is for -- but it may not BE the scratch root, and it may
# not swallow it or any of the four directories derived from it. CMake owns
# everything under its build tree and reconfigures it freely, and the staging
# directory, the binaries and the golden captures are all read back after the
# build, so an overlap would let one step remove another's inputs.
if [ "${REFERENCE_DIR}" = "${BUILD}" ]; then
  printf 'build-reference.sh: error: %s\n' \
    "REFERENCE_BUILD_DIR and BUILD_DIR both resolve to ${BUILD}. The CMake \
tree is one directory inside the scratch tree, or somewhere else entirely, \
but it cannot be the scratch tree itself: the log, the facts file, the \
staging directory, the binaries and the golden captures all live there" >&2
  exit 1
fi
for candidate in "${BUILD}" "${STAGE_DIR}" "${BIN_DIR}" "${GOLDEN_DIR}"; do
  if path_within "${REFERENCE_DIR}" "${candidate}"; then
    printf 'build-reference.sh: error: %s\n' \
      "REFERENCE_BUILD_DIR resolves to ${REFERENCE_DIR}, which contains \
${candidate}. CMake owns its build tree and reconfigures it freely, so \
nothing this script reads back afterwards may live inside it" >&2
    exit 1
  fi
done
if path_within "${REPO_ROOT}" "${REFERENCE_DIR}" &&
   path_within "${REFERENCE_DIR}" "${CRATE_DIR}"; then
  printf 'build-reference.sh: error: %s\n' \
    "REFERENCE_BUILD_DIR resolves to ${REFERENCE_DIR}, which contains the \
crate directory ${CRATE_DIR}" >&2
  exit 1
fi

# The one tracked file this script writes. Acceptance criterion A7 is a
# zero-byte difference between the demo linked against the Rust crate and the
# demo linked against the unmodified C implementation, and these are the
# bytes that criterion is measured against.
DEMO_GOLDEN="${CRATE_DIR}/demo/expected-output.txt"

# Inputs read from the crate. Each is checked for existence below rather than
# assumed, because a missing one produces a compiler diagnostic that says far
# less than a named prerequisite failure does.
HARNESS_SHIM="${CRATE_DIR}/harness/first.h"
HARNESS_RUNNER="${CRATE_DIR}/harness/runner.c"
HARNESS_MAIN="${CRATE_DIR}/harness/main.c"
DEMO_SOURCE="${CRATE_DIR}/demo/urlapi_demo.c"

# The unmodified test source. Never copied and never edited: it is reached
# through a symlink, for the reason spelled out at stage_test_source() below.
TEST_SOURCE="${REPO_ROOT}/tests/libtest/lib1560.c"

# The C compiler. CC is honored because a caller comparing two compilers is a
# legitimate use of this script, and because the crate's own build honors it.
CC_BIN="${CC:-cc}"

# The preprocessor state handed to the harness compilation, exposed as an
# overridable variable and written into the summary file for the reason set
# out under "Reference harness" below: run-parity.sh must hand the Rust
# harness compilation the identical set or the resulting diff compares two
# different test suites and proves nothing.
#
# The default applies only when the variable is UNSET, not when it is set and
# empty, which is why the expansion is ${VAR-default} and not ${VAR:-default}.
# The two forms differ in exactly the case that matters here: a caller
# building a reference libcurl without libidn2 has to be able to ask for no
# defines at all, and ${VAR:-default} would silently hand them -DUSE_LIBIDN2
# instead, compiling IDN assertions into a harness whose libcurl cannot
# satisfy them. Measured: with the colon form, HARNESS_DEFINES= had no effect.
HARNESS_DEFINES="${HARNESS_DEFINES--DUSE_LIBIDN2}"

# Warning options for the C compilations. -Wall is the floor, -Wextra adds the
# checks measurement shows both compilations already satisfy, and -Werror is
# what makes that measurement binding rather than decorative.
#
# -Werror is not caution for its own sake. Everything downstream treats these
# two binaries as the oracle: the golden captures become the tracked
# demo/expected-output.txt
# and the four harness transcripts run-parity.sh diffs against. A diagnostic
# from the compiler is the compiler saying it is not certain what the program
# means, and an oracle built from code the compiler was unsure about is an
# oracle that cannot be appealed to. So the compilation stops instead, and
# compile_with_report() below also returns non-zero on a warning line for the
# case where a caller replaced these options with a set that lacks -Werror.
#
# Colon-less for the same reason as above: an empty value has to mean no
# options. A caller who genuinely needs a warning tolerated names the specific
# -Wno- option here rather than being handed a blanket exemption.
HARNESS_CFLAGS="${HARNESS_CFLAGS--O2 -Wall -Wextra -Werror}"

# Option state, each also settable from the environment so that the same
# behavior is reachable from a Makefile without argument plumbing.
FORCE="${REGENERATE:-0}"
WANT_VALGRIND="${RUN_VALGRIND:-0}"
JOBS="${JOBS:-}"

# Set once the log file exists, so that the helpers below know whether they
# can append to it. Every diagnostic before that point still reaches the
# terminal.
LOG_READY=0

# Accumulated exit status. A golden file that no longer matches is a real
# regression signal and must not be silent, but it must also not abort the
# run before the summary file is written -- the other scripts need those
# facts even on a failing run. So such a finding sets this and the script
# exits with it at the very end.
FINAL_STATUS=0

usage() {
  printf '%s\n' \
    "Usage: build-reference.sh [--force] [--valgrind] [--jobs N]" \
    "" \
    "Builds the C reference baseline for the curl-urlapi-rs parity run:" \
    "libcurl.a from the unmodified repository, the reference harness and" \
    "demo binaries linked against it, and the golden outputs both are" \
    "compared to." \
    "" \
    "Options:" \
    "  -f, --force      replace demo/expected-output.txt even when the" \
    "                   newly captured transcript differs from it. Without" \
    "                   this the difference is reported and the tracked" \
    "                   file is left alone, because a golden file that" \
    "                   silently re-records itself cannot detect anything." \
    "                   Equivalent to REGENERATE=1." \
    "      --valgrind   additionally count allocations with valgrind. Not" \
    "                   the accounting tests/data/test1560 asks for; see" \
    "                   the R3 note this script prints. Equivalent to" \
    "                   RUN_VALGRIND=1." \
    "  -j, --jobs N     parallel build jobs, a whole number from 1 to" \
    "                   1024. Defaults to the processor count. Equivalent" \
    "                   to JOBS=N." \
    "  -h, --help       print this and exit." \
    "" \
    "Environment:" \
    "  CC                   C compiler. Default: cc" \
    "  BUILD_DIR            scratch tree. Default: <crate>/build. Must" \
    "                       resolve to <crate>/build, <crate>/target or a" \
    "                       directory outside the repository." \
    "  REFERENCE_BUILD_DIR  CMake build tree. Default: <build>/reference," \
    "                       with the same containment rule." \
    "  HARNESS_DEFINES      preprocessor state for the harness compile." \
    "                       Default: -DUSE_LIBIDN2" \
    "  HARNESS_CFLAGS       compiler options for the harness and demo." \
    "                       Default: -O2 -Wall -Wextra -Werror. A compiler" \
    "                       diagnostic fails the run either way; -Werror" \
    "                       is in the default so the compiler reports it" \
    "                       rather than this script having to grep for it."
}

# Appends one line to the build log, if the log exists yet. Kept separate
# from say() so that every write to the log goes through a single statement,
# which is also what keeps consecutive appends out of the source.
logonly() {
  if [ "${LOG_READY}" = "1" ]; then
    printf '%s\n' "$*" >> "${LOG_FILE}"
  fi
}

# Normal progress output: terminal and log.
say() {
  printf '%s\n' "$*"
  logonly "$*"
}

# A blank line and a heading, so the transcript of a long run stays readable.
section() {
  say ""
  say "== $* =="
}

# A finding that does not stop the run. Sent to stderr so that it cannot be
# mistaken for progress output by anything parsing stdout.
warn() {
  printf 'build-reference.sh: warning: %s\n' "$*" >&2
  logonly "warning: $*"
}

# A finding that stops the run. Every diagnostic reached through here names
# what was expected, what was found and what to do about it, because the whole
# value of a baseline script is that a wrong baseline is caught here rather
# than misread as a parity failure three scripts later.
fatal() {
  printf 'build-reference.sh: error: %s\n' "$*" >&2
  logonly "error: $*"
  exit 1
}

# Removes whatever occupies a path so that the next write creates it fresh.
#
# Every destination this script writes is a predictable path underneath the
# scratch tree, because the other scripts have to be able to find it without
# being told. That predictability is what a symlink attack needs: plant
# build/compile-harness-ref.log as a link to something else and a plain ">"
# redirection follows it and truncates the target. rm removes the LINK rather
# than what it points at, so removing first and creating second turns the
# whole class of problem into a no-op. Directories are left alone -- a
# destination that is a directory is a bug in this script, not something to
# delete -- and an absent path is not an error.
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

# Appends one key=value line to the machine-readable summary, having first
# established that both halves are fit to be written.
#
# THREE THINGS ARE CHECKED, and each one is checked because the value can come
# from the environment, from a version string, from curl-config or from a
# symbol table, none of which this script controls:
#
#   the key must be lowercase letters, digits and dashes. A dash is not
#   allowed in a shell identifier, so a file of these keys cannot be sourced
#   by anything -- which is the point. Sourcing was how a hostile value used
#   to be able to become a command;
#
#   the value must contain no control byte. A newline would let one value
#   forge a second key on the following line, which is the whole injection;
#   a carriage return would leave an invisible trailing byte in the value a
#   consumer reads back; a NUL cannot survive a shell variable at all. All of
#   them are refused rather than escaped, because there is no legitimate
#   value here -- path, flag, symbol name, version, number -- that contains
#   one, so refusing loses nothing and escaping would need a matching
#   unescape in three other scripts;
#
#   the key must not have been written already. A repeated key is a
#   programming error in this script, and it matters because a consumer
#   taking the last occurrence would silently read the second one.
#
# The write goes to the in-progress file, never to the published one. See
# publish_facts() for why.
#
#   $1  key
#   $2  value
FACT_KEYS=" "
fact() {
  local key="${1}"
  local value="${2}"

  case "${key}" in
    '' | *[!A-Za-z0-9_-]* | [!A-Za-z]*)
      fatal "fact: refusing the key '${key}'. A summary key is either \
lowercase letters, digits and dashes -- the shape the provenance records and \
scripts/check-abi.sh use, and one nothing can source because a dash is not \
legal in a shell identifier -- or upper case with underscores, the spelling \
scripts/run-parity.sh reads. Either way it starts with a letter"
      ;;
  esac

  case "${FACT_KEYS}" in
    *" ${key} "*)
      fatal "fact: the key '${key}' has already been written to \
${FACTS_FILE}. A duplicate key is a programming error here: a consumer that \
takes the last occurrence would read the wrong one of the two"
      ;;
  esac

  # The bracket expression covers every C0 control byte and DEL. A NUL cannot
  # reach here inside a shell variable in the first place, and the pattern
  # would not be able to see it if it did, which is stated so that the gap is
  # a known one rather than an assumed absence.
  case "${value}" in
    *[[:cntrl:]]*)
      fatal "fact: refusing the value of '${key}' because it contains a \
control character. A newline in a value forges a key on the next line, a \
carriage return leaves an invisible byte in what a consumer reads back, and \
no legitimate value here -- a path, a compiler flag, a symbol name, a \
version, a count -- contains either"
      ;;
  esac

  FACT_KEYS="${FACT_KEYS}${key} "
  printf '%s=%s\n' "${key}" "${value}" >> "${FACTS_INPROGRESS}"
}

# Runs one compiler command, keeping every diagnostic it produced, and FAILING
# on any diagnostic at all rather than letting one scroll past unread.
#
# The default options carry -Werror, so an ordinary warning already arrives
# here as a non-zero status and the grep below never sees it. The grep exists
# for the other case: a caller who replaced HARNESS_CFLAGS with a set that has
# no -Werror in it would otherwise get a silently-warned oracle, and the whole
# reason -Werror is in the default is that an oracle the compiler was unsure
# about cannot be appealed to. Both routes therefore end the same way -- a
# non-zero return, which every caller turns into fatal() -- and the full text
# is kept in a file named after the compilation so it can be read afterwards.
#
#   $1    label used for the per-compilation log and in diagnostics
#   rest  the command to run
compile_with_report() {
  local label="${1}"
  shift
  local output="${BUILD}/compile-${label}.log"
  local warnings
  local status=0

  # Removed before it is written. The path is predictable by design, so if
  # something already occupies it -- a symlink most of all -- the redirection
  # below would follow it instead of creating a file here.
  fresh_path "${output}"
  "$@" > "${output}" 2>&1 || status="$?"

  logonly "--- ${label} compiler output (${status}) ---"
  cat "${output}" >> "${LOG_FILE}"

  if [ "${status}" != "0" ]; then
    cat "${output}" >&2
    return "${status}"
  fi

  # grep -c answers 0 with status 1 when it matches nothing, which is the
  # ordinary case here and not a failure, so the status is discarded. With
  # pipefail set this has to be a discarded status on a plain command rather
  # than on a pipeline, which is why the count is not piped anywhere.
  warnings="$(grep -c -E ': (warning|error):' "${output}" || true)"
  if [ "${warnings}" != "0" ]; then
    cat "${output}" >&2
    printf 'build-reference.sh: error: %s\n' \
      "the ${label} compilation produced ${warnings} diagnostic line(s), \
kept in ${output}. The compiler is the judge of whether the oracle means what \
it says, so a diagnostic stops this run: fix the source, or name a specific \
-Wno- option in HARNESS_CFLAGS if the diagnostic is genuinely not applicable" \
      >&2
    logonly "error: ${label} produced ${warnings} diagnostic line(s)"
    return 1
  fi
  return 0
}

# Prints the first dotted-numeric token in the text given, or "unknown".
# Version strings across these tools have no common shape -- "cmake version
# 3.31.6", "GNU Make 4.4.1", a bare "1.8.1" -- so the number is extracted
# rather than positionally indexed.
version_token() {
  local found
  found="$(printf '%s\n' "${1}" | grep -o -E '[0-9][0-9.]*[0-9]' |
           head -n 1 || true)"
  if [ -z "${found}" ]; then
    printf 'unknown\n'
  else
    printf '%s\n' "${found}"
  fi
}

# The upper bound on --jobs. Not a machine limit: it is the point past which
# a number is far likelier to be a typo than an intention, and libcurl has 178
# source files so nothing above it can help anyway.
JOBS_MAX=1024

# Validates a job count the moment it arrives, rather than letting it travel
# to "cmake --build --parallel" and fail there.
#
# The values this refuses are the ones that used to get through: 0, which
# GNU make reads as unlimited parallelism and which is never what a caller
# asking for a specific number meant; a negative number; text; the empty
# string; and -- the case that matters most -- the NEXT OPTION, which is what
# arrives when a caller writes "--jobs --valgrind". That last one used to be
# consumed as the job count and thereby also removed from the argument list,
# so the option the caller actually asked for silently did not happen and the
# failure surfaced minutes later inside CMake.
#
#   $1  where the value came from, for the diagnostic
#   $2  the value
validate_jobs() {
  local origin="${1}"
  local value="${2}"

  case "${value}" in
    '' | *[!0-9]* | 0*)
      # Rejects the empty string, anything with a non-digit in it -- which
      # covers a leading dash, so an option name cannot pass as a number --
      # and any leading zero, which covers 0 itself and 007.
      printf 'build-reference.sh: error: %s\n' \
        "${origin} must be a whole number from 1 to ${JOBS_MAX}, and \
\"${value}\" is not. A count of zero means unlimited parallelism to GNU \
make, which is never what asking for a specific number meant, and an option \
name arriving here means the previous option ate it" >&2
      exit 2
      ;;
  esac

  if [ "${value}" -gt "${JOBS_MAX}" ]; then
    printf 'build-reference.sh: error: %s\n' \
      "${origin}=${value} is above the ${JOBS_MAX} this script accepts. \
libcurl is 178 source files, so a number that large is a typo rather than a \
plan" >&2
    exit 2
  fi
}

while [ "$#" -gt 0 ]; do
  case "${1}" in
    -f | --force)
      FORCE=1
      ;;
    --valgrind)
      WANT_VALGRIND=1
      ;;
    -j | --jobs)
      if [ "$#" -lt 2 ]; then
        printf 'build-reference.sh: error: %s\n' \
          "--jobs requires a number" >&2
        exit 2
      fi
      validate_jobs "--jobs" "${2}"
      JOBS="${2}"
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      printf 'build-reference.sh: error: unknown argument: %s\n' "${1}" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

# JOBS can also arrive from the environment, where it gets exactly the same
# scrutiny -- an unvalidated value is unvalidated whichever door it came
# through. Checked here rather than at the assignment above because the
# command-line option overrides the variable, so this is the point at which
# the value that will actually be used is known. An empty JOBS is the default
# and means "ask nproc", so it is left to the discovery below.
if [ -n "${JOBS}" ]; then
  validate_jobs "JOBS" "${JOBS}"
fi

mkdir -p "${BUILD}" "${STAGE_DIR}" "${BIN_DIR}" "${GOLDEN_DIR}"

# The log is truncated rather than appended to, so that a transcript always
# describes exactly one run. Removed first for the reason fresh_path()
# explains: the path is predictable, so a symlink planted here would otherwise
# be followed and its target truncated.
fresh_path "${LOG_FILE}"
: > "${LOG_FILE}"
LOG_READY=1

# ---------------------------------------------------------------------------
# The summary file: invalidated now, published at the end
#
# This happens BEFORE any of the expensive work, and that ordering is the
# whole point. The old arrangement truncated the summary just before writing
# it, which is well over a thousand lines and several minutes into the run, so
# a rerun that failed anywhere earlier left the PREVIOUS run's complete
# summary -- result and all -- sitting on disk looking current. check-abi.sh
# and run-parity.sh read that file to find the archive, the extracted urlapi
# object and the harness preprocessor state, so a stale summary is how a
# failed reference build gets certified as a passing one.
#
# Three steps, in this order:
#
#   1. accumulate every fact into a private temporary file, never into the
#      published path;
#   2. publish an explicit result=in-progress summary right now, replacing
#      whatever was there. A consumer that arrives mid-run, or after this
#      process is killed hard enough that the trap below never runs, then
#      finds in-progress rather than a verdict it can act on;
#   3. let the EXIT trap publish the real verdict, whatever the exit path.
# ---------------------------------------------------------------------------

# mktemp, not a fixed name: the file is created with no race and with this
# umask, and the name is unpredictable, so nothing can be sitting at it. It
# lives beside the published file so that the rename below is within one
# filesystem and therefore atomic.
if ! FACTS_INPROGRESS="$(mktemp "${BUILD}/reference-build.env.XXXXXX")"; then
  fatal "could not create a temporary summary file in ${BUILD}"
fi

# The header line, and the reason it is a comment rather than a key. Anyone
# who opens this file should be told in the file itself that it is data, and
# a "#" line is how a reader of a key=value file expects to be told.
printf '%s\n' \
  '# curl-urlapi-rs reference summary. DATA, NOT SHELL: the keys contain' \
  '# dashes and are therefore not valid shell identifiers, so this file' \
  '# cannot be sourced. Parse it with sed, the way check-abi.sh and' \
  '# run-parity.sh do. Do not act on it unless result=pass.' \
  > "${FACTS_INPROGRESS}"

# Replaces the published summary with the in-progress file plus one verdict
# line, atomically.
#
# Atomic matters here for a reason particular to this workflow: run-parity.sh
# can legitimately be started while this script is still running -- a person
# working through a failure does exactly that -- and rename() is the only way
# to guarantee it reads either the whole old file or the whole new one and
# never half of either. Appending to the published file would give it a third
# possibility.
#
#   $1  the verdict to record
publish_facts() {
  local verdict="${1}"
  local staged

  if [ -z "${FACTS_INPROGRESS}" ] || [ ! -f "${FACTS_INPROGRESS}" ]; then
    return 0
  fi

  if ! staged="$(mktemp "${BUILD}/reference-build.env.XXXXXX")"; then
    printf 'build-reference.sh: warning: %s\n' \
      "could not stage the summary file, so ${FACTS_FILE} was left alone" >&2
    return 1
  fi

  cat "${FACTS_INPROGRESS}" > "${staged}"
  printf 'result=%s\n' "${verdict}" >> "${staged}"
  if ! mv -f -- "${staged}" "${FACTS_FILE}"; then
    rm -f -- "${staged}"
    printf 'build-reference.sh: warning: %s\n' \
      "could not publish the summary to ${FACTS_FILE}" >&2
    return 1
  fi
  return 0
}

# Publishes the verdict on every exit path, then hands the original status
# back so that nothing here changes what the script exits with.
#
# The suppression below is for a known limitation of the static analyser
# rather than for a finding. This script ends with an unconditional
# "exit ${FINAL_STATUS}", so the reachability analysis concludes that nothing
# after that point runs -- and a handler installed with trap does run after
# it, which is the whole purpose of a handler. The analyser's own diagnostic
# says as much: "or ignore if invoked indirectly". Reshaping the control flow
# to satisfy it would trade a clear statement of the exit contract for an
# obscure one, so the limitation is named here instead.
# shellcheck disable=SC2317
on_exit() {
  local status=$?

  publish_facts "${RESULT}" || true
  if [ -n "${FACTS_INPROGRESS}" ]; then
    rm -f -- "${FACTS_INPROGRESS}"
  fi
  return "${status}"
}
trap 'on_exit' EXIT

# The provenance keys, written first so that they are present in the
# in-progress summary a consumer might read mid-run.
fact "schema" "curl-urlapi-rs/build-reference/1"
fact "generated-by" "rust-urlapi/scripts/build-reference.sh"

# Published the moment those two literal keys are in place, and no later.
#
# The ordering is the point. Everything after this line can fail -- a value
# refused for a control character, a failed CMake configure, a baseline that
# does not pass lib1560 -- and each of those failures has to leave a file that
# says so. Publishing later leaves a window in which a failure inside the
# intervening facts finds the PREVIOUS run's result=pass still on disk, which
# is the staleness this whole arrangement exists to remove. Two literal keys
# cannot fail, so this is the earliest point at which the file is worth
# publishing and the latest at which it is safe to wait.
publish_facts 'in-progress' || true

# Seconds since the epoch, which is what a consumer needs to answer "is this
# summary older than the artifact it names?". Bash supplies it without an
# external command, so there is no tool to check for.
fact "generated-at" "${EPOCHSECONDS:-0}"

# Which commit this baseline was built from, so that check-abi.sh and
# run-parity.sh can refuse to pair a Rust build from one revision with a
# reference build from another. git is OPTIONAL and deliberately absent from
# the prerequisite table below: this script is meant to work in an exported
# tree with no .git at all, which is also why REPO_ROOT is derived from the
# directory layout rather than from git. Without it the fact reads unknown and
# the consumers say so instead of pretending to have checked.
SOURCE_REVISION='unknown'
if command -v git > /dev/null 2>&1; then
  SOURCE_REVISION="$(git -C "${REPO_ROOT}" rev-parse HEAD 2> /dev/null ||
                     printf 'unknown')"
fi
fact "source-revision" "${SOURCE_REVISION}"

fact "crate-dir" "${CRATE_DIR}"
fact "repo-root" "${REPO_ROOT}"
fact "build-root" "${BUILD}"
fact "cmake-dir" "${REFERENCE_DIR}"
fact "log" "${LOG_FILE}"

say "curl-urlapi-rs reference baseline"
say "crate directory:      ${CRATE_DIR}"
say "repository root:      ${REPO_ROOT}"
say "scratch directory:    ${BUILD}"
say "CMake build tree:     ${REFERENCE_DIR}"
say "build log:            ${LOG_FILE}"

section "Prerequisites"

# Collected rather than reported one at a time, so that a caller setting a
# machine up learns everything that is missing from a single run instead of
# discovering the next item after installing the last.
MISSING=()

# Every command this script invokes, paired with the Debian/Ubuntu package
# that supplies it. The claim this table makes is that it is COMPLETE, and the
# claim is meant literally: the list was built by extracting every command
# position from this file rather than by recollection, because a table that is
# merely nearly complete produces the failure it exists to prevent -- a
# missing tool discovered minutes into a build instead of in this section.
#
# Three commands necessarily escape it, and each is named rather than left as
# a silent gap:
#
#   mkdir and rm ran a moment ago, creating and clearing the scratch tree,
#   because the build log has to exist before this section can record anything
#   into it. Both are listed anyway;
#
#   mktemp created the in-progress summary file, for the same reason. Listed;
#
#   git is deliberately NOT required. It is consulted once, for the commit the
#   baseline was built from, and this script has to work in an exported tree
#   with no .git in it -- so its absence records source-revision=unknown and
#   is not a prerequisite failure.
#
# Shell builtins are absent by definition: printf, cd, pwd, read, command,
# trap, umask and the arithmetic and pattern-matching constructs need nothing
# installed. So is valgrind, which only --valgrind reaches and which that
# option checks for itself.
REQUIRED_TOOLS=(
  "${CC_BIN}:build-essential (or set CC to a working compiler)"
  "cmake:cmake"
  "make:make"
  "pkg-config:pkg-config"
  "ar:binutils"
  "nm:binutils"
  "sh:dash"
  "awk:gawk"
  "grep:grep"
  "find:findutils"
  "diff:diffutils"
  "cmp:diffutils"
  "cat:coreutils"
  "chmod:coreutils"
  "cp:coreutils"
  "env:coreutils"
  "getconf:libc-bin"
  "head:coreutils"
  "ln:coreutils"
  "mkdir:coreutils"
  "mktemp:coreutils"
  "mv:coreutils"
  "nproc:coreutils"
  "rm:coreutils"
  "sha256sum:coreutils"
  "sort:coreutils"
  "tail:coreutils"
  "tee:coreutils"
  "tr:coreutils"
  "wc:coreutils"
)

for entry in "${REQUIRED_TOOLS[@]}"; do
  tool="${entry%%:*}"
  package="${entry#*:}"
  # command -v, never which: .github/scripts/shellcheck.sh enables
  # deprecate-which, and command -v is a shell builtin that needs nothing
  # installed to answer.
  if command -v "${tool}" > /dev/null 2>&1; then
    # Recorded rather than printed: twenty confirmations of the obvious would
    # bury the four version lines that a reader of this section actually
    # needs. The log keeps the full record.
    logonly "  found tool ${tool}"
  else
    MISSING+=("tool ${tool} -- install the ${package} package")
  fi
done
say "  ${#REQUIRED_TOOLS[@]} required tools checked"

# autoconf and automake are deliberately absent from that list. They appear in
# the reference environment this script compares against, but no autotools
# path is offered here: the reference build is driven entirely through CMake,
# so requiring them would report a prerequisite that nothing uses.

# Holds the version discovered by the last probe_pkg() call. A global rather
# than a return value because the caller has to be able to queue a diagnostic
# into MISSING, and a command substitution would run in a subshell and lose
# the append.
PROBE_VERSION=""

# Probes for a development library through pkg-config.
#   $1  pkg-config module name
probe_pkg() {
  PROBE_VERSION=""
  if ! command -v pkg-config > /dev/null 2>&1; then
    return 1
  fi
  if pkg-config --exists "${1}" 2> /dev/null; then
    PROBE_VERSION="$(pkg-config --modversion "${1}" 2> /dev/null || true)"
    if [ -z "${PROBE_VERSION}" ]; then
      PROBE_VERSION="unknown"
    fi
    return 0
  fi
  return 1
}

# Fallback probe for a library with no pkg-config file, which is the common
# case for LDAP. Compiles and links a trivial program so that the answer
# covers the library and not only the header.
#   $1  header to include
#   $2  first link flag
#   $3  second link flag
probe_link() {
  local dir
  local status=0

  # A private directory per probe, created with mktemp -d, rather than two
  # fixed names under the scratch tree. The fixed names were predictable, so
  # writing the source through one of them would follow a symlink planted
  # there, and the compiler would then write its output through the other. A
  # directory nothing can guess removes both, and removing the directory
  # removes both files with it.
  if ! dir="$(mktemp -d "${BUILD}/link-probe.XXXXXX")"; then
    return 1
  fi

  printf '%s\n' "#include <${1}>" "int main(void) { return 0; }" \
    > "${dir}/probe.c"
  if ! "${CC_BIN}" -o "${dir}/probe" "${dir}/probe.c" "${2}" "${3}" \
         > /dev/null 2>&1; then
    status=1
  fi
  rm -rf -- "${dir:?}"
  return "${status}"
}

# Versions of the reference environment this baseline is compared against,
# recorded in AAP 0.10.6. A difference is warned about and never fatal: a
# newer toolchain is the normal case and the parity diff is between two
# binaries built by the SAME toolchain, so a mismatch with the table below
# cannot by itself invalidate a result. It is reported because it is the
# first thing to look at when two machines disagree.
REF_CC_VERSION="13.3.0"
REF_MAKE_VERSION="4.3"
REF_PKGCONFIG_VERSION="1.8.1"
REF_CMAKE_VERSION="3.28.3"
REF_SSL_VERSION="3.0.13"
REF_IDN2_VERSION="2.3.7"
REF_LDAP_VERSION="2.6.10"

MISMATCHES=()

# Records one discovered version, comparing it with the reference
# environment. Both values reach the log; a difference also reaches the
# aggregated warning printed at the end of this section.
#   $1  label
#   $2  discovered version
#   $3  reference version
record_version() {
  if [ "${2}" = "${3}" ]; then
    say "  ${1}: ${2} (matches the reference environment)"
  else
    say "  ${1}: ${2} (reference environment: ${3})"
    MISMATCHES+=("${1} ${2} against the reference ${3}")
  fi
}

CC_VERSION="$("${CC_BIN}" -dumpfullversion 2> /dev/null ||
              "${CC_BIN}" -dumpversion 2> /dev/null || echo unknown)"
CC_VERSION="$(version_token "${CC_VERSION}")"
MAKE_VERSION="$(version_token \
  "$(make --version 2> /dev/null | head -n 1 || true)")"
PKGCONFIG_VERSION="$(version_token \
  "$(pkg-config --version 2> /dev/null | head -n 1 || true)")"
CMAKE_VERSION="$(version_token \
  "$(cmake --version 2> /dev/null | head -n 1 || true)")"

record_version "C compiler (${CC_BIN})" "${CC_VERSION}" "${REF_CC_VERSION}"
record_version "GNU make" "${MAKE_VERSION}" "${REF_MAKE_VERSION}"
record_version "pkg-config" "${PKGCONFIG_VERSION}" "${REF_PKGCONFIG_VERSION}"
record_version "CMake" "${CMAKE_VERSION}" "${REF_CMAKE_VERSION}"

# The three development libraries the reference build must have, and the one
# it merely benefits from. SSL, IDN and LDAP are not optional: without SSL and
# LDAP the resulting protocol set omits https and ldap, and
# tests/data/test1560:L17-L25 declares both among the nine features it
# requires, so scheme-dependent assertions in the test would then diverge for
# reasons that have nothing to do with the port.
#
# The four package names named below are the ones curl's own CI installs:
# libidn2-dev and libldap-dev at .github/workflows/linux.yml:L76 and L180,
# libssl-dev at its L215 and zlib1g-dev at its L419.
SSL_VERSION="unknown"
if probe_pkg openssl; then
  SSL_VERSION="${PROBE_VERSION}"
  record_version "OpenSSL" "${SSL_VERSION}" "${REF_SSL_VERSION}"
else
  MISSING+=("library OpenSSL -- install the libssl-dev package")
fi

IDN2_VERSION="unknown"
if probe_pkg libidn2; then
  IDN2_VERSION="${PROBE_VERSION}"
  record_version "libidn2" "${IDN2_VERSION}" "${REF_IDN2_VERSION}"
else
  MISSING+=("library libidn2 -- install the libidn2-dev package")
fi

ZLIB_VERSION="unknown"
if probe_pkg zlib; then
  ZLIB_VERSION="${PROBE_VERSION}"
  say "  zlib: ${ZLIB_VERSION}"
else
  MISSING+=("library zlib -- install the zlib1g-dev package")
fi

# LDAP is the one that regularly has no pkg-config file, so a failed probe
# falls back to compiling and linking against it and says which answer was
# used. Only when both fail is the library reported missing.
LDAP_VERSION="unknown"
if probe_pkg ldap; then
  LDAP_VERSION="${PROBE_VERSION}"
  record_version "LDAP" "${LDAP_VERSION}" "${REF_LDAP_VERSION}"
elif probe_link ldap.h -lldap -llber; then
  say "  LDAP: present, version unknown -- pkg-config has no ldap module" \
      "here, so this was established by compiling and linking against" \
      "<ldap.h> with -lldap -llber instead"
else
  MISSING+=("library LDAP -- install the libldap-dev package")
fi

# The crate-local inputs and the repository landmarks. Checked here, with
# everything else, rather than at the point of use: a missing harness source
# reported now names itself, while the same absence discovered during the
# compile arrives as a compiler diagnostic that says considerably less.
REQUIRED_FILES=(
  "${CRATE_DIR}/Cargo.toml"
  "${HARNESS_SHIM}"
  "${HARNESS_RUNNER}"
  "${HARNESS_MAIN}"
  "${DEMO_SOURCE}"
  "${REPO_ROOT}/CMakeLists.txt"
  "${REPO_ROOT}/include/curl/urlapi.h"
  "${REPO_ROOT}/lib/urlapi.c"
  "${REPO_ROOT}/tests/data/test1560"
  "${TEST_SOURCE}"
)

for required in "${REQUIRED_FILES[@]}"; do
  if [ -f "${required}" ]; then
    logonly "  found file ${required}"
  else
    MISSING+=("file ${required} -- expected to exist and be readable")
  fi
done
say "  ${#REQUIRED_FILES[@]} required input files checked"

if [ "${#MISSING[@]}" -gt 0 ]; then
  printf 'build-reference.sh: error: %s\n' \
    "${#MISSING[@]} prerequisite(s) missing; nothing was built" >&2
  for item in "${MISSING[@]}"; do
    printf '  missing: %s\n' "${item}" >&2
    logonly "  missing: ${item}"
  done
  printf '%s\n' \
    "On Debian and Ubuntu the whole set is:" \
    "  sudo apt-get install build-essential cmake make pkg-config \\" \
    "    libssl-dev libidn2-dev libldap-dev zlib1g-dev" >&2
  exit 1
fi

if [ "${#MISMATCHES[@]}" -gt 0 ]; then
  for item in "${MISMATCHES[@]}"; do
    warn "version mismatch: this environment has ${item}; not fatal"
  done
fi

say "  all prerequisites present"

section "Reference libcurl: configure"

# Parallelism. CMake's --parallel with no number hands the Make generator a
# bare -j, which is unbounded and can start one compiler per source file;
# libcurl has 178 of them, so the count is always given explicitly.
#
# nproc is asked first and getconf only as a fallback, because the two do not
# agree inside a container: nproc reports the processors this process may
# actually run on, honoring its affinity mask and cgroup limits, while
# getconf _NPROCESSORS_ONLN reports what the host has. Measured in a
# four-processor container on a 128-processor host, getconf answered 128 --
# which is the unbounded-parallelism problem back again by another route.
if [ -z "${JOBS}" ]; then
  JOBS="$(nproc 2> /dev/null || getconf _NPROCESSORS_ONLN 2> /dev/null ||
          echo 4)"
fi
say "  parallel jobs: ${JOBS}"

# Every option is passed explicitly, including the ones that merely restate
# the current default, so that the configuration is self-documenting and
# immune to an upstream default change. The four that carry real consequences
# are annotated.
CMAKE_OPTIONS=(
  "-DCMAKE_BUILD_TYPE=RelWithDebInfo"

  # BUILD_STATIC_LIBS is the critical one, and it is NOT the default:
  # CMakeLists.txt:L181 declares it OFF. Without it there is no archive at
  # all, and the drop-in mode of run-parity.sh has nothing to delete the
  # urlapi member from.
  "-DBUILD_STATIC_LIBS=ON"
  "-DBUILD_SHARED_LIBS=OFF"

  # ENABLE_DEBUG must stay off: reported constraint R3, printed in full at
  # the end of this run. CMakeLists.txt:L259 declares it and L265-L267
  # appends DEBUGBUILD; lib/curl_setup.h:L1327-L1329 turns DEBUGBUILD into
  # CURL_MEMDEBUG; and under CURL_MEMDEBUG the allocator macros at
  # lib/curl_setup.h:L1453-L1461 make curlx_free() expand to
  # curl_dbg_free(ptr, __LINE__, __FILE__). That function does not consult its
  # allocation table before releasing anything and rejects nothing: it
  # subtracts the offset of the payload within its own header struct from the
  # pointer it was given and frees that address unconditionally
  # (lib/memdebug.c:L362-L385). The Rust crate takes the buffers it hands to C
  # from the C allocator, and those carry no such header, so the address handed
  # to the real deallocator would not be the start of any allocation. That is
  # heap corruption rather than a diagnostic, which is why this is a
  # configuration to avoid rather than one to detect.
  "-DENABLE_DEBUG=OFF"

  # CURL_LTO must stay off. lib/CMakeLists.txt gates
  # INTERPROCEDURAL_OPTIMIZATION on CURL_HAS_LTO, and with it on the archive
  # members are intermediate representation rather than real object files --
  # so "delete one member and relink" would stop behaving like a plain object
  # substitution, which is precisely what the drop-in link is.
  "-DCURL_LTO=OFF"

  # SSL, IDN and LDAP on. See the protocol assertion below for why each is
  # mandatory rather than merely desirable.
  "-DCURL_ENABLE_SSL=ON"
  "-DCURL_USE_OPENSSL=ON"
  "-DUSE_LIBIDN2=ON"
  "-DCURL_DISABLE_LDAP=OFF"
  "-DCURL_DISABLE_LDAPS=OFF"

  # Nothing but the library is needed, and skipping the rest is most of the
  # wall-clock cost of this script. None of these four touches the library
  # configuration: they gate separate targets.
  "-DBUILD_CURL_EXE=OFF"
  "-DBUILD_TESTING=OFF"
  "-DBUILD_EXAMPLES=OFF"
  "-DBUILD_LIBCURL_DOCS=OFF"
  "-DENABLE_CURL_MANUAL=OFF"

  # Left on so that CMakeLists.txt generates curl-config, which is where the
  # link line and the protocol set are read from below. Nothing is installed:
  # the install targets are simply never built.
  "-DCURL_DISABLE_INSTALL=OFF"
)

# UNITTESTS is deliberately absent from that list, and its absence is
# load-bearing for check-abi.sh. lib/curl_setup.h:L1505-L1509 makes UNITTEST
# expand to nothing under UNITTESTS and to "static" otherwise, and
# lib/urlapi.c has two UNITTEST-marked symbols -- Curl_parse_port at its L335
# and dedotdotify at L715-L716. Without UNITTESTS the module's object defines
# exactly the eight globals the port has to match; with it, ten. In this tree
# the macro reaches only the separate curlu target (lib/CMakeLists.txt:L46)
# and never libcurl itself, so leaving it alone is enough -- and the symbol
# assertion below proves it rather than trusting it.

mkdir -p "${REFERENCE_DIR}"

# Configured out of tree, always. An in-tree configure would leave generated
# files scattered through the repository that the root .gitignore does not
# cover, and acceptance criterion A12 requires "git status --porcelain" to
# report only additions under rust-urlapi/ after a full run.
say "  configuring ${REFERENCE_DIR} from ${REPO_ROOT}"
if ! cmake -S "${REPO_ROOT}" -B "${REFERENCE_DIR}" "${CMAKE_OPTIONS[@]}" 2>&1 |
     tee -a "${LOG_FILE}"; then
  fatal "CMake configuration of the reference build failed; see ${LOG_FILE}"
fi

section "Reference libcurl: build"

if ! cmake --build "${REFERENCE_DIR}" --parallel "${JOBS}" 2>&1 |
     tee -a "${LOG_FILE}"; then
  fatal "the reference libcurl build failed; see ${LOG_FILE}"
fi

section "Reference libcurl: verification"

# The archive is searched for rather than assumed. CMakeLists.txt:L156 sets
# LIB_NAME to libcurl and lib/CMakeLists.txt sets PREFIX "" with OUTPUT_NAME
# "${LIBCURL_OUTPUT_NAME}" and SUFFIX
# "${STATIC_LIB_SUFFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}", STATIC_LIB_SUFFIX
# defaulting to empty, which yields <build>/lib/libcurl.a here -- but a
# caller who sets STATIC_LIB_SUFFIX, or a future rename, would move it, and a
# hard-coded path would then fail with a confusing diagnostic instead of this
# one.
#
# EXACTLY ONE candidate is required, and this is the part worth being strict
# about. An earlier version took the first match in sorted order and stopped,
# which is indistinguishable from a correct answer when it is wrong: a stale
# tree left behind by a differently configured run, or a second archive from a
# subproject, would silently become the baseline every later comparison is
# read against. A wrong baseline does not announce itself as a wrong baseline;
# it announces itself as a parity failure three scripts later. So both zero
# and several are fatal, and both print the full candidate list.
# scripts/check-abi.sh applies the same rule to the member, in
# discover_member, and for the same reason.
ARCHIVE_CANDIDATES="${BUILD}/reference-archive-candidates.txt"
ARCHIVE_MATCHES="${BUILD}/reference-archive-matches.txt"
find "${REFERENCE_DIR}" -name 'libcurl*.a' -type f |
  LC_ALL=C sort > "${ARCHIVE_CANDIDATES}"
: > "${ARCHIVE_MATCHES}"

while IFS= read -r candidate; do
  if [ -z "${candidate}" ]; then
    continue
  fi
  # The right archive is the one that holds the urlapi member; anything else
  # matching the name pattern is not what the drop-in link needs. Both member
  # spellings are accepted: CMake names members after the source file, so the
  # member is urlapi.c.o, while an autotools or libtool build of the same
  # source produces urlapi.o.
  if ar t "${candidate}" 2> /dev/null |
     grep -q -E '^urlapi(\.c)?\.o$'; then
    printf '%s\n' "${candidate}" >> "${ARCHIVE_MATCHES}"
  fi
done < "${ARCHIVE_CANDIDATES}"

ARCHIVE_MATCH_COUNT="$(wc -l < "${ARCHIVE_MATCHES}" | tr -d ' ')"

if [ "${ARCHIVE_MATCH_COUNT}" -eq 0 ]; then
  say "  candidates considered: \
$(wc -l < "${ARCHIVE_CANDIDATES}" | tr -d ' ') (${ARCHIVE_CANDIDATES})"
  fatal "no libcurl archive holding a urlapi object was found under \
${REFERENCE_DIR}. BUILD_STATIC_LIBS defaults to OFF in CMakeLists.txt, so a \
build that produced no archive is the first thing to check; see ${LOG_FILE}"
fi

if [ "${ARCHIVE_MATCH_COUNT}" -ne 1 ]; then
  while IFS= read -r candidate; do
    say "  candidate: ${candidate}"
  done < "${ARCHIVE_MATCHES}"
  fatal "${ARCHIVE_MATCH_COUNT} archives under ${REFERENCE_DIR} hold a \
urlapi object, and exactly one is required. Every later comparison is read \
against whichever archive is chosen here, so choosing is not this script's \
to do. A stale build tree from a differently configured run is the usual \
cause: remove ${REFERENCE_DIR} and run this script again, or point \
REFERENCE_BUILD_DIR at a directory of its own. The full candidate list is in \
${ARCHIVE_MATCHES} and every libcurl*.a considered is in \
${ARCHIVE_CANDIDATES}"
fi

REFERENCE_ARCHIVE="$(cat "${ARCHIVE_MATCHES}")"
say "  archive: ${REFERENCE_ARCHIVE}"

ARCHIVE_MEMBERS="$(ar t "${REFERENCE_ARCHIVE}" | wc -l | tr -d ' ')"
say "  archive members: ${ARCHIVE_MEMBERS}"

# The member name is discovered, never hard-coded, and is recorded in the
# summary file so that run-parity.sh -- which deletes this member from a copy
# of the archive to make room for the Rust one -- consumes the fact instead of
# re-deriving it.
#
# EXACTLY ONE match again, and here the stakes are higher than at the archive:
# run-parity.sh deletes this member by name, so taking the first of several
# would leave a second copy of the C implementation in the archive and the
# link would then resolve the eight symbols from it or fail on duplicates,
# either way measuring something other than the port. The pattern is
# deliberately wider than the anchored one used to find the archive, because a
# member whose name merely contains urlapi is still a candidate worth
# reporting.
MEMBER_MATCHES="${BUILD}/reference-member-matches.txt"
ar t "${REFERENCE_ARCHIVE}" | grep -E 'urlapi' > "${MEMBER_MATCHES}" || true
MEMBER_MATCH_COUNT="$(wc -l < "${MEMBER_MATCHES}" | tr -d ' ')"

if [ "${MEMBER_MATCH_COUNT}" -ne 1 ]; then
  while IFS= read -r member; do
    say "  member candidate: ${member}"
  done < "${MEMBER_MATCHES}"
  fatal "${MEMBER_MATCH_COUNT} members of ${REFERENCE_ARCHIVE} match urlapi, \
and exactly one is required. CMake names the member urlapi.c.o, autotools \
urlapi.o and libtool libcurl_la-urlapi.o; none of those spellings is assumed \
here, so a count other than one means this is not a libcurl archive built \
from one lib/Makefile.inc:267 entry. run-parity.sh deletes this member by \
name to make room for the Rust archive, so a second copy would leave the C \
implementation in the link. The candidate list is in ${MEMBER_MATCHES}"
fi

REFERENCE_URLAPI_MEMBER="$(cat "${MEMBER_MATCHES}")"
say "  urlapi member: ${REFERENCE_URLAPI_MEMBER}"

# Extracted so that check-abi.sh has the exact object the Rust archive has to
# match, and so that the symbol assertion below runs on a real object file.
REFERENCE_URLAPI_OBJECT="${BIN_DIR}/urlapi-reference.o"
fresh_path "${REFERENCE_URLAPI_OBJECT}"
if ! ar p "${REFERENCE_ARCHIVE}" "${REFERENCE_URLAPI_MEMBER}" \
       > "${REFERENCE_URLAPI_OBJECT}"; then
  fatal "could not extract ${REFERENCE_URLAPI_MEMBER} from \
${REFERENCE_ARCHIVE}"
fi

# nm succeeding on that object is also the link-time-optimization check: an
# archive member built with LTO carries intermediate representation, not a
# symbol table, and nm reports no symbols for it. The POSIX output format is
# asked for so that the symbol name is the first field regardless of address
# width, and the sort is pinned to the C locale so that the order does not
# depend on the caller's environment -- there, and only there, do
# Curl_-prefixed names sort ahead of curl_-prefixed ones.
REFERENCE_URLAPI_SYMBOLS="$(nm -g --defined-only -P \
  "${REFERENCE_URLAPI_OBJECT}" | awk '{ print $1 }' | LC_ALL=C sort |
  tr '\n' ' ')"
REFERENCE_URLAPI_SYMBOLS="${REFERENCE_URLAPI_SYMBOLS% }"
say "  urlapi globals: ${REFERENCE_URLAPI_SYMBOLS}"

# The eight globals lib/urlapi.c defines: Curl_is_absolute_url (its L182),
# Curl_junkscan (L223), Curl_url_set_authority (L658), curl_url (L1288),
# curl_url_cleanup (L1293), curl_url_dup (L1310), curl_url_get (L1541) and
# curl_url_set (L1805). Sorted, because the comparison is against a sorted
# list. Note that curl_url_strerror is NOT among them -- it lives in
# lib/strerror.c -- and neither is curl_free, which lives in lib/escape.c.
EXPECTED_URLAPI_SYMBOLS="Curl_is_absolute_url Curl_junkscan \
Curl_url_set_authority curl_url curl_url_cleanup curl_url_dup curl_url_get \
curl_url_set"

if [ "${REFERENCE_URLAPI_SYMBOLS}" != "${EXPECTED_URLAPI_SYMBOLS}" ]; then
  fatal "the reference urlapi object exports \
[${REFERENCE_URLAPI_SYMBOLS}] but the drop-in contract is \
[${EXPECTED_URLAPI_SYMBOLS}]. Two extra names, Curl_parse_port and \
dedotdotify, appear when UNITTESTS is defined for libcurl, which would make \
the symbol-set equality check-abi.sh performs unachievable; no symbols at \
all is what an archive built with link-time optimization looks like. Neither \
is configured here, so a mismatch means the reference configuration was \
overridden"
fi
say "  urlapi globals match the eight-symbol drop-in contract"

# Digests of the archive and of the extracted object, recorded so that the
# downstream scripts can bind the paths this summary hands them to the bytes
# this run actually produced.
#
# The need is concrete rather than theoretical. check-abi.sh reads a symbol
# table out of the object named here and declares the drop-in surface correct
# or incorrect on the strength of it; run-parity.sh copies the archive named
# here, deletes a member from the copy and links against the result. Both
# operate minutes or hours after this script finished, on paths inside a
# scratch tree that is deliberately reusable. Without a digest, "the file at
# the recorded path" and "the file this run built" are two different claims
# that happen to coincide most of the time. run-parity.sh also uses the
# archive digest for a second purpose: comparing it before and after the copy
# is what proves the original was never modified.
#
# sha256sum is a prerequisite for exactly this, and is listed as one.
REFERENCE_ARCHIVE_SHA256="$(sha256sum "${REFERENCE_ARCHIVE}" |
  awk '{ print $1 }')"
REFERENCE_URLAPI_OBJECT_SHA256="$(sha256sum "${REFERENCE_URLAPI_OBJECT}" |
  awk '{ print $1 }')"
say "  archive sha256: ${REFERENCE_ARCHIVE_SHA256}"
say "  object sha256:  ${REFERENCE_URLAPI_OBJECT_SHA256}"

# Memory debugging, asserted empirically rather than inferred from the
# options. If DEBUGBUILD had reached the library, lib/memdebug.c would define
# curl_dbg_free and the tracking free described at the ENABLE_DEBUG option
# above would be in the link. The grep is guarded because grep exits non-zero
# when it matches nothing, which is the passing case here.
REFERENCE_MEMDEBUG="off"
if nm -g --defined-only -P "${REFERENCE_ARCHIVE}" 2> /dev/null |
   awk '{ print $1 }' | grep -q -x 'curl_dbg_free'; then
  fatal "the reference archive defines curl_dbg_free, so it was built with \
memory debugging enabled. curlx_free() then expands to that function, which \
subtracts its own header from the pointer and frees that address without any \
lookup, so a buffer the Rust crate allocated with the C allocator would \
corrupt the heap rather than be refused. Reconfigure with -DENABLE_DEBUG=OFF"
fi
say "  memory debugging: ${REFERENCE_MEMDEBUG} (no curl_dbg_free defined)"

# curl-config is generated by CMakeLists.txt into the build tree root. It is
# generated without the execute bit, so it is run through sh.
CURL_CONFIG="${REFERENCE_DIR}/curl-config"
if [ ! -f "${CURL_CONFIG}" ]; then
  fatal "${CURL_CONFIG} was not generated. It is produced under \
\"if(NOT CURL_DISABLE_INSTALL)\" in CMakeLists.txt, and this script needs it \
for both the protocol set and the link line"
fi

# The protocol set, lower-cased for comparison with the feature names
# tests/data/test1560 uses. curl-config is the primary source because it is
# generated from the same variables the configure summary prints; the
# configure log is the fallback for a tree configured before this check
# existed.
REFERENCE_PROTOCOLS="$(sh "${CURL_CONFIG}" --protocols 2> /dev/null |
  tr '[:upper:]' '[:lower:]' | LC_ALL=C sort | tr '\n' ' ' || true)"
if [ -z "${REFERENCE_PROTOCOLS}" ]; then
  REFERENCE_PROTOCOLS="$(grep -E '^-- Protocols:' "${LOG_FILE}" |
    tail -n 1 | tr '[:upper:]' '[:lower:]' || true)"
  REFERENCE_PROTOCOLS="${REFERENCE_PROTOCOLS#*protocols:}"
fi
REFERENCE_PROTOCOLS="${REFERENCE_PROTOCOLS# }"
REFERENCE_PROTOCOLS="${REFERENCE_PROTOCOLS% }"
say "  protocols: ${REFERENCE_PROTOCOLS}"

# The nine features tests/data/test1560:L17-L25 declares. Every one is
# asserted, not just the two that a missing library removes: the URL parser
# only accepts schemes this instance of libcurl supports, which
# tests/libtest/lib1560.c:L28-L30 says in as many words, so a reference build
# missing any of them makes scheme-dependent assertions diverge for reasons
# that have nothing to do with the port.
REQUIRED_PROTOCOLS=(file https http pop3 smtp imap ldap dict ftp)
MISSING_PROTOCOLS=()
for protocol in "${REQUIRED_PROTOCOLS[@]}"; do
  case " ${REFERENCE_PROTOCOLS} " in
    *" ${protocol} "*)
      ;;
    *)
      MISSING_PROTOCOLS+=("${protocol}")
      ;;
  esac
done

if [ "${#MISSING_PROTOCOLS[@]}" -gt 0 ]; then
  fatal "the reference build lacks $(printf '%s ' \
"${MISSING_PROTOCOLS[@]}")-- tests/data/test1560 declares all nine of \
${REQUIRED_PROTOCOLS[*]} as required features. A configuration without SSL \
and LDAP yields no https and no ldap, so check that libssl-dev and \
libldap-dev were visible to CMake; see ${LOG_FILE}"
fi
say "  all nine features tests/data/test1560 declares are present"

# The system libraries the archive itself needs. Derived from the generated
# curl-config rather than hard-coded, because the set depends on what CMake
# actually found. Its --static-libs output leads with the INSTALLED archive
# path, which does not exist in an uninstalled build tree, so only the flags
# are kept and the archive found above is named separately. The Rust
# staticlib brings its own additional system dependencies; run-parity.sh adds
# those to the list recorded in the summary file.
REFERENCE_SYSTEM_LIBS="$(sh "${CURL_CONFIG}" --static-libs 2> /dev/null |
  tr ' ' '\n' | grep -E '^-' | tr '\n' ' ' || true)"
REFERENCE_SYSTEM_LIBS="${REFERENCE_SYSTEM_LIBS}-lpthread -ldl -lm"
say "  system libraries: ${REFERENCE_SYSTEM_LIBS}"

REFERENCE_FEATURES="$(sh "${CURL_CONFIG}" --features 2> /dev/null |
  LC_ALL=C sort | tr '\n' ' ' || true)"
REFERENCE_FEATURES="${REFERENCE_FEATURES% }"
say "  features: ${REFERENCE_FEATURES}"

# IDN consistency between the library and the harness, checked because getting
# it wrong produces a failure that looks exactly like a port defect and is not
# one.
#
# tests/libtest/lib1560.c:L34-L36 folds USE_LIBIDN2, USE_WIN32_IDN and
# USE_APPLE_IDN into USE_IDN, and USE_IDN decides which rows the test compiles.
# Those rows have to agree with what the linked libcurl actually does. Measured
# here, on this baseline: compiling the harness with no IDN define while
# linking a libcurl that has libidn2 makes lib1560 fail its get_parts sub-test
# (exit 4) under EVERY locale -- the test asserting one behavior while the
# library performs the other. Nothing about the port is involved.
#
# Reported rather than fatal, and loudly: the golden files this run captured
# are still a faithful record of what that combination does, and a caller may
# be exploring it deliberately. The non-zero exit status at the end is what
# says the run needs a second look.
REFERENCE_IDN="off"
case " ${REFERENCE_FEATURES} " in
  *" IDN "*)
    REFERENCE_IDN="on"
    ;;
esac

HARNESS_IDN="off"
case " ${HARNESS_DEFINES} " in
  *" -DUSE_LIBIDN2"* | *" -DUSE_WIN32_IDN"* | *" -DUSE_APPLE_IDN"*)
    HARNESS_IDN="on"
    ;;
esac

if [ "${REFERENCE_IDN}" = "${HARNESS_IDN}" ]; then
  say "  IDN: ${REFERENCE_IDN} in the library and ${HARNESS_IDN} in the" \
      "harness, which agree"
else
  warn "IDN is ${REFERENCE_IDN} in the reference libcurl but ${HARNESS_IDN} \
in the harness compilation (HARNESS_DEFINES is [${HARNESS_DEFINES}]). \
tests/libtest/lib1560.c compiles a different set of assertions either way, so \
lib1560 will fail for a reason that has nothing to do with the port. Add or \
remove -DUSE_LIBIDN2 in HARNESS_DEFINES, or reconfigure the library, so that \
the two agree"
  FINAL_STATUS=1
fi

section "Staging the unmodified test source"

# KEEP IN STEP WITH run-parity.sh.
#
# Both harness binaries -- the reference one built below and the Rust one
# run-parity.sh builds -- have to compile from the SAME staged inputs, or the
# byte-for-byte diff of their output compares two different test suites. The
# arrangement is therefore that this function owns the staging and
# run-parity.sh reuses the directory this script leaves behind, whose path is
# recorded as harness-stage-dir in the summary file. Should run-parity.sh ever
# need to stage on its own -- to run without a preceding reference build --
# its copy of these three steps must be kept identical to this one, and this
# comment is the reason each step is the way it is.
#
# Why a staging directory exists at all: tests/libtest/lib1560.c:L33 contains
# exactly one include, a quoted "first.h", and a quoted include is searched in
# the directory the compiler opened the INCLUDING file from before any -I
# path. Compiling the test source in place would therefore always resolve
# first.h to the real tests/libtest/first.h, 574 lines that pull in libcurl's
# private build environment at its L33 and L46. Reaching the test source
# through this directory instead puts the ~20-line shim in that position. It
# is the only arrangement that honors "the test file is unmodified" and "do
# not touch tests/" at the same time.
stage_test_source() {
  mkdir -p "${STAGE_DIR}"

  # A symlink, never a copy. A copy would be a second instance of a file the
  # port is required to consume byte-unchanged, and it would silently stop
  # tracking the original.
  if ! ln -sfn "${TEST_SOURCE}" "${STAGE_DIR}/lib1560.c"; then
    fatal "could not link ${TEST_SOURCE} into ${STAGE_DIR}"
  fi

  # The shim is copied rather than linked, deliberately: the compiler resolves
  # the quoted include against the directory of the file it opened, and a
  # symlinked header would still be found there, but a copy makes the staged
  # directory self-describing to anyone reading it and cannot be broken by a
  # later move of the crate. It is regenerated on every run so that an edit to
  # harness/first.h is never silently stale here.
  # Removed before it is written, for the reason fresh_path() gives: cp -f
  # opens an existing symlink's TARGET and writes through it, so a link
  # planted at this predictable path would let the copy land outside the
  # staging directory. Removing the link first means cp always creates a
  # regular file here.
  fresh_path "${STAGE_DIR}/first.h"
  if ! cp -f "${HARNESS_SHIM}" "${STAGE_DIR}/first.h"; then
    fatal "could not copy ${HARNESS_SHIM} into ${STAGE_DIR}"
  fi
}

stage_test_source
say "  ${STAGE_DIR}/lib1560.c -> ${TEST_SOURCE}"
say "  ${STAGE_DIR}/first.h   <- ${HARNESS_SHIM}"

# Proof that the mechanism took, rather than an assumption that it did. If the
# staged header were ever the real one it would name libcurl's private setup
# header, and every IDN assertion in the test would then depend on a build
# environment this harness does not have.
if grep -q 'HEADER_RUST_URLAPI_HARNESS_FIRST_H' "${STAGE_DIR}/first.h"; then
  say "  staged first.h is the harness shim, not tests/libtest/first.h"
else
  fatal "${STAGE_DIR}/first.h is not the harness shim. The quoted include in \
tests/libtest/lib1560.c would then resolve to libcurl's private build \
environment"
fi

section "Reference harness"

# The include path, and what is deliberately not on it.
#
# -I<stage> supplies the staged test source that HARNESS_TEST_SOURCE names,
# and is also what makes the shim win the test source's own quoted include.
# -I<repo>/include supplies the real public headers from the unmodified tree.
#
# <repo>/lib is NEVER added. The harness must see the public API and nothing
# else; adding it would let the shim's includes reach libcurl's private
# headers and quietly change which assertions the test compiles.
#
# Built as an array first and flattened only for display and for the summary
# file, so that a directory name containing a space survives into the compiler
# argument list intact.
HARNESS_INCLUDES_ARRAY=("-I${STAGE_DIR}" "-I${REPO_ROOT}/include")
HARNESS_INCLUDES="${HARNESS_INCLUDES_ARRAY[*]}"

# The macro that names the staged test source, spelled exactly as
# harness/runner.c expects it: that file guards on HARNESS_TEST_SOURCE and
# emits an #error naming this very spelling when it is undefined, then uses it
# as an include operand, so the value has to arrive complete with its quotes.
HARNESS_TEST_SOURCE_DEFINE="-DHARNESS_TEST_SOURCE=\"lib1560.c\""

# Preprocessor parity, and why it is a hard requirement rather than a detail.
#
# tests/libtest/lib1560.c compiles a different set of assertions depending on
# three macros: USE_IDN, which its L34-L36 derives from USE_LIBIDN2,
# USE_WIN32_IDN or USE_APPLE_IDN; CURL_DISABLE_WEBSOCKETS at its L295; and
# _WIN32 at its L361. harness/runner.c deliberately defines none of them and
# says so, leaving the build as the single owner -- because the build is the
# only place that can hand the reference compilation and the Rust compilation
# an identical set. Whatever is resolved here is written into the summary file
# as harness-defines, and run-parity.sh consumes that value rather than
# choosing its own.
#
# -DUSE_LIBIDN2 is the default because the reference build above links
# libidn2 and the crate binds it too, so the IDN rows at L200-L223 and the
# punycode expectation at L629-L632 have to be live in both. Nothing defines
# CURL_DISABLE_WEBSOCKETS, which is what an ordinary libcurl build gives the
# test, and _WIN32 belongs to the platform.
say "  preprocessor state: ${HARNESS_DEFINES} ${HARNESS_TEST_SOURCE_DEFINE}"
say "  compiler options:   ${HARNESS_CFLAGS}"
say "  include path:       ${HARNESS_INCLUDES}"

# The link line, assembled as an array so that a path containing a space
# survives it. The archive comes before the system libraries, as a static
# archive must.
#
# harness/shims.c is deliberately absent, and so is -DHARNESS_MODE_B: in this
# link the real mprintf.c.o and escape.c.o already define the curl_m*printf
# family and curl_free, and shims.c emits an #error outside Mode B precisely
# so that a mistaken link fails loudly instead of duplicating symbols.
REFERENCE_HARNESS_BIN="${BIN_DIR}/harness-ref"

# The three settings that arrive as single strings -- because they are
# overridable from the environment, and because the summary file records them
# as one value each -- are split into arrays here. Word splitting is the
# intended behavior for a list of compiler flags, which is why it is done
# deliberately through read rather than by leaving an expansion unquoted.
read -r -a HARNESS_CFLAGS_ARRAY <<< "${HARNESS_CFLAGS}"
read -r -a HARNESS_DEFINES_ARRAY <<< "${HARNESS_DEFINES}"
read -r -a REFERENCE_SYSTEM_LIBS_ARRAY <<< "${REFERENCE_SYSTEM_LIBS}"

HARNESS_COMMAND=(
  "${CC_BIN}"
  "${HARNESS_CFLAGS_ARRAY[@]}"
  "${HARNESS_DEFINES_ARRAY[@]}"
  "${HARNESS_TEST_SOURCE_DEFINE}"
  "${HARNESS_INCLUDES_ARRAY[@]}"
  -o "${REFERENCE_HARNESS_BIN}"
  "${HARNESS_RUNNER}"
  "${HARNESS_MAIN}"
  "${REFERENCE_ARCHIVE}"
  "${REFERENCE_SYSTEM_LIBS_ARRAY[@]}"
)

logonly "harness link line: ${HARNESS_COMMAND[*]}"
if ! compile_with_report harness-ref "${HARNESS_COMMAND[@]}"; then
  fatal "the reference harness failed to build or link. The full command and \
the compiler output are in ${LOG_FILE}; a missing system library on the link \
line is the usual cause"
fi
say "  built ${REFERENCE_HARNESS_BIN}"

section "Reference demo"

# Compiled in drop-in form: the real public headers from the unmodified tree,
# and URLAPI_DEMO_STANDALONE deliberately NOT defined. That macro, at
# demo/urlapi_demo.c:L66, selects the mirror header include/curl_urlapi_rs.h
# for the standalone link where no libcurl takes part; here libcurl does, and
# it is also what supplies curl_url_strerror, which lives in lib/strerror.c
# and not in the module being replaced.
#
# The demo performs no network activity by construction -- it creates no easy
# handle, no multi handle and calls no global initializer -- so nothing here
# configures any, and if it ever appeared to, that would be a finding to
# report rather than something to accommodate.
REFERENCE_DEMO_BIN="${BIN_DIR}/demo-ref"

DEMO_COMMAND=(
  "${CC_BIN}"
  "${HARNESS_CFLAGS_ARRAY[@]}"
  "-I${REPO_ROOT}/include"
  -o "${REFERENCE_DEMO_BIN}"
  "${DEMO_SOURCE}"
  "${REFERENCE_ARCHIVE}"
  "${REFERENCE_SYSTEM_LIBS_ARRAY[@]}"
)

logonly "demo link line: ${DEMO_COMMAND[*]}"
if ! compile_with_report demo-ref "${DEMO_COMMAND[@]}"; then
  fatal "the reference demo failed to build or link; the compiler output is \
in ${LOG_FILE}"
fi
say "  built ${REFERENCE_DEMO_BIN}"

section "Golden capture: the harness, under all four environments"

# Three settings gate the internationalized-domain assertions, and dropping
# any one of them makes those assertions silently stop running while the
# harness still prints success -- a false green, which is worse than a
# failure:
#
#   LC_ALL, which tests/data/test1560:L14 sets to C.UTF-8. libidn2 is reached
#   through the lookup macro in lib/idn.c, which off Windows expands to the
#   locale-aware idn2_lookup_ul, so a non-ASCII host converts only while the
#   process codeset is UTF-8.
#
#   setlocale(LC_ALL, ""), which harness/main.c calls, mirroring
#   tests/libtest/first.c:L231. Without it a C program stays in the "C"
#   locale whatever LC_ALL holds. That call belongs to the harness, not here.
#
#   CURL_TEST_HAVE_CODESET_UTF8, which tests/runtests.pl:L836-L839 exports and
#   tests/libtest/lib1560.c:L2036 reads into has_utf8 to gate the punycode
#   rows at its L1446, L1548 and L1591.
#
# All four combinations are captured rather than only the passing one, because
# the reference is the oracle including its failure modes: under LC_ALL=C the
# locale-aware lookup fails every non-ASCII input and that propagates to
# CURLUE_BAD_HOSTNAME, which is a real, reachable divergence run-parity.sh
# has to reproduce rather than avoid.
GOLDEN_LABELS=()
GOLDEN_STATUSES=()

# The name of the sub-test an exit status stands for, transcribed from the
# short-circuiting sequence at tests/libtest/lib1560.c:L2040-L2071. The
# execution order there is not the numeric one, which is why the mapping is
# written out rather than computed: the first sub-test to run is urldup and it
# answers 11. Anything outside 1 through 11 is not a sub-test, and the caller
# below says so rather than naming one.
#
#   $1  the exit status
subtest_name() {
  case "${1}" in
    1)  printf 'set_url' ;;
    2)  printf 'set_parts' ;;
    3)  printf 'get_url' ;;
    4)  printf 'get_parts' ;;
    5)  printf 'append' ;;
    6)  printf 'scopeid' ;;
    7)  printf 'get_nothing' ;;
    8)  printf 'clear_url' ;;
    9)  printf 'huge' ;;
    10) printf 'setget_parts' ;;
    11) printf 'urldup' ;;
    *)  printf 'not a sub-test code' ;;
  esac
}

# Runs the reference harness once and records what it did.
#   $1  label used in the file names
#   $2  LC_ALL value
#   $3  CURL_TEST_HAVE_CODESET_UTF8 value, or empty to unset it
capture_golden() {
  local label="${1}"
  local locale_value="${2}"
  local codeset_value="${3}"
  local out="${GOLDEN_DIR}/harness-${label}.stdout"
  local err="${GOLDEN_DIR}/harness-${label}.stderr"
  local statusfile="${GOLDEN_DIR}/harness-${label}.status"
  local status=0
  local envargs=()

  if [ -n "${codeset_value}" ]; then
    envargs=(env "LC_ALL=${locale_value}"
             "CURL_TEST_HAVE_CODESET_UTF8=${codeset_value}")
  else
    envargs=(env -u CURL_TEST_HAVE_CODESET_UTF8 "LC_ALL=${locale_value}")
  fi

  # stdout and stderr are captured to separate files and never merged.
  # Acceptance rests on a diff of stdout alone: tests/libtest/lib1560.c owns
  # every byte of it, while its failure detail on stderr carries __FILE__ and
  # __LINE__ of the STAGED test source, whose absolute path differs between
  # the reference tree and the Rust one. Merging the two would make the diff
  # fail on the path rather than on the port. harness/main.c sends its "Test
  # ended with result" line to stderr for the same reason, mirroring
  # tests/libtest/first.c:L280.
  #
  # A non-zero status is recorded, never treated as an error of this script:
  # see the LC_ALL=C case above.
  #
  # All three destinations are cleared before they are written. They are
  # predictable paths -- run-parity.sh has to find them by name -- so each is
  # a place a symlink could have been planted, and a plain ">" would follow it.
  fresh_path "${out}"
  fresh_path "${err}"
  fresh_path "${statusfile}"
  "${envargs[@]}" "${REFERENCE_HARNESS_BIN}" > "${out}" 2> "${err}" ||
    status="$?"

  printf '%s\n' "${status}" > "${statusfile}"
  GOLDEN_LABELS+=("${label}")
  GOLDEN_STATUSES+=("${status}")

  say "  ${label}: LC_ALL=${locale_value}" \
      "CURL_TEST_HAVE_CODESET_UTF8=${codeset_value:-<unset>}" \
      "-> status ${status}, stdout $(wc -c < "${out}" | tr -d ' ') bytes"
}

capture_golden "utf8-codeset" "C.UTF-8" "1"
capture_golden "utf8-nocodeset" "C.UTF-8" ""
capture_golden "c-codeset" "C" "1"
capture_golden "c-nocodeset" "C" ""

# The reading of those four, stated so that a later run has something to
# compare against. On a fully passing reference the stdout of a run is the
# single line "success" -- tests/libtest/lib1560.c:L2073, which is what
# tests/data/test1560:L37 expects -- and the status is 0. A non-zero status is
# the number of the sub-test that failed, from the short-circuiting sequence
# at tests/libtest/lib1560.c:L2040-L2071: 1 set_url, 2 set_parts, 3 get_url,
# 4 get_parts, 5 append, 6 scopeid, 7 get_nothing, 8 clear_url, 9 huge,
# 10 setget_parts, 11 urldup. A status of 120 is harness/main.c refusing to
# start because setlocale() could not honor LC_ALL, which is not a sub-test
# failure at all.
# That reading is applied to the fully gated run as a HARD PREREQUISITE rather
# than recorded as an observation. Everything downstream -- the symbol
# comparison in check-abi.sh, and in run-parity.sh the byte-for-byte stdout
# diff, the per-sub-test report and acceptance criteria A5 through A9 -- is a
# comparison against these captures, so if the C baseline does not itself pass
# lib1560 then no parity result drawn from it means anything, whichever way the
# diff comes out. An earlier version of this block warned and carried on with
# FINAL_STATUS untouched, which let the run print "reference baseline complete"
# and exit 0 immediately after recording that no parity conclusion would be
# meaningful. Both halves of the criterion are checked, because either can fail
# on its own: a run can exit 0 having printed nothing, and a run can print
# success on stdout and still exit non-zero.
ORACLE_LABEL="utf8-codeset"
ORACLE_STDOUT="${GOLDEN_DIR}/harness-${ORACLE_LABEL}.stdout"
ORACLE_STATUS=0
index=0
while [ "${index}" -lt "${#GOLDEN_LABELS[@]}" ]; do
  if [ "${GOLDEN_LABELS[${index}]}" = "${ORACLE_LABEL}" ]; then
    ORACLE_STATUS="${GOLDEN_STATUSES[${index}]}"
  fi
  index=$((index + 1))
done

# Exactly the seven bytes "success" and one newline, tested as a whole file
# rather than with a line match: a capture carrying success plus anything else
# is not what tests/data/test1560:L37 asserts, and grep -q would accept it.
ORACLE_STDOUT_OK="no"
if [ "$(LC_ALL=C wc -c < "${ORACLE_STDOUT}" | tr -d ' ')" = "8" ] &&
   [ "$(cat "${ORACLE_STDOUT}")" = "success" ]; then
  ORACLE_STDOUT_OK="yes"
fi

GATED_RUN_STATE='fail'
ORACLE_VERDICT="pass"
if [ "${ORACLE_STDOUT_OK}" = "yes" ] && [ "${ORACLE_STATUS}" = "0" ]; then
  GATED_RUN_STATE='pass'
  say "  the fully-gated run exits 0 and prints exactly success, as" \
      "tests/data/test1560 expects"
else
  ORACLE_VERDICT="fail"
  FINAL_STATUS=1

  # The status is named rather than printed bare, because the three ranges mean
  # different things and mistaking one for another sends a reader to the wrong
  # place. 1 through 11 is a sub-test of the test itself; 120 is
  # harness/main.c refusing to start because setlocale() could not honor
  # LC_ALL, which is infrastructure and not a sub-test at all; anything else is
  # neither -- a crash, a signal, or a binary that could not be run.
  case "${ORACLE_STATUS}" in
    0)
      warn "the reference harness exited 0 under LC_ALL=C.UTF-8 with \
CURL_TEST_HAVE_CODESET_UTF8=1 but its stdout is not exactly the single line \
success that tests/data/test1560:L37 asserts. See ${ORACLE_STDOUT}"
      ;;
    1|2|3|4|5|6|7|8|9|10|11)
      warn "the reference harness failed sub-test ${ORACLE_STATUS} under \
LC_ALL=C.UTF-8 with CURL_TEST_HAVE_CODESET_UTF8=1 -- $(subtest_name \
"${ORACLE_STATUS}") -- so the C baseline does not itself pass lib1560. The \
failure detail is on stderr in ${GOLDEN_DIR}/harness-${ORACLE_LABEL}.stderr"
      ;;
    120)
      warn "the reference harness exited 120, which is harness/main.c \
refusing to start because setlocale(LC_ALL, \"\") could not honor \
LC_ALL=C.UTF-8. That is an infrastructure failure of this environment and not \
a sub-test failure: install the C.UTF-8 locale. Until it is installed the IDN \
rows of lib1560 cannot run at all"
      ;;
    *)
      warn "the reference harness exited ${ORACLE_STATUS} under \
LC_ALL=C.UTF-8 with CURL_TEST_HAVE_CODESET_UTF8=1, which is neither a \
sub-test code (1 through 11) nor the locale refusal (120). Treat it as an \
infrastructure failure -- a crash, a signal, or a binary that could not be \
run -- and read ${GOLDEN_DIR}/harness-${ORACLE_LABEL}.stderr"
      ;;
  esac

  warn "the golden captures are still recorded faithfully, and the summary \
file is still written so that a reader can see what was built, but this run \
is a FAILURE: no parity result drawn from this baseline would mean anything. \
Fix the baseline before running scripts/run-parity.sh"
fi

section "Golden capture: the demo transcript"

# Captured into the scratch tree first and verified there, so that the tracked
# file is only ever written from bytes that have already been checked.
DEMO_CAPTURE="${GOLDEN_DIR}/demo.stdout"
DEMO_CAPTURE_ERR="${GOLDEN_DIR}/demo.stderr"
DEMO_STATUS=0
fresh_path "${DEMO_CAPTURE}"
fresh_path "${DEMO_CAPTURE_ERR}"
"${REFERENCE_DEMO_BIN}" > "${DEMO_CAPTURE}" 2> "${DEMO_CAPTURE_ERR}" ||
  DEMO_STATUS="$?"
say "  demo exit status: ${DEMO_STATUS}"

# The demo writes to stderr only on an allocation failure, and then the
# transcript no longer describes what the URL API does.
if [ -s "${DEMO_CAPTURE_ERR}" ]; then
  warn "the reference demo wrote to stderr, which it does only for an \
allocation failure; the captured transcript is not trustworthy. See \
${DEMO_CAPTURE_ERR}"
  FINAL_STATUS=1
fi
if [ "${DEMO_STATUS}" != "0" ]; then
  warn "the reference demo exited ${DEMO_STATUS}; it returns non-zero only \
when an allocation failed"
  FINAL_STATUS=1
fi

# Verifies that a captured transcript satisfies every rule that
# scripts/spacecheck.pl applies to a tracked file. Checked, never assumed, and
# never filtered:
# a violation here has to be fixed in demo/urlapi_demo.c's printf sequence,
# because a post-processing filter would change the very bytes the parity diff
# compares. Prints one line per finding and returns the number of findings.
#   $1  file to check
verify_transcript_bytes() {
  local file="${1}"
  local findings=0
  local tab
  local carriage

  tab="$(printf '\t')"
  carriage="$(printf '\r')"

  if [ ! -s "${file}" ]; then
    say "    FINDING: the capture is empty"
    findings=$((findings + 1))
  fi
  if LC_ALL=C grep -q "${tab}" "${file}"; then
    say "    FINDING: contains a tab character"
    findings=$((findings + 1))
  fi
  if LC_ALL=C grep -q "${carriage}" "${file}"; then
    say "    FINDING: contains a carriage return, so the EOL is not LF"
    findings=$((findings + 1))
  fi
  if LC_ALL=C grep -q "[ ${tab}]\$" "${file}"; then
    say "    FINDING: a line ends in whitespace"
    findings=$((findings + 1))
  fi
  # Bytes at or above 0x80. spacecheck.pl allows only 0xC3 and 0xB6, each on
  # its own, and no transcript should need either.
  if [ "$(LC_ALL=C tr -d '\000-\177' < "${file}" | wc -c | tr -d ' ')" \
       != "0" ]; then
    say "    FINDING: contains non-ASCII bytes"
    findings=$((findings + 1))
  fi
  # Control bytes other than LF. Tab and carriage return are reported above,
  # so they are excluded here to keep one finding per cause.
  if [ "$(LC_ALL=C tr -d '\011\012\015\040-\176\200-\377' < "${file}" |
          wc -c | tr -d ' ')" != "0" ]; then
    say "    FINDING: contains control bytes"
    findings=$((findings + 1))
  fi
  # Command substitution strips trailing newlines, so a non-empty result from
  # the last byte means that byte is not a newline, and an empty result from
  # the last two means both of them are.
  if [ -n "$(tail -c 1 "${file}")" ]; then
    say "    FINDING: no newline at end of file"
    findings=$((findings + 1))
  fi
  if [ -z "$(tail -c 2 "${file}")" ]; then
    say "    FINDING: more than one newline at end of file"
    findings=$((findings + 1))
  fi
  if LC_ALL=C awk '/^$/ { if(blank) { bad = 1 } blank = 1; next }
                        { blank = 0 }
                   END  { if(bad) exit 0; exit 1 }' "${file}"; then
    say "    FINDING: two consecutive blank lines"
    findings=$((findings + 1))
  fi

  return "${findings}"
}

TRANSCRIPT_FINDINGS=0
verify_transcript_bytes "${DEMO_CAPTURE}" || TRANSCRIPT_FINDINGS="$?"
if [ "${TRANSCRIPT_FINDINGS}" != "0" ]; then
  fatal "the captured demo transcript breaks ${TRANSCRIPT_FINDINGS} of the \
rules scripts/spacecheck.pl applies to a tracked file, listed above. \
demo/expected-output.txt is tracked, so it cannot be written from these \
bytes. The fix belongs in demo/urlapi_demo.c's printf sequence: filtering the \
capture instead would break the byte-for-byte parity the golden file exists \
to establish"
fi
say "  the transcript satisfies every scripts/spacecheck.pl rule"

# Replaces the tracked golden file with the capture, atomically and without
# following anything.
#
# demo/expected-output.txt is the ONE tracked file this script writes, and it
# is the oracle acceptance criterion A7 is measured against, so the two
# properties below are worth the helper rather than a bare cp:
#
#   the write is atomic. The capture is copied to a private temporary name in
#   the same directory and renamed over the target, so a reader -- a
#   concurrent run-parity.sh, or git -- sees the whole old file or the whole
#   new one. A cp straight onto the target has a window in which the oracle is
#   half of each;
#
#   nothing is followed. cp -f onto an existing symlink writes through it, so
#   a link at this path would send the bytes somewhere else and leave the
#   oracle untouched. rename() replaces the link itself.
install_golden() {
  local staged

  if ! staged="$(mktemp "${CRATE_DIR}/demo/expected-output.txt.XXXXXX")"; then
    fatal "could not create a temporary file beside ${DEMO_GOLDEN}"
  fi
  if ! cat "${DEMO_CAPTURE}" > "${staged}"; then
    rm -f -- "${staged}"
    fatal "could not stage the capture beside ${DEMO_GOLDEN}"
  fi

  # This one file is tracked, so it must carry the permissions a tracked file
  # carries rather than the 0600 this script's umask would give it.
  chmod 644 "${staged}"
  if ! mv -f -- "${staged}" "${DEMO_GOLDEN}"; then
    rm -f -- "${staged}"
    fatal "could not publish the capture to ${DEMO_GOLDEN}"
  fi
}

# Installing the golden. A golden file that silently re-records itself cannot
# detect a regression, so a difference is reported and the tracked file is
# left alone unless the caller explicitly asks for it to be replaced.
if [ -f "${DEMO_GOLDEN}" ]; then
  if cmp -s "${DEMO_CAPTURE}" "${DEMO_GOLDEN}"; then
    DEMO_GOLDEN_STATE="unchanged"
    say "  ${DEMO_GOLDEN} is byte-identical to this capture"
  elif [ "${FORCE}" = "1" ]; then
    DEMO_GOLDEN_STATE="replaced"
    say "  --force given; the difference being recorded is:"
    diff -u "${DEMO_GOLDEN}" "${DEMO_CAPTURE}" 2>&1 |
      tee -a "${LOG_FILE}" || true
    install_golden
    warn "replaced ${DEMO_GOLDEN} on explicit request"
  else
    DEMO_GOLDEN_STATE="differs"
    say "  the committed golden and this capture differ:"
    diff -u "${DEMO_GOLDEN}" "${DEMO_CAPTURE}" 2>&1 |
      tee -a "${LOG_FILE}" || true
    warn "${DEMO_GOLDEN} differs from the transcript the reference build just \
produced, and was NOT replaced. Either the demo source or the reference \
configuration changed. Rerun with --force (or REGENERATE=1) to record the \
new bytes deliberately"
    FINAL_STATUS=1
  fi
else
  DEMO_GOLDEN_STATE="created"
  install_golden
  say "  created ${DEMO_GOLDEN}"
fi

# The independent allocation count, offered because curl's own counter does
# not run in this configuration. See the R3 note printed at the end.
REFERENCE_ALLOCATIONS="not measured"
if [ "${WANT_VALGRIND}" = "1" ]; then
  section "Independent allocation count"
  if command -v valgrind > /dev/null 2>&1; then
    VALGRIND_LOG="${GOLDEN_DIR}/harness-utf8-codeset.valgrind"
    fresh_path "${VALGRIND_LOG}"
    env LC_ALL=C.UTF-8 CURL_TEST_HAVE_CODESET_UTF8=1 \
      valgrind --tool=memcheck --error-exitcode=0 \
      "${REFERENCE_HARNESS_BIN}" > /dev/null 2> "${VALGRIND_LOG}" || true
    REFERENCE_ALLOCATIONS="$(awk '/total heap usage/ {
        for(i = 1; i <= NF; i++) {
          if($i == "usage:") { print $(i + 1); exit }
        }
      }' "${VALGRIND_LOG}" || true)"
    REFERENCE_ALLOCATIONS="${REFERENCE_ALLOCATIONS//,/}"
    if [ -z "${REFERENCE_ALLOCATIONS}" ]; then
      REFERENCE_ALLOCATIONS="unknown"
    fi
    say "  the reference harness performs ${REFERENCE_ALLOCATIONS} \
allocations for one run of lib1560, counted by valgrind"
    say "  this is NOT the accounting tests/data/test1560 asks for: it" \
        "counts process startup as well, and curl's own counter belongs to" \
        "the memory-debug build this baseline deliberately does not use"
  else
    warn "valgrind was asked for but is not installed; no independent \
allocation count was taken. Install the valgrind package"
  fi
fi

section "Machine-readable summary"

# Written so that run-parity.sh and check-abi.sh consume facts this run
# established instead of re-deriving them -- which is not merely tidier: a
# second derivation is a second chance to derive something different, and the
# whole point of the parity comparison is that both sides were built from one
# set of decisions.
#
# The provenance keys -- schema, generated-by, generated-at, source-revision
# and the five directories -- were written at startup and are not repeated
# here; fact() refuses a duplicate key, so a repetition would stop the run
# rather than produce a file with two answers to one question.
fact "reference-archive" "${REFERENCE_ARCHIVE}"
fact "reference-archive-members" "${ARCHIVE_MEMBERS}"
fact "reference-urlapi-member" "${REFERENCE_URLAPI_MEMBER}"
fact "reference-urlapi-object" "${REFERENCE_URLAPI_OBJECT}"
fact "reference-urlapi-symbols" "${REFERENCE_URLAPI_SYMBOLS}"
fact "reference-protocols" "${REFERENCE_PROTOCOLS}"
fact "reference-features" "${REFERENCE_FEATURES}"
fact "reference-idn" "${REFERENCE_IDN}"
fact "reference-memdebug" "${REFERENCE_MEMDEBUG}"
fact "reference-curl-config" "${CURL_CONFIG}"

# Digests of the two artifacts the downstream scripts inspect, so that they
# can bind a path recorded here to the bytes this run produced instead of
# trusting that whatever now sits at the path is the same file. check-abi.sh
# verifies both before it reads a symbol table, and run-parity.sh verifies the
# archive before AND after it copies it -- which is how it proves it never
# modified the original.
fact "reference-archive-sha256" "${REFERENCE_ARCHIVE_SHA256}"
fact "reference-urlapi-object-sha256" "${REFERENCE_URLAPI_OBJECT_SHA256}"

# The same records under the upper-case spelling. Two consumers were written
# against two spellings and this file satisfies both: scripts/check-abi.sh
# reads the lower-case dashed records, scripts/run-parity.sh reads the
# upper-case ones. fact() accepts either shape and still refuses a repeated
# key, so these are aliases rather than a second answer to one question.
fact "REFERENCE_GENERATED_BY" "rust-urlapi/scripts/build-reference.sh"
fact "REFERENCE_CRATE_DIR" "${CRATE_DIR}"
fact "REFERENCE_REPO_ROOT" "${REPO_ROOT}"
fact "REFERENCE_BUILD_ROOT" "${BUILD}"
fact "REFERENCE_CMAKE_DIR" "${REFERENCE_DIR}"
fact "REFERENCE_LOG" "${LOG_FILE}"
fact "REFERENCE_ARCHIVE" "${REFERENCE_ARCHIVE}"
fact "REFERENCE_ARCHIVE_MEMBERS" "${ARCHIVE_MEMBERS}"
fact "REFERENCE_URLAPI_MEMBER" "${REFERENCE_URLAPI_MEMBER}"
fact "REFERENCE_URLAPI_OBJECT" "${REFERENCE_URLAPI_OBJECT}"
fact "REFERENCE_URLAPI_SYMBOLS" "${REFERENCE_URLAPI_SYMBOLS}"
fact "REFERENCE_PROTOCOLS" "${REFERENCE_PROTOCOLS}"
fact "REFERENCE_FEATURES" "${REFERENCE_FEATURES}"
fact "REFERENCE_IDN" "${REFERENCE_IDN}"
fact "REFERENCE_MEMDEBUG" "${REFERENCE_MEMDEBUG}"
fact "REFERENCE_CURL_CONFIG" "${CURL_CONFIG}"

# The preprocessor state and the compile settings, so that the Rust harness
# compilation is handed the identical set. This is the value run-parity.sh
# must consume rather than choose.
fact "harness-stage-dir" "${STAGE_DIR}"
fact "harness-test-source" "lib1560.c"
fact "harness-test-source-origin" "${TEST_SOURCE}"
fact "harness-defines" "${HARNESS_DEFINES}"
fact "harness-cflags" "${HARNESS_CFLAGS}"
fact "harness-includes" "${HARNESS_INCLUDES}"

fact "reference-cc" "${CC_BIN}"
fact "reference-cc-version" "${CC_VERSION}"
fact "reference-cmake-version" "${CMAKE_VERSION}"
fact "reference-make-version" "${MAKE_VERSION}"
fact "reference-pkgconfig-version" "${PKGCONFIG_VERSION}"
fact "reference-ssl-version" "${SSL_VERSION}"
fact "reference-idn2-version" "${IDN2_VERSION}"
fact "reference-ldap-version" "${LDAP_VERSION}"
fact "reference-zlib-version" "${ZLIB_VERSION}"

fact "reference-system-libs" "${REFERENCE_SYSTEM_LIBS}"
fact "reference-harness-link" "${HARNESS_COMMAND[*]}"
fact "reference-demo-link" "${DEMO_COMMAND[*]}"
fact "reference-harness-bin" "${REFERENCE_HARNESS_BIN}"
fact "reference-demo-bin" "${REFERENCE_DEMO_BIN}"

fact "golden-dir" "${GOLDEN_DIR}"
fact "demo-golden" "${DEMO_GOLDEN}"
fact "demo-golden-state" "${DEMO_GOLDEN_STATE}"
fact "demo-exit-status" "${DEMO_STATUS}"
fact "reference-allocations" "${REFERENCE_ALLOCATIONS}"

# One entry per captured environment, keyed by the same label the file names
# use, so that a consumer can pair a status with its stdout without knowing
# the order they were run in. The labels are already lowercase with dashes,
# which is exactly the key shape fact() requires, so they are used as they
# are.

# The same records under the upper-case spelling. Two consumers were written
# against two spellings and this file satisfies both: scripts/check-abi.sh
# reads the lower-case dashed records, scripts/run-parity.sh reads the
# upper-case ones. fact() accepts either shape and still refuses a repeated
# key, so these are aliases rather than a second answer to one question.
fact "HARNESS_STAGE_DIR" "${STAGE_DIR}"
fact "HARNESS_TEST_SOURCE" "lib1560.c"
fact "HARNESS_TEST_SOURCE_ORIGIN" "${TEST_SOURCE}"
fact "HARNESS_DEFINES" "${HARNESS_DEFINES}"
fact "HARNESS_CFLAGS" "${HARNESS_CFLAGS}"
fact "HARNESS_INCLUDES" "${HARNESS_INCLUDES}"
fact "REFERENCE_CC" "${CC_BIN}"
fact "REFERENCE_CC_VERSION" "${CC_VERSION}"
fact "REFERENCE_CMAKE_VERSION" "${CMAKE_VERSION}"
fact "REFERENCE_MAKE_VERSION" "${MAKE_VERSION}"
fact "REFERENCE_PKGCONFIG_VERSION" "${PKGCONFIG_VERSION}"
fact "REFERENCE_SSL_VERSION" "${SSL_VERSION}"
fact "REFERENCE_IDN2_VERSION" "${IDN2_VERSION}"
fact "REFERENCE_LDAP_VERSION" "${LDAP_VERSION}"
fact "REFERENCE_ZLIB_VERSION" "${ZLIB_VERSION}"
fact "REFERENCE_SYSTEM_LIBS" "${REFERENCE_SYSTEM_LIBS}"
fact "REFERENCE_HARNESS_LINK" "${HARNESS_COMMAND[*]}"
fact "REFERENCE_DEMO_LINK" "${DEMO_COMMAND[*]}"
fact "REFERENCE_HARNESS_BIN" "${REFERENCE_HARNESS_BIN}"
fact "REFERENCE_DEMO_BIN" "${REFERENCE_DEMO_BIN}"
fact "GOLDEN_DIR" "${GOLDEN_DIR}"
fact "ORACLE_LABEL" "${ORACLE_LABEL}"
fact "ORACLE_STDOUT" "${ORACLE_STDOUT}"
fact "ORACLE_STATUS" "${ORACLE_STATUS}"
fact "ORACLE_VERDICT" "${ORACLE_VERDICT}"
fact "DEMO_GOLDEN" "${DEMO_GOLDEN}"
fact "DEMO_GOLDEN_STATE" "${DEMO_GOLDEN_STATE}"
fact "DEMO_EXIT_STATUS" "${DEMO_STATUS}"
fact "REFERENCE_ALLOCATIONS" "${REFERENCE_ALLOCATIONS}"

index=0
while [ "${index}" -lt "${#GOLDEN_LABELS[@]}" ]; do
  label="${GOLDEN_LABELS[${index}]}"
  fact "golden-status-${label}" "${GOLDEN_STATUSES[${index}]}"
  # The label names files, so it is lower case with hyphens; the
  # upper-case alias is the same value under the spelling
  # run-parity.sh reads.
  key_suffix="${label//-/_}"
  fact "GOLDEN_STATUS_${key_suffix^^}" "${GOLDEN_STATUSES[${index}]}"
  index=$((index + 1))
done

# The verdict of the one run that has to pass, recorded separately from the
# four statuses so that a consumer does not have to know which label is the
# fully-gated one.
fact "reference-gated-run" "${GATED_RUN_STATE}"

say "  facts accumulated; ${FACTS_FILE} is published with its verdict as \
this run exits"

section "Reported constraints"

# Both of these are reported and deliberately NOT remedied. The directive is
# explicit: where something in scope would require touching something out of
# scope in order to work, report it instead of expanding scope. They are
# printed on every run rather than buried in a document, because both change
# how a reader should interpret what this script produced.
printf '%s\n' \
  "R1 -- the distribution check will fail once rust-urlapi/ is committed." \
  "" \
  "  .github/scripts/distfiles.sh compares the output of git ls-files (its" \
  "  L42) against the contents of the generated release tarball, subtracts a" \
  "  fixed literal exception list that contains no entry able to match" \
  "  rust-urlapi, and exits 1 for anything reported missing (its L56). It" \
  "  runs as the missing-files job of .github/workflows/distcheck.yml (its" \
  "  L210 and L225), in a workflow that triggers on every push to the" \
  "  default branch and every pull request against it with no path filter" \
  "  (its L7-L14). Committing rust-urlapi/** therefore makes that job" \
  "  report the new files as missing from the tarball and fail." \
  "" \
  "  The only remedies are adding the directory to EXTRA_DIST at" \
  "  Makefile.am:L67 or to the distributed subdirectory lists at its" \
  "  L73-L74. Both are edits to Makefile.am, which is out of scope. This" \
  "  script does not make them, and neither should anything else in this" \
  "  work item; the one-line addition is a follow-up decision for the" \
  "  owners of curl's build system." \
  "" \
  "R2 -- a second URL API test is out of reach, and is not run here." \
  "" \
  "  tests/unit/unit1653.c calls Curl_parse_port() directly, handing it a" \
  "  CURLU * together with a struct dynbuf it built itself. That entry" \
  "  point exists only in a build that defines UNITTESTS, and satisfying it" \
  "  would need a ninth exported symbol plus bit-compatible interoperation" \
  "  with libcurl's private dynamic-buffer structure. Only lib1560 and" \
  "  test1560 are named as success criteria, so unit1653 is out of scope --" \
  "  recorded here rather than passed over in silence." \
  "" \
  "R3 -- memory-debug builds are incompatible, so curl's own allocation" \
  "     counter does not run against this baseline." \
  "" \
  "  curl_free() forwards to curlx_free() (lib/escape.c:L189-L192), which" \
  "  resolves at compile time three ways. Under memory debugging it becomes" \
  "  curl_dbg_free(ptr, __LINE__, __FILE__) (lib/curl_setup.h:L1453-L1461)," \
  "  and that function performs no lookup and refuses nothing: it subtracts" \
  "  the offset of the payload within its own header struct from the pointer" \
  "  it was handed and frees that address unconditionally" \
  "  (lib/memdebug.c:L362-L385). The Rust crate takes the buffers it hands" \
  "  back to C from the C allocator, and those carry no such header, so the" \
  "  address released would not be the start of any allocation -- heap" \
  "  corruption rather than a rejection. Routing through libcurl's internal" \
  "  hook instead would mean importing a private symbol and would still" \
  "  leave the tracking table with no record of the block." \
  "" \
  "  This baseline is therefore configured with -DENABLE_DEBUG=OFF, and the" \
  "  consequence is stated rather than glossed: the ceiling of" \
  "  \"Allocations: 3000\" at tests/data/test1560:L39-L41 is honored in" \
  "  spirit -- the port is not materially more allocation-hungry -- but is" \
  "  NOT counted by the mechanism that wrote it. Run this script with" \
  "  --valgrind for an independent count from platform tooling, which is" \
  "  the available substitute rather than an equivalent." \
  | tee -a "${LOG_FILE}"

section "Summary"

say "  archive:        ${REFERENCE_ARCHIVE} (${ARCHIVE_MEMBERS} members)"
say "  urlapi member:  ${REFERENCE_URLAPI_MEMBER}"
say "  harness binary: ${REFERENCE_HARNESS_BIN}"
say "  demo binary:    ${REFERENCE_DEMO_BIN}"
say "  golden outputs: ${GOLDEN_DIR}"
say "  demo golden:    ${DEMO_GOLDEN} (${DEMO_GOLDEN_STATE})"
say "  facts:          ${FACTS_FILE}"
say "  log:            ${LOG_FILE}"

index=0
while [ "${index}" -lt "${#GOLDEN_LABELS[@]}" ]; do
  status="${GOLDEN_STATUSES[${index}]}"
  if [ "${status}" = "0" ]; then
    say "  harness ${GOLDEN_LABELS[${index}]}: exit 0, all eleven sub-tests \
passed"
  else
    say "  harness ${GOLDEN_LABELS[${index}]}: exit ${status}, \
$(subtest_name "${status}")"
  fi
  index=$((index + 1))
done
say "  oracle gate:    ${ORACLE_VERDICT} (${ORACLE_LABEL}, exit \
${ORACLE_STATUS})"

# The verdict, and the single place it is decided.
#
# RESULT is what the EXIT trap writes into the published summary, and it is set
# to pass HERE and nowhere else: after every check, every capture, every
# comparison and every golden decision has already had its chance to set
# FINAL_STATUS. That ordering is the point. Any earlier assignment would be a
# promise made before the evidence was in, and the downstream scripts treat
# result=pass as permission to build a parity claim on these artifacts.
#
# The oracle gate is part of FINAL_STATUS -- see the gate above -- so a
# baseline that does not pass lib1560 can never reach the pass branch, and the
# failure branch names the gate explicitly when it is what failed.
if [ "${FINAL_STATUS}" = "0" ]; then
  RESULT='pass'
  say ""
  say "reference baseline complete and the oracle passes; run" \
      "scripts/run-parity.sh next"
else
  if [ "${ORACLE_VERDICT}" = "fail" ]; then
    warn "the reference baseline was built but the oracle gate FAILED, so it \
is not a usable baseline: scripts/run-parity.sh would compare against a C \
implementation that does not pass lib1560 here. Fix that first"
  else
    warn "the reference baseline was built, but a finding above needs \
attention"
  fi
  warn "${FACTS_FILE} therefore records result=fail. check-abi.sh and \
run-parity.sh refuse a summary that does not say pass, which is deliberate: \
every parity claim they make rests on this baseline"
fi

exit "${FINAL_STATUS}"
