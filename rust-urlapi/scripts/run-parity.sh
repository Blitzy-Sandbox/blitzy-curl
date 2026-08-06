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

# Decide whether the Rust port of lib/urlapi.c behaves as the C original
# does, and report the answer per sub-test rather than in aggregate.
#
# This is the script the whole exercise turns on. scripts/build-reference.sh
# produces the C baseline, scripts/build-rust.sh produces the crate and
# scripts/check-abi.sh compares the two symbol sets; this one links the
# unmodified tests/libtest/lib1560.c against the crate in both supported link
# modes, runs it beside the reference under every environment that changes
# what it asserts, and diffs the results byte for byte. It discharges
# acceptance criteria A4 through A10.
#
# What it does, in order:
#
#   1. resolves its inputs from the summary files the two build scripts
#      wrote, rather than re-deriving any of them, which is what keeps the
#      three scripts from disagreeing about the archive, the member name,
#      the link line or the preprocessor state;
#   2. checks that scripts/check-abi.sh has passed, because a symbol
#      mismatch makes every behavior result below meaningless;
#   3. stages the unmodified test source beside the harness shim header, so
#      that the shim wins the test's own quoted include, and proves that it
#      did with the preprocessor rather than assuming it;
#   4. proves which of the three optional assertion blocks the test compiled,
#      by preprocessing it and looking for a marker from each;
#   5. links Mode A, the authoritative drop-in: the reference archive with
#      the urlapi member deleted, plus the crate. The control links come
#      first and are evidence -- the stripped archive alone must fail with
#      the drop-in symbols undefined, and the intact archive must succeed
#      and print success -- because without them a passing Mode A link
#      proves nothing;
#   6. links Mode B, the standalone: the crate plus the C shims and no
#      libcurl at all;
#   7. runs the reference and both Rust binaries under all four combinations
#      of locale and codeset, comparing Rust against reference WITHIN each
#      environment, since the reference's own non-UTF-8 failure mode is part
#      of the oracle rather than a defect to smooth over;
#   8. diffs stdout byte for byte, stdout only, captured separately from
#      stderr;
#   9. maps each exit status back to the sub-test that produced it and
#      prints a verdict for all eleven, iterating while a run keeps making
#      progress;
#  10. compares both demo transcripts with the committed golden bytes;
#  11. reports the four constraints this work deliberately does not remedy,
#      and the honest limits of the validation itself.
#
# Outputs, all inside the crate directory and all under the ignored build/
# tree. This script writes no tracked file whatsoever:
#
#   build/harness/                staged test source symlink + first.h shim
#   build/parity/obj/             runner.o, main.o, shims.o
#   build/parity/runs/            one stdout, stderr and status per run
#   build/parity/*.log            one log per compilation and link
#   build/mode-a/libcurl.a        the reference archive, urlapi deleted
#   build/mode-a/harness-a        the Mode A harness
#   build/mode-a/demo-a           the Mode A demo
#   build/mode-b/harness-b        the Mode B harness
#   build/mode-b/demo-b           the Mode B demo
#   build/run-parity.log          full transcript of this run
#   build/parity-summary.txt      key=value summary of every verdict
#
# demo/expected-output.txt is READ here and never written. Regenerating a
# golden file is build-reference.sh's job, behind its own explicit opt-in; a
# golden that re-records itself cannot detect anything.
#
# Nothing under tests/, lib/, include/, src/ or docs/ is created, edited,
# moved or deleted -- not a file, not a symlink, not a temporary. After a
# full run "git status --porcelain" reports nothing at all, which is
# acceptance criterion A12. The sibling ../.gitignore is what covers build/;
# the repository root .gitignore spells its own entry "/build/" with a
# leading slash, which anchors it to the repository root and never reaches
# this subdirectory.
#
# Usage: run-parity.sh [options]        (--help lists them)

set -eu
set -o pipefail

# Working directory: the crate root, so that every relative path below means
# the same thing however the script was started -- as
# rust-urlapi/scripts/run-parity.sh, as ./run-parity.sh from inside scripts/,
# or through the parity target of ../GNUmakefile.
#
# Derived with parameter expansion rather than with dirname, for the reason
# build-reference.sh gives at the same point: the prerequisite table has not
# run yet and cannot, because it needs the log file, which needs this
# directory. A missing or shadowed dirname would make a command substitution
# expand to nothing and both directories would then resolve to the filesystem
# root instead of failing. Parameter expansion is a builtin and cannot fail
# that way.
SCRIPT_DIR="${0%/*}"
if [ "${SCRIPT_DIR}" = "${0}" ]; then
  # No slash in "$0" at all, so it was run from the directory holding it.
  SCRIPT_DIR="."
elif [ -z "${SCRIPT_DIR}" ]; then
  # "$0" was "/name", so the directory is the root.
  SCRIPT_DIR="/"
fi
cd "${SCRIPT_DIR}/.."
CRATE_DIR="${PWD}"

# The unmodified repository. Needed separately from the crate directory: the
# public headers and tests/libtest/lib1560.c both come from it, and both are
# read only. Taken as the parent rather than from git, so that the script
# works in an exported tree with no .git at all.
REPO_ROOT="$(cd .. && pwd)"

# Both resolutions are checked at once, with plain printf because none of the
# helpers below exist yet. This exists so that a script started from
# somewhere unexpected says so in one line, instead of reporting a dozen
# missing files whose paths are the real clue.
if [ ! -f "${CRATE_DIR}/Cargo.toml" ] ||
   [ ! -f "${REPO_ROOT}/CMakeLists.txt" ]; then
  printf 'run-parity.sh: error: %s\n' "resolved the crate directory as \
${CRATE_DIR} and the repository root as ${REPO_ROOT}, but Cargo.toml is not \
in the first or CMakeLists.txt is not in the second. This script has to be \
run from the scripts directory of the curl-urlapi-rs crate inside a curl \
checkout" >&2
  exit 1
fi

# The scratch tree. Overridable as a whole so that a caller can move it out
# of the repository entirely, or give each of several parallel clones its
# own, without editing anything here. It must be the same tree the two build
# scripts used, since their summary files live in it.
BUILD="${BUILD_DIR:-${CRATE_DIR}/build}"

# Where the two build scripts recorded what they did. Two formats, one
# reader: build-reference.sh writes KEY='value' and build-rust.sh writes bare
# key=value with dashes in the key names, which is also why neither file can
# simply be sourced -- a key with a dash is not a shell identifier.
REFERENCE_FACTS="${BUILD}/reference-build.env"
RUST_FACTS="${BUILD}/rust-build-summary.txt"
ABI_FACTS="${BUILD}/abi-check-summary.txt"

# The staging directory that makes the harness shim win the test source's
# quoted include. Shared with build-reference.sh, whose stage_test_source()
# creates it; the "Staging the unmodified test source" section below says why
# it has to be shared rather than duplicated.
STAGE_DIR="${BUILD}/harness"

# Everything this script produces.
PARITY_DIR="${BUILD}/parity"
OBJ_DIR="${PARITY_DIR}/obj"
RUN_DIR="${PARITY_DIR}/runs"
MODE_A_DIR="${BUILD}/mode-a"
MODE_B_DIR="${BUILD}/mode-b"
LOG_FILE="${BUILD}/run-parity.log"
SUMMARY_FILE="${BUILD}/parity-summary.txt"

# Inputs read from the crate. Each is checked for existence before use: a
# named prerequisite failure says far more than the compiler diagnostic a
# missing one produces.
HARNESS_SHIM="${CRATE_DIR}/harness/first.h"
HARNESS_RUNNER="${CRATE_DIR}/harness/runner.c"
HARNESS_MAIN="${CRATE_DIR}/harness/main.c"
HARNESS_SHIMS="${CRATE_DIR}/harness/shims.c"
DEMO_SOURCE="${CRATE_DIR}/demo/urlapi_demo.c"
MIRROR_INCLUDE_DIR="${CRATE_DIR}/include"
ABI_SCRIPT="${CRATE_DIR}/scripts/check-abi.sh"

# The committed parity oracle for the demo, acceptance criterion A7. Read
# only, always.
DEMO_GOLDEN="${CRATE_DIR}/demo/expected-output.txt"

# The unmodified test source. Never copied and never edited: it is reached
# through a symlink, for the reason the staging section below sets out.
TEST_SOURCE="${REPO_ROOT}/tests/libtest/lib1560.c"

# The real tests/libtest/first.h, named here only so that the include proof
# can assert it was NOT the header the test source picked up.
PRIVATE_FIRST_H="${REPO_ROOT}/tests/libtest/first.h"

# The C compiler. CC is honored because both build scripts honor it and
# because comparing two compilers is a legitimate use of this script.
CC_BIN="${CC:-cc}"

# Option state, each also settable from the environment so that the same
# behavior is reachable from a Makefile without argument plumbing.
#
# ATTEMPTS bounds the per-run iteration of section 9. Two is enough to
# observe a repeat; three leaves room to watch a changing status settle.
ATTEMPTS="${ATTEMPTS:-3}"
WANT_ABI_RUN="${RUN_CHECK_ABI:-0}"
IGNORE_ABI="${IGNORE_ABI:-0}"
WANT_DEMO="${RUN_DEMO:-1}"
WANT_VALGRIND="${RUN_VALGRIND:-0}"
MODES_REQUESTED="${PARITY_MODES:-both}"
ENVS_REQUESTED="${PARITY_ENVIRONMENTS:-all}"

# Set once the log file exists, so the helpers know whether they may append
# to it. Every diagnostic before that point still reaches the terminal.
LOG_READY=0

# Verdict accounting. A failing check must not abort the run: the value of
# this script is the whole table, and a summary file written even on a
# failing run is what a reader needs most. So a failure is counted here and
# the script exits non-zero at the very end.
CHECKS_PASSED=0
CHECKS_FAILED=0
FINAL_STATUS=0

usage() {
  printf '%s\n' \
    "Usage: run-parity.sh [options]" \
    "" \
    "Links the unmodified tests/libtest/lib1560.c against the Rust port of" \
    "lib/urlapi.c in both link modes, runs it beside the C reference under" \
    "every environment that changes what it asserts, diffs stdout byte for" \
    "byte and reports a verdict for each of the eleven sub-tests." \
    "" \
    "Run scripts/build-reference.sh, scripts/build-rust.sh and" \
    "scripts/check-abi.sh first, in that order." \
    "" \
    "Options:" \
    "      --check-abi    run scripts/check-abi.sh first and stop if it" \
    "                     fails. Without this its recorded verdict is read" \
    "                     from build/abi-check-summary.txt instead." \
    "                     Equivalent to RUN_CHECK_ABI=1." \
    "      --ignore-abi   continue even when that verdict is not a pass." \
    "                     A symbol mismatch makes every behavior result" \
    "                     below meaningless, so this is for investigating" \
    "                     one, never for declaring parity." \
    "                     Equivalent to IGNORE_ABI=1." \
    "  -m, --mode MODE    a, b or both. Default both. Mode A is the" \
    "                     authoritative drop-in and Mode B the standalone" \
    "                     link; a Mode B failure is a real failure." \
    "                     Equivalent to PARITY_MODES=MODE." \
    "  -e, --env LABEL    restrict the environment matrix to one label, or" \
    "                     to several by repeating the option. Labels are" \
    "                     utf8-codeset, utf8-nocodeset, c-codeset and" \
    "                     c-nocodeset. Default all four." \
    "                     Equivalent to PARITY_ENVIRONMENTS='LABEL ...'." \
    "  -a, --attempts N   how many times one binary may be re-run in one" \
    "                     environment while its exit status keeps changing." \
    "                     Default 3. Equivalent to ATTEMPTS=N." \
    "      --no-demo      skip the demo comparison. Equivalent to" \
    "                     RUN_DEMO=0." \
    "      --valgrind     count allocations with valgrind and report the" \
    "                     number without asserting on it. Not the" \
    "                     accounting tests/data/test1560 asks for; see the" \
    "                     R3 note this script prints. Equivalent to" \
    "                     RUN_VALGRIND=1." \
    "  -h, --help         print this and exit." \
    "" \
    "Environment:" \
    "  CC                     C compiler. Default: cc" \
    "  BUILD_DIR              scratch tree. Default: <crate>/build" \
    "  HARNESS_DEFINES        preprocessor state for the harness compile." \
    "                         Default: whatever the reference build used" \
    "  HARNESS_CFLAGS         compiler options. Default: as above" \
    "  REFERENCE_ARCHIVE      libcurl archive to copy and strip" \
    "  REFERENCE_URLAPI_MEMBER  archive member to delete from the copy" \
    "  REFERENCE_SYSTEM_LIBS  system libraries for the Mode A link" \
    "  MODE_A_ARCHIVE         Rust archive built --no-default-features" \
    "  MODE_B_ARCHIVE         Rust archive built with default features" \
    "  MODE_B_SYSTEM_LIBS     system libraries for the Mode B link" \
    "" \
    "Exit status is 0 only when every check passed."
}

# ------------------------------------------------------------------------
# Output helpers
# ------------------------------------------------------------------------

# Appends one line to the transcript, if the transcript exists yet. Kept
# separate from say() so that every write to it goes through one statement.
logonly() {
  if [ "${LOG_READY}" = "1" ]; then
    printf '%s\n' "$*" >> "${LOG_FILE}"
  fi
}

# Normal progress and report output: terminal and transcript.
say() {
  printf '%s\n' "$*"
  logonly "$*"
}

# A blank line and a heading, so a long transcript stays readable.
section() {
  say ""
  say "== $* =="
}

# A finding that does not stop the run. Sent to stderr so that it cannot be
# mistaken for report output by anything parsing stdout.
warn() {
  printf 'run-parity.sh: warning: %s\n' "$*" >&2
  logonly "warning: $*"
}

# A finding that stops the run. Reached only for a condition that makes the
# comparison itself invalid -- a missing input, a staging failure, a
# preprocessor state that does not match the reference -- never for a parity
# difference, which is a result and belongs in the table.
fatal() {
  printf 'run-parity.sh: error: %s\n' "$*" >&2
  logonly "error: $*"
  exit 1
}

# One check passed. The two-space indent and fixed-width verdict make the
# transcript greppable: "grep -E '^  (PASS|FAIL)' " lists every check.
pass() {
  CHECKS_PASSED=$((CHECKS_PASSED + 1))
  say "  PASS  $*"
}

# One check failed. Counted and remembered; the run continues, because a
# partial table is worth less than a complete one.
fail() {
  CHECKS_FAILED=$((CHECKS_FAILED + 1))
  FINAL_STATUS=1
  say "  FAIL  $*"
}

# Appends one key=value line to the machine-readable summary. Written in the
# bare form build-rust.sh uses rather than the quoted form
# build-reference.sh uses, because several values here are link lines and
# symbol lists that read better unquoted; read_fact() below handles both.
fact() {
  printf '%s=%s\n' "${1}" "${2}" >> "${SUMMARY_FILE}"
}

# ------------------------------------------------------------------------
# Reading the summary files
# ------------------------------------------------------------------------

# One value from one summary file, or the empty string when the file or the
# key is absent. Absence is not an error here: every caller decides for
# itself whether its key is required, and says so by name when it is.
#
# Both formats are handled by the same reader, exactly as check-abi.sh does
# it, so that the two scripts cannot disagree about what a summary file says.
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
      fatal "read_fact: refusing to look up the key '${key}'"
      ;;
  esac

  # The last occurrence wins. Neither writer repeats a key, and taking the
  # last is what makes an appended correction behave the way a reader would
  # expect if one ever did.
  line="$(sed -n "s/^${key}=//p" "${file}" | tail -n 1)"

  # Strip one layer of single quotes when they are there, and leave the value
  # alone when they are not.
  case "${line}" in
    "'"*"'")
      line="${line#\'}"
      line="${line%\'}"
      ;;
  esac

  printf '%s\n' "${line}"
}

# A required value: the environment override if the caller set one, else the
# summary file, else a named failure telling the reader which script writes
# it. Every input this script consumes comes through here or through
# read_fact directly, so that "consume the facts, do not re-derive them" is
# structural rather than a matter of discipline.
#
#   $1  the override value, possibly empty
#   $2  the summary file to consult
#   $3  the key in that file
#   $4  the script that writes that key, named in the diagnostic
require_fact() {
  local override="${1}"
  local file="${2}"
  local key="${3}"
  local owner="${4}"
  local value

  if [ -n "${override}" ]; then
    printf '%s\n' "${override}"
    return 0
  fi

  value="$(read_fact "${file}" "${key}")"
  if [ -z "${value}" ]; then
    fatal "${file} does not record ${key}. Run ${owner} first; if it has \
already run, its summary file is from an older version of it and the whole \
scratch tree should be removed and rebuilt. scripts/check-abi.sh must then \
pass before this script means anything, because a symbol mismatch makes \
every behavior result meaningless"
  fi
  printf '%s\n' "${value}"
}

# True when a command exists. command -v is a builtin and is the reason this
# script never calls which, whose use the repository shellcheck invocation
# reports through its deprecate-which check.
have() {
  command -v "${1}" > /dev/null 2>&1
}

# ------------------------------------------------------------------------
# The sub-test table
# ------------------------------------------------------------------------

# tests/libtest/lib1560.c:L2034-L2075 is the test's entry point, and these
# two arrays are that function transcribed. It calls eleven sub-tests, it
# SHORT-CIRCUITS at the first one that fails, and it returns a code naming
# that sub-test -- in an execution order which is not the numeric order of
# the codes, which is why both arrays exist and why they are indexed
# together. Read off L2040-L2071:
#
#   L2040 urldup        -> 11      L2055 scopeid       ->  6
#   L2043 setget_parts  -> 10      L2058 append        ->  5
#   L2046 get_url       ->  3      L2061 set_url       ->  1
#   L2049 huge          ->  9      L2064 set_parts     ->  2
#   L2052 get_nothing   ->  7      L2067 get_parts     ->  4
#                                  L2070 clear_url     ->  8
#
# Reaching L2073 means all eleven passed: it prints the single line "success"
# and returns CURLE_OK, and that line is exactly what tests/data/test1560:L37
# expects. Three of the sub-tests -- setget_parts, get_url and get_parts --
# take the has_utf8 flag L2036 reads from the environment, which is why the
# environment matrix below exists.
SUBTEST_NAMES=(urldup setget_parts get_url huge get_nothing scopeid
               append set_url set_parts get_parts clear_url)
SUBTEST_CODES=(11 10 3 9 7 6 5 1 2 4 8)

# The exit status harness/main.c uses when setlocale() could not honor the
# locale the environment names, at its HARNESS_ERR_SETLOCALE. It is outside
# 1..11 deliberately, so that a harness which never started cannot be
# misread as a sub-test that failed.
STATUS_SETLOCALE=120

# The execution position of the sub-test a given exit status names, or an
# empty string when the status names none. Positions are 1-based, matching
# the order printed in the report.
subtest_position() {
  local status="${1}"
  local index=0

  while [ "${index}" -lt "${#SUBTEST_CODES[@]}" ]; do
    if [ "${SUBTEST_CODES[${index}]}" = "${status}" ]; then
      printf '%s\n' "$((index + 1))"
      return 0
    fi
    index=$((index + 1))
  done
  return 0
}

# What an exit status means, in one phrase, for the report. Anything above
# the eleven sub-test codes is an infrastructure failure rather than a
# result: 120 is the harness refusing to start, 126 and 127 belong to the
# shell, and 128+n is a signal. Reporting those as a sub-test failure would
# be a lie, and a plausible-looking one.
describe_status() {
  local status="${1}"
  local position

  if [ "${status}" = "0" ]; then
    printf 'all eleven sub-tests passed\n'
    return 0
  fi

  position="$(subtest_position "${status}")"
  if [ -n "${position}" ]; then
    printf 'sub-test %s failed\n' "${SUBTEST_NAMES[$((position - 1))]}"
    return 0
  fi

  case "${status}" in
    "${STATUS_SETLOCALE}")
      printf 'harness refused to start: setlocale() failed\n'
      ;;
    126)
      printf 'not executable (shell status 126)\n'
      ;;
    127)
      printf 'binary not found (shell status 127)\n'
      ;;
    129|13[0-9]|1[4-8][0-9]|19[0-9])
      printf 'killed by signal %s\n' "$((status - 128))"
      ;;
    *)
      # Including 125, which is harness/main.c's clamp ceiling from
      # tests/libtest/first.c:L289 and therefore means the test returned
      # something larger than any sub-test code.
      printf 'unrecognized status, not a sub-test code\n'
      ;;
  esac
}

# ------------------------------------------------------------------------
# The environment matrix
# ------------------------------------------------------------------------

# Three settings gate the test's internationalized-domain assertions, and
# dropping any one of them makes those assertions stop running while the
# harness still prints success -- a false green, which is worse than a
# failure. Two of the three are environment variables and belong here; the
# third is the setlocale(LC_ALL, "") call in harness/main.c, which this
# script must not defeat and does confirm is present.
#
#   LC_ALL, which tests/data/test1560:L14 sets to C.UTF-8. libidn2 is
#   reached through the lookup macro at lib/idn.c:L35-L41, which off Windows
#   expands to the locale-aware idn2_lookup_ul, so a non-ASCII host converts
#   only while the process codeset is UTF-8.
#
#   CURL_TEST_HAVE_CODESET_UTF8, which tests/runtests.pl:L836-L839 exports
#   when the codeset supports UTF-8 and tests/libtest/lib1560.c:L2036 reads
#   into has_utf8, gating the CURLU_PUNYCODE and CURLU_PUNY2IDN rows of
#   setget_parts at its L1446, of get_url at L1548 and of get_parts at
#   L1591. It is tested for mere PRESENCE, so the "unset" half of this
#   matrix has to unset it rather than set it empty -- which is what the
#   empty entry in ENV_CODESETS means and what run_harness() below does with
#   env -u.
#
# All four combinations are run, not only the passing one, because the
# reference is the oracle including its failure modes: under LC_ALL=C the
# locale-aware lookup fails every non-ASCII input, that propagates to
# CURLUE_BAD_HOSTNAME and the reference itself exits 3, naming get_url. A
# locale-independent IDN backend would instead succeed there. So the
# comparison is always Rust against reference WITHIN one environment, never
# across two.
ENV_LABELS=(utf8-codeset utf8-nocodeset c-codeset c-nocodeset)
ENV_LOCALES=(C.UTF-8 C.UTF-8 C C)
ENV_CODESETS=(1 '' 1 '')

# The environment whose result the acceptance criteria are written against:
# both variables set, as tests/data/test1560 and tests/runtests.pl between
# them produce. A5 is that this one prints "success".
PRIMARY_ENV=utf8-codeset

# The locale and codeset values for one environment label are looked up in
# those three arrays by label, rather than carried around as a pair of
# parallel indices, so that every caller names the environment it means.
env_locale() {
  local label="${1}"
  local index=0

  while [ "${index}" -lt "${#ENV_LABELS[@]}" ]; do
    if [ "${ENV_LABELS[${index}]}" = "${label}" ]; then
      printf '%s\n' "${ENV_LOCALES[${index}]}"
      return 0
    fi
    index=$((index + 1))
  done
  fatal "env_locale: no such environment label '${label}'"
}

# The codeset value for one environment label, empty meaning "unset it".
env_codeset() {
  local label="${1}"
  local index=0

  while [ "${index}" -lt "${#ENV_LABELS[@]}" ]; do
    if [ "${ENV_LABELS[${index}]}" = "${label}" ]; then
      printf '%s\n' "${ENV_CODESETS[${index}]}"
      return 0
    fi
    index=$((index + 1))
  done
  fatal "env_codeset: no such environment label '${label}'"
}

# Runs one binary once in one environment, capturing stdout and stderr to
# separate files and returning the exit status through a global.
#
# stdout and stderr are never merged, and the reason is not tidiness.
# Acceptance rests on a diff of stdout alone: tests/libtest/lib1560.c owns
# every byte of it, while its failure detail on stderr carries __FILE__ and
# __LINE__ of the staged test source, whose absolute path differs between the
# reference tree and this one. Merging them would make the diff fail on a path
# rather than on the port. harness/main.c sends its "Test ended with result"
# line to stderr for the same reason, mirroring tests/libtest/first.c:L280.
#
#   $1  binary
#   $2  environment label
#   $3  destination stem for the capture files
LAST_RUN_STATUS=0
run_harness_once() {
  local binary="${1}"
  local label="${2}"
  local stem="${3}"
  local locale_value
  local codeset_value
  local envargs=()

  locale_value="$(env_locale "${label}")"
  codeset_value="$(env_codeset "${label}")"

  # CURL_TEST_HAVE_CODESET_UTF8 is tested for mere presence at
  # tests/libtest/lib1560.c:L2036, so the "unset" half of the matrix has to
  # remove it from the environment rather than set it empty. env -u is what
  # removes it, and it is also what keeps a value inherited from the
  # surrounding shell -- from a runtests.pl run in the same terminal, say --
  # from silently turning that half of the matrix into a duplicate of the
  # other.
  if [ -n "${codeset_value}" ]; then
    envargs=(env "LC_ALL=${locale_value}"
             "CURL_TEST_HAVE_CODESET_UTF8=${codeset_value}")
  else
    envargs=(env -u CURL_TEST_HAVE_CODESET_UTF8 "LC_ALL=${locale_value}")
  fi

  LAST_RUN_STATUS=0
  "${envargs[@]}" "${binary}" > "${stem}.stdout" 2> "${stem}.stderr" ||
    LAST_RUN_STATUS="$?"
  printf '%s\n' "${LAST_RUN_STATUS}" > "${stem}.status"
}

# Markers used to prove which optional assertion blocks the test compiled.
# Each is a literal from inside one conditional block, matched as a fixed
# string against preprocessed output, so that the answer is measured rather
# than inferred from the -D flags that were passed.
#
# The IDN marker is the punycode form of the test's own example. Its
# non-ASCII counterpart is deliberately NOT written here: scripts/spacecheck.pl
# allows the bytes C3 and B6 individually and flags every other byte above
# 7F, so the a-diaeresis and a-ring of that hostname cannot appear in this
# file at all. The punycode form is pure ASCII and identifies the block just
# as well.
IDN_MARKER='xn--rksmrgs-5wao1o.se'
WEBSOCKET_MARKER='ws://example.com/color/'
WINDOWS_MARKER='C:\\programs\\foo'

# ------------------------------------------------------------------------
# Options
# ------------------------------------------------------------------------

# Environment labels the caller asked for, accumulated so that --env can be
# repeated.
ENV_SELECTION=''

while [ "$#" -gt 0 ]; do
  case "${1}" in
    -h|--help)
      usage
      exit 0
      ;;
    --check-abi)
      WANT_ABI_RUN=1
      ;;
    --ignore-abi)
      IGNORE_ABI=1
      ;;
    -m|--mode)
      if [ "$#" -lt 2 ]; then
        fatal "--mode needs an argument: a, b or both"
      fi
      MODES_REQUESTED="${2}"
      shift
      ;;
    -e|--env)
      if [ "$#" -lt 2 ]; then
        fatal "--env needs an argument: one of ${ENV_LABELS[*]}"
      fi
      ENV_SELECTION="${ENV_SELECTION} ${2}"
      shift
      ;;
    -a|--attempts)
      if [ "$#" -lt 2 ]; then
        fatal "--attempts needs a number"
      fi
      ATTEMPTS="${2}"
      shift
      ;;
    --no-demo)
      WANT_DEMO=0
      ;;
    --valgrind)
      WANT_VALGRIND=1
      ;;
    *)
      printf 'run-parity.sh: error: unknown option %s\n' "${1}" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

if [ -n "${ENV_SELECTION}" ]; then
  ENVS_REQUESTED="${ENV_SELECTION}"
fi

case "${ATTEMPTS}" in
  ''|*[!0-9]*)
    fatal "--attempts takes a number, not '${ATTEMPTS}'"
    ;;
esac
if [ "${ATTEMPTS}" -lt 1 ]; then
  fatal "--attempts must be at least 1"
fi

# Which link modes to exercise. Mode B is not optional in the ordinary sense:
# it proves the crate is independently linkable, and a Mode B failure is a
# real failure rather than a skip. The option exists for bisecting one mode.
RUN_MODE_A=0
RUN_MODE_B=0
case "${MODES_REQUESTED}" in
  both) RUN_MODE_A=1; RUN_MODE_B=1 ;;
  a|A|mode-a) RUN_MODE_A=1 ;;
  b|B|mode-b) RUN_MODE_B=1 ;;
  *) fatal "--mode takes a, b or both, not '${MODES_REQUESTED}'" ;;
esac

# Resolve the requested environment labels against the table, so that a typo
# is reported here rather than silently narrowing the matrix to nothing.
SELECTED_ENVS=()
if [ "${ENVS_REQUESTED}" = "all" ]; then
  SELECTED_ENVS=("${ENV_LABELS[@]}")
else
  # Deliberate word splitting: the value is a list of labels, from --env
  # accumulation or from PARITY_ENVIRONMENTS.
  read -r -a REQUESTED_ARRAY <<< "${ENVS_REQUESTED}"
  for requested in "${REQUESTED_ARRAY[@]}"; do
    matched=0
    for label in "${ENV_LABELS[@]}"; do
      if [ "${requested}" = "${label}" ]; then
        matched=1
      fi
    done
    if [ "${matched}" = "0" ]; then
      fatal "unknown environment label '${requested}'. Known labels are \
${ENV_LABELS[*]}"
    fi
    SELECTED_ENVS+=("${requested}")
  done
fi

# ------------------------------------------------------------------------
# Scratch tree, transcript and summary file
# ------------------------------------------------------------------------

# Every directory this script writes into, created before anything is
# written. All of them are under build/, which ../.gitignore covers; see the
# note in the header about why that sibling file is needed at all.
mkdir -p "${BUILD}" "${PARITY_DIR}" "${OBJ_DIR}" "${RUN_DIR}" \
         "${MODE_A_DIR}" "${MODE_B_DIR}" "${STAGE_DIR}"

# Truncated rather than appended, so that a transcript always describes one
# run. The previous one is of no use once this one starts disagreeing with
# it.
: > "${LOG_FILE}"
LOG_READY=1

: > "${SUMMARY_FILE}"
fact 'schema' 'curl-urlapi-rs/run-parity/1'
fact 'generated-by' 'rust-urlapi/scripts/run-parity.sh'
fact 'crate-root' "${CRATE_DIR}"
fact 'repo-root' "${REPO_ROOT}"
fact 'build-root' "${BUILD}"

say "curl-urlapi-rs parity run"
say "  crate:      ${CRATE_DIR}"
say "  repository: ${REPO_ROOT}"
say "  scratch:    ${BUILD}"
say "  transcript: ${LOG_FILE}"

section "Prerequisites"

# Reported all at once rather than one per run, because a reader fixing an
# environment wants the whole list. The compiler is checked under whatever
# name CC gives it, so that a wrong CC is reported here rather than as a
# mysterious compilation failure later.
#
# Each name below is called by this script: cc compiles and links, ar copies
# and strips the archive, nm reads the symbol tables the control link is
# judged by, ln stages the test source, readlink verifies that staging, diff
# and cmp are the parity verdict itself, and env runs each binary with one
# variable set or unset.
MISSING_TOOLS=()
for tool in "${CC_BIN}" ar nm ln readlink diff cmp env grep sed awk tr \
            wc cat cp mkdir; do
  if ! have "${tool}"; then
    MISSING_TOOLS+=("${tool}")
  fi
done

if [ "${#MISSING_TOOLS[@]}" -gt 0 ]; then
  fatal "these commands are needed and were not found: \
${MISSING_TOOLS[*]}. On a Debian or Ubuntu system build-essential supplies \
the compiler, ar and nm, and coreutils supplies the rest"
fi
say "  all required commands are present"

# valgrind is optional and only consulted when asked for; see the R3 note in
# the constraint report for what it substitutes for and what it does not.
HAVE_VALGRIND=0
if have valgrind; then
  HAVE_VALGRIND=1
fi
if [ "${WANT_VALGRIND}" = "1" ] && [ "${HAVE_VALGRIND}" = "0" ]; then
  warn "--valgrind was requested but valgrind is not installed. The \
allocation count is skipped; every other check still runs"
  WANT_VALGRIND=0
fi

section "Inputs from the build scripts"

# The two summary files are hard requirements, and their absence is the most
# common way to reach this script too early, so each is named with the script
# that writes it.
if [ ! -f "${REFERENCE_FACTS}" ]; then
  fatal "no ${REFERENCE_FACTS}. Run scripts/build-reference.sh first: it \
builds the C baseline every comparison here is made against, captures the \
golden outputs and records the archive, the member name, the link line and \
the preprocessor state that this script consumes"
fi
if [ ! -f "${RUST_FACTS}" ]; then
  fatal "no ${RUST_FACTS}. Run scripts/build-rust.sh first: it builds the \
crate in both feature configurations and records where each archive is"
fi
say "  reference facts: ${REFERENCE_FACTS}"
say "  crate facts:     ${RUST_FACTS}"

# Files, never re-derived. Each may be overridden from the environment, and
# each override is used as given so that a typo in one is reported as a
# missing file the caller named rather than being quietly replaced.
REFERENCE_ARCHIVE="$(require_fact "${REFERENCE_ARCHIVE:-}" \
  "${REFERENCE_FACTS}" 'REFERENCE_ARCHIVE' 'scripts/build-reference.sh')"
RECORDED_MEMBER="$(require_fact "${REFERENCE_URLAPI_MEMBER:-}" \
  "${REFERENCE_FACTS}" 'REFERENCE_URLAPI_MEMBER' \
  'scripts/build-reference.sh')"
REFERENCE_SYSTEM_LIBS="$(require_fact "${REFERENCE_SYSTEM_LIBS:-}" \
  "${REFERENCE_FACTS}" 'REFERENCE_SYSTEM_LIBS' 'scripts/build-reference.sh')"
MODE_A_ARCHIVE="$(require_fact "${MODE_A_ARCHIVE:-}" "${RUST_FACTS}" \
  'mode-a-archive' 'scripts/build-rust.sh')"
MODE_B_ARCHIVE="$(require_fact "${MODE_B_ARCHIVE:-}" "${RUST_FACTS}" \
  'mode-b-archive' 'scripts/build-rust.sh')"

# The staged test source file name, which is also the value runner.c is
# compiled with. Defaulted rather than required: the name is an implementation
# detail of the staging directory and lib1560.c is what both scripts use.
STAGED_NAME="$(read_fact "${REFERENCE_FACTS}" 'HARNESS_TEST_SOURCE')"
if [ -z "${STAGED_NAME}" ]; then
  STAGED_NAME='lib1560.c'
fi

# The reference binaries and their golden captures. Optional in the narrow
# sense that the captures can stand in for the binaries -- see the reference
# participant in the run matrix -- but a missing golden directory is fatal,
# because then there is nothing to compare against at all.
REFERENCE_HARNESS="$(read_fact "${REFERENCE_FACTS}" 'REFERENCE_HARNESS_BIN')"
REFERENCE_DEMO="$(read_fact "${REFERENCE_FACTS}" 'REFERENCE_DEMO_BIN')"
GOLDEN_DIR="$(read_fact "${REFERENCE_FACTS}" 'GOLDEN_DIR')"
if [ -z "${GOLDEN_DIR}" ]; then
  GOLDEN_DIR="${BUILD}/golden"
fi
if [ ! -d "${GOLDEN_DIR}" ]; then
  fatal "no golden directory at ${GOLDEN_DIR}. scripts/build-reference.sh \
captures the reference harness output there, under all four environments, \
and those captures are what the Rust runs are diffed against"
fi

# Existence checks for everything that must be readable, reported together.
MISSING_INPUTS=()
for input in "${REFERENCE_ARCHIVE}" "${MODE_A_ARCHIVE}" "${MODE_B_ARCHIVE}" \
             "${HARNESS_SHIM}" "${HARNESS_RUNNER}" "${HARNESS_MAIN}" \
             "${HARNESS_SHIMS}" "${DEMO_SOURCE}" "${DEMO_GOLDEN}" \
             "${TEST_SOURCE}" "${REPO_ROOT}/include/curl/urlapi.h" \
             "${MIRROR_INCLUDE_DIR}/curl_urlapi_rs.h"; do
  if [ ! -r "${input}" ]; then
    MISSING_INPUTS+=("${input}")
  fi
done
if [ "${#MISSING_INPUTS[@]}" -gt 0 ]; then
  fatal "these inputs are missing or unreadable: ${MISSING_INPUTS[*]}. A \
missing archive means scripts/build-reference.sh or scripts/build-rust.sh \
has not run in this scratch tree; a missing file under the crate means the \
crate itself is incomplete"
fi

say "  reference archive: ${REFERENCE_ARCHIVE}"
say "  Mode A archive:    ${MODE_A_ARCHIVE}"
say "  Mode B archive:    ${MODE_B_ARCHIVE}"
say "  demo golden:       ${DEMO_GOLDEN} (read only, never written here)"

fact 'reference-archive' "${REFERENCE_ARCHIVE}"
fact 'mode-a-archive' "${MODE_A_ARCHIVE}"
fact 'mode-b-archive' "${MODE_B_ARCHIVE}"
fact 'demo-golden' "${DEMO_GOLDEN}"
fact 'golden-dir' "${GOLDEN_DIR}"

# The feature configuration each archive was built with, reported rather than
# assumed, and checked for the one combination that cannot link.
#
# Mode A must NOT carry strerror or cfree: curl_url_strerror lives in
# lib/strerror.c and curl_free in lib/escape.c, both of which take part in a
# drop-in link, so exporting either from the crate duplicates a symbol the
# archive already defines. build-rust.sh builds Mode A with
# --no-default-features for exactly that reason, and check-abi.sh asserts the
# resulting symbol set; this is the cheap early diagnostic, so that a
# misconfigured archive is named here instead of surfacing as a linker error
# forty lines of output later.
MODE_A_FEATURES="$(read_fact "${RUST_FACTS}" 'mode-a-effective-features')"
MODE_B_FEATURES="$(read_fact "${RUST_FACTS}" 'mode-b-effective-features')"
IDN_BACKEND="$(read_fact "${RUST_FACTS}" 'idn-backend')"
say "  Mode A features:   ${MODE_A_FEATURES:-unrecorded}"
say "  Mode B features:   ${MODE_B_FEATURES:-unrecorded}"
say "  IDN backend:       ${IDN_BACKEND:-unrecorded}"
fact 'mode-a-features' "${MODE_A_FEATURES:-unrecorded}"
fact 'mode-b-features' "${MODE_B_FEATURES:-unrecorded}"
fact 'idn-backend' "${IDN_BACKEND:-unrecorded}"

case "${MODE_A_FEATURES}" in
  *strerror*|*cfree*)
    fatal "the Mode A archive was built with ${MODE_A_FEATURES}, which \
exports curl_url_strerror or curl_free. Both are already defined by the \
libcurl archive a drop-in link uses -- strerror.c.o and escape.c.o -- so the \
link would fail on duplicate symbols. Rebuild with scripts/build-rust.sh, \
which uses --no-default-features --features idn-libidn2 for this mode"
    ;;
esac

# The pure-Rust IDN backend is a documented opt-in and is documented as NOT
# bit-for-bit: no transitional retry, locale independence which inverts the
# usual direction of failure, and different Unicode tables. Saying so here,
# loudly, is the difference between a parity claim and a parity-shaped claim.
if [ -n "${IDN_BACKEND}" ] && [ "${IDN_BACKEND}" != "libidn2" ]; then
  warn "the crate was built with the ${IDN_BACKEND} internationalized-domain \
backend. Parity claims do not apply to it: docs/KNOWN-DIVERGENCES.md records \
that it has no transitional retry, is locale-independent where libidn2 is \
not, and uses different Unicode tables. Whatever this run reports, it is not \
evidence about the default backend"
fi

section "The symbol-set gate"

# This runs before any behavior is measured, and the reason is worth stating:
# if the crate does not export the symbol set the object built from
# lib/urlapi.c exports, then every result below is measuring something other
# than a drop-in replacement. scripts/check-abi.sh is the check; this is the
# gate that refuses to proceed past a failing one.
ABI_VERDICT='not-run'
if [ "${WANT_ABI_RUN}" = "1" ]; then
  if [ ! -x "${ABI_SCRIPT}" ]; then
    fatal "--check-abi was requested but ${ABI_SCRIPT} is missing or not \
executable"
  fi
  say "  running ${ABI_SCRIPT}"
  ABI_RUN_STATUS=0
  # Allowed to fail so that its status can be read and reported; without the
  # || the errexit setting would abort here and the diagnostic below, which
  # is the useful part, would never print.
  "${ABI_SCRIPT}" > "${PARITY_DIR}/check-abi.log" 2>&1 || ABI_RUN_STATUS="$?"
  cat "${PARITY_DIR}/check-abi.log" >> "${LOG_FILE}"
  if [ "${ABI_RUN_STATUS}" = "0" ]; then
    ABI_VERDICT='pass'
    say "  scripts/check-abi.sh passed"
  else
    ABI_VERDICT='fail'
    say "  scripts/check-abi.sh exited ${ABI_RUN_STATUS}; its output is in \
${PARITY_DIR}/check-abi.log"
  fi
else
  ABI_VERDICT="$(read_fact "${ABI_FACTS}" 'result')"
  if [ -z "${ABI_VERDICT}" ]; then
    ABI_VERDICT='not-run'
  fi
fi

case "${ABI_VERDICT}" in
  pass)
    pass "the exported symbol set matches the C object (A2, recorded by \
scripts/check-abi.sh)"
    ;;
  not-run)
    warn "scripts/check-abi.sh has not run in this scratch tree, so no \
${ABI_FACTS} exists. A symbol mismatch makes every behavior result below \
meaningless, so run it -- or pass --check-abi to have this script run it -- \
before treating anything here as evidence of parity"
    ;;
  *)
    if [ "${IGNORE_ABI}" = "1" ]; then
      warn "the recorded symbol-set verdict is '${ABI_VERDICT}' and \
--ignore-abi was given, so the run continues. Nothing below is evidence of \
parity while that verdict stands"
      fail "the symbol-set verdict is '${ABI_VERDICT}' (A2)"
    else
      fatal "the recorded symbol-set verdict is '${ABI_VERDICT}'. A symbol \
mismatch makes every behavior result below meaningless, so this stops here. \
Fix the export set, re-run scripts/check-abi.sh, and only then this script. \
Pass --ignore-abi to proceed anyway while investigating"
    fi
    ;;
esac
fact 'abi-verdict' "${ABI_VERDICT}"

section "Preprocessor parity"

# tests/libtest/lib1560.c compiles a different set of assertions depending on
# three macros: USE_IDN, which its L34-L36 folds from USE_LIBIDN2,
# USE_WIN32_IDN and USE_APPLE_IDN and which gates the IDN rows at L200-L223
# and the punycode expectation at L629-L632; CURL_DISABLE_WEBSOCKETS at its
# L295, gating the ws:// and wss:// rows; and _WIN32 at its L361, gating the
# drive-letter and network-path rows.
#
# harness/runner.c deliberately defines none of the three and says so, which
# leaves the build as the single owner. That is what makes this section
# possible: the reference harness was compiled with whatever
# build-reference.sh recorded as HARNESS_DEFINES, and the Rust harness has to
# be compiled with the IDENTICAL value or the byte-for-byte diff compares two
# different test suites and proves nothing. So the recorded value is the
# default here, and an override that disagrees with it is refused rather than
# honored.
#
# The colon-less ${VAR-default} form is deliberate: it applies the default
# only when the variable is UNSET, so a caller with a reference build that
# has no libidn2 can ask for no defines at all with HARNESS_DEFINES=, and
# ${VAR:-default} would silently hand them -DUSE_LIBIDN2 instead.
RECORDED_DEFINES="$(read_fact "${REFERENCE_FACTS}" 'HARNESS_DEFINES')"
RECORDED_CFLAGS="$(read_fact "${REFERENCE_FACTS}" 'HARNESS_CFLAGS')"
HARNESS_DEFINES="${HARNESS_DEFINES-${RECORDED_DEFINES}}"
HARNESS_CFLAGS="${HARNESS_CFLAGS-${RECORDED_CFLAGS}}"

if [ "${HARNESS_DEFINES}" != "${RECORDED_DEFINES}" ]; then
  fatal "the reference harness was compiled with HARNESS_DEFINES \
'${RECORDED_DEFINES}' and this run was asked for '${HARNESS_DEFINES}'. Those \
two compile different sets of assertions from the same test source, so \
diffing their output would compare two different suites. Re-run \
scripts/build-reference.sh with the value you want, then this script"
fi

if [ "${HARNESS_CFLAGS}" != "${RECORDED_CFLAGS}" ]; then
  warn "compiler options differ from the reference build: '${HARNESS_CFLAGS}' \
here against '${RECORDED_CFLAGS}' there. Optimization options do not change \
which assertions compile, so this is reported rather than refused, unlike a \
preprocessor difference"
fi

# The staging directory has to be the one the reference harness compiled
# from, since both binaries must be built from identical inputs. It is the
# same path by construction whenever BUILD_DIR is left alone.
RECORDED_STAGE="$(read_fact "${REFERENCE_FACTS}" 'HARNESS_STAGE_DIR')"
if [ -n "${RECORDED_STAGE}" ] &&
   [ "${RECORDED_STAGE}" != "${STAGE_DIR}" ]; then
  warn "the reference harness was compiled from ${RECORDED_STAGE} and this \
run stages into ${STAGE_DIR}. Both hold a symlink to the same unmodified \
test source and a copy of the same shim, so the compilation is equivalent, \
but the two trees can drift; keeping BUILD_DIR the same for both scripts \
avoids the question"
fi

# Split into arrays for the compiler argument lists. Word splitting is the
# intended behavior for a list of flags, which is why it is done deliberately
# through read rather than by leaving an expansion unquoted. An empty value
# yields an empty array, and expanding an empty array under "set -u" is well
# defined in bash 4.4 and later.
read -r -a HARNESS_DEFINES_ARRAY <<< "${HARNESS_DEFINES}"
read -r -a HARNESS_CFLAGS_ARRAY <<< "${HARNESS_CFLAGS}"
read -r -a REFERENCE_SYSTEM_LIBS_ARRAY <<< "${REFERENCE_SYSTEM_LIBS}"

# The macro that names the staged test source, spelled exactly as
# harness/runner.c expects: that file guards on HARNESS_TEST_SOURCE, emits an
# #error naming this spelling when it is undefined, and then uses the value as
# an include operand, so it has to arrive complete with its quotes. Required
# in BOTH link modes.
TEST_SOURCE_DEFINE="-DHARNESS_TEST_SOURCE=\"${STAGED_NAME}\""

# The include path, and what is deliberately not on it. -I<stage> supplies
# the staged test source and is also what makes the shim win the test's own
# quoted include; -I<repo>/include supplies the real public headers from the
# unmodified tree. <repo>/lib is NEVER added: the harness must see the public
# API and nothing else, and adding it would let the shim's includes reach
# libcurl's private headers and quietly change which assertions compile.
HARNESS_INCLUDES_ARRAY=("-I${STAGE_DIR}" "-I${REPO_ROOT}/include")

say "  preprocessor state: ${HARNESS_DEFINES} ${TEST_SOURCE_DEFINE}"
say "  compiler options:   ${HARNESS_CFLAGS}"
say "  include path:       ${HARNESS_INCLUDES_ARRAY[*]}"
fact 'harness-defines' "${HARNESS_DEFINES}"
fact 'harness-cflags' "${HARNESS_CFLAGS}"
fact 'harness-test-source' "${STAGED_NAME}"

section "Staging the unmodified test source"

# KEEP IN STEP WITH build-reference.sh, whose stage_test_source() carries the
# same note. Both harness binaries have to compile from the SAME staged
# inputs, so that script owns the staging and this one reuses the directory it
# left behind, verifying rather than silently re-creating it. These three
# steps are its three steps.
#
# Why a staging directory exists at all: tests/libtest/lib1560.c:L33 contains
# exactly one include directive, a quoted "first.h", and a quoted include is
# searched in the directory the compiler opened the INCLUDING file from before
# any -I path. Compiling the test source in place would therefore always
# resolve first.h to the real tests/libtest/first.h -- 574 lines that pull in
# libcurl's private build environment through "curl_setup.h" at its L33 and
# <curlx/curlx.h> at its L46. Reaching the test source through this directory
# instead puts the roughly twenty-line shim in that position. It is the only
# arrangement that honors "the test file is unmodified" and "do not touch
# tests/" at the same time, and nothing under tests/ is written here: the
# symlink and the shim copy both land in the ignored scratch tree.
STAGED_TEST="${STAGE_DIR}/${STAGED_NAME}"
STAGED_SHIM="${STAGE_DIR}/first.h"

if [ -L "${STAGED_TEST}" ]; then
  STAGED_TARGET="$(readlink "${STAGED_TEST}")"
  if [ "${STAGED_TARGET}" = "${TEST_SOURCE}" ]; then
    say "  reusing ${STAGED_TEST} -> ${STAGED_TARGET}"
  else
    warn "${STAGED_TEST} pointed at ${STAGED_TARGET} and has been repointed \
at ${TEST_SOURCE}. A stale target would have compared the port against some \
other copy of the test"
    if ! ln -sfn "${TEST_SOURCE}" "${STAGED_TEST}"; then
      fatal "could not link ${TEST_SOURCE} into ${STAGE_DIR}"
    fi
  fi
elif [ -e "${STAGED_TEST}" ]; then
  # A regular file here would be a second, drifting instance of a file the
  # port is required to consume byte-unchanged. Replaced with the symlink
  # rather than tolerated.
  warn "${STAGED_TEST} was a regular file, not a symlink, and has been \
replaced by a symlink to ${TEST_SOURCE}. A copy would stop tracking the \
original silently"
  if ! ln -sfn "${TEST_SOURCE}" "${STAGED_TEST}"; then
    fatal "could not link ${TEST_SOURCE} into ${STAGE_DIR}"
  fi
else
  if ! ln -sfn "${TEST_SOURCE}" "${STAGED_TEST}"; then
    fatal "could not link ${TEST_SOURCE} into ${STAGE_DIR}"
  fi
  say "  staged ${STAGED_TEST} -> ${TEST_SOURCE}"
fi

# The shim is copied rather than linked, as build-reference.sh copies it: the
# compiler resolves the quoted include against the directory it opened the
# including file from, so either works, but a copy makes the staged directory
# self-describing. Refreshed whenever it differs from harness/first.h, so
# that an edit there is never silently stale here.
if [ -f "${STAGED_SHIM}" ] && cmp -s "${HARNESS_SHIM}" "${STAGED_SHIM}"; then
  say "  reusing ${STAGED_SHIM}, byte-identical to harness/first.h"
else
  if ! cp -f "${HARNESS_SHIM}" "${STAGED_SHIM}"; then
    fatal "could not copy ${HARNESS_SHIM} into ${STAGE_DIR}"
  fi
  say "  refreshed ${STAGED_SHIM} from harness/first.h"
fi

# Proof that the staged header is the shim, not the real one. If it were ever
# the real one it would name libcurl's private setup header, and every IDN
# assertion in the test would then depend on a build environment this harness
# does not have.
if grep -q 'HEADER_RUST_URLAPI_HARNESS_FIRST_H' "${STAGED_SHIM}"; then
  pass "the staged first.h is the harness shim"
else
  fatal "${STAGED_SHIM} is not the harness shim. The quoted include in \
tests/libtest/lib1560.c would then resolve to libcurl's private build \
environment"
fi

section "Proof that the staged shim wins the quoted include"

# The quoted-include mechanic is the single load-bearing trick of the whole
# harness, so it is measured rather than trusted. The dependency list the
# preprocessor emits names every header it actually opened, which makes it the
# cheapest possible proof: the staged shim must be in it and the real
# tests/libtest/first.h must not. If the real one ever won, the run would be
# invalid, and it would be invalid quietly -- the test would still compile,
# just against a different set of assertions.
INCLUDE_PROOF="${PARITY_DIR}/include-proof.txt"
INCLUDE_PROOF_ERR="${PARITY_DIR}/include-proof.err"
if ! "${CC_BIN}" "${HARNESS_DEFINES_ARRAY[@]}" "${TEST_SOURCE_DEFINE}" \
     "${HARNESS_INCLUDES_ARRAY[@]}" -M "${HARNESS_RUNNER}" \
     > "${INCLUDE_PROOF}" 2> "${INCLUDE_PROOF_ERR}"; then
  cat "${INCLUDE_PROOF_ERR}" >&2
  cat "${INCLUDE_PROOF_ERR}" >> "${LOG_FILE}"
  fatal "the preprocessor could not resolve the harness includes. Its output \
is in ${INCLUDE_PROOF_ERR}; a missing staged test source or a wrong include \
path is the usual cause"
fi

if grep -q -F "${STAGED_TEST}" "${INCLUDE_PROOF}"; then
  pass "the test source was opened as ${STAGED_TEST}"
else
  fatal "${STAGED_TEST} is not in the dependency list at ${INCLUDE_PROOF}. \
The compilation reached the test source some other way, so the shim cannot be \
relied on to have won the quoted include"
fi

if grep -q -F "${STAGED_SHIM}" "${INCLUDE_PROOF}"; then
  pass "the test source's own include resolved to ${STAGED_SHIM}"
else
  fatal "${STAGED_SHIM} is not in the dependency list at ${INCLUDE_PROOF}"
fi

if grep -q -F "${PRIVATE_FIRST_H}" "${INCLUDE_PROOF}"; then
  fatal "${PRIVATE_FIRST_H} is in the dependency list at ${INCLUDE_PROOF}. \
The real 574-line harness header won the quoted include, which pulls in \
libcurl's private build environment and changes which assertions the test \
compiles. The run would be invalid, so it stops here"
else
  pass "tests/libtest/first.h took no part in the compilation"
fi

section "Which optional assertion blocks the test compiled"

# Three conditional blocks in tests/libtest/lib1560.c change what the run
# asserts, and the state of all three is measured here from preprocessed
# output rather than inferred from the -D flags. Inference would be the
# weaker answer twice over: a flag can be passed and have no effect, and a
# block can be live for a reason no flag on this command line explains.
PREPROCESSED="${PARITY_DIR}/preprocessed.i"
if ! "${CC_BIN}" "${HARNESS_DEFINES_ARRAY[@]}" "${TEST_SOURCE_DEFINE}" \
     "${HARNESS_INCLUDES_ARRAY[@]}" -E "${HARNESS_RUNNER}" \
     > "${PREPROCESSED}" 2>> "${LOG_FILE}"; then
  fatal "the harness source could not be preprocessed; see ${LOG_FILE}"
fi

IDN_ROWS='absent'
if grep -q -F "${IDN_MARKER}" "${PREPROCESSED}"; then
  IDN_ROWS='live'
fi
WEBSOCKET_ROWS='absent'
if grep -q -F "${WEBSOCKET_MARKER}" "${PREPROCESSED}"; then
  WEBSOCKET_ROWS='live'
fi
WINDOWS_ROWS='absent'
if grep -q -F "${WINDOWS_MARKER}" "${PREPROCESSED}"; then
  WINDOWS_ROWS='live'
fi

say "  USE_IDN rows (L200-L223, L629-L632):        ${IDN_ROWS}"
say "  websocket rows (L295-L304):                 ${WEBSOCKET_ROWS}"
say "  _WIN32 rows (L361-L375):                    ${WINDOWS_ROWS}"
fact 'idn-rows' "${IDN_ROWS}"
fact 'websocket-rows' "${WEBSOCKET_ROWS}"
fact 'windows-rows' "${WINDOWS_ROWS}"

# When the build asked for internationalized-domain support, the rows have to
# be there. This is the first half of acceptance criterion A8: assertions that
# silently do not run are the failure mode that matters, because the harness
# still prints success and the run still looks green.
case "${HARNESS_DEFINES}" in
  *USE_LIBIDN2*|*USE_WIN32_IDN*|*USE_APPLE_IDN*)
    if [ "${IDN_ROWS}" = "live" ]; then
      pass "the internationalized-domain rows are compiled in (A8, first \
half: the rows exist)"
    else
      fatal "the preprocessor state asks for internationalized-domain \
support -- ${HARNESS_DEFINES} -- yet ${IDN_MARKER} is absent from the \
preprocessed source, so tests/libtest/lib1560.c:L34-L36 did not fold it into \
USE_IDN and none of those rows will run. The harness would print success \
having exercised none of the conversion this port is most likely to get wrong"
    fi
    ;;
  *)
    warn "no internationalized-domain macro is defined, so the rows at \
tests/libtest/lib1560.c:L200-L223 and L629-L632 are not compiled and \
acceptance criterion A8 cannot be met by this run. The default configuration \
of scripts/build-reference.sh passes -DUSE_LIBIDN2"
    ;;
esac

# Windows-only paths in this port are compiled conditionally and are NOT
# validated here. Reported as its own line rather than left to be inferred
# from the absence of a line.
if [ "${WINDOWS_ROWS}" = "absent" ]; then
  say "  note: the drive-letter and network-path rows are not compiled on \
this platform, so the port's Windows-only paths are not exercised by this run"
fi

section "Compiling the harness translation units"

# Compiled once, to objects, and reused by every link below: the intact
# control link, the failing control link, Mode A and Mode B. That is both
# faster and stronger evidence -- the three links are then demonstrably
# comparing the same translation units, rather than three compilations that
# ought to be identical.
#
# One compiler command, with its output kept and any warning made loud. A
# warning does not fail the run: the object is still correct and a later
# compiler release adding a benign diagnostic must not stop the parity
# workflow.
#
#   $1    label used for the log file name and in diagnostics
#   $2    report, to print the diagnostics on failure, or silent, to keep
#         them in the log alone. Silent exists for the control link, whose
#         failure is the expected result and whose several hundred lines of
#         undefined-symbol output are evidence to be counted rather than an
#         error to be shown.
#   rest  the command to run
compiler_invoke() {
  local label="${1}"
  local on_failure="${2}"
  shift 2
  local output="${PARITY_DIR}/${label}.log"
  local status=0
  local warnings

  "$@" > "${output}" 2>&1 || status="$?"

  logonly "--- ${label} (${status}) ---"
  logonly "command: $*"
  cat "${output}" >> "${LOG_FILE}"

  if [ "${status}" != "0" ]; then
    if [ "${on_failure}" = "report" ]; then
      cat "${output}" >&2
    fi
    return "${status}"
  fi

  warnings="$(grep -c -E ': (warning|error):' "${output}" || true)"
  if [ "${warnings}" != "0" ]; then
    cat "${output}" >&2
    warn "the ${label} compilation produced ${warnings} warning line(s), \
kept in ${output}"
  fi
  return 0
}

# The ordinary form: a failure here is a defect and its diagnostics belong in
# front of whoever is reading.
compile_step() {
  compiler_invoke "${1}" report "${@:2}"
}

# The form for a command that is expected to fail.
compile_step_quiet() {
  compiler_invoke "${1}" silent "${@:2}"
}

RUNNER_OBJECT="${OBJ_DIR}/runner.o"
MAIN_OBJECT="${OBJ_DIR}/main.o"
SHIMS_OBJECT="${OBJ_DIR}/shims.o"

if ! compile_step runner "${CC_BIN}" "${HARNESS_CFLAGS_ARRAY[@]}" \
     "${HARNESS_DEFINES_ARRAY[@]}" "${TEST_SOURCE_DEFINE}" \
     "${HARNESS_INCLUDES_ARRAY[@]}" -c -o "${RUNNER_OBJECT}" \
     "${HARNESS_RUNNER}"; then
  fatal "harness/runner.c did not compile. It includes the staged test \
source, so a diagnostic from inside tests/libtest/lib1560.c means the staging \
or the include path is wrong, not the test"
fi
say "  ${RUNNER_OBJECT}"

if ! compile_step main "${CC_BIN}" "${HARNESS_CFLAGS_ARRAY[@]}" \
     "${HARNESS_DEFINES_ARRAY[@]}" "${TEST_SOURCE_DEFINE}" \
     "${HARNESS_INCLUDES_ARRAY[@]}" -c -o "${MAIN_OBJECT}" \
     "${HARNESS_MAIN}"; then
  fatal "harness/main.c did not compile"
fi
say "  ${MAIN_OBJECT}"

# harness/main.c owns the third of the three settings that gate the IDN
# assertions: setlocale(LC_ALL, ""), mirroring tests/libtest/first.c:L231.
# This script exports the other two and must not defeat that call, so its
# presence is confirmed rather than assumed. Without it a C program stays in
# the "C" locale whatever LC_ALL holds, libidn2's locale-aware lookup fails
# every non-ASCII name, and the gated rows quietly do not run.
if grep -q 'setlocale(LC_ALL, "")' "${HARNESS_MAIN}"; then
  pass "harness/main.c calls setlocale(LC_ALL, \"\"), so the locale the \
environment names takes effect"
else
  fail "harness/main.c does not call setlocale(LC_ALL, \"\"). The \
internationalized-domain assertions would not run whatever this script \
exports"
fi

# The Mode B shims are compiled only for the mode that links them.
# -DHARNESS_MODE_B is mandatory: harness/shims.c emits an #error without it,
# deliberately, so that compiling it into a Mode A link fails loudly instead
# of duplicating the curl_m*printf family that libcurl's own mprintf.c.o
# already defines.
#
# HARNESS_SHIM_CURL_FREE is NOT defined, in either mode. Mode B builds the
# crate with default features, so its cfree feature already exports
# curl_free from src/ffi.rs; defining the macro would have shims.c define it
# too, which is a hard multiple-definition error.
if [ "${RUN_MODE_B}" = "1" ]; then
  if ! compile_step shims "${CC_BIN}" "${HARNESS_CFLAGS_ARRAY[@]}" \
       -DHARNESS_MODE_B "${HARNESS_INCLUDES_ARRAY[@]}" \
       -c -o "${SHIMS_OBJECT}" "${HARNESS_SHIMS}"; then
    fatal "harness/shims.c did not compile. If the diagnostic is its own \
#error about HARNESS_MODE_B then this script failed to pass -DHARNESS_MODE_B, \
which is a defect here rather than in that file"
  fi
  say "  ${SHIMS_OBJECT} (-DHARNESS_MODE_B, without HARNESS_SHIM_CURL_FREE)"
fi

# ------------------------------------------------------------------------
# Link helpers
# ------------------------------------------------------------------------

# The eight globals the object built from lib/urlapi.c defines, which is the
# set a drop-in replacement has to satisfy. Five are public and declared in
# include/curl/urlapi.h; three are internal, declared in lib/urlapi-int.h at
# its L28-L33 and consumed elsewhere in libcurl.
DROPIN_SYMBOLS=(Curl_is_absolute_url Curl_junkscan Curl_url_set_authority
                curl_url curl_url_cleanup curl_url_dup curl_url_get
                curl_url_set)

# The six of those eight that MUST come up undefined when the harness is
# linked against a libcurl archive with the urlapi member deleted. They are
# reached from members this link always pulls in: url.c.o, http.c.o and
# http1.c.o among them.
MANDATORY_UNDEFINED=(Curl_is_absolute_url curl_url curl_url_cleanup
                     curl_url_dup curl_url_get curl_url_set)

# The other two are configuration-dependent, and this is measured rather than
# predicted. Curl_url_set_authority is reached only from lib/http2.c:L739, so
# it surfaces exactly when http2.c.o is pulled in, which depends on whether
# the reference build enabled HTTP/2. Curl_junkscan is reached only from
# lib/doh.c:L1127, inside that file's HTTPS-RR handling, so it surfaces only
# when that block is compiled. Neither absence is a defect; asserting on
# either would make this script fail on a perfectly good reference build.
OPTIONAL_UNDEFINED=(Curl_junkscan Curl_url_set_authority)

# Every symbol a linker reported as undefined, one per line, deduplicated.
# Two diagnostic spellings are recognized: GNU ld's "undefined reference to
# `sym'" and lld's "undefined symbol: sym".
extract_undefined() {
  # Assembled in two pieces only so that no line here runs past the column
  # limit the repository holds its sources to.
  local pattern='.*undefined (reference to|symbol:?)'
  pattern="${pattern}"'[^A-Za-z_]*([A-Za-z_][A-Za-z_0-9]*).*'

  sed -n -E "s/${pattern}/\\2/p" "${1}" | sort -u
}

# Which members of an archive reference a symbol, as a space-separated list.
# This is the evidence behind "that symbol did not surface because nothing
# pulled the object referencing it in": if the list is empty, no member of the
# archive wants the symbol at all.
archive_referrers() {
  local symbol="${1}"
  local archive="${2}"

  nm -A --undefined-only "${archive}" 2>/dev/null |
    awk -v sym="${symbol}" '$NF == sym {
      key = $1
      sub(/:$/, "", key)
      n = split(key, parts, ":")
      printf "%s ", parts[n]
    }'
}

# One line with its trailing padding removed. The table below is built by
# appending fixed-width columns, which leaves the last one padded; a report
# whose lines carry invisible trailing spaces is a nuisance to diff and to
# paste, so every assembled line goes through here first.
trim_right() {
  local text="${1}"

  printf '%s\n' "${text%"${text##*[![:space:]]}"}"
}

# True when the named symbol is in the newline-separated list.
list_has() {
  local needle="${1}"
  local list="${2}"

  printf '%s\n' "${list}" | grep -q -x -F "${needle}"
}

# How many Rust static libraries appear in a command. Exactly one may take
# part in any link: multiple Rust staticlib files are likely to conflict,
# each carrying its own copy of the runtime pieces it needs, so this is
# asserted at every link rather than assumed from how the command was built.
count_rust_archives() {
  local count=0
  local arg

  for arg in "$@"; do
    case "${arg}" in
      *libcurl_urlapi_rs*.a)
        count=$((count + 1))
        ;;
    esac
  done
  printf '%s\n' "${count}"
}

# Asserts the one-archive rule for a command about to be run.
assert_one_rust_archive() {
  local label="${1}"
  shift
  local found
  found="$(count_rust_archives "$@")"

  if [ "${found}" = "1" ]; then
    pass "${label}: exactly one Rust archive on the link line"
  else
    fail "${label}: ${found} Rust archives on the link line, and exactly one \
is allowed. Multiple Rust static libraries in one link are likely to conflict"
  fi
}

# The linker options that enclose the two archives of a Mode A link. Named
# once rather than written inline at each of the two link lines, so that the
# pair cannot drift apart between them -- and, incidentally, so that a linker
# option which legitimately contains a comma does not read as a comma-
# separated array element, which is what shellcheck's SC2054 heuristic looks
# for.
GROUP_START='-Wl,--start-group'
GROUP_END='-Wl,--end-group'

# Asserts that a link which succeeded really did resolve everything, and did
# not resolve anything twice. A linker fails an executable link on either
# count, so this reads the log for both diagnostics and turns the absence of
# them into a stated result -- acceptance criterion A4 is a claim about this
# link, and a claim needs evidence rather than an exit status alone.
assert_clean_link() {
  local label="${1}"
  local logfile="${2}"
  local undefined
  local duplicate

  undefined="$(grep -c -E 'undefined (reference|symbol)' "${logfile}" || true)"
  duplicate="$(grep -c -E 'multiple definition|duplicate symbol' \
    "${logfile}" || true)"

  if [ "${undefined}" = "0" ] && [ "${duplicate}" = "0" ]; then
    pass "${label}: no undefined and no duplicate symbols (A4)"
  else
    fail "${label}: ${undefined} undefined-symbol and ${duplicate} \
duplicate-symbol diagnostics in ${logfile}"
  fi
}

# ------------------------------------------------------------------------
# Mode A: the authoritative drop-in link
# ------------------------------------------------------------------------

MODE_A_STRIPPED="${MODE_A_DIR}/libcurl.a"
MODE_A_HARNESS="${MODE_A_DIR}/harness-a"
MODE_A_DEMO="${MODE_A_DIR}/demo-a"
MODE_A_INTACT="${MODE_A_DIR}/harness-intact"
MODE_A_CONTROL="${MODE_A_DIR}/harness-control"

if [ "${RUN_MODE_A}" = "1" ]; then
  section "Mode A: preparing the archive"

  # This is the mode that actually demonstrates "linkable in place of
  # lib/urlapi.c's object file", because the Rust code has to satisfy real
  # internal callers and coexist with the real free function, the
  # formatted-print family, the scheme table and the error-string function.
  #
  # Operating on a COPY, always. The reference archive stays as
  # scripts/build-reference.sh left it so that the baseline remains
  # reproducible and so that a second run of this script starts from the same
  # place as the first.
  if ! cp -f "${REFERENCE_ARCHIVE}" "${MODE_A_STRIPPED}"; then
    fatal "could not copy ${REFERENCE_ARCHIVE} to ${MODE_A_STRIPPED}"
  fi

  MEMBERS_BEFORE="$(ar t "${MODE_A_STRIPPED}" | grep -c . || true)"

  # The member name is DISCOVERED, never hardcoded. Under CMake the archive
  # is assembled from the libcurl_object OBJECT library and members are named
  # after their source file, giving urlapi.c.o; an autotools build gives
  # urlapi.o, and a libtool one libcurl_la-urlapi.o. The pattern below covers
  # all three shapes, and exactly one match is required: zero means this is
  # not an archive holding the module, and more than one means the name is
  # ambiguous and deleting either would be a guess.
  MEMBER_MATCHES="$(ar t "${MODE_A_STRIPPED}" |
    grep -E '(^|/)(lib[^/]*[-_])?urlapi(\.c)?\.(o|obj|lo)$' || true)"
  MEMBER_COUNT="$(printf '%s\n' "${MEMBER_MATCHES}" | grep -c . || true)"

  if [ "${MEMBER_COUNT}" = "0" ]; then
    fatal "no member of ${REFERENCE_ARCHIVE} looks like the object built \
from lib/urlapi.c. Its ${MEMBERS_BEFORE} members were searched for urlapi.o, \
urlapi.c.o and the libtool spelling. Either the archive is not libcurl or the \
reference build did not compile that module, and in both cases nothing here \
can be a drop-in test"
  fi
  if [ "${MEMBER_COUNT}" != "1" ]; then
    fatal "${MEMBER_COUNT} members of ${REFERENCE_ARCHIVE} look like the \
object built from lib/urlapi.c: $(printf '%s' "${MEMBER_MATCHES}" | tr '\n' \
' '). Deleting one of several would be a guess, so this stops here"
  fi

  URLAPI_MEMBER="${MEMBER_MATCHES}"
  if [ "${URLAPI_MEMBER}" != "${RECORDED_MEMBER}" ]; then
    warn "scripts/build-reference.sh recorded the urlapi member as \
'${RECORDED_MEMBER}' and this archive holds '${URLAPI_MEMBER}'. The name \
found in the archive is used, since it is the only one ar can delete, but the \
disagreement means the summary file and the archive are from different builds"
  fi

  say "  archive:        ${MODE_A_STRIPPED}"
  say "  members before: ${MEMBERS_BEFORE}"
  say "  deleting:       ${URLAPI_MEMBER}"

  if ! ar d "${MODE_A_STRIPPED}" "${URLAPI_MEMBER}" \
       >> "${LOG_FILE}" 2>&1; then
    fatal "ar could not delete ${URLAPI_MEMBER} from ${MODE_A_STRIPPED}"
  fi

  MEMBERS_AFTER="$(ar t "${MODE_A_STRIPPED}" | grep -c . || true)"
  say "  members after:  ${MEMBERS_AFTER}"

  if [ "${MEMBERS_AFTER}" = "$((MEMBERS_BEFORE - 1))" ]; then
    pass "exactly one member was removed from the archive copy"
  else
    fail "the archive copy went from ${MEMBERS_BEFORE} members to \
${MEMBERS_AFTER}, and exactly one fewer was expected"
  fi

  if ar t "${MODE_A_STRIPPED}" |
     grep -q -E '(^|/)(lib[^/]*[-_])?urlapi(\.c)?\.(o|obj|lo)$'; then
    fail "a urlapi-shaped member is still in ${MODE_A_STRIPPED} after the \
deletion, so the link below would not be testing the Rust implementation"
  else
    pass "no urlapi member remains in the archive copy"
  fi

  fact 'mode-a-archive-copy' "${MODE_A_STRIPPED}"
  fact 'mode-a-urlapi-member' "${URLAPI_MEMBER}"
  fact 'mode-a-members-before' "${MEMBERS_BEFORE}"
  fact 'mode-a-members-after' "${MEMBERS_AFTER}"

  section "Mode A: the control links, which are the evidence"

  # Two control links come before the real one, and they are what make a
  # successful Mode A link mean anything. Without them, a link that succeeds
  # is equally consistent with the archive still containing the C
  # implementation.
  #
  # Control one: the INTACT reference archive must link and the binary must
  # print success. That establishes that the harness, the staging, the
  # preprocessor state and the system library list are all correct, so that a
  # later failure cannot be blamed on them.
  INTACT_COMMAND=(
    "${CC_BIN}"
    "${HARNESS_CFLAGS_ARRAY[@]}"
    -o "${MODE_A_INTACT}"
    "${RUNNER_OBJECT}"
    "${MAIN_OBJECT}"
    "${REFERENCE_ARCHIVE}"
    "${REFERENCE_SYSTEM_LIBS_ARRAY[@]}"
  )
  logonly "intact control link: ${INTACT_COMMAND[*]}"
  if compile_step link-intact "${INTACT_COMMAND[@]}"; then
    pass "the control link against the intact reference archive succeeded"
    # Run in the fully-gated environment, taken from the matrix table rather
    # than spelled out here, so that this control and the matrix runs can
    # never drift apart.
    INTACT_OUT="${PARITY_DIR}/harness-intact.stdout"
    run_harness_once "${MODE_A_INTACT}" "${PRIMARY_ENV}" \
      "${PARITY_DIR}/harness-intact"
    INTACT_STATUS="${LAST_RUN_STATUS}"
    if [ "${INTACT_STATUS}" = "0" ] &&
       grep -q -x 'success' "${INTACT_OUT}"; then
      pass "that binary printed success and exited 0, so the harness and the \
C implementation agree before anything is replaced"
    else
      fail "the intact-archive control binary exited ${INTACT_STATUS} and its \
stdout is in ${INTACT_OUT}. The C baseline itself does not pass lib1560 here, \
so no parity result drawn from it would mean anything: $(describe_status \
"${INTACT_STATUS}")"
    fi
  else
    fail "the control link against the INTACT reference archive failed. That \
is not a finding about the port at all -- the C implementation is still in \
that archive -- but about the harness, the include path or the system library \
list. The command and its output are in ${PARITY_DIR}/link-intact.log"
  fi

  # Control two: the STRIPPED archive alone must FAIL, with the drop-in
  # symbols undefined. This is the measurement that gives the real Mode A
  # link its force.
  CONTROL_COMMAND=(
    "${CC_BIN}"
    "${HARNESS_CFLAGS_ARRAY[@]}"
    -o "${MODE_A_CONTROL}"
    "${RUNNER_OBJECT}"
    "${MAIN_OBJECT}"
    "${MODE_A_STRIPPED}"
    "${REFERENCE_SYSTEM_LIBS_ARRAY[@]}"
  )
  logonly "failing control link: ${CONTROL_COMMAND[*]}"
  CONTROL_LOG="${PARITY_DIR}/link-control.log"
  # Quiet: this link is MEANT to fail, and its output is hundreds of lines of
  # undefined-symbol diagnostics which are read below rather than displayed.
  if compile_step_quiet link-control "${CONTROL_COMMAND[@]}"; then
    fail "the control link against the stripped archive SUCCEEDED, and it had \
to fail. Something else in that archive is still defining the URL API, so a \
successful Mode A link below would prove nothing about the Rust code"
    UNDEFINED_FOUND=''
  else
    UNDEFINED_FOUND="$(extract_undefined "${CONTROL_LOG}")"
    pass "the control link against the stripped archive failed, as it must"
  fi

  UNDEFINED_COUNT="$(printf '%s\n' "${UNDEFINED_FOUND}" | grep -c . || true)"
  say "  undefined symbols reported: ${UNDEFINED_COUNT}"

  # Every mandatory symbol has to be among them.
  MISSING_MANDATORY=()
  for symbol in "${MANDATORY_UNDEFINED[@]}"; do
    if ! list_has "${symbol}" "${UNDEFINED_FOUND}"; then
      MISSING_MANDATORY+=("${symbol}")
    fi
  done
  if [ "${#MISSING_MANDATORY[@]}" = "0" ]; then
    pass "all six always-reachable drop-in symbols came up undefined: \
${MANDATORY_UNDEFINED[*]}"
  else
    fail "these drop-in symbols did NOT come up undefined although the \
member defining them was deleted: ${MISSING_MANDATORY[*]}. Something else in \
the archive defines them, so the control link is not the evidence it should be"
  fi

  # And nothing outside the eight may be among them: an extra undefined
  # symbol means the deletion took more than the module with it, or that the
  # harness needs something the reference build does not provide.
  UNEXPECTED_UNDEFINED=()
  if [ -n "${UNDEFINED_FOUND}" ]; then
    while read -r symbol; do
      if [ -z "${symbol}" ]; then
        continue
      fi
      known=0
      for candidate in "${DROPIN_SYMBOLS[@]}"; do
        if [ "${symbol}" = "${candidate}" ]; then
          known=1
        fi
      done
      if [ "${known}" = "0" ]; then
        UNEXPECTED_UNDEFINED+=("${symbol}")
      fi
    done <<< "${UNDEFINED_FOUND}"
  fi
  if [ "${#UNEXPECTED_UNDEFINED[@]}" = "0" ]; then
    pass "no symbol outside the drop-in set came up undefined"
  else
    fail "these undefined symbols are not part of the drop-in set: \
${UNEXPECTED_UNDEFINED[*]}. Deleting the urlapi member should leave exactly \
the symbols that member defined unresolved, and nothing else"
  fi

  # The two configuration-dependent ones are reported with the reason, so
  # that a reader does not have to wonder why the count is not always eight.
  for symbol in "${OPTIONAL_UNDEFINED[@]}"; do
    referrers="$(trim_right \
      "$(archive_referrers "${symbol}" "${MODE_A_STRIPPED}")")"
    if list_has "${symbol}" "${UNDEFINED_FOUND}"; then
      say "  ${symbol}: undefined, referenced by ${referrers:-nothing}"
    else
      say "  ${symbol}: did not surface; no member this link pulls in \
references it (referenced in the archive by: ${referrers:-nothing})"
    fi
  done
  say "  their only consumers in the tree are lib/doh.c:L1127 for \
Curl_junkscan and lib/http2.c:L739 for Curl_url_set_authority, so each \
surfaces only when the object holding that call site is pulled in"

  fact 'control-undefined-count' "${UNDEFINED_COUNT}"
  fact 'control-undefined' \
    "$(printf '%s' "${UNDEFINED_FOUND}" | tr '\n' ' ')"

  section "Mode A: the real link"

  # Archive ordering and why a group is used. The Rust artifact is an archive,
  # so it must precede libcurl on the link line -- and here the dependency is
  # mutual: the libcurl members want curl_url*, while the crate in this
  # configuration wants Curl_get_scheme from url.c.o, since the scheme-table
  # feature is off for the drop-in. A single left-to-right pass can satisfy
  # one direction but not both, so the two archives are enclosed in a group
  # and the Rust archive is placed first inside it, which honors the ordering
  # rule and resolves the cycle at once.
  #
  # The system libraries are named explicitly and come from what
  # scripts/build-reference.sh recorded: a Rust staticlib's own dynamic
  # dependencies have to be specified manually when it is linked from
  # elsewhere, and taking the list from the reference build rather than
  # hardcoding one keeps this script working on a machine configured
  # differently.
  #
  # harness/shims.c is deliberately absent and so is -DHARNESS_MODE_B: this
  # link resolves the curl_m*printf family from libcurl's own mprintf.c.o and
  # curl_free from escape.c.o.
  MODE_A_COMMAND=(
    "${CC_BIN}"
    "${HARNESS_CFLAGS_ARRAY[@]}"
    -o "${MODE_A_HARNESS}"
    "${RUNNER_OBJECT}"
    "${MAIN_OBJECT}"
    "${GROUP_START}"
    "${MODE_A_ARCHIVE}"
    "${MODE_A_STRIPPED}"
    "${GROUP_END}"
    "${REFERENCE_SYSTEM_LIBS_ARRAY[@]}"
  )
  assert_one_rust_archive "Mode A harness" "${MODE_A_COMMAND[@]}"
  logonly "Mode A harness link: ${MODE_A_COMMAND[*]}"
  say "  link line kept in ${LOG_FILE}"
  if compile_step link-mode-a "${MODE_A_COMMAND[@]}"; then
    pass "the Mode A harness linked: the Rust archive satisfied every symbol \
the deleted member used to define"
    assert_clean_link "Mode A harness" "${PARITY_DIR}/link-mode-a.log"
  else
    fail "the Mode A harness did not link. The full command is in \
${LOG_FILE} and the diagnostics in ${PARITY_DIR}/link-mode-a.log; an \
unresolved symbol there is the port's export set, and a duplicate one is a \
feature that should have been off for this mode"
    RUN_MODE_A=0
  fi

  if [ "${RUN_MODE_A}" = "1" ] && [ "${WANT_DEMO}" = "1" ]; then
    # The demo in drop-in form: the real public headers, and
    # URLAPI_DEMO_STANDALONE deliberately NOT defined. That macro selects the
    # mirror header for the standalone link; here libcurl takes part, and it
    # is also what supplies curl_url_strerror, which lives in lib/strerror.c
    # rather than in the module being replaced.
    MODE_A_DEMO_COMMAND=(
      "${CC_BIN}"
      "${HARNESS_CFLAGS_ARRAY[@]}"
      "-I${REPO_ROOT}/include"
      -o "${MODE_A_DEMO}"
      "${DEMO_SOURCE}"
      "${GROUP_START}"
      "${MODE_A_ARCHIVE}"
      "${MODE_A_STRIPPED}"
      "${GROUP_END}"
      "${REFERENCE_SYSTEM_LIBS_ARRAY[@]}"
    )
    assert_one_rust_archive "Mode A demo" "${MODE_A_DEMO_COMMAND[@]}"
    logonly "Mode A demo link: ${MODE_A_DEMO_COMMAND[*]}"
    if compile_step link-demo-a "${MODE_A_DEMO_COMMAND[@]}"; then
      pass "the Mode A demo linked"
      assert_clean_link "Mode A demo" "${PARITY_DIR}/link-demo-a.log"
    else
      fail "the Mode A demo did not link; see \
${PARITY_DIR}/link-demo-a.log"
      MODE_A_DEMO=''
    fi
  else
    MODE_A_DEMO=''
  fi
fi

# ------------------------------------------------------------------------
# Mode B: the standalone link
# ------------------------------------------------------------------------

MODE_B_HARNESS="${MODE_B_DIR}/harness-b"
MODE_B_DEMO="${MODE_B_DIR}/demo-b"

if [ "${RUN_MODE_B}" = "1" ]; then
  section "Mode B: the standalone link"

  # Mode B proves the crate is independently linkable and gives the demo a
  # path that needs no libcurl at all. A Mode B failure is a real failure and
  # is never downgraded to a skip.
  #
  # The system libraries a Rust staticlib needs have to be named explicitly
  # here too. The internationalized-domain library is asked of pkg-config
  # when it can answer, since that is what the crate's own build script does,
  # and named directly otherwise; the thread, dynamic-loader and math
  # libraries are what the Rust standard library itself pulls in on this
  # platform. When the crate was built with the pure-Rust backend there is no
  # C library to name at all.
  if [ -n "${MODE_B_SYSTEM_LIBS:-}" ]; then
    MODE_B_LIBS="${MODE_B_SYSTEM_LIBS}"
  else
    MODE_B_LIBS=''
    if [ "${IDN_BACKEND}" != "idna" ]; then
      if have pkg-config && pkg-config --exists libidn2 2>/dev/null; then
        MODE_B_LIBS="$(pkg-config --libs libidn2)"
      else
        MODE_B_LIBS='-lidn2'
      fi
    fi
    MODE_B_LIBS="${MODE_B_LIBS} -lpthread -ldl -lm"
  fi
  read -r -a MODE_B_LIBS_ARRAY <<< "${MODE_B_LIBS}"
  # Rejoined from the split form, so that whatever pkg-config padded the list
  # with does not reach the report or the summary file.
  MODE_B_LIBS="${MODE_B_LIBS_ARRAY[*]}"
  say "  system libraries: ${MODE_B_LIBS}"
  fact 'mode-b-system-libs' "${MODE_B_LIBS}"

  # harness/shims.c supplies the curl_m*printf family that
  # tests/libtest/lib1560.c and harness/main.c call, and nothing else: it does
  # NOT define curl_free here, because Mode B builds the crate with default
  # features and its cfree feature already exports curl_free from
  # src/ffi.rs. HARNESS_SHIM_CURL_FREE is therefore left undefined, in this
  # mode and in every other.
  MODE_B_COMMAND=(
    "${CC_BIN}"
    "${HARNESS_CFLAGS_ARRAY[@]}"
    -o "${MODE_B_HARNESS}"
    "${RUNNER_OBJECT}"
    "${MAIN_OBJECT}"
    "${SHIMS_OBJECT}"
    "${MODE_B_ARCHIVE}"
    "${MODE_B_LIBS_ARRAY[@]}"
  )
  assert_one_rust_archive "Mode B harness" "${MODE_B_COMMAND[@]}"
  logonly "Mode B harness link: ${MODE_B_COMMAND[*]}"
  if compile_step link-mode-b "${MODE_B_COMMAND[@]}"; then
    pass "the Mode B harness linked against the crate with no libcurl at all"
    assert_clean_link "Mode B harness" "${PARITY_DIR}/link-mode-b.log"
  else
    fail "the Mode B harness did not link; see \
${PARITY_DIR}/link-mode-b.log. A duplicate curl_free there means \
HARNESS_SHIM_CURL_FREE reached the shims compilation, which this script never \
defines"
    RUN_MODE_B=0
  fi

  if [ "${RUN_MODE_B}" = "1" ] && [ "${WANT_DEMO}" = "1" ]; then
    # The demo in standalone form. -DURLAPI_DEMO_STANDALONE selects the mirror
    # header include/curl_urlapi_rs.h, which is why the crate's own include
    # directory is on the path; in that mode the demo declares curl_free
    # itself, because the mirror header deliberately omits it -- curl_free is
    # declared in include/curl/curl.h, not in urlapi.h, and the mirror covers
    # only the latter.
    MODE_B_DEMO_COMMAND=(
      "${CC_BIN}"
      "${HARNESS_CFLAGS_ARRAY[@]}"
      -DURLAPI_DEMO_STANDALONE
      "-I${MIRROR_INCLUDE_DIR}"
      -o "${MODE_B_DEMO}"
      "${DEMO_SOURCE}"
      "${MODE_B_ARCHIVE}"
      "${MODE_B_LIBS_ARRAY[@]}"
    )
    assert_one_rust_archive "Mode B demo" "${MODE_B_DEMO_COMMAND[@]}"
    logonly "Mode B demo link: ${MODE_B_DEMO_COMMAND[*]}"
    if compile_step link-demo-b "${MODE_B_DEMO_COMMAND[@]}"; then
      pass "the Mode B demo linked"
      assert_clean_link "Mode B demo" "${PARITY_DIR}/link-demo-b.log"
    else
      fail "the Mode B demo did not link; see \
${PARITY_DIR}/link-demo-b.log"
      MODE_B_DEMO=''
    fi
  else
    MODE_B_DEMO=''
  fi
fi

if [ "${RUN_MODE_A}" = "0" ] && [ "${RUN_MODE_B}" = "0" ]; then
  fatal "neither link mode produced a harness, so there is nothing to run. \
The link diagnostics are under ${PARITY_DIR}"
fi

# ------------------------------------------------------------------------
# The run matrix
# ------------------------------------------------------------------------

# The participants, in report order. The reference comes first because
# everything else is compared against it, within its own environment.
PARTICIPANT_LABELS=()
PARTICIPANT_BINARIES=()

if [ -n "${REFERENCE_HARNESS}" ] && [ -x "${REFERENCE_HARNESS}" ]; then
  PARTICIPANT_LABELS+=(reference)
  PARTICIPANT_BINARIES+=("${REFERENCE_HARNESS}")
  REFERENCE_SOURCE='rerun'
else
  # The golden captures still hold what the reference did, so the comparison
  # is still possible; it is simply weaker, because it cannot notice that the
  # reference binary has changed since they were taken.
  REFERENCE_SOURCE='golden'
  warn "the reference harness binary is not available at \
'${REFERENCE_HARNESS}', so the golden captures from \
scripts/build-reference.sh are used as the oracle instead of a fresh run. \
Re-run scripts/build-reference.sh to restore the stronger comparison"
fi
if [ "${RUN_MODE_A}" = "1" ]; then
  PARTICIPANT_LABELS+=(mode-a)
  PARTICIPANT_BINARIES+=("${MODE_A_HARNESS}")
fi
if [ "${RUN_MODE_B}" = "1" ]; then
  PARTICIPANT_LABELS+=(mode-b)
  PARTICIPANT_BINARIES+=("${MODE_B_HARNESS}")
fi
fact 'reference-oracle' "${REFERENCE_SOURCE}"

# Results, indexed by "<participant>/<environment>" through a name-to-value
# lookup, because bash has no nested arrays and parallel index arithmetic
# across two dimensions is exactly the kind of thing that goes quietly wrong.
declare -A RUN_STATUS=()
declare -A RUN_STDOUT=()
declare -A RUN_ATTEMPTS=()
declare -A RUN_STATUSES_SEEN=()

# The verdict for one sub-test, given the exit status of a whole run and the
# execution position of that sub-test. Everything before the failing position
# ran and passed, the failing position is the one the status names, and
# everything after it never ran, because tests/libtest/lib1560.c:L2040-L2071
# returns at the first failure.
subtest_verdict() {
  local status="${1}"
  local position="${2}"
  local failing

  if [ "${status}" = "0" ]; then
    printf 'pass\n'
    return 0
  fi

  failing="$(subtest_position "${status}")"
  if [ -z "${failing}" ]; then
    # An infrastructure failure says nothing about any individual sub-test.
    printf 'unknown\n'
    return 0
  fi

  if [ "${position}" -lt "${failing}" ]; then
    printf 'pass\n'
  elif [ "${position}" = "${failing}" ]; then
    printf 'fail\n'
  else
    printf 'blocked\n'
  fi
}

section "Running the matrix"

say "  ${#SELECTED_ENVS[@]} environment(s) x \
${#PARTICIPANT_LABELS[@]} binaries, up to ${ATTEMPTS} attempt(s) each"

participant_index=0
while [ "${participant_index}" -lt "${#PARTICIPANT_LABELS[@]}" ]; do
  participant="${PARTICIPANT_LABELS[${participant_index}]}"
  binary="${PARTICIPANT_BINARIES[${participant_index}]}"
  participant_index=$((participant_index + 1))

  for env_label in "${SELECTED_ENVS[@]}"; do
    run_key="${participant}/${env_label}"
    attempt=1
    attempts_made=0
    statuses_seen=''
    previous_status=''
    run_status=0
    run_stem=''

    # Bounded iteration. The entry point short-circuits, so one run can only
    # ever name one failing sub-test; re-running is what distinguishes a
    # deterministic failure -- the same status again, which is the ordinary
    # case and means the later sub-tests simply cannot be reached in this
    # configuration -- from a status that moves, which would be a finding in
    # its own right for a URL parser and is worth another attempt to observe.
    # The loop stops on a clean run, on a repeat, or at the attempt limit, so
    # it cannot spin.
    while [ "${attempt}" -le "${ATTEMPTS}" ]; do
      run_stem="${RUN_DIR}/${participant}-${env_label}-attempt${attempt}"
      run_harness_once "${binary}" "${env_label}" "${run_stem}"
      run_status="${LAST_RUN_STATUS}"
      attempts_made="${attempt}"
      statuses_seen="${statuses_seen}${run_status} "

      say "  ${participant} ${env_label} attempt ${attempt}: exit \
${run_status}, $(describe_status "${run_status}"), stdout \
$(wc -c < "${run_stem}.stdout" | tr -d ' ') bytes"

      if [ "${run_status}" = "0" ]; then
        break
      fi
      if [ -n "${previous_status}" ] &&
         [ "${run_status}" = "${previous_status}" ]; then
        say "    the same status came back, so the run is not making \
progress and the iteration stops here. The sub-tests after the failing one \
cannot be reached in this configuration without changing the test, which is \
out of scope"
        break
      fi
      if [ -n "${previous_status}" ]; then
        warn "${participant} in ${env_label} exited ${previous_status} and \
then ${run_status}. A URL parser that answers differently on two identical \
runs is a finding in itself, and both statuses are kept in ${RUN_DIR}"
      fi
      previous_status="${run_status}"
      attempt=$((attempt + 1))
    done

    RUN_STATUS["${run_key}"]="${run_status}"
    RUN_STDOUT["${run_key}"]="${run_stem}.stdout"
    RUN_ATTEMPTS["${run_key}"]="${attempts_made}"
    RUN_STATUSES_SEEN["${run_key}"]="${statuses_seen% }"
  done
done

# When no reference binary was available, the golden captures stand in for it,
# so that the comparison below is written one way only.
if [ "${REFERENCE_SOURCE}" = "golden" ]; then
  for env_label in "${SELECTED_ENVS[@]}"; do
    run_key="reference/${env_label}"
    golden_status_file="${GOLDEN_DIR}/harness-${env_label}.status"
    golden_stdout="${GOLDEN_DIR}/harness-${env_label}.stdout"
    if [ ! -f "${golden_status_file}" ] || [ ! -f "${golden_stdout}" ]; then
      fatal "neither a reference binary nor a golden capture exists for the \
${env_label} environment. Run scripts/build-reference.sh"
    fi
    RUN_STATUS["${run_key}"]="$(tr -d ' \n' < "${golden_status_file}")"
    RUN_STDOUT["${run_key}"]="${golden_stdout}"
    RUN_ATTEMPTS["${run_key}"]='0'
    RUN_STATUSES_SEEN["${run_key}"]="${RUN_STATUS["${run_key}"]}"
  done
fi

section "The reference against its own golden capture"

# A drift check, and it comes before the parity comparison for a reason: if
# the reference binary no longer does what it did when the goldens were
# taken, then the goldens are stale and any parity verdict drawn against
# either of them is describing two different baselines. Skipped, with a note,
# when the goldens are themselves standing in for the binary.
if [ "${REFERENCE_SOURCE}" = "golden" ]; then
  say "  skipped: the golden captures ARE the oracle for this run"
else
  for env_label in "${SELECTED_ENVS[@]}"; do
    run_key="reference/${env_label}"
    golden_status_file="${GOLDEN_DIR}/harness-${env_label}.status"
    golden_stdout="${GOLDEN_DIR}/harness-${env_label}.stdout"
    fresh_status="${RUN_STATUS["${run_key}"]}"
    fresh_stdout="${RUN_STDOUT["${run_key}"]}"

    if [ ! -f "${golden_status_file}" ] || [ ! -f "${golden_stdout}" ]; then
      fail "no golden capture for the ${env_label} environment in \
${GOLDEN_DIR}. scripts/build-reference.sh writes one per environment"
      continue
    fi

    golden_status="$(tr -d ' \n' < "${golden_status_file}")"
    if [ "${fresh_status}" = "${golden_status}" ] &&
       cmp -s "${fresh_stdout}" "${golden_stdout}"; then
      pass "reference, ${env_label}: matches its golden capture (exit \
${golden_status})"
    else
      fail "reference, ${env_label}: the binary now exits ${fresh_status} \
where its golden capture recorded ${golden_status}, or its stdout has \
changed. The baseline itself has moved, so re-run \
scripts/build-reference.sh before reading anything below as a parity result"
      diff -u "${golden_stdout}" "${fresh_stdout}" >> "${LOG_FILE}" 2>&1 ||
        true
    fi
  done
fi

section "Parity: each mode against the reference, within each environment"

# The comparison is always within one environment and never across two.
# libidn2's lookup is locale-aware, so under LC_ALL=C every non-ASCII host
# conversion fails and that propagates to CURLUE_BAD_HOSTNAME; the reference
# itself then exits 3, naming get_url. That is part of the oracle, not a
# defect: a Rust build whose backend were locale-independent would succeed
# there and would be WRONG to. So a non-zero status that matches the
# reference's is parity, and the report says so in as many words rather than
# printing a bare "fail" that a reader would misread.
for env_label in "${SELECTED_ENVS[@]}"; do
  reference_key="reference/${env_label}"
  reference_status="${RUN_STATUS["${reference_key}"]}"
  reference_stdout="${RUN_STDOUT["${reference_key}"]}"

  for participant in "${PARTICIPANT_LABELS[@]}"; do
    if [ "${participant}" = "reference" ]; then
      continue
    fi
    run_key="${participant}/${env_label}"
    mode_status="${RUN_STATUS["${run_key}"]}"
    mode_stdout="${RUN_STDOUT["${run_key}"]}"

    if [ "${mode_status}" = "${reference_status}" ]; then
      if [ "${mode_status}" = "0" ]; then
        pass "${participant}, ${env_label}: exit status matches the \
reference (0, all eleven sub-tests passed)"
      else
        pass "${participant}, ${env_label}: exit status matches the \
reference (${mode_status}, $(describe_status "${mode_status}") in both, which \
is the divergence the reference itself has here and therefore parity)"
      fi
    else
      fail "${participant}, ${env_label}: exit ${mode_status} \
($(describe_status "${mode_status}")) where the reference exits \
${reference_status} ($(describe_status "${reference_status}")). The stderr of \
the run names the failing assertion: ${mode_stdout%.stdout}.stderr"
    fi

    # Acceptance criteria A5 and A7 rest on a byte-for-byte comparison of
    # stdout, and stdout only.
    if cmp -s "${mode_stdout}" "${reference_stdout}"; then
      pass "${participant}, ${env_label}: stdout is byte-identical to the \
reference"
    else
      fail "${participant}, ${env_label}: stdout differs from the reference. \
The difference follows and is also in ${LOG_FILE}"
      diff -u "${reference_stdout}" "${mode_stdout}" 2>&1 | head -n 40 ||
        true
      diff -u "${reference_stdout}" "${mode_stdout}" >> "${LOG_FILE}" 2>&1 ||
        true
    fi
  done
done

# Acceptance criterion A5, stated on its own because it is the criterion the
# test definition itself asserts: in the fully-gated environment the stdout of
# a passing run is the single line "success", printed at
# tests/libtest/lib1560.c:L2073 and expected by tests/data/test1560:L37.
if printf '%s\n' "${SELECTED_ENVS[@]}" | grep -q -x -F "${PRIMARY_ENV}"; then
  for participant in "${PARTICIPANT_LABELS[@]}"; do
    run_key="${participant}/${PRIMARY_ENV}"
    primary_stdout="${RUN_STDOUT["${run_key}"]}"
    if [ "${RUN_STATUS["${run_key}"]}" = "0" ] &&
       [ "$(cat "${primary_stdout}")" = "success" ]; then
      pass "${participant}: prints exactly the line tests/data/test1560 \
expects in the ${PRIMARY_ENV} environment (A5)"
    else
      fail "${participant}: did not print the single line success in the \
${PRIMARY_ENV} environment; its capture is ${primary_stdout} (A5)"
    fi
  done
else
  warn "the ${PRIMARY_ENV} environment was excluded from this run, so \
acceptance criterion A5 -- the single line success, which \
tests/data/test1560:L37 asserts -- is not measured here"
fi

# Acceptance criterion A9 is stated over the pair of locale configurations
# rather than over one environment: behavior has to match under LC_ALL=C.UTF-8
# AND under LC_ALL=C, the second of which is where the reference's own
# locale-dependent failure mode lives. Both have to have run for the criterion
# to be measured at all, so that is checked rather than assumed.
LOCALES_COVERED=''
for env_label in "${SELECTED_ENVS[@]}"; do
  LOCALES_COVERED="${LOCALES_COVERED}$(env_locale "${env_label}") "
done

case "${LOCALES_COVERED}" in
  *C.UTF-8*)
    case "${LOCALES_COVERED}" in
      *' C '*)
        for participant in "${PARTICIPANT_LABELS[@]}"; do
          if [ "${participant}" = "reference" ]; then
            continue
          fi
          mismatches=0
          for env_label in "${SELECTED_ENVS[@]}"; do
            reference_key="reference/${env_label}"
            run_key="${participant}/${env_label}"
            if [ "${RUN_STATUS["${run_key}"]}" != \
                 "${RUN_STATUS["${reference_key}"]}" ] ||
               ! cmp -s "${RUN_STDOUT["${run_key}"]}" \
                 "${RUN_STDOUT["${reference_key}"]}"; then
              mismatches=$((mismatches + 1))
            fi
          done
          if [ "${mismatches}" = "0" ]; then
            pass "${participant}: matches the reference under LC_ALL=C.UTF-8 \
and under LC_ALL=C, the reference's own non-UTF-8 failure mode included (A9)"
          else
            fail "${participant}: diverges from the reference in \
${mismatches} of the ${#SELECTED_ENVS[@]} environments run, so behavior does \
not match across both locale configurations (A9)"
          fi
        done
        ;;
      *)
        warn "only the C.UTF-8 locale was exercised, so acceptance criterion \
A9 -- matching behavior under both locale configurations, including the \
reference's non-UTF-8 failure mode -- is not measured here"
        ;;
    esac
    ;;
  *)
    warn "the C.UTF-8 locale was not exercised, so acceptance criterion A9 \
is not measured here"
    ;;
esac

section "That the internationalized-domain assertions really ran"

# Acceptance criterion A8, second half. The first half proved the rows are
# compiled in; this half proves they were exercised in both halves of the
# codeset matrix. The failure mode being ruled out is a silent one: with the
# variable unset the punycode rows at tests/libtest/lib1560.c:L1446, L1548 and
# L1591 do not run, and the harness prints success anyway.
IDN_MATRIX_COMPLETE=1
for needed in utf8-codeset utf8-nocodeset; do
  if ! printf '%s\n' "${SELECTED_ENVS[@]}" | grep -q -x -F "${needed}"; then
    IDN_MATRIX_COMPLETE=0
  fi
done

if [ "${IDN_ROWS}" != "live" ]; then
  warn "the internationalized-domain rows were not compiled, so A8 is not \
measured by this run"
elif [ "${IDN_MATRIX_COMPLETE}" = "0" ]; then
  warn "the codeset matrix was narrowed by --env, so A8 -- the gated \
sub-tests passing with CURL_TEST_HAVE_CODESET_UTF8 both set and unset -- is \
not measured by this run"
else
  for participant in "${PARTICIPANT_LABELS[@]}"; do
    set_status="${RUN_STATUS["${participant}/utf8-codeset"]}"
    unset_status="${RUN_STATUS["${participant}/utf8-nocodeset"]}"
    if [ "${set_status}" = "0" ] && [ "${unset_status}" = "0" ]; then
      pass "${participant}: setget_parts, get_url and get_parts passed with \
CURL_TEST_HAVE_CODESET_UTF8 set and again with it unset (A8)"
    else
      fail "${participant}: exit ${set_status} with the codeset variable set \
and ${unset_status} with it unset, so the punycode rows those three sub-tests \
gate are not both demonstrated (A8)"
    fi
  done
fi

section "The demo transcripts against the committed golden"

# Acceptance criterion A7: a zero-byte difference between the demo linked
# against the crate and demo/expected-output.txt, the bytes
# scripts/build-reference.sh captured from the same program linked against the
# unmodified C implementation.
#
# That file is read here and never written. Regenerating it belongs to
# build-reference.sh, behind its explicit --force, because a golden file that
# re-records itself when it disagrees cannot detect anything at all. If it
# looks wrong, the answer is to report it, which is what a failing check here
# does.
DEMO_GOLDEN_HAS_IDN=0
if grep -q -F "${IDN_MARKER}" "${DEMO_GOLDEN}"; then
  DEMO_GOLDEN_HAS_IDN=1
fi

# Runs one demo binary and compares its stdout with the golden bytes.
#   $1  label for the report
#   $2  the binary
compare_demo() {
  local label="${1}"
  local binary="${2}"
  local stem="${RUN_DIR}/demo-${label}"
  local status=0

  "${binary}" > "${stem}.stdout" 2> "${stem}.stderr" || status="$?"

  if [ "${status}" != "0" ]; then
    fail "the ${label} demo exited ${status}. It accumulates its own status \
rather than short-circuiting, and reports non-zero only when an allocation \
failed somewhere, so a non-zero status here is a real defect"
  fi

  if [ -s "${stem}.stderr" ]; then
    warn "the ${label} demo wrote to stderr, which it does only for an \
allocation failure. Its transcript no longer describes what the URL API does. \
The text is in ${stem}.stderr"
  fi

  if cmp -s "${stem}.stdout" "${DEMO_GOLDEN}"; then
    pass "the ${label} demo transcript is byte-identical to \
demo/expected-output.txt (A7)"
  else
    fail "the ${label} demo transcript differs from \
demo/expected-output.txt (A7). The difference follows and is also in \
${LOG_FILE}"
    diff -u "${DEMO_GOLDEN}" "${stem}.stdout" 2>&1 | head -n 40 || true
    diff -u "${DEMO_GOLDEN}" "${stem}.stdout" >> "${LOG_FILE}" 2>&1 || true
  fi

  # The demo converts the test's own example hostname to its compatibility
  # form, so a matching transcript is direct evidence that the conversion ran
  # and produced the expected bytes -- the other half of the A8 argument,
  # reached from the demo rather than from the harness.
  if [ "${DEMO_GOLDEN_HAS_IDN}" = "1" ]; then
    if grep -q -F "${IDN_MARKER}" "${stem}.stdout"; then
      pass "the ${label} demo transcript carries ${IDN_MARKER}, so the \
compatibility-form conversion of the test's own example was exercised (A8)"
    else
      fail "the ${label} demo transcript does not contain ${IDN_MARKER} \
although the golden does, so the compatibility-form conversion did not \
happen (A8)"
    fi
  fi
}

if [ "${WANT_DEMO}" = "0" ]; then
  warn "--no-demo was given, so acceptance criterion A7 -- a zero-byte \
difference against demo/expected-output.txt -- is not measured by this run"
else
  if [ "${DEMO_GOLDEN_HAS_IDN}" = "0" ]; then
    warn "demo/expected-output.txt does not contain ${IDN_MARKER}, so it was \
captured from a reference build without internationalized-domain support. The \
transcripts are still compared byte for byte, but they carry no evidence \
about the conversion"
  fi
  if [ -n "${REFERENCE_DEMO}" ] && [ -x "${REFERENCE_DEMO}" ]; then
    # A drift check on the golden itself, for the same reason the harness has
    # one: if the reference demo no longer produces the committed bytes, the
    # committed bytes are stale and comparing anything against them is
    # meaningless.
    compare_demo reference "${REFERENCE_DEMO}"
  else
    warn "the reference demo binary is not available at '${REFERENCE_DEMO}', \
so demo/expected-output.txt is compared against the Rust builds without being \
re-confirmed against the C one"
  fi
  if [ -n "${MODE_A_DEMO}" ]; then
    compare_demo mode-a "${MODE_A_DEMO}"
  fi
  if [ -n "${MODE_B_DEMO}" ]; then
    compare_demo mode-b "${MODE_B_DEMO}"
  fi
fi

section "Allocation count"

# Reported limitation R3 in practice. The ceiling of "Allocations: 3000" at
# tests/data/test1560:L39-L40 is measured by curl's own memory-debug
# accounting, and this harness is deliberately built without it: curl_free
# resolves at compile time and under memory debugging becomes a tracking free
# that validates pointers against its own table, which would reject the
# C-allocator buffers the crate hands back. So that ceiling is honored in
# spirit here and not measured by the mechanism that wrote it.
#
# valgrind is the available substitute, and it is opt-in because it multiplies
# the runtime of every run. The number is REPORTED and never asserted on:
# asserting on a figure from a different accounting than the one the ceiling
# was written for would be a false precision.
if [ "${WANT_VALGRIND}" = "0" ]; then
  say "  not measured. curl's own counter belongs to the memory-debug build, \
which this harness deliberately is not; pass --valgrind for an independent \
count"
else
  count_allocations() {
    local label="${1}"
    local binary="${2}"
    local logfile="${RUN_DIR}/valgrind-${label}.log"
    local allocs

    env "LC_ALL=C.UTF-8" 'CURL_TEST_HAVE_CODESET_UTF8=1' \
      valgrind --tool=memcheck --error-exitcode=0 \
      --log-file="${logfile}" "${binary}" > /dev/null 2>&1 || true

    allocs="$(sed -n -E 's/.*total heap usage: ([0-9,]+) allocs.*/\1/p' \
      "${logfile}" | head -n 1)"
    if [ -n "${allocs}" ]; then
      say "  ${label}: ${allocs} allocations"
      fact "allocations-${label}" "${allocs}"
    else
      warn "valgrind produced no allocation total for ${label}; its log is \
${logfile}"
    fi
  }

  if [ "${REFERENCE_SOURCE}" = "rerun" ]; then
    count_allocations reference "${REFERENCE_HARNESS}"
  fi
  if [ "${RUN_MODE_A}" = "1" ]; then
    count_allocations mode-a "${MODE_A_HARNESS}"
  fi
  if [ "${RUN_MODE_B}" = "1" ]; then
    count_allocations mode-b "${MODE_B_HARNESS}"
  fi
  say "  reported, not asserted on: this is not the accounting \
tests/data/test1560 asks for. docs/MEMORY-OWNERSHIP.md records both sets of \
numbers and why they differ"
fi

section "Per-sub-test report"

# Reporting per sub-test rather than in aggregate is an explicit requirement,
# and acceptance criterion A6 is that all eleven are accounted for
# individually. The entry point short-circuits, so one run names at most one
# failure; a table of eleven rows with "blocked" against everything the
# failure prevented is the honest way to say that, and it is far more useful
# than the first exit code on its own.
#
# The rows are in EXECUTION order -- tests/libtest/lib1560.c:L2040-L2071, not
# the numeric order of the codes -- because that is the order in which one
# failure blocks the rest.
say ""
say "  Acceptance criterion A6: each of the eleven sub-tests gets its own"
say "  verdict below, in the order tests/libtest/lib1560.c runs them, rather"
say "  than the run being summarized by the first exit code it produced."
say ""
say "  Legend: pass    the sub-test ran and reported no error"
say "          fail    the sub-test ran and reported an error"
say "          blocked did not run: an earlier sub-test failed first"
say "          unknown the run did not reach the test at all"
say ""
say "  A fail in the same row for the reference and for a mode is PARITY:"
say "  the reference has real failure modes of its own, notably under"
say "  LC_ALL=C where libidn2's locale-aware lookup fails every non-ASCII"
say "  host and get_url reports CURLUE_BAD_HOSTNAME. Reproducing that is"
say "  correct behavior for the port, and not reproducing it would not be."

for env_label in "${SELECTED_ENVS[@]}"; do
  locale_shown="$(env_locale "${env_label}")"
  codeset_shown="$(env_codeset "${env_label}")"
  say ""
  say "  Environment ${env_label}: LC_ALL=${locale_shown}, \
CURL_TEST_HAVE_CODESET_UTF8=${codeset_shown:-<unset>}"

  status_line='    exit status:'
  for participant in "${PARTICIPANT_LABELS[@]}"; do
    run_key="${participant}/${env_label}"
    status_line="${status_line} ${participant} \
${RUN_STATUS["${run_key}"]},"
  done
  say "${status_line%,}"

  header="$(printf '    %2s  %-13s %4s' '#' 'sub-test' 'code')"
  for participant in "${PARTICIPANT_LABELS[@]}"; do
    header="${header}$(printf '  %-9s' "${participant}")"
  done
  say "$(trim_right "${header}")"

  subtest_index=0
  while [ "${subtest_index}" -lt "${#SUBTEST_NAMES[@]}" ]; do
    position=$((subtest_index + 1))
    row="$(printf '    %2s  %-13s %4s' "${position}" \
      "${SUBTEST_NAMES[${subtest_index}]}" \
      "${SUBTEST_CODES[${subtest_index}]}")"
    for participant in "${PARTICIPANT_LABELS[@]}"; do
      run_key="${participant}/${env_label}"
      verdict="$(subtest_verdict "${RUN_STATUS["${run_key}"]}" \
        "${position}")"
      row="${row}$(printf '  %-9s' "${verdict}")"
    done
    say "$(trim_right "${row}")"
    subtest_index=$((subtest_index + 1))
  done

  # Attempts and every status seen, so that a reader can tell a deterministic
  # failure from one that moved between attempts.
  for participant in "${PARTICIPANT_LABELS[@]}"; do
    run_key="${participant}/${env_label}"
    if [ "${RUN_ATTEMPTS["${run_key}"]}" != "1" ] &&
       [ "${RUN_ATTEMPTS["${run_key}"]}" != "0" ]; then
      say "    ${participant}: ${RUN_ATTEMPTS["${run_key}"]} attempts, \
statuses ${RUN_STATUSES_SEEN["${run_key}"]}"
    fi
    fact "status-${participant}-${env_label}" "${RUN_STATUS["${run_key}"]}"
  done
done

section "Reported constraints: noted here, deliberately not remedied"

# Each of these needs a change to a file that is out of scope. The
# instruction in that situation is to report the constraint and its remedy
# rather than to take the edit, so that is what these four do. None of the
# remedies below is applied by this script or by anything it runs.
say ""
say "  R1  Committing rust-urlapi/** makes the distribution check fail."
say "      .github/scripts/distfiles.sh diffs the output of git ls-files"
say "      against the contents of the release tarball, subtracts a fixed"
say "      literal exception list with no entry that could match this"
say "      directory, and exits non-zero for whatever it reports as"
say "      missing. It runs as the missing-files job of"
say "      .github/workflows/distcheck.yml:L210-L224, in a workflow that"
say "      triggers on every push to the default branch and every pull"
say "      request against it with no path filter, at its L7-L14. The only"
say "      remedies edit Makefile.am -- EXTRA_DIST at its L67, or the"
say "      distributed subdirectory lists at its L73-L74 -- and the build"
say "      system is out of scope. That one-line addition is a follow-up"
say "      decision for downstream owners, and this work does not make it."
say ""
say "  R2  A second URL API test is beyond drop-in reach and is not run."
say "      tests/unit/unit1653.c, driven by tests/data/test1653 and named"
say "      urlapi port number parsing, calls Curl_parse_port directly at"
say "      its L37, handing it a CURLU * together with a struct dynbuf *"
say "      it constructed itself at L33-L38. That symbol is exported only"
say "      in unit-test builds. Satisfying it from Rust would need a ninth"
say "      exported symbol AND bit-compatible interoperation with C's"
say "      dynamic-buffer structure, a materially harder contract than"
say "      anything the public API demands. Out of scope, and recorded"
say "      here rather than passed over in silence."
say ""
say "  R3  The harness is built without curl's memory-debug configuration,"
say "      so curl's own allocation counter does not run. curl_free"
say "      forwards to a macro that resolves at compile time"
say "      (lib/escape.c:L189-L192); under memory debugging it becomes a"
say "      tracking free that validates every pointer against its own"
say "      table (lib/memdebug.c:L383), which would reject or mis-account"
say "      the C-allocator buffers the crate hands back. The ceiling of"
say "      Allocations: 3000 at tests/data/test1560:L39-L40 is therefore"
say "      honored in spirit -- the port is not materially more"
say "      allocation-hungry -- but is not measured by the mechanism that"
say "      wrote it. --valgrind offers an independent count, reported"
say "      without being asserted on. docs/MEMORY-OWNERSHIP.md has the"
say "      whole resolution chain and both sets of numbers."
say ""
say "  R4  Alternative allocators are not supported. libcurl's free hook is"
say "      a mutable global function pointer, initialized to free and"
say "      reassignable at runtime through curl_global_init_mem, so an"
say "      application that installs its own allocators would release the"
say "      crate's C-allocator buffers with its own deallocator. Reported,"
say "      not worked around; see docs/MEMORY-OWNERSHIP.md."
say ""
say "  Honest limits of this validation, beyond the four above:"
say "    - acceptance criterion A10, that the six faithfully reproduced"
say "      oddities of the C implementation are preserved rather than"
say "      fixed, is not measured here. Every one of them is enforced by"
say "      the crate's own tests, tests/ffi_surface.rs among them, and"
say "      catalogued in docs/KNOWN-DIVERGENCES.md. What this run does"
say "      contribute to it is the locale-dependent divergence above:"
say "      under LC_ALL=C the port reproduces the reference's own"
say "      CURLUE_BAD_HOSTNAME failure rather than succeeding where the C"
say "      implementation cannot."
say "    - tests/unit/unit1653.c is not run, per R2."
say "    - Windows-specific paths in the port are compiled conditionally"
say "      and are not exercised here; the rows that would cover them are"
say "      reported above as absent from the preprocessed source."
say "    - the idn-pure backend, if anyone selects it, is not bit-for-bit."
say "      docs/KNOWN-DIVERGENCES.md records what differs. Parity claims"
say "      apply to the default libidn2 backend."
say "    - the crate's own tests are not run here. They belong to the test"
say "      target of GNUmakefile, which runs cargo test."

section "Verdict"

fact 'checks-passed' "${CHECKS_PASSED}"
fact 'checks-failed' "${CHECKS_FAILED}"
fact 'environments' "${SELECTED_ENVS[*]}"
fact 'participants' "${PARTICIPANT_LABELS[*]}"
fact 'attempt-limit' "${ATTEMPTS}"
fact 'mode-a-harness' "${MODE_A_HARNESS}"
fact 'mode-b-harness' "${MODE_B_HARNESS}"
fact 'log' "${LOG_FILE}"

say "  checks passed: ${CHECKS_PASSED}"
say "  checks failed: ${CHECKS_FAILED}"
say "  transcript:    ${LOG_FILE}"
say "  captures:      ${RUN_DIR}"
say "  summary:       ${SUMMARY_FILE}"

if [ "${FINAL_STATUS}" = "0" ]; then
  fact 'result' 'pass'
  say ""
  say "  PARITY: the Rust port behaves as the C implementation does in every"
  say "  environment measured, and the demo transcripts are byte-identical."
else
  fact 'result' 'fail'
  say ""
  say "  PARITY NOT ESTABLISHED: ${CHECKS_FAILED} check(s) failed. Every"
  say "  failing check above names its own evidence file. Nothing here"
  say "  edits the test, the golden files or the C implementation to make a"
  say "  check pass."
fi

exit "${FINAL_STATUS}"
