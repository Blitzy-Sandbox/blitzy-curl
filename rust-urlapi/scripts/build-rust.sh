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

# Build curl-urlapi-rs in both of its feature configurations, prove both
# builds are warning-free and lint-clean, and record what was built so the
# other scripts in this directory read facts instead of re-deriving them.
#
# MODE A, the static drop-in configuration:
#
#   cargo build --release --no-default-features --features idn-libidn2
#
# strerror, cfree and scheme-table are all OFF here, because a real libcurl
# already defines curl_url_strerror (lib/strerror.c:420) and curl_free
# (lib/escape.c:189), and because src/scheme.rs is to consult libcurl's own
# Curl_get_scheme (lib/url.c:1469-1471) rather than a table of its own. The
# authoritative deliverable is the archive, and it is the one run-parity.sh
# links in place of urlapi.c.o. The shared object of this configuration
# exports the same eight names and IMPORTS the two libcurl-private scheme
# entry points declared at lib/url.h:76-77 -- two names where lib/urlapi.o
# itself leaves seventeen curl_/Curl_ names to the link, and both defined in
# the same lib/url.c that supplied its Curl_get_scheme. It resolves in a link
# where libcurl takes part and not at a bare dlopen.
#
# MODE B, the standalone configuration:
#
#   cargo build --release
#
# The default features, so the crate also supplies curl_url_strerror,
# curl_free and a built-in scheme table and needs no libcurl at all. The
# archive and the shared object are both closed here, and the shared object
# exports ten names: the eight plus the two feature-gated ones.
#
# Those two commands are the two configurations acceptance criterion A1 names,
# and they are issued verbatim unless --idn-backend asks for something else.
#
# MODE C, the shared drop-in configuration:
#
#   cargo build --release --no-default-features \
#     --features idn-libidn2,scheme-table
#
# The shared half of G1. strerror and cfree stay OFF, so the export set is
# exactly the eight names lib/urlapi.o defines, while scheme-table ON removes
# the two libcurl-private imports -- so build.rs proves the cdylib link closed
# with -Wl,-z,defs and the object loads under dlopen. The price is that scheme
# capabilities come from the crate's modelled table rather than the linked
# libcurl's real one, which is a knowing trade because the configuration names
# the feature on its own command line. See docs/KNOWN-DIVERGENCES.md,
# "Integration limitation: the shared object's contract varies by mode".
#
# All three configurations write to target/release, so each is built into its
# own target directory and its artifacts are copied to a mode-tagged place
# under build/ as soon as they exist. check-abi.sh and run-parity.sh need the
# archives to coexist.
#
# The canonical static deliverable of each mode is not Cargo's own archive but
# libcurl_urlapi_rs_dropin.a, which build.rs produces from it in a second
# invocation driven by CURL_URLAPI_DROPIN_ARCHIVE: ld -r --whole-archive,
# objcopy --keep-global-symbol, ar rcs. Only that archive defines exactly the
# ABI -- 8 globals in mode A, 10 in mode B -- where Cargo's defines thousands,
# because a staticlib carries the Rust standard library with it. build.rs
# validates the raw input before touching it and writes a provenance record
# beside the result. Cargo has no post-build hook, which is why the pass is a
# second invocation and why this script exists to drive the pair.
#
# What is produced, all under build/ and all ignored by rust-urlapi/.gitignore:
#
#   build/rust/mode-a/libcurl_urlapi_rs.a          Cargo's archive
#   build/rust/mode-a/libcurl_urlapi_rs_dropin.a   canonical, 8 globals
#   build/rust/mode-a/libcurl_urlapi_rs_dropin.a.provenance
#   build/rust/mode-a/libcurl_urlapi_rs.so         8 exports, imports scheme
#   build/rust/mode-a/DROP-IN-CDYLIB-NOTICE.txt    that import contract
#   build/rust/mode-b/libcurl_urlapi_rs.a          Cargo's archive
#   build/rust/mode-b/libcurl_urlapi_rs_dropin.a   canonical, 10 globals
#   build/rust/mode-b/libcurl_urlapi_rs_dropin.a.provenance
#   build/rust/mode-b/libcurl_urlapi_rs.so         closed, 10 exports
#   build/rust/mode-c/libcurl_urlapi_rs.a          Cargo's archive
#   build/rust/mode-c/libcurl_urlapi_rs_dropin.a   canonical, 8 globals
#   build/rust/mode-c/libcurl_urlapi_rs_dropin.a.provenance
#   build/rust/mode-c/libcurl_urlapi_rs.so         closed, 8 exports
#   build/rust/deps-mode-{a,b,c}.txt               resolved dependencies
#   build/rust/*.log                               one log per step
#   build/rust-build-summary.txt                   key=value summary
#
# Nothing tracked by git is written: --locked keeps Cargo.lock as it is, and
# the mirror header under include/ is only ever regenerated when somebody asks
# for the genheader feature and sets CURL_URLAPI_WRITE_MIRROR_HEADER, which
# this script refuses to pass on.
#
# THE SUMMARY FILE IS DATA, NOT SHELL. Its keys are lowercase with dashes,
# which are deliberately not valid shell identifiers, so the file cannot be
# sourced even by accident. Every value is validated before it is written --
# no carriage return, no newline, no other control byte -- and every key is
# written at most once. Consumers parse it with sed, which is what
# check-abi.sh and run-parity.sh do.
#
# THE SUMMARY FILE IS ALSO A VERDICT, and it names the exact bytes it
# describes. It carries result=pass only when both configurations built and
# passed clippy, it carries an sha256 for every staged artifact, and a run that
# stops part-way through leaves result=fail behind rather than the previous
# run's summary. That is what lets check-abi.sh and run-parity.sh tell "the
# file at the recorded path" from "the file this run produced" -- two claims
# that coincide most of the time and not always, because the scratch tree is
# deliberately reusable.

set -eu

# pipefail, so that a failure anywhere in a pipeline is the pipeline's failure.
# Without it the status of "cargo build | tee log" is tee's, and tee succeeds
# whatever it was handed; the same goes for every counting and normalising
# pipeline below. Each place where a non-zero status is genuinely expected --
# grep matching nothing, mostly -- guards itself explicitly, so enabling this
# reports real failures rather than manufacturing false ones.
set -o pipefail

# Every file this script creates is created for this user only. The staging
# tree is a predictable path by design -- check-abi.sh and run-parity.sh have
# to find it -- so the protection against another user planting a file or a
# symlink there first is the permission mask plus the remove-before-write
# discipline fresh_path() applies.
umask 077

# Run from the crate root whatever directory the caller was in, so that
# rust-toolchain.toml applies to every cargo command below without any of them
# naming a toolchain, and so relative paths in the summary mean one thing.
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
CRATE_ROOT="$(pwd -P)"

# The repository root, needed only so that the containment rule below has
# something to measure against. Taken as the parent directory rather than from
# git, so that this works in an exported tree with no .git in it.
REPO_ROOT="$(cd .. && pwd -P)"

# Where an output tree is allowed to be, and why the question needs asking.
#
# BUILD_DIR and CARGO_TARGET_DIR are environment-controlled, and everything
# this script writes goes underneath one of them: the staging tree, the logs,
# the summary, and Cargo's own object and artifact directories. An unvalidated
# value therefore lets the environment aim a Cargo build and a dozen
# redirections at any directory on the machine, lib/ and tests/ and the
# repository root among them, where the result would be modifications to
# pre-existing files. That is goal G4 and acceptance criterion A12 broken by an
# environment variable, so the value is checked rather than trusted.
#
# The rule is the same one build-reference.sh and check-abi.sh apply, stated in
# full here as well because each script has to stand on its own:
#
#   - inside the repository, only <crate>/build and <crate>/target and their
#     descendants are allowed. Those two are what ../.gitignore covers, so
#     they are the only places inside the tree where writing cannot show up in
#     "git status --porcelain";
#   - outside the repository, anything is allowed except the filesystem root.
#     That is the parallel-clone case, where each clone points its target at
#     something like /tmp/cargo-target-$CLONE_INDEX;
#   - the repository root itself and the empty string are refused outright.
#
# The path is canonicalized with cd + pwd -P before any of that is decided,
# which is what makes a symlink harmless rather than an escape: a target
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
    printf 'build-rust.sh: error: %s\n' \
      "${label} is set but empty. Unset it to accept the default, or give it \
a directory" >&2
    exit 2
  fi

  # Created before it is resolved, because cd cannot resolve a path that does
  # not exist yet and the ordinary first run has to work.
  if ! mkdir -p -- "${raw}" 2> /dev/null; then
    printf 'build-rust.sh: error: %s\n' \
      "${label}=${raw} could not be created" >&2
    exit 2
  fi

  if ! canonical="$(cd -- "${raw}" && pwd -P)"; then
    printf 'build-rust.sh: error: %s\n' \
      "${label}=${raw} exists but could not be entered, so its real location \
cannot be established" >&2
    exit 2
  fi

  if [ "${canonical}" = '/' ]; then
    printf 'build-rust.sh: error: %s\n' \
      "${label} resolves to the filesystem root, and this script writes a \
build tree, artifacts, logs and a summary underneath it" >&2
    exit 2
  fi

  if [ "${canonical}" = "${REPO_ROOT}" ]; then
    printf 'build-rust.sh: error: %s\n' \
      "${label}=${raw} resolves to the repository root ${REPO_ROOT}. Writing \
there would modify pre-existing files, which goal G4 forbids" >&2
    exit 2
  fi

  case "${canonical}" in
    "${CRATE_ROOT}/build" | "${CRATE_ROOT}/build/"* | \
    "${CRATE_ROOT}/target" | "${CRATE_ROOT}/target/"*)
      # Inside the crate's own ignored output. The allowed in-repository case.
      ;;
    "${REPO_ROOT}/"*)
      printf 'build-rust.sh: error: %s\n' \
        "${label}=${raw} resolves to ${canonical}, which is inside the \
repository but outside the crate's ignored output. Only ${CRATE_ROOT}/build \
and ${CRATE_ROOT}/target are writable inside the tree -- everything else \
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

# Removes whatever occupies a path so that the next write creates it fresh.
#
# Every destination this script writes is a predictable path underneath the
# staging tree, because check-abi.sh and run-parity.sh have to find it without
# being told. That predictability is what a symlink attack needs: plant
# build/rust/build-mode-a.log as a link to something else and a plain ">"
# redirection follows it and truncates the target. rm removes the LINK rather
# than what it points at, so removing first and creating second turns the whole
# class of problem into a no-op. Real directories are left alone, and an absent
# path is not an error.
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

# BUILD_DIR is honoured here for the same reason build-reference.sh and
# check-abi.sh honour it: a caller who moved the scratch tree elsewhere, or who
# parameterised it per clone for a parallel run, has to be able to point all
# four scripts at one place. This script used to hardcode <crate>/build while
# the other two read BUILD_DIR, so a custom root produced a workflow in which
# the reference build and the ABI gate looked in one directory and the Rust
# artifacts were written to another -- reported downstream as artifacts that
# were simply missing.
#
# The colon-less expansion is deliberate: the default applies when BUILD_DIR is
# UNSET, and a value that is set and empty is handed to resolve_output_root()
# to be refused there. ${VAR:-default} would silently read "BUILD_DIR=" as "no
# BUILD_DIR", which is a guess between two meanings that want opposite answers.
BUILD="$(resolve_output_root BUILD_DIR "${BUILD_DIR-${CRATE_ROOT}/build}")"
STAGE="${BUILD}/rust"
SUMMARY="${BUILD}/rust-build-summary.txt"

# The published summary is replaced whole, by rename, from this file. Nothing
# ever appends to the published path. See publish_summary().
SUMMARY_INPROGRESS=''

# The verdict the summary will carry. Declared here, next to the file it
# belongs to, and set to pass only at the very end when both configurations
# have built and passed clippy. The EXIT trap publishes whatever it holds at
# that moment, so a run that dies anywhere -- a refused value, a missing
# artifact, a clippy finding, an interrupt -- leaves result=fail behind rather
# than the previous run's result=pass. Declaring it before the trap is
# installed is what keeps the handler from reading an unset variable under
# set -u, which would make the handler itself fail and leave no verdict at all.
RESULT='fail'

CRATE='curl-urlapi-rs'
LIBRARY='curl_urlapi_rs'
ARCHIVE="lib${LIBRARY}.a"
DROPIN="lib${LIBRARY}_dropin.a"
SHARED="lib${LIBRARY}.so"
NOTICE='DROP-IN-CDYLIB-NOTICE.txt'

# The three minimum Rust versions in play, reported rather than enforced.
# 1.75 is this crate's declared minimum, from the technical specification and
# from rust-version in Cargo.toml. 1.73 is curl's own documented floor,
# docs/RUSTLS.md:59. 1.86 is what the optional idn-pure backend needs, through
# the internationalisation packages its dependency tree pulls in, and is
# exactly why that backend is not the default.
MSRV_CRATE='1.75'
MSRV_CURL='1.73'
MSRV_IDN_PURE='1.86'

# The feature sets. Mode A names its one feature explicitly; mode B takes the
# manifest default, which is these three plus the selected IDN backend.
STANDALONE_FEATURES='strerror,cfree,scheme-table'

# Defaults, each overridable by an option or by the environment variable of
# the same purpose. Every one of them is off by default: an unadorned run
# builds the two canonical configurations and nothing else.
WITH_CAPI="${WITH_CAPI:-0}"
ALLOW_UPDATE="${ALLOW_UPDATE:-0}"
STRICT_FMT="${STRICT_FMT:-0}"
SKIP_DROPIN="${SKIP_DROPIN:-0}"
IDN_BACKEND="${IDN_BACKEND:-libidn2}"
EXTRA_FEATURES="${EXTRA_FEATURES:-}"

usage() {
  cat <<'EOF'
Usage: scripts/build-rust.sh [options]

Builds curl-urlapi-rs three times: the static drop-in configuration, the
standalone one, and the shared drop-in one, which is the closed
eight-export shared object G1 asks for. Runs the drop-in localization pass
over each archive, checks every configuration with clippy, records the
resolved dependencies and writes build/rust-build-summary.txt.

Options:
  -h, --help              show this text and exit
  --idn-backend=BACKEND   libidn2 (default), pure or none. Anything other
                          than libidn2 leaves the two configurations
                          acceptance criterion A1 names, so parity claims no
                          longer apply; the script says so when it happens.
  --features=LIST         extra features added to both configurations, comma
                          or space separated. Naming an IDN backend here is
                          refused: use --idn-backend instead.
  --capi                  also run the optional cargo-c packaging path, which
                          is packaging support only and wires nothing into
                          curl's own build system. It cannot run on this
                          manifest -- cargo-c needs a declared capi feature
                          and Cargo.toml declares the six the plan freezes --
                          so giving this option FAILS the run rather than
                          reporting a success that installed nothing. See
                          docs/KNOWN-DIVERGENCES.md, "Reported constraint:
                          cargo-c and the capi feature".
  --strict-fmt            make a rustfmt difference fail the run instead of
                          being reported
  --no-dropin             skip the drop-in localization pass. The canonical
                          archive is then not produced and check-abi.sh has
                          nothing to compare, so this is for a quick
                          compile check and not for a parity run.

Environment variables, each equivalent to the option beside it:
  WITH_CAPI=1             --capi
  STRICT_FMT=1            --strict-fmt
  SKIP_DROPIN=1           --no-dropin
  IDN_BACKEND=...         --idn-backend=...
  EXTRA_FEATURES=...      --features=...
  ALLOW_UPDATE=1          drop --locked, letting Cargo re-resolve the
                          dependency graph. Cargo.lock is committed, so a
                          resolution that drifts should be a loud failure;
                          using this invalidates every reproducibility claim
                          in build/rust-build-summary.txt.
  BUILD_DIR=...           the scratch tree, default <crate>/build. Shared
                          with build-reference.sh, check-abi.sh and
                          run-parity.sh: point all four at the same place.
                          Must resolve to <crate>/build, <crate>/target or
                          a directory outside the repository.
  CARGO_TARGET_DIR=...    the parent of the two per-mode target directories,
                          default <crate>/target, with the same containment
                          rule
  CURL_URLAPI_IDN2_H=...  a readable idn2.h, accepted together with a
                          successful -lidn2 link probe in place of
                          pkg-config for the libidn2 backend. build.rs
                          reads the same variable for the two version
                          constants lib/idn.c compares against.

Two variables this script does not merely read:
  RUSTFLAGS               INHERITED AND APPENDED TO, not replaced. Whatever
                          the caller set is kept and "-D warnings" is added
                          after it, which is what makes "zero compiler
                          warnings" a build failure rather than something to
                          grep for. RUSTFLAGS is part of Cargo's fingerprint,
                          so the first build after it changes is a full
                          rebuild. The resolved value is recorded in the
                          summary file as "rustflags".
  CURL_URLAPI_WRITE_MIRROR_HEADER
                          FORCIBLY CLEARED, with a warning, if it is set.
                          Honoring it would have build.rs rewrite the tracked
                          include/curl_urlapi_rs.h, and a run of this script
                          must add nothing to the working tree outside
                          target/ and build/. Under the genheader feature the
                          default is to compare the committed header against
                          the generated one, which is the check worth having.
                          Run cargo directly if installing it is really
                          wanted.

Compiler flags. This script adds "-D warnings" so that "zero compiler
warnings" is enforced rather than looked for afterwards, and it adds them to
whichever variable Cargo will actually read. Cargo uses the FIRST of these
that is set and does not merge them:

  CARGO_ENCODED_RUSTFLAGS  highest precedence: the whole argument vector in
                           one variable, arguments separated by 0x1f. When it
                           is already set, "-D warnings" is appended to it and
                           RUSTFLAGS is unset for the run.
  RUSTFLAGS               used when the encoded form is unset. "-D warnings"
                           is appended to whatever it holds.
  CARGO_BUILD_RUSTFLAGS   lowest precedence, and therefore never in force
                           here, because one of the two above always is. It is
                           reported when set so that a caller knows it did not
                           apply.

The flags in force are recorded as rustflags in
build/rust-build-summary.txt, with rustflags-source naming which of the three
carried them.

Exit status is 0 only when all three configurations built with no compiler
warning and no clippy finding, no explicitly requested optional path failed,
and every expected artifact was produced by THIS run -- the expected artifacts
are removed from the target tree before each build and an sha256 for each is
recorded in the summary, so a stale file cannot stand in for one.
EOF
}

# --------------------------------------------------------------------------
# Reporting helpers. Progress goes to stdout, everything a caller might act on
# goes to stderr, and each build step's full output goes to its own log under
# build/rust/ so a failure can be read after the fact.
# --------------------------------------------------------------------------

say() {
  printf '%s\n' "$*"
}

step() {
  printf '\n== %s\n' "$*"
}

warn() {
  printf 'build-rust.sh: warning: %s\n' "$*" >&2
}

die() {
  printf 'build-rust.sh: error: %s\n' "$*" >&2
  exit 1
}

# Run a command with its output captured. The log is kept whether the command
# succeeded or not, and the tail is printed on failure so the caller sees the
# reason without having to go looking for it. Deliberately pipeline-free: a
# `| tee` here would need pipefail to report the command's own status.
run_logged() {
  local log="${1}"
  shift
  local status=0

  printf '+ %s\n' "$*" >> "${log}"
  # The status is captured on the failing command itself. Reading $? after an
  # if/fi would read the if statement's own status, which is 0 when the
  # condition simply did not hold, and a failure would then be reported as a
  # success -- which is exactly what happened to the first version of this.
  "$@" >> "${log}" 2>&1 || status=$?
  if [ "${status}" -eq 0 ]; then
    return 0
  fi

  printf 'build-rust.sh: command failed with status %s:\n' "${status}" >&2
  printf '    %s\n' "$*" >&2
  printf '  last 40 lines of %s:\n' "${log}" >&2
  tail -n 40 "${log}" >&2
  return "${status}"
}

# --------------------------------------------------------------------------
# Options
# --------------------------------------------------------------------------

while [ "$#" -gt 0 ]; do
  case "${1}" in
    -h|--help)
      usage
      exit 0
      ;;
    --capi)
      WITH_CAPI=1
      ;;
    --strict-fmt)
      STRICT_FMT=1
      ;;
    --no-dropin)
      SKIP_DROPIN=1
      ;;
    --idn-backend=*)
      IDN_BACKEND="${1#*=}"
      ;;
    --idn-backend)
      shift
      if [ "$#" -eq 0 ]; then
        die '--idn-backend needs a value: libidn2, pure or none'
      fi
      IDN_BACKEND="${1}"
      ;;
    --features=*)
      EXTRA_FEATURES="${1#*=}"
      ;;
    --features)
      shift
      if [ "$#" -eq 0 ]; then
        die '--features needs a comma or space separated list'
      fi
      EXTRA_FEATURES="${1}"
      ;;
    *)
      printf 'build-rust.sh: error: unknown argument: %s\n' "${1}" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

# Normalise the extra feature list: spaces to commas, no empty entries, so it
# can be handed to cargo as a single --features argument.
EXTRA_FEATURES="${EXTRA_FEATURES//[[:space:]]/,}"
while [ "${EXTRA_FEATURES}" != "${EXTRA_FEATURES//,,/,}" ]; do
  EXTRA_FEATURES="${EXTRA_FEATURES//,,/,}"
done
EXTRA_FEATURES="${EXTRA_FEATURES#,}"
EXTRA_FEATURES="${EXTRA_FEATURES%,}"

# The two IDN backends are mutually exclusive, mirroring the #error at
# lib/curl_setup.h:726-728. Cargo features are additive, so build.rs is what
# enforces it -- and a build script panic is a poor first explanation, so the
# combination is refused here, by name, before cargo is ever called.
case ",${EXTRA_FEATURES}," in
  *,idn-libidn2,*|*,idn-pure,*)
    warn 'the two IDN backends are mutually exclusive, and --features would'
    warn 'add one on top of the backend --idn-backend already selected,'
    warn 'which build.rs refuses with a panic once cargo reaches it'
    die 'select the IDN backend with --idn-backend, never with --features'
    ;;
esac

case "${IDN_BACKEND}" in
  libidn2|pure|none)
    ;;
  *)
    die "unknown IDN backend \"${IDN_BACKEND}\": expected libidn2, pure, none"
    ;;
esac

# The backend feature, and whether the run still builds what A1 names.
BACKEND_FEATURE=''
CANONICAL='yes'
case "${IDN_BACKEND}" in
  libidn2)
    BACKEND_FEATURE='idn-libidn2'
    ;;
  pure)
    BACKEND_FEATURE='idn-pure'
    CANONICAL='no'
    ;;
  none)
    CANONICAL='no'
    ;;
esac

if [ -n "${EXTRA_FEATURES}" ]; then
  CANONICAL='no'
fi

LOCKED='on'
if [ "${ALLOW_UPDATE}" != '0' ]; then
  LOCKED='off'
fi

# --------------------------------------------------------------------------
# Prerequisites. Every missing one is collected and reported together: being
# told about cargo, then about binutils, then about libidn2 across three runs
# wastes the caller's time, and the analysis environment really did start
# without a Rust toolchain at all.
# --------------------------------------------------------------------------

MISSING=0

missing() {
  printf 'build-rust.sh: missing prerequisite: %s\n' "${1}" >&2
  shift
  while [ "$#" -gt 0 ]; do
    printf '    remedy: %s\n' "${1}" >&2
    shift
  done
  MISSING=$((MISSING + 1))
}

# command -v rather than which, because which is deprecated and the
# repository's own style gate enables deprecate-which to say so.
have() {
  command -v "${1}" > /dev/null 2>&1
}

# Whether a program that includes the named idn2.h and links -lidn2 builds.
#
# Asked by compiling and linking rather than by looking for a file, because
# where libidn2.so lives is the linker's business: a caller who installed it
# outside pkg-config's view has almost certainly told the linker about it
# through LIBRARY_PATH or a linker configuration file, and only the linker
# knows. The program calls idn2_lookup_ul so that the probe needs a real
# definition and not merely a library that exists -- that is the entry point
# lib/idn.c reaches through its lookup macro, so it is also the right one to
# demand.
#
#   $1  the header to include
probe_libidn2_link() {
  local header="${1}"
  local dir
  local status=0

  # A private directory, so that neither the source nor the binary is written
  # through a path something else could have prepared.
  if ! dir="$(mktemp -d "${TMPDIR:-/tmp}/curl-urlapi-idn2.XXXXXX")"; then
    return 1
  fi

  printf '%s\n' \
    "#include \"${header}\"" \
    'int main(void) {' \
    '  char *out = 0;' \
    '  (void)idn2_lookup_ul("example.com", &out, 0);' \
    '  return 0;' \
    '}' \
    > "${dir}/probe.c"

  if ! "${CC:-cc}" -o "${dir}/probe" "${dir}/probe.c" -lidn2 \
       > "${dir}/probe.log" 2>&1; then
    status=1
  fi
  rm -rf -- "${dir:?}"
  return "${status}"
}

step 'Checking prerequisites'

if have cargo; then
  CARGO_VERSION="$(cargo --version)"
  say "cargo:   ${CARGO_VERSION}"
else
  CARGO_VERSION='absent'
  missing 'cargo' \
    'install a Rust toolchain with rustup, https://rustup.rs' \
    'rust-toolchain.toml then selects the channel and the components'
fi

if have rustc; then
  RUSTC_VERSION="$(rustc --version)"
  say "rustc:   ${RUSTC_VERSION}"
else
  RUSTC_VERSION='absent'
  missing 'rustc' 'comes with the same Rust toolchain as cargo'
fi

# clippy is a hard requirement rather than an optional extra, because zero
# lint findings is half of what acceptance criterion A1 asks for and
# rust-toolchain.toml lists the component, so a correctly provisioned
# toolchain has it.
if have cargo-clippy; then
  CLIPPY_VERSION="$(cargo clippy --version 2>/dev/null || printf 'unknown')"
  say "clippy:  ${CLIPPY_VERSION}"
else
  CLIPPY_VERSION='absent'
  missing 'cargo-clippy' 'rustup component add clippy'
fi

# rustfmt is genuinely optional: a formatting difference is reported, and only
# fails the run when --strict-fmt asks it to.
if have rustfmt; then
  RUSTFMT_VERSION="$(rustfmt --version 2>/dev/null || printf 'unknown')"
  say "rustfmt: ${RUSTFMT_VERSION}"
else
  RUSTFMT_VERSION='absent'
  if [ "${STRICT_FMT}" != '0' ]; then
    missing 'rustfmt, which --strict-fmt requires' \
      'rustup component add rustfmt, or drop --strict-fmt'
  else
    warn 'rustfmt is absent, so the formatting check is skipped'
  fi
fi

# The drop-in localization pass in build.rs shells out to ld, objcopy, ar and
# nm, and lets LD, OBJCOPY, AR and NM name something else instead, which is
# what a cross build needs. Whichever binary each of them resolves to has to
# exist, because without it the canonical archive cannot be produced at all,
# so they are prerequisites of every run that is not --no-dropin.
if [ "${SKIP_DROPIN}" = '0' ]; then
  for tool_pair in 'LD:ld' 'OBJCOPY:objcopy' 'AR:ar' 'NM:nm'; do
    tool_variable="${tool_pair%%:*}"
    tool_default="${tool_pair#*:}"
    tool_name="${!tool_variable:-${tool_default}}"
    if ! have "${tool_name}"; then
      missing "${tool_name}, which the drop-in localization pass runs" \
        'apt-get install binutils' \
        "or set ${tool_variable} to the binary to use instead" \
        'or pass --no-dropin and give up the canonical archive'
    fi
  done
fi

# Everything else this script runs, paired with the package that supplies it.
#
# The claim this list makes is that it is COMPLETE, and the claim is meant
# literally: it was built by extracting every command position from this file
# rather than by recollection, because a table that is merely nearly complete
# produces the failure it exists to prevent -- a missing tool discovered in the
# middle of a build instead of here. The four toolchain entries above and the
# libidn2 section below cover the rest.
#
# Two commands necessarily escape it, and both are named rather than left as
# silent gaps: mkdir and rm ran before this section, creating the output roots,
# and are listed anyway; and git is deliberately NOT required, being consulted
# once for the commit the artifacts were built from, so that this script works
# in an exported tree with no .git in it.
#
# Shell builtins are absent by definition: printf, cd, pwd, read, command,
# trap, umask and the pattern-matching constructs need nothing installed.
for tool_pair in \
    'awk:gawk or mawk' \
    'cat:coreutils' \
    'cp:coreutils' \
    'env:coreutils' \
    'find:findutils' \
    'grep:grep' \
    'mkdir:coreutils' \
    'mktemp:coreutils' \
    'mv:coreutils' \
    'rm:coreutils' \
    'sed:sed' \
    'sha256sum:coreutils' \
    'sort:coreutils' \
    'tail:coreutils' \
    'tr:coreutils' \
    'wc:coreutils'; do
  tool_name="${tool_pair%%:*}"
  tool_package="${tool_pair#*:}"
  if ! have "${tool_name}"; then
    missing "${tool_name}, which this script runs" \
      "apt-get install ${tool_package}"
  fi
done

# libidn2 is only a prerequisite when the backend that binds it is selected.
# build.rs emits the link request for it and reads its header for the two
# version constants lib/idn.c compares against, so a missing one fails the
# build late and confusingly rather than here.
#
# THERE ARE TWO WAYS TO SATISFY IT, and both are honoured, which they used not
# to be. The first is pkg-config, which answers for the header and the library
# together and also supplies the version. The second is
# CURL_URLAPI_IDN2_H naming a readable idn2.h, which is precisely the override
# build.rs itself reads -- and the old code named that override in its remedy
# text while still calling missing() and exiting 1, so a caller who did exactly
# what the diagnostic asked for got the same diagnostic again. A remedy that
# does not work is worse than no remedy: it sends the reader hunting for a
# fault in their own environment.
#
# The header override is deliberately paired with a link probe rather than
# trusted on its own: a header without a library produces an undefined-symbol
# failure at link time, which is exactly the late and confusing failure this
# section exists to convert into a named prerequisite. Both halves are checked,
# so the answer covers the whole dependency.
LIBIDN2_VERSION='not-required'
if [ "${IDN_BACKEND}" = 'libidn2' ]; then
  IDN2_HEADER_OVERRIDE="${CURL_URLAPI_IDN2_H:-}"

  # An override that is SET is checked whether or not pkg-config also answers,
  # because build.rs reads the variable unconditionally: an unreadable path
  # there fails the build with a Rust panic rather than with a named
  # prerequisite, which is the late and confusing failure this whole section
  # exists to convert. Checked first, so the diagnostic names the variable
  # rather than the build that tripped over it.
  if [ -n "${IDN2_HEADER_OVERRIDE}" ] &&
     [ ! -r "${IDN2_HEADER_OVERRIDE}" ]; then
    LIBIDN2_VERSION='override-unreadable'
    missing "CURL_URLAPI_IDN2_H=${IDN2_HEADER_OVERRIDE}, which is not a \
readable file. build.rs reads this variable whenever it is set, so an \
unreadable path fails the build rather than being ignored" \
      'correct the path' \
      'or unset it and let pkg-config locate libidn2' \
      'or select another backend, --idn-backend=pure or =none'
  elif have pkg-config && pkg-config --exists libidn2; then
    LIBIDN2_VERSION="$(pkg-config --modversion libidn2)"
    say "libidn2: ${LIBIDN2_VERSION} (pkg-config)"
  elif [ -n "${IDN2_HEADER_OVERRIDE}" ]; then
    # The header the caller named is readable. What remains is whether the
    # library itself can be linked, asked by compiling and linking a trivial
    # program against -lidn2 rather than by looking for a file, because where
    # the library lives is the linker's business and not this script's.
    if probe_libidn2_link "${IDN2_HEADER_OVERRIDE}"; then
      LIBIDN2_VERSION='header-override'
      say "libidn2: satisfied by CURL_URLAPI_IDN2_H=${IDN2_HEADER_OVERRIDE}"
      say '         and a successful -lidn2 link probe, so pkg-config is not'
      say '         needed. build.rs reads the same override for the two'
      say '         version constants lib/idn.c compares against.'
    else
      LIBIDN2_VERSION='header-without-library'
      missing "libidn2 itself: CURL_URLAPI_IDN2_H names a readable \
${IDN2_HEADER_OVERRIDE} but a program including it and linking -lidn2 does \
not build" \
        'apt-get install libidn2-dev, the package linux.yml:76 installs' \
        'or add the library directory to LIBRARY_PATH' \
        'or select another backend, --idn-backend=pure or =none'
    fi
  elif ! have pkg-config; then
    LIBIDN2_VERSION='unknown'
    missing 'pkg-config, used to locate libidn2' \
      'apt-get install pkg-config' \
      'or point CURL_URLAPI_IDN2_H at a readable idn2.h, which build.rs' \
      '  reads and which this script accepts together with a -lidn2 link' \
      '  probe in place of pkg-config' \
      'or select another backend, --idn-backend=pure or =none'
  else
    LIBIDN2_VERSION='absent'
    missing 'libidn2 development files' \
      'apt-get install libidn2-dev, the package linux.yml:76 installs' \
      'or point CURL_URLAPI_IDN2_H at a readable idn2.h if the library is' \
      '  installed somewhere pkg-config cannot see' \
      'or select another backend, --idn-backend=pure or =none'
  fi
fi

if [ "${MISSING}" -gt 0 ]; then
  die "${MISSING} prerequisite(s) missing, so nothing was built"
fi

# --------------------------------------------------------------------------
# Toolchain floors: information, not gates. A toolchain below the declared
# minimum is warned about and then used, because the failure it produces is
# more useful than a refusal here would be.
# --------------------------------------------------------------------------

RUSTC_SEMVER="${RUSTC_VERSION#rustc }"
RUSTC_SEMVER="${RUSTC_SEMVER%% *}"

# Print below, ok or unknown for the detected toolchain against the given
# major.minor. A word rather than an exit status, so a caller reads it without
# the indirection of $?, and unknown rather than a guess when the version
# string is a nightly or has been patched by a distribution.
version_state() {
  local want="${1}"
  local want_major="${want%%.*}"
  local want_minor="${want#*.}"
  local have_major="${RUSTC_SEMVER%%.*}"
  local have_rest="${RUSTC_SEMVER#*.}"
  local have_minor="${have_rest%%.*}"

  # Trim anything that is not a digit, so 1.98.0-nightly reads as 1.98.
  have_major="${have_major%%[!0-9]*}"
  have_minor="${have_minor%%[!0-9]*}"

  case "${have_major}" in
    ''|*[!0-9]*)
      printf 'unknown\n'
      return 0
      ;;
  esac
  case "${have_minor}" in
    ''|*[!0-9]*)
      printf 'unknown\n'
      return 0
      ;;
  esac

  if [ "${have_major}" -lt "${want_major}" ] ||
     { [ "${have_major}" -eq "${want_major}" ] &&
       [ "${have_minor}" -lt "${want_minor}" ]; }; then
    printf 'below\n'
    return 0
  fi
  printf 'ok\n'
}

RUSTC_FLOOR="$(version_state "${MSRV_CRATE}")"
case "${RUSTC_FLOOR}" in
  below)
    RUSTC_FLOOR='below-declared-minimum'
    warn "rustc ${RUSTC_SEMVER} is below ${MSRV_CRATE}, the minimum this"
    warn "crate declares as rust-version in Cargo.toml; curl's own"
    warn "documented floor is ${MSRV_CURL}, docs/RUSTLS.md:59"
    warn 'the build is attempted anyway, because the failure it produces'
    warn 'is more informative than a refusal here would be'
    ;;
  unknown)
    RUSTC_FLOOR='unreadable'
    warn "no major.minor version could be read out of \"${RUSTC_VERSION}\","
    warn "so the ${MSRV_CRATE} minimum was not checked"
    ;;
  *)
    say "floors:  declared ${MSRV_CRATE}, curl ${MSRV_CURL}, idn-pure \
${MSRV_IDN_PURE}"
    ;;
esac

if [ "${IDN_BACKEND}" = 'pure' ] &&
   [ "$(version_state "${MSRV_IDN_PURE}")" = 'below' ]; then
  warn "the idn-pure backend needs rustc ${MSRV_IDN_PURE} or newer through"
  warn "its dependency tree, and this toolchain is ${RUSTC_SEMVER}"
fi

# --------------------------------------------------------------------------
# The environment every cargo invocation below shares
# --------------------------------------------------------------------------

# -D warnings is what makes "zero compiler warnings" unambiguous: a warning
# becomes an error rather than something to grep for afterwards. It is
# appended to whatever the caller already had rather than replacing it.
# Setting RUSTFLAGS is part of Cargo's fingerprint, so the first build after a
# change to it is a full rebuild; that is the price of the guarantee, and for a
# crate with one dependency it is a few seconds.
#
# RUSTFLAGS IS NOT THE ONLY WAY TO SET COMPILER FLAGS, AND IT IS NOT THE ONE
# CARGO PREFERS. Cargo consults, in this order, and uses the FIRST that is set
# rather than merging them:
#
#   1. CARGO_ENCODED_RUSTFLAGS, a single variable holding the whole argument
#      vector separated by 0x1f units;
#   2. RUSTFLAGS, split on whitespace;
#   3. the target-specific and host-wide rustflags of the configuration files,
#      including build.rustflags, which is what CARGO_BUILD_RUSTFLAGS sets
#      through the environment.
#
# So appending to RUSTFLAGS alone is not enough to promise anything: a caller
# with CARGO_ENCODED_RUSTFLAGS already set gets that vector and the appended
# "-D warnings" is silently discarded, which turns "zero compiler warnings" in
# the summary into a claim about a build that never enforced it. All three are
# therefore handled here, and the effective vector is recorded rather than the
# variable this script happened to write.
#
# The encoded form is COMPOSED, not refused: a caller using it is doing
# something legitimate -- it is the only form that can carry a flag containing
# a space -- and refusing it would take that away. It is composed by appending
# a unit separator and the two arguments, which is exactly the concatenation
# the format defines. RUSTFLAGS is then unset, so nothing downstream can read a
# value Cargo is going to ignore, and the same is done in reverse when the
# encoded form is absent.
#
# CARGO_BUILD_RUSTFLAGS is the third form. It is lower precedence than both of
# the others, so whichever of them this script ends up setting wins and the
# build.rustflags value never applies; that is stated in the summary rather
# than silently relied on, because a caller who set it deserves to know it did
# not take effect.
RUSTFLAGS_SOURCE='rustflags'
if [ -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]; then
  RUSTFLAGS_SOURCE='cargo-encoded-rustflags'
  # 0x1f is the unit separator the encoded format puts between arguments, so
  # appending one separator per argument is the whole of the composition.
  UNIT_SEPARATOR=$'\037'
  CARGO_ENCODED_RUSTFLAGS="${CARGO_ENCODED_RUSTFLAGS}${UNIT_SEPARATOR}-D"
  CARGO_ENCODED_RUSTFLAGS="${CARGO_ENCODED_RUSTFLAGS}${UNIT_SEPARATOR}warnings"
  export CARGO_ENCODED_RUSTFLAGS
  # Whitespace-separated for the record only; the vector above is what Cargo
  # reads, and the two are equivalent for these arguments.
  RUSTFLAGS_EFFECTIVE="$(printf '%s' "${CARGO_ENCODED_RUSTFLAGS}" |
    tr '\037' ' ')"
  unset RUSTFLAGS
  warn 'CARGO_ENCODED_RUSTFLAGS was already set, so the -D warnings policy was'
  warn 'appended to it rather than to RUSTFLAGS: Cargo reads the encoded form'
  warn 'in preference and would otherwise have ignored RUSTFLAGS entirely.'
  warn 'RUSTFLAGS is unset for the rest of this run.'
else
  if [ -n "${RUSTFLAGS:-}" ]; then
    RUSTFLAGS="${RUSTFLAGS} -D warnings"
  else
    RUSTFLAGS='-D warnings'
  fi
  export RUSTFLAGS
  RUSTFLAGS_EFFECTIVE="${RUSTFLAGS}"
fi

BUILD_RUSTFLAGS_STATE='unset'
if [ -n "${CARGO_BUILD_RUSTFLAGS:-}" ]; then
  BUILD_RUSTFLAGS_STATE="set-and-overridden: ${CARGO_BUILD_RUSTFLAGS}"
  warn 'CARGO_BUILD_RUSTFLAGS is set. It is the lowest precedence of the three'
  warn 'ways to pass compiler flags, so it does NOT apply to this run: the'
  warn "flags in force are ${RUSTFLAGS_EFFECTIVE}"
fi

# build.rs writes the regenerated mirror header into the source tree when this
# is set, which would leave include/curl_urlapi_rs.h modified and break the
# requirement that a run of this script adds nothing to the working tree
# outside target/ and build/. Under the genheader feature the default is to
# compare the committed header against the generated one, which is the check
# worth having, so the variable is cleared instead of honoured.
if [ -n "${CURL_URLAPI_WRITE_MIRROR_HEADER:-}" ]; then
  warn 'CURL_URLAPI_WRITE_MIRROR_HEADER is set; clearing it, because it would'
  warn 'have build.rs rewrite the tracked include/curl_urlapi_rs.h. Run cargo'
  warn 'directly with the genheader feature if that is really what you want.'
  unset CURL_URLAPI_WRITE_MIRROR_HEADER
fi

mkdir -p "${BUILD}" "${STAGE}"

# Cargo's output root, held to the same containment rule as BUILD_DIR and for
# the same reason. It is handed straight to --target-dir below, so an
# unvalidated value would let the environment have Cargo create object
# directories inside lib/ or tests/.
TARGET_ROOT="$(resolve_output_root CARGO_TARGET_DIR \
  "${CARGO_TARGET_DIR-${CRATE_ROOT}/target}")"

TOOLCHAIN_LOG="${STAGE}/toolchain.txt"
fresh_path "${TOOLCHAIN_LOG}"
rustc --version --verbose > "${TOOLCHAIN_LOG}"
HOST_TARGET="$(sed -n 's/^host: //p' "${TOOLCHAIN_LOG}")"
if [ -z "${HOST_TARGET}" ]; then
  HOST_TARGET='unknown'
fi

# The summary file: invalidated now, published at the end.
#
# Facts accumulate in a private temporary file and the published path is only
# ever REPLACED, never appended to. Two properties follow, and both matter to
# the scripts downstream:
#
#   a stale summary cannot survive a failed rerun. The published file is
#   overwritten with result=in-progress right here, before anything expensive
#   runs, so a run killed hard enough that the trap never fires still leaves a
#   file that says so rather than the previous run's result=pass;
#
#   a consumer never sees half a file. check-abi.sh can legitimately be started
#   while this script is running, and rename() is the only way to guarantee it
#   reads either the whole old file or the whole new one.
if ! SUMMARY_INPROGRESS="$(mktemp "${BUILD}/rust-build-summary.txt.XXXXXX")"
then
  die "could not create a temporary summary file in ${BUILD}"
fi

printf '%s\n' \
  '# curl-urlapi-rs Rust build summary. DATA, NOT SHELL: the keys contain' \
  '# dashes and are therefore not valid shell identifiers, so this file' \
  '# cannot be sourced. Parse it with sed, the way check-abi.sh and' \
  '# run-parity.sh do. Do not act on it unless result=pass.' \
  > "${SUMMARY_INPROGRESS}"

# Append one fact to the summary, having first established that both halves are
# fit to be written. check-abi.sh and run-parity.sh are meant to read this file
# rather than re-derive any of it, so the keys are stable names and every path
# in it is absolute.
#
# THREE THINGS ARE CHECKED, and each one because the value can come from the
# environment, from a version string, from a feature list or from Cargo's own
# output, none of which this script controls:
#
#   the key must be lowercase letters, digits and dashes. A dash is not allowed
#   in a shell identifier, so a file of these keys cannot be sourced by
#   anything -- which is the point;
#
#   the value must contain no control byte. A newline would let one value forge
#   a second key on the following line, which is the whole injection; a
#   carriage return would leave an invisible trailing byte in the value a
#   consumer reads back. Both are refused rather than escaped, because no
#   legitimate value here contains one, so refusing loses nothing and escaping
#   would need a matching unescape in two other scripts;
#
#   the key must not have been written already. A repeated key is a programming
#   error here, and it matters because a consumer taking the last occurrence
#   would silently read the second one.
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
carriage return leaves an invisible byte in what a consumer reads back, and \
no legitimate value here -- a path, a feature list, a version, a digest, a \
count -- contains either"
      ;;
  esac

  SUMMARY_KEYS="${SUMMARY_KEYS}${key} "
  printf '%s=%s\n' "${key}" "${value}" >> "${SUMMARY_INPROGRESS}"
}

# Replaces the published summary with the in-progress file plus one verdict
# line, atomically.
#
#   $1  the verdict to record
publish_summary() {
  local verdict="${1}"
  local staged

  if [ -z "${SUMMARY_INPROGRESS}" ] || [ ! -f "${SUMMARY_INPROGRESS}" ]; then
    return 0
  fi

  if ! staged="$(mktemp "${BUILD}/rust-build-summary.txt.XXXXXX")"; then
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

# A run that stops part-way through must not leave behind a summary that reads
# like a finished one, because the next script along has no other way to tell.
# Every exit from here on publishes whatever RESULT holds, so the file always
# carries exactly one verdict -- and exactly one, rather than a fail appended
# after an earlier pass.
#
# The suppression below is for a known limitation of the static analyser rather
# than for a finding: this handler is installed with trap and is therefore
# invoked indirectly, which the analyser's own diagnostic says to ignore.
# shellcheck disable=SC2317
on_exit() {
  local status=$?

  publish_summary "${RESULT}" || true
  if [ -n "${SUMMARY_INPROGRESS}" ]; then
    rm -f -- "${SUMMARY_INPROGRESS}"
  fi
  return "${status}"
}
trap 'on_exit' EXIT

summary 'schema' 'curl-urlapi-rs/build-rust/1'
summary 'generated-by' 'rust-urlapi/scripts/build-rust.sh'

# Published the moment those two literal keys are in place, and no later.
#
# The ordering is the point. Everything after this line can fail -- a value
# refused for a control character, a missing artifact, a clippy finding -- and
# each of those failures has to leave a file that says so. Publishing later,
# after thirty more facts, leaves a window in which a failure inside one of
# those thirty finds the PREVIOUS run's result=pass still on disk, which is the
# staleness this whole arrangement exists to remove. Two literal keys cannot
# fail, so this is the earliest point at which the file is worth publishing and
# the latest at which it is safe to wait.
publish_summary 'in-progress' || true

# Seconds since the epoch, which is what a consumer needs to answer "is this
# summary older than the artifact it names?". Bash supplies it without an
# external command.
summary 'generated-at' "${EPOCHSECONDS:-0}"

# Which commit these artifacts were built from, so that check-abi.sh and
# run-parity.sh can refuse to pair a Rust build from one revision with a
# reference build from another. git is OPTIONAL and deliberately absent from
# the prerequisite list: this script has to work in an exported tree with no
# .git in it. Without it the fact reads unknown and the consumers say so
# instead of pretending to have checked.
SOURCE_REVISION='unknown'
if have git; then
  SOURCE_REVISION="$(git -C "${REPO_ROOT}" rev-parse HEAD 2> /dev/null ||
                     printf 'unknown')"
fi
summary 'source-revision' "${SOURCE_REVISION}"

summary 'crate' "${CRATE}"
summary 'library' "${LIBRARY}"
summary 'profile' 'release'
summary 'crate-root' "${CRATE_ROOT}"
summary 'build-root' "${BUILD}"
summary 'staging-root' "${STAGE}"
summary 'target-root' "${TARGET_ROOT}"
summary 'host-target' "${HOST_TARGET}"
summary 'rustc' "${RUSTC_VERSION}"
summary 'rustc-semver' "${RUSTC_SEMVER}"
summary 'rustc-floor' "${RUSTC_FLOOR}"
summary 'rustc-verbose' "${TOOLCHAIN_LOG}"
summary 'cargo' "${CARGO_VERSION}"
summary 'clippy' "${CLIPPY_VERSION}"
summary 'rustfmt' "${RUSTFMT_VERSION}"
summary 'libidn2' "${LIBIDN2_VERSION}"
# The flags actually in force, and which of the three variables carries them,
# so that a reader can tell the "-D warnings" promise was kept rather than
# assuming it because this script would have liked to keep it.
summary 'rustflags' "${RUSTFLAGS_EFFECTIVE}"
summary 'rustflags-source' "${RUSTFLAGS_SOURCE}"
summary 'cargo-build-rustflags' "${BUILD_RUSTFLAGS_STATE}"
summary 'locked' "${LOCKED}"
summary 'idn-backend' "${IDN_BACKEND}"
summary 'extra-features' "${EXTRA_FEATURES:-none}"
summary 'canonical-configurations' "${CANONICAL}"
summary 'msrv-declared' "${MSRV_CRATE}"
summary 'msrv-curl-docs' "${MSRV_CURL}"
summary 'msrv-idn-pure' "${MSRV_IDN_PURE}"

DROPIN_STATE='on'
if [ "${SKIP_DROPIN}" != '0' ]; then
  DROPIN_STATE='off'
  warn 'the drop-in localization pass is skipped, so the canonical archive is'
  warn 'not produced and check-abi.sh has nothing to compare; the raw Cargo'
  warn 'archive defines thousands of globals and is not a drop-in artifact'
fi
summary 'dropin-pass' "${DROPIN_STATE}"

if [ "${LOCKED}" = 'off' ]; then
  warn 'ALLOW_UPDATE is set, so --locked is dropped and Cargo may re-resolve'
  warn 'the dependency graph. Cargo.lock is committed precisely so that a'
  warn 'drift is a loud failure; this run makes no reproducibility claim.'
fi

if [ "${CANONICAL}" = 'no' ]; then
  warn 'this run does not build the two configurations acceptance criterion'
  warn 'A1 names, because the IDN backend or the feature list was changed;'
  warn 'no parity claim applies to its artifacts'
fi

# --------------------------------------------------------------------------
# Artifact helpers
# --------------------------------------------------------------------------

# Find one artifact by searching rather than by assuming a layout: the release
# directory moves under a --target triple, and a hard-coded path would report
# "missing" for something that was built perfectly well.
#
# Shallowest first, and skipping deps/ on the way, because Cargo puts the
# artifact at release/<name> and hard-links a copy into release/deps/<name>
# under a hashed sibling. The two have the same content, but the shallow one is
# the path everything else in the tree names, so it is the one reported. The
# last search drops both restrictions rather than call an artifact missing.
find_artifact() {
  local root="${1}"
  local name="${2}"
  local depth
  local found

  if [ ! -d "${root}" ]; then
    return 0
  fi

  for depth in 2 3 4 5; do
    found="$(find "${root}" -mindepth 1 -maxdepth "${depth}" -type f \
      -name "${name}" -not -path '*/deps/*' -print -quit)"
    if [ -n "${found}" ]; then
      printf '%s\n' "${found}"
      return 0
    fi
  done

  find "${root}" -maxdepth 6 -type f -name "${name}" -print -quit
}

stage_file() {
  local source="${1}"
  local destination="${2}"

  # Removed before the copy, for the reason fresh_path() gives: cp opens an
  # existing symlink's TARGET and writes through it, so a link planted at this
  # predictable staging path would send the artifact somewhere else and leave
  # the staging directory looking correct.
  fresh_path "${destination}"
  cp -p "${source}" "${destination}"
}

# The sha256 of a file, or the literal unavailable.
#
# This is the provenance every downstream consumer needs and used not to have.
# check-abi.sh reads a symbol table out of a path this summary names and
# declares the drop-in surface correct on the strength of it; run-parity.sh
# links against a path this summary names. Both run minutes or hours later,
# against a staging tree that is deliberately reusable, so "the file at the
# recorded path" and "the file this run produced" are two different claims. A
# digest is what turns the second one into something checkable.
#
#   $1  the file to digest
artifact_digest() {
  if [ ! -f "${1}" ]; then
    printf 'unavailable\n'
    return 0
  fi
  sha256sum "${1}" | awk '{ print $1 }'
}

# Removes the artifacts a mode's build is expected to produce, before it runs.
#
# WHY THIS EXISTS, because it looks like pointless work against an incremental
# build: the staging directory was already rebuilt from scratch each run, but
# the per-mode TARGET directory persisted, and find_artifact() searches it by
# name. So a build that stopped producing an artifact -- a crate-type removed
# from Cargo.toml, a feature that no longer reaches the code, a build.rs pass
# that silently did nothing -- left the previous run's file exactly where the
# search looks. The script then staged it, recorded it, and exited 0, and
# check-abi.sh went on to certify a symbol set nobody had just built.
#
# Removing them first makes the guarantee positive rather than negative: every
# artifact this script reports was created by the cargo invocation in this run,
# because nothing else could have created it. The digest recorded alongside is
# what carries that guarantee forward to the next script.
#
# Only these four exact paths are removed, never the target directory itself:
# throwing away Cargo's incremental state would turn every run into a full
# rebuild for no gain, since the state is not what could be stale here.
#
#   $1  the mode's target directory
#   $2  the mode's staging directory
clear_expected_artifacts() {
  local target_dir="${1}"
  local stage_dir="${2}"
  local name
  local found

  for name in "${ARCHIVE}" "${SHARED}" "${DROPIN}" "${NOTICE}"; do
    # Every copy under the target tree, not only the shallowest: Cargo
    # hard-links the artifact into release/deps/ under a hashed name, and
    # find_artifact() falls back to searching there, so leaving that copy in
    # place would leave exactly the staleness this is here to remove.
    while read -r found; do
      if [ -n "${found}" ]; then
        rm -f -- "${found}"
      fi
    done <<< "$(find "${target_dir}" -maxdepth 6 -type f -name "${name}" \
      2> /dev/null || true)"

    # And the staged copy, so that a mode whose build stops producing an
    # artifact cannot be read out of the staging directory either.
    fresh_path "${stage_dir}/${name}"
  done
}

# How many names the drop-in pass certified, read out of the provenance record
# it wrote rather than by running nm again here. Comparing symbol sets is
# check-abi.sh's job; this is only the count for the summary.
provenance_exports() {
  local record="${1}"
  local line

  if [ ! -f "${record}" ]; then
    printf 'unknown\n'
    return 0
  fi
  line="$(sed -n 's/^exported-symbols: //p' "${record}")"
  if [ -z "${line}" ]; then
    printf 'unknown\n'
    return 0
  fi
  printf '%s\n' "${line}" | wc -w | tr -d ' '
}

# Compose one mode's cargo arguments into the global array CARGO_ARGS: the
# leading arguments given here, then the lock setting and the feature
# selection. A global array rather than a return value because bash has no
# other way to hand an argument vector back, and building the vector element
# by element is what keeps a path with a space in it intact. The leading
# arguments are never empty, so the array is never expanded empty either.
#
#   $1 whether the manifest default features are on
#   $2 the feature list, possibly empty
#   $@ the leading arguments, at least one
compose_args() {
  local defaults="${1}"
  local features="${2}"
  shift 2

  CARGO_ARGS=("$@")
  if [ "${LOCKED}" = 'on' ]; then
    CARGO_ARGS+=(--locked)
  fi
  if [ "${defaults}" = 'off' ]; then
    CARGO_ARGS+=(--no-default-features)
  fi
  if [ -n "${features}" ]; then
    CARGO_ARGS+=(--features "${features}")
  fi
}

# --------------------------------------------------------------------------
# Record which versions a configuration actually resolved to, because a parity
# result is only reproducible if the graph behind it is written down. The
# expected answer today, verified against the committed Cargo.lock: the
# default configuration resolves libc and nothing else, one dependency; the
# optional idn-pure backend brings the internationalisation packages with it
# and lands near thirty; cbindgen appears only under genheader. Those figures
# are orientation, not a gate -- what is measured is what gets written.
#
# One trap is worth recording next to the numbers, because a naive reading of
# the registry reproduces it: asking crates.io for the newest libc reports a
# 1.0.0 pre-release, which the resolver will not select for a 0.2 requirement
# nor for a bare 1, so 0.2.189 as pinned in Cargo.toml is the correct answer
# and "use the newest shown" would produce a manifest that does not build.
#
#   $1 mode tag, $2 default features on or off, $3 feature list,
#   $4 the effective feature set, for the file's own header
# --------------------------------------------------------------------------

record_dependencies() {
  local tag="${1}"
  local defaults="${2}"
  local features="${3}"
  local effective="${4}"

  local out="${STAGE}/deps-mode-${tag}.txt"
  local raw="${STAGE}/deps-mode-${tag}.tree"
  local count='unknown'
  local source='cargo-tree'

  compose_args "${defaults}" "${features}" --prefix none
  # Both destinations are predictable paths inside the staging tree, so each is
  # cleared first rather than written through whatever may occupy it. See
  # fresh_path().
  fresh_path "${raw}"
  fresh_path "${out}"
  if cargo tree "${CARGO_ARGS[@]}" > "${raw}" 2>/dev/null; then
    # The tree marks a package it has already shown with a trailing (*), so
    # the same package appears twice in the flat listing. Strip the marker
    # before counting, then drop the crate's own root line.
    count="$(sed -e 's/ (\*)$//' -e '/^[[:space:]]*$/d' "${raw}" |
      sort -u | wc -l | tr -d ' ')"
    if [ "${count}" -gt 0 ]; then
      count=$((count - 1))
    fi
  else
    # Cargo.lock is committed, so reading it always works even when cargo
    # tree does not. It records the union over every feature rather than this
    # configuration's own graph, which the header below says out loud.
    source='cargo-lock'
    if [ -f "${CRATE_ROOT}/Cargo.lock" ]; then
      # grep -c exits non-zero on a count of zero, which set -e would take as
      # a failure, so the status is discarded and the printed count kept.
      count="$(grep -c '^\[\[package\]\]' "${CRATE_ROOT}/Cargo.lock" || true)"
      if [ -z "${count}" ]; then
        count='0'
      fi
      if [ "${count}" -gt 0 ]; then
        count=$((count - 1))
      fi
      cp "${CRATE_ROOT}/Cargo.lock" "${raw}"
    else
      count='unknown'
      : > "${raw}"
    fi
  fi

  {
    printf '# %s dependency resolution, mode %s\n' "${CRATE}" "${tag}"
    printf '# effective features: %s\n' "${effective}"
    printf '# default features: %s\n' "${defaults}"
    printf '# lockfile honoured (--locked): %s\n' "${LOCKED}"
    printf '# source: %s\n' "${source}"
    if [ "${source}" = 'cargo-lock' ]; then
      printf '# cargo tree was unavailable, so this is Cargo.lock, which\n'
      printf '# covers every feature rather than this configuration alone\n'
    fi
    printf '# dependencies, excluding the crate itself: %s\n' "${count}"
    printf '# rustc: %s\n' "${RUSTC_VERSION}"
    printf '# cargo: %s\n' "${CARGO_VERSION}"
    printf '# libidn2: %s\n' "${LIBIDN2_VERSION}"
    printf '#\n'
    cat "${raw}"
  } > "${out}"
  rm -f "${raw}"

  say "deps:      ${count} (${source}), recorded in ${out}"
  summary "mode-${tag}-dependencies" "${count}"
  summary "mode-${tag}-dependency-source" "${source}"
  summary "mode-${tag}-dependency-log" "${out}"
}

# --------------------------------------------------------------------------
# One configuration, end to end: build, drop-in localization, staging,
# dependency record and clippy.
#
#   $1 mode tag, a, b or c
#   $2 label for the caller
#   $3 whether the manifest default features are on
#   $4 the feature list to pass to --features, possibly empty
#   $5 the effective feature set, for the record
#   $6 the shared object's contract in this configuration: 'closed' when the
#      crate is self-contained and build.rs proved the cdylib link with
#      -Wl,-z,defs, or 'imports-scheme-provider' when it references the two
#      libcurl-private scheme entry points instead
# --------------------------------------------------------------------------

build_mode() {
  local tag="${1}"
  local label="${2}"
  local defaults="${3}"
  local features="${4}"
  local effective="${5}"
  local shared_contract="${6}"

  local upper="${tag}"
  upper="${upper^^}"

  local target_dir="${TARGET_ROOT}/mode-${tag}"
  local stage="${STAGE}/mode-${tag}"
  local build_log="${STAGE}/build-mode-${tag}.log"
  local dropin_log="${STAGE}/dropin-mode-${tag}.log"
  local clippy_log="${STAGE}/clippy-mode-${tag}.log"

  step "Mode ${upper}, ${label}"
  say "features:  ${effective}"
  say "target:    ${target_dir}"
  say "staging:   ${stage}"

  # A stale artifact from an earlier run in a different configuration would
  # mislead every reader of this directory, so the staging directory is
  # rebuilt rather than added to. Only this one path is removed, and the :?
  # makes an empty variable stop the removal rather than widen it.
  rm -rf "${stage:?}"
  mkdir -p "${stage}"

  # And the artifacts inside the persistent target directory, which the
  # staging rebuild above never reached. See clear_expected_artifacts() for
  # why an incremental build is not enough on its own.
  clear_expected_artifacts "${target_dir}" "${stage}"

  fresh_path "${build_log}"
  : > "${build_log}"

  summary "mode-${tag}-label" "${label}"
  summary "mode-${tag}-default-features" "${defaults}"
  summary "mode-${tag}-features" "${features:-none}"
  summary "mode-${tag}-effective-features" "${effective}"
  summary "mode-${tag}-target-dir" "${target_dir}"
  summary "mode-${tag}-staging-dir" "${stage}"
  summary "mode-${tag}-build-log" "${build_log}"

  compose_args "${defaults}" "${features}" --release
  if ! run_logged "${build_log}" cargo build "${CARGO_ARGS[@]}" \
      --target-dir "${target_dir}"; then
    die "mode ${upper} did not build; see ${build_log}"
  fi

  local archive
  archive="$(find_artifact "${target_dir}" "${ARCHIVE}")"
  if [ -z "${archive}" ]; then
    die "mode ${upper} produced no ${ARCHIVE} under ${target_dir}, which the
 staticlib crate type is supposed to guarantee"
  fi
  say "archive:   ${archive}"

  # Staged before the localization pass runs, so that what lands here is
  # exactly the archive that pass validated: the pass re-links the staticlib
  # afterwards, and a copy taken later would be a different build of the same
  # source rather than the certified input.
  stage_file "${archive}" "${stage}/${ARCHIVE}"
  summary "mode-${tag}-archive" "${stage}/${ARCHIVE}"
  summary "mode-${tag}-archive-sha256" \
    "$(artifact_digest "${stage}/${ARCHIVE}")"

  # The shared object is staged in EVERY configuration, and required in every
  # one, because check-abi.sh asserts its dynamic export set in every one --
  # eight names where strerror and cfree are off, ten where they are on. What
  # differs between configurations is the object's IMPORT contract, which is
  # what $6 records:
  #
  #   closed                    build.rs put -Wl,-z,defs on the cdylib link,
  #                             so the object has no unresolved strong
  #                             reference and loads under dlopen.
  #   imports-scheme-provider   scheme-table is off, so the object references
  #                             Curl_get_scheme and Curl_getn_scheme, which
  #                             are libcurl-private (lib/url.h:76-77) and
  #                             resolve only in a link where url.c.o takes
  #                             part. Two names, where lib/urlapi.o itself
  #                             leaves seventeen curl_/Curl_ names to the
  #                             link. build.rs records the contract in a
  #                             notice rather than failing the link, the
  #                             notice is staged beside the object, and
  #                             check-abi.sh asserts both halves of it.
  local shared
  shared="$(find_artifact "${target_dir}" "${SHARED}")"
  if [ -z "${shared}" ]; then
    die "mode ${upper} produced no ${SHARED} under ${target_dir}, which the
 cdylib crate type is supposed to guarantee"
  fi
  stage_file "${shared}" "${stage}/${SHARED}"
  summary "mode-${tag}-shared-object" "${stage}/${SHARED}"
  summary "mode-${tag}-shared-object-sha256" \
    "$(artifact_digest "${stage}/${SHARED}")"
  summary "mode-${tag}-shared-contract" "${shared_contract}"
  say "shared:    ${stage}/${SHARED} (${shared_contract})"

  if [ "${shared_contract}" = 'closed' ]; then
    summary "mode-${tag}-shared-object-notice" 'not-applicable'
  else
    local notice
    notice="$(find_artifact "${target_dir}" "${NOTICE}")"
    if [ -n "${notice}" ]; then
      stage_file "${notice}" "${stage}/${NOTICE}"
      summary "mode-${tag}-shared-object-notice" "${stage}/${NOTICE}"
    else
      # build.rs writes the notice on every release build of this
      # configuration on an ELF target, so its absence means either a target
      # whose linker has no -z defs equivalent or a build.rs that stopped
      # writing it. Reported rather than passed over, and not fatal, because
      # the artifact itself is unaffected and check-abi.sh asserts the
      # contract from the object.
      summary "mode-${tag}-shared-object-notice" 'not-found'
      warn "mode ${upper} produced no ${NOTICE}; build.rs writes one on every"
      warn 'release build of this configuration on an ELF target. The import'
      warn 'contract is asserted from the object itself by check-abi.sh, so'
      warn 'the run continues.'
    fi
  fi

  # The drop-in localization pass, and the reason this script exists as a
  # driver rather than as two commands in a README: Cargo has no post-build
  # hook, so build.rs cannot post-process an archive that does not exist until
  # after it has run. The second invocation names the archive through
  # CURL_URLAPI_DROPIN_ARCHIVE and asks for the staticlib alone, so nothing
  # else is re-linked. CURL_URLAPI_DROPIN_OUTPUT puts the canonical artifact
  # straight into the staging directory, which is also where build.rs writes
  # the provenance record beside it.
  #
  # The feature arguments are deliberately the same ones the build above used:
  # build.rs validates the raw archive against the feature set it was told,
  # and refuses a pairing that does not match, which is what stops a
  # default-feature archive from being certified as a drop-in one.
  local dropin="${stage}/${DROPIN}"
  local provenance="${dropin}.provenance"
  if [ "${SKIP_DROPIN}" = '0' ]; then
    fresh_path "${dropin_log}"
    : > "${dropin_log}"
    compose_args "${defaults}" "${features}" --release
    if ! run_logged "${dropin_log}" \
        env "CURL_URLAPI_DROPIN_ARCHIVE=${archive}" \
            "CURL_URLAPI_DROPIN_OUTPUT=${dropin}" \
        cargo rustc "${CARGO_ARGS[@]}" --target-dir "${target_dir}" \
          --lib --crate-type staticlib; then
      die "the drop-in localization pass failed for mode ${upper}; see
 ${dropin_log}"
    fi
    if [ ! -f "${dropin}" ]; then
      die "the drop-in localization pass reported success but ${dropin} is
 not there"
    fi
    local exports
    exports="$(provenance_exports "${provenance}")"
    say "drop-in:   ${dropin} (${exports} exported globals)"
    summary "mode-${tag}-dropin-archive" "${dropin}"
    summary "mode-${tag}-dropin-archive-sha256" \
      "$(artifact_digest "${dropin}")"
    summary "mode-${tag}-dropin-provenance" "${provenance}"
    summary "mode-${tag}-dropin-exports" "${exports}"
    summary "mode-${tag}-dropin-log" "${dropin_log}"
  else
    summary "mode-${tag}-dropin-archive" 'not-produced'
    summary "mode-${tag}-dropin-archive-sha256" 'not-produced'
    summary "mode-${tag}-dropin-provenance" 'not-produced'
    summary "mode-${tag}-dropin-exports" 'not-measured'
  fi

  record_dependencies "${tag}" "${defaults}" "${features}" "${effective}"

  # clippy in its own target directory: sharing one with the build would have
  # each invalidate the other's fingerprints, so every repeat run would
  # recompile everything twice. --all-targets is the part that matters, since
  # it brings the integration tests under tests/ into the check as well as the
  # library. No profile flag, because a lint finding does not depend on one.
  step "Mode ${upper}, clippy"
  fresh_path "${clippy_log}"
  : > "${clippy_log}"
  compose_args "${defaults}" "${features}" --all-targets
  if ! run_logged "${clippy_log}" cargo clippy "${CARGO_ARGS[@]}" \
      --target-dir "${TARGET_ROOT}/clippy-${tag}" -- -D warnings; then
    summary "mode-${tag}-clippy" 'fail'
    summary "mode-${tag}-clippy-log" "${clippy_log}"
    die "clippy reported findings for mode ${upper}; see ${clippy_log}. Fix
 them in the crate: no lint is ever silenced from this script, because
 src/lib.rs denies the panicking constructs on purpose."
  fi
  say 'clippy:    no findings'
  summary "mode-${tag}-clippy" 'pass'
  summary "mode-${tag}-clippy-log" "${clippy_log}"
}

# --------------------------------------------------------------------------
# The three configurations, in that order. Mode A first because it is the one
# that has to be linkable in place of lib/urlapi.o and therefore the one whose
# failure matters most; mode B second because it needs nothing from libcurl and
# so can only fail for reasons of its own; mode C last because it is mode A's
# feature set plus one feature and a failure there is read against mode A.
# --------------------------------------------------------------------------

MODE_A_FEATURES="${BACKEND_FEATURE}"
if [ -n "${EXTRA_FEATURES}" ]; then
  if [ -n "${MODE_A_FEATURES}" ]; then
    MODE_A_FEATURES="${MODE_A_FEATURES},${EXTRA_FEATURES}"
  else
    MODE_A_FEATURES="${EXTRA_FEATURES}"
  fi
fi

MODE_A_EFFECTIVE="${MODE_A_FEATURES}"
if [ -z "${MODE_A_EFFECTIVE}" ]; then
  # No feature at all, which is a deliberate configuration rather than an
  # oversight: with no IDN backend the crate reproduces what the C does with
  # USE_IDN undefined, returning CURLUE_LACKS_IDN from host encode and decode.
  MODE_A_EFFECTIVE='none, host encode and decode return CURLUE_LACKS_IDN'
fi

# Mode B is the manifest default when the backend is the default one, which
# keeps the command exactly the `cargo build --release` acceptance criterion A1
# names. Any other backend has to be spelled out, because Cargo features are
# additive and there is no way to subtract idn-libidn2 from the default set.
MODE_B_DEFAULTS='on'
MODE_B_FEATURES="${EXTRA_FEATURES}"
MODE_B_EFFECTIVE="${STANDALONE_FEATURES},idn-libidn2"
if [ "${IDN_BACKEND}" != 'libidn2' ]; then
  MODE_B_DEFAULTS='off'
  MODE_B_FEATURES="${STANDALONE_FEATURES}"
  if [ -n "${BACKEND_FEATURE}" ]; then
    MODE_B_FEATURES="${MODE_B_FEATURES},${BACKEND_FEATURE}"
  fi
  if [ -n "${EXTRA_FEATURES}" ]; then
    MODE_B_FEATURES="${MODE_B_FEATURES},${EXTRA_FEATURES}"
  fi
  MODE_B_EFFECTIVE="${MODE_B_FEATURES}"
elif [ -n "${EXTRA_FEATURES}" ]; then
  MODE_B_EFFECTIVE="${MODE_B_EFFECTIVE},${EXTRA_FEATURES}"
fi

# Mode C is mode A plus scheme-table and nothing else, so it is derived from
# mode A's feature list rather than assembled again. That is deliberate: the
# two must differ by exactly one feature, or the shared object it produces
# would not be the shared form of the same drop-in surface.
MODE_C_FEATURES='scheme-table'
if [ -n "${MODE_A_FEATURES}" ]; then
  MODE_C_FEATURES="${MODE_A_FEATURES},scheme-table"
fi
MODE_C_EFFECTIVE="${MODE_C_FEATURES}"

build_mode 'a' 'static drop-in, replaces lib/urlapi.o inside a real libcurl' \
  'off' "${MODE_A_FEATURES}" "${MODE_A_EFFECTIVE}" 'imports-scheme-provider'

build_mode 'b' 'standalone, needs no libcurl at all' \
  "${MODE_B_DEFAULTS}" "${MODE_B_FEATURES}" "${MODE_B_EFFECTIVE}" 'closed'

build_mode 'c' 'shared drop-in, the closed eight-export shared object' \
  'off' "${MODE_C_FEATURES}" "${MODE_C_EFFECTIVE}" 'closed'

# --------------------------------------------------------------------------
# Formatting. Reported rather than enforced by default, because a formatting
# difference is not a defect in the artifact, and --strict-fmt is there for
# anyone who wants it to be a failure. rustfmt is one of the components
# rust-toolchain.toml asks for, so a correctly provisioned toolchain has it.
# --------------------------------------------------------------------------

FMT_STATE='skipped'
if [ "${RUSTFMT_VERSION}" != 'absent' ]; then
  step 'Formatting'
  FMT_LOG="${STAGE}/fmt-check.log"
  fresh_path "${FMT_LOG}"
  : > "${FMT_LOG}"
  if run_logged "${FMT_LOG}" cargo fmt --check; then
    FMT_STATE='pass'
    say 'rustfmt:   no differences'
  else
    FMT_STATE='differs'
    if [ "${STRICT_FMT}" != '0' ]; then
      summary 'fmt-check' 'differs'
      summary 'fmt-check-log' "${FMT_LOG}"
      die "rustfmt reports differences and --strict-fmt was given; run
 cargo fmt to apply them, or drop --strict-fmt to have them reported"
    fi
    warn "rustfmt reports differences; see ${FMT_LOG}. They do not affect the"
    warn 'artifacts, so the run continues. Pass --strict-fmt to make this a'
    warn 'failure, or run cargo fmt to apply them.'
  fi
  summary 'fmt-check-log' "${FMT_LOG}"
fi
summary 'fmt-check' "${FMT_STATE}"

# --------------------------------------------------------------------------
# The optional cargo-c packaging path.
#
# PACKAGING SUPPORT ONLY. It produces the artifacts a C consumer expects -- an
# archive, a shared object, a pkg-config file and a header -- in one step, and
# installs them where it is told. It wires nothing into curl's own build
# system, and this script must not either: pointing lib/Makefile.inc or
# CMakeLists.txt at a cargo-c artifact is resolved as out of scope, because
# "no other part of curl is modified" is a definition of success while that
# wiring is explicitly not the deliverable. Nothing here writes to
# lib/Makefile.inc, CMakeLists.txt, Makefile.am, configure.ac or m4/.
#
# Any install stays inside build/, never in a system prefix and never anywhere
# else in the repository, so a run of this script still adds nothing to the
# working tree outside target/ and build/.
#
# Held in reserve and deliberately not implemented here: for a build system
# that takes a single relocatable object rather than an archive, ld -r turns
# the archive into one .o. build.rs already uses that step as part of the
# drop-in localization pass, so the technique is available where it is needed
# and does not need a second home in this script.
#
# THE VERDICT DEPENDS ON WHETHER THE PATH WAS ASKED FOR. Not asking for it is
# the ordinary case and its absence is not a failure -- no acceptance criterion
# at 0.9.2 runs it, and everything it would install is obtainable from the two
# builds above plus the committed include/curl_urlapi_rs.h. Asking for it with
# --capi or WITH_CAPI=1 is a different statement: the caller wants those
# artifacts, so a run that does not produce them has not done what it was
# asked, whatever the reason. Both of the two non-completing outcomes below --
# cargo-c not installed, and the recorded capi-feature constraint -- therefore
# fail an explicitly requested run while still being reported for what they
# are. An earlier version recorded them and then wrote result=pass regardless,
# which told a reader the packaging path had succeeded when it had not run at
# all.
# --------------------------------------------------------------------------

CAPI_STATE='off'
if [ "${WITH_CAPI}" != '0' ]; then
  step 'cargo-c packaging path'
  CAPI_LOG="${STAGE}/capi.log"
  CAPI_PREFIX="${BUILD}/capi"
  fresh_path "${CAPI_LOG}"
  : > "${CAPI_LOG}"
  summary 'capi-log' "${CAPI_LOG}"
  summary 'capi-prefix' "${CAPI_PREFIX}"

  if ! have cargo-capi; then
    # Explicitly requested and not installable from here, so the request
    # fails. --capi is off by default; an ordinary run never reaches this.
    CAPI_STATE='unavailable'
    summary 'capi' "${CAPI_STATE}"
    # The version is pinned and --locked is passed, because everything this
    # script documents about the path -- the exact failure text it matches
    # below, and the cargo-c-0.10.24/src/build.rs line numbers the reported
    # constraint cites -- was measured against 0.10.24 and nothing else.
    die "--capi was given but cargo-c is not installed, so no package can be
 produced. Install it with: cargo install --locked cargo-c@0.10.24. Drop
 --capi to build the three configurations without the packaging path, which
 is what every acceptance criterion at 0.9.2 actually runs."
  else
    mkdir -p "${CAPI_PREFIX}"
    compose_args "${MODE_B_DEFAULTS}" "${MODE_B_FEATURES}" --release
    # Not run through run_logged, because one of the two failures here is
    # expected and printing a failure tail for it would read as a defect.
    printf '+ cargo cbuild %s\n' "${CARGO_ARGS[*]}" >> "${CAPI_LOG}"
    if cargo cbuild "${CARGO_ARGS[@]}" \
        --target-dir "${TARGET_ROOT}/capi" >> "${CAPI_LOG}" 2>&1; then
      if run_logged "${CAPI_LOG}" cargo cinstall "${CARGO_ARGS[@]}" \
          --target-dir "${TARGET_ROOT}/capi" --prefix "${CAPI_PREFIX}"; then
        CAPI_STATE='pass'
        say "cargo-c:   installed under ${CAPI_PREFIX}"
      else
        die "cargo cinstall failed; see ${CAPI_LOG}"
      fi
    elif grep -qE 'does not contain this feature: [^a-z]*capi' \
        "${CAPI_LOG}"; then
      # The one failure that is a recorded constraint rather than a defect.
      # cargo-c appends --features capi to every invocation and treats a
      # package as C-API-relevant only when that feature is declared, and
      # Cargo.toml declares the six features the plan tables and no seventh.
      # The pattern above allows for the way the feature name is quoted
      # changing between versions: 0.10.24 renders it bare inside a debug
      # dump of the error, while Cargo's own message carries backticks.
      # The remedy is one line, capi = [], and it is deliberately not taken.
      # No acceptance criterion runs this path, so the constraint is reported
      # and the run is not failed by it. What it costs is bounded but not
      # nothing, and the difference is stated rather than rounded off: the
      # archive, the shared object and the header are all reachable without
      # cargo-c -- the two builds above produce the first two and include/
      # carries the third -- but the pkg-config file is NOT. No other route in
      # this crate emits one, and none is added, because a hand-written .pc
      # would have to be kept in step with a packaging path that does not run.
      CAPI_STATE='blocked'
      summary 'capi' "${CAPI_STATE}"
      # A reported constraint, and STILL a failure of this invocation. The
      # distinction matters and is worth stating: the constraint is why the
      # path cannot run, not a licence to report a successful run that
      # installed nothing. --capi is an explicit request for a package; when
      # no package can be produced, the request failed. Nothing else in this
      # script is affected, which is why the exit happens here rather than
      # being folded into the overall verdict: the three builds above have
      # already completed and their artifacts are staged and usable.
      die "--capi was given, but the cargo-c packaging path cannot run on this
 manifest and no package was produced. cargo-c appends --features capi to
 every invocation and treats a package as C-API-relevant only when that
 feature is declared, and Cargo.toml declares the six features the plan
 freezes at 0.3.1.1 and no seventh. The remedy is one line, capi = [], and it
 is deliberately not taken. See docs/KNOWN-DIVERGENCES.md, \"Reported
 constraint: cargo-c and the capi feature\". Drop --capi to build without the
 packaging path: no acceptance criterion at 0.9.2 runs it, and everything it
 would install is available from the three builds above plus the committed
 include/curl_urlapi_rs.h. Full output: ${CAPI_LOG}"
    else
      tail -n 40 "${CAPI_LOG}" >&2
      die "cargo cbuild failed for a reason other than the recorded capi
 constraint; see ${CAPI_LOG}"
    fi
  fi
fi
summary 'capi' "${CAPI_STATE}"
summary 'capi-requested' "$([ "${WITH_CAPI}" != '0' ] && printf 'yes' ||
  printf 'no')"
summary 'constraint-r1' 'reported'

# Everything that can fail has now run, so the verdict is settled. Recorded
# here and nowhere else: publish_summary() is the only writer of the result
# line, so the file carries exactly one verdict rather than a fail appended
# after an earlier pass, and the trap installed above publishes whatever this
# assignment left behind.

# Everything that can fail has now run, so the verdict is settled -- except for
# the one outcome that is a failure only because it was asked for. An
# explicitly requested packaging path that did not complete fails the run: the
# trap installed above appends result=fail, and the non-zero exit is what a
# Makefile or a CI step reads.
case "${CAPI_STATE}" in
  unavailable|blocked)
    die "the cargo-c packaging path was requested with --capi but ended \
'${CAPI_STATE}', so it produced none of the artifacts it was asked for. The \
two canonical configurations above built and linted clean and their artifacts \
are in ${STAGE}; rerun without --capi if the packaging path is not needed. \
See ${CAPI_LOG:-the capi log under ${STAGE}}"
    ;;
esac

RESULT='pass'

# Published here as well as from the trap, so that the listing below shows the
# finished file rather than the in-progress one this run published at startup.
# Publishing twice is idempotent -- the same facts and the same verdict -- and
# the trap remains the guarantee that SOME verdict reaches the file on every
# exit path, including the ones that never get here.
publish_summary "${RESULT}" || die "could not publish ${SUMMARY}"

# --------------------------------------------------------------------------
# What was built, and the constraints this script sits next to. The
# constraints are reported and never remedied: each one would need an edit
# outside this directory, and reporting them is the instruction.
# --------------------------------------------------------------------------

step 'Summary'
say "written to ${SUMMARY}"
say ''
while IFS= read -r line; do
  say "  ${line}"
done < "${SUMMARY}"

step 'Reported constraints, not remedied here'
say ''
say 'R1, the distribution check will report these files as missing.'
say '    .github/workflows/distcheck.yml runs the missing-files job on every'
say '    push to the default branch and every pull request against it, with no'
say '    path filter, and that job runs .github/scripts/distfiles.sh, which'
say '    compares git ls-files against the release tarball minus a fixed'
say '    literal exception list. No entry in that list can match rust-urlapi/,'
say '    so committing this directory makes the job fail. The only remedies'
say '    edit Makefile.am, either EXTRA_DIST at line 67 or the distributed'
say '    subdirectory lists at lines 73 and 74, and Makefile.am is out of'
say '    scope. That edit is deliberately not made, here or anywhere else.'

if [ "${IDN_BACKEND}" = 'pure' ]; then
  say ''
  say 'THE idn-pure BACKEND IS NOT BIT-FOR-BIT COMPATIBLE.'
  say '    It has no equivalent of libidn2 retrying the lookup with the'
  say '    transitional flag after a failure; it is locale-independent where'
  say '    the C path is locale-sensitive, so it succeeds on non-ASCII names'
  say '    under a codeset the C path fails on; it uses different Unicode'
  say '    tables; it adds around thirty dependencies to the one the default'
  say "    configuration has; and it needs rustc ${MSRV_IDN_PURE}, above this"
  say "    crate's declared ${MSRV_CRATE} and curl's own ${MSRV_CURL}. That is"
  say '    why it is not the default. Parity claims apply to the libidn2'
  say '    backend only. See docs/KNOWN-DIVERGENCES.md, "Residual divergence:'
  say '    the idn-pure backend".'
fi

step 'Done'
for tag in a b c; do
  say "mode ${tag^^} archive:  ${STAGE}/mode-${tag}/${ARCHIVE}"
  if [ "${DROPIN_STATE}" = 'on' ]; then
    say "mode ${tag^^} drop-in:  ${STAGE}/mode-${tag}/${DROPIN}"
  fi
  say "mode ${tag^^} shared:   ${STAGE}/mode-${tag}/${SHARED}"
done
say ''
say 'The two configurations acceptance criterion A1 names -- mode A and mode'
say 'B -- built with no compiler warning and no clippy finding, and so did'
say 'mode C, the shared drop-in. The G1 pair is the mode A drop-in archive and'
say 'the mode C shared object: one archive and one shared object from a single'
say 'crate, each exporting exactly the eight names lib/urlapi.o defines.'
say 'check-abi.sh asserts those symbol sets next, and run-parity.sh links and'
say 'runs the harness and the demonstration program.'
