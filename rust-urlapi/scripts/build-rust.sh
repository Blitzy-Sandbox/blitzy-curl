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
# MODE A, the drop-in configuration:
#
#   cargo build --release --no-default-features --features idn-libidn2
#
# strerror, cfree and scheme-table are all OFF here, because a real libcurl
# already defines curl_url_strerror (lib/strerror.c:420) and curl_free
# (lib/escape.c:189), and because src/scheme.rs is to consult libcurl's own
# Curl_get_scheme (lib/url.c:1469-1471) rather than a table of its own. The
# deliverable is the archive. A shared object built in this configuration is
# NOT a deliverable: it comes out with the two libcurl-private scheme symbols
# undefined and no libcurl NEEDED entry, so it fails at dlopen every time. See
# docs/KNOWN-DIVERGENCES.md, "Integration limitation: the shared object exists
# in one configuration only".
#
# MODE B, the standalone configuration:
#
#   cargo build --release
#
# The default features, so the crate also supplies curl_url_strerror,
# curl_free and a built-in scheme table and needs no libcurl at all. Both the
# archive and the shared object are deliverables here.
#
# Those two commands are the two configurations acceptance criterion A1 names,
# and they are issued verbatim unless --idn-backend asks for something else.
#
# Both configurations write to target/release, so each is built into its own
# target directory and its artifacts are copied to a mode-tagged place under
# build/ as soon as they exist. check-abi.sh and run-parity.sh need the two
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
#   build/rust/mode-b/libcurl_urlapi_rs.a          Cargo's archive
#   build/rust/mode-b/libcurl_urlapi_rs_dropin.a   canonical, 10 globals
#   build/rust/mode-b/libcurl_urlapi_rs_dropin.a.provenance
#   build/rust/mode-b/libcurl_urlapi_rs.so         shared deliverable
#   build/rust/deps-mode-a.txt, deps-mode-b.txt    resolved dependencies
#   build/rust/*.log                               one log per step
#   build/rust-build-summary.txt                   key=value summary
#
# Nothing tracked by git is written: --locked keeps Cargo.lock as it is, and
# the mirror header under include/ is only ever regenerated when somebody asks
# for the genheader feature and sets CURL_URLAPI_WRITE_MIRROR_HEADER, which
# this script refuses to pass on.

set -eu

# Run from the crate root whatever directory the caller was in, so that
# rust-toolchain.toml applies to every cargo command below without any of them
# naming a toolchain, and so relative paths in the summary mean one thing.
cd "$(dirname "${0}")"/..

CRATE_ROOT="${PWD}"
BUILD="${PWD}/build"
STAGE="${BUILD}/rust"
SUMMARY="${BUILD}/rust-build-summary.txt"

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

Builds curl-urlapi-rs twice, in the drop-in configuration and in the
standalone configuration, runs the drop-in localization pass over each
archive, checks both configurations with clippy, records the resolved
dependencies and writes build/rust-build-summary.txt.

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
                          curl's own build system
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
  CARGO_TARGET_DIR=...    the parent of the two per-mode target directories

Exit status is 0 only when both configurations built with no compiler warning
and no clippy finding, and every expected artifact was produced.
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

# libidn2 is only a prerequisite when the backend that binds it is selected.
# build.rs emits the link request for it and reads its header for the two
# version constants lib/idn.c compares against, so a missing one fails the
# build late and confusingly rather than here.
LIBIDN2_VERSION='not-required'
if [ "${IDN_BACKEND}" = 'libidn2' ]; then
  if ! have pkg-config; then
    LIBIDN2_VERSION='unknown'
    missing 'pkg-config, used to locate libidn2' \
      'apt-get install pkg-config' \
      'or point CURL_URLAPI_IDN2_H at idn2.h for build.rs to read'
  elif pkg-config --exists libidn2; then
    LIBIDN2_VERSION="$(pkg-config --modversion libidn2)"
    say "libidn2: ${LIBIDN2_VERSION}"
  else
    LIBIDN2_VERSION='absent'
    missing 'libidn2 development files' \
      'apt-get install libidn2-dev, the package linux.yml:76 installs' \
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
if [ -n "${RUSTFLAGS:-}" ]; then
  RUSTFLAGS="${RUSTFLAGS} -D warnings"
else
  RUSTFLAGS='-D warnings'
fi
export RUSTFLAGS

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

TARGET_ROOT="${CARGO_TARGET_DIR:-${CRATE_ROOT}/target}"
TOOLCHAIN_LOG="${STAGE}/toolchain.txt"
rustc --version --verbose > "${TOOLCHAIN_LOG}"
HOST_TARGET="$(sed -n 's/^host: //p' "${TOOLCHAIN_LOG}")"
if [ -z "${HOST_TARGET}" ]; then
  HOST_TARGET='unknown'
fi

: > "${SUMMARY}"

# Append one fact to the summary. check-abi.sh and run-parity.sh are meant to
# read this file rather than re-derive any of it, so the keys are stable names
# and every path in it is absolute.
summary() {
  printf '%s=%s\n' "${1}" "${2}" >> "${SUMMARY}"
}

# A run that stops part-way through must not leave behind a summary that reads
# like a finished one, because the next script along has no other way to tell.
# Every exit from here on appends result=fail unless a pass has been recorded,
# so the file always ends with one verdict or the other.
RESULT='fail'
mark_result() {
  if [ "${RESULT}" != 'pass' ]; then
    printf 'result=fail\n' >> "${SUMMARY}"
  fi
}
trap 'mark_result' EXIT

summary 'schema' 'curl-urlapi-rs/build-rust/1'
summary 'generated-by' 'rust-urlapi/scripts/build-rust.sh'
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
summary 'rustflags' "${RUSTFLAGS}"
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

  cp -p "${source}" "${destination}"
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
#   $1 mode tag, a or b
#   $2 label for the caller
#   $3 whether the manifest default features are on
#   $4 the feature list to pass to --features, possibly empty
#   $5 the effective feature set, for the record
#   $6 whether a shared object is a deliverable in this configuration
# --------------------------------------------------------------------------

build_mode() {
  local tag="${1}"
  local label="${2}"
  local defaults="${3}"
  local features="${4}"
  local effective="${5}"
  local wants_shared="${6}"

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

  local shared
  shared="$(find_artifact "${target_dir}" "${SHARED}")"
  if [ "${wants_shared}" = 'yes' ]; then
    if [ -z "${shared}" ]; then
      die "mode ${upper} produced no ${SHARED} under ${target_dir}, and the
 shared object is a deliverable in this configuration"
    fi
    stage_file "${shared}" "${stage}/${SHARED}"
    summary "mode-${tag}-shared-object" "${stage}/${SHARED}"
    say "shared:    ${stage}/${SHARED}"
  else
    # Not an omission and not a failure. With scheme-table off the crate
    # imports libcurl's own Curl_get_scheme and Curl_getn_scheme, which are
    # libcurl-private and never reach a shared libcurl's dynamic symbol
    # table, so a shared object built here cannot load. build.rs records that
    # in a notice instead of failing the link, and the notice is staged here
    # as the evidence for it.
    summary "mode-${tag}-shared-object" 'not-a-deliverable'
    say 'shared:    not a deliverable in this configuration'
    local notice
    notice="$(find_artifact "${target_dir}" "${NOTICE}")"
    if [ -n "${notice}" ]; then
      stage_file "${notice}" "${stage}/${NOTICE}"
      summary "mode-${tag}-shared-object-notice" "${stage}/${NOTICE}"
    else
      summary "mode-${tag}-shared-object-notice" 'not-found'
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
    summary "mode-${tag}-dropin-provenance" "${provenance}"
    summary "mode-${tag}-dropin-exports" "${exports}"
    summary "mode-${tag}-dropin-log" "${dropin_log}"
  else
    summary "mode-${tag}-dropin-archive" 'not-produced'
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
# The two configurations, in that order. Mode A first because it is the one
# that has to be linkable in place of lib/urlapi.o and therefore the one whose
# failure matters most; mode B second because it needs nothing from libcurl and
# so can only fail for reasons of its own.
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

build_mode 'a' 'drop-in, replaces lib/urlapi.o inside a real libcurl' \
  'off' "${MODE_A_FEATURES}" "${MODE_A_EFFECTIVE}" 'no'

build_mode 'b' 'standalone, needs no libcurl at all' \
  "${MODE_B_DEFAULTS}" "${MODE_B_FEATURES}" "${MODE_B_EFFECTIVE}" 'yes'

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
# --------------------------------------------------------------------------

CAPI_STATE='off'
if [ "${WITH_CAPI}" != '0' ]; then
  step 'cargo-c packaging path'
  CAPI_LOG="${STAGE}/capi.log"
  CAPI_PREFIX="${BUILD}/capi"
  : > "${CAPI_LOG}"
  summary 'capi-log' "${CAPI_LOG}"
  summary 'capi-prefix' "${CAPI_PREFIX}"

  if ! have cargo-capi; then
    CAPI_STATE='unavailable'
    say 'cargo-c is not installed, so the packaging path is skipped.'
    say 'Install it with: cargo install cargo-c'
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
      # No acceptance criterion runs this path, and everything it would
      # install is obtainable from the two builds above plus the committed
      # header under include/, so the constraint is reported and the run is
      # not failed by it.
      CAPI_STATE='blocked'
      warn 'the cargo-c path is blocked, and this is a reported constraint'
      warn 'rather than a defect: cargo-c requires a declared capi feature'
      warn 'which Cargo.toml deliberately does not have. See'
      warn 'docs/KNOWN-DIVERGENCES.md, "Reported constraint: cargo-c and the'
      warn 'capi feature". Everything that path would install is available'
      warn 'from the two builds above and include/curl_urlapi_rs.h.'
    else
      tail -n 40 "${CAPI_LOG}" >&2
      die "cargo cbuild failed for a reason other than the recorded capi
 constraint; see ${CAPI_LOG}"
    fi
  fi
fi
summary 'capi' "${CAPI_STATE}"
summary 'constraint-r1' 'reported'

# Everything that can fail has now run, so the verdict is settled and the trap
# installed above has nothing left to record.
RESULT='pass'
summary 'result' 'pass'

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
say "mode A archive:  ${STAGE}/mode-a/${ARCHIVE}"
if [ "${DROPIN_STATE}" = 'on' ]; then
  say "mode A drop-in:  ${STAGE}/mode-a/${DROPIN}"
fi
say "mode B archive:  ${STAGE}/mode-b/${ARCHIVE}"
if [ "${DROPIN_STATE}" = 'on' ]; then
  say "mode B drop-in:  ${STAGE}/mode-b/${DROPIN}"
fi
say "mode B shared:   ${STAGE}/mode-b/${SHARED}"
say ''
say 'Both configurations built with no compiler warning and no clippy'
say 'finding, which is what acceptance criterion A1 asks for. check-abi.sh'
say 'compares the symbol sets next, and run-parity.sh links and runs the'
say 'harness and the demonstration program.'
