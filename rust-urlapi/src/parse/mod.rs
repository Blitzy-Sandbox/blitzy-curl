// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The parse pipeline: the module tree of its ten stages, the one order they
//! may run in, and the atomic replacement that makes a failed parse
//! invisible to the caller.
//!
//! This module root ports two functions. Both are `static` in the C and
//! neither is declared in `lib/urlapi-int.h`.
//!
//! | C function | Location | Role |
//! |---|---|---|
//! | `parseurl` | `lib/urlapi.c` L1110-L1192 | the mandatory stage order |
//! | `parseurl_and_replace` | `lib/urlapi.c` L1197-L1209 | parse, then swap |
//!
//! The comment at L1194-L1196 sits between the two in the C and is
//! reproduced on [`parseurl_and_replace`]. Neither function carries an
//! export attribute: `src/ffi.rs` owns the whole exported surface, and
//! acceptance criterion A2 requires the archive's symbol set to equal the
//! eight globals `lib/urlapi.o` defines, so an extra export here would fail
//! the surface check rather than help it.
//!
//! # The ten stage modules
//!
//! One C translation unit becomes eleven files. Every stage is declared
//! below and every function this module calls is imported by name, never by
//! glob, so each cross-module call is visible at its use site.
//!
//! | Module | C span | Stage |
//! |---|---|---|
//! | [`junk`] | L223-L239 | reject junk bytes, measure the input |
//! | [`scheme`] | L182-L221, L935-L1010 | detect, parse and guess the scheme |
//! | [`self::file`] | L823-L933 | the whole `file:` branch |
//! | [`authority`] | L248-L333, L604-L680 | credentials, host, port |
//! | [`host`] | L444-L602 | host validation, IPv4, host decoding |
//! | [`ipv6`] | L390-L442 | bracketed addresses and zone identifiers |
//! | [`port`] | L335-L388 | port extraction |
//! | [`query`] | L1012-L1064 | fragment and query |
//! | [`path`] | L682-L821, L1066-L1108 | path encoding and dot segments |
//! | [`redirect`] | L1214-L1286 | relative-URL resolution |
//!
//! [`redirect`] is declared here and calls back into this module for
//! [`parseurl_and_replace`]. A cycle between a module root and its own child
//! is legal in Rust and needs nothing done about it; restructuring to avoid
//! it would only obscure the C, where `redirect_url` calls
//! `parseurl_and_replace` at L1277 in exactly the same way.
//!
//! # Stage ordering is behavior, not style
//!
//! Earlier stages mutate what later stages read, so the order below is a
//! correctness property. A later tidy-up that reorders the pipeline is a
//! regression rather than a refactor.
//!
//! 1. **Junk scan**, L1124. Measures the input. Every later stage works from
//!    that length instead of measuring again, so an off-by-one here corrupts
//!    the whole pipeline rather than one part of one URL.
//! 2. **Absolute-URL detection**, L1128-L1130. Writes the lower-cased scheme
//!    into a caller-supplied buffer and returns its length; stage 3 consumes
//!    both.
//! 3. **Scheme**, L1138 -- or, at L1134, the entire `file:` branch, which
//!    skips stage 4 outright.
//! 4. **Authority**, L1149, with the guess at L1152. Accumulates the host
//!    into the buffer initialized at L1122, whose ownership moves to the
//!    handle at L1185.
//! 5. **Fragment**, L1168, after which L1170 shortens the shared length.
//! 6. **Query**, L1177, after which L1178 shortens it again.
//! 7. **Path**, L1183, over whatever neither of those two claimed.
//!
//! Reverse stages 5 and 6 and the query search runs against the full length,
//! so the query swallows the fragment along with it. The C records the
//! dependency in its own source, in the comment at L1169.
//!
//! # The shared length, and the two searches that read it
//!
//! `pathlen` is cumulative and destructive. It starts at L1147 holding the
//! path, the query and the fragment; loses the fragment at L1170; loses the
//! query at L1178; and only then describes the path alone. Every
//! subtraction here is saturating and the intermediate values are not
//! reordered.
//!
//! The two searches are deliberately asymmetric in the C. The fragment
//! search at L1165 is `strchr(path, '#')`, which scans to the terminating
//! NUL and ignores `pathlen`. The query search at L1174 is
//! `memchr(path, '?', pathlen)`, which stops at the length the fragment
//! stage has already reduced.
//!
//! Both branches enter stage 5 with `pathlen` equal to the number of bytes
//! remaining, so at that moment the two spans coincide: L1147 computes
//! `urllen - (path - url)`, and `parse_file` maintains the same identity on
//! every path out of itself -- L836, L907, and the paired decrement at
//! L926-L927. What makes the asymmetry observable is therefore not the
//! fragment search but the mutation between the two stages. By the time the
//! query search runs, its bound excludes everything the fragment claimed, so
//! a `?` that sits after the `#` is never seen.
//!
//! `tests/libtest/lib1560.c` L376-L379 is the case that pins it:
//! `https://example.com/color/#green?no-red` yields a path of `/color/`, a
//! fragment of `green?no-red`, and no query at all. L388-L391 pins the other
//! half: `https://example.com/#color/?green#no-red` yields a path of `/` and
//! a fragment of `color/?green#no-red`, because the first `#` wins and
//! everything after it belongs to the fragment.
//!
//! # One failure handler, reached three ways
//!
//! The C's `fail` label at L1188 is reached by the `goto` at L1126 when the
//! junk scan rejects the input, by the `goto` at L1140 when the scheme is
//! rejected, and -- most often -- by falling out of the bottom at L1187 with
//! a non-zero `result`. Stages 5, 6 and 7 are each guarded by `if(!result)`
//! rather than returning early, so a failure in the fragment stage does not
//! leave the function: it falls through the query and path guards, which do
//! nothing, and lands on the label.
//!
//! [`parseurl`] reproduces that shape rather than smoothing it into two
//! early returns and a happy path. The stages sit in a labeled block whose
//! `break` is the `goto` and whose tail value is the fall-through, so all
//! three routes converge on one handler, and that handler releases both the
//! host buffer (L1189) and the handle (L1190).
//!
//! # Ownership of the host buffer
//!
//! The buffer is initialized at L1122 and belongs to [`parseurl`] alone.
//! `parse_authority` documents that it never releases it and `parse_file`
//! either leaves it holding a UNC host name or resets it, so exactly two
//! things can happen to it here: on success L1185 hands its allocation to
//! the handle, which is [`crate::dynbuf::DynBuf::into_cbuf`] in this port,
//! and on failure L1189 frees it.
//!
//! No stage needs to release it on its own failure path either, and that is
//! a property of the buffer rather than an omission: a failed append has
//! already released the whole allocation, which `crate::dynbuf` states as
//! its first contract. Releasing it a second time would be a double free in
//! the C and is not expressible here at all.
//!
//! # Atomic replacement, and why `FB2` is harmless on this path
//!
//! [`parseurl_and_replace`] parses into a zeroed temporary and moves it into
//! the live handle only on success, so no partial mutation is ever
//! observable. `docs/KNOWN-DIVERGENCES.md` records as `FB2` that
//! `parse_hostname_login` reaches a shared exit label at L323 which assigns
//! null to the handle's user, password and options at L328-L330 without
//! releasing what they held, and that the label is reached even on success,
//! at L273-L275, for every URL that carries no credentials. On the ordinary
//! parse path the finding is harmless for exactly one reason: the handle
//! those three lines write to is the temporary this module creates, whose
//! three fields are already absent, so nothing is dropped on the floor.
//! `FB2` is observable only against a live handle, which is what
//! `Curl_url_set_authority` at L658-L675 operates on and what
//! `lib/http2.c` L739 passes it. `src/parse/authority.rs` owns the
//! reproduction; the cross-reference belongs here because the temporary is
//! created here and the connection is invisible from either side alone.
//!
//! # Panic and unsafe posture
//!
//! Nothing here can panic and nothing here is `unsafe`. The crate root
//! denies `unwrap`, `expect`, `panic!`, direct indexing and unchecked
//! arithmetic, and this module carries `#![forbid(unsafe_code)]`, so both
//! properties are enforced by the compiler rather than by convention.
//!
//! The arithmetic in this file is the most consequential in the folder --
//! `path - url`, `urllen - (path - url)`, `pathlen - fraglen`,
//! `pathlen - qlen`, `fragment - path` and `query - path` -- because an
//! off-by-one in any of it silently corrupts every stage downstream. All of
//! it is expressed as offsets into the original slice with saturating
//! subtraction, so a mistake can produce a wrong length but never an
//! out-of-bounds read.
//!
//! # End-to-end verification
//!
//! The tests at the end of this file cover the ordering and the
//! short-circuit shape; each stage is tested in its own file. Those are the
//! oracle currently in force.
//!
//! The end-to-end oracle is to be the unmodified `tests/libtest/lib1560.c`,
//! whose success condition is the literal single line `success` on stdout --
//! which is exactly what `tests/data/test1560` asserts.
//! `rust-urlapi/scripts/run-parity.sh` is the script that is to run it and is
//! a later deliverable, so it does not exist yet. That entry point returns a
//! distinct exit code per failing sub-test and short-circuits at the first
//! failure, so the script is to map the code back to the name and iterate
//! rather than report only the first one it meets:
//!
//! | Code | Sub-test | Code | Sub-test |
//! |---|---|---|---|
//! | 1 | `set_url` | 7 | `get_nothing` |
//! | 2 | `set_parts` | 8 | `clear_url` |
//! | 3 | `get_url` | 9 | `huge` |
//! | 4 | `get_parts` | 10 | `setget_parts` |
//! | 5 | `append` | 11 | `urldup` |
//! | 6 | `scopeid` | | |

// Reachability here is decided by two consumers, matching the C exactly.
// `parseurl_and_replace` has two callers in the C -- `set_url` at L1715 and
// L1723, and `redirect_url` at L1277 -- which are `src/getset.rs` and
// `src/parse/redirect.rs` in this crate. Both exist and are compiled
// unconditionally.
//
// No dead-code allowance is stated here. The crate-level one in `src/lib.rs`
// covers the whole feature matrix in one place, which is where the reason for
// it belongs; see "DEAD-CODE POLICY" there.

// The plan puts every `unsafe` block in `src/ffi.rs` (AAP 0.3.3) and the
// technical specification forbids `unsafe` outside FFI code (1.3.2.1).
// Orchestration needs none of it: this module inspects slices, calls the
// stages and moves owned buffers, and both `crate::dynbuf` and
// `crate::handle` are shaped so that no raw pointer reaches here. `forbid`
// rather than `deny`, so that an inner `allow` has to be argued for rather
// than slipped in.
#![forbid(unsafe_code)]

pub(crate) mod authority;
pub(crate) mod file;
pub(crate) mod host;
pub(crate) mod ipv6;
pub(crate) mod junk;
pub(crate) mod path;
pub(crate) mod port;
pub(crate) mod query;
pub(crate) mod redirect;
pub(crate) mod scheme;

use core::ffi::c_uint;

use crate::abi::{CURLUcode, CURLUE_NO_HOST, CURLUE_OK, CURLUE_OUT_OF_MEMORY};
use crate::abi::{CURLU_ALLOW_SPACE, CURLU_DEFAULT_SCHEME, CURLU_GUESS_SCHEME};
use crate::abi::{CURLU_NO_AUTHORITY, CURL_MAX_INPUT_LENGTH, MAX_SCHEME_LEN};
use crate::dynbuf::DynBuf;
use crate::handle::{CurlUrl, StringField};

use self::authority::parse_authority;
use self::file::parse_file;
use self::junk::junkscan;
use self::path::handle_path;
use self::query::{handle_fragment, handle_query};
use self::scheme::{guess_scheme, is_absolute_url, parse_scheme};

/// The size of the scheme buffer, which is `MAX_SCHEME_LEN + 1` at L1114.
///
/// Forty-one bytes: forty for the longest scheme name libcurl knows, and one
/// for the terminator `Curl_is_absolute_url` writes at L215. Its
/// precondition, `DEBUGASSERT(!buf || (buflen > MAX_SCHEME_LEN))` at L186,
/// is what makes the `+ 1` a minimum rather than a convenience.
///
/// `urlget_url` declares its own buffer as `MAX_SCHEME_LEN + 5` at L1452 and
/// the two are deliberately **not** harmonized. That one assembles
/// `scheme://` and needs room for the three punctuation bytes and the
/// terminator alongside the name; this one holds only the name.
///
/// Spelled with `saturating_add` because the crate root denies unchecked
/// arithmetic. The expression is evaluated in a constant context, where an
/// overflow is a compile error rather than a panic, so the spelling costs
/// nothing and keeps the file free of a bare operator.
const SCHEMEBUF_LEN: usize = MAX_SCHEME_LEN.saturating_add(1);

/// The scheme name that selects the `file:` branch, compared at L1133.
///
/// The C compares with `strcmp` against the buffer `Curl_is_absolute_url`
/// lower-cased at L214, which is why `FILE://` and `File://` take this
/// branch as readily as `file://`.
const SCHEME_FILE: &[u8] = b"file";

/// The bytes a C function reading through this pointer would see: the prefix
/// up to the first NUL, or all of them if there is none.
///
/// One call site, the host handover at L1185, and it is not hypothetical.
/// `ipv6_parse` normalizes a bracketed address **in place** and terminates it
/// where the shorter form ends, at L437 and L422, without telling the dynamic
/// buffer -- `docs/KNOWN-DIVERGENCES.md` records that as `FB6` and
/// `crate::parse::ipv6` documents leaving the recorded length stale on
/// purpose. The C never notices, because L1185 takes `curlx_dyn_ptr(&host)`
/// and a `char *` ends at its terminator. A [`crate::alloc::CBuf`] carries a
/// length instead, so the length has to be brought down to what C would
/// measure or `[fe80::1%25eth0]` reaches the handle as nine recorded bytes
/// over a nine-byte string followed by the tail of the original.
///
/// `Curl_url_set_authority` needs the identical trim at L672, the other place
/// the C hands this buffer over, and `src/parse/authority.rs` performs it
/// there. `src/parse/host.rs`, `src/parse/port.rs` and `src/encode.rs` each
/// carry the same private helper for the same reason. None is imported here:
/// this file's dependency whitelist does not include them, and a helper this
/// small is better duplicated than reached for across a boundary the plan
/// drew on purpose.
fn cstring_window(content: &[u8]) -> &[u8] {
    match content.iter().position(|&byte| byte == 0) {
        Some(end) => content.get(..end).unwrap_or(content),
        None => content,
    }
}

/// Parses a URL into a handle, running the stages in the one order they may
/// run in.
///
/// `parseurl` at `lib/urlapi.c` L1110-L1192. Private, because the C function
/// is `static`: its only caller there is `parseurl_and_replace` at L1203, and
/// its only caller here is [`parseurl_and_replace`].
///
/// # Parameters
///
/// - `url`: the input, holding exactly the bytes up to the C caller's
///   terminating NUL and no further. `src/ffi.rs` owns that conversion, and
///   the `DEBUGASSERT(url)` at L1120 is discharged by the type rather than
///   by a check, because a slice cannot be null.
/// - `u`: the handle to fill. Always a freshly emptied temporary in
///   practice, which is what [`parseurl_and_replace`] guarantees and what
///   several stages rely on; see the note on `FB2` in the module
///   documentation.
/// - `flags`: the caller's `CURLU_*` word, forwarded to every stage. Four
///   bits are read in this function: `CURLU_ALLOW_SPACE` at L1124,
///   `CURLU_GUESS_SCHEME` and `CURLU_DEFAULT_SCHEME` together at
///   L1129-L1130, `CURLU_GUESS_SCHEME` again on its own at L1151, and
///   `CURLU_NO_AUTHORITY` at L1154.
///
/// # Returns
///
/// `CURLUE_OK` at L1186, with the handle populated and owning the host
/// buffer's allocation.
///
/// # Errors
///
/// Whatever the stage that failed reported, unchanged. This function invents
/// only two codes of its own: `CURLUE_NO_HOST` at L1160 and the
/// `CURLUE_OUT_OF_MEMORY` at L1157. On every failure the handle is emptied
/// and the host buffer released, so the caller is handed a handle it can
/// discard or reuse rather than a half-parsed one.
#[must_use = "the parse verdict is the return value and must be handled"]
fn parseurl(url: &[u8], u: &mut CurlUrl, flags: c_uint) -> CURLUcode {
    // L1118 and L1122. The ceiling is `CURL_MAX_INPUT_LENGTH` rather than the
    // input length, because a host can legitimately grow: `ipv4_normalize`
    // rewrites `0` as `0.0.0.0`. Dropping this value releases its
    // allocation, which is the `curlx_dyn_free` of L1189; the explicit call
    // on the failure path below exists to keep the line-for-line
    // correspondence, not because the release depends on it.
    let mut host = DynBuf::new(CURL_MAX_INPUT_LENGTH);

    // The body of the C function from L1112 to L1187. This block's value is
    // the C's `result` variable as it stands when control reaches either
    // L1184 or the label at L1188, and `break 'stages` is the `goto fail` of
    // L1126 and L1140. One handler, reached the same three ways.
    let result: CURLUcode = 'stages: {
        let mut result: CURLUcode = CURLUE_OK;

        // L1124-L1126. The C's `!!` narrows the masked flag to a boolean;
        // here the parameter is a `bool` and the comparison is the
        // narrowing. The measured length replaces `strlen` for every later
        // stage, exactly as the C's `*urllen` does.
        let urllen = match junkscan(url, (flags & CURLU_ALLOW_SPACE) != 0) {
            Ok(len) => len,
            Err(code) => break 'stages code,
        };

        // L1114 and L1128-L1130. The buffer is `MAX_SCHEME_LEN + 1`; see
        // `SCHEMEBUF_LEN` for why it is not the `+ 5` of L1452. The third
        // argument is a masked flag word rather than a single flag test, and
        // both bits genuinely matter: either one means the caller might be
        // looking at an input carrying no scheme at all, which is what turns
        // `c:/x` and `data:1234` from schemes into hosts.
        let mut schemebuf = [0_u8; SCHEMEBUF_LEN];
        let guessing = (flags & (CURLU_GUESS_SCHEME | CURLU_DEFAULT_SCHEME)) != 0;
        let schemelen = is_absolute_url(url, Some(schemebuf.as_mut_slice()), guessing);
        // The C reads this buffer as a C string at L1133 and passes it with
        // `schemelen` alongside at L1138. One slice carries both, which is
        // the shape `parse_scheme` asks for and removes the only way the two
        // could be passed inconsistently.
        let scheme = schemebuf.get(..schemelen).unwrap_or_default();

        // The C's L1112-L1113. Declared before the branch because both arms
        // produce them and every stage from L1162 on consumes them.
        let path: &[u8];
        let mut pathlen: usize;

        // L1132-L1134. `parse_file` handles the scheme, the authority and
        // the path together, so stage 4 is skipped outright -- there is no
        // `parse_scheme` call and no `parse_authority` call on this branch.
        if schemelen != 0 && scheme == SCHEME_FILE {
            match parse_file(url, u, &mut host) {
                Ok(filepath) => {
                    // The C's `*pathp` and `*pathlenp`, L930-L931. The
                    // returned slice carries both, and it satisfies the
                    // identity stage 5 depends on, because `parse_file`
                    // maintains `pathlen == urllen - (path - url)` on every
                    // path out of itself.
                    path = filepath;
                    pathlen = filepath.len();
                }
                Err(code) => {
                    result = code;
                    // The C leaves `path` and `pathlen` indeterminate here
                    // and never reads them, because every guard from L1162
                    // on tests `result` first. Rust requires a value; these
                    // two lines are that requirement and nothing more.
                    path = &[];
                    pathlen = 0;
                }
            }
        } else {
            // L1136-L1140. The offset is measured from the start of `url`,
            // which is why `parse_scheme` is handed the whole input rather
            // than the tail after the scheme.
            let hostp = match parse_scheme(url, u, scheme, flags) {
                Ok(offset) => offset,
                Err(code) => break 'stages code,
            };
            let authority = url.get(hostp..).unwrap_or_default();

            // L1142-L1143, `strcspn(hostp, "/?#")`: the end of the host name
            // and port number. No match means the authority runs to the end
            // of the input, which is what `strcspn` answers with the
            // remaining length.
            let hostlen = authority
                .iter()
                .position(|&byte| matches!(byte, b'/' | b'?' | b'#'))
                .unwrap_or(authority.len());

            // L1144, `path = &hostp[hostlen]`, as an offset into `url`.
            let pathoff = hostp.saturating_add(hostlen);
            path = url.get(pathoff..).unwrap_or_default();
            // L1146-L1147, and the C's comment there: this length still
            // contains the query and the fragment. It equals `path.len()`,
            // because `urllen` is the length of `url`; the C's formula is
            // kept because it is the line being ported.
            pathlen = urllen.saturating_sub(pathoff);

            if hostlen != 0 {
                // L1149-L1150. `has_scheme` is the C's `u->scheme != NULL`,
                // read into a local first because the call borrows the
                // handle mutably. The argument is load-bearing rather than
                // incidental: it is what makes the bare-colon port leniency
                // `docs/KNOWN-DIVERGENCES.md` records as `FB4` conditional
                // on a scheme being present, and computing it here rather
                // than from the flags is why `CURLU_DEFAULT_SCHEME` also
                // enables the leniency.
                let has_scheme = u.scheme().is_some();
                result = parse_authority(u, authority, hostlen, flags, &mut host, has_scheme);

                // L1151-L1152, triple-guarded: the authority must have
                // parsed, the caller must have asked for a guess, and no
                // scheme may have been established yet.
                // `CURLU_DEFAULT_SCHEME` establishes one inside
                // `parse_scheme`, so the two flags together mean no guessing
                // happens. `tests/libtest/lib1560.c` L404-L406 pins that:
                // `boing:80` with both flags set yields `https`, not the
                // `http` a guess from the host name would have produced.
                let wants_guess = (flags & CURLU_GUESS_SCHEME) != 0;
                if result == CURLUE_OK && wants_guess && u.scheme().is_none() {
                    // L1152. The C passes `curlx_dyn_ptr(host)`, which is
                    // the accumulated host name rather than the raw input.
                    // The buffer has not been handed over yet; that happens
                    // at L1185.
                    if let Err(code) = guess_scheme(u, host.as_bytes()) {
                        result = code;
                    }
                }
            } else if (flags & CURLU_NO_AUTHORITY) != 0 {
                // L1154-L1157, and the C's comment: allowed to be empty. The
                // append still allocates, so the handle ends up owning an
                // empty string rather than nothing, which is what lets
                // `custom-scheme://?expected=test-new-good` at
                // `tests/libtest/lib1560.c` L842-L845 serialize back as
                // `custom-scheme:///?expected=test-new-good`. The failure is
                // reported as a plain `CURLUE_OUT_OF_MEMORY` and is
                // deliberately not folded through `cc2cu`, matching L1157:
                // an empty append cannot exceed the ceiling, so the only
                // failure available is an allocation failure.
                if host.add("").is_err() {
                    result = CURLUE_OUT_OF_MEMORY;
                }
            } else {
                result = CURLUE_NO_HOST;
            }
        }

        // L1162-L1172. Guarded rather than returned from: a failure here
        // falls through the two guards below, which then do nothing, and
        // lands on the handler.
        if result == CURLUE_OK {
            // L1163-L1165 and its comment. `strchr(path, '#')` is unbounded:
            // it scans to the terminating NUL rather than stopping at
            // `pathlen`. Searching the whole remaining slice is that scan,
            // and it covers the same span here for the reason the module
            // documentation gives.
            if let Some(fragoff) = path.iter().position(|&byte| byte == b'#') {
                let fraglen = pathlen.saturating_sub(fragoff);
                // L1168. The slice runs to the end of the input while
                // `fraglen` stops at the end of the fragment;
                // `handle_fragment` clamps to the length, which is what
                // keeps anything beyond it out of the part.
                let fragment = path.get(fragoff..).unwrap_or_default();
                result = handle_fragment(u, fragment, fraglen, flags);
                // L1169-L1170, and the C's comment: after this, `pathlen`
                // still contains the query.
                pathlen = pathlen.saturating_sub(fraglen);
            }
        }
        if result == CURLUE_OK {
            // L1174, `memchr(path, '?', pathlen)`: bounded by the length the
            // fragment stage has already reduced, which is precisely what
            // keeps a `?` sitting after the `#` out of the query.
            let searchable = path.get(..pathlen).unwrap_or(path);
            if let Some(queryoff) = searchable.iter().position(|&byte| byte == b'?') {
                let qlen = pathlen.saturating_sub(queryoff);
                // L1177. The slice again runs past the part and `qlen` stops
                // at its end, so `handle_query` does the clamping.
                let query = path.get(queryoff..).unwrap_or_default();
                result = handle_query(u, query, qlen, flags);
                pathlen = pathlen.saturating_sub(qlen);
            }
        }
        // L1181-L1183, and the C's comment: the fragment and query parts are
        // trimmed off from the path.
        if result == CURLUE_OK {
            result = handle_path(u, path, pathlen, flags);
        }

        // L1184 and L1187. Whatever the stages left is the block's value.
        // Falling out of the bottom with a failure in hand is the third and
        // commonest route to the handler below.
        result
    };

    if result == CURLUE_OK {
        // L1185, `u->host = curlx_dyn_ptr(&host)`. Ownership of the
        // allocation moves from the buffer to the handle in one step, so
        // there is no window in which two owners exist and none in which
        // nothing owns it.
        //
        // `None` is the C's null pointer, and the C assigns that just the
        // same: `parse_file` leaves the buffer empty for every `file:` URL
        // without a UNC host name, which is why such a handle ends up with
        // no host at all rather than with an empty one. Clearing the field
        // reproduces that assignment, and it releases any earlier value
        // where the C would overwrite and leak one. Nothing observable turns
        // on the difference, because the only handle that reaches here is
        // the emptied temporary, but the release costs nothing.
        //
        // The trim in front of the move is the C string bound that
        // `curlx_dyn_ptr` implies, and it is load-bearing rather than tidy:
        // see `cstring_window` for which stage leaves an interior terminator
        // behind and why the length has to follow it. `setlen` cannot refuse,
        // because the window is never longer than the content, and its
        // `bool` is the value both C call sites drop for the reasons
        // `crate::dynbuf::DynBuf::setlen` records.
        let measured = cstring_window(host.as_bytes()).len();
        host.setlen(measured);
        match host.into_cbuf() {
            Some(hostname) => u.store(StringField::Host, hostname),
            None => u.clear(StringField::Host),
        }
        return CURLUE_OK;
    }

    // L1188-L1191, the shared handler. L1189 releases the host buffer, which
    // dropping it would do anyway; the call is kept so that both C lines
    // have a counterpart here. L1190 releases the handle: `free_urlhandle`
    // frees its ten strings, and `reset` frees those and also clears the
    // four scalar members. That difference is unobservable, because the only
    // handle that ever reaches this line is the temporary
    // [`parseurl_and_replace`] is about to discard, and it is the safe
    // direction: the C leaves ten dangling pointers behind in that
    // temporary, which is sound only because nothing reads them again.
    host.free();
    u.reset();
    result
}

/// Parses the URL and, if successful, replaces everything in the handle.
///
/// `parseurl_and_replace` at `lib/urlapi.c` L1197-L1209. The C's own comment
/// at L1194-L1196 is the sentence above, with `Curl_URL` where this port
/// says handle.
///
/// # Atomicity
///
/// The whole point of the function. L1201-L1202 declares a temporary and
/// zeroes it, L1203 parses into that, and only L1204's success test unlocks
/// L1205-L1206, which releases the live handle and moves the temporary over
/// it. **No partial mutation is ever observable**: a caller whose parse
/// fails still holds exactly the handle it held before, with every field
/// intact.
///
/// The C achieves that by discipline and this port gets it by construction,
/// because a caller cannot even name a half-parsed handle: `fresh` is a value
/// [`CurlUrl::replace`] consumes, so the swap is one move rather than a
/// window during which two handles are half-valid.
///
/// # No second cleanup
///
/// On failure this function does nothing beyond returning the code, and that
/// is deliberate. [`parseurl`]'s own handler has already released the
/// temporary's contents at L1189-L1190, so the temporary reaching the end of
/// this scope has nothing left to release. Adding a cleanup here would be a
/// double free in the C and is simply redundant here.
///
/// # Why `FB2` cannot bite on this path
///
/// The temporary is also what makes the `FB2` finding harmless whenever a
/// URL is parsed rather than an authority assigned. `parse_hostname_login`
/// assigns null to the handle's user, password and options at
/// `lib/urlapi.c` L328-L330 without releasing what they held, on a label
/// reached even on success at L273-L275. Here those three fields are always
/// already absent, because the handle is the temporary created two lines up,
/// so there is nothing to leak. The finding is observable only against a
/// live handle -- `Curl_url_set_authority` at L658-L675, which `lib/http2.c`
/// L739 calls -- and `src/parse/authority.rs` owns its reproduction. Whoever
/// maintains `rust-urlapi/docs/KNOWN-DIVERGENCES.md` needs both halves of
/// that sentence, which is why it is recorded at both ends.
///
/// # Parameters
///
/// - `url`: the input, as [`parseurl`] takes it.
/// - `u`: the live handle. Written only on success.
/// - `flags`: the caller's `CURLU_*` word, forwarded unchanged. `set_url`
///   passes its own flags straight through at L1715 and L1723, and
///   `redirect_url` clears `CURLU_PATH_AS_IS` before calling at L1277.
///
/// # Returns
///
/// `CURLUE_OK` with the handle replaced, or the failing stage's code with
/// the handle untouched. L1208.
#[must_use = "the parse verdict is the return value and must be handled"]
pub(crate) fn parseurl_and_replace(url: &[u8], u: &mut CurlUrl, flags: c_uint) -> CURLUcode {
    // L1201-L1202, `CURLU tmpurl; memset(&tmpurl, 0, sizeof(tmpurl));`. The
    // constructor is the `memset`: ten absent strings, port number zero and
    // three clear flags, which is what every stage assumes on entry.
    let mut tmpurl = CurlUrl::new();

    let result = parseurl(url, &mut tmpurl, flags);

    // L1204-L1207. `replace` is L1205 and L1206 together: dropping the value
    // it displaces releases that handle's ten strings, which is
    // `free_urlhandle(u)`, and the move is `*u = tmpurl`.
    if result == CURLUE_OK {
        u.replace(tmpurl);
    }

    // L1208. On the failure path `tmpurl` goes out of scope here with
    // nothing left in it to release; see "No second cleanup" above.
    result
}

#[cfg(test)]
mod tests {
    //! Tests for the ordering and the short-circuit shape, which is what
    //! this module owns. Each stage is tested against its own C span in its
    //! own file, so nothing here re-tests a stage: every case below either
    //! pins the order two stages run in, the arithmetic they share, or the
    //! route control takes on a failure.
    //!
    //! Most of the inputs are lifted from `tests/libtest/lib1560.c` with
    //! their line numbers, because a case the reference suite already
    //! asserts is worth more than one invented here: if the port and the
    //! comment ever disagree, the parity run says which is wrong.
    //!
    //! # Why every input here uses `https`, `imap` or `file`
    //!
    //! `parse_scheme` rejects a scheme the build cannot resolve, at L951, and
    //! where the resolution comes from depends on the feature set. With
    //! `scheme-table` on, `crate::scheme` answers from its own table. With it
    //! off -- the drop-in configuration -- the answer comes from libcurl's
    //! `Curl_get_scheme`, which a Rust-only test binary has no libcurl to
    //! ask, so `crate::ffi::scheme_import` substitutes a four-descriptor
    //! double under `cfg(test)`: `https`, `imap`, `file` and `rtmp`.
    //!
    //! Every case below therefore either names one of those, carries no
    //! scheme at all, or sets `CURLU_NON_SUPPORT_SCHEME`. That is a
    //! deliberate constraint rather than an accident: it means this file's
    //! tests run identically in both feature configurations instead of being
    //! gated out of one of them, and nothing here is testing the scheme
    //! table anyway -- `src/scheme.rs` and `src/parse/scheme.rs` own that.

    use core::ffi::c_uint;

    use super::{parseurl, parseurl_and_replace};
    use crate::abi::{CURLUcode, CURLUE_BAD_SCHEME, CURLUE_MALFORMED_INPUT};
    use crate::abi::{CURLUE_NO_HOST, CURLUE_OK};
    use crate::abi::{CURLU_DEFAULT_SCHEME, CURLU_GUESS_SCHEME};
    use crate::abi::{CURLU_NON_SUPPORT_SCHEME, CURLU_NO_AUTHORITY};
    use crate::handle::CurlUrl;

    /// No flags at all, which is what most of these cases want.
    const NO_FLAGS: c_uint = 0;

    /// The input the two atomicity tests build their live handle from.
    ///
    /// Chosen so that every member a parse can populate is populated:
    /// credentials, a host, an explicit port, a path, a query and a
    /// fragment. That makes "nothing changed" a strong assertion rather
    /// than a vacuous one.
    const FIRST_URL: &[u8] = b"https://user:pass@first.example.com:99/one?q=1#f";

    /// Asserts that the handle holds exactly what [`FIRST_URL`] parses to.
    ///
    /// Every one of the fourteen members is named, so a stage that started
    /// writing one it should not write would fail here.
    fn assert_first_url(u: &CurlUrl) {
        assert_eq!(u.scheme(), Some(b"https".as_slice()));
        assert_eq!(u.user(), Some(b"user".as_slice()));
        assert_eq!(u.password(), Some(b"pass".as_slice()));
        assert_eq!(u.options(), None);
        assert_eq!(u.host(), Some(b"first.example.com".as_slice()));
        assert_eq!(u.zoneid(), None);
        assert_eq!(u.port(), Some(b"99".as_slice()));
        assert_eq!(u.path(), Some(b"/one".as_slice()));
        assert_eq!(u.query(), Some(b"q=1".as_slice()));
        assert_eq!(u.fragment(), Some(b"f".as_slice()));
        assert_eq!(u.portnum(), 99);
        assert!(u.query_present());
        assert!(u.fragment_present());
        assert!(!u.guessed_scheme());
    }

    /// Asserts that all fourteen members are in the state
    /// [`CurlUrl::new`] leaves them in.
    ///
    /// This is how the failure-handler tests show that L1190 ran: the
    /// handle they hand to [`parseurl`] is fully populated beforehand, so
    /// finding it empty afterwards can only mean the handle was released.
    fn assert_empty(u: &CurlUrl) {
        assert_eq!(u.scheme(), None);
        assert_eq!(u.user(), None);
        assert_eq!(u.password(), None);
        assert_eq!(u.options(), None);
        assert_eq!(u.host(), None);
        assert_eq!(u.zoneid(), None);
        assert_eq!(u.port(), None);
        assert_eq!(u.path(), None);
        assert_eq!(u.query(), None);
        assert_eq!(u.fragment(), None);
        assert_eq!(u.portnum(), 0);
        assert!(!u.query_present());
        assert!(!u.fragment_present());
        assert!(!u.guessed_scheme());
    }

    /// Parses into a fresh handle and reports the verdict alongside it.
    fn parse(url: &[u8], flags: c_uint) -> (CURLUcode, CurlUrl) {
        let mut u = CurlUrl::new();
        let result = parseurl(url, &mut u, flags);
        (result, u)
    }

    /// The single best regression test for the stage arithmetic: one URL
    /// carrying every part, with each part landing where it belongs.
    ///
    /// An off-by-one anywhere in `pathlen`, `fraglen` or `qlen` moves a
    /// delimiter into or out of a part and this fails.
    #[test]
    fn a_full_url_puts_every_part_in_its_place() {
        let (result, u) = parse(FIRST_URL, NO_FLAGS);
        assert_eq!(result, CURLUE_OK);
        assert_first_url(&u);
    }

    /// `lib/urlapi.c` L1133-L1134: the `file:` branch handles everything and
    /// the authority stages are skipped outright.
    ///
    /// The marker that they did not run is the host. `parse_file` resets the
    /// buffer for a `file:` URL with no UNC host name, so L1185 hands over a
    /// null pointer and the member stays absent -- which is a different
    /// state from the empty string the `CURLU_NO_AUTHORITY` branch produces
    /// two tests below. Nothing else the authority stages write is set
    /// either.
    #[test]
    fn the_file_branch_short_circuits_the_authority_stages() {
        let (result, u) = parse(b"file:///tmp/x", NO_FLAGS);
        assert_eq!(result, CURLUE_OK);
        assert_eq!(u.scheme(), Some(b"file".as_slice()));
        assert_eq!(u.path(), Some(b"/tmp/x".as_slice()));
        assert_eq!(u.host(), None);
        assert_eq!(u.user(), None);
        assert_eq!(u.password(), None);
        assert_eq!(u.options(), None);
        assert_eq!(u.port(), None);
        assert_eq!(u.zoneid(), None);
        assert_eq!(u.portnum(), 0);
    }

    /// The scheme comparison at L1133 is against the lower-cased buffer
    /// `Curl_is_absolute_url` wrote at L214, so the branch is
    /// case-insensitive.
    #[test]
    fn the_file_branch_is_reached_whatever_the_case() {
        let (result, u) = parse(b"FILE:///tmp/x", NO_FLAGS);
        assert_eq!(result, CURLUE_OK);
        assert_eq!(u.scheme(), Some(b"file".as_slice()));
        assert_eq!(u.host(), None);
    }

    /// The `goto fail` at L1126, and proof that L1190 ran.
    ///
    /// `0x7f` is junk whatever the flags say, L234, so this needs no flag to
    /// trigger. The handle is populated first, so an empty handle afterwards
    /// can only mean the handler released it.
    #[test]
    fn a_junk_scan_failure_runs_the_failure_handler() {
        let mut u = CurlUrl::new();
        assert_eq!(parseurl(FIRST_URL, &mut u, NO_FLAGS), CURLUE_OK);
        assert_first_url(&u);
        let verdict = parseurl(b"https://example.com/\x7f", &mut u, NO_FLAGS);
        assert_eq!(verdict, CURLUE_MALFORMED_INPUT);
        assert_empty(&u);
    }

    /// The `goto fail` at L1140, and proof that L1190 ran on that route too.
    ///
    /// With neither `CURLU_DEFAULT_SCHEME` nor `CURLU_GUESS_SCHEME`, an
    /// input carrying no scheme is rejected by `parse_scheme` at L964-L965.
    #[test]
    fn a_scheme_failure_runs_the_failure_handler() {
        let mut u = CurlUrl::new();
        assert_eq!(parseurl(FIRST_URL, &mut u, NO_FLAGS), CURLUE_OK);
        let verdict = parseurl(b"example.com/x", &mut u, NO_FLAGS);
        assert_eq!(verdict, CURLUE_BAD_SCHEME);
        assert_empty(&u);
    }

    /// L1154-L1157: an empty authority is allowed to stay empty, and the
    /// host ends up as an empty string rather than as nothing.
    ///
    /// `tests/libtest/lib1560.c` L842-L845, which serializes this input back
    /// as `custom-scheme:///?expected=test-new-good` -- the third slash is
    /// the empty host this test asserts.
    #[test]
    fn no_authority_accepts_an_empty_host() {
        let flags = CURLU_NON_SUPPORT_SCHEME | CURLU_NO_AUTHORITY;
        let (result, u) = parse(b"custom-scheme://?expected=test-new-good", flags);
        assert_eq!(result, CURLUE_OK);
        assert_eq!(u.scheme(), Some(b"custom-scheme".as_slice()));
        assert_eq!(u.host(), Some(b"".as_slice()));
        assert_eq!(u.query(), Some(b"expected=test-new-good".as_slice()));
        assert!(u.query_present());
        assert_eq!(u.path(), None);
    }

    /// L1159-L1160: without the flag, the same input is rejected.
    ///
    /// `tests/libtest/lib1560.c` L836-L838, whose expected code is
    /// `CURLUE_NO_HOST`. The handle is emptied on the way out, which is the
    /// fall-through route to the handler rather than either `goto`.
    #[test]
    fn without_no_authority_an_empty_authority_is_rejected() {
        let flags = CURLU_NON_SUPPORT_SCHEME;
        let (result, u) = parse(b"custom-scheme://?expected=test-bad", flags);
        assert_eq!(result, CURLUE_NO_HOST);
        assert_empty(&u);
    }

    /// L1151-L1152: the guess runs, and it marks the scheme as guessed.
    ///
    /// `tests/libtest/lib1560.c` L353-L356 asserts every part of this
    /// input, and it exercises the whole pipeline in one go: credentials,
    /// a guessed scheme taken from the host name, an unbounded fragment
    /// search and a query that is not one.
    #[test]
    fn guess_scheme_fills_in_a_scheme_and_marks_it_guessed() {
        let url = b"user:moo@ftp.example.com/color/#green?no-red";
        let (result, u) = parse(url, CURLU_GUESS_SCHEME);
        assert_eq!(result, CURLUE_OK);
        assert_eq!(u.scheme(), Some(b"ftp".as_slice()));
        assert!(u.guessed_scheme());
        assert_eq!(u.user(), Some(b"user".as_slice()));
        assert_eq!(u.password(), Some(b"moo".as_slice()));
        assert_eq!(u.host(), Some(b"ftp.example.com".as_slice()));
        assert_eq!(u.path(), Some(b"/color/".as_slice()));
        assert_eq!(u.fragment(), Some(b"green?no-red".as_slice()));
        assert_eq!(u.query(), None);
    }

    /// The third arm of the triple guard at L1151: a scheme is already
    /// established, so no guess happens.
    ///
    /// `tests/libtest/lib1560.c` L404-L406. `CURLU_DEFAULT_SCHEME` supplies
    /// `https` inside `parse_scheme`, which makes `!u->scheme` false; a
    /// guess from the host name would have produced `http` instead, so the
    /// scheme this asserts is the whole difference between the two
    /// mechanisms. The flag is not set either, which
    /// `CURLU_NO_GUESS_SCHEME` can tell apart.
    #[test]
    fn the_default_scheme_suppresses_the_guess() {
        let flags = CURLU_DEFAULT_SCHEME | CURLU_GUESS_SCHEME;
        let (result, u) = parse(b"boing:80", flags);
        assert_eq!(result, CURLUE_OK);
        assert_eq!(u.scheme(), Some(b"https".as_slice()));
        assert!(!u.guessed_scheme());
        assert_eq!(u.host(), Some(b"boing".as_slice()));
        assert_eq!(u.port(), Some(b"80".as_slice()));
        assert_eq!(u.portnum(), 80);
        assert_eq!(u.path(), None);
    }

    /// A `#` and no `?`: the fragment is set and the query stays absent.
    #[test]
    fn a_fragment_without_a_query() {
        let (result, u) = parse(b"https://example.com/a#f", NO_FLAGS);
        assert_eq!(result, CURLUE_OK);
        assert_eq!(u.path(), Some(b"/a".as_slice()));
        assert_eq!(u.fragment(), Some(b"f".as_slice()));
        assert!(u.fragment_present());
        assert_eq!(u.query(), None);
        assert!(!u.query_present());
    }

    /// A `?` and no `#`: the converse.
    #[test]
    fn a_query_without_a_fragment() {
        let (result, u) = parse(b"https://example.com/a?q", NO_FLAGS);
        assert_eq!(result, CURLUE_OK);
        assert_eq!(u.path(), Some(b"/a".as_slice()));
        assert_eq!(u.query(), Some(b"q".as_slice()));
        assert!(u.query_present());
        assert_eq!(u.fragment(), None);
        assert!(!u.fragment_present());
    }

    /// Both, in the ordinary order: the fragment is trimmed first at L1170
    /// and the query then sees only what is left.
    ///
    /// `tests/libtest/lib1560.c` L385-L387.
    #[test]
    fn a_query_before_a_fragment_is_a_query() {
        let url = b"https://example.com/color/?green#no-red";
        let (result, u) = parse(url, NO_FLAGS);
        assert_eq!(result, CURLUE_OK);
        assert_eq!(u.path(), Some(b"/color/".as_slice()));
        assert_eq!(u.query(), Some(b"green".as_slice()));
        assert_eq!(u.fragment(), Some(b"no-red".as_slice()));
    }

    /// **The bounded-versus-unbounded case.** A `?` sitting after the `#` is
    /// part of the fragment and is not a query, because the query search at
    /// L1174 is bounded by the `pathlen` the fragment stage already reduced
    /// at L1170.
    ///
    /// `tests/libtest/lib1560.c` L376-L379. Reverse the two stages and this
    /// input yields a query of `no-red` and no fragment, which is why the
    /// order is behavior rather than style.
    #[test]
    fn a_query_after_a_fragment_belongs_to_the_fragment() {
        let url = b"https://example.com/color/#green?no-red";
        let (result, u) = parse(url, NO_FLAGS);
        assert_eq!(result, CURLUE_OK);
        assert_eq!(u.path(), Some(b"/color/".as_slice()));
        assert_eq!(u.fragment(), Some(b"green?no-red".as_slice()));
        assert_eq!(u.query(), None);
        assert!(!u.query_present());
    }

    /// The unbounded search at L1165 stops at the **first** `#`, so a second
    /// one and a `?` after it both belong to the fragment.
    ///
    /// `tests/libtest/lib1560.c` L388-L391. The path is left absent here
    /// because only the leading slash remains and L1080-L1083 unsets a path
    /// of one byte; the getter substitutes `/` for it, which is what the
    /// reference expectation shows.
    #[test]
    fn the_first_hash_wins_and_takes_everything_after_it() {
        let url = b"https://example.com/#color/?green#no-red";
        let (result, u) = parse(url, NO_FLAGS);
        assert_eq!(result, CURLUE_OK);
        assert_eq!(u.path(), None);
        assert_eq!(u.fragment(), Some(b"color/?green#no-red".as_slice()));
        assert_eq!(u.query(), None);
    }

    /// `fraglen` of exactly one: L1167 computes it, L1017 declines to store
    /// anything, and L1170 still subtracts it.
    ///
    /// The subtraction is what this pins. A bare `#` must take one byte off
    /// `pathlen` and no more, or the path grows or shrinks by one.
    #[test]
    fn a_bare_hash_records_presence_and_costs_one_byte() {
        let (result, u) = parse(b"https://example.com/a#", NO_FLAGS);
        assert_eq!(result, CURLUE_OK);
        assert_eq!(u.path(), Some(b"/a".as_slice()));
        assert_eq!(u.fragment(), None);
        assert!(u.fragment_present());
    }

    /// `qlen` of exactly one: the same subtraction on the other stage, and
    /// with it the one difference between L1017 and L1040 that is easiest to
    /// lose.
    ///
    /// `handle_query` has an `else` branch at L1057-L1062 and
    /// `handle_fragment` has none, so a bare `?` stores an **empty** query
    /// where the test above leaves the fragment absent. Both still record
    /// their presence bit and both still cost `pathlen` exactly one byte,
    /// which is what this pair of tests pins from the orchestrator's side.
    #[test]
    fn a_bare_question_mark_records_presence_and_costs_one_byte() {
        let (result, u) = parse(b"https://example.com/a?", NO_FLAGS);
        assert_eq!(result, CURLUE_OK);
        assert_eq!(u.path(), Some(b"/a".as_slice()));
        assert_eq!(u.query(), Some(b"".as_slice()));
        assert!(u.query_present());
    }

    /// **The host handover trim.** A bracketed address that normalization
    /// shortens must reach the handle at its shortened length, not at the
    /// length the buffer still records.
    ///
    /// `ipv6_parse` rewrites the address in place and terminates it where the
    /// shorter form ends, L435-L439, leaving the dynamic buffer's own record
    /// stale -- `FB6`. L1185 hands the buffer over as a `char *`, so C
    /// measures the shorter string; this port hands over a length, so L1185
    /// has to measure it too. Without the trim the handle receives
    /// `[::1]\0000:0000:0000:0001]` and the whole-URL template then produces a
    /// URL that stops dead at the interior terminator.
    ///
    /// Both cases were verified against a reference libcurl built from the
    /// unmodified tree: `[::1]` with the port and path intact.
    #[test]
    fn a_normalized_ipv6_host_is_trimmed_to_what_c_would_measure() {
        let url = b"https://[0000:0000:0000:0000:0000:0000:0000:0001]:8080/x";
        let (result, u) = parse(url, NO_FLAGS);
        assert_eq!(result, CURLUE_OK);
        assert_eq!(u.host(), Some(b"[::1]".as_slice()));
        assert_eq!(u.port(), Some(b"8080".as_slice()));
        assert_eq!(u.portnum(), 8080);
        assert_eq!(u.path(), Some(b"/x".as_slice()));
        assert_eq!(u.zoneid(), None);
    }

    /// The same trim on the zone-identifier path, where the terminator comes
    /// from the other `FB6` site.
    ///
    /// L421-L422 insert the closing bracket over the `%` and terminate one
    /// byte further on, which cuts `%25eth0]` off the recorded length without
    /// changing it. The zone itself is stored separately at L418 and must
    /// survive.
    #[test]
    fn a_zoned_ipv6_host_is_trimmed_and_keeps_its_zone() {
        let (result, u) = parse(b"https://[fe80::1%25eth0]/x", NO_FLAGS);
        assert_eq!(result, CURLUE_OK);
        assert_eq!(u.host(), Some(b"[fe80::1]".as_slice()));
        assert_eq!(u.zoneid(), Some(b"eth0".as_slice()));
        assert_eq!(u.path(), Some(b"/x".as_slice()));
    }

    /// The zone path again, with an address whose canonical form is longer
    /// than the text, so L435 declines and the terminator written at L422 is
    /// the only thing bounding the host.
    ///
    /// `1::2:3:4:5:6:7` is fourteen bytes and `inet_ntop` needs fifteen, so
    /// the normalization is refused and the address stays as written. The
    /// reference build answers `[1::2:3:4:5:6:7]` with the zone `eth0`.
    #[test]
    fn an_unnormalized_zoned_host_is_still_trimmed() {
        let (result, u) = parse(b"https://[1::2:3:4:5:6:7%eth0]/x", NO_FLAGS);
        assert_eq!(result, CURLUE_OK);
        assert_eq!(u.host(), Some(b"[1::2:3:4:5:6:7]".as_slice()));
        assert_eq!(u.zoneid(), Some(b"eth0".as_slice()));
        assert_eq!(u.path(), Some(b"/x".as_slice()));
    }

    /// A host that normalization does not shorten passes through untouched,
    /// so the trim cannot be cutting anything it should not.
    #[test]
    fn an_ipv6_host_that_does_not_shrink_is_left_alone() {
        let (result, u) = parse(b"https://[::1]/x", NO_FLAGS);
        assert_eq!(result, CURLUE_OK);
        assert_eq!(u.host(), Some(b"[::1]".as_slice()));
        assert_eq!(u.path(), Some(b"/x".as_slice()));
    }

    /// **The atomicity guard.** A failing parse leaves the live handle
    /// exactly as it was, L1204-L1207.
    ///
    /// This is the most valuable test in the file. Every member is asserted
    /// twice, before and after, so any partial mutation at all shows up --
    /// and a partial mutation is precisely what a caller can never be
    /// allowed to observe.
    #[test]
    fn a_failed_replacement_leaves_the_handle_untouched() {
        let mut u = CurlUrl::new();
        assert_eq!(parseurl_and_replace(FIRST_URL, &mut u, NO_FLAGS), CURLUE_OK);
        assert_first_url(&u);
        let verdict = parseurl_and_replace(b"example.com", &mut u, NO_FLAGS);
        assert_eq!(verdict, CURLUE_BAD_SCHEME);
        assert_first_url(&u);
    }

    /// A failing parse of a different shape, to show the guarantee does not
    /// depend on which stage rejected the input.
    ///
    /// This one is rejected by the junk scan before any stage has run, where
    /// the case above is rejected by the scheme stage after the handle has
    /// been touched.
    #[test]
    fn a_replacement_rejected_by_the_junk_scan_changes_nothing_either() {
        let mut u = CurlUrl::new();
        assert_eq!(parseurl_and_replace(FIRST_URL, &mut u, NO_FLAGS), CURLUE_OK);
        let verdict = parseurl_and_replace(b"https://a/\x01", &mut u, NO_FLAGS);
        assert_eq!(verdict, CURLUE_MALFORMED_INPUT);
        assert_first_url(&u);
    }

    /// A succeeding parse replaces the whole handle, with nothing surviving
    /// from what was there before.
    ///
    /// The new input has no credentials, no port, no query and no fragment,
    /// so every member the old one had set must now be absent. A swap that
    /// merged instead of replacing would leave `user`, `port` or
    /// `query_present` behind.
    #[test]
    fn a_successful_replacement_leaves_nothing_behind() {
        let mut u = CurlUrl::new();
        assert_eq!(parseurl_and_replace(FIRST_URL, &mut u, NO_FLAGS), CURLUE_OK);
        let second = b"imap://second.example.com/two";
        assert_eq!(parseurl_and_replace(second, &mut u, NO_FLAGS), CURLUE_OK);
        assert_eq!(u.scheme(), Some(b"imap".as_slice()));
        assert_eq!(u.host(), Some(b"second.example.com".as_slice()));
        assert_eq!(u.path(), Some(b"/two".as_slice()));
        assert_eq!(u.user(), None);
        assert_eq!(u.password(), None);
        assert_eq!(u.options(), None);
        assert_eq!(u.port(), None);
        assert_eq!(u.zoneid(), None);
        assert_eq!(u.query(), None);
        assert_eq!(u.fragment(), None);
        assert_eq!(u.portnum(), 0);
        assert!(!u.query_present());
        assert!(!u.fragment_present());
        assert!(!u.guessed_scheme());
    }

    /// Replacing into a handle that was never populated works too, which is
    /// the path `curl_url_set(u, CURLUPART_URL, ...)` takes on a fresh
    /// handle.
    #[test]
    fn replacing_into_a_fresh_handle_populates_it() {
        let mut u = CurlUrl::new();
        assert_empty(&u);
        assert_eq!(parseurl_and_replace(FIRST_URL, &mut u, NO_FLAGS), CURLUE_OK);
        assert_first_url(&u);
    }
}
