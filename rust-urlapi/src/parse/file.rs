// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The `file:` stage: the one branch of the parser that bypasses every other
//! branch.
//!
//! Port of `parse_file`, `lib/urlapi.c` L823-L933, together with the two
//! drive-prefix macros it tests, `STARTS_WITH_DRIVE_PREFIX` at L38-L44 and
//! `STARTS_WITH_URL_DRIVE_PREFIX` at L46-L52.
//!
//! # Why this stage stands alone
//!
//! `parseurl` dispatches at `lib/urlapi.c` L1133-L1134:
//!
//! ```c
//! if(schemelen && !strcmp(schemebuf, "file"))
//!   result = parse_file(url, urllen, u, &host, &path, &pathlen);
//! else {
//! ```
//!
//! Everything in that `else` -- `parse_scheme`, the `strcspn` host-length
//! scan, `parse_authority`, `guess_scheme`, the `CURLU_NO_AUTHORITY`
//! allowance and the `CURLUE_NO_HOST` fallback, L1135-L1161 -- is skipped.
//! Three consequences follow, and each is this module's responsibility
//! alone:
//!
//! - it is the only place `u->scheme` is set on this path, so the store at
//!   L838 is not redundant with `parse_scheme`;
//! - it is the only place the host buffer's final state is decided, so a
//!   `file:` URL gets no port parsing, no IPv4 normalization and no host
//!   validation at all;
//! - the comparison at L1133 is against `schemebuf`, which
//!   `Curl_is_absolute_url` has already lower-cased at L214, its
//!   `Curl_strntolower(buf, url, i)` call, so `FILE://`
//!   and `File://` reach this stage exactly as `file://` does. The URL
//!   itself keeps its original case, and this stage never inspects those
//!   five bytes: it skips them and stores the lower-case literal `"file"`.
//!
//! # What is handed back
//!
//! The C reports two out-parameters, `*pathp` and `*pathlenp`. They are not
//! independent: at all four sites that assign them, L835-L836, L906-L907 and
//! L926-L927, `pathlen` is exactly `urllen - (path - url)`. A subslice of
//! the input expresses that pair in one value that cannot desynchronize, so
//! this port returns the path slice and its `len()` is `*pathlenp`.
//!
//! The path still contains any query and any fragment. `parseurl` trims them
//! afterwards, at L1162-L1180, so trimming here would remove them twice.
//! `tests/libtest/lib1560.c` L1356 pins that: `file://localhost/path?query#frag`
//! must reach the later stages with `/path?query#frag` intact.
//!
//! # RFC 8089 and the three authorities that are accepted
//!
//! The comment at L842-L870 explains the narrowness. A `file:` URL can be
//! dereferenced reliably when it has no authority, when the authority is
//! `localhost`, when the authority is a name that resolves to this machine,
//! or when it is a UNC path rendered as a URI, which is Windows only. curl
//! implements a deliberate subset: empty, `localhost` and `127.0.0.1` count
//! as local, anything else is treated as a UNC host on Windows and rejected
//! everywhere else. A Windows drive letter in the authority is admitted as a
//! further exception, which the comment at L867-L869 notes was left out of
//! the RFC by accident.
//!
//! Reproducing the subset is the requirement. This module resolves no name,
//! so a fully qualified name that does resolve to this machine is still
//! rejected off Windows, exactly as the C rejects it.
//!
//! # The nine-byte skip is not an off-by-one
//!
//! `"localhost/"` and `"127.0.0.1/"` are both ten bytes, and L876 advances
//! nine. That leaves the cursor **on** the slash, which then becomes the
//! first byte of the path: `file://localhost/path` yields `/path`, not
//! `path`. Advancing ten would drop the leading slash of every such URL and
//! would fail `tests/libtest/lib1560.c` L457 and L1356. The constant here is
//! [`LOCAL_HOST_SKIP`] and the relationship to the prefix length is asserted
//! at compile time below.
//!
//! Both tests are case-insensitive, because `checkprefix` at
//! `lib/strcase.h` L33 expands to `curl_strnequal`, so `file://LOCALHOST/x`
//! is accepted.
//!
//! # Reading past the end is reading the terminating NUL
//!
//! The C walks a NUL-terminated string, and two of its tests depend on it.
//! `STARTS_WITH_URL_DRIVE_PREFIX` accepts a terminator as the byte after the
//! drive separator, L52, and `strpbrk` at L885 stops at the terminator. That
//! is reachable, not theoretical: for `file://c:` the macro is applied to a
//! two-byte tail and matches only because the third byte read is the NUL.
//!
//! `Curl_junkscan` measures the string with `strlen` at L225 and reports
//! that length at L237, so `url[urllen]` is the terminator and every read
//! past `urllen` is a zero. This module therefore takes the bytes up to but
//! not including the terminator and models a read past the end as zero, in
//! [`byte_at`]. The junk scan also rejects an interior zero byte, L233-L236,
//! so no in-range byte can be confused with the terminator.
//!
//! # Platform mapping, and what is not validated
//!
//! The C uses two different guards, and this port keeps them apart:
//!
//! - `#ifdef _WIN32`, at L38 and L879, becomes `cfg(windows)`. It governs
//!   `STARTS_WITH_DRIVE_PREFIX` and the UNC arm.
//! - `#if !defined(_WIN32) && !defined(MSDOS) && !defined(__CYGWIN__)`, at
//!   L914, becomes `cfg(not(any(windows, target_os = "cygwin")))`. It governs
//!   the drive-letter rule alone.
//!
//! Keeping them apart matters for one platform in particular. Cygwin defines
//! `__CYGWIN__` and not `_WIN32`, so the C compiles the UNC arm **out** there
//! while still taking the drive-letter strip; the two `cfg`s above reproduce
//! that asymmetry exactly, where a single `cfg(windows)` for both would not.
//!
//! `windows` is the target family, so it covers both the MSVC and the GNU
//! toolchains, and `_WIN32` is defined by both. `MSDOS` has no counterpart:
//! Rust has no MS-DOS target, so the condition is unrepresentable rather
//! than omitted. Spelling it `target_os = "msdos"` anyway was measured on
//! the toolchain this crate pins and produces an `unexpected_cfgs` warning,
//! which a crate held to zero warnings cannot carry, whereas
//! `target_os = "cygwin"` is a value the compiler knows and accepts.
//!
//! Per the plan's non-functional constraints, the Windows arms are ported as
//! conditional code and will **not be validated** by the parity workflow: that
//! workflow builds for the parity platform, where every `cfg(windows)` arm is
//! compiled out, and the four Windows-only rows of
//! `tests/libtest/lib1560.c` L362-L371 sit inside `#ifdef _WIN32` and so are
//! not compiled there either. Nobody should read a green parity run as
//! evidence about the UNC path or the drive-letter strip.
//!
//! `rust-urlapi/scripts/run-parity.sh` is the script that is to drive that
//! workflow. It is a later deliverable and does not exist yet.
//!
//! # Memory ownership
//!
//! Two allocations are in play and neither is owned by this module when it
//! returns.
//!
//! The scheme is a fresh C-allocator buffer, [`CBuf`], moved into the handle
//! by [`CurlUrl::store`]. The handle releases it, which is what
//! `free_urlhandle` at L86-L98 does for the C, and if it later reaches C
//! through `curl_url_get` the documented `curl_free` contract holds because
//! the block came from the C allocator. It is stored **before** the
//! authority analysis, so a later error leaves a handle that owns a scheme;
//! that is the C's order too, and `parseurl` cleans up at L1188-L1191.
//!
//! The host buffer belongs to the caller. Only the UNC arm appends to it,
//! and a failed append has already released it, so the code is folded with
//! `cc2cu` and returned without a second release, per `DynBuf::addn`'s
//! contract and L891-L893. Otherwise it is reset at L910-L912, which keeps
//! the allocation and empties the content. Since nothing appended to it on
//! that path, it still holds no block, so `parseurl`'s `curlx_dyn_ptr` at
//! L1185 yields a null pointer and `u->host` stays absent. That is why the
//! oracle prints `[14]`, an unset host, for every non-UNC `file:` URL, and
//! why `localhost` is discarded rather than stored.

// Reachability here matches the C exactly. `parse_file` has one caller in the
// C, `parseurl` at `lib/urlapi.c` L1134, so this module's consumer is
// `src/parse/mod.rs`, which declares `mod file;` and calls the stage from the
// same position in the pipeline. It is compiled unconditionally, so nothing
// here is unreached.
//
// No dead-code allowance is stated here. The crate-level one in `src/lib.rs`
// covers the whole feature matrix in one place, which is where the reason for
// it belongs; see "DEAD-CODE POLICY" there.

// The plan puts every `unsafe` block in `src/ffi.rs` and the technical
// specification forbids `unsafe` outside FFI code. `forbid` rather than
// `deny` because an inner `allow` here would be a design change and should
// have to be argued for, not slipped in. This module needs nothing from C:
// it reads a byte slice, asks `src/alloc.rs` for one buffer and appends to a
// buffer the caller owns.
#![forbid(unsafe_code)]

use crate::abi::{CURLUcode, CURLUE_BAD_FILE_URL, CURLUE_OUT_OF_MEMORY};
use crate::alloc::CBuf;
use crate::ctype::{is_alpha, starts_with_ignore_case};
use crate::dynbuf::DynBuf;
use crate::handle::{CurlUrl, StringField};

// `cc2cu` folds a dynamic-buffer failure into a `CURLUcode` and is reached
// from the UNC arm alone, `lib/urlapi.c` L893. The import is gated exactly as
// that arm is, because an ungated `use` would be an unused import on every
// other platform and this crate is held to zero warnings.
#[cfg(windows)]
use crate::error::cc2cu;

/// The length of `"file:"`, and so the offset of the path within the URL.
///
/// `lib/urlapi.c` L835 writes it as the literal `&url[5]`. The five bytes are
/// never inspected: `Curl_is_absolute_url` has already established that the
/// URL starts with a `file` scheme name and a colon, in whatever case.
const FILE_PREFIX_LEN: usize = 5;

/// The length of `"file:/"`, which is the largest input this stage rejects
/// out of hand.
///
/// `lib/urlapi.c` L830-L832, whose comment is the whole justification:
/// `file:/` is not enough to be a complete `file:` URL. The test is `<=`, so
/// seven bytes is the shortest acceptable input and `file:/h` at
/// `tests/libtest/lib1560.c` L451 is the shortest accepted one.
const FILE_COLON_SLASH_LEN: usize = 6;

/// The scheme this stage stores, spelled as the literal at `lib/urlapi.c`
/// L838.
///
/// Lower-case regardless of how the input spelled it, which is what makes
/// the scheme comparisons elsewhere in the crate work on a plain byte
/// equality.
const SCHEME_FILE: &[u8] = b"file";

/// The first authority spelling accepted as local, `lib/urlapi.c` L874.
///
/// The trailing slash is part of the prefix, not decoration: it is what
/// distinguishes `file://localhost/x` from a host named `localhostx`, and it
/// is why `file://localhost` with nothing after it is not accepted.
const LOCALHOST_PREFIX: &[u8] = b"localhost/";

/// The second authority spelling accepted as local, `lib/urlapi.c` L875.
const LOOPBACK_PREFIX: &[u8] = b"127.0.0.1/";

/// How far `lib/urlapi.c` L876 advances past a local authority: nine bytes
/// of a ten-byte prefix, leaving the cursor on the slash.
///
/// See the module documentation. This is deliberate in the original and must
/// not be "corrected" to the prefix length.
const LOCAL_HOST_SKIP: usize = 9;

/// The bytes a NetBIOS computer name cannot contain, `lib/urlapi.c` L885.
///
/// The C passes them to `strpbrk` as the literal `"/\\:*?\"<>|"`, which is
/// nine characters once the two C escapes are resolved.
#[cfg(windows)]
const UNC_DELIMITERS: &[u8] = b"/\\:*?\"<>|";

// Pinned under the same gate as the constant, because the claim above is
// about escape resolution and nothing else checks it: a backslash written
// singly or a quote written unescaped would change the set silently, and the
// Rust literal has to come out as the same nine bytes the C literal does.
#[cfg(windows)]
#[allow(clippy::assertions_on_constants)]
const _: () = {
    assert!(UNC_DELIMITERS.len() == 9);
};

// The four numbers above are pinned at compile time because two of them are
// load-bearing in a way a reader cannot check locally. `LOCAL_HOST_SKIP`
// must be one less than each prefix length, or every local `file:` URL loses
// the leading slash of its path; and `FILE_COLON_SLASH_LEN` must be one more
// than `FILE_PREFIX_LEN`, or the entry gate and the path offset disagree
// about where the scheme ends. The relationships are written as the
// arithmetic-free comparisons the crate's denial of unchecked arithmetic
// leaves available, with each side stated as a literal.
//
// The assertions are gathered into one block so that a single allow covers
// them, following `src/inet.rs`, whose own block carries the measured account
// of why the allow is kept: on the pinned toolchain the lint does not fire for
// comparisons of named numeric constants at all, and the attribute is retained
// as a deliberate scoped exception for the declared 1.75 floor rather than to
// silence a finding.
#[allow(clippy::assertions_on_constants)]
const _: () = {
    assert!(FILE_PREFIX_LEN == 5);
    assert!(FILE_COLON_SLASH_LEN == 6);
    assert!(LOCAL_HOST_SKIP == 9);
    assert!(LOCALHOST_PREFIX.len() == 10);
    assert!(LOOPBACK_PREFIX.len() == 10);
};

/// The byte at `index`, or zero when `index` is past the end.
///
/// This is the whole of this module's NUL model, described in the module
/// documentation: the caller hands over the bytes before the terminator, and
/// a C read of `str[i]` at or past that point yields the terminator itself.
/// Returning zero is therefore not a fallback, it is the value C reads.
///
/// Written as a `match` rather than with an `Option` combinator so that the
/// file contains no spelling of the panicking constructs the crate root
/// denies, not even as part of a longer, harmless method name.
fn byte_at(bytes: &[u8], index: usize) -> u8 {
    match bytes.get(index) {
        Some(&byte) => byte,
        None => 0,
    }
}

/// Everything from `from` onward, or nothing when `from` is past the end.
///
/// The C's `&path[1]` and `&url[5]`, expressed so that no offset can address
/// outside the slice. `from == bytes.len()` yields an empty slice, which is
/// the position of the terminator and a legitimate cursor: `file://` parks
/// the cursor exactly there.
fn tail(bytes: &[u8], from: usize) -> &[u8] {
    match bytes.get(from..) {
        Some(rest) => rest,
        None => &[],
    }
}

/// A drive prefix as a URL may spell it: `c:`, `c|`, then a slash, a
/// backslash or the end of the string.
///
/// `STARTS_WITH_URL_DRIVE_PREFIX`, `lib/urlapi.c` L46-L52, which is **not**
/// platform-gated in the original and is not gated here either. It has four
/// call sites, all in this module: L871, where a drive prefix in the
/// authority position suppresses the host analysis; L917 and L918, the
/// off-Windows rejection; and L924, the Windows leading-slash strip.
///
/// The `|` alternative is historical URL spelling for the drive separator,
/// and the terminator alternative is what lets a URL end immediately after
/// the drive: `file://c:` matches, on the strength of a byte this module
/// models rather than reads.
#[must_use]
pub(crate) fn starts_with_url_drive_prefix(bytes: &[u8]) -> bool {
    // Read all three positions first, so the three lines below read as the
    // three lines of the macro do.
    let letter = byte_at(bytes, 0);
    let separator = byte_at(bytes, 1);
    let follower = byte_at(bytes, 2);
    // L49-L50 spells the letter test as two explicit ranges;
    // `crate::ctype::is_alpha` is that same disjunction, ported from
    // `ISALPHA` at `lib/curl_ctype.h` L38, and reusing it keeps one
    // definition of "a letter" in the crate.
    is_alpha(letter)
        && (separator == b':' || separator == b'|')
        // L52. Zero is the terminating NUL, per [`byte_at`].
        && (follower == b'/' || follower == b'\\' || follower == 0)
}

/// A drive prefix as MS-DOS spells it: a letter and a colon, and nothing is
/// required after them.
///
/// `STARTS_WITH_DRIVE_PREFIX`, `lib/urlapi.c` L38-L44, gated there by
/// `#ifdef _WIN32` and gated here by `cfg(windows)` for the same reason.
///
/// It is the stricter two-byte form: no `|` alternative and no requirement
/// on the third byte, so it matches `c:foo` where
/// [`starts_with_url_drive_prefix`] does not. Its only C call site is L191,
/// inside `Curl_is_absolute_url`, where a drive prefix stops a path such as
/// `c:/x` from being read as a scheme named `c` -- and only when scheme
/// guessing is on. That belongs to the scheme stage rather than to this one;
/// it is ported here because it is one of the two macros this module owns,
/// and it is `pub(crate)` so the scheme stage can use it rather than
/// restate it.
#[cfg(windows)]
#[must_use]
pub(crate) fn starts_with_drive_prefix(bytes: &[u8]) -> bool {
    is_alpha(byte_at(bytes, 0)) && byte_at(bytes, 1) == b':'
}

/// The authority that is neither empty, nor local, nor a drive prefix:
/// a UNC host. Windows arm, `lib/urlapi.c` L879-L897.
///
/// # Parameters
///
/// - `rest`: the bytes from the cursor onward, that is the C's `ptr`.
/// - `ptr`: where that cursor sits in the URL, so the rewind can be
///   expressed as an offset rather than as pointer arithmetic.
/// - `host`: the caller's host buffer, appended to on success.
///
/// # Returns
///
/// The rewound cursor and whether a host was stored, that is the C's `ptr`
/// after L897 and its `uncpath` after L894. Returning both keeps the caller
/// free of any `cfg`, which is what lets the two platform arms of this
/// function differ without the parse flow differing.
///
/// # Errors
///
/// `CURLUE_BAD_FILE_URL` when the name is unterminated or is terminated by
/// something other than a slash, L886-L887; or a folded dynamic-buffer
/// failure, L891-L893.
#[cfg(windows)]
fn unc_authority(rest: &[u8], ptr: usize, host: &mut DynBuf) -> Result<(usize, bool), CURLUcode> {
    let mut uncpath = false;

    // L882-L887. `strpbrk` finds the first byte of the set anywhere in the
    // remainder of the string, so the search is over the whole tail rather
    // than over the authority alone; the delimiter it lands on must be the
    // slash that ends the host name. A `None` here is the C's null return,
    // which is the `file://hello.html` case at
    // `tests/libtest/lib1560.c` L436: no delimiter at all, so no host name
    // can be delimited, so the URL is bad -- on this platform as much as on
    // any other.
    let stop = match rest.iter().position(|byte| UNC_DELIMITERS.contains(byte)) {
        Some(at) if byte_at(rest, at) == b'/' => at,
        _ => return Err(CURLUE_BAD_FILE_URL),
    };

    // L889-L895. The name is everything before that slash, and the slash
    // itself stays in the path.
    if stop != 0 {
        let name = match rest.get(..stop) {
            Some(bytes) => bytes,
            // Unreachable: `position` returned an index inside `rest`, so
            // the range is in bounds by construction. Reported rather than
            // asserted, because this crate has no panic paths.
            None => return Err(CURLUE_BAD_FILE_URL),
        };
        // The bytes are copied into the caller's buffer; nothing changes
        // hands. A failure has already released that buffer, so the code is
        // folded and returned without a second release.
        let code = host.addn(name);
        if code.is_err() {
            return Err(cc2cu(code));
        }
        uncpath = true;
    }

    // L897. Rewind over the two slashes so the path keeps the `//` that
    // makes it a UNC path: `file://host/Share/x` yields `//host/Share/x`,
    // which is the shape `tests/libtest/lib1560.c` L371-L373 asserts.
    //
    // The subtraction is safe for a reason the compiler cannot see: the only
    // caller reaches here from inside the two-slash branch, where the cursor
    // was set to the path offset plus two, so it is at least
    // `FILE_PREFIX_LEN + 2`. It saturates rather than wraps because the
    // crate denies unchecked arithmetic, and saturation is unreachable.
    Ok((ptr.saturating_sub(2), uncpath))
}

/// The authority that is neither empty, nor local, nor a drive prefix:
/// rejected outright. Non-Windows arm, `lib/urlapi.c` L899-L901.
///
/// The C comment is exact about the rule -- `localhost`, `127.0.0.1` or
/// nothing -- and there is no fallback: a name that would resolve to this
/// machine is still refused, which is the subset described in the module
/// documentation. `tests/libtest/lib1560.c` L436 asserts it for
/// `file://hello.html`.
///
/// The parameters exist to match the Windows arm's signature, which is what
/// keeps `cfg` out of the caller.
#[cfg(not(windows))]
fn unc_authority(
    _rest: &[u8],
    _ptr: usize,
    _host: &mut DynBuf,
) -> Result<(usize, bool), CURLUcode> {
    Err(CURLUE_BAD_FILE_URL)
}

/// Drive letters are not accepted off Windows, `lib/urlapi.c` L914-L921.
///
/// Both spellings are rejected, and the C comment at L915-L916 says which:
/// `file:/c:` reaches here as a path of `/c:`, matching the first test, and
/// `file:c:` reaches here as a path of `c:`, matching the second. A
/// `file://c:/x` URL also arrives here as `c:/x`, because the drive prefix
/// suppressed the host analysis at L871, and is rejected by the same second
/// test -- so off Windows the two branches converge on one code, and only
/// [`starts_with_url_drive_prefix`] itself can distinguish them.
#[cfg(not(any(windows, target_os = "cygwin")))]
fn apply_drive_letter_rule(path: &[u8]) -> Result<&[u8], CURLUcode> {
    // L917-L918. The first test looks one byte in, the second at the start.
    if (byte_at(path, 0) == b'/' && starts_with_url_drive_prefix(tail(path, 1)))
        || starts_with_url_drive_prefix(path)
    {
        return Err(CURLUE_BAD_FILE_URL);
    }
    Ok(path)
}

/// A drive letter behind a leading slash loses the slash, `lib/urlapi.c`
/// L922-L928.
///
/// `file:///C:\programs\foo` has a path of `/C:\programs\foo` and must yield
/// `C:\programs\foo`, which is what `tests/libtest/lib1560.c` L368-L370
/// asserts. The C notes at L925 that `strcpy` cannot do this because the
/// source and destination overlap; a subslice has no such problem, and
/// dropping the first byte is also what makes the length follow
/// automatically where the C has to decrement `pathlen` by hand at L927.
///
/// This is the arm for `_WIN32`, `MSDOS` and `__CYGWIN__`. MS-DOS is
/// unrepresentable as a Rust target and is discussed in the module
/// documentation.
#[cfg(any(windows, target_os = "cygwin"))]
// This arm cannot fail, where the other one can. The shared `Result` is what
// keeps the call site identical on both platforms, and a vacuous `Ok` is a
// smaller cost than a `cfg` in the parse flow.
#[allow(clippy::unnecessary_wraps)]
fn apply_drive_letter_rule(path: &[u8]) -> Result<&[u8], CURLUcode> {
    if byte_at(path, 0) == b'/' && starts_with_url_drive_prefix(tail(path, 1)) {
        return Ok(tail(path, 1));
    }
    Ok(path)
}

/// Parses a `file:` URL: stores the scheme, decides the host, and reports the
/// path.
///
/// `parse_file` at `lib/urlapi.c` L823-L933. The module documentation carries
/// the RFC 8089 subset, the NUL model, the platform mapping and the ownership
/// rules; what follows is the contract.
///
/// # Parameters
///
/// - `url`: the whole URL, from its first byte, holding exactly the bytes
///   `Curl_junkscan` measured -- no terminator. The caller must already have
///   established, through `Curl_is_absolute_url`, that it begins with a
///   `file` scheme name and a colon in some case; those five bytes are
///   skipped unread. This is the C's `url` together with its `urllen`.
/// - `u`: the handle being filled. Only the scheme field is touched.
/// - `host`: the caller's host buffer, freshly initialized. Left holding a
///   UNC host name on Windows, and reset on every other path.
///
/// # Returns
///
/// The path, as a subslice of `url`: the C's `*pathp` with the C's
/// `*pathlenp` as its length. Any query and any fragment are still part of
/// it, for the caller to trim.
///
/// # Errors
///
/// - `CURLUE_BAD_FILE_URL` for an input of six bytes or fewer, L830-L832;
///   for an unacceptable authority, L901 off Windows and L887 on it; and for
///   a drive letter off Windows, L920.
/// - `CURLUE_OUT_OF_MEMORY` when the scheme cannot be allocated, L840.
/// - `CURLUE_TOO_LARGE` or `CURLUE_OUT_OF_MEMORY`, folded by `cc2cu`, when
///   storing a UNC host name fails, L893.
///
/// On every failure path after L838 the handle owns a scheme. That matches
/// the C, whose caller releases the whole handle at L1190.
pub(crate) fn parse_file<'u>(
    url: &'u [u8],
    u: &mut CurlUrl,
    host: &mut DynBuf,
) -> Result<&'u [u8], CURLUcode> {
    // The C is handed the length separately, from `Curl_junkscan`; a slice
    // arrives measured, as in `src/parse/junk.rs`.
    let urllen = url.len();

    // L830-L832, before anything is allocated, so a rejected input costs
    // nothing and no partially filled handle is produced.
    if urllen <= FILE_COLON_SLASH_LEN {
        return Err(CURLUE_BAD_FILE_URL);
    }

    // L835-L836: the path starts after `"file:"`. Held as an offset into
    // `url` rather than as a slice, because the UNC arm rewinds it and an
    // offset is the only representation in which the rewind is checkable.
    // `pathlen` needs no variable: it is `urllen - path` at every point in
    // this function, which is exactly the length of `tail(url, path)`.
    let mut path = FILE_PREFIX_LEN;

    // L838-L840. The literal is stored, not the input's five bytes, so the
    // stored scheme is lower-case whatever the URL said. The buffer comes
    // from the C allocator and the handle takes ownership of it here.
    match CBuf::from_slice(SCHEME_FILE) {
        Some(scheme) => u.store(StringField::Scheme, scheme),
        None => return Err(CURLUE_OUT_OF_MEMORY),
    }

    // L829. Set by the UNC arm alone, and read once, at L910.
    let mut uncpath = false;

    // L848: an authority component is present only if two slashes follow the
    // colon. Both reads are in bounds -- the gate above guarantees at least
    // two bytes here -- but they go through `byte_at` anyway, because the
    // crate denies direct indexing and a uniform accessor is what makes the
    // NUL model consistent across the function.
    if byte_at(url, path) == b'/' && byte_at(url, path.saturating_add(1)) == b'/' {
        // L849-L850: swallow the two slashes. Every offset addition in this
        // function saturates because the crate denies unchecked arithmetic;
        // none can actually clamp, since `urllen` is bounded by
        // `CURL_MAX_INPUT_LENGTH` and these add single digits to it.
        let mut ptr = path.saturating_add(2);

        // L871: a third slash means the authority is empty, and a drive
        // prefix means those bytes are a path rather than a host. Either way
        // the host analysis is skipped entirely, which is how
        // `file:///hello.html` and `file:////hello.html` at
        // `tests/libtest/lib1560.c` L460-L465 keep their leading slashes.
        let rest = tail(url, ptr);
        if byte_at(url, ptr) != b'/' && !starts_with_url_drive_prefix(rest) {
            // L872-L877: the URL carries a host name, and only these two
            // spellings are local. Case-insensitive, and the nine-byte skip
            // deliberately stops on the slash. See the module documentation.
            if starts_with_ignore_case(rest, LOCALHOST_PREFIX)
                || starts_with_ignore_case(rest, LOOPBACK_PREFIX)
            {
                ptr = ptr.saturating_add(LOCAL_HOST_SKIP);
            } else {
                // L878-L903: a UNC host on Windows, a hard error anywhere
                // else. The platform difference lives entirely inside
                // `unc_authority`, so this flow reads the same either way.
                let (rewound, stored) = unc_authority(rest, ptr, host)?;
                ptr = rewound;
                uncpath = stored;
            }
        }

        // L906-L907. The C recomputes `pathlen` from the original `url`
        // base, so it stays right whether the cursor advanced by nine or
        // rewound by two; taking the tail at the final offset is that same
        // computation.
        path = ptr;
    }

    // L910-L912: a `file:` URL has no host unless a UNC name was stored.
    // Note that this discards `localhost` and `127.0.0.1` rather than
    // recording them, and that it runs after the UNC append, which sets
    // `uncpath` only for a name of non-zero length -- so an empty UNC name
    // is reset away like any other.
    if !uncpath {
        host.reset();
    }

    // L914-L929, then L930-L932: the platform-conditional drive-letter rule
    // decides between rejecting the URL and shortening the path, and its
    // result is what the C writes through `*pathp` and `*pathlenp`.
    apply_drive_letter_rule(tail(url, path))
}

#[cfg(test)]
mod tests {
    // Every expectation below is taken from a row of
    // `tests/libtest/lib1560.c` where one exists, because that file is the
    // oracle the parity run diffs against and RFC 8089 is not: the C
    // implements a deliberate subset of it. The row is cited at each test.
    //
    // The crate root denies the panicking constructs so that no panic can
    // ever reach the C boundary. A test never crosses that boundary, so the
    // denials are relaxed here and only here, enumerated rather than blanket,
    // matching `src/dynbuf.rs` and `src/scheme.rs`. One construct is needed:
    // the length property below states an expectation as a subtraction, and
    // saturating it would weaken the very check it makes. Nothing here
    // unwraps an `Option` or indexes a slice, so those denials stand.
    #![allow(clippy::arithmetic_side_effects)]

    use super::{parse_file, starts_with_url_drive_prefix};
    use crate::abi::{CURLUcode, CURLUE_BAD_FILE_URL, CURL_MAX_INPUT_LENGTH};
    use crate::dynbuf::DynBuf;
    use crate::handle::CurlUrl;

    /// Runs the stage over `url` and hands back everything it can be judged
    /// by: the result, the handle it filled and the host buffer it decided.
    ///
    /// The handle and the buffer move out, which is possible because the
    /// borrows the call takes end with it; the returned path borrows `url`
    /// alone, exactly as the C's `*pathp` points into the caller's string.
    ///
    /// The ceiling is `CURL_MAX_INPUT_LENGTH`, which is what `parseurl`
    /// passes to `curlx_dyn_init` at `lib/urlapi.c` L1122.
    fn parse(url: &[u8]) -> (Result<&[u8], CURLUcode>, CurlUrl, DynBuf) {
        let mut u = CurlUrl::new();
        let mut host = DynBuf::new(CURL_MAX_INPUT_LENGTH);
        let outcome = parse_file(url, &mut u, &mut host);
        (outcome, u, host)
    }

    /// `lib/urlapi.c` L830-L832 and `tests/libtest/lib1560.c` L454-L456.
    ///
    /// The gate precedes the allocation at L838, so a rejected input leaves
    /// the handle untouched. The two shortest inputs are here as well,
    /// because a slice-based port has to survive them where a pointer-based
    /// one is simply never handed them.
    #[test]
    fn six_bytes_or_fewer_is_rejected_before_anything_is_stored() {
        for url in [
            b"file:/".as_slice(),
            b"file:".as_slice(),
            b"file".as_slice(),
            b"f".as_slice(),
            b"".as_slice(),
        ] {
            let (outcome, u, host) = parse(url);
            assert_eq!(outcome, Err(CURLUE_BAD_FILE_URL), "{url:?}");
            assert_eq!(u.scheme(), None, "{url:?}");
            assert!(host.is_empty(), "{url:?}");
        }
    }

    /// The `<=` at L830 makes seven bytes the shortest acceptable input, and
    /// `tests/libtest/lib1560.c` L451-L453 asserts exactly that input.
    #[test]
    fn seven_bytes_is_the_shortest_accepted_input() {
        let (outcome, u, host) = parse(b"file:/h");
        assert_eq!(outcome, Ok(b"/h".as_slice()));
        assert_eq!(u.scheme(), Some(b"file".as_slice()));
        assert!(host.is_empty());
    }

    /// L838 stores the literal, so the case the URL used is irrelevant.
    ///
    /// `parseurl` reaches this stage by comparing the lower-cased
    /// `schemebuf`, L1133, which is why `FILE:` gets here at all. The five
    /// bytes of the input are skipped unread.
    #[test]
    fn the_stored_scheme_is_the_lower_case_literal() {
        for url in [
            b"FILE:/x".as_slice(),
            b"File:/x".as_slice(),
            b"file:/x".as_slice(),
        ] {
            let (outcome, u, _host) = parse(url);
            assert_eq!(outcome, Ok(b"/x".as_slice()), "{url:?}");
            assert_eq!(u.scheme(), Some(b"file".as_slice()), "{url:?}");
        }
    }

    /// `tests/libtest/lib1560.c` L463-L465: three slashes, an empty
    /// authority, and a path that keeps its leading slash.
    #[test]
    fn an_empty_authority_leaves_the_path_and_no_host() {
        let (outcome, u, host) = parse(b"file:///hello.html");
        assert_eq!(outcome, Ok(b"/hello.html".as_slice()));
        assert_eq!(u.scheme(), Some(b"file".as_slice()));
        assert!(host.is_empty());
        assert_eq!(u.host(), None);
    }

    /// `tests/libtest/lib1560.c` L460-L462. The fourth slash is part of the
    /// path: `ptr[0]` is a slash at L871, so the host analysis never runs
    /// and the cursor stays where the two swallowed slashes left it.
    #[test]
    fn a_fourth_slash_belongs_to_the_path() {
        let (outcome, _u, host) = parse(b"file:////hello.html");
        assert_eq!(outcome, Ok(b"//hello.html".as_slice()));
        assert!(host.is_empty());
    }

    /// The nine-byte skip at L876, landing on the slash rather than past it.
    /// `tests/libtest/lib1560.c` L457-L459 for the loopback spelling.
    #[test]
    fn a_local_authority_is_discarded_and_its_slash_becomes_the_path() {
        for url in [
            b"file://localhost/path".as_slice(),
            b"file://127.0.0.1/path".as_slice(),
        ] {
            let (outcome, u, host) = parse(url);
            assert_eq!(outcome, Ok(b"/path".as_slice()), "{url:?}");
            // The authority matched, and was then thrown away by the reset
            // at L910-L912 rather than stored.
            assert!(host.is_empty(), "{url:?}");
            assert_eq!(u.host(), None, "{url:?}");
        }
    }

    /// `checkprefix` is `curl_strnequal`, `lib/strcase.h` L33, so the
    /// authority test folds case. The loopback spelling has no letters, so
    /// only the name is exercised here.
    #[test]
    fn the_local_authority_test_folds_case() {
        for url in [
            b"file://LOCALHOST/path".as_slice(),
            b"file://LocalHost/path".as_slice(),
            b"file://lOcAlHoSt/path".as_slice(),
        ] {
            let (outcome, _u, host) = parse(url);
            assert_eq!(outcome, Ok(b"/path".as_slice()), "{url:?}");
            assert!(host.is_empty(), "{url:?}");
        }
    }

    /// The trailing slash is part of both prefixes, L874-L875, so an
    /// authority that merely starts with one of them is not local.
    ///
    /// `file://localhost` fails on every platform: off Windows because no
    /// other authority is accepted, and on Windows because `strpbrk` at L885
    /// finds no delimiter to end the name with. That is the same reason
    /// `tests/libtest/lib1560.c` L436-L438 expects `file://hello.html` to
    /// fail, and that row sits outside the `#ifdef _WIN32` block precisely
    /// because it holds everywhere.
    #[test]
    fn an_unterminated_authority_is_rejected_on_every_platform() {
        for url in [
            b"file://localhost".as_slice(),
            b"file://127.0.0.1".as_slice(),
            b"file://hello.html".as_slice(),
        ] {
            let (outcome, u, _host) = parse(url);
            assert_eq!(outcome, Err(CURLUE_BAD_FILE_URL), "{url:?}");
            // L838 ran before the authority analysis, so the handle owns a
            // scheme even though the parse failed. `parseurl` releases the
            // whole handle at L1190.
            assert_eq!(u.scheme(), Some(b"file".as_slice()), "{url:?}");
        }
    }

    /// `tests/libtest/lib1560.c` L448-L450: the single-slash form of RFC
    /// 8089, which never enters the authority branch at all.
    #[test]
    fn a_single_slash_needs_no_authority() {
        let (outcome, _u, host) = parse(b"file:/hello.html");
        assert_eq!(outcome, Ok(b"/hello.html".as_slice()));
        assert!(host.is_empty());
    }

    /// `tests/libtest/lib1560.c` L778: `file:./` parses, because nothing in
    /// this stage requires the path to start with a slash. The dot segments
    /// are the later path stage's business.
    #[test]
    fn a_path_that_starts_with_a_dot_is_left_alone() {
        let (outcome, _u, host) = parse(b"file:./");
        assert_eq!(outcome, Ok(b"./".as_slice()));
        assert!(host.is_empty());
    }

    /// The query and the fragment are still in the path when this stage
    /// returns, because `parseurl` trims them afterwards at L1162-L1180.
    ///
    /// `tests/libtest/lib1560.c` L1356-L1359 is the row that depends on it,
    /// and L775 is the fragment-only case.
    #[test]
    fn the_query_and_the_fragment_stay_in_the_path() {
        let (outcome, _u, _host) = parse(b"file://localhost/path?query#frag");
        assert_eq!(outcome, Ok(b"/path?query#frag".as_slice()));

        let (outcome, _u, _host) = parse(b"file:///file.txt#moo");
        assert_eq!(outcome, Ok(b"/file.txt#moo".as_slice()));

        let (outcome, _u, _host) = parse(b"file:///basic?hello");
        assert_eq!(outcome, Ok(b"/basic?hello".as_slice()));
    }

    /// The returned slice is the C's pair, and the C's `pathlen` is always
    /// `urllen - (path - url)`: L836, L907 and L927 are the three places it
    /// is written, and each keeps that identity.
    ///
    /// Checked here as a property rather than as three literals, so that a
    /// future edit that recomputes a length independently is caught.
    #[test]
    fn the_length_is_always_the_remainder_of_the_input() {
        for (url, offset) in [
            (b"file:/hello.html".as_slice(), 5),
            (b"file:///hello.html".as_slice(), 7),
            (b"file:////hello.html".as_slice(), 7),
            (b"file://localhost/path".as_slice(), 16),
            (b"file://127.0.0.1/path".as_slice(), 16),
        ] {
            let (outcome, _u, _host) = parse(url);
            // Comparing the mapped result rather than matching on it keeps
            // the failure case an assertion rather than a second panic path:
            // an `Err` here fails the comparison and reports its code.
            assert_eq!(
                outcome.map(|path| path.len()),
                Ok(url.len() - offset),
                "{url:?}"
            );
        }
    }

    /// `STARTS_WITH_URL_DRIVE_PREFIX`, `lib/urlapi.c` L46-L52, over the
    /// cases each of its three clauses decides.
    ///
    /// The terminator clause at L52 is the interesting one: `c:` matches on
    /// the strength of the byte after the drive separator being the C
    /// string's NUL, which this port models as a read past the end of the
    /// slice.
    #[test]
    fn the_url_drive_prefix_predicate_matches_the_macro() {
        for accepted in [
            b"c:/".as_slice(),
            b"C:/".as_slice(),
            b"z:\\".as_slice(),
            b"c|/".as_slice(),
            b"c|\\".as_slice(),
            b"c:".as_slice(),
            b"c|".as_slice(),
            b"c:/rest/of/path".as_slice(),
        ] {
            assert!(
                starts_with_url_drive_prefix(accepted),
                "{accepted:?} should match"
            );
        }

        for rejected in [
            // Not a letter.
            b"1:/".as_slice(),
            b":/".as_slice(),
            b"/c:/".as_slice(),
            // Not a drive separator.
            b"cc/".as_slice(),
            b"c;/".as_slice(),
            b"c./".as_slice(),
            // A letter and a separator, but the wrong third byte.
            b"c:x".as_slice(),
            b"c|?".as_slice(),
            // Too short to be anything.
            b"c".as_slice(),
            b"".as_slice(),
        ] {
            assert!(
                !starts_with_url_drive_prefix(rejected),
                "{rejected:?} should not match"
            );
        }
    }

    /// A drive prefix in the authority position suppresses the host analysis
    /// at L871, which is the exception the comment at L867-L869 describes.
    ///
    /// Off Windows the two branches converge on `CURLUE_BAD_FILE_URL`: the
    /// drive prefix skips the host analysis, and the check at L917-L918 then
    /// rejects the very same bytes. Only the predicate can show which branch
    /// ran, so it is asserted alongside, and the Windows test below pins the
    /// path the drive branch produces.
    #[test]
    fn a_drive_authority_takes_the_drive_branch() {
        assert!(starts_with_url_drive_prefix(b"c:/x"));
        let (outcome, u, _host) = parse(b"file://c:/x");
        assert_eq!(u.scheme(), Some(b"file".as_slice()));
        #[cfg(not(any(windows, target_os = "cygwin")))]
        assert_eq!(outcome, Err(CURLUE_BAD_FILE_URL));
        #[cfg(any(windows, target_os = "cygwin"))]
        assert_eq!(outcome, Ok(b"c:/x".as_slice()));
    }

    /// `lib/urlapi.c` L914-L921, whose comment names both spellings it
    /// catches: `file:/c:` and `file:c:`.
    ///
    /// The `|` separator and the bare drive with nothing after it are here
    /// too, because both are reachable through the same macro.
    #[cfg(not(any(windows, target_os = "cygwin")))]
    #[test]
    fn drive_letters_are_refused_off_windows() {
        for url in [
            b"file:/c:/x".as_slice(),
            b"file:c:/x".as_slice(),
            b"file://c:/x".as_slice(),
            b"file:/c|/x".as_slice(),
            b"file:c|/x".as_slice(),
            b"file:/c:".as_slice(),
            b"file:/C:\\programs\\foo".as_slice(),
            b"file:///C:\\programs".as_slice(),
        ] {
            let (outcome, u, _host) = parse(url);
            assert_eq!(outcome, Err(CURLUE_BAD_FILE_URL), "{url:?}");
            assert_eq!(u.scheme(), Some(b"file".as_slice()), "{url:?}");
        }
    }

    /// A path that merely looks like a drive is not one, so it survives the
    /// rejection above.
    #[test]
    fn a_path_that_is_not_a_drive_prefix_survives() {
        for (url, path) in [
            // Two letters before the colon.
            (b"file:/cc:/x".as_slice(), b"/cc:/x".as_slice()),
            // A digit where the letter must be.
            (b"file:/1:/x".as_slice(), b"/1:/x".as_slice()),
            // A letter and a colon, but the third byte is neither a
            // separator nor the end.
            (b"file:/c:x".as_slice(), b"/c:x".as_slice()),
        ] {
            let (outcome, _u, _host) = parse(url);
            assert_eq!(outcome, Ok(path), "{url:?}");
        }
    }

    /// `lib/urlapi.c` L922-L928 and `tests/libtest/lib1560.c` L362-L370,
    /// which are compiled only under `#ifdef _WIN32`.
    ///
    /// Compiled here on the same condition and, per the plan's
    /// non-functional constraints, **not** exercised by the parity workflow,
    /// which runs on a platform where this test does not exist.
    #[cfg(any(windows, target_os = "cygwin"))]
    #[test]
    fn a_slash_before_a_drive_letter_is_dropped_on_windows() {
        for (url, path) in [
            // The row at lib1560.c L362: the single-slash form.
            (
                b"file:/C:\\programs\\foo".as_slice(),
                b"C:\\programs\\foo".as_slice(),
            ),
            // L368: three slashes, so the strip happens after the empty
            // authority is swallowed.
            (
                b"file:///C:\\programs\\foo".as_slice(),
                b"C:\\programs\\foo".as_slice(),
            ),
            // L365: the drive sits in the authority position, so L871
            // suppresses the host analysis and no strip is needed.
            (
                b"file://C:\\programs\\foo".as_slice(),
                b"C:\\programs\\foo".as_slice(),
            ),
        ] {
            let (outcome, u, host) = parse(url);
            assert_eq!(outcome, Ok(path), "{url:?}");
            assert_eq!(u.scheme(), Some(b"file".as_slice()), "{url:?}");
            assert!(host.is_empty(), "{url:?}");
        }
    }

    /// `lib/urlapi.c` L879-L897 and `tests/libtest/lib1560.c` L371-L374:
    /// the authority becomes the host, and the path keeps the `//` that the
    /// rewind at L897 restores.
    ///
    /// Windows only, and not exercised by the parity workflow.
    #[cfg(windows)]
    #[test]
    fn a_unc_authority_becomes_the_host_and_keeps_its_slashes() {
        let (outcome, _u, host) = parse(b"file://host.example.com/Share/path/to/file.txt");
        assert_eq!(
            outcome,
            Ok(b"//host.example.com/Share/path/to/file.txt".as_slice())
        );
        assert_eq!(host.as_bytes(), b"host.example.com".as_slice());
    }

    /// The delimiter `strpbrk` lands on must be the slash, L886-L887.
    ///
    /// A colon in the authority reaches the delimiter set first, so the name
    /// is never stored and the URL is refused rather than read as a host and
    /// a port -- there is no port parsing on this path at all.
    ///
    /// Windows only, and not exercised by the parity workflow.
    #[cfg(windows)]
    #[test]
    fn a_unc_authority_stopped_by_the_wrong_delimiter_is_refused() {
        for url in [
            b"file://host:8080/share".as_slice(),
            b"file://ho*st/share".as_slice(),
            b"file://ho|st/share".as_slice(),
            b"file://host.example.com".as_slice(),
        ] {
            let (outcome, _u, host) = parse(url);
            assert_eq!(outcome, Err(CURLUE_BAD_FILE_URL), "{url:?}");
            assert!(host.is_empty(), "{url:?}");
        }
    }

    /// `STARTS_WITH_DRIVE_PREFIX`, `lib/urlapi.c` L38-L44: the stricter
    /// two-byte form, which imposes nothing on the third byte.
    ///
    /// Windows only, as in the original, and not exercised by the parity
    /// workflow.
    #[cfg(windows)]
    #[test]
    fn the_plain_drive_prefix_predicate_matches_the_macro() {
        use super::starts_with_drive_prefix;

        for accepted in [
            b"c:".as_slice(),
            b"C:".as_slice(),
            // Where the URL form insists on a slash, a backslash or the
            // end, this one accepts anything.
            b"c:foo".as_slice(),
            b"c:/foo".as_slice(),
        ] {
            assert!(starts_with_drive_prefix(accepted), "{accepted:?}");
        }

        for rejected in [
            // The `|` alternative belongs to the URL form only.
            b"c|".as_slice(),
            b"1:".as_slice(),
            b"cc".as_slice(),
            b"c".as_slice(),
            b"".as_slice(),
        ] {
            assert!(!starts_with_drive_prefix(rejected), "{rejected:?}");
        }
    }
}
