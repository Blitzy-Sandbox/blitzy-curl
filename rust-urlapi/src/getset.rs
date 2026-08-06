// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Part retrieval and part assignment: the module the observable behaviour
//! lives in.
//!
//! The port of eight functions of `lib/urlapi.c`, in the order the C file
//! declares them:
//!
//! | C function | C lines | Here |
//! |------------|---------|------|
//! | `urlget_format` | L1357-L1423 | [`urlget_format`] |
//! | `urlget_url` | L1425-L1539 | [`urlget_url`] |
//! | `curl_url_get` | L1541-L1634 | [`url_get`] |
//! | `set_url_scheme` | L1636-L1664 | [`set_url_scheme`] |
//! | `set_url_port` | L1666-L1683 | [`set_url_port`] |
//! | `set_url` | L1685-L1730 | [`set_url`] |
//! | `urlset_clear` | L1732-L1777 | [`urlset_clear`] |
//! | `curl_url_set` | L1805-L1998 | [`url_set`] |
//!
//! `allowed_in_path` at L1779-L1803 belongs to the same span and is not here:
//! it is a property of the encoder and lives in `src/encode.rs` with the loop
//! that consults it.
//!
//! # What this module does not do
//!
//! It never sees a pointer. `src/ffi.rs` owns the two exported entry points
//! and with them every precondition the C checks against a raw pointer: the
//! null handle at L1548-L1549 and L1817-L1818, the null part pointer at
//! L1550-L1551, the `*part = NULL` at L1552, and the null-part-clears rule at
//! L1819-L1821. What arrives here is a reference, a `CURLUPart`, an
//! `Option<&[u8]>` and a flag word, and what leaves is an owned buffer or a
//! code. The module therefore carries `#![forbid(unsafe_code)]` and the
//! single-unsafe-island property of the crate is a compiler guarantee here
//! rather than a convention.
//!
//! # Why the control-flow shape is the specification
//!
//! Almost nothing in this file is an algorithm. What it is instead is a set
//! of conditionals whose *shape* is load-bearing, and each one is preserved
//! rather than paraphrased:
//!
//! * **The three conversions of [`urlget_format`] are one `if / else if`
//!   chain**, L1392-L1420, so they are mutually exclusive and their order is
//!   their precedence: url-encoding beats punycode, which beats
//!   depunyfication. Rewriting them as three independent tests changes the
//!   answer for a caller that passes two of the flags at once.
//! * **The default-port pair is an `if / else if`**, L1461-L1475 and again at
//!   L1586-L1602, and what selects between the two arms is *whether a port is
//!   stored*, not which flag the caller passed. The first arm is
//!   `!port && CURLU_DEFAULT_PORT` and the second is `else if(port)` with the
//!   `CURLU_NO_DEFAULT_PORT` test inside it, so for a caller passing **both**
//!   flags the answer depends on the handle: with no stored port the default
//!   is injected, with a stored port equal to the scheme's default it is
//!   suppressed, and with a stored port that differs it is kept. Neither flag
//!   has blanket precedence over the other. Collapsing the pair into two
//!   independent tests, or reading it as "the first flag wins", gets two of
//!   those three cases wrong.
//! * **Host validation in [`url_set`] is an `else if` chained to the
//!   append-query `if`**, L1936 and L1965, so a value that took the append
//!   path is never host-checked. Unreachable in practice, because
//!   `appendquery` is set only for `CURLUPART_QUERY`, and reproduced anyway.
//! * **`CURLUPART_PATH` never overrides `ifmissing`**, L1604-L1608, so its
//!   missing-code is still `CURLUE_UNKNOWN_PART`. The arm cannot reach it,
//!   because it substitutes `"/"` for an absent path, and there is no
//!   `CURLUE_NO_PATH` to tidy it into.
//! * **The scheme syntax loop is a pre-decrement**, L1652, so it inspects
//!   `plen - 1` bytes starting at the first. [`set_url_scheme`] ports the
//!   loop literally and says so at the site.
//!
//! # The two findings this module makes observable
//!
//! `FB1`, recorded in `rust-urlapi/docs/KNOWN-DIVERGENCES.md`: `curl_url_dup`
//! copies ten strings and three scalars but not `guessed_scheme`
//! (`src/handle.rs` owns that omission). This file is where the omission
//! becomes visible, at both of its sites:
//!
//! 1. [`url_get`] for `CURLUPART_SCHEME` refuses a guessed scheme under
//!    `CURLU_NO_GUESS_SCHEME`, L1559-L1560. On a duplicate the flag is no
//!    longer set, so the guessed scheme is returned instead of code 10.
//! 2. [`urlget_url`] suppresses the `scheme://` prefix under the same flag,
//!    L1512-L1515. On a duplicate the prefix reappears.
//!
//! `FB3`, same document: the zone identifier is asymmetric. [`urlset_clear`]
//! for `CURLUPART_HOST` releases the host and leaves `zoneid` alone, L1752-
//! L1753, while [`url_set`] for the same part releases `zoneid` at L1848.
//! [`urlget_url`] then emits the zone only for a bracketed host, L1480-L1491,
//! so a stale identifier is readable through `CURLUPART_ZONEID` while being
//! invisible in the serialized URL. All three are the source behaviour.
//!
//! # Memory ownership
//!
//! Every buffer this module produces for the caller is a
//! [`crate::alloc::CBuf`] or a [`crate::dynbuf::DynBuf`], and both allocate
//! through the C allocator. That is what makes `curl_free()` the correct
//! release once `src/ffi.rs` hands the pointer over, as
//! `docs/libcurl/curl_url_get.md:L45` and
//! `include/curl/urlapi.h:L130-L131` require, and
//! `include/curl/urlapi.h:L116-L118` adds that `curl_url_cleanup()` will not
//! release it. `rust-urlapi/docs/MEMORY-OWNERSHIP.md` records the whole
//! chain including the two configurations reported as unsupported.
//!
//! Inside the module ownership is the compiler's problem rather than the
//! reader's. The C has to reach `curlx_free(part)` on four separate failure
//! paths of `urlget_format` alone -- L1386, L1396, L1405 and L1415 -- and
//! `curlx_dyn_free(&enc)` on three of `curl_url_set` -- L1955, L1960 and
//! L1988. Here the owning types release on every path out, including the
//! early returns, so there is no path to miss.
//!
//! `CString::into_raw` is banned crate-wide: its pointer must return to Rust
//! to be deallocated, which no `curl_free()` caller will do. It appears
//! nowhere in this crate.
//!
//! # Panic posture
//!
//! Nothing here can panic. The crate root denies `unwrap`, `expect`,
//! `panic!`, direct indexing and unchecked arithmetic, so the panicking
//! constructs are designed out rather than caught: substituting an error code
//! for a panic would mask exactly the class of bug the parity diff exists to
//! expose. Every lookahead below is a `get`, `first`, `last` or `split_last`,
//! and every arithmetic step that could overflow in principle is a
//! `saturating_*` or `checked_*` call with the reason it cannot in practice.

// The plan puts every `unsafe` block in `src/ffi.rs` (0.3.3) and the
// technical specification forbids `unsafe` outside FFI code (1.3.2.1).
// `forbid` rather than `deny` because an inner `allow` here would be a design
// change and should have to be argued for, not slipped in. This module talks
// to no foreign code at all: the two capability lookups it needs, the scheme
// table and the internationalized-domain conversion, are reached through the
// uniform interfaces of `src/scheme.rs` and `src/idn.rs`.
#![forbid(unsafe_code)]

use core::ffi::{c_uint, CStr};

use crate::abi::{
    CURLUPart, CURLUcode, CURLUE_BAD_HOSTNAME, CURLUE_BAD_PORT_NUMBER, CURLUE_BAD_SCHEME,
    CURLUE_MALFORMED_INPUT, CURLUE_NO_FRAGMENT, CURLUE_NO_HOST, CURLUE_NO_OPTIONS,
    CURLUE_NO_PASSWORD, CURLUE_NO_PORT, CURLUE_NO_QUERY, CURLUE_NO_SCHEME, CURLUE_NO_USER,
    CURLUE_NO_ZONEID, CURLUE_OK, CURLUE_OUT_OF_MEMORY, CURLUE_UNKNOWN_PART,
    CURLUE_UNSUPPORTED_SCHEME, CURLUE_URLDECODE, CURLUPART_FRAGMENT, CURLUPART_HOST,
    CURLUPART_OPTIONS, CURLUPART_PASSWORD, CURLUPART_PATH, CURLUPART_PORT, CURLUPART_QUERY,
    CURLUPART_SCHEME, CURLUPART_URL, CURLUPART_USER, CURLUPART_ZONEID, CURLU_APPENDQUERY,
    CURLU_DEFAULT_PORT, CURLU_DEFAULT_SCHEME, CURLU_GET_EMPTY, CURLU_GUESS_SCHEME,
    CURLU_NON_SUPPORT_SCHEME, CURLU_NO_AUTHORITY, CURLU_NO_DEFAULT_PORT, CURLU_NO_GUESS_SCHEME,
    CURLU_PUNY2IDN, CURLU_PUNYCODE, CURLU_URLDECODE, CURLU_URLENCODE, CURL_MAX_INPUT_LENGTH,
    DEFAULT_SCHEME, DEFAULT_SCHEME_CSTR, MAX_SCHEME_LEN,
};
use crate::alloc::CBuf;
use crate::ctype::{eq_ignore_case, is_alnum, is_alpha, is_digit};
use crate::decode::{urldecode, UrlReject};
use crate::dynbuf::DynBuf;
use crate::encode::{add_preencoded, easy_escape_bytes, encode_part, urlencode_str};
use crate::error::cc2cu;
use crate::handle::{CurlUrl, StringField};
use crate::idn::{host_decode, host_encode, is_ascii_name};
use crate::parse::host::hostname_check;
use crate::parse::parseurl_and_replace;
use crate::parse::redirect::redirect_url;
use crate::parse::scheme::is_absolute_url;
use crate::scheme::{get_scheme, getn_scheme, SchemeInfo};
use crate::strparse::str_number;

/// The size of the C's port scratch buffer, `char portbuf[7]` at
/// `lib/urlapi.c` L1439 and L1546.
///
/// Seven bytes hold five digits and a terminator with one to spare, and the
/// widest value that can reach it is `defport`, an `unsigned short`. The
/// truncation `curl_msnprintf` would perform is reproduced by
/// [`portbuf_render`] and is unreachable for that reason.
const PORTBUF_LEN: usize = 7;

/// The size of the C's scheme scratch buffer, `char schemebuf[MAX_SCHEME_LEN
/// + 5]` at `lib/urlapi.c` L1452.
///
/// Forty-five bytes for at most forty of scheme, three of `://` and a
/// terminator, with one to spare. Both paths that can put a scheme on a
/// handle refuse anything longer than [`MAX_SCHEME_LEN`] -- `parse_scheme` at
/// L949-L950 and [`set_url_scheme`] at L1641 -- so the truncation
/// [`schemebuf_render`] reproduces is unreachable too.
const SCHEMEBUF_LEN: usize = MAX_SCHEME_LEN + 5;

/// What `curl_maprintf` renders for a null `%s` with no precision.
///
/// `lib/mprintf.c` L836 defines `static const char nilstr[] = "(nil)"` and
/// L849-L861 substitutes it for a null argument. This is not undefined
/// behaviour to be avoided, then, but a defined output of the reference
/// implementation, and there is exactly one place a null pointer can reach a
/// conversion: `u->path` in the `file:` template at L1442. A handle whose
/// scheme is `file` and whose path has been cleared with
/// `curl_url_set(u, CURLUPART_PATH, NULL, 0)` serializes as `file://(nil)`.
///
/// Every other conversion in both templates is either a literal or a ternary
/// with an empty-string alternative, so no other site needs this.
const NIL_STR: &[u8] = b"(nil)";

/// The bytes of a C string, stopping at the first NUL.
///
/// Everywhere the C calls `strlen()` on a caller's `const char *`, the length
/// it gets is the distance to the terminator, and every byte past it is
/// invisible. A Rust slice carries its own length instead, so the two agree
/// only for a slice with no interior NUL. That is the case for every input
/// this module actually receives -- `src/ffi.rs` builds its slices from
/// `CStr`, the junk scan at L233-L236 refuses a NUL in a URL, and
/// `REJECT_CTRL` decoding refuses one in a part -- and the truncation is
/// applied anyway, at the two sites the C measures with `strlen`, so that no
/// question of faithfulness arises from a caller this module cannot see.
///
/// `src/encode.rs` applies the same window inside [`encode_part`] and
/// [`add_preencoded`], for the same reason.
fn cstring_window(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&byte| byte == 0) {
        Some(end) => bytes.get(..end).unwrap_or(&[]),
        None => bytes,
    }
}

/// Looks up a scheme held as a NUL-terminated byte range.
///
/// The port of `Curl_get_scheme(scheme)`, which `lib/urlapi.c` calls at L1460,
/// L1589 and L1598 with a `char *` that is either `u->scheme` or the
/// `DEFAULT_SCHEME` literal. `src/scheme.rs` takes a `&CStr` there because in
/// drop-in mode the pointer is handed to C and the terminator is a
/// precondition of that call; this function is the one place that conversion
/// happens, so the two callers below read as the C reads.
///
/// # Returns
///
/// `None` for a name the table does not hold, which is the C's null return,
/// and also `None` for a range that is not a valid C string. The second case
/// is unreachable: both callers pass either
/// [`crate::alloc::CBuf::as_bytes_with_nul`], whose content cannot hold a NUL
/// for the reasons [`cstring_window`] gives, or the [`DEFAULT_SCHEME_CSTR`]
/// literal. Folding it into "not found" keeps the function infallible without
/// an `unwrap`, and answers exactly as C would for a scheme it cannot match.
fn scheme_lookup(terminated: &[u8]) -> Option<SchemeInfo> {
    CStr::from_bytes_with_nul(terminated)
        .ok()
        .and_then(get_scheme)
}

/// Looks up the scheme stored on a handle.
///
/// `Curl_get_scheme(u->scheme)` at `lib/urlapi.c` L1589 and L1598, both inside
/// [`url_get`]'s port arm. An absent scheme answers `None`, which is the same
/// answer the C reaches by testing `u->scheme` in the surrounding condition
/// before it looks anything up.
fn handle_scheme(u: &CurlUrl) -> Option<SchemeInfo> {
    u.field(StringField::Scheme)
        .and_then(|buf| scheme_lookup(buf.as_bytes_with_nul()))
}

/// The empty part the fragment arm substitutes at `lib/urlapi.c` L1622.
///
/// A named constant rather than a literal at the site, because there the type
/// has to be the same `Option<&[u8]>` the handle's own accessors produce and a
/// bare byte-string literal is an array reference.
const EMPTY_PART: &[u8] = b"";

/// Renders a default port into the C's seven-byte scratch buffer.
///
/// `curl_msnprintf(portbuf, sizeof(portbuf), "%u", h->defport)` at
/// `lib/urlapi.c` L1465 and L1591. A stack buffer rather than an allocation
/// because that is what the C uses: the rendered digits are one of fifteen
/// template arguments and never outlive the call, so allocating for them
/// would add a heap operation the reference implementation does not perform,
/// which `tests/data/test1560`'s allocation ceiling cares about.
///
/// # Returns
///
/// The number of bytes written, never more than `PORTBUF_LEN - 1`, which is
/// the truncation `snprintf` performs to leave room for its terminator. The
/// widest input is `65535`, five digits, so the ceiling is unreachable.
fn portbuf_render(buf: &mut [u8; PORTBUF_LEN], value: u16) -> usize {
    // Digits come out least-significant first, so they are collected and then
    // reversed. Five slots is the widest an `unsigned short` needs.
    let mut digits = [0_u8; 5];
    let mut count: usize = 0;
    let mut rest = value;
    loop {
        // `checked_rem` and `checked_div` rather than `%` and `/`: the crate
        // denies unchecked arithmetic, and a divisor of ten can only fail to
        // be nonzero if this literal is edited. The fallbacks keep the
        // function total without an `unwrap`.
        let digit = rest.checked_rem(10).unwrap_or(0);
        rest = rest.checked_div(10).unwrap_or(0);
        if let Some(slot) = digits.get_mut(count) {
            // `wrapping_add` on a value below ten cannot wrap; it is spelled
            // this way because the crate denies the bare operator.
            *slot = b'0'.wrapping_add(u8::try_from(digit).unwrap_or(0));
        }
        count = count.saturating_add(1);
        if rest == 0 {
            break;
        }
    }

    let ceiling = PORTBUF_LEN.saturating_sub(1);
    let mut written: usize = 0;
    // Most significant first, which is the reverse of collection order.
    for offset in (0..count).rev() {
        if written >= ceiling {
            break;
        }
        if let (Some(&digit), Some(slot)) = (digits.get(offset), buf.get_mut(written)) {
            *slot = digit;
        }
        written = written.saturating_add(1);
    }
    written
}

/// Renders `"scheme://"` into the C's forty-five-byte scratch buffer.
///
/// `curl_msnprintf(schemebuf, sizeof(schemebuf), "%s://", scheme)` at
/// `lib/urlapi.c` L1513, and a stack buffer for the same reason as
/// [`portbuf_render`].
///
/// # Returns
///
/// The number of bytes written, never more than `SCHEMEBUF_LEN - 1`. The
/// truncation is unreachable, as [`SCHEMEBUF_LEN`] explains, and is
/// reproduced so that an oversized scheme arriving by some future route
/// cannot write outside the buffer.
fn schemebuf_render(buf: &mut [u8; SCHEMEBUF_LEN], scheme: &[u8]) -> usize {
    let ceiling = SCHEMEBUF_LEN.saturating_sub(1);
    let mut written: usize = 0;
    // The scheme, then the three punctuation bytes, in one pass so the
    // truncation point is the same one `snprintf` would choose.
    for &byte in cstring_window(scheme).iter().chain(b"://".iter()) {
        if written >= ceiling {
            break;
        }
        if let Some(slot) = buf.get_mut(written) {
            *slot = byte;
        }
        written = written.saturating_add(1);
    }
    written
}

/// Copies one part and applies the caller's conversions to the copy.
///
/// The port of `urlget_format`, `lib/urlapi.c` L1357-L1423. Every arm of
/// [`url_get`] that found something funnels through here, so this is where
/// `CURLU_URLDECODE`, `CURLU_URLENCODE`, `CURLU_PUNYCODE` and `CURLU_PUNY2IDN`
/// take effect, and where the caller's buffer is born.
///
/// # The conversions are exclusive, in this precedence
///
/// L1392-L1420 is a single `if / else if / else if`, so at most one of the
/// three conversions runs even when the caller sets several flags:
/// url-encoding, then punycode, then depunyfication. Plus-decoding at
/// L1371-L1379 and url-decoding at L1380-L1391 are separate `if`s that run
/// before all of them and are not part of the chain.
///
/// # Two flags that are inert for every part but one
///
/// `punycode` and `depunyfy` are `AND`ed with `what == CURLUPART_HOST` at
/// L1365-L1366, so passing either for a path or a query does nothing at all.
/// Both branches then consult **the handle's host** rather than the part being
/// formatted, at L1402 and L1412, which is why `u` is a parameter of a
/// function that is otherwise about `ptr`.
///
/// # Parameters
///
/// - `u`: the handle, read for its host by the two internationalized-domain
///   branches and for nothing else. Shared, never unique: `curl_url_get` takes
///   a `const CURLU *` and `src/ffi.rs` may not form a mutable reference from
///   it.
/// - `what`: the part identifier, read only for the two comparisons above and
///   for the query test that selects `+`-for-space encoding at L1395.
/// - `ptr`: the bytes to format. Measured with [`cstring_window`], which is
///   the `strlen()` at L1362.
/// - `plusdecode`: whether `'+'` becomes `' '`. Set by exactly one arm of
///   [`url_get`], the query one, and only when decoding.
/// - `flags`: the caller's `CURLU_*` word, already adjusted by the arm that
///   dispatched here -- the scheme and port arms clear `CURLU_URLDECODE`
///   before calling.
///
/// # Returns
///
/// `Ok(Some(buffer))` with an owned C-allocator buffer the caller may hand to
/// C, which is `*partp = part` at L1421.
///
/// `Ok(None)` is the C's other success, and it is not a tidy-up of an
/// impossible case: L1399 takes `curlx_dyn_ptr(&enc)`, which is **null when
/// nothing was appended**, and L1421 stores it and reports `CURLUE_OK`. An
/// empty part retrieved with `CURLU_URLENCODE` therefore succeeds while
/// yielding no pointer at all, and a caller that trusts the code and
/// dereferences the pointer faults. Reachable through
/// `curl_url_get(u, CURLUPART_QUERY, &p, CURLU_GET_EMPTY | CURLU_URLENCODE)`
/// on a handle whose query is blank. `src/ffi.rs` reproduces it by leaving
/// `*part` at the null it wrote at L1552 and returning success, and its
/// `curl_url_get` documents the same pair of successes from the C caller's
/// side; `tests::an_empty_part_under_url_encoding_succeeds_with_no_buffer`
/// pins it.
///
/// # Errors
///
/// - `CURLUE_OUT_OF_MEMORY` when the initial copy fails, L1369-L1370.
/// - `CURLUE_URLDECODE` for **any** decode failure, L1387-L1388. The
///   underlying `CURLcode` is discarded: a rejected control byte and a failed
///   allocation are both code 6. The C's comment at L1383-L1384 records that
///   the unconditional control-byte rejection is documented API behaviour
///   rather than an oversight.
/// - Whatever the encoder reported, L1397-L1398, or the
///   internationalized-domain conversion reported, L1406-L1407 and
///   L1416-L1417.
fn urlget_format(
    u: &CurlUrl,
    what: CURLUPart,
    ptr: &[u8],
    plusdecode: bool,
    flags: c_uint,
) -> Result<Option<CBuf>, CURLUcode> {
    // L1362. The window is the `strlen()`; see `cstring_window`.
    let window = cstring_window(ptr);
    let mut partlen = window.len();

    // L1363-L1366. The two `what` tests are the whole reason `CURLU_PUNYCODE`
    // and `CURLU_PUNY2IDN` do nothing for any other part.
    let decode_requested = (flags & CURLU_URLDECODE) != 0;
    let urlencode = (flags & CURLU_URLENCODE) != 0;
    let punycode = (flags & CURLU_PUNYCODE) != 0 && what == CURLUPART_HOST;
    let depunyfy = (flags & CURLU_PUNY2IDN) != 0 && what == CURLUPART_HOST;

    // L1367, `curlx_memdup0(ptr, partlen)`, and L1369-L1370 for its failure.
    //
    // L1368 writes `*partp = NULL` before anything can fail, so that a caller
    // who ignores the return code cannot read a stale pointer. The `Result`
    // is that guarantee made structural: no buffer exists for the caller
    // unless this function returns `Ok`, and `src/ffi.rs` has already written
    // the null at L1552 regardless.
    //
    // OWNERSHIP: the block comes from the C allocator through `src/alloc.rs`,
    // so it is releasable with `curl_free()` from the moment it exists. Until
    // one of the returns below hands it over, `Drop` releases it -- which is
    // what removes the C's four manual frees at L1386, L1396, L1405 and L1415.
    let mut part = CBuf::from_slice(window).ok_or(CURLUE_OUT_OF_MEMORY)?;

    if plusdecode {
        // L1371-L1379, "convert + to space". The C walks exactly `partlen`
        // bytes; `as_mut_bytes` is exactly that extent, because the buffer was
        // built from `window` one statement ago, so the bound is a property of
        // the value rather than a loop condition to get wrong.
        for byte in part.as_mut_bytes() {
            if *byte == b'+' {
                *byte = b' ';
            }
        }
    }

    if decode_requested {
        // L1380-L1391. `REJECT_CTRL` is not a choice made here: all three
        // decode sites in the C module pass it.
        let decoded = urldecode(part.as_bytes(), partlen, UrlReject::Ctrl)
            // L1387-L1388: the code is flattened to `CURLUE_URLDECODE`
            // whatever went wrong.
            .map_err(|_| CURLUE_URLDECODE)?;
        // L1389-L1390. The assignment drops the pre-decode buffer, which is
        // the `curlx_free(part)` at L1386; on the error path above the same
        // drop happens as the value goes out of scope.
        partlen = decoded.len();
        part = decoded;
    }

    // L1392-L1420. One chain, three exclusive arms, in the C's order.
    let converted: Option<CBuf> = if urlencode {
        // L1392-L1400. `relative` is TRUE, so no host prefix is skipped: this
        // encodes the whole part. `query` decides `+`-for-space, and is the
        // part identifier rather than a flag.
        let mut enc = DynBuf::new(CURL_MAX_INPUT_LENGTH);
        let uc = urlencode_str(
            &mut enc,
            part.as_bytes(),
            partlen,
            true,
            what == CURLUPART_QUERY,
        );
        // L1396: released before the code is inspected, so the failure path
        // needs no free of its own.
        drop(part);
        if uc != CURLUE_OK {
            return Err(uc);
        }
        // L1399. `into_cbuf` is `curlx_dyn_ptr`, null and all: see the Returns
        // section above for the empty-input case this deliberately preserves.
        enc.into_cbuf()
    } else if punycode {
        // L1401-L1410. The gate reads the handle's host, not `part`.
        if is_ascii_name(u.host()) {
            // The C's `if(!Curl_is_ASCII_name(u->host))` was false, so the
            // arm does nothing and the copy is returned unchanged.
            Some(part)
        } else {
            let punyversion = host_decode(&part);
            // L1405, again before the code is inspected.
            drop(part);
            Some(punyversion?)
        }
    } else if depunyfy {
        // L1411-L1420, whose gate is the opposite way round from the
        // punycode arm's.
        if is_ascii_name(u.host()) {
            let unpunified = host_encode(&part);
            drop(part);
            Some(unpunified?)
        } else {
            Some(part)
        }
    } else {
        Some(part)
    };

    Ok(converted)
}

/// Serializes the whole URL, reproducing `urlget_url`.
///
/// The port of `lib/urlapi.c` L1425-L1539, and the single most
/// output-defining function of the module: its fifteen-argument template at
/// L1517-L1532 *is* the string the demo parity diff compares byte for byte,
/// and its `file:` alternative at L1441 is the other.
///
/// # The two templates
///
/// A `file:` URL takes the five-argument form and carries no host, no port and
/// no credentials at all -- the scheme test at L1440 is case-insensitive, so
/// `FILE:` reaches it too. Everything else takes the fifteen-argument form.
/// The order of those fifteen and the ternary on each of them are reproduced
/// exactly; see the comment at the array.
///
/// # Where a null pointer meets a conversion
///
/// Once, at L1442: `u->path` may be absent, and `curl_maprintf` renders a null
/// `%s` as `(nil)` per `lib/mprintf.c` L836 and L849-L861. [`NIL_STR`] carries
/// that string and explains why reproducing it is faithfulness rather than
/// undefined behaviour. Every other conversion in either template has an
/// empty-string alternative.
///
/// # Returns
///
/// An owned C-allocator buffer holding the serialized URL.
///
/// # Errors
///
/// - `CURLUE_NO_HOST` for a non-`file:` handle with no host, L1448-L1449.
/// - `CURLUE_NO_SCHEME` when there is no scheme and `CURLU_DEFAULT_SCHEME` was
///   not passed, L1457-L1458.
/// - `CURLUE_OUT_OF_MEMORY` for a failed assembly at L1535-L1536, for a failed
///   zone-identifier append at L1486-L1488 -- note that site returns the code
///   verbatim rather than folding through `cc2cu`, so a too-large result is
///   reported as code 7 -- and for a failed host escape at L1494-L1495.
/// - Whatever the internationalized-domain conversion reported, L1500-L1501
///   and L1507-L1508.
fn urlget_url(u: &CurlUrl, flags: c_uint) -> Result<CBuf, CURLUcode> {
    // L1429-L1438. `options` and `port` are the two locals the C reassigns
    // below; everything else here is read once.
    let mut options = u.options();
    let mut port = u.port();
    let show_fragment =
        u.fragment().is_some() || (u.fragment_present() && (flags & CURLU_GET_EMPTY) != 0);
    // L1434-L1435. Not the same shape as `show_fragment`: the query half
    // additionally requires a non-empty first byte, so a stored blank query is
    // shown only through the `query_present` half.
    let show_query = u.query().is_some_and(|query| !query.is_empty())
        || (u.query_present() && (flags & CURLU_GET_EMPTY) != 0);
    let punycode = (flags & CURLU_PUNYCODE) != 0;
    let depunyfy = (flags & CURLU_PUNY2IDN) != 0;
    let urlencode = (flags & CURLU_URLENCODE) != 0;
    // L1439, `char portbuf[7]`.
    let mut portbuf = [0_u8; PORTBUF_LEN];

    // L1440-L1447. `curl_strequal("file", u->scheme)` is a full
    // case-insensitive comparison, so the argument order does not matter.
    if u.scheme()
        .is_some_and(|scheme| eq_ignore_case(b"file", scheme))
    {
        // L1441-L1446, `"file://%s%s%s%s%s"`.
        let template: [&[u8]; 6] = [
            b"file://",
            // L1442. The one conversion in either template that can receive a
            // null pointer; see `NIL_STR`.
            u.path().unwrap_or(NIL_STR),
            if show_query { b"?" } else { b"" },
            u.query().unwrap_or(b""),
            if show_fragment { b"#" } else { b"" },
            u.fragment().unwrap_or(b""),
        ];
        // L1535-L1536. OWNERSHIP: the assembled buffer's block comes from the
        // C allocator, so the `curl_free()` the caller owes is correct.
        return CBuf::concat(&template).ok_or(CURLUE_OUT_OF_MEMORY);
    }

    // L1448-L1449. Binding the host here rather than testing for it keeps the
    // C's guarantee -- every use below is unconditional in the C because this
    // return has already happened -- without an `unwrap` anywhere.
    let Some(host) = u.host() else {
        return Err(CURLUE_NO_HOST);
    };

    // L1452, `char schemebuf[MAX_SCHEME_LEN + 5]`.
    let mut schemebuf = [0_u8; SCHEMEBUF_LEN];
    // L1453-L1458. The terminated view is for the lookup at L1460, which in
    // drop-in mode really does hand a `const char *` to libcurl.
    let (scheme, scheme_terminated): (&[u8], &[u8]) = match u.field(StringField::Scheme) {
        Some(buf) => (buf.as_bytes(), buf.as_bytes_with_nul()),
        None if (flags & CURLU_DEFAULT_SCHEME) != 0 => {
            (DEFAULT_SCHEME.as_bytes(), DEFAULT_SCHEME_CSTR)
        }
        None => return Err(CURLUE_NO_SCHEME),
    };

    let h = scheme_lookup(scheme_terminated);

    // L1461-L1475. An `if / else if`, so injecting a default port and
    // suppressing a matching one are alternatives rather than independent
    // steps: a caller passing both flags gets the injection only.
    if port.is_none() && (flags & CURLU_DEFAULT_PORT) != 0 {
        // L1462-L1467: no stored port, but a default was asked for.
        if let Some(info) = h {
            let written = portbuf_render(&mut portbuf, info.defport());
            // L1466. The empty fallback is unreachable; `portbuf_render`
            // always writes at least one digit.
            port = Some(portbuf.get(..written).unwrap_or(&[]));
        }
    } else if port.is_some() {
        // L1469-L1475: a stored port, to be inhibited if it is the default.
        if let Some(info) = h {
            if info.defport() == u.portnum() && (flags & CURLU_NO_DEFAULT_PORT) != 0 {
                port = None;
            }
        }
    }

    // L1477-L1478. The options part exists in the URL only for a scheme whose
    // handler owns `PROTOPT_URLOPTIONS`; note the guard is `h &&`, so an
    // unknown scheme keeps its options.
    if h.is_some_and(|info| !info.has_url_options()) {
        options = None;
    }

    // L1480-L1510. One chain of four alternatives producing at most one
    // replacement host.
    let allochost: Option<CBuf> = if host.first() == Some(&b'[') {
        // L1480-L1491. A bracketed host emits its zone identifier; a
        // non-bracketed one never does, which is one half of the `FB3`
        // asymmetry the module documentation describes.
        match u.zoneid() {
            Some(zoneid) => {
                // L1483-L1487, `"%.*s%%25%s]"` with precision `hostlen - 1`:
                // the host without its closing bracket, the percent sign in
                // its encoded form, the zone, and the bracket restored.
                let mut enc = DynBuf::new(CURL_MAX_INPUT_LENGTH);
                let trimmed = host.split_last().map_or::<&[u8], _>(&[], |(_, rest)| rest);
                if enc.addn(trimmed).is_err()
                    || enc.addn(b"%25").is_err()
                    || enc.addn(zoneid).is_err()
                    || enc.addn(b"]").is_err()
                {
                    // L1486-L1488. A failed append has already released the
                    // buffer, which is why the C returns without a free.
                    return Err(CURLUE_OUT_OF_MEMORY);
                }
                // L1489. The failure arm is unreachable: four appends
                // succeeded, so a block exists.
                Some(enc.into_cbuf().ok_or(CURLUE_OUT_OF_MEMORY)?)
            }
            // A bracketed host with no zone falls out of the whole chain, so
            // the encode and internationalized-domain arms below are skipped
            // for it as well. That is the C's shape, not an oversight.
            None => None,
        }
    } else if urlencode {
        // L1492-L1496. This escapes the host, which is the exact opposite of
        // what `urlencode_str` does: that function locates the host separator
        // at L104-L118 and copies the authority verbatim, because encoding it
        // would break internationalized-domain resolution (its comment at
        // L127-L128). Both behaviours are correct, they belong to different
        // paths, and both are ported -- this one here, the exemption in
        // `src/encode.rs`.
        let escaped = easy_escape_bytes(host).ok_or(CURLUE_OUT_OF_MEMORY)?;
        // L1494-L1495. `easy_escape_bytes` yields an allocated, terminated
        // buffer even for an empty host, so the failure arm is the allocation
        // one only.
        Some(escaped.into_cbuf().ok_or(CURLUE_OUT_OF_MEMORY)?)
    } else if punycode {
        if is_ascii_name(u.host()) {
            None
        } else {
            match u.field(StringField::Host) {
                Some(buf) => Some(host_decode(buf)?),
                // Unreachable: `host` above came from this very field.
                None => None,
            }
        }
    } else if depunyfy {
        // L1504-L1509, with the gate the other way round.
        if is_ascii_name(u.host()) {
            match u.field(StringField::Host) {
                Some(buf) => Some(host_encode(buf)?),
                None => None,
            }
        } else {
            None
        }
    } else {
        None
    };

    // L1512-L1515, and this is `FB1`'s second observable. The prefix is
    // emitted unless the caller asked to suppress a guessed scheme *and* the
    // scheme on this handle was guessed. `curl_url_dup` does not copy
    // `guessed_scheme` (`src/handle.rs`, L1310-L1332), so the same flag
    // against a duplicate of a guessed-scheme handle takes the first branch
    // and emits the prefix the original suppresses. Reproduced, not fixed;
    // `rust-urlapi/docs/KNOWN-DIVERGENCES.md` records it, and
    // `tests/libtest/lib1560.c` L583-L585 pins the original's behaviour with
    // the expected output `example.com/`.
    let scheme_prefix_len = if (flags & CURLU_NO_GUESS_SCHEME) == 0 || !u.guessed_scheme() {
        schemebuf_render(&mut schemebuf, scheme)
    } else {
        // L1515, `schemebuf[0] = 0`, an empty C string.
        0
    };
    let scheme_prefix = schemebuf.get(..scheme_prefix_len).unwrap_or(&[]);

    // L1524. Computed from the possibly-nulled `options`, as the C's
    // expression is.
    let has_userinfo = u.user().is_some() || u.password().is_some() || options.is_some();

    // L1517-L1532: the fifteen conversions of the one `curl_maprintf` call, in
    // its order, each with its own ternary. This array is the C's argument
    // list read top to bottom, and it is the observable output of the port --
    // reorder a line and the parity diff fails.
    let template: [&[u8]; 15] = [
        scheme_prefix,
        // L1519-L1524, the userinfo: user, then `:` and password, then `;`
        // and options, then the `@` that only appears if any of the three did.
        u.user().unwrap_or(b""),
        if u.password().is_some() { b":" } else { b"" },
        u.password().unwrap_or(b""),
        if options.is_some() { b";" } else { b"" },
        options.unwrap_or(b""),
        if has_userinfo { b"@" } else { b"" },
        // L1525. The replacement host if one of the four arms produced it,
        // otherwise the handle's own.
        allochost.as_ref().map_or(host, CBuf::as_bytes),
        if port.is_some() { b":" } else { b"" },
        port.unwrap_or(b""),
        // L1528. An absent path serializes as a bare slash. Note this is the
        // template's substitution, not the getter's at L1606-L1607: both
        // exist, and both are `"/"`.
        u.path().unwrap_or(b"/"),
        if show_query { b"?" } else { b"" },
        u.query().unwrap_or(b""),
        if show_fragment { b"#" } else { b"" },
        u.fragment().unwrap_or(b""),
    ];

    // L1533 releases the allocated host; here `allochost` owns it and its
    // `Drop` does that when this function returns, one statement later than
    // the C and to the same effect. L1535-L1536 maps a failed assembly to out
    // of memory.
    //
    // OWNERSHIP: the returned buffer's block comes from the C allocator, so
    // once `src/ffi.rs` hands the pointer over, the caller's `curl_free()` is
    // the correct release.
    CBuf::concat(&template).ok_or(CURLUE_OUT_OF_MEMORY)
}

/// Retrieves one part of a handle. The logic half of `curl_url_get`.
///
/// The port of `lib/urlapi.c` L1541-L1634 without its three pointer
/// preconditions: the null handle at L1548-L1549, the null part pointer at
/// L1550-L1551 and the `*part = NULL` at L1552 belong to `src/ffi.rs`, which
/// owns every raw pointer in this crate.
///
/// # The shape of the switch
///
/// Every arm chooses two things: which bytes to format, and which code to
/// report if there are none. `ifmissing` starts as `CURLUE_UNKNOWN_PART` at
/// L1545 and each arm overwrites it -- **except the path arm**, L1604-L1608,
/// which leaves it alone and substitutes `"/"` for an absent path so that the
/// missing case cannot arise. There is no `CURLUE_NO_PATH` in the ABI and this
/// is not a place to invent one. The `default:` arm at L1626-L1628 chooses no
/// bytes and overwrites nothing, so an out-of-range part falls out of the
/// switch and is reported as code 9 rather than crashing.
///
/// Two arms edit the caller's flag word before the format step, both to remove
/// `CURLU_URLDECODE`: the scheme arm at L1558, whose comment is "never for
/// schemes", and the port arm at L1585. Because the C mutates its own
/// parameter, so does this function.
///
/// # Parameters
///
/// - `u`: the handle. **Shared**, and that is a soundness requirement rather
///   than a preference: `curl_url_get` is declared with a `const CURLU *` at
///   `include/curl/urlapi.h:L129`, so no mutable reference may be formed from
///   the pointer `src/ffi.rs` receives.
/// - `what`: the part identifier, as an integer, because a caller may pass any
///   `int` at all and the out-of-range case has a defined answer.
/// - `flags`: the caller's `CURLU_*` word, taken by value and edited as above.
///
/// # Returns
///
/// `Ok(Some(buffer))` with a buffer the caller owns, or `Ok(None)` for the
/// null-with-success case [`urlget_format`] documents.
///
/// # Errors
///
/// The part's own missing-code -- `CURLUE_NO_SCHEME`, `NO_USER`,
/// `NO_PASSWORD`, `NO_OPTIONS`, `NO_HOST`, `NO_ZONEID`, `NO_PORT`, `NO_QUERY`
/// or `NO_FRAGMENT` -- or `CURLUE_UNKNOWN_PART` for an out-of-range part, or
/// whatever [`urlget_format`] and [`urlget_url`] report.
pub(crate) fn url_get(
    u: &CurlUrl,
    what: CURLUPart,
    mut flags: c_uint,
) -> Result<Option<CBuf>, CURLUcode> {
    let mut ifmissing = CURLUE_UNKNOWN_PART;
    let mut portbuf = [0_u8; PORTBUF_LEN];
    let mut plusdecode = false;

    let ptr: Option<&[u8]> = match what {
        CURLUPART_SCHEME => {
            ifmissing = CURLUE_NO_SCHEME;
            // L1558, "never for schemes".
            flags &= !CURLU_URLDECODE;
            // L1559-L1560, and this is `FB1`'s first observable: a handle
            // whose scheme was guessed reports having none when the caller
            // says it does not want guesses. `curl_url_dup` drops the
            // `guessed_scheme` member, so the same call against a duplicate
            // returns the guessed scheme instead. Reproduced, not fixed.
            if (flags & CURLU_NO_GUESS_SCHEME) != 0 && u.guessed_scheme() {
                return Err(CURLUE_NO_SCHEME);
            }
            u.scheme()
        }
        CURLUPART_USER => {
            ifmissing = CURLUE_NO_USER;
            u.user()
        }
        CURLUPART_PASSWORD => {
            ifmissing = CURLUE_NO_PASSWORD;
            u.password()
        }
        CURLUPART_OPTIONS => {
            // L1570-L1573. Note that unlike the whole-URL path at L1477-L1478
            // this arm applies no `PROTOPT_URLOPTIONS` gate: the part is
            // readable for any scheme, it is only the serialized URL that
            // suppresses it.
            ifmissing = CURLUE_NO_OPTIONS;
            u.options()
        }
        CURLUPART_HOST => {
            ifmissing = CURLUE_NO_HOST;
            u.host()
        }
        CURLUPART_ZONEID => {
            // L1578-L1581. A zone identifier left behind by an earlier
            // bracketed host is still readable here even once the host has
            // been replaced by a name that cannot carry one, which is the
            // other half of the `FB3` asymmetry.
            ifmissing = CURLUE_NO_ZONEID;
            u.zoneid()
        }
        CURLUPART_PORT => {
            ifmissing = CURLUE_NO_PORT;
            // L1585, "never for port".
            flags &= !CURLU_URLDECODE;
            let mut ptr = u.port();
            // The same injection-or-suppression pair as L1461-L1475, with one
            // difference: both branches additionally require `u->scheme`,
            // L1586 and L1595. Folding that into the lookup would give the
            // same answers, and it is written out because the condition is
            // what selects the branch.
            if ptr.is_none() && (flags & CURLU_DEFAULT_PORT) != 0 && u.has(StringField::Scheme) {
                if let Some(info) = handle_scheme(u) {
                    let written = portbuf_render(&mut portbuf, info.defport());
                    // L1592. The empty fallback is unreachable.
                    ptr = Some(portbuf.get(..written).unwrap_or(EMPTY_PART));
                }
            } else if ptr.is_some() && u.has(StringField::Scheme) {
                if let Some(info) = handle_scheme(u) {
                    if info.defport() == u.portnum() && (flags & CURLU_NO_DEFAULT_PORT) != 0 {
                        ptr = None;
                    }
                }
            }
            ptr
        }
        CURLUPART_PATH => {
            // L1604-L1608. Deliberately no `ifmissing`; see the doc above.
            Some(u.path().unwrap_or(b"/"))
        }
        CURLUPART_QUERY => {
            ifmissing = CURLUE_NO_QUERY;
            // L1612. Plus-decoding is the query part's alone, and only when
            // decoding was asked for.
            plusdecode = (flags & CURLU_URLDECODE) != 0;
            let mut ptr = u.query();
            // L1613-L1615: "there was a blank query and the user do not ask
            // for it".
            if ptr.is_some_and(<[u8]>::is_empty) && (flags & CURLU_GET_EMPTY) == 0 {
                ptr = None;
            }
            ptr
        }
        CURLUPART_FRAGMENT => {
            ifmissing = CURLUE_NO_FRAGMENT;
            let mut ptr = u.fragment();
            // L1620-L1622: "there was a blank fragment and the user asks for
            // it". Note the asymmetry with the query arm above: this one
            // *adds* an empty answer where that one removes one, because a
            // blank fragment is stored as an absent string with the presence
            // bit set while a blank query is stored as a zero-length string.
            if ptr.is_none() && u.fragment_present() && (flags & CURLU_GET_EMPTY) != 0 {
                ptr = Some(EMPTY_PART);
            }
            ptr
        }
        CURLUPART_URL => {
            // L1624-L1625. The only arm that does not funnel through
            // `urlget_format`, so none of the conversions that function
            // applies reach the whole-URL path; `urlget_url` does its own.
            return urlget_url(u, flags).map(Some);
        }
        _ => {
            // L1626-L1628. `ifmissing` is still `CURLUE_UNKNOWN_PART`, so a
            // bogus part identifier is answered with code 9.
            None
        }
    };

    match ptr {
        Some(ptr) => urlget_format(u, what, ptr, plusdecode, flags),
        None => Err(ifmissing),
    }
}

/// Validates a scheme and clears the guessed marker. The port of
/// `set_url_scheme`, `lib/urlapi.c` L1636-L1664.
///
/// It does **not** store anything. The caller stores the value through the
/// ordinary encode-and-store path, which for this part encodes nothing; all
/// this function does is decide whether the value is acceptable and update the
/// `guessed_scheme` marker at L1662.
///
/// # Two tests, and a third only for an unknown scheme
///
/// The length bound at L1641 refuses a scheme longer than
/// [`MAX_SCHEME_LEN`] or shorter than one byte. The support test at
/// L1646-L1647 refuses a scheme the table does not hold *or* holds with no
/// implementation -- the disabled-protocol case, which is why the condition
/// reads `!h || !h->run` rather than just `!h` -- unless the caller passed
/// `CURLU_NON_SUPPORT_SCHEME`. Only when the table has never heard of the name
/// does the syntax check at L1648-L1661 run, because a name the table holds is
/// known to be well formed.
///
/// # The loop is a pre-decrement, and that is not the same as "every byte"
///
/// L1652 is `while(--plen)`, so it decrements before testing: for a
/// three-byte scheme the body runs twice and inspects `s[0]` and `s[1]`, never
/// `s[2]`. The last byte of an unknown scheme is therefore unchecked, and
/// `s[0]` is inspected twice -- once by the `ISALPHA` guard, once by the first
/// pass of the loop. The port below is that loop transcribed, decrement and
/// all, rather than an idiomatic scan over the bytes, because the idiomatic
/// scan accepts a different set of inputs.
///
/// # Errors
///
/// - `CURLUE_BAD_SCHEME` for a length outside the bounds, L1643, for a first
///   byte that is not a letter, L1660, and for a rejected byte inside the
///   loop, L1656.
/// - `CURLUE_UNSUPPORTED_SCHEME` for an unknown or unimplemented scheme
///   without `CURLU_NON_SUPPORT_SCHEME`, L1647.
// Clippy offers `!(1..=MAX_SCHEME_LEN).contains(&plen)` for the length test.
// That is behaviourally identical and is not taken, for the same reason
// `src/encode.rs` declines it above its own range predicate: a reviewer
// diffing this function against L1641 has to read the same two comparisons in
// the same shape to confirm the port, and an inverted inclusive range hides
// which bound is which. The allow is scoped to this function and to this one
// lint.
#[allow(clippy::manual_range_contains)]
fn set_url_scheme(u: &mut CurlUrl, scheme: &[u8], flags: c_uint) -> CURLUcode {
    let window = cstring_window(scheme);
    let plen = window.len();

    // L1641-L1643, "too long or too short".
    if plen > MAX_SCHEME_LEN || plen < 1 {
        return CURLUE_BAD_SCHEME;
    }

    // L1645. The length-taking lookup, because what arrives here is the
    // caller's part rather than a handle field and carries no terminator this
    // function can promise. `Curl_get_scheme` is itself a one-line forward to
    // the length-taking form at `lib/url.c` L1469-L1472, so this is the same
    // call.
    let h = getn_scheme(window);

    if (flags & CURLU_NON_SUPPORT_SCHEME) == 0 && !h.is_some_and(SchemeInfo::implemented) {
        return CURLUE_UNSUPPORTED_SCHEME;
    }

    if h.is_none() {
        // L1648-L1661, the RFC 3986 3.1 production
        // `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`.
        if !is_alpha(window.first().copied().unwrap_or(0)) {
            // L1659-L1660. The C spells this as the `else` of the `ISALPHA`
            // test; inverting it costs nothing and removes a nesting level.
            return CURLUE_BAD_SCHEME;
        }
        // L1652-L1657, the pre-decrement loop; see the doc above.
        let mut remaining = plen;
        let mut index: usize = 0;
        loop {
            // `--plen` at L1652. Saturation cannot trigger: `remaining` starts
            // at `plen`, which L1641 established is at least one.
            remaining = remaining.saturating_sub(1);
            if remaining == 0 {
                break;
            }
            // L1653. The zero fallback is unreachable, because `index` never
            // passes `plen - 2`, and a zero would be refused anyway.
            let byte = window.get(index).copied().unwrap_or(0);
            if is_alnum(byte) || byte == b'+' || byte == b'-' || byte == b'.' {
                // L1654, `s++`.
                index = index.saturating_add(1);
            } else {
                return CURLUE_BAD_SCHEME;
            }
        }
    }

    // L1662. Setting the scheme explicitly means it was not guessed, whatever
    // it was before.
    u.set_guessed_scheme(false);
    CURLUE_OK
}

/// Parses and stores a port. The port of `set_url_port`, `lib/urlapi.c`
/// L1666-L1683.
///
/// The one part whose assignment bypasses the encode-and-store path entirely:
/// [`url_set`] returns this function's answer directly at L1854, so no dynamic
/// buffer is built and no encoding is applied. What is stored is not the
/// caller's text but a **re-rendering of the parsed number**, L1676, which is
/// how `"080"` and `"000000000000000000000443"` both become `"443"`-style
/// canonical text; `tests/libtest/lib1560.c` L592-L594 pins exactly that.
///
/// # Three tests, in this order
///
/// The first byte must be a digit, L1670 -- which also rejects an empty
/// string, whose first byte is the terminator. The scan must succeed within
/// `0xffff`, L1673. And **the caller checks the trailing byte itself**: the
/// scanner stops at the first non-digit without complaining, so `*provided_port`
/// at L1673 is what refuses `"80x"`. Because the `||` short-circuits, a failed
/// scan skips the trailing test.
///
/// # Errors
///
/// - `CURLUE_BAD_PORT_NUMBER` for all three refusals, L1672 and L1675.
/// - `CURLUE_OUT_OF_MEMORY` when the re-rendering cannot be allocated, L1678.
///   Note what the C leaves behind on that path: the old port text is still in
///   place, because L1679 has not run yet.
fn set_url_port(u: &mut CurlUrl, provided_port: &[u8]) -> CURLUcode {
    let window = cstring_window(provided_port);

    // L1670-L1672, "not a number". An empty part reaches the `unwrap_or` and
    // is refused, which is what reading the terminator does in the C.
    if !is_digit(window.first().copied().unwrap_or(0)) {
        return CURLUE_BAD_PORT_NUMBER;
    }

    // L1673-L1675, "weirdly provided number, not good!". The cursor is
    // advanced by the scan exactly as the C advances its pointer, and the
    // emptiness test afterwards is the C's `*provided_port`.
    let mut cursor = window;
    let Ok(port) = str_number(&mut cursor, 0xffff) else {
        return CURLUE_BAD_PORT_NUMBER;
    };
    if !cursor.is_empty() {
        return CURLUE_BAD_PORT_NUMBER;
    }

    // L1681's `(unsigned short)port`, hoisted above the store so that its
    // unreachable failure arm cannot leave a handle half-updated. `try_from`
    // is that cast with the guarantee made explicit: the scan above already
    // refused anything past `0xffff`. The arm answers with the code an
    // out-of-range port gets anyway, so being unreachable costs nothing.
    let Ok(portnum) = u16::try_from(port) else {
        return CURLUE_BAD_PORT_NUMBER;
    };

    // L1676-L1678. The number is printed, not the input, which is what
    // discards leading zeros. OWNERSHIP: `CBuf` allocates through the C
    // allocator, so the buffer the handle takes on here is releasable by the
    // same `curl_free` chain as every other field.
    let Some(text) = CBuf::format(format_args!("{port}")) else {
        return CURLUE_OUT_OF_MEMORY;
    };

    // L1679-L1680. `store` releases the displaced buffer as part of the
    // assignment, so the `curlx_free(u->port)` cannot be forgotten and cannot
    // happen in the wrong order.
    u.store(StringField::Port, text);
    u.set_portnum(portnum);
    CURLUE_OK
}

/// Replaces the whole URL, absolutely or relatively. The port of `set_url`,
/// `lib/urlapi.c` L1685-L1730.
///
/// # The empty-string rule, and the flag sensitivity nobody expects
///
/// An empty value is not an error. L1697-L1710 treats it as a relative URL
/// that changes nothing: the handle's own URL is serialized, and if that
/// succeeds the copy is thrown away and `CURLUE_OK` is reported. So
/// `curl_url_set(u, CURLUPART_URL, "", 0)` on a handle that already holds a
/// complete URL is a **no-op success**.
///
/// What is easy to miss is that **the caller's flags are passed into that
/// serialization** at L1700, so the decision is flag-sensitive. The read asks
/// for `CURLUPART_URL`, which L1623-L1624 dispatches to `urlget_url`, and that
/// function can fail three ways: `CURLUE_NO_HOST` at L1448-L1449,
/// `CURLUE_NO_SCHEME` at L1453-L1458 when the handle has no scheme and the
/// caller did not pass `CURLU_DEFAULT_SCHEME`, and `CURLUE_OUT_OF_MEMORY`.
/// L1707-L1709 turns the first two into `CURLUE_MALFORMED_INPUT` and passes
/// the third through.
///
/// So the flag that decides the outcome is `CURLU_DEFAULT_SCHEME`. Take a
/// handle with a host and no scheme -- parse an absolute URL and clear the
/// scheme, which `urlset_clear` does at L1739-L1742 -- and the same empty
/// value answers `CURLUE_MALFORMED_INPUT` with no flags and `CURLUE_OK` with
/// `CURLU_DEFAULT_SCHEME`. One handle, one empty string, opposite outcomes
/// decided by a flag that describes how to read a URL rather than how to write
/// one. `tests::the_empty_url_decision_is_flag_sensitive` pins both halves,
/// because an implementation that special-cased the empty string would pass one
/// and fail the other.
///
/// # The second sensitivity, which `AAP` 0.6.5 specifies
///
/// `CURLU_NO_GUESS_SCHEME` on a handle whose scheme was **guessed** answers
/// `CURLUE_MALFORMED_INPUT`, and the port implements that because 0.6.5 states
/// it and this file's own specification restates it as a mandatory pair:
/// "with `CURLU_NO_GUESS_SCHEME` on a guessed-scheme handle (malformed
/// input)". The check is made ahead of the general retrieval, because that is
/// the only place it can be made -- the retrieval itself cannot produce the
/// answer.
///
/// It is worth being exact about why, since the reason is a divergence from
/// the C rather than a reading of it. In the reference, the whole-URL arm
/// reads the flag at L1512-L1515 only to *blank the scheme prefix*, never to
/// fail; the arm where the flag is an error, L1559-L1560, belongs to
/// `CURLUPART_SCHEME`, which L1700 never asks for. So the reference answers
/// `CURLUE_OK` for this call. `AAP` 0.6.5 specifies the failing answer, and a
/// frozen plan governs an implementation choice, so the failing answer is what
/// this module returns. `docs/KNOWN-DIVERGENCES.md` records the resulting
/// oracle conflict in full -- including the measurement against an unmodified
/// `libcurl.a` -- without weakening the requirement, and notes that
/// `tests/libtest/lib1560.c` never writes `""` to `CURLUPART_URL`, so the
/// unmodified oracle is unaffected either way.
///
/// The flag is still a formatting choice on the *read* side, exactly as in the
/// C: `url_get(u, CURLUPART_URL, CURLU_NO_GUESS_SCHEME)` on the same handle
/// succeeds with the prefix suppressed, which is the vector
/// `tests/libtest/lib1560.c` asserts at L583-L585. Only the empty *write*
/// differs, and only in this one combination.
///
/// # The three-way dispatch that follows
///
/// * An absolute input replaces the handle outright, L1713-L1715. The
///   guess argument is `flags & (CURLU_GUESS_SCHEME | CURLU_DEFAULT_SCHEME)`
///   -- two flags, either of which enables guessing.
/// * Otherwise the handle is serialized. Out of memory propagates verbatim,
///   L1720-L1721; **any other failure means the handle could not produce an
///   absolute URL**, so the new value replaces it as if it had been absolute,
///   L1722-L1723.
/// * Otherwise the relative part is resolved against the serialized base,
///   L1727.
///
/// # Errors
///
/// `CURLUE_MALFORMED_INPUT` for an empty value the handle cannot serialize and
/// for an empty value carrying `CURLU_NO_GUESS_SCHEME` on a guessed-scheme
/// handle, `CURLUE_OUT_OF_MEMORY` propagated from either serialization, or
/// whatever the parse or the resolution reported.
fn set_url(u: &mut CurlUrl, url: &[u8], part_size: usize, flags: c_uint) -> CURLUcode {
    if part_size == 0 {
        // `AAP` 0.6.5, ahead of the retrieval because the retrieval cannot
        // produce this answer: the whole-URL arm treats the flag as a
        // formatting choice (L1512-L1515) and succeeds. See the doc comment
        // above for the divergence this is, and
        // `docs/KNOWN-DIVERGENCES.md` for the measurement behind it.
        if (flags & CURLU_NO_GUESS_SCHEME) != 0 && u.guessed_scheme() {
            return CURLUE_MALFORMED_INPUT;
        }

        // L1697-L1710. "a blank URL is not a valid URL unless we already have
        // a complete one and this is a redirect".
        return match url_get(u, CURLUPART_URL, flags) {
            // L1701-L1706. The retrieved copy is dropped here, which is the
            // `curlx_free(oldurl)` at L1704, and nothing about the handle
            // changes.
            Ok(_oldurl) => CURLUE_OK,
            Err(CURLUE_OUT_OF_MEMORY) => CURLUE_OUT_OF_MEMORY,
            // L1709. Every other failure becomes malformed input. Reaching it
            // takes a handle that cannot serialize under the caller's flags,
            // which in practice means no host (L1448-L1449) or no scheme
            // without `CURLU_DEFAULT_SCHEME` (L1453-L1458).
            Err(_) => CURLUE_MALFORMED_INPUT,
        };
    }

    // L1712-L1715. The third argument is a bitwise-or of two flags, not one.
    // The buffer argument is `None` because the C passes a null pointer here:
    // it wants the length only.
    if is_absolute_url(
        url,
        None,
        (flags & (CURLU_GUESS_SCHEME | CURLU_DEFAULT_SCHEME)) != 0,
    ) != 0
    {
        return parseurl_and_replace(url, u, flags);
    }

    // L1717-L1723. "if the old URL is incomplete (we cannot get an absolute
    // URL in 'oldurl'), replace the existing with the new".
    let oldurl = match url_get(u, CURLUPART_URL, flags) {
        Err(CURLUE_OUT_OF_MEMORY) => return CURLUE_OUT_OF_MEMORY,
        Err(_) => return parseurl_and_replace(url, u, flags),
        Ok(value) => value,
    };

    // L1725, `DEBUGASSERT(oldurl)`. The assertion is discharged rather than
    // reproduced: an empty base is what `src/parse/redirect.rs` answers with
    // `CURLUE_MALFORMED_INPUT`, which is the code the C's own unreachable
    // `if(!base)` at L1227-L1228 returns.
    let base = oldurl.as_ref().map_or(EMPTY_PART, CBuf::as_bytes);

    // L1726-L1729. `oldurl` is released when it leaves scope at the end of
    // this expression, which is the `curlx_free(oldurl)` at L1728.
    redirect_url(base, url, u, flags)
}

/// Clears one part. The port of `urlset_clear`, `lib/urlapi.c` L1732-L1777.
///
/// Reached from [`url_set`] whenever the caller passes a null part pointer,
/// L1819-L1821, which `src/ffi.rs` renders as `None`.
///
/// # Four arms do more than release a string
///
/// * `CURLUPART_URL` releases all ten strings and zeroes the four scalars,
///   L1736-L1737, leaving a handle the caller may keep using.
/// * `CURLUPART_SCHEME` also clears the guessed marker, L1741.
/// * `CURLUPART_PORT` zeroes the number **before** releasing the text, L1759-
///   L1760.
/// * `CURLUPART_QUERY` and `CURLUPART_FRAGMENT` also clear their presence
///   bits, L1767 and L1771, so a cleared blank query stops being reportable
///   under `CURLU_GET_EMPTY`.
///
/// # And one arm does less than it looks like it does
///
/// `CURLUPART_HOST` releases the host and **leaves the zone identifier
/// alone**, L1752-L1753, while assigning a host releases it at L1848. That
/// asymmetry is `FB3`; both halves are the source behaviour and neither is
/// corrected here.
///
/// # Errors
///
/// `CURLUE_UNKNOWN_PART` for an out-of-range part, L1773-L1774. Note this is a
/// real `default:` arm, unlike [`url_get`]'s, which reaches the same code by
/// falling out of its switch.
fn urlset_clear(u: &mut CurlUrl, what: CURLUPart) -> CURLUcode {
    match what {
        CURLUPART_URL => {
            // L1735-L1738. `reset` is `free_urlhandle()` followed by the
            // `memset`, in that order.
            u.reset();
        }
        CURLUPART_SCHEME => {
            u.clear(StringField::Scheme);
            u.set_guessed_scheme(false);
        }
        CURLUPART_USER => u.clear(StringField::User),
        CURLUPART_PASSWORD => u.clear(StringField::Password),
        CURLUPART_OPTIONS => u.clear(StringField::Options),
        // L1752-L1754. The zone identifier deliberately survives; see `FB3`
        // above.
        CURLUPART_HOST => u.clear(StringField::Host),
        CURLUPART_ZONEID => u.clear(StringField::ZoneId),
        CURLUPART_PORT => {
            // L1758-L1761, number first.
            u.set_portnum(0);
            u.clear(StringField::Port);
        }
        CURLUPART_PATH => u.clear(StringField::Path),
        CURLUPART_QUERY => {
            u.clear(StringField::Query);
            u.set_query_present(false);
        }
        CURLUPART_FRAGMENT => {
            u.clear(StringField::Fragment);
            u.set_fragment_present(false);
        }
        _ => return CURLUE_UNKNOWN_PART,
    }
    CURLUE_OK
}

/// Assigns one part of a handle. The logic half of `curl_url_set`.
///
/// The port of `lib/urlapi.c` L1805-L1998 without its two pointer
/// preconditions: the null handle at L1817-L1818 and the null-part-clears rule
/// at L1819-L1821 belong to `src/ffi.rs`, which renders the second as
/// `part == None` and this function forwards to [`urlset_clear`].
///
/// # Three parts never reach the encode-and-store path
///
/// `CURLUPART_PORT` returns [`set_url_port`]'s answer directly at L1854,
/// `CURLUPART_URL` returns [`set_url`]'s at L1872, and an out-of-range part
/// returns `CURLUE_UNKNOWN_PART` at L1874. Everything else picks a destination
/// field and falls through to the block at L1877.
///
/// # Side effects that happen before the value is even valid
///
/// Four arms mutate the handle while choosing a destination, so a later failure
/// in the encode block leaves those mutations in place. That is the C's
/// behaviour and it is observable:
///
/// * `CURLUPART_SCHEME` runs [`set_url_scheme`], which clears
///   `guessed_scheme`, L1830 and L1662.
/// * `CURLUPART_HOST` releases the zone identifier, L1848. This is the
///   assigning half of the `FB3` asymmetry whose clearing half is in
///   [`urlset_clear`].
/// * `CURLUPART_QUERY` sets the query-present bit, L1865.
/// * `CURLUPART_FRAGMENT` sets the fragment-present bit, L1869.
///
/// # Errors
///
/// `CURLUE_MALFORMED_INPUT` for an excessive length, L1826;
/// `CURLUE_UNKNOWN_PART` for an out-of-range part, L1874;
/// `CURLUE_BAD_HOSTNAME` for a host the checker refuses, L1989;
/// `CURLUE_OUT_OF_MEMORY` or `CURLUE_TOO_LARGE` from a failed append; or
/// whatever the three delegating arms report.
pub(crate) fn url_set(
    u: &mut CurlUrl,
    what: CURLUPart,
    part: Option<&[u8]>,
    flags: c_uint,
) -> CURLUcode {
    // L1809-L1814. Six decisions the switch below makes and the encode block
    // consumes.
    let mut urlencode = (flags & CURLU_URLENCODE) != 0;
    let mut plusencode = false;
    let mut pathmode = false;
    let mut leadingslash = false;
    let mut appendquery = false;
    let equalsencode;

    // L1819-L1821, "setting a part to NULL clears it".
    let Some(part) = part else {
        return urlset_clear(u, what);
    };

    // L1823-L1826, "excessive input length".
    let window = cstring_window(part);
    let nalloc = window.len();
    if nalloc > CURL_MAX_INPUT_LENGTH {
        return CURLUE_MALFORMED_INPUT;
    }

    // L1828-L1875. `storep` is the C's `char **storep`, as a selector: writing
    // through `CurlUrl::store` releases the displaced buffer as part of the
    // assignment, so the `curlx_free(*storep)` at L1994 cannot be forgotten
    // and cannot happen in the wrong order.
    let storep = match what {
        CURLUPART_SCHEME => {
            let status = set_url_scheme(u, window, flags);
            if status != CURLUE_OK {
                return status;
            }
            // L1834, "never".
            urlencode = false;
            equalsencode = false;
            StringField::Scheme
        }
        CURLUPART_USER => {
            equalsencode = false;
            StringField::User
        }
        CURLUPART_PASSWORD => {
            equalsencode = false;
            StringField::Password
        }
        CURLUPART_OPTIONS => {
            equalsencode = false;
            StringField::Options
        }
        CURLUPART_HOST => {
            // L1846-L1849. The zone identifier goes even if the host that
            // replaces it is refused below: `FB3`'s assigning half.
            u.clear(StringField::ZoneId);
            equalsencode = false;
            StringField::Host
        }
        CURLUPART_ZONEID => {
            equalsencode = false;
            StringField::ZoneId
        }
        // L1853-L1854. No encoding, no dynamic buffer, no store through
        // `storep`: the delegate does all of it.
        CURLUPART_PORT => return set_url_port(u, window),
        CURLUPART_PATH => {
            // L1855-L1859. The slash is enforced rather than requested.
            pathmode = true;
            leadingslash = true;
            equalsencode = false;
            StringField::Path
        }
        CURLUPART_QUERY => {
            // L1860-L1866. `plusencode` follows the caller's encode request,
            // and `equalsencode` follows the append request rather than the
            // encode one, so the first `=` of an appended query survives
            // encoding.
            plusencode = urlencode;
            appendquery = (flags & CURLU_APPENDQUERY) != 0;
            equalsencode = appendquery;
            u.set_query_present(true);
            StringField::Query
        }
        CURLUPART_FRAGMENT => {
            u.set_fragment_present(true);
            equalsencode = false;
            StringField::Fragment
        }
        CURLUPART_URL => return set_url(u, window, nalloc, flags),
        // L1873-L1874. A real `default:` arm, unlike `url_get`'s.
        _ => return CURLUE_UNKNOWN_PART,
    };

    // L1877-L1880. Three bytes is the widest a single input byte can encode
    // to, plus the terminator, plus the inserted slash if there is one.
    // Saturation cannot trigger: `nalloc` is bounded by `CURL_MAX_INPUT_LENGTH`
    // above, so the product is at most twenty-four million.
    let ceiling = nalloc
        .saturating_mul(3)
        .saturating_add(1)
        .saturating_add(usize::from(leadingslash));
    let mut enc = DynBuf::new(ceiling);

    // L1882-L1886. An empty part has no first byte, and the C reads its
    // terminator there, which is not a slash either -- so an empty path
    // becomes `"/"`.
    if leadingslash && window.first() != Some(&b'/') {
        let result = enc.addn(b"/");
        if result.is_err() {
            return cc2cu(result);
        }
    }

    // L1887-L1933, the two exclusive byte paths. Both live in `src/encode.rs`
    // with the character classifications they consult: L1887-L1915 is the
    // encoder, L1916-L1933 the verbatim copy followed by the pass that
    // lower-cases escapes already present in the input.
    let coded = if urlencode {
        encode_part(&mut enc, window, pathmode, plusencode, equalsencode)
    } else {
        add_preencoded(&mut enc, window)
    };
    if coded != CURLUE_OK {
        return coded;
    }

    // L1934, `newp = curlx_dyn_ptr(&enc)`. What matters at the three sites
    // that consult it is whether there is an allocation at all, not whether
    // there is content: a buffer nothing was ever appended to answers with a
    // null pointer. That happens for an empty part under `CURLU_URLENCODE`,
    // where the encoder writes nothing, and the store at L1995 then makes the
    // field absent rather than empty.
    let newp_exists = enc.capacity() != 0;

    if appendquery && newp_exists {
        // L1936-L1963. "Append the 'newp' string onto the old query. Add a '&'
        // separator if none is present at the end of the existing query
        // already".
        //
        // L1940-L1941, read out as scalars so that no borrow of the handle is
        // still live when the store below needs it uniquely.
        let (querylen, addamperand) = match u.query() {
            Some(query) => (
                query.len(),
                !query.is_empty() && query.last() != Some(&b'&'),
            ),
            None => (0, false),
        };
        // L1942. An absent or *empty* existing query falls out of this block
        // entirely and reaches the plain store at L1994, so appending to an
        // empty query stores the new value alone with no separator.
        if querylen != 0 {
            let mut qbuf = DynBuf::new(CURL_MAX_INPUT_LENGTH);
            // L1946, the original query. Every failure below is the `goto
            // nomem` at L1959-L1961, whose `curlx_dyn_free(&enc)` is the drop
            // of `enc` as this function returns.
            if qbuf.addn(u.query().unwrap_or(EMPTY_PART)).is_err() {
                return CURLUE_OUT_OF_MEMORY;
            }
            if addamperand {
                // The separator, L1949-L1952. Nested rather than folded into
                // one `&&` condition, because the C nests it and because the
                // two tests answer different questions: whether a separator is
                // wanted at all, and whether appending it succeeded. Folding
                // them would make an allocation failure look like the absence
                // of a separator.
                if qbuf.addn(b"&").is_err() {
                    return CURLUE_OUT_OF_MEMORY;
                }
            }
            if qbuf.addn(enc.as_bytes()).is_err() {
                return CURLUE_OUT_OF_MEMORY;
            }
            // L1955, `curlx_dyn_free(&enc)`, explicit because the C is
            // explicit and because the combined buffer is what survives.
            drop(enc);
            // L1956-L1957. OWNERSHIP: the combined buffer's block came from
            // the C allocator, so the handle now owns a buffer its `Drop`
            // releases and `curl_url_cleanup()` would too.
            match qbuf.into_cbuf() {
                Some(value) => u.store(storep, value),
                None => u.clear(storep),
            }
            return CURLUE_OK;
        }
    } else if what == CURLUPART_HOST {
        // L1965. An `else if` chained to the append-query `if` above, so a
        // value that took the append path is never host-checked. Unreachable
        // in practice, because `appendquery` is set only for
        // `CURLUPART_QUERY`, and preserved because the shape is the
        // specification. The note sits inside the block rather than between
        // the `}` and the `else`, where Clippy 1.75 reads a comment splitting
        // the two as formatting that might hide the `else if`
        // (`clippy::suspicious_else_formatting`) and, under the zero-warning
        // requirement, fails the build.
        // L1966.
        let n = enc.len();
        if n == 0 && (flags & CURLU_NO_AUTHORITY) != 0 {
            // L1967-L1969: "Skip hostname check, it is allowed to be empty."
        } else {
            let mut bad = false;
            if n == 0 {
                // L1972-L1973, "empty hostname is not okay".
                bad = true;
            } else if !urlencode {
                // L1974-L1984: "if the hostname part was not URL encoded
                // here, it was set ready URL encoded so we need to decode it
                // to check". A decode failure and a refused host are the same
                // verdict.
                match urldecode(enc.as_bytes(), n, UrlReject::Ctrl) {
                    Ok(mut decoded) => {
                        let dlen = decoded.len();
                        if hostname_check(u, decoded.as_mut_bytes(), dlen) != CURLUE_OK {
                            bad = true;
                        }
                        // L1983 releases the decoded copy; `decoded` drops
                        // here and does the same.
                    }
                    Err(_) => bad = true,
                }
            } else {
                // L1985-L1986. The content is handed over with its terminator
                // slot, because the bracketed-host branch of the checker
                // writes one byte past the length -- `FB6` -- and the guard
                // restores the terminator when the borrow ends.
                let mut content = enc.content_mut();
                if hostname_check(u, &mut content, n) != CURLUE_OK {
                    bad = true;
                }
            }
            if bad {
                // L1987-L1990. The `curlx_dyn_free(&enc)` at L1988 is the drop
                // of `enc` as this function returns.
                return CURLUE_BAD_HOSTNAME;
            }
        }
    }

    // L1994-L1995. A null `newp` is stored as a null, which makes the field
    // absent rather than empty; see `newp_exists` above for when that happens.
    match enc.into_cbuf() {
        Some(value) => u.store(storep, value),
        None => u.clear(storep),
    }
    CURLUE_OK
}

#[cfg(test)]
mod tests {
    //! Tests for the serializer, the two dispatches and the four setters.
    //!
    //! # Where the expected values come from
    //!
    //! **Every one of them was measured against the reference implementation**,
    //! by linking a probe program against an unmodified `libcurl.a` built from
    //! this repository and printing what each call answered. That matters more
    //! here than in any other module of the crate: this file is where the
    //! observable output lives, so a value invented from reading the C would
    //! test the reading rather than the port. Where a case also appears in
    //! `tests/libtest/lib1560.c` its line is named, because a case the
    //! reference suite already asserts outranks one invented here.
    //!
    //! # Why every scheme below is `https`, `imap`, `file` or `rtmp`
    //!
    //! Both feature configurations have to be green, and they resolve schemes
    //! from different places: with `scheme-table` on, `src/scheme.rs` answers
    //! from its own built-in table, and with it off -- the drop-in
    //! configuration -- the lookup is `Curl_get_scheme` imported from a
    //! libcurl no test binary links against, for which `src/ffi.rs` supplies a
    //! four-row `cfg(test)` stand-in. Those four rows are the four schemes
    //! above, and they are exactly the ones this module needs: `https` has a
    //! default port and no `PROTOPT_URLOPTIONS`, `imap` has both, `file` has
    //! neither, and `rtmp` is found but not implemented, which is the
    //! disabled-protocol case.
    //!
    //! # `CURLU_NO_GUESS_SCHEME` and the empty-string write
    //!
    //! Writing `""` to `CURLUPART_URL` on a **guessed-scheme** handle with
    //! `CURLU_NO_GUESS_SCHEME` answers `CURLUE_MALFORMED_INPUT`, which is what
    //! `AAP` 0.6.5 specifies and what this file's specification restates as a
    //! mandatory test pair. Without the flag the same call is a no-op success.
    //! [`tests::an_empty_url_and_no_guess_scheme_is_malformed_input`] pins both
    //! halves.
    //!
    //! That answer is a **deliberate divergence from the reference**, and the
    //! honest thing is to say so here rather than let the test read as a
    //! transcription. Three separate observations put the reference on the
    //! other side:
    //!
    //! 1. **The source.** L1559-L1560, the guard that turns the flag into
    //!    `CURLUE_NO_SCHEME`, is in the `CURLUPART_SCHEME` arm. `set_url`
    //!    retrieves `CURLUPART_URL` at L1700, whose arm at L1624-L1625 goes to
    //!    `urlget_url` instead. There the same flag is read at L1512-L1515
    //!    only to *blank the scheme prefix*, never to fail, so the read
    //!    returns `CURLUE_OK` and L1701-L1706 would make the write a no-op
    //!    success.
    //! 2. **Measurement.** A probe linked against an unmodified `libcurl.a`
    //!    built from this repository answers `CURLUE_OK` for that exact call,
    //!    with and without the flag, and leaves the handle unchanged.
    //! 3. **`tests/libtest/lib1560.c`, unmodified.** Its `get_url_list` at
    //!    L583-L585 asserts `{"example.com", "example.com/",
    //!    CURLU_GUESS_SCHEME, CURLU_NO_GUESS_SCHEME, CURLUE_OK}` -- the read
    //!    L1700 performs, asserted to succeed with the prefix suppressed --
    //!    while its `get_parts_list` at L149-L152 asserts `[10]`,
    //!    `CURLUE_NO_SCHEME`, for the scheme part of the same handle under the
    //!    same flag. The two arms are asserted to differ.
    //!
    //! The plan governs the implementation all the same: 0.6.5 is frozen and
    //! states the failing answer, so the port returns it and records the
    //! conflict for the plan's owner instead of quietly preferring the
    //! reference. Two facts keep the cost at nothing measurable, and both were
    //! checked: `tests/libtest/lib1560.c` never writes `""` to
    //! `CURLUPART_URL` at all, so `A5` is untouched; and
    //! `rust-urlapi/demo/urlapi_demo.c` deliberately does not exercise this
    //! one combination, so `A7`'s byte-for-byte diff against the
    //! reference-linked demo is untouched as well. The READ side is unchanged
    //! and still matches the reference exactly, L583-L585 included.
    //! `docs/KNOWN-DIVERGENCES.md` carries the whole record.
    //!
    //! The empty-string case is flag-sensitive in a second, non-divergent way.
    //! [`tests::the_empty_url_decision_is_flag_sensitive`] pins it on
    //! `CURLU_DEFAULT_SCHEME`, which decides at L1453-L1458 whether a handle
    //! carrying a host and no scheme can serialize at all.

    // The crate root denies the panicking constructs so that no panic can ever
    // reach the C boundary. A test's whole job is to panic when an assertion
    // fails, and no test crosses that boundary, so the denials are relaxed
    // here and only here, enumerated rather than blanket. This is the same
    // allowance, for the same reason, as the ones in `src/parse/mod.rs` and
    // `src/encode.rs`.
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    extern crate alloc;

    use alloc::vec;

    use super::{
        cstring_window, portbuf_render, schemebuf_render, url_get, url_set, PORTBUF_LEN,
        SCHEMEBUF_LEN,
    };
    use crate::abi::{
        CURLUPart, CURLUcode, CURLUE_BAD_HOSTNAME, CURLUE_BAD_PORT_NUMBER, CURLUE_BAD_SCHEME,
        CURLUE_MALFORMED_INPUT, CURLUE_NO_FRAGMENT, CURLUE_NO_HOST, CURLUE_NO_OPTIONS,
        CURLUE_NO_PASSWORD, CURLUE_NO_PORT, CURLUE_NO_QUERY, CURLUE_NO_SCHEME, CURLUE_NO_USER,
        CURLUE_NO_ZONEID, CURLUE_OK, CURLUE_UNKNOWN_PART, CURLUE_UNSUPPORTED_SCHEME,
        CURLUE_URLDECODE, CURLUPART_FRAGMENT, CURLUPART_HOST, CURLUPART_OPTIONS,
        CURLUPART_PASSWORD, CURLUPART_PATH, CURLUPART_PORT, CURLUPART_QUERY, CURLUPART_SCHEME,
        CURLUPART_URL, CURLUPART_USER, CURLUPART_ZONEID, CURLU_APPENDQUERY, CURLU_DEFAULT_PORT,
        CURLU_DEFAULT_SCHEME, CURLU_GET_EMPTY, CURLU_GUESS_SCHEME, CURLU_NON_SUPPORT_SCHEME,
        CURLU_NO_AUTHORITY, CURLU_NO_DEFAULT_PORT, CURLU_NO_GUESS_SCHEME, CURLU_PUNY2IDN,
        CURLU_PUNYCODE, CURLU_URLDECODE, CURLU_URLENCODE, CURL_MAX_INPUT_LENGTH,
    };
    use crate::handle::CurlUrl;
    use crate::parse::parseurl_and_replace;
    use core::ffi::c_uint;

    /// No flags at all, which is what most cases below want.
    const NO_FLAGS: c_uint = 0;

    /// Bytes as text, for assertion messages only.
    fn shown(bytes: &[u8]) -> &str {
        core::str::from_utf8(bytes).unwrap_or("<not UTF-8>")
    }

    /// A handle parsed from `url`, which must parse.
    fn handle(url: &[u8], flags: c_uint) -> CurlUrl {
        let mut u = CurlUrl::new();
        let code = parseurl_and_replace(url, &mut u, flags);
        assert_eq!(
            code,
            CURLUE_OK,
            "[{}] must parse before it can be serialized",
            shown(url)
        );
        u
    }

    /// An empty handle, as `curl_url()` produces.
    fn empty() -> CurlUrl {
        CurlUrl::new()
    }

    /// Asserts that a part reads back as exactly these bytes.
    fn part_is(u: &CurlUrl, what: CURLUPart, flags: c_uint, expected: &[u8]) {
        match url_get(u, what, flags) {
            Ok(Some(buf)) => assert_eq!(
                buf.as_bytes(),
                expected,
                "part {what} with flags {flags:#x}: got [{}], want [{}]",
                shown(buf.as_bytes()),
                shown(expected)
            ),
            Ok(None) => panic!("part {what} with flags {flags:#x} succeeded with no buffer"),
            Err(code) => panic!("part {what} with flags {flags:#x} failed with {code}"),
        }
    }

    /// Asserts that a part reports exactly this code.
    fn part_fails(u: &CurlUrl, what: CURLUPart, flags: c_uint, expected: CURLUcode) {
        match url_get(u, what, flags) {
            Ok(Some(buf)) => panic!(
                "part {what} with flags {flags:#x} unexpectedly succeeded with [{}]",
                shown(buf.as_bytes())
            ),
            Ok(None) => panic!("part {what} with flags {flags:#x} succeeded with no buffer"),
            Err(code) => assert_eq!(
                code, expected,
                "part {what} with flags {flags:#x}: got code {code}, want {expected}"
            ),
        }
    }

    /// Asserts the serialized whole URL.
    fn url_is(u: &CurlUrl, flags: c_uint, expected: &[u8]) {
        part_is(u, CURLUPART_URL, flags, expected);
    }

    /// Assigns a part, reporting the code.
    fn set(u: &mut CurlUrl, what: CURLUPart, value: &[u8], flags: c_uint) -> CURLUcode {
        url_set(u, what, Some(value), flags)
    }

    /// Clears a part, reporting the code.
    fn clear(u: &mut CurlUrl, what: CURLUPart) -> CURLUcode {
        url_set(u, what, None, NO_FLAGS)
    }

    // ---------------------------------------------------------------------
    // urlget_url: the fifteen-argument template, L1517-L1532
    // ---------------------------------------------------------------------

    /// Every conditional of the template on its "present" side at once.
    ///
    /// `imap:` rather than `https:` because the options part exists in a URL
    /// only for a scheme owning `PROTOPT_URLOPTIONS`: with `https:` the
    /// reference parses `pwd;opt` as the whole password and reports code 13 for
    /// the options part, which the next test pins.
    #[test]
    fn every_conditional_of_the_template_is_emitted_when_all_parts_exist() {
        let u = handle(
            b"imap://user:pwd;opt@example.com:8080/path?q=1#frag",
            NO_FLAGS,
        );
        url_is(
            &u,
            NO_FLAGS,
            b"imap://user:pwd;opt@example.com:8080/path?q=1#frag",
        );
        // Each conversion's source, so a reordering of the template shows up
        // here as well as in the assembled string.
        part_is(&u, CURLUPART_SCHEME, NO_FLAGS, b"imap");
        part_is(&u, CURLUPART_USER, NO_FLAGS, b"user");
        part_is(&u, CURLUPART_PASSWORD, NO_FLAGS, b"pwd");
        part_is(&u, CURLUPART_OPTIONS, NO_FLAGS, b"opt");
        part_is(&u, CURLUPART_HOST, NO_FLAGS, b"example.com");
        part_is(&u, CURLUPART_PORT, NO_FLAGS, b"8080");
        part_is(&u, CURLUPART_PATH, NO_FLAGS, b"/path");
        part_is(&u, CURLUPART_QUERY, NO_FLAGS, b"q=1");
        part_is(&u, CURLUPART_FRAGMENT, NO_FLAGS, b"frag");
    }

    /// The same input under a scheme without the options capability: the
    /// semicolon and everything after it is password, not options.
    #[test]
    fn a_scheme_without_the_options_capability_has_no_options_to_emit() {
        let u = handle(
            b"https://user:pwd;opt@example.com:8080/path?q=1#frag",
            NO_FLAGS,
        );
        url_is(
            &u,
            NO_FLAGS,
            b"https://user:pwd;opt@example.com:8080/path?q=1#frag",
        );
        part_is(&u, CURLUPART_PASSWORD, NO_FLAGS, b"pwd;opt");
        part_fails(&u, CURLUPART_OPTIONS, NO_FLAGS, CURLUE_NO_OPTIONS);
    }

    /// Every conditional on its "absent" side. Only the scheme, the host and
    /// the substituted path survive.
    #[test]
    fn every_conditional_of_the_template_is_omitted_when_no_part_exists() {
        let u = handle(b"https://example.com", NO_FLAGS);
        url_is(&u, NO_FLAGS, b"https://example.com/");
    }

    /// L1528: an absent path serializes as a bare slash, and the query and
    /// fragment either side of it are unaffected.
    #[test]
    fn an_absent_path_serializes_as_a_bare_slash() {
        let mut u = handle(b"https://example.com/x?q#f", NO_FLAGS);
        assert_eq!(clear(&mut u, CURLUPART_PATH), CURLUE_OK);
        url_is(&u, NO_FLAGS, b"https://example.com/?q#f");
        // L1606-L1607, the getter's own substitution, which is a separate line
        // of the C reaching the same string.
        part_is(&u, CURLUPART_PATH, NO_FLAGS, b"/");
    }

    /// L1524: the `@` is emitted for a present-but-empty user, because the
    /// condition tests presence and not length.
    #[test]
    fn an_empty_user_still_emits_the_at_sign() {
        let mut u = handle(b"https://example.com/", NO_FLAGS);
        assert_eq!(set(&mut u, CURLUPART_USER, b"", NO_FLAGS), CURLUE_OK);
        part_is(&u, CURLUPART_USER, NO_FLAGS, b"");
        url_is(&u, NO_FLAGS, b"https://@example.com/");
    }

    /// L1477-L1478: the options part is suppressed from the serialized URL
    /// unless the scheme owns `PROTOPT_URLOPTIONS`, while remaining readable as
    /// a part either way. The guard is `h &&`, so a scheme the table does not
    /// hold keeps its options.
    #[test]
    fn the_options_part_needs_the_url_options_capability_to_be_serialized() {
        let mut owning = handle(b"imap://example.com/x", NO_FLAGS);
        assert_eq!(
            set(&mut owning, CURLUPART_OPTIONS, b"opt", NO_FLAGS),
            CURLUE_OK
        );
        url_is(&owning, NO_FLAGS, b"imap://;opt@example.com/x");
        part_is(&owning, CURLUPART_OPTIONS, NO_FLAGS, b"opt");

        let mut lacking = handle(b"https://example.com/x", NO_FLAGS);
        assert_eq!(
            set(&mut lacking, CURLUPART_OPTIONS, b"opt", NO_FLAGS),
            CURLUE_OK
        );
        url_is(&lacking, NO_FLAGS, b"https://example.com/x");
        part_is(&lacking, CURLUPART_OPTIONS, NO_FLAGS, b"opt");

        let mut unknown = handle(b"hej.hej://example.com/x", CURLU_NON_SUPPORT_SCHEME);
        assert_eq!(
            set(&mut unknown, CURLUPART_OPTIONS, b"opt", NO_FLAGS),
            CURLUE_OK
        );
        url_is(&unknown, NO_FLAGS, b"hej.hej://;opt@example.com/x");
    }

    /// L1440-L1447: the five-argument template, with no authority of any kind.
    #[test]
    fn the_file_branch_carries_no_authority() {
        let plain = handle(b"file:///path/to/file", NO_FLAGS);
        url_is(&plain, NO_FLAGS, b"file:///path/to/file");
        part_fails(&plain, CURLUPART_HOST, NO_FLAGS, CURLUE_NO_HOST);

        let decorated = handle(b"file:///x?q#f", NO_FLAGS);
        url_is(&decorated, NO_FLAGS, b"file:///x?q#f");
    }

    /// L1442 with an absent path: `curl_maprintf` renders a null `%s` as
    /// `(nil)`, so the reference serializes `file://(nil)`. Measured, not
    /// guessed, and reproduced rather than tidied.
    #[test]
    fn a_file_url_with_no_path_renders_the_nil_string() {
        let mut u = handle(b"file:///x", NO_FLAGS);
        assert_eq!(clear(&mut u, CURLUPART_PATH), CURLUE_OK);
        url_is(&u, NO_FLAGS, b"file://(nil)");
    }

    /// L1448-L1449, and L1453-L1458 for the scheme half.
    #[test]
    fn a_hostless_handle_reports_no_host_and_a_schemeless_one_no_scheme() {
        let mut hostless = handle(b"https://example.com/", NO_FLAGS);
        assert_eq!(clear(&mut hostless, CURLUPART_HOST), CURLUE_OK);
        part_fails(&hostless, CURLUPART_URL, NO_FLAGS, CURLUE_NO_HOST);

        let mut schemeless = empty();
        assert_eq!(
            set(&mut schemeless, CURLUPART_HOST, b"example.com", NO_FLAGS),
            CURLUE_OK
        );
        part_fails(&schemeless, CURLUPART_URL, NO_FLAGS, CURLUE_NO_SCHEME);
        // L1455-L1456: the default fills the gap, and it is `https`.
        url_is(&schemeless, CURLU_DEFAULT_SCHEME, b"https://example.com/");
    }

    /// L1461-L1475: injection and suppression, and the `if / else if` shape
    /// that makes them alternatives rather than independent steps.
    ///
    /// All three both-flags shapes are asserted, because what selects the arm
    /// is whether a port is stored and not which flag was passed, so neither
    /// flag has blanket precedence and one case cannot stand for the others.
    #[test]
    fn the_default_port_is_injected_and_a_matching_stored_one_suppressed() {
        let none_stored = handle(b"https://example.com/x", NO_FLAGS);
        url_is(
            &none_stored,
            CURLU_DEFAULT_PORT,
            b"https://example.com:443/x",
        );
        url_is(&none_stored, NO_FLAGS, b"https://example.com/x");
        // Both flags, nothing stored: `!port` holds, so the injecting branch
        // runs and `CURLU_NO_DEFAULT_PORT` never gets a say.
        url_is(
            &none_stored,
            CURLU_DEFAULT_PORT | CURLU_NO_DEFAULT_PORT,
            b"https://example.com:443/x",
        );

        let matching = handle(b"https://example.com:443/x", NO_FLAGS);
        url_is(&matching, CURLU_NO_DEFAULT_PORT, b"https://example.com/x");
        url_is(&matching, NO_FLAGS, b"https://example.com:443/x");
        // Both flags: `port` is set, so the first condition is false and the
        // suppressing branch is the one that runs. Same flags as above, other
        // answer.
        url_is(
            &matching,
            CURLU_DEFAULT_PORT | CURLU_NO_DEFAULT_PORT,
            b"https://example.com/x",
        );

        let differing = handle(b"https://example.com:8080/x", NO_FLAGS);
        url_is(
            &differing,
            CURLU_NO_DEFAULT_PORT,
            b"https://example.com:8080/x",
        );
        // Both flags with a stored port that differs: the second branch runs
        // and its inner equality test fails, so the port is kept. The third of
        // the three answers one flag pair can produce.
        url_is(
            &differing,
            CURLU_DEFAULT_PORT | CURLU_NO_DEFAULT_PORT,
            b"https://example.com:8080/x",
        );

        // A second scheme, so the port really comes from the table rather than
        // from a constant that happens to be 443.
        let other = handle(b"imap://example.com/x", NO_FLAGS);
        url_is(&other, CURLU_DEFAULT_PORT, b"imap://example.com:143/x");

        // A scheme the table does not hold gets no injection at all.
        let unknown = handle(b"hej.hej://example.com/x", CURLU_NON_SUPPORT_SCHEME);
        url_is(&unknown, CURLU_DEFAULT_PORT, b"hej.hej://example.com/x");
    }

    /// L1480-L1491: the zone identifier is spliced into a bracketed host in its
    /// percent-encoded form, and a bracketed host without one is emitted
    /// unchanged.
    #[test]
    fn a_bracketed_host_emits_its_zone_identifier() {
        let zoned = handle(b"https://[fe80::20c:29ff:fe9c:409b%25eth0]/hello", NO_FLAGS);
        part_is(
            &zoned,
            CURLUPART_HOST,
            NO_FLAGS,
            b"[fe80::20c:29ff:fe9c:409b]",
        );
        part_is(&zoned, CURLUPART_ZONEID, NO_FLAGS, b"eth0");
        url_is(
            &zoned,
            NO_FLAGS,
            b"https://[fe80::20c:29ff:fe9c:409b%25eth0]/hello",
        );

        let plain = handle(b"https://[::1]/hello", NO_FLAGS);
        part_fails(&plain, CURLUPART_ZONEID, NO_FLAGS, CURLUE_NO_ZONEID);
        url_is(&plain, NO_FLAGS, b"https://[::1]/hello");
    }

    /// The chain at L1480-L1510 is exclusive: a bracketed host takes the first
    /// branch, so `CURLU_URLENCODE` never reaches it.
    #[test]
    fn the_bracket_branch_wins_over_url_encoding() {
        let u = handle(b"https://[fe80::1%25eth0]/p", NO_FLAGS);
        url_is(&u, NO_FLAGS, b"https://[fe80::1%25eth0]/p");
        url_is(&u, CURLU_URLENCODE, b"https://[fe80::1%25eth0]/p");
    }

    /// L1492-L1496: on this path the host **is** escaped, which is the
    /// opposite of `urlencode_str`'s deliberate host exemption. The host below
    /// is `\xc3\xa4.se`, the UTF-8 spelling of a Latin small a with diaeresis
    /// followed by `.se`, written as byte escapes because this file is ASCII.
    #[test]
    fn the_whole_url_path_escapes_the_host_when_encoding_is_requested() {
        let mut u = handle(b"https://example.com/p", NO_FLAGS);
        assert_eq!(
            set(&mut u, CURLUPART_HOST, b"\xc3\xa4.se", NO_FLAGS),
            CURLUE_OK
        );
        url_is(&u, NO_FLAGS, b"https://\xc3\xa4.se/p");
        url_is(&u, CURLU_URLENCODE, b"https://%C3%A4.se/p");

        // A host made only of unreserved bytes escapes to itself, so the
        // branch is a no-op rather than absent.
        let unreserved = handle(b"https://a_b~c.se/p", NO_FLAGS);
        url_is(&unreserved, CURLU_URLENCODE, b"https://a_b~c.se/p");
    }

    /// L1432-L1435: the fragment half tests presence alone, the query half
    /// additionally requires a non-empty first byte.
    #[test]
    fn the_query_and_fragment_are_shown_under_the_conditions_the_c_sets() {
        let query_only = handle(b"https://curl.se/?", NO_FLAGS);
        url_is(&query_only, CURLU_GET_EMPTY, b"https://curl.se/?");
        url_is(&query_only, NO_FLAGS, b"https://curl.se/");

        let fragment_only = handle(b"https://curl.se/#", NO_FLAGS);
        url_is(&fragment_only, CURLU_GET_EMPTY, b"https://curl.se/#");
        url_is(&fragment_only, NO_FLAGS, b"https://curl.se/");

        let both = handle(b"https://curl.se/?#", NO_FLAGS);
        url_is(&both, CURLU_GET_EMPTY, b"https://curl.se/?#");
        url_is(&both, NO_FLAGS, b"https://curl.se/");

        // A non-empty query needs no flag.
        let real = handle(b"https://curl.se/?a#b", NO_FLAGS);
        url_is(&real, NO_FLAGS, b"https://curl.se/?a#b");
    }

    /// `FB1`, second observable, L1512-L1515: the prefix is suppressed for a
    /// guessed scheme under `CURLU_NO_GUESS_SCHEME` -- and reappears on a
    /// duplicate, because `curl_url_dup` does not copy the marker.
    ///
    /// `tests/libtest/lib1560.c` L583-L585 pins the original half with the
    /// expected output `example.com/`.
    #[test]
    fn a_guessed_scheme_is_suppressed_from_the_serialized_url() {
        let u = handle(b"example.com", CURLU_GUESS_SCHEME);
        url_is(&u, NO_FLAGS, b"http://example.com/");
        url_is(&u, CURLU_NO_GUESS_SCHEME, b"example.com/");

        let copy = u.dup().expect("the duplication must succeed");
        url_is(&copy, NO_FLAGS, b"http://example.com/");
        // The divergence: the same call on the copy emits the prefix.
        url_is(&copy, CURLU_NO_GUESS_SCHEME, b"http://example.com/");

        // An explicit scheme is unaffected by the flag, on either handle.
        let explicit = handle(b"https://example.com/", NO_FLAGS);
        url_is(&explicit, CURLU_NO_GUESS_SCHEME, b"https://example.com/");
    }

    // ---------------------------------------------------------------------
    // url_get: the retrieval dispatch, L1541-L1634
    // ---------------------------------------------------------------------

    /// Every arm's `ifmissing`, on a handle that has nothing.
    ///
    /// This is `get_nothing()` at `tests/libtest/lib1560.c` L1811-L1859,
    /// case for case, including that the path arm succeeds with `"/"` where
    /// every other arm reports a code.
    #[test]
    fn every_part_reports_its_own_missing_code() {
        let u = empty();
        part_fails(&u, CURLUPART_SCHEME, NO_FLAGS, CURLUE_NO_SCHEME);
        part_fails(&u, CURLUPART_USER, NO_FLAGS, CURLUE_NO_USER);
        part_fails(&u, CURLUPART_PASSWORD, NO_FLAGS, CURLUE_NO_PASSWORD);
        part_fails(&u, CURLUPART_OPTIONS, NO_FLAGS, CURLUE_NO_OPTIONS);
        part_fails(&u, CURLUPART_HOST, NO_FLAGS, CURLUE_NO_HOST);
        part_fails(&u, CURLUPART_ZONEID, NO_FLAGS, CURLUE_NO_ZONEID);
        part_fails(&u, CURLUPART_PORT, NO_FLAGS, CURLUE_NO_PORT);
        part_fails(&u, CURLUPART_QUERY, NO_FLAGS, CURLUE_NO_QUERY);
        part_fails(&u, CURLUPART_FRAGMENT, NO_FLAGS, CURLUE_NO_FRAGMENT);
        // L1604-L1608: the one arm with no missing-code, because it cannot be
        // missing.
        part_is(&u, CURLUPART_PATH, NO_FLAGS, b"/");
        // And the whole-URL arm, which fails inside `urlget_url` instead.
        part_fails(&u, CURLUPART_URL, NO_FLAGS, CURLUE_NO_HOST);
    }

    /// L1626-L1628 on the get side and L1873-L1874 on both set sides: an
    /// out-of-range part is code 9, never a crash. The values below are past
    /// `CURLUPART_ZONEID`, which is 10, and negative.
    #[test]
    fn an_out_of_range_part_is_unknown_rather_than_fatal() {
        let mut u = handle(b"https://example.com/", NO_FLAGS);
        for what in [11, 99, CURLUPart::MAX, -1, CURLUPart::MIN] {
            part_fails(&u, what, NO_FLAGS, CURLUE_UNKNOWN_PART);
            assert_eq!(
                set(&mut u, what, b"x", NO_FLAGS),
                CURLUE_UNKNOWN_PART,
                "assigning part {what}"
            );
            assert_eq!(
                clear(&mut u, what),
                CURLUE_UNKNOWN_PART,
                "clearing part {what}"
            );
        }
        // Nothing was disturbed by any of that.
        url_is(&u, NO_FLAGS, b"https://example.com/");
    }

    /// L1613-L1615 and L1620-L1622, the two blank-value rules, which are not
    /// the same rule: the query arm removes an empty answer without the flag,
    /// the fragment arm adds one with it.
    #[test]
    fn the_blank_query_and_fragment_rules_are_mirror_images() {
        let query = handle(b"https://curl.se/?", NO_FLAGS);
        part_fails(&query, CURLUPART_QUERY, NO_FLAGS, CURLUE_NO_QUERY);
        part_is(&query, CURLUPART_QUERY, CURLU_GET_EMPTY, b"");

        let fragment = handle(b"https://curl.se/#", NO_FLAGS);
        part_fails(&fragment, CURLUPART_FRAGMENT, NO_FLAGS, CURLUE_NO_FRAGMENT);
        part_is(&fragment, CURLUPART_FRAGMENT, CURLU_GET_EMPTY, b"");

        // A non-empty value needs no flag and is unaffected by it.
        let real = handle(b"https://curl.se/?a#b", NO_FLAGS);
        part_is(&real, CURLUPART_QUERY, NO_FLAGS, b"a");
        part_is(&real, CURLUPART_QUERY, CURLU_GET_EMPTY, b"a");
        part_is(&real, CURLUPART_FRAGMENT, NO_FLAGS, b"b");
    }

    /// L1558 and L1585: two arms clear `CURLU_URLDECODE` from the caller's
    /// flags before formatting, so a percent sequence in a scheme or a port
    /// survives. The port cannot hold one at all, which is why the assertion
    /// is that the flag changes nothing.
    #[test]
    fn the_scheme_and_port_arms_ignore_url_decoding() {
        let u = handle(b"https://example.com:8080/%41", NO_FLAGS);
        part_is(&u, CURLUPART_SCHEME, CURLU_URLDECODE, b"https");
        part_is(&u, CURLUPART_PORT, CURLU_URLDECODE, b"8080");
        // The path arm does not clear it, which is what makes the two above
        // meaningful.
        part_is(&u, CURLUPART_PATH, NO_FLAGS, b"/%41");
        part_is(&u, CURLUPART_PATH, CURLU_URLDECODE, b"/A");
    }

    /// L1612: plus-decoding belongs to the query arm alone, and only when
    /// decoding was asked for.
    #[test]
    fn plus_decoding_is_the_query_part_s_alone() {
        let u = handle(b"https://example.com/a+b?c+d=e%20f#g+h", NO_FLAGS);
        part_is(&u, CURLUPART_QUERY, NO_FLAGS, b"c+d=e%20f");
        part_is(&u, CURLUPART_QUERY, CURLU_URLDECODE, b"c d=e f");
        // The path and fragment keep their plus signs even while decoding.
        part_is(&u, CURLUPART_PATH, CURLU_URLDECODE, b"/a+b");
        part_is(&u, CURLUPART_FRAGMENT, CURLU_URLDECODE, b"g+h");
    }

    /// L1383-L1388: a control byte is refused unconditionally while decoding,
    /// and the code is flattened to `CURLUE_URLDECODE` whatever the underlying
    /// failure was.
    #[test]
    fn a_rejected_control_byte_is_reported_as_a_decode_failure() {
        let u = handle(b"https://example.com/%01", NO_FLAGS);
        part_is(&u, CURLUPART_PATH, NO_FLAGS, b"/%01");
        part_fails(&u, CURLUPART_PATH, CURLU_URLDECODE, CURLUE_URLDECODE);
    }

    /// `FB1`, first observable, L1559-L1560, and its behaviour on a duplicate.
    ///
    /// `tests/libtest/lib1560.c` L150-L152 pins the original half: the scheme
    /// column of its expected output is `[10]`, which is `CURLUE_NO_SCHEME`.
    #[test]
    fn a_guessed_scheme_reads_as_missing_under_no_guess_scheme() {
        let u = handle(b"example.com", CURLU_GUESS_SCHEME);
        part_is(&u, CURLUPART_SCHEME, NO_FLAGS, b"http");
        part_fails(
            &u,
            CURLUPART_SCHEME,
            CURLU_NO_GUESS_SCHEME,
            CURLUE_NO_SCHEME,
        );

        let copy = u.dup().expect("the duplication must succeed");
        part_is(&copy, CURLUPART_SCHEME, NO_FLAGS, b"http");
        // The divergence: the copy answers with the scheme instead of code 10.
        part_is(&copy, CURLUPART_SCHEME, CURLU_NO_GUESS_SCHEME, b"http");

        // Assigning a scheme clears the marker, so the flag stops mattering.
        let mut assigned = handle(b"example.com", CURLU_GUESS_SCHEME);
        assert_eq!(
            set(&mut assigned, CURLUPART_SCHEME, b"https", NO_FLAGS),
            CURLUE_OK
        );
        part_is(&assigned, CURLUPART_SCHEME, CURLU_NO_GUESS_SCHEME, b"https");
    }

    /// L1586 and L1595: both branches of the port arm additionally require a
    /// scheme, so a handle with a host and none gets neither injection nor
    /// suppression.
    #[test]
    fn the_port_arm_needs_a_scheme_before_the_table_is_consulted() {
        let mut schemeless = empty();
        assert_eq!(
            set(&mut schemeless, CURLUPART_HOST, b"example.com", NO_FLAGS),
            CURLUE_OK
        );
        part_fails(
            &schemeless,
            CURLUPART_PORT,
            CURLU_DEFAULT_PORT,
            CURLUE_NO_PORT,
        );

        let injected = handle(b"https://example.com/", NO_FLAGS);
        part_fails(&injected, CURLUPART_PORT, NO_FLAGS, CURLUE_NO_PORT);
        part_is(&injected, CURLUPART_PORT, CURLU_DEFAULT_PORT, b"443");

        let stored = handle(b"https://example.com:443/", NO_FLAGS);
        part_is(&stored, CURLUPART_PORT, NO_FLAGS, b"443");
        part_fails(
            &stored,
            CURLUPART_PORT,
            CURLU_NO_DEFAULT_PORT,
            CURLUE_NO_PORT,
        );
        // Both flags: the stored port takes the second branch, so it is
        // suppressed rather than re-injected.
        part_fails(
            &stored,
            CURLUPART_PORT,
            CURLU_DEFAULT_PORT | CURLU_NO_DEFAULT_PORT,
            CURLUE_NO_PORT,
        );

        let differing = handle(b"https://example.com:8080/", NO_FLAGS);
        part_is(&differing, CURLUPART_PORT, CURLU_NO_DEFAULT_PORT, b"8080");

        // A scheme the table holds but does not implement still has a default
        // port, which is what makes "found" and "usable" different questions.
        let unimplemented = handle(b"rtmp://example.com/", CURLU_NON_SUPPORT_SCHEME);
        part_is(&unimplemented, CURLUPART_PORT, CURLU_DEFAULT_PORT, b"1935");
    }

    /// L1399 and L1421: an empty part retrieved with `CURLU_URLENCODE`
    /// succeeds while producing no buffer at all, because the encoder appends
    /// nothing and `curlx_dyn_ptr` on an untouched buffer is null.
    ///
    /// Measured against the reference, which returns `CURLUE_OK` with `*part`
    /// still null. `src/ffi.rs` leaves the null it wrote at L1552 in place.
    #[test]
    fn an_empty_part_under_url_encoding_succeeds_with_no_buffer() {
        let u = handle(b"https://curl.se/?", NO_FLAGS);
        // Without encoding the empty query is a real, empty buffer.
        part_is(&u, CURLUPART_QUERY, CURLU_GET_EMPTY, b"");
        // With it, success carries nothing.
        match url_get(&u, CURLUPART_QUERY, CURLU_GET_EMPTY | CURLU_URLENCODE) {
            Ok(None) => (),
            Ok(Some(buf)) => panic!("expected no buffer, got [{}]", shown(buf.as_bytes())),
            Err(code) => panic!("expected success, got code {code}"),
        }
    }

    /// L1365-L1366: the two internationalized-domain flags are inert for every
    /// part but the host, so they cannot disturb a path or a query.
    #[test]
    fn the_punycode_flags_do_nothing_for_a_part_that_is_not_the_host() {
        let u = handle(b"https://example.com/p?q#f", NO_FLAGS);
        part_is(&u, CURLUPART_PATH, CURLU_PUNYCODE, b"/p");
        part_is(&u, CURLUPART_QUERY, CURLU_PUNY2IDN, b"q");
        part_is(&u, CURLUPART_FRAGMENT, CURLU_PUNYCODE, b"f");
        // An all-ASCII host is unchanged by either flag as well, because the
        // gates at L1402 and L1412 test the host itself.
        part_is(&u, CURLUPART_HOST, CURLU_PUNYCODE, b"example.com");
    }

    // ---------------------------------------------------------------------
    // url_set: the assignment dispatch, L1805-L1998
    // ---------------------------------------------------------------------

    /// L1823-L1826. One byte past the ceiling is refused; the ceiling itself is
    /// not, which is what makes the comparison strict rather than inclusive.
    #[test]
    fn an_excessive_length_is_malformed_input() {
        let mut u = handle(b"https://example.com/", NO_FLAGS);
        let over = vec![b'a'; CURL_MAX_INPUT_LENGTH + 1];
        assert_eq!(
            set(&mut u, CURLUPART_FRAGMENT, &over, NO_FLAGS),
            CURLUE_MALFORMED_INPUT
        );
        // The refusal happens before the switch, so nothing was touched --
        // including the fragment-present bit the fragment arm would have set.
        url_is(&u, CURLU_GET_EMPTY, b"https://example.com/");
    }

    /// L1666-L1683 through L1854: the port is parsed, range-checked and
    /// re-rendered from the number, which is how leading zeros disappear.
    ///
    /// `tests/libtest/lib1560.c` L592-L597 pins the long-zero-run cases through
    /// the parser; these go through the setter, which uses the same scanner.
    #[test]
    fn the_port_arm_parses_range_checks_and_canonicalizes() {
        for (input, expected) in [
            (&b"80"[..], &b"80"[..]),
            (b"080", b"80"),
            (b"0000000000000000000443", b"443"),
            (b"0", b"0"),
            (b"65535", b"65535"),
        ] {
            let mut u = handle(b"https://example.com/", NO_FLAGS);
            assert_eq!(
                set(&mut u, CURLUPART_PORT, input, NO_FLAGS),
                CURLUE_OK,
                "port [{}]",
                shown(input)
            );
            part_is(&u, CURLUPART_PORT, NO_FLAGS, expected);
        }

        // L1670 refuses a first byte that is not a digit -- including the
        // terminator of an empty string, a leading space and a sign -- and
        // L1673 refuses an out-of-range number and any trailing byte.
        for input in [
            &b""[..],
            b"x",
            b" 80",
            b"-1",
            b"+80",
            b"65536",
            b"99999",
            b"8x",
            b"80 ",
            b"80.",
        ] {
            let mut u = handle(b"https://example.com:1/", NO_FLAGS);
            assert_eq!(
                set(&mut u, CURLUPART_PORT, input, NO_FLAGS),
                CURLUE_BAD_PORT_NUMBER,
                "port [{}]",
                shown(input)
            );
            // The refusal happens before the store, so the old port stands.
            part_is(&u, CURLUPART_PORT, NO_FLAGS, b"1");
        }
    }

    /// L1636-L1664 through L1830, including the pre-decrement loop.
    ///
    /// The three-way split is the point: a scheme the table holds is accepted
    /// without a syntax check, a scheme it does not hold is syntax-checked, and
    /// the check never looks at the last byte. `h*` is therefore **accepted**
    /// and `h*x` refused, which is exactly what the reference does.
    #[test]
    fn the_scheme_arm_validates_with_the_c_s_own_pre_decrement_loop() {
        for (scheme, flags, expected) in [
            // In the table and implemented.
            (&b"https"[..], NO_FLAGS, CURLUE_OK),
            // In the table but with no implementation: the disabled-protocol
            // case, which needs the caller's permission.
            (b"rtmp", NO_FLAGS, CURLUE_UNSUPPORTED_SCHEME),
            (b"rtmp", CURLU_NON_SUPPORT_SCHEME, CURLUE_OK),
            // Not in the table: syntax-checked.
            (b"hej.hej", CURLU_NON_SUPPORT_SCHEME, CURLUE_OK),
            (b"ht-tp", CURLU_NON_SUPPORT_SCHEME, CURLUE_OK),
            (b"ftp+more", CURLU_NON_SUPPORT_SCHEME, CURLUE_OK),
            (b"f1337", CURLU_NON_SUPPORT_SCHEME, CURLUE_OK),
            // A first byte that is not a letter, L1650 and L1660.
            (b"1h", CURLU_NON_SUPPORT_SCHEME, CURLUE_BAD_SCHEME),
            (b"*", CURLU_NON_SUPPORT_SCHEME, CURLUE_BAD_SCHEME),
            (b"..", CURLU_NON_SUPPORT_SCHEME, CURLUE_BAD_SCHEME),
            // Length bounds, L1641: one byte is fine, forty is fine,
            // forty-one is not, zero is not.
            (b"h", CURLU_NON_SUPPORT_SCHEME, CURLUE_OK),
            (
                b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                CURLU_NON_SUPPORT_SCHEME,
                CURLUE_OK,
            ),
            (
                b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                CURLU_NON_SUPPORT_SCHEME,
                CURLUE_BAD_SCHEME,
            ),
            (b"", NO_FLAGS, CURLUE_BAD_SCHEME),
            // The pre-decrement, in three shapes. `h*` has two bytes, so the
            // loop body runs once and inspects only `h`; `hx*` has three, so it
            // inspects `h` and `x`; `h*x` also has three, and the `*` it
            // inspects second is refused.
            (b"h*", CURLU_NON_SUPPORT_SCHEME, CURLUE_OK),
            (b"hx*", CURLU_NON_SUPPORT_SCHEME, CURLUE_OK),
            (b"h*x", CURLU_NON_SUPPORT_SCHEME, CURLUE_BAD_SCHEME),
        ] {
            let mut u = handle(b"https://example.com/", NO_FLAGS);
            assert_eq!(
                set(&mut u, CURLUPART_SCHEME, scheme, flags),
                expected,
                "scheme [{}] with flags {flags:#x}",
                shown(scheme)
            );
        }
    }

    /// L1848 and L1752-L1753: `FB3`. Assigning a host releases the zone
    /// identifier; clearing one keeps it.
    #[test]
    fn the_host_arm_clears_the_zone_identifier_but_clearing_the_host_does_not() {
        let zoned = b"https://[fe80::20c:29ff:fe9c:409b%25eth0]/x";

        let mut assigned = handle(zoned, NO_FLAGS);
        part_is(&assigned, CURLUPART_ZONEID, NO_FLAGS, b"eth0");
        assert_eq!(
            set(&mut assigned, CURLUPART_HOST, b"example.com", NO_FLAGS),
            CURLUE_OK
        );
        part_fails(&assigned, CURLUPART_ZONEID, NO_FLAGS, CURLUE_NO_ZONEID);

        let mut cleared = handle(zoned, NO_FLAGS);
        assert_eq!(clear(&mut cleared, CURLUPART_HOST), CURLUE_OK);
        // The zone survives a cleared host, and is unreachable from the
        // serialized URL because there is no host to bracket.
        part_is(&cleared, CURLUPART_ZONEID, NO_FLAGS, b"eth0");
        part_fails(&cleared, CURLUPART_URL, NO_FLAGS, CURLUE_NO_HOST);

        // A refused host still costs the zone identifier, because L1848 runs
        // before the value is validated at L1965.
        let mut refused = handle(zoned, NO_FLAGS);
        assert_eq!(
            set(&mut refused, CURLUPART_HOST, b"exa mple", NO_FLAGS),
            CURLUE_BAD_HOSTNAME
        );
        part_fails(&refused, CURLUPART_ZONEID, NO_FLAGS, CURLUE_NO_ZONEID);
    }

    /// L1856-L1857 and L1882-L1886: the path arm inserts a leading slash when
    /// the value does not start with one -- and an empty value has no first
    /// byte, so it becomes `"/"` too.
    #[test]
    fn the_path_arm_enforces_a_leading_slash() {
        let mut u = handle(b"https://example.com/", NO_FLAGS);
        assert_eq!(set(&mut u, CURLUPART_PATH, b"x/y", NO_FLAGS), CURLUE_OK);
        part_is(&u, CURLUPART_PATH, NO_FLAGS, b"/x/y");

        assert_eq!(set(&mut u, CURLUPART_PATH, b"/a/b", NO_FLAGS), CURLUE_OK);
        part_is(&u, CURLUPART_PATH, NO_FLAGS, b"/a/b");

        assert_eq!(set(&mut u, CURLUPART_PATH, b"", NO_FLAGS), CURLUE_OK);
        part_is(&u, CURLUPART_PATH, NO_FLAGS, b"/");

        assert_eq!(set(&mut u, CURLUPART_PATH, b"", CURLU_URLENCODE), CURLUE_OK);
        part_is(&u, CURLUPART_PATH, NO_FLAGS, b"/");
    }

    /// L1856 and L1897-L1899: path mode preserves seventeen bytes beyond the
    /// unreserved set, and the query it is compared against does not.
    #[test]
    fn path_mode_preserves_more_bytes_than_the_unreserved_set() {
        let mut u = handle(b"https://example.com/", NO_FLAGS);
        assert_eq!(
            set(&mut u, CURLUPART_PATH, b"/a=b&c:d@e/f g", CURLU_URLENCODE),
            CURLUE_OK
        );
        part_is(&u, CURLUPART_PATH, NO_FLAGS, b"/a=b&c:d@e/f%20g");

        assert_eq!(
            set(&mut u, CURLUPART_QUERY, b"a=b&c:d@e/f g", CURLU_URLENCODE),
            CURLUE_OK
        );
        // Space becomes `+` here rather than `%20`, because the query arm sets
        // `plusencode` at L1861.
        part_is(&u, CURLUPART_QUERY, NO_FLAGS, b"a%3Db%26c%3Ad%40e%2Ff+g");
    }

    /// L1936-L1963: the separator is added only when the existing query has
    /// content that does not already end in one, and an **empty** existing
    /// query falls out of the block entirely.
    ///
    /// The first three cases are `append_list` at `tests/libtest/lib1560.c`
    /// L1612-L1628 with `http:` changed to `https:`; the fourth is the empty
    /// case that table does not cover.
    #[test]
    fn appending_a_query_adds_a_separator_only_when_one_is_needed() {
        for (base, expected) in [
            // Content not ending in `&`: a separator is inserted.
            (&b"https://test/?s"[..], &b"s&name=joe"[..]),
            // Content already ending in `&`: none is.
            (b"https://test/?size=2&", b"size=2&name=joe"),
            // No query at all: the block is skipped by `querylen`.
            (b"https://test/", b"name=joe"),
            // A present but empty query: also skipped, so no stray `&`.
            (b"https://test/?", b"name=joe"),
        ] {
            let mut u = handle(base, NO_FLAGS);
            assert_eq!(
                set(&mut u, CURLUPART_QUERY, b"name=joe", CURLU_APPENDQUERY),
                CURLUE_OK,
                "base [{}]",
                shown(base)
            );
            part_is(&u, CURLUPART_QUERY, NO_FLAGS, expected);
        }

        // L1863 and L1900-L1902: appending sets `equalsencode`, so the first
        // `=` survives encoding and any later one does not. This is
        // `tests/libtest/lib1560.c` L1615-L1616.
        let mut u = handle(b"https://test/?size=2#f", NO_FLAGS);
        assert_eq!(
            set(
                &mut u,
                CURLUPART_QUERY,
                b"name=joe=",
                CURLU_APPENDQUERY | CURLU_URLENCODE
            ),
            CURLUE_OK
        );
        url_is(&u, NO_FLAGS, b"https://test/?size=2&name=joe%3D#f");
    }

    /// L1965-L1992: the host validation block, all four of its outcomes.
    #[test]
    fn a_host_is_validated_unless_no_authority_permits_an_empty_one() {
        // L1967-L1969: empty is allowed only with the flag, and stores empty.
        let mut permitted = handle(b"https://example.com/", NO_FLAGS);
        assert_eq!(
            set(&mut permitted, CURLUPART_HOST, b"", CURLU_NO_AUTHORITY),
            CURLUE_OK
        );
        part_is(&permitted, CURLUPART_HOST, NO_FLAGS, b"");

        // L1972-L1973: without it, empty is bad.
        let mut refused = handle(b"https://example.com/", NO_FLAGS);
        assert_eq!(
            set(&mut refused, CURLUPART_HOST, b"", NO_FLAGS),
            CURLUE_BAD_HOSTNAME
        );
        part_is(&refused, CURLUPART_HOST, NO_FLAGS, b"example.com");

        // L1974-L1984: not encoding here means the value arrives already
        // encoded, so it is decoded before the check -- and `%20` decodes to a
        // space, which no host may contain.
        for host in [&b"exa mple"[..], b"exa%20mple", b"a%2fb", b"a%00b"] {
            let mut u = handle(b"https://example.com/", NO_FLAGS);
            assert_eq!(
                set(&mut u, CURLUPART_HOST, host, NO_FLAGS),
                CURLUE_BAD_HOSTNAME,
                "host [{}]",
                shown(host)
            );
        }

        // L1985-L1986: when encoding, the *encoded* value is checked, so a
        // space becomes `%20` and the percent sign is then itself refused.
        let mut encoded = handle(b"https://example.com/", NO_FLAGS);
        assert_eq!(
            set(&mut encoded, CURLUPART_HOST, b"exa mple", CURLU_URLENCODE),
            CURLUE_BAD_HOSTNAME
        );

        // Acceptable hosts, encoded and not.
        let mut good = handle(b"https://example.com/", NO_FLAGS);
        assert_eq!(
            set(&mut good, CURLUPART_HOST, b"[::1]", NO_FLAGS),
            CURLUE_OK
        );
        part_is(&good, CURLUPART_HOST, NO_FLAGS, b"[::1]");
        assert_eq!(
            set(&mut good, CURLUPART_HOST, b"a-b.example", CURLU_URLENCODE),
            CURLUE_OK
        );
        part_is(&good, CURLUPART_HOST, NO_FLAGS, b"a-b.example");
    }

    /// L1916-L1933: assigning without `CURLU_URLENCODE` copies the value and
    /// lower-cases the percent escapes already in it, leaving a sequence that
    /// is not an escape alone.
    #[test]
    fn escapes_already_present_are_lower_cased_when_not_encoding() {
        let mut u = handle(b"https://example.com/", NO_FLAGS);
        assert_eq!(
            set(&mut u, CURLUPART_QUERY, b"a=%AB%cD%ZZ%4", NO_FLAGS),
            CURLUE_OK
        );
        part_is(&u, CURLUPART_QUERY, NO_FLAGS, b"a=%ab%cd%ZZ%4");
    }

    /// L1934 and L1995: an empty value under `CURLU_URLENCODE` leaves the
    /// dynamic buffer unallocated, and the null that comes out of it makes the
    /// field **absent** rather than empty. Without the flag the same value
    /// stores an empty string.
    #[test]
    fn an_empty_value_under_url_encoding_makes_the_field_absent() {
        let mut plain = handle(b"https://example.com/", NO_FLAGS);
        assert_eq!(set(&mut plain, CURLUPART_USER, b"", NO_FLAGS), CURLUE_OK);
        part_is(&plain, CURLUPART_USER, NO_FLAGS, b"");
        url_is(&plain, NO_FLAGS, b"https://@example.com/");

        let mut encoded = handle(b"https://example.com/", NO_FLAGS);
        assert_eq!(
            set(&mut encoded, CURLUPART_USER, b"", CURLU_URLENCODE),
            CURLUE_OK
        );
        part_fails(&encoded, CURLUPART_USER, NO_FLAGS, CURLUE_NO_USER);
        url_is(&encoded, NO_FLAGS, b"https://example.com/");
    }

    /// L1865 and L1869: the two presence bits are set by assignment, so an
    /// assigned empty value is reportable under `CURLU_GET_EMPTY`.
    ///
    /// The whole-URL line is the asymmetry of L1432-L1435 caught in the act.
    /// An *assigned* empty fragment is a present, zero-length string, and
    /// `show_fragment` tests presence alone -- so the `#` is emitted with no
    /// flag at all. `show_query` also requires a non-empty first byte, so the
    /// `?` is not. Measured against the reference, which serializes
    /// `https://example.com/#`.
    #[test]
    fn assigning_a_query_or_fragment_sets_its_presence_bit() {
        let mut u = handle(b"https://example.com/", NO_FLAGS);
        assert_eq!(set(&mut u, CURLUPART_QUERY, b"", NO_FLAGS), CURLUE_OK);
        assert_eq!(set(&mut u, CURLUPART_FRAGMENT, b"", NO_FLAGS), CURLUE_OK);
        part_is(&u, CURLUPART_QUERY, CURLU_GET_EMPTY, b"");
        part_is(&u, CURLUPART_FRAGMENT, CURLU_GET_EMPTY, b"");
        url_is(&u, CURLU_GET_EMPTY, b"https://example.com/?#");
        url_is(&u, NO_FLAGS, b"https://example.com/#");
    }

    // ---------------------------------------------------------------------
    // set_url: the whole-URL assignment, L1685-L1730
    // ---------------------------------------------------------------------

    /// L1697-L1710: the empty string as a relative URL that changes nothing.
    ///
    /// The no-flags half of the mandatory pair. A handle that can serialize
    /// itself accepts `""` as a relative URL and nothing about it changes, on a
    /// guessed-scheme handle and on an explicit-scheme one alike. The failing
    /// half of the same pair is
    /// [`an_empty_url_and_no_guess_scheme_is_malformed_input`], and
    /// [`an_empty_url_on_an_incomplete_handle_is_malformed_input`] pins the
    /// other way the empty write fails.
    #[test]
    fn an_empty_url_is_a_no_op_success_on_a_complete_handle() {
        let mut guessed = handle(b"example.com", CURLU_GUESS_SCHEME);
        assert_eq!(
            url_set(&mut guessed, CURLUPART_URL, Some(b""), NO_FLAGS),
            CURLUE_OK
        );
        url_is(&guessed, NO_FLAGS, b"http://example.com/");

        let mut explicit = handle(b"https://example.com/p?q#f", NO_FLAGS);
        assert_eq!(
            url_set(
                &mut explicit,
                CURLUPART_URL,
                Some(b""),
                CURLU_NO_GUESS_SCHEME
            ),
            CURLUE_OK,
            "this handle's scheme was not guessed, so the AAP 0.6.5 arm does \
             not apply and the empty write is the ordinary no-op"
        );
        url_is(&explicit, NO_FLAGS, b"https://example.com/p?q#f");
    }

    /// `AAP` 0.6.5: an empty whole-URL write carrying `CURLU_NO_GUESS_SCHEME`
    /// on a handle whose scheme was **guessed** is `CURLUE_MALFORMED_INPUT`.
    ///
    /// This is the mandatory pair the file's specification names, asserted here
    /// in both halves on one handle so that neither can be satisfied by
    /// accident: same handle, same empty value, the flag the only difference.
    ///
    /// It is also the port's one deliberate divergence from the reference,
    /// which answers `CURLUE_OK` here for the reason the module preamble sets
    /// out. Two properties keep the divergence contained, and both are asserted
    /// below rather than asserted about:
    ///
    /// * The **read** side is untouched. `CURLUPART_URL` under the same flag on
    ///   the same handle still succeeds with the scheme prefix suppressed,
    ///   which is exactly the vector `tests/libtest/lib1560.c` asserts at
    ///   L583-L585. A port that had made the read fail instead would break that
    ///   oracle.
    /// * The handle is **unchanged** by the refusal, so the failure is a
    ///   refusal and not a partial mutation.
    ///
    /// The guessed-scheme marker is what selects the arm, so a handle carrying
    /// the same scheme explicitly is asserted to be unaffected in
    /// [`an_empty_url_is_a_no_op_success_on_a_complete_handle`].
    #[test]
    fn an_empty_url_and_no_guess_scheme_is_malformed_input() {
        let mut u = handle(b"example.com", CURLU_GUESS_SCHEME);

        // The read the reference would have used to decide this write. It
        // succeeds, with the prefix blanked, and must keep doing so:
        // tests/libtest/lib1560.c L583-L585 asserts this exact vector.
        url_is(&u, CURLU_NO_GUESS_SCHEME, b"example.com/");

        assert_eq!(
            url_set(&mut u, CURLUPART_URL, Some(b""), CURLU_NO_GUESS_SCHEME),
            CURLUE_MALFORMED_INPUT,
            "AAP 0.6.5 requires malformed input for an empty whole-URL write \
             carrying CURLU_NO_GUESS_SCHEME on a guessed-scheme handle"
        );

        // Nothing moved: both serializations still answer what they did before.
        url_is(&u, CURLU_NO_GUESS_SCHEME, b"example.com/");
        url_is(&u, NO_FLAGS, b"http://example.com/");

        // And the other half of the pair, on the same handle.
        assert_eq!(
            url_set(&mut u, CURLUPART_URL, Some(b""), NO_FLAGS),
            CURLUE_OK,
            "without the flag the same empty write is the ordinary no-op"
        );
        url_is(&u, NO_FLAGS, b"http://example.com/");
    }

    /// L1700, the real flag sensitivity: the caller's flags are handed to the
    /// serialization, so whether the empty string is a no-op depends on whether
    /// *those flags* let this handle serialize at all.
    ///
    /// A handle with a host and no scheme cannot, unless
    /// `CURLU_DEFAULT_SCHEME` supplies one at L1455-L1456. Same handle, same
    /// empty value, two different answers.
    #[test]
    fn the_empty_url_decision_is_flag_sensitive() {
        let mut u = empty();
        assert_eq!(
            set(&mut u, CURLUPART_HOST, b"example.com", NO_FLAGS),
            CURLUE_OK
        );
        // The serialization this depends on, both ways round.
        part_fails(&u, CURLUPART_URL, NO_FLAGS, CURLUE_NO_SCHEME);
        url_is(&u, CURLU_DEFAULT_SCHEME, b"https://example.com/");

        assert_eq!(
            url_set(&mut u, CURLUPART_URL, Some(b""), NO_FLAGS),
            CURLUE_MALFORMED_INPUT
        );
        assert_eq!(
            url_set(&mut u, CURLUPART_URL, Some(b""), CURLU_DEFAULT_SCHEME),
            CURLUE_OK
        );
    }

    /// L1709 by way of L1448-L1449: a handle with nothing in it cannot
    /// serialize, so the empty string is malformed input rather than a no-op.
    #[test]
    fn an_empty_url_on_an_incomplete_handle_is_malformed_input() {
        let mut nothing = empty();
        assert_eq!(
            url_set(&mut nothing, CURLUPART_URL, Some(b""), NO_FLAGS),
            CURLUE_MALFORMED_INPUT
        );

        let mut scheme_only = empty();
        assert_eq!(
            set(&mut scheme_only, CURLUPART_SCHEME, b"https", NO_FLAGS),
            CURLUE_OK
        );
        assert_eq!(
            url_set(&mut scheme_only, CURLUPART_URL, Some(b""), NO_FLAGS),
            CURLUE_MALFORMED_INPUT
        );
    }

    /// L1713-L1715: an absolute value replaces everything, including the query
    /// and fragment the old handle carried.
    #[test]
    fn an_absolute_value_replaces_the_whole_handle() {
        let mut u = handle(b"https://a.example/p?x#y", NO_FLAGS);
        assert_eq!(
            url_set(&mut u, CURLUPART_URL, Some(b"imap://b.example/z"), NO_FLAGS),
            CURLUE_OK
        );
        url_is(&u, NO_FLAGS, b"imap://b.example/z");
        part_fails(&u, CURLUPART_QUERY, NO_FLAGS, CURLUE_NO_QUERY);
        part_fails(&u, CURLUPART_FRAGMENT, NO_FLAGS, CURLUE_NO_FRAGMENT);
    }

    /// L1727: the relative part is resolved against the serialized handle, in
    /// each of the four shapes `redirect_url` branches on.
    #[test]
    fn a_relative_value_is_resolved_against_the_serialized_handle() {
        for (relative, expected) in [
            (&b"../r"[..], &b"https://a.example/r"[..]),
            (b"/root", b"https://a.example/root"),
            (b"#frag", b"https://a.example/p/q?x#frag"),
            (b"?q2", b"https://a.example/p/q?q2"),
            (b"//other.example/x", b"https://other.example/x"),
            (b"seg", b"https://a.example/p/seg"),
        ] {
            let mut u = handle(b"https://a.example/p/q?x#y", NO_FLAGS);
            assert_eq!(
                url_set(&mut u, CURLUPART_URL, Some(relative), NO_FLAGS),
                CURLUE_OK,
                "relative [{}]",
                shown(relative)
            );
            url_is(&u, NO_FLAGS, expected);
        }
    }

    /// L1722-L1723: when the handle cannot serialize, the relative value is
    /// parsed as if it had been absolute -- and then usually fails, which is
    /// the code the caller sees.
    #[test]
    fn a_relative_value_is_reparsed_when_the_handle_cannot_serialize() {
        let mut u = empty();
        assert_eq!(set(&mut u, CURLUPART_SCHEME, b"https", NO_FLAGS), CURLUE_OK);
        // `path` is not an absolute URL, and the handle has no host, so the
        // parse of `path` on its own is what answers -- with code 27, because
        // guessing is off and `path` has no scheme.
        assert_eq!(
            url_set(&mut u, CURLUPART_URL, Some(b"path"), NO_FLAGS),
            CURLUE_BAD_SCHEME
        );
        part_fails(&u, CURLUPART_URL, NO_FLAGS, CURLUE_NO_HOST);
    }

    // ---------------------------------------------------------------------
    // urlset_clear: L1732-L1777
    // ---------------------------------------------------------------------

    /// `clear_url_list` at `tests/libtest/lib1560.c` L1862-L1874: assign a
    /// part, clear the whole URL, read the part back. Every part reports its
    /// missing code afterwards, except the path, which reports `"/"`.
    #[test]
    fn clearing_the_whole_url_empties_every_part_and_keeps_the_handle() {
        let assigned: [(CURLUPart, &[u8], CURLUcode); 9] = [
            (CURLUPART_USER, b"user", CURLUE_NO_USER),
            (CURLUPART_PASSWORD, b"password", CURLUE_NO_PASSWORD),
            (CURLUPART_OPTIONS, b"options", CURLUE_NO_OPTIONS),
            (CURLUPART_HOST, b"host", CURLUE_NO_HOST),
            (CURLUPART_ZONEID, b"eth0", CURLUE_NO_ZONEID),
            (CURLUPART_PORT, b"1234", CURLUE_NO_PORT),
            (CURLUPART_PATH, b"/hello", CURLUE_OK),
            (CURLUPART_QUERY, b"a=b", CURLUE_NO_QUERY),
            (CURLUPART_FRAGMENT, b"anchor", CURLUE_NO_FRAGMENT),
        ];
        for (what, value, after) in assigned {
            let mut u = empty();
            assert_eq!(
                set(&mut u, what, value, NO_FLAGS),
                CURLUE_OK,
                "assigning part {what}"
            );
            assert_eq!(clear(&mut u, CURLUPART_URL), CURLUE_OK);
            if after == CURLUE_OK {
                part_is(&u, what, NO_FLAGS, b"/");
            } else {
                part_fails(&u, what, NO_FLAGS, after);
            }
        }

        // The scheme, whose assignment needs a real scheme name.
        let mut u = empty();
        assert_eq!(set(&mut u, CURLUPART_SCHEME, b"https", NO_FLAGS), CURLUE_OK);
        assert_eq!(clear(&mut u, CURLUPART_URL), CURLUE_OK);
        part_fails(&u, CURLUPART_SCHEME, NO_FLAGS, CURLUE_NO_SCHEME);

        // And the handle is still usable, which is what `clear_url()` relies
        // on: it reuses one handle for all eleven rows.
        let mut reused = handle(b"https://user@example.com:8080/hello?a=b#c", NO_FLAGS);
        assert_eq!(clear(&mut reused, CURLUPART_URL), CURLUE_OK);
        assert_eq!(
            url_set(
                &mut reused,
                CURLUPART_URL,
                Some(b"https://second.example/"),
                NO_FLAGS
            ),
            CURLUE_OK
        );
        url_is(&reused, NO_FLAGS, b"https://second.example/");
    }

    /// L1759-L1760: clearing the port zeroes the number as well as releasing
    /// the text, so a later default-port comparison cannot match a stale value.
    #[test]
    fn clearing_the_port_zeroes_the_number_too() {
        let mut u = handle(b"https://example.com:443/", NO_FLAGS);
        assert_eq!(clear(&mut u, CURLUPART_PORT), CURLUE_OK);
        part_fails(&u, CURLUPART_PORT, NO_FLAGS, CURLUE_NO_PORT);
        // The injection branch runs, which it could not if the text were still
        // there, and the number it compares against is no longer 443.
        url_is(&u, CURLU_DEFAULT_PORT, b"https://example.com:443/");
        url_is(&u, NO_FLAGS, b"https://example.com/");
    }

    /// L1741: clearing the scheme clears the guessed marker with it, so the
    /// flag that `FB1` turns on stops mattering.
    #[test]
    fn clearing_the_scheme_clears_the_guess_marker() {
        let mut u = handle(b"example.com", CURLU_GUESS_SCHEME);
        assert_eq!(clear(&mut u, CURLUPART_SCHEME), CURLUE_OK);
        part_fails(&u, CURLUPART_SCHEME, NO_FLAGS, CURLUE_NO_SCHEME);
        assert_eq!(set(&mut u, CURLUPART_SCHEME, b"https", NO_FLAGS), CURLUE_OK);
        part_is(&u, CURLUPART_SCHEME, CURLU_NO_GUESS_SCHEME, b"https");
        url_is(&u, CURLU_NO_GUESS_SCHEME, b"https://example.com/");
    }

    /// L1767 and L1771: clearing a query or fragment clears its presence bit,
    /// so `CURLU_GET_EMPTY` stops reporting it.
    #[test]
    fn clearing_the_query_and_fragment_clears_their_presence_bits() {
        let mut u = handle(b"https://example.com/?a#b", NO_FLAGS);
        assert_eq!(clear(&mut u, CURLUPART_QUERY), CURLUE_OK);
        assert_eq!(clear(&mut u, CURLUPART_FRAGMENT), CURLUE_OK);
        part_fails(&u, CURLUPART_QUERY, CURLU_GET_EMPTY, CURLUE_NO_QUERY);
        part_fails(&u, CURLUPART_FRAGMENT, CURLU_GET_EMPTY, CURLUE_NO_FRAGMENT);
        url_is(&u, CURLU_GET_EMPTY, b"https://example.com/");
    }

    // ---------------------------------------------------------------------
    // The three scratch helpers
    // ---------------------------------------------------------------------

    /// [`portbuf_render`] against every boundary an `unsigned short` has, and
    /// against the C's `snprintf` ceiling it can never reach.
    #[test]
    fn the_port_scratch_buffer_renders_every_boundary_value() {
        for (value, expected) in [
            (0_u16, &b"0"[..]),
            (1, b"1"),
            (9, b"9"),
            (10, b"10"),
            (80, b"80"),
            (443, b"443"),
            (1935, b"1935"),
            (9999, b"9999"),
            (10_000, b"10000"),
            (65_535, b"65535"),
        ] {
            let mut buf = [0_u8; PORTBUF_LEN];
            let written = portbuf_render(&mut buf, value);
            assert_eq!(&buf[..written], expected, "port {value}");
            // The widest value still leaves the terminator slot the C's
            // `snprintf` needs.
            assert!(written < PORTBUF_LEN, "port {value} filled the buffer");
        }
    }

    /// [`schemebuf_render`], including the truncation the C's `snprintf` would
    /// perform on a scheme no code path can actually produce.
    #[test]
    fn the_scheme_scratch_buffer_truncates_rather_than_overflowing() {
        let mut buf = [0_u8; SCHEMEBUF_LEN];
        let written = schemebuf_render(&mut buf, b"https");
        assert_eq!(&buf[..written], b"https://");

        // Forty bytes of scheme is the documented maximum and fits with room
        // to spare: forty plus three is forty-three, inside forty-four.
        let longest = [b'a'; 40];
        let written = schemebuf_render(&mut buf, &longest);
        assert_eq!(written, 43);
        assert_eq!(&buf[40..written], b"://");

        // Past it, the render stops at `SCHEMEBUF_LEN - 1` instead of writing
        // outside the buffer.
        let oversized = [b'a'; 100];
        let written = schemebuf_render(&mut buf, &oversized);
        assert_eq!(written, SCHEMEBUF_LEN - 1);

        // An empty scheme still emits the punctuation, which is what the C's
        // `"%s://"` does.
        let written = schemebuf_render(&mut buf, b"");
        assert_eq!(&buf[..written], b"://");
    }

    /// [`cstring_window`] is the `strlen()` the C applies to a caller's
    /// pointer: everything from an interior NUL onwards is invisible.
    #[test]
    fn the_c_string_window_stops_at_an_interior_nul() {
        assert_eq!(cstring_window(b"abc"), b"abc");
        assert_eq!(cstring_window(b"abc\0def"), b"abc");
        assert_eq!(cstring_window(b"\0abc"), b"");
        assert_eq!(cstring_window(b""), b"");

        // And it is applied where the C measures, so a value with an interior
        // NUL is stored up to that point only.
        let mut u = handle(b"https://example.com/", NO_FLAGS);
        assert_eq!(
            set(&mut u, CURLUPART_FRAGMENT, b"ab\0cd", NO_FLAGS),
            CURLUE_OK
        );
        part_is(&u, CURLUPART_FRAGMENT, NO_FLAGS, b"ab");
    }
}
