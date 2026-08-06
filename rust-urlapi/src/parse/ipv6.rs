// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Bracketed IPv6 addresses: validation, zone identifiers, normalization.
//!
//! Port of `ipv6_parse`, `lib/urlapi.c` L389-L442. Fifty-three lines of C,
//! and the only stage of the parser that rewrites the host buffer in place
//! rather than building a new one. Two of the six faithfully reproduced
//! oddities in `docs/KNOWN-DIVERGENCES.md` live here, `FB3` and `FB6`, and
//! both are consequences of that in-place rewriting.
//!
//! # Entry contract
//!
//! The C signature is `(struct Curl_URL *u, char *hostname, size_t hlen)`
//! and its preconditions are stated by the comment at L389 and the assertion
//! at L394: `hostname` points at a `[`, and `hlen` is the length of the
//! whole bracketed host. `hostname` is a NUL-terminated C string of exactly
//! `hlen` bytes, so `hlen + 1` bytes of it are writable.
//!
//! [`ipv6_parse`] keeps all three arguments, and `hostname` is the writable
//! extent rather than only the content: `hostname.len()` must be at least
//! `hlen + 1`. That is not a convenience. `FB6` writes a terminator at index
//! `hlen` of the caller's buffer, so a view trimmed to `hlen` bytes could
//! not express the C's behavior at all, and the two ways around that are
//! both unacceptable -- changing what happens to input at the maximum
//! length, or reaching for `unsafe` in a parser module. `src/dynbuf.rs`
//! documents the same requirement from the other side, as contract 2 and as
//! the reason [`crate::dynbuf::DynBuf::content_mut`] hands out `leng + 1`
//! bytes.
//!
//! # Four call sites, two shapes of buffer
//!
//! The C reaches this function from four places, and they do not all hand it
//! a dynamic buffer, which is why the port takes a slice rather than a
//! [`crate::dynbuf::DynBuf`]:
//!
//! - `parse_authority` at `lib/urlapi.c` L638 calls it directly, as
//!   `ipv6_parse(u, curlx_dyn_ptr(host), curlx_dyn_len(host))`, once
//!   `ipv4_normalize` has answered `HOST_IPV6`. That answer is returned at
//!   L491-L492 on a leading `[` **without validating anything**, so every
//!   check on a bracketed host is this module's alone.
//! - `hostname_check` at L453 forwards `hostname` and `hlen` unchanged after
//!   testing `hostname[0] == '['` at L452. It is itself called from three
//!   places:
//!   - L643, the `HOST_NAME` arm of `parse_authority`, again over the host
//!     dynamic buffer. A `[` can appear there only after percent-decoding.
//!   - L1981, inside the `CURLUPART_HOST` arm of `set_url_part`, over the
//!     `Curl_urldecode` result and its `dlen`. That buffer is released at
//!     L1983 immediately afterwards, so the rewriting is thrown away and the
//!     only lasting effects are the verdict and the zone identifier. This is
//!     how `curl_url_set(u, CURLUPART_HOST, "[fe80::1%25eth0]", 0)` comes to
//!     set a zone at all, which the `scopeid` sub-test relies on.
//!   - L1985, the same arm when the value was encoded here, over the
//!     encoding buffer and its length.
//!
//! On the `parse_authority` path the closing bracket is guaranteed:
//! `Curl_parse_port` at L343-L346 rejects a bracketed host with no `]`, and
//! L370 truncates the buffer to end just after it. On the `set_url_part`
//! paths there is no such guarantee, and the algorithm below needs none.
//!
//! # The rebase, which is where the offsets come from
//!
//! L397-L398 advance the pointer past the `[` and shorten the length by two,
//! so that from L401 onward every index is relative to the **inner** span
//! and excludes both brackets:
//!
//! ```text
//! absolute:  0    1                       hlen-1   hlen
//!            [    <---- inner span ---->   ]        NUL
//! inner:          0                        hlen-2
//! ```
//!
//! Everything below therefore works on `inner`, obtained once as
//! `hostname.get_mut(1..)`, and on a length that starts at `hlen - 2`. The
//! whole remaining extent is kept rather than just the inner span, because
//! the writes reach the caller's terminator slot.
//!
//! # Why no `unsafe`, and why nothing is trimmed
//!
//! The highest index this function ever writes is `hlen` of the caller's
//! buffer -- the terminator slot, and no further. The argument is short
//! enough to check, and worth checking, because it is what lets `FB6` be
//! reproduced exactly with `get_mut` and no `unsafe`. Write `H` for the
//! `hlen` on entry, so the inner span is `H - 2` bytes and the inner C
//! string is `H - 1` bytes:
//!
//! 1. The zone-identifier branch runs only when `inner[len] == '%'`. A `%`
//!    is not the terminator, so `len <= H - 2`, and its two writes land at
//!    inner `len` and `len + 1`, that is absolute `len + 1 <= H - 1` and
//!    `len + 2 <= H`.
//! 2. If the span test found no illegal byte at all, `len` is the inner C
//!    string length `H - 1`, and `inner[len]` is the terminator rather than a
//!    `%`, so L424-L425 rejects the input. Normalization is therefore
//!    reached only with a length of at most `H - 2`.
//! 3. Normalization writes inner `hlen`, absolute `hlen + 1 <= H - 1`; hands
//!    `inet_ntop` an extent of `hlen + 1` inner bytes, absolute `hlen + 1 <=
//!    H - 1` at the top; and then writes inner `hlen + 1` for a length that
//!    can only have shrunk, absolute at most `H`.
//!
//! `tests::the_highest_byte_written_is_the_terminator_slot` checks the
//! conclusion by experiment over every vector in the module rather than
//! leaving it to this argument.
//!
//! # The logical length is deliberately left stale
//!
//! The C rewrites the bytes behind the dynamic buffer's back: nothing here
//! calls `curlx_dyn_setlen`, so `curlx_dyn_len(host)` still reports the
//! bracketed length the caller appended, even after normalization has
//! shortened the address. Callers do not notice, because what they use next
//! is the pointer -- `Curl_url_set_authority` at L672 stores
//! `curlx_dyn_ptr(&host)` into `u->host` and the C string ends at the first
//! terminator. This port reproduces both halves: the observable bytes and
//! the untouched length. Correcting the bookkeeping is out of scope and
//! would change what `parse_authority`'s caller sees.
//!
//! # `FB3`: the zone identifier is overwritten without a release, and never
//! cleared
//!
//! `docs/KNOWN-DIVERGENCES.md` records this as `FB3`. The assignment at
//! `lib/urlapi.c` L418 is `u->zoneid = curlx_strdup(zoneid)`, with no
//! `curlx_free` of whatever `u->zoneid` already held and no `else` branch
//! clearing it when the host carries no zone. Two consequences are
//! observable and both are preserved here:
//!
//! 1. On the live-handle path a previous zone identifier is overwritten
//!    without being released. `Curl_url_set_authority` at L658-L675 parses
//!    into a handle that already holds data -- `lib/http2.c` L739 calls it
//!    that way for HTTP/2 server push -- so any earlier zone leaks.
//! 2. A stale zone identifier survives a host replacement that removes the
//!    zone, because this function assigns on the zone branch only. It stops
//!    appearing in a serialized URL, since L1480-L1491 emits the zone for a
//!    bracketed host alone, yet it stays readable through
//!    `CURLUPART_ZONEID`.
//!
//! The second is asymmetric with the host setter, which **does** release the
//! zone, at L1848. Measured against the reference build, that release is why
//! `curl_url_set(u, CURLUPART_HOST, ...)` reports `CURLUE_NO_ZONEID`
//! afterwards while a direct authority parse does not. The asymmetry is the
//! finding; `src/getset.rs` owns L1848 and must keep clearing there, and
//! this module must keep not clearing here.
//!
//! **What diverges, and it is internal only.** Storing into the handle's
//! field releases the displaced buffer, because [`crate::alloc::CBuf`] has a
//! `Drop`. So this port does not literally leak where the C leaks. The
//! observable behavior is identical in both consequences above -- the new
//! value replaces the old, and no path clears the field -- and the leak is
//! not reachable through the URL API in any case. Recorded for
//! `docs/KNOWN-DIVERGENCES.md` under `FB3`, as behavior reproduced with an
//! internal difference, not as behavior corrected.
//!
//! # `FB6`: a terminator one byte past the logical length
//!
//! `docs/KNOWN-DIVERGENCES.md` records this as `FB6`. Two writes land one
//! byte above the length being tracked, `hostname[len + 1] = 0` at L422 and
//! `hostname[hlen + 1] = 0` at L437. The C gets away with it because a
//! dynamic buffer is always allocated at least `leng + 1` bytes and keeps a
//! terminator there, per `fit = len + idx + 1` at `lib/curlx/dynbuf.c` L72.
//!
//! Neither write is decoration. The second is what ends the host string
//! after normalization: `inet_ntop` puts its own terminator at inner
//! `hlen`, and the bracket restored at L439 immediately overwrites it, so
//! without the byte written at L437 the host would run on into whatever the
//! longer original left behind. Both are reproduced, and both are marked at
//! their sites.
//!
//! # The fifteen-byte zone cap rejects; it does not truncate
//!
//! The scan at L413 stops at fifteen bytes, and L415 then requires that it
//! stopped **on** a `]`. A sixteen-byte zone therefore stops on its
//! sixteenth byte and is rejected with `CURLUE_BAD_IPV6`. The truncation the
//! buffer size implies is real but unobservable, because the only path out of
//! the branch that keeps a truncated value would have to find `]` where the
//! sixteenth byte is.
//!
//! This was checked against the reference build rather than reasoned about,
//! because it is easy to get backwards: a fourteen-byte and a fifteen-byte
//! zone are accepted and returned whole, while sixteen and seventeen bytes
//! both answer 22, `CURLUE_BAD_IPV6`.
//!
//! # Where the parity oracle actually lives
//!
//! `curlx_inet_pton` and `curlx_inet_ntop` are macros, not functions:
//! `lib/curlx/inet_pton.h` L28-L46 and `lib/curlx/inet_ntop.h` L28-L46
//! expand them to the platform's own `inet_pton` and `inet_ntop` whenever
//! `HAVE_INET_PTON` and `HAVE_INET_NTOP` are defined, and only otherwise to
//! curl's in-tree Vixie-derived code. On the reference platform the
//! canonical form is therefore whatever the C library produces, which is
//! what `src/inet.rs` binds and what the tests below were checked against.
//! Two of its properties matter here and neither is obvious:
//!
//! - Compression picks the first of the longest runs of zero groups, so
//!   `fe80:0:0:0:409b::` comes back as `fe80::409b:0:0:0`, which
//!   `tests/libtest/lib1560.c` L616-L617 asserts.
//! - The canonical form can be **longer** than the input, in which case the
//!   `hlen + 1` extent is too small and the call fails. `1::2:3:4:5:6:7` is
//!   fourteen bytes and canonicalizes to fifteen, so the host is kept
//!   unnormalized and `https://[1::2:3:4:5:6:7]/` round-trips unchanged.
//!   That is why L435 tests the return value at all.
//!
//! End to end, this module is to be verified by the parity run over the
//! unmodified `tests/libtest/lib1560.c`. The sub-test that exercises it
//! hardest is `scopeid` at L1681-L1809, whose failure would show up as exit
//! code 6 in the mapping recorded in the plan; the bracketed hosts in
//! `set_url`, `get_parts` and `urldup` cover the rest.
//!
//! `rust-urlapi/scripts/run-parity.sh` is the script that is to drive that
//! run. It is a later deliverable and does not exist yet, so the tests at the
//! foot of this file are the only oracle this file can currently point at.

// The plan puts every `unsafe` block in `src/ffi.rs` (0.3.3) and the technical
// specification forbids `unsafe` outside FFI code (1.3.2.1). `forbid` rather
// than `deny` because an inner `allow` here would be a design change and
// should have to be argued for, not slipped in. This module rewrites a buffer
// in place and writes one byte past a logical length, which is exactly the
// shape of code that invites a raw pointer; the attribute turns "it did not
// need one" into a compiler guarantee. See the bounds argument in the module
// documentation for why it does not.
#![forbid(unsafe_code)]

use crate::abi::{CURLUcode, CURLUE_BAD_IPV6, CURLUE_OK, CURLUE_OUT_OF_MEMORY};
use crate::alloc::CBuf;
use crate::ctype::is_xdigit;
use crate::handle::{CurlUrl, StringField};
use crate::inet::{inet_ntop, inet_pton, ADDRSZ_IPV6, AF_INET6, PTON_SUCCESS};

/// The shortest bracketed host the parser accepts, four bytes.
///
/// `lib/urlapi.c` L395 with its own comment at the same line: `'[::]' is the
/// shortest possible valid string`. The comparison there is `hlen < 4`, so
/// four is accepted and three is not, and the reference build answers
/// `CURLUE_BAD_IPV6` for `[]`, `[:]` and `[1]` alike.
const MIN_BRACKETED_LEN: usize = 4;

/// `sizeof(zoneid)` at `lib/urlapi.c` L407, which declares `char zoneid[16]`.
const ZONEID_SIZE: usize = 16;

/// The scan limit at `lib/urlapi.c` L413, `i < 15`.
///
/// One below [`ZONEID_SIZE`], because L417 writes a terminator at `zoneid[i]`
/// once the loop has stopped and that write has to stay inside the array.
/// Written as a literal rather than derived, so that a reader diffing this
/// against L413 sees the same number, with the relationship asserted below
/// instead of assumed.
const ZONEID_CAP: usize = 15;

// The one relationship between the two constants above that the code depends
// upon: `i` can reach `ZONEID_CAP`, and L417 then writes at `zoneid[i]`, so
// the cap must leave that index inside the array. Checked at compile time so
// that raising one constant without the other cannot build.
//
// The allow is spelled the same way `src/inet.rs` and `src/ffi.rs` spell
// theirs, and `src/inet.rs` carries the measured account: on the pinned
// toolchain the lint does not fire for a comparison of named numeric constants,
// so the attribute is retained as a deliberate scoped exception covering the
// declared 1.75 floor rather than to suppress a finding.
#[allow(clippy::assertions_on_constants)]
const _: () = {
    assert!(ZONEID_CAP < ZONEID_SIZE);
};

/// One byte of the accepted address alphabet.
///
/// The `strspn` set at `lib/urlapi.c` L401 is the literal
/// `"0123456789abcdefABCDEF:."`, and its comment at L400 is `only valid IPv6
/// letters are ok`. That is the hexadecimal digits in both cases, plus the
/// group separator and the dot an embedded IPv4 quad needs, and nothing else:
/// no `%`, which is what makes the zone-identifier branch reachable, and no
/// `]`, which is what makes the span stop at the closing bracket.
///
/// Expressed through [`crate::ctype::is_xdigit`] rather than by carrying a
/// second copy of the sixteen digit characters. That predicate is `ISXDIGIT`
/// from `lib/curl_ctype.h` L39 and accepts exactly `0-9`, `a-f` and `A-F`, so
/// the two spellings describe the same set;
/// `tests::the_span_set_is_the_c_string_literal` proves it by sweeping all
/// 256 byte values against the literal itself.
///
/// The terminator is not in the set, which is the property that makes
/// [`address_span`] stop where `strspn` stops without needing to know the
/// string's length.
const fn is_address_byte(byte: u8) -> bool {
    is_xdigit(byte) || matches!(byte, b':' | b'.')
}

/// The length of the leading run of address bytes.
///
/// `strspn(hostname, "0123456789abcdefABCDEF:.")` at `lib/urlapi.c` L401.
///
/// `strspn` walks a C string and stops at the first byte outside the set,
/// which includes the terminator. This walks a slice and stops at the first
/// byte outside the set, which likewise includes the terminator, so the two
/// agree for any input satisfying the entry contract: the caller's buffer is
/// a C string, so a terminator is present and is reached before the slice
/// runs out.
///
/// The `unwrap_or` arm is what happens when there is no such byte at all,
/// which means the caller handed over a slice with no terminator in it. The
/// result is then the slice length, the span test at L403 fails, and the byte
/// tested at L405 is absent rather than a `%`, so the input is rejected.
/// Reported as invalid rather than assumed away, so that no panic path exists
/// even in principle.
fn address_span(inner: &[u8]) -> usize {
    inner
        .iter()
        .position(|byte| !is_address_byte(*byte))
        .unwrap_or(inner.len())
}

/// Copies a zone identifier out of the bytes following the `%`.
///
/// The block at `lib/urlapi.c` L406-L417: the local `char zoneid[16]`, the
/// `25` skip, the bounded copy loop and the terminator. The array is the
/// caller's, so that this function has the C's stack buffer with the C's
/// exact size and cap rather than allocating.
///
/// # The `25` skip has three conditions, not one
///
/// L411 reads `if(!strncmp(h, "25", 2) && h[2] && (h[2] != ']'))`, and every
/// part of it is load-bearing. The two bytes must be `25`, because `%25` is
/// the percent-encoded form of the `%` that introduces a zone. The byte after
/// them must be non-zero, so `...%25` at the end of the string does not skip.
/// And it must not be `]`, so `...%25]` does not skip either -- which is why
/// `https://[fe80::20c:29ff:fe9c:409b%25]:1234` has the zone `25` and
/// serializes back as `%2525`, exactly as `tests/libtest/lib1560.c`
/// L689-L691 asserts.
///
/// # Returns
///
/// The zone length in bytes, at least one and at most [`ZONEID_CAP`], with
/// that many bytes of `zoneid` written and a terminator after them.
///
/// `None` for the two rejections L415 folds into one test, both of which the
/// caller turns into `CURLUE_BAD_IPV6`:
///
/// - `!i`, an empty zone, so `[fe80::1%]` is invalid.
/// - `']' != *h`, meaning the scan stopped anywhere other than on the closing
///   bracket. That covers the end of the string, so an unterminated
///   `[fe80::1%eth0` is invalid, and it covers the fifteen-byte cap, so a
///   sixteen-byte zone is invalid rather than truncated.
fn scan_zoneid(tail: &[u8], zoneid: &mut [u8; ZONEID_SIZE]) -> Option<usize> {
    // L409: `char *h = &hostname[len + 1]`. The caller has already narrowed
    // to that, so `h` starts as the whole tail and is only ever advanced.
    let mut h: &[u8] = tail;

    // L410-L412, with the comment at L410: `pass '25' if present and is a URL
    // encoded percent sign`. A byte past the end of the slice reads as the
    // terminator, which is what `h[2]` reads in the C when the string ends
    // there, so the second condition holds for a short tail as well.
    if h.starts_with(b"25") {
        let third = h.get(2).copied().unwrap_or(0);
        if third != 0 && third != b']' {
            // L412: `h += 2`. The `unwrap_or` arm cannot be taken, since
            // `starts_with` established two bytes and `h[2]` was just read;
            // it exists only so that no unwrap appears.
            h = h.get(2..).unwrap_or(&[]);
        }
    }

    // L413-L414. The C advances `i` and `h` together, `zoneid[i++] = *h++`,
    // so one index serves for both and `h[i]` is the C's `*h`.
    let mut i: usize = 0;
    loop {
        // Reading past the end of the slice as the terminator is what makes
        // this the same stop the C makes on `*h`: the caller's buffer is a C
        // string, so the terminator is inside the slice, and the fallback
        // only covers a caller that passed none.
        let byte = h.get(i).copied().unwrap_or(0);
        if byte == 0 || byte == b']' || i >= ZONEID_CAP {
            break;
        }
        // In bounds because the guard above keeps `i` below `ZONEID_CAP`,
        // which the compile-time assertion keeps below `ZONEID_SIZE`. The
        // `None` arm is unreachable and exists only so that no unwrap
        // appears; taking it would stop the copy, and the test at L415 would
        // then reject the input rather than store a short zone.
        match zoneid.get_mut(i) {
            Some(slot) => *slot = byte,
            None => break,
        }
        i = i.saturating_add(1);
    }

    // L415-L416: `if(!i || (']' != *h)) return CURLUE_BAD_IPV6;`. Both halves
    // in one test, as the C writes it.
    if i == 0 || h.get(i).copied().unwrap_or(0) != b']' {
        return None;
    }

    // L417: `zoneid[i] = 0`. In bounds by the assertion above, since the loop
    // cannot leave `i` above `ZONEID_CAP`. The array reaches this function
    // zero-filled, so the write is redundant in practice and is made anyway,
    // because it is what bounds the string the C then duplicates.
    if let Some(slot) = zoneid.get_mut(i) {
        *slot = 0;
    }

    Some(i)
}

/// Validates a bracketed IPv6 host, extracts its zone identifier and
/// rewrites it into canonical form, in place.
///
/// `ipv6_parse` at `lib/urlapi.c` L389-L442. The module documentation carries
/// the entry contract, the rebase that fixes every offset below, the argument
/// that bounds the writes, and the write-ups of `FB3` and `FB6`.
///
/// Not exported to C, and deliberately: the C function is `static`, and the
/// drop-in symbol set is the eight globals `lib/urlapi.o` defines, of which
/// this is not one. It stays `pub(crate)` and carries neither `#[no_mangle]`
/// nor `extern "C"`.
///
/// # Parameters
///
/// - `u`: the handle. Only the zone identifier is ever touched, and only on
///   the branch that finds one, which is `FB3`.
/// - `hostname`: the writable extent of the host buffer, starting at the
///   opening `[`. `hostname.len()` must be at least `hlen + 1`, so that the
///   caller's terminator slot is reachable; `crate::dynbuf::DynBuf::content_mut`
///   yields exactly that. On return the bytes hold the rewritten host as a C
///   string, which is the function's real output.
/// - `hlen`: the length of the bracketed host, excluding the terminator. It
///   is **not** updated, and the caller's own record of the length is left
///   stale on purpose; see the module documentation.
///
/// # Returns
///
/// `crate::abi::CURLUE_OK`, L441, with `hostname` rewritten.
///
/// # Errors
///
/// - `crate::abi::CURLUE_BAD_IPV6` for a host shorter than four bytes (L396),
///   an illegal byte that is not the `%` of a zone (L425), a zone that is
///   empty, unterminated or longer than fifteen bytes (L416), or an address
///   the platform will not parse (L434).
/// - `crate::abi::CURLUE_OUT_OF_MEMORY` when the zone identifier cannot be
///   duplicated, L420.
///
/// A rejection can leave `hostname` partly rewritten, exactly as the C does,
/// and can also leave a zone identifier stored on the handle, because L418
/// stores it before the address itself is validated at L434. Which of those
/// two survives the rejection depends on the caller, and the difference is
/// worth stating because only one of the three paths is atomic:
///
/// - `parse_authority` on the ordinary parse path builds into a temporary
///   handle that L1188-L1191 discards whole, so neither survives.
/// - `parse_authority` reached from `Curl_url_set_authority` runs against a
///   **live** handle. `u->host` is left untouched, because L668-L669 releases
///   the host buffer instead of storing it, but a zone identifier written
///   here stays on the handle after the error is returned. So does anything
///   `parse_hostname_login` and `Curl_parse_port` changed earlier in the same
///   call; `crate::parse::authority::url_set_authority` lists all of it.
/// - The two `set_url_part` paths at L1981 and L1985 leave the **host** as it
///   was, because L1987-L1990 returns before the store at L1994-L1995 -- but
///   they do not restore a zone identifier either, so a rejected host
///   assignment can still leave a new zone readable through
///   `CURLUPART_ZONEID`.
///
/// None of that is a defect introduced here: it is `FB3`, and the asymmetry
/// with the host setter's own `Curl_safefree(u->zoneid)` at L1848 is set out
/// in the module documentation.
#[must_use = "the accept-or-reject verdict is the return value and must be handled"]
pub(crate) fn ipv6_parse(u: &mut CurlUrl, hostname: &mut [u8], hlen: usize) -> CURLUcode {
    // L394 is `DEBUGASSERT(*hostname == '[')`, restating the comment at L389.
    // It is not reproduced, in either form: an assertion is a panic path and
    // this crate has none, and returning an error instead would invent a
    // behavior the C does not have, since a release build of the C simply
    // proceeds. Every caller tests the byte first -- L452 in
    // `hostname_check`, L491 in `ipv4_normalize` -- so the precondition is
    // established at each call site rather than here. A buffer that reached
    // this function without a leading bracket would have its second byte read
    // as the first address byte, which is what the C does too.

    if hlen < MIN_BRACKETED_LEN {
        return CURLUE_BAD_IPV6;
    }

    // L397: `hostname++`. The rest of the extent is kept, not merely the
    // inner span, because the two `FB6` writes reach the caller's terminator
    // slot; the module documentation bounds them. `get_mut` rather than a
    // slice expression, because the crate denies direct indexing. The `None`
    // arm is unreachable, since the guard above established at least four
    // bytes of host and therefore at least five of buffer.
    let Some(inner) = hostname.get_mut(1..) else {
        return CURLUE_BAD_IPV6;
    };

    // L398: `hlen -= 2`, dropping both brackets. Saturating rather than bare
    // subtraction because the crate denies arithmetic that could wrap, and
    // exact here because the guard above established `hlen >= 4`. Shadows the
    // parameter, as the C reassigns its own, so that every index below reads
    // against the same name as in the original.
    let mut hlen = hlen.saturating_sub(2);

    let len = address_span(inner);

    // L403: an illegal byte was found inside the span. In the ordinary case
    // that byte is the closing bracket and the two lengths agree, so this
    // whole block is skipped.
    if hlen != len {
        // L404. Everything after this point works from the shortened length,
        // which is what makes the address end where the zone begins.
        hlen = len;

        // L405. `Some` compared against `Some` rather than the byte compared
        // against `'%'`, so that an absent byte is handled by the same
        // expression: `inner[len]` is the terminator when the span ran to the
        // end of the string, and is out of range only for a caller that
        // passed no terminator at all. Both are "not a `%`" and both reach
        if inner.get(len).copied() != Some(b'%') {
            // L424-L425: the `else` arm. Anything but a `%` here is invalid.
            return CURLUE_BAD_IPV6;
        }

        // L406-L409, with the comment at L406: `this could now be '%[zone
        // id]'`. `&hostname[len + 1]` is the byte after the `%`; the
        // `unwrap_or` arm covers a `%` that ends the buffer, for which the
        // scan then finds an empty zone and rejects.
        let start = len.saturating_add(1);
        let mut zoneid = [0u8; ZONEID_SIZE];
        let Some(zonelen) = scan_zoneid(inner.get(start..).unwrap_or(&[]), &mut zoneid) else {
            return CURLUE_BAD_IPV6;
        };

        // L418: `u->zoneid = curlx_strdup(zoneid)`, and with it FB3.
        //
        // FB3, reproduced deliberately and recorded in
        // docs/KNOWN-DIVERGENCES.md. Two things are absent from the C here and
        // stay absent: there is no release of a zone identifier the handle
        // already holds, and there is no `else` arm clearing the field when
        // the host carries no zone. Both absences are observable -- see the
        // module documentation for the two consequences and for the asymmetry
        // with the host setter at L1848, which does clear and must go on
        // clearing.
        //
        // The one internal difference: `store` releases the buffer it
        // displaces, because `CBuf` has a `Drop`, so this port does not leak
        // where the C leaks. The observable behavior is unchanged, the new
        // value replacing the old, and a leak is not reachable through the URL
        // API. Internal difference, not a correction.
        //
        // `zoneid.get(..zonelen)` is the C string L418 duplicates: the scan
        // reported a length at or below the cap and stored no zero byte, so
        // the range is in bounds and holds exactly the zone.
        let Some(zone) = zoneid.get(..zonelen).and_then(CBuf::from_slice) else {
            return CURLUE_OUT_OF_MEMORY;
        };
        u.store(StringField::ZoneId, zone);

        // L421: `hostname[len] = ']'`, with its comment `insert end bracket`.
        // This overwrites the `%`, so the address now ends in a bracket
        // wherever the zone began.
        if let Some(slot) = inner.get_mut(len) {
            *slot = b']';
        }

        // L422: `hostname[len + 1] = 0`, with its comment `terminate the
        // hostname`. FB6, first site: one byte above the length being
        // tracked, which is `len` from L404 onward. In bounds because
        // `inner[len]` is a `%` rather than the terminator, so the module
        // documentation's step 1 applies.
        if let Some(slot) = inner.get_mut(start) {
            *slot = 0;
        }
        // L426: `hostname is fine`.
    }

    // L429-L440: `Normalize the IPv6 address`. Reached on both paths, which is
    // why an address with a zone is canonicalized too.
    {
        // L431: `char dest[16]`, with its comment `fits a binary IPv6
        // address`. Zero-filled here where the C leaves it uninitialized;
        // `inet_pton` writes all sixteen bytes on success and the value is
        // read on no other path, so the difference is unobservable.
        let mut dest = [0u8; ADDRSZ_IPV6];

        // L432: `hostname[hlen] = 0`, with its comment `end the address
        // there`. This overwrites whatever was at that index -- the closing
        // bracket on the ordinary path, or the bracket L421 just inserted --
        // so that the address alone is what the parser sees.
        if let Some(slot) = inner.get_mut(hlen) {
            *slot = 0;
        }

        // L433-L434. The C hands over the C string that starts at `hostname`,
        // which the write above has just bounded at `hlen`; the equivalent
        // slice is passed instead, so the length is carried by the type rather
        // than by a terminator. `!= 1` in the C, so both `PTON_INVALID` and
        // `PTON_ERROR` are rejected alike, and `src/inet.rs` keeps the three
        // values distinct rather than collapsing them for exactly this
        // comparison to be checkable.
        let address = inner.get(..hlen).unwrap_or(&[]);
        if inet_pton(AF_INET6, address, &mut dest) != PTON_SUCCESS {
            return CURLUE_BAD_IPV6;
        }

        // L435: `curlx_inet_ntop(AF_INET6, dest, hostname, hlen + 1)`. The
        // size is the address bytes plus one slot for the terminator, so the
        // canonical form is written back over the space the original address
        // occupied and no further. `dst.len()` is that size in this port, so
        // the extent is expressed by the slice rather than by an argument that
        // could disagree with it.
        //
        // The test around the call is behavior, not defensiveness. A canonical
        // form can be longer than what it replaces -- `1::2:3:4:5:6:7` is
        // fourteen bytes and canonicalizes to fifteen -- and the call then
        // fails, leaving the host unnormalized and the length as it was. Only
        // the success arm re-measures.
        let extent = hlen.saturating_add(1);
        let written = match inner.get_mut(..extent) {
            Some(target) => inet_ntop(AF_INET6, dest.as_slice(), target),
            // Unreachable under the entry contract: the module
            // documentation's step 3 bounds `extent` below the extent the
            // caller must supply. Handled as a failed conversion, which is
            // the same "leave it alone" the C takes on a null return.
            None => None,
        };
        if let Some(canonical) = written {
            // L436: `hlen = strlen(hostname)`, with its comment `might be
            // shorter now`. The length is returned rather than measured a
            // second time; `src/inet.rs` documents it as exactly what the C's
            // `strlen` would find.
            hlen = canonical;

            // L437: `hostname[hlen + 1] = 0`. FB6, second site, and the one
            // that carries weight: `inet_ntop` put its terminator at inner
            // `hlen`, and L439 below overwrites that with the bracket, so this
            // byte is what ends the host string. Without it the host would run
            // on into whatever a longer original left behind.
            if let Some(slot) = inner.get_mut(hlen.saturating_add(1)) {
                *slot = 0;
            }
        }

        // L439: `hostname[hlen] = ']'`, with its comment `restore ending
        // bracket`. The buffer now reads `[` + canonical address + `]`,
        // terminated by the byte written just above.
        if let Some(slot) = inner.get_mut(hlen) {
            *slot = b']';
        }
    }

    CURLUE_OK
}

#[cfg(test)]
mod tests {
    // The crate root denies the panicking constructs so that no panic can ever
    // reach the C boundary. A test's entire job is to panic when an assertion
    // fails, and a test never crosses that boundary, so the denials are
    // relaxed here and only here. The allowance is scoped to this module and
    // enumerated rather than blanket, matching `src/dynbuf.rs`.
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::arithmetic_side_effects)]

    // The buffers these tests build need the heap, and they reach it through
    // the `alloc` crate rather than through `std`, so that this module
    // compiles the same way whichever the crate root turns out to declare.
    extern crate alloc;

    // Imported by name rather than through a glob, as everywhere else in the
    // crate, so each use site names its source.
    use super::{
        address_span, ipv6_parse, is_address_byte, MIN_BRACKETED_LEN, ZONEID_CAP, ZONEID_SIZE,
    };
    use crate::abi::{CURLUcode, CURLUE_BAD_IPV6, CURLUE_OK, CURL_MAX_INPUT_LENGTH};
    use crate::dynbuf::DynBuf;
    use crate::handle::CurlUrl;
    use alloc::vec;
    use alloc::vec::Vec;

    /// The `strspn` set at `lib/urlapi.c` L401, copied byte for byte.
    ///
    /// Present so that [`is_address_byte`] can be held against the literal
    /// itself rather than against a second predicate that could repeat the
    /// same mistake.
    const SPAN_SET: &[u8] = b"0123456789abcdefABCDEF:.";

    /// A byte no vector contains, used to prove that nothing is written above
    /// the extent the entry contract promises.
    const GUARD: u8 = 0xaa;

    /// What a C caller can observe after one call.
    #[derive(Debug)]
    struct Outcome {
        /// The returned `CURLUcode`.
        code: CURLUcode,
        /// The host as C reads it: the bytes up to the first terminator.
        host: Vec<u8>,
        /// The zone identifier the handle holds afterwards, if any.
        zone: Option<Vec<u8>>,
        /// The whole buffer, so a test can inspect above the terminator and
        /// confirm that nothing was trimmed.
        buffer: Vec<u8>,
    }

    /// Runs [`ipv6_parse`] over the supplied handle and a buffer built the way
    /// a C caller builds one: the bracketed host followed by its terminator,
    /// which is the `leng + 1` extent both a dynamic buffer and a
    /// `Curl_urldecode` result guarantee.
    ///
    /// One byte of [`GUARD`] is placed beyond that extent and the slice handed
    /// over stops short of it, so every call in this module also checks the
    /// bound the module documentation argues for.
    fn parse_into(u: &mut CurlUrl, host: &[u8]) -> Outcome {
        let hlen = host.len();
        let mut buffer = vec![GUARD; hlen + 2];
        buffer[..hlen].copy_from_slice(host);
        buffer[hlen] = 0;

        let code = ipv6_parse(u, &mut buffer[..=hlen], hlen);

        assert_eq!(
            buffer[hlen + 1],
            GUARD,
            "a byte was written above the caller's extent"
        );
        let end = buffer[..=hlen]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(hlen + 1);
        Outcome {
            code,
            host: buffer[..end].to_vec(),
            zone: u.zoneid().map(<[u8]>::to_vec),
            buffer,
        }
    }

    /// [`parse_into`] on a fresh handle, which is the ordinary case: the C
    /// parses into a zeroed temporary at L1197-L1209.
    fn parse(host: &[u8]) -> Outcome {
        let mut u = CurlUrl::new();
        parse_into(&mut u, host)
    }

    /// Asserts an accepted host and the exact bytes it became.
    fn accepts(input: &[u8], host: &[u8], zone: Option<&[u8]>) {
        let out = parse(input);
        assert_eq!(
            out.code,
            CURLUE_OK,
            "{:?} should be accepted",
            alloc::string::String::from_utf8_lossy(input)
        );
        assert_eq!(
            out.host,
            host,
            "{:?} became {:?}",
            alloc::string::String::from_utf8_lossy(input),
            alloc::string::String::from_utf8_lossy(&out.host)
        );
        assert_eq!(
            out.zone.as_deref(),
            zone,
            "{:?} zone",
            alloc::string::String::from_utf8_lossy(input)
        );
    }

    /// Asserts a rejected host and the code it was rejected with.
    fn rejects(input: &[u8], code: CURLUcode) {
        let out = parse(input);
        assert_eq!(
            out.code,
            code,
            "{:?} returned {} rather than {}",
            alloc::string::String::from_utf8_lossy(input),
            out.code,
            code
        );
    }

    /// [`is_address_byte`] and the literal at `lib/urlapi.c` L401 accept
    /// exactly the same 256-value set.
    ///
    /// The predicate is written through [`crate::ctype::is_xdigit`] rather
    /// than by carrying the digits a second time, and this is what makes that
    /// substitution checkable. The three bytes worth naming are the ones the
    /// algorithm turns on: `%` is outside the set, which is what makes the
    /// zone branch reachable at all; `]` is outside it, which is what makes
    /// the span stop at the closing bracket; and the terminator is outside it,
    /// which is what makes [`address_span`] stop where `strspn` stops.
    #[test]
    fn the_span_set_is_the_c_string_literal() {
        for byte in 0..=u8::MAX {
            assert_eq!(
                is_address_byte(byte),
                SPAN_SET.contains(&byte),
                "byte {byte:#04x}"
            );
        }
        assert!(!is_address_byte(b'%'));
        assert!(!is_address_byte(b']'));
        assert!(!is_address_byte(0));
        assert!(is_address_byte(b'.'));
        assert!(is_address_byte(b':'));
    }

    /// [`address_span`] measures the leading run and stops at the terminator,
    /// which is what `strspn` does over the same bytes.
    #[test]
    fn the_span_stops_at_the_first_byte_outside_the_set() {
        assert_eq!(address_span(b"::1]\0"), 3);
        assert_eq!(address_span(b"fe80::1%eth0]\0"), 7);
        assert_eq!(address_span(b"\0"), 0);
        assert_eq!(address_span(b"]\0"), 0);
        // No byte outside the set at all, which is the caller-passed-no-
        // terminator case: the whole slice is the answer, and the caller then
        // rejects because the byte at that index is absent rather than a `%`.
        assert_eq!(address_span(b"::1"), 3);
        assert_eq!(address_span(b""), 0);
    }

    /// `'[::]'` is the shortest accepted host, per the comment at
    /// `lib/urlapi.c` L395, and the comparison there is `hlen < 4`.
    ///
    /// The three shorter forms are what the guard exists for, and the
    /// reference build answers 22 for each of them.
    #[test]
    fn four_bytes_is_the_shortest_accepted_host() {
        assert_eq!(MIN_BRACKETED_LEN, 4, "lib/urlapi.c:L395");
        accepts(b"[::]", b"[::]", None);
        rejects(b"[::", CURLUE_BAD_IPV6);
        rejects(b"[:]", CURLUE_BAD_IPV6);
        rejects(b"[1]", CURLUE_BAD_IPV6);
        rejects(b"[]", CURLUE_BAD_IPV6);
        rejects(b"[", CURLUE_BAD_IPV6);
        rejects(b"", CURLUE_BAD_IPV6);
    }

    /// An address already in canonical form comes back byte for byte.
    ///
    /// The first is the address `tests/unit/unit1653.c` L55 builds; the rest
    /// are from `tests/libtest/lib1560.c` L344-L351 and L406-L414.
    #[test]
    fn a_canonical_address_survives_unchanged() {
        accepts(
            b"[fe80::250:56ff:fea7:da15]",
            b"[fe80::250:56ff:fea7:da15]",
            None,
        );
        accepts(b"[::1]", b"[::1]", None);
        accepts(b"[fd00:a41::50]", b"[fd00:a41::50]", None);
        // The dot is in the span set for this: an IPv4-mapped address.
        accepts(b"[::ffff:127.0.0.1]", b"[::ffff:127.0.0.1]", None);
    }

    /// Whatever single byte sits where the closing bracket belongs is simply
    /// overwritten, so this stage does **not** require a `]` at all.
    ///
    /// This is the least obvious property of the function and it falls
    /// straight out of the rebase. L398 shortens the length by two on the
    /// assumption that the last byte is a bracket, so the span test at L403
    /// compares against a length that already excludes that byte. A stray byte
    /// there therefore makes the two lengths *agree*, the whole
    /// zone-identifier block is skipped, and L432 zeroes the byte before
    /// `inet_pton` ever sees it. Only a second stray byte makes the lengths
    /// disagree and reaches the rejection at L424-L425.
    ///
    /// The first vector is the invalid input `tests/unit/unit1653.c` L66 uses,
    /// and it is worth being precise about where that test's rejection comes
    /// from: not from here, but from `Curl_parse_port` at L344-L346, which
    /// looks for a `]` with `strchr` and answers `CURLUE_BAD_IPV6` when there
    /// is none. That function is out of scope, so the address text is reused
    /// here against this stage alone -- where it is accepted.
    ///
    /// Measured against the reference build through the one public door that
    /// bypasses `Curl_parse_port`, the `CURLUPART_HOST` setter, which reaches
    /// `hostname_check` at L1981: `[fe80::250:56ff:fea7:da15|` and `[::1x` are
    /// both accepted, while `[::1xy` answers 21, the `CURLUE_BAD_HOSTNAME`
    /// that L1987 folds this stage's `CURLUE_BAD_IPV6` into.
    #[test]
    fn one_stray_byte_where_the_bracket_belongs_is_overwritten() {
        accepts(
            b"[fe80::250:56ff:fea7:da15|",
            b"[fe80::250:56ff:fea7:da15]",
            None,
        );
        accepts(b"[::1x", b"[::1]", None);
        accepts(b"[fe80::1x", b"[fe80::1]", None);
        // A `%` in that position is no different: it is not examined as a zone
        // delimiter, because L405 is only reached when the lengths disagree.
        accepts(b"[fe80::1%", b"[fe80::1]", None);
        // Two stray bytes do make them disagree, and then the byte at the span
        // end is not a `%`, so L424-L425 rejects.
        rejects(b"[::1xy", CURLUE_BAD_IPV6);
        rejects(b"[fe80::250:56ff:fea7:da15|]", CURLUE_BAD_IPV6);
    }

    /// Normalization shortens the address and the closing bracket moves with
    /// it.
    ///
    /// Every pair is from `tests/libtest/lib1560.c` L607-L621 and was
    /// re-checked against the platform's own `inet_ntop`, which is what
    /// `curlx_inet_ntop` expands to on this platform. The fourth pair is the
    /// one worth reading twice: compression picks the **first** of the longest
    /// runs of zero groups, so an address that already ends in `::` can come
    /// back with the compression moved to the front.
    #[test]
    fn normalization_compresses_and_moves_the_bracket() {
        accepts(
            b"[fe80::0000:20c:29ff:fe9c:409b]",
            b"[fe80::20c:29ff:fe9c:409b]",
            None,
        );
        accepts(
            b"[fe80::020c:29ff:fe9c:409b]",
            b"[fe80::20c:29ff:fe9c:409b]",
            None,
        );
        accepts(
            b"[fe80:0000:0000:0000:020c:29ff:fe9c:409b]",
            b"[fe80::20c:29ff:fe9c:409b]",
            None,
        );
        accepts(b"[fe80:0:0:0:409b::]", b"[fe80::409b:0:0:0]", None);
        // Lower-cased on the way through, which is `inet_ntop`'s doing rather
        // than this module's. lib1560.c L619-L621.
        accepts(b"[FE80:0:A:0:409B:0:0:0]", b"[fe80:0:a:0:409b::]", None);
        accepts(b"[0:0:0:0:0:0:0:0]", b"[::]", None);
        accepts(b"[1:0:0:0:0:0:0:8]", b"[1::8]", None);
        accepts(
            b"[fe80:0000:0000:0000:0250:56ff:fea7:da15]",
            b"[fe80::250:56ff:fea7:da15]",
            None,
        );
    }

    /// Normalization is declined when the canonical form would be longer, and
    /// the host is then kept exactly as it arrived.
    ///
    /// `1::2:3:4:5:6:7` is fourteen bytes and canonicalizes to
    /// `1:0:2:3:4:5:6:7`, which is fifteen, so the `hlen + 1` extent at L435
    /// is one byte too small and the call returns null. L435's `if` is what
    /// makes that a no-op rather than a failure, and the reference build
    /// round-trips `https://[1::2:3:4:5:6:7]/` unchanged for this reason.
    #[test]
    fn normalization_is_declined_when_the_canonical_form_is_longer() {
        accepts(b"[1::2:3:4:5:6:7]", b"[1::2:3:4:5:6:7]", None);
    }

    /// A zone identifier is copied out and the address is normalized without
    /// it.
    ///
    /// The zone is stored raw, so a serialized URL re-encodes the delimiter as
    /// `%25`, which is what L1486 does and what `tests/libtest/lib1560.c`
    /// L692-L694 asserts.
    #[test]
    fn a_zone_identifier_is_extracted_and_stored() {
        accepts(
            b"[fe80::250:56ff:fea7:da15%eth0]",
            b"[fe80::250:56ff:fea7:da15]",
            Some(b"eth0"),
        );
        accepts(
            b"[fe80::20c:29ff:fe9c:409b%eth0]",
            b"[fe80::20c:29ff:fe9c:409b]",
            Some(b"eth0"),
        );
        accepts(b"[::ffff:127.0.0.1%lo]", b"[::ffff:127.0.0.1]", Some(b"lo"));
    }

    /// The encoded delimiter is skipped, so `%25eth0` yields the same zone as
    /// `%eth0`.
    ///
    /// `tests/libtest/lib1560.c` L415-L417 relies on it for
    /// `https://[::1%252]:1234`, whose zone is the single byte `2`.
    #[test]
    fn the_encoded_percent_sign_is_skipped() {
        accepts(b"[fe80::1%25eth0]", b"[fe80::1]", Some(b"eth0"));
        accepts(b"[::1%252]", b"[::1]", Some(b"2"));
        accepts(b"[::%25fakeit]", b"[::]", Some(b"fakeit"));
        // Only the first `25` is skipped, so a doubled one leaves `2525`.
        accepts(b"[fe80::1%252525]", b"[fe80::1]", Some(b"2525"));
        // And a following percent sign is ordinary zone content.
        accepts(b"[fe80::1%25%25]", b"[fe80::1]", Some(b"%25"));
    }

    /// The `25` skip requires all three conditions of `lib/urlapi.c` L411,
    /// and the third one is directly observable.
    ///
    /// `%25]` must **not** skip: skipping would leave an empty zone and
    /// L415-L416 would reject, whereas the reference build accepts it with the
    /// zone `25` and serializes it back as `%2525`. That is exactly what
    /// `tests/libtest/lib1560.c` L689-L691 asserts.
    ///
    /// The second condition, `h[2]` being non-zero, is transcribed because the
    /// C has it, and it is honestly not separately observable: for a tail of
    /// exactly `25` both the skipping and the non-skipping reading end in
    /// `CURLUE_BAD_IPV6`, one for an empty zone and the other for a scan that
    /// stopped on the terminator. The case is covered below so that a future
    /// edit which drops the condition still has to keep the outcome.
    #[test]
    fn the_skip_needs_all_three_conditions() {
        accepts(
            b"[fe80::20c:29ff:fe9c:409b%25]",
            b"[fe80::20c:29ff:fe9c:409b]",
            Some(b"25"),
        );
        accepts(b"[fe80::1%25]", b"[fe80::1]", Some(b"25"));
        rejects(b"[fe80::1%25", CURLUE_BAD_IPV6);
        rejects(b"[fe80::1%2", CURLUE_BAD_IPV6);
    }

    /// An empty zone is rejected, which is the `!i` half of L415.
    ///
    /// `tests/libtest/lib1560.c` L686-L688 asserts `CURLUE_BAD_IPV6` for
    /// `https://[fe80::20c:29ff:fe9c:409b%]:1234`.
    ///
    /// A `%` that ends the buffer is **not** in this set, because it never
    /// reaches the zone branch at all; see
    /// [`one_stray_byte_where_the_bracket_belongs_is_overwritten`].
    #[test]
    fn an_empty_zone_is_rejected() {
        rejects(b"[fe80::1%]", CURLUE_BAD_IPV6);
        rejects(b"[fe80::20c:29ff:fe9c:409b%]", CURLUE_BAD_IPV6);
        // A `%` followed by anything at all does reach it, and an immediate
        // `]` is the empty zone.
        rejects(b"[fe80::1%]x", CURLUE_BAD_IPV6);
    }

    /// A zone the scan cannot finish on a `]` is rejected, which is the
    /// `']' != *h` half of L415.
    #[test]
    fn an_unterminated_zone_is_rejected() {
        rejects(b"[fe80::1%eth0", CURLUE_BAD_IPV6);
        rejects(b"[fe80::1%25eth0", CURLUE_BAD_IPV6);
    }

    /// Fifteen bytes of zone are accepted whole; sixteen are **rejected**, not
    /// truncated.
    ///
    /// This is the one place where the obvious reading of the C is backwards,
    /// so it was measured against the reference build rather than reasoned
    /// about: fourteen and fifteen bytes come back whole, sixteen and
    /// seventeen both answer 22. The buffer at L407 does cap the copy at
    /// fifteen, but the scan then stops on the sixteenth byte rather than on
    /// the `]`, and L415 rejects on exactly that.
    #[test]
    fn the_zone_cap_accepts_fifteen_and_rejects_sixteen() {
        assert_eq!(ZONEID_CAP, 15, "lib/urlapi.c:L413");
        assert_eq!(ZONEID_SIZE, 16, "lib/urlapi.c:L407");

        for len in 1..=ZONEID_CAP {
            let mut input = Vec::from(b"[fe80::1%".as_slice());
            input.extend(core::iter::repeat(b'a').take(len));
            input.push(b']');
            let zone = vec![b'a'; len];
            accepts(&input, b"[fe80::1]", Some(&zone));
        }

        for len in [ZONEID_SIZE, ZONEID_SIZE + 1, 40] {
            let mut input = Vec::from(b"[fe80::1%".as_slice());
            input.extend(core::iter::repeat(b'a').take(len));
            input.push(b']');
            rejects(&input, CURLUE_BAD_IPV6);
        }
    }

    /// An illegal byte that is not a `%` is rejected, which is L424-L425.
    ///
    /// The last two are `tests/libtest/lib1560.c` L396-L399, which assert
    /// `CURLUE_BAD_IPV6` for `http://[ab.be:1]/x` and `http://[ab.be]/x`. Both
    /// pass the span test -- every byte of `ab.be` is in the set -- and are
    /// rejected by `inet_pton` at L433-L434 instead, which is a different door
    /// to the same code.
    #[test]
    fn an_illegal_byte_that_is_not_a_percent_is_rejected() {
        rejects(b"[fe80::1g]", CURLUE_BAD_IPV6);
        rejects(b"[fe80::1 ]", CURLUE_BAD_IPV6);
        rejects(b"[fe80::1/]", CURLUE_BAD_IPV6);
        rejects(b"[ab.be]", CURLUE_BAD_IPV6);
        rejects(b"[ab.be:1]", CURLUE_BAD_IPV6);
        rejects(b"[::1::2]", CURLUE_BAD_IPV6);
        rejects(b"[1.2.3.4]", CURLUE_BAD_IPV6);
    }

    /// A host that is nothing but a zone has no address left to parse, so
    /// `inet_pton` rejects it after the zone has been taken.
    ///
    /// The reference build answers 22 for `https://[%25a]/`, and this is the
    /// path: the span is empty, the `%` is at index zero, the zone `a` is
    /// stored, and the address handed to L433 is the empty string.
    #[test]
    fn a_host_that_is_only_a_zone_is_rejected() {
        rejects(b"[%25a]", CURLUE_BAD_IPV6);
        rejects(b"[%eth0]", CURLUE_BAD_IPV6);
    }

    /// `FB3`, first consequence: a zone identifier already on the handle is
    /// replaced, not merged, and nothing releases it first in the C.
    ///
    /// The replacement is the observable half and is what this asserts. The
    /// unreleased buffer is the internal half, which this port does not
    /// reproduce because storing into the field drops the displaced [`CBuf`];
    /// see the module documentation.
    #[test]
    fn fb3_a_new_zone_replaces_the_old_one() {
        let mut u = CurlUrl::new();

        let first = parse_into(&mut u, b"[fe80::1%eth0]");
        assert_eq!(first.code, CURLUE_OK);
        assert_eq!(first.zone.as_deref(), Some(b"eth0".as_slice()));

        let second = parse_into(&mut u, b"[fe80::2%eth1]");
        assert_eq!(second.code, CURLUE_OK);
        assert_eq!(second.host, b"[fe80::2]");
        assert_eq!(second.zone.as_deref(), Some(b"eth1".as_slice()));
    }

    /// `FB3`, second consequence: a stale zone identifier survives a host that
    /// has none, because `lib/urlapi.c` L405-L423 assigns on the zone branch
    /// only and has no `else` arm that clears the field.
    ///
    /// This is the finding, reproduced deliberately and never to be fixed
    /// here. It is asymmetric with the host setter at L1848, which does
    /// release the zone -- measured against the reference build,
    /// `curl_url_set(u, CURLUPART_HOST, "[::1]", 0)` answers
    /// `CURLUE_NO_ZONEID` afterwards for exactly that reason. The path on which
    /// the staleness is reachable is the live-handle one,
    /// `Curl_url_set_authority` at L658-L675, which `lib/http2.c` L739 calls
    /// for HTTP/2 server push.
    ///
    /// The stale value stops appearing in a serialized URL, because L1480-L1491
    /// emits a zone only for a bracketed host, yet it stays readable through
    /// `CURLUPART_ZONEID`.
    #[test]
    fn fb3_a_stale_zone_survives_a_host_without_one() {
        let mut u = CurlUrl::new();

        let zoned = parse_into(&mut u, b"[fe80::20c:29ff:fe9c:409b%eth0]");
        assert_eq!(zoned.code, CURLUE_OK);
        assert_eq!(zoned.zone.as_deref(), Some(b"eth0".as_slice()));

        let plain = parse_into(&mut u, b"[::1]");
        assert_eq!(plain.code, CURLUE_OK);
        assert_eq!(plain.host, b"[::1]");
        assert_eq!(
            plain.zone.as_deref(),
            Some(b"eth0".as_slice()),
            "FB3: the zone must NOT be cleared here"
        );
    }

    /// `FB3`: a zone stored before a later rejection stays on the handle.
    ///
    /// L418 runs before `inet_pton` is reached at L433, and the C has no
    /// unwinding on the L434 return, so a host whose zone is well formed and
    /// whose address is not leaves the zone behind. Harmless in practice --
    /// `parse_authority` builds into a temporary handle that L1188-L1191
    /// discards whole -- and reproduced rather than tidied.
    #[test]
    fn fb3_a_zone_survives_a_later_rejection() {
        let mut u = CurlUrl::new();
        let out = parse_into(&mut u, b"[%eth0]");
        assert_eq!(out.code, CURLUE_BAD_IPV6);
        assert_eq!(out.zone.as_deref(), Some(b"eth0".as_slice()));
    }

    /// `FB6`, second site: the terminator written at `hostname[hlen + 1]`
    /// (L437) is what ends a shortened host, and nothing below it is trimmed.
    ///
    /// After normalization the buffer holds the shorter host, its bracket, the
    /// terminator this write puts there -- and then the tail of the longer
    /// original, untouched. That tail is the evidence: a port that rebuilt the
    /// buffer instead of rewriting it would not leave it behind, and a port
    /// that trimmed the view to the logical length could not write the
    /// terminator at all.
    #[test]
    fn fb6_the_second_write_terminates_a_shortened_host() {
        let input = b"[fe80:0000:0000:0000:0250:56ff:fea7:da15]";
        let out = parse(input);
        assert_eq!(out.code, CURLUE_OK);
        assert_eq!(out.host, b"[fe80::250:56ff:fea7:da15]");

        // The host is 26 bytes, so L437 wrote the terminator at index 26 --
        // one above the 25 the length was tracking after L436.
        assert_eq!(out.host.len(), 26);
        assert_eq!(out.buffer[25], b']', "L439 restored the bracket");
        assert_eq!(out.buffer[26], 0, "L437 terminated one byte further on");

        // Nothing below was cleared: this is the middle of the original
        // `56ff` group, still where it was.
        assert_eq!(&out.buffer[27..31], b"6ff:");
        assert_eq!(out.buffer.len(), input.len() + 2);
    }

    /// `FB6`, first site: the terminator written at `hostname[len + 1]` (L422)
    /// is what ends the host when normalization is later declined.
    ///
    /// This is the one case where that write is the only thing terminating the
    /// string, and it needs both halves at once: a zone, so that L421-L422
    /// run, and an address whose canonical form is longer, so that L435 returns
    /// null and L437 never runs. `1::2:3:4:5:6:7` supplies the second half.
    /// Without L422 the host would read `[1::2:3:4:5:6:7]eth0]`, and the
    /// reference build answers `[1::2:3:4:5:6:7]` with the zone `eth0`.
    #[test]
    fn fb6_the_first_write_terminates_when_normalization_is_declined() {
        let out = parse(b"[1::2:3:4:5:6:7%eth0]");
        assert_eq!(out.code, CURLUE_OK);
        assert_eq!(out.host, b"[1::2:3:4:5:6:7]");
        assert_eq!(out.zone.as_deref(), Some(b"eth0".as_slice()));
        assert_eq!(out.buffer[15], b']', "L421 inserted the bracket");
        assert_eq!(out.buffer[16], 0, "L422 terminated the host");
        // The encoded spelling of the same thing, which is what a URL carries.
        let encoded = parse(b"[1::2:3:4:5:6:7%25eth0]");
        assert_eq!(encoded.code, CURLUE_OK);
        assert_eq!(encoded.host, b"[1::2:3:4:5:6:7]");
        assert_eq!(encoded.zone.as_deref(), Some(b"eth0".as_slice()));
    }

    /// Nothing is ever written above index `hlen` of the caller's buffer.
    ///
    /// [`parse_into`] checks the guard byte on every call, so this test is the
    /// sweep: it drives every vector in the module through one place, so that
    /// the bound the module documentation argues for is confirmed by experiment
    /// rather than only by the argument. The accepted and rejected cases are
    /// mixed on purpose, since an early return leaves the rewriting half done.
    #[test]
    fn the_highest_byte_written_is_the_terminator_slot() {
        const VECTORS: [&[u8]; 24] = [
            b"[::]",
            b"[::1]",
            b"[::",
            b"[]",
            b"[1]",
            b"[fe80::250:56ff:fea7:da15]",
            b"[fe80::250:56ff:fea7:da15|",
            b"[fe80:0000:0000:0000:0250:56ff:fea7:da15]",
            b"[fe80:0:0:0:409b::]",
            b"[FE80:0:A:0:409B:0:0:0]",
            b"[0:0:0:0:0:0:0:0]",
            b"[1::2:3:4:5:6:7]",
            b"[1::2:3:4:5:6:7%eth0]",
            b"[fe80::1%eth0]",
            b"[fe80::1%25eth0]",
            b"[fe80::1%25]",
            b"[fe80::1%252525]",
            b"[fe80::1%]",
            b"[fe80::1%eth0",
            b"[fe80::1%aaaaaaaaaaaaaaa]",
            b"[fe80::1%aaaaaaaaaaaaaaaa]",
            b"[%eth0]",
            b"[ab.be]",
            b"[::ffff:127.0.0.1%lo]",
        ];

        for input in VECTORS {
            let out = parse(input);
            assert!(
                out.code == CURLUE_OK || out.code == CURLUE_BAD_IPV6,
                "{:?} returned {}",
                alloc::string::String::from_utf8_lossy(input),
                out.code
            );
            // The guard is the last byte and parse_into asserted it; assert the
            // extent too, so a future change to the helper cannot make the
            // sweep vacuous.
            assert_eq!(out.buffer.len(), input.len() + 2);
            assert_eq!(*out.buffer.last().unwrap(), GUARD);
        }
    }

    /// The real caller's shape: a [`DynBuf`], mutated in place through the
    /// `leng + 1` view, with its logical length left stale.
    ///
    /// This is `lib/urlapi.c` L638, `ipv6_parse(u, curlx_dyn_ptr(host),
    /// curlx_dyn_len(host))`, and it pins the two properties that call site
    /// depends on. The view is one byte wider than the content, which is what
    /// makes `FB6` expressible -- for this input the second write lands exactly
    /// on the terminator slot. And the length is not updated, so
    /// `curlx_dyn_len` still reports the bracketed length while the C string
    /// the caller goes on to use is shorter.
    #[test]
    fn the_dynamic_buffer_caller_sees_a_stale_length() {
        let input = b"[fe80:0000:0000:0000:0250:56ff:fea7:da15]";
        let mut host = DynBuf::new(CURL_MAX_INPUT_LENGTH);
        assert!(host.addn(input).is_ok());
        let hlen = host.len();
        assert_eq!(hlen, input.len());

        let mut u = CurlUrl::new();
        let code = {
            let mut view = host.content_mut();
            assert_eq!(view.len(), hlen + 1, "src/dynbuf.rs contract 2");
            ipv6_parse(&mut u, &mut view, hlen)
        };
        assert_eq!(code, CURLUE_OK);

        // The bytes are the new host; the length is the old one. Both halves
        // are the C's behavior and neither is corrected.
        assert_eq!(host.len(), input.len(), "the logical length is left stale");
        let bytes = host.as_bytes_with_nul();
        let end = bytes.iter().position(|byte| *byte == 0).unwrap();
        assert_eq!(&bytes[..end], b"[fe80::250:56ff:fea7:da15]");
        assert!(end < host.len(), "the C string is shorter than the length");
    }

    /// The same shape for an address that is already canonical, which is where
    /// the second `FB6` write lands on the very last byte of the view.
    ///
    /// `[fe80::250:56ff:fea7:da15]` is 26 bytes and normalizes to itself, so
    /// L436 leaves the length at 24 and L437 writes at inner index 25, which is
    /// index 26 of the buffer -- the terminator slot, and the reason
    /// [`crate::dynbuf::DynBuf::content_mut`] is `leng + 1` bytes wide rather
    /// than `leng`.
    #[test]
    fn the_second_write_can_land_on_the_last_byte_of_the_view() {
        let input = b"[fe80::250:56ff:fea7:da15]";
        let mut host = DynBuf::new(CURL_MAX_INPUT_LENGTH);
        assert!(host.addn(input).is_ok());
        let hlen = host.len();

        let mut u = CurlUrl::new();
        let code = {
            let mut view = host.content_mut();
            ipv6_parse(&mut u, &mut view, hlen)
        };
        assert_eq!(code, CURLUE_OK);
        assert_eq!(host.len(), input.len());
        assert_eq!(host.as_bytes(), input);
        assert_eq!(host.as_bytes_with_nul().len(), hlen + 1);
    }

    /// A caller that hands over only `hlen` bytes still gets the right verdict
    /// and the right zone.
    ///
    /// Not a supported shape -- the entry contract asks for `hlen + 1` -- but
    /// worth pinning, because one C call site does throw the rewritten bytes
    /// away and keep only those two results: L1981 releases the
    /// `Curl_urldecode` buffer at L1983 immediately after the check. Whatever a
    /// future caller passes, no write can leave the slice and no path panics.
    #[test]
    fn a_short_extent_still_yields_the_verdict_and_the_zone() {
        let host = b"[fe80::20c:29ff:fe9c:409b%25eth0]";
        let mut buffer = Vec::from(host.as_slice());
        let hlen = buffer.len();
        let mut u = CurlUrl::new();
        assert_eq!(ipv6_parse(&mut u, &mut buffer, hlen), CURLUE_OK);
        assert_eq!(u.zoneid(), Some(b"eth0".as_slice()));
        assert_eq!(buffer.len(), hlen, "the slice cannot be resized");

        let mut u = CurlUrl::new();
        let mut bad = Vec::from(b"[fe80::1g]".as_slice());
        let badlen = bad.len();
        assert_eq!(ipv6_parse(&mut u, &mut bad, badlen), CURLUE_BAD_IPV6);
    }

    /// A rejected host may be left partly rewritten, exactly as in the C, and
    /// that is safe because every caller discards it.
    ///
    /// `parse_authority` parses into a temporary handle and buffer that
    /// L1188-L1191 releases whole on any error, and both `set_url_part` paths
    /// keep the previous value. Pinned so that nobody "tidies" the failure
    /// paths into restoring the input, which would be a divergence with no
    /// caller to benefit from it.
    #[test]
    fn a_rejection_may_leave_the_buffer_rewritten() {
        let out = parse(b"[%eth0]");
        assert_eq!(out.code, CURLUE_BAD_IPV6);
        // L421 inserted a bracket over the `%` and L422 terminated after it,
        // before L434 rejected the empty address; L432 then zeroed index 1.
        assert_eq!(out.buffer[0], b'[');
        assert_eq!(out.buffer[1], 0);
    }
}
