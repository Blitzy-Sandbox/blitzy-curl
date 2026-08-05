// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The port extractor: one delimiter, one number, one deliberate oddity.
//!
//! Port of `Curl_parse_port`, defined at `lib/urlapi.c` L335-L387 and
//! declared at `lib/urlapi-int.h` L36-L37. Fifty lines of C that do three
//! things: find where the host name stops, cut it off there, and turn
//! whatever followed the cut into `u->portnum` and `u->port`.
//!
//! # The one caller, and what it does either side of this stage
//!
//! `parse_authority` at `lib/urlapi.c` L604-L655 is the only caller, at
//! L627, and the order it works in matters because two of its own steps
//! depend on what this stage leaves behind.
//!
//! - L621 has just appended the authority, credentials already stripped,
//!   into the host buffer. The bytes this stage sees are therefore
//!   `host:port` and never a whole URL: no scheme, no `user:pwd@` prefix,
//!   no path.
//! - L631, immediately after the call, is
//!   `if(!curlx_dyn_len(host)) return CURLUE_NO_HOST;`. That is precisely
//!   how an authority of just `":80"` becomes a no-host error rather than a
//!   port error: the truncation below leaves the buffer empty and the
//!   caller notices.
//! - L634 then hands the shortened buffer to `ipv4_normalize`, so every
//!   later stage sees a host with no port stuck on the end of it.
//!
//! `has_scheme` arrives from two places, and in both it is a plain boolean
//! test of one pointer: `u->scheme != NULL` at L1150 on the ordinary parse
//! path, and `!!u->scheme` at L667 inside `Curl_url_set_authority`, the
//! HTTP/2 server-push entry point, which passes a **live** handle.
//!
//! # Why nothing here is exported
//!
//! `lib/urlapi-int.h` wraps the declaration in `#ifdef UNITTESTS` at
//! L35-L38, and `lib/urlapi.c` L335 marks the definition `UNITTEST`. So
//! `lib/urlapi.o` does not export `Curl_parse_port` in an ordinary build,
//! and neither may this crate: acceptance criterion A2 requires the
//! archive's exported symbol set to equal the C object file's exactly, so a
//! `#[no_mangle] extern "C"` here would break the drop-in rather than
//! complete it. [`parse_port`] is `pub(crate)` and `src/ffi.rs` must leave
//! it alone.
//!
//! The consequence is reported rather than worked around.
//! `tests/unit/unit1653.c` L37 calls the C function directly, handing it a
//! `struct dynbuf` it constructed itself, so satisfying that test would
//! need both a ninth exported symbol and bit-compatible interoperation with
//! C's dynamic-buffer layout. That is reportable constraint R2. Its
//! vectors are ported into the test module at the bottom of this file,
//! which is the part of it that can be honored without an export.
//!
//! # The rule, byte for byte
//!
//! Given the host buffer's content, in the order the C performs the steps:
//!
//! 1. Take the content as a NUL-terminated string, L339.
//! 2. If it starts with `[`, look for the first `]`. A missing `]` is
//!    `CURLUE_BAD_IPV6` -- an address error, not a port error, L345-L346.
//!    Step past the bracket, L347, and let exactly one byte decide: the end
//!    of the string means there is no port at all, L353-L354; a `:` means a
//!    port follows; **any other byte** is `CURLUE_BAD_PORT_NUMBER`,
//!    L350-L351.
//! 3. Otherwise the delimiter is simply the first `:` in the whole string,
//!    L357. So `host:1:2` finds the first colon and fails later, on the
//!    leftover `:2`, rather than finding the second.
//! 4. With no delimiter, there is nothing to do and nothing to report,
//!    L386.
//! 5. With one, shorten the host to end where the delimiter was, L370, and
//!    then read what came after it, L371.
//! 6. Nothing after it is the `FB4` case below, L372-L373.
//! 7. Otherwise scan a decimal number with a ceiling of `0xffff` and
//!    reject any leftover byte, L375-L376.
//! 8. Store the number, L378, then regenerate the textual port from it,
//!    L379-L381, which is how leading zeroes disappear: `:080` yields a
//!    `portnum` of 80 and a `port` string of `"80"`.
//!
//! # `FB4`, reproduced and not fixed
//!
//! `docs/KNOWN-DIVERGENCES.md` collects the findings this port reproduces
//! deliberately; this module carries `FB4`, which is two joined
//! observations. Both sites are marked with an `FB4` comment in the code
//! below so that the document can cite them.
//!
//! **The truncation precedes the failure.** `curlx_dyn_setlen(host, keep)`
//! at L370 runs before the bare-colon return at L372-L373 *and* before the
//! bad-number return at L376. A failing parse therefore leaves the host
//! buffer already shortened, and `curl_url_set(u, CURLUPART_URL, ..)` hides
//! that only because it parses into a temporary handle it then throws away,
//! L1197-L1209. `Curl_url_set_authority` does not: it works on a live
//! handle at L666-L667. Moving the truncation after the checks would be
//! tidier and would be a behavior change.
//!
//! **The leniency is scheme-conditional.** A trailing colon with no digits
//! after it succeeds -- host cut short, default port used -- but only when
//! the URL had a scheme. The rationale in the C comment at L363-L369 is
//! that browsers do the same thing, paraphrased: a colon with nothing after
//! it is ignored and the default port applies, as Firefox, Chrome and
//! Safari all do; and it is deliberately not done for a scheme-less input,
//! so that a long run of characters ending in a colon is not quietly
//! accepted as a host with no port when it looks far more like a scheme.
//! `tests/unit/unit1653.c` L202-L212 pins exactly that case with a
//! sixty-four character name.
//!
//! # The buffer-aliasing hazard, which is the subtle part
//!
//! `curlx_dyn_setlen` in `lib/curlx/dynbuf.c` L282-L292 does this and
//! nothing more:
//!
//! ```c
//! if(set > s->leng) return CURLE_BAD_FUNCTION_ARGUMENT;
//! s->leng = set;
//! s->bufr[s->leng] = 0;
//! ```
//!
//! It overwrites **exactly one byte**, the delimiter at index `keep`, and
//! leaves every later byte of the allocation intact. That is the only
//! reason the C can increment `portptr` at L371, *after* the truncation at
//! L370, and still read the port's digits: they were never erased, and the
//! pointer it holds still aims into the same allocation.
//!
//! [`crate::dynbuf::DynBuf`] cannot be read that way, and deliberately so.
//! `as_bytes` yields `..len` and `content_mut` yields `..len + 1`, so the
//! moment the length comes down to `keep` the digits are outside every view
//! the type hands out. A port written over that API in the C's order would
//! find an empty port for every input, and would find it silently.
//!
//! So [`parse_port`] reads the digits **before** it truncates: [`plan`]
//! locates the delimiter and reads what follows it under one immutable
//! borrow of the buffer, and only then does the truncation happen and the
//! outcome get applied. That is not a reordering of anything observable.
//! The scan has no side effects, so computing it earlier cannot be seen
//! from outside, while the two things that *are* observable both survive
//! exactly: the truncation still happens before both failing returns, and
//! the bytes scanned are the same bytes, because the single byte L370
//! overwrites sits at `keep` and every byte read sits above it.
//!
//! Do not "simplify" this back into the C's order. It would compile, it
//! would pass a review that only compared it with the C line by line, and
//! it would break every URL carrying a port.
//!
//! Two alternatives were considered and rejected. Copying the digits to
//! the heap first costs one allocation on every URL that carries a port,
//! and the allocation ceiling `tests/data/test1560` asserts is part of the
//! specification. Copying them into a fixed-size stack buffer is worse
//! than costly, it is wrong: leading zeroes are accepted, so a *valid*
//! digit run has no length bound at all, and `:00000000000000000080` is
//! port 80.
//!
//! # Ownership, and an ordering the sibling setter does not share
//!
//! Nothing here allocates the host buffer; this stage only ever shortens
//! it. The buffer's ownership moves into the handle later, at
//! `lib/urlapi.c` L1185 on the parse path and L671-L672 on the authority
//! path, ported in `src/parse/mod.rs` and `src/parse/authority.rs`.
//!
//! One allocation does happen: the regenerated port string at L381, which
//! C produces with `curl_maprintf` and which this module produces with
//! [`crate::alloc::CBuf::format`] so that the buffer comes from the C
//! allocator and a later `curl_free` on it is correct. `CString::into_raw`
//! is banned crate-wide for exactly that reason.
//!
//! The order around it is worth stating, because the other port setter in
//! the module chose the opposite one and the difference is observable.
//! Here, L380 releases the old `u->port` *before* L381 allocates the new
//! one, so a failed allocation leaves the handle with no textual port and
//! with `u->portnum` already updated by L378. `set_url_port` at
//! L1666-L1683, which `src/getset.rs` ports, allocates first and releases
//! afterwards, so its own failure path keeps the old value. This module
//! reproduces its own order: [`store_port`] sets the number, clears the
//! field, and only then allocates.
//!
//! # Verification
//!
//! The unit tests below cover this stage in isolation, and their vectors
//! come from `tests/unit/unit1653.c` and from the port-bearing rows of
//! `tests/libtest/lib1560.c`. Neither file is modified; both are read-only
//! references.
//!
//! End-to-end verification is to be the parity run: the unmodified
//! `tests/libtest/lib1560.c` built against the reference C library and
//! against this crate, with the two outputs diffed byte for byte.
//! `rust-urlapi/scripts/run-parity.sh` is the script that is to drive it and
//! is a later deliverable, so it does not exist yet and no claim here rests
//! on its having run.

// Reachability here matches the C exactly. `Curl_parse_port` has one caller in
// the C tree, `parse_authority` at `lib/urlapi.c` L627, so the sole in-crate
// consumer of `parse_port` is `src/parse/authority.rs`, which calls it at its
// own L726. `src/parse/mod.rs` declares `mod port;`, and both modules are
// compiled unconditionally, so nothing here is unreached.
//
// No dead-code allowance is stated here. The crate-level one in `src/lib.rs`
// covers the whole feature matrix in one place, which is where the reason for
// it belongs; see "DEAD-CODE POLICY" there.

// The plan puts every `unsafe` block in `src/ffi.rs` (0.3.3) and the
// technical specification forbids `unsafe` outside FFI code (1.3.2.1).
// `forbid` rather than `deny` because an inner `allow` here would be a
// design change and should have to be argued for, not slipped in. This
// module needs nothing from C, so the attribute costs it nothing and turns
// the crate's single-unsafe-island property into a compiler guarantee
// instead of a convention.
#![forbid(unsafe_code)]

use crate::abi::{
    CURLUcode, CURLUE_BAD_IPV6, CURLUE_BAD_PORT_NUMBER, CURLUE_OK, CURLUE_OUT_OF_MEMORY,
};
use crate::alloc::CBuf;
use crate::dynbuf::DynBuf;
use crate::handle::{CurlUrl, StringField};
use crate::strparse::str_number;

/// The largest port number this API accepts: `0xffff`, from the scan at
/// `lib/urlapi.c` L375.
///
/// Typed `i64` because that is `curl_off_t` on every platform this port
/// targets, and `crate::strparse::str_number` takes its ceiling in the same
/// type the C's `curlx_str_number` does. Named rather than spelled inline
/// because `set_url_port` at L1673 uses the identical ceiling, and the two
/// have to stay equal: a URL parsed with one and then edited through the
/// other must accept the same set of numbers.
const PORT_MAX: i64 = 0xffff;

/// What the bytes after the delimiter turned out to be.
///
/// The C has no such type; it has three control-flow outcomes at L372-L376
/// and reaches them by returning early. Naming them is what lets the scan
/// happen before the truncation without the ordering of the two returns
/// changing. See the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PortText {
    /// The delimiter was the last byte, so `!*portptr` at L372 holds.
    ///
    /// This is the `FB4` leniency's trigger, and the only outcome whose
    /// result depends on `has_scheme`.
    Absent,
    /// The bytes are not a port number: either they do not begin with a
    /// digit, or they overflow the `0xffff` ceiling, or a byte is left over
    /// after the digits.
    ///
    /// All three fold into `CURLUE_BAD_PORT_NUMBER` at L376, exactly as the
    /// C's `if(curlx_str_number(..) || *portptr)` folds them.
    Rejected,
    /// A number in `0..=0xffff` with nothing after it.
    ///
    /// Carried as the `curl_off_t` the C scans, not as the `unsigned short`
    /// it narrows to at L378, because L381 prints this value and not the
    /// narrowed one.
    Number(i64),
}

/// What [`parse_port`] decided to do, computed while the host buffer is
/// only borrowed.
///
/// Three variants for the three shapes the C's control flow takes before it
/// touches anything: return a code without truncating, return success
/// without truncating, or truncate and then act.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Plan {
    /// `portptr` came out NULL, so the C falls through to L386. Reached
    /// from L353-L354 for a bracketed address with nothing after the
    /// bracket, and from L357 for a name with no colon in it.
    NoPort,
    /// One of the two early failures, L346 and L351. Both return **before**
    /// L370, so the host buffer is left exactly as it was found -- which is
    /// the half of `FB4` that is easy to get wrong in the other direction.
    Failed(CURLUcode),
    /// A delimiter was found, and the truncation at L370 applies whatever
    /// the port then turns out to be.
    Truncate {
        /// The C's `keep` at L361, `portptr - hostname`: the index of the
        /// delimiter, and so the length the host is cut down to.
        keep: usize,
        /// What followed the delimiter, per [`read_port`].
        port: PortText,
    },
}

/// The bytes C would see through `curlx_dyn_ptr()` at `lib/urlapi.c` L339.
///
/// That pointer is a `char *` and every read of it here goes through
/// `strchr`, at L344 and L357, so the string C inspects ends at the first
/// zero byte whether or not the buffer holds more after it. A
/// [`DynBuf`] can hold an interior zero -- `addn` copies whatever it is
/// given -- so the window is taken explicitly rather than assumed away.
///
/// No call site can actually produce one: `Curl_junkscan` at
/// `lib/urlapi.c` L223-L246 rejects every byte at or below `0x20` in the
/// input, and `Curl_url_set_authority` measures its argument with `strlen`
/// at L666. The window is therefore a faithfulness measure, not a
/// correction, and it is two lines.
///
/// `src/encode.rs` has an equivalent private helper. It is not imported,
/// because this file's dependency whitelist does not include that module
/// and a helper this small is better duplicated than reached for across a
/// boundary the plan drew deliberately.
fn cstring_window(content: &[u8]) -> &[u8] {
    match content.iter().position(|&byte| byte == 0) {
        // The prefix is in bounds by construction, so the fallback is
        // unreachable; `get` is used anyway so that the bound is checked by
        // the compiler rather than argued for in a comment.
        Some(nul) => content.get(..nul).unwrap_or(content),
        None => content,
    }
}

/// Reads the bytes after the delimiter: `lib/urlapi.c` L371-L376.
///
/// `digits` is what `portptr` points at once L371 has stepped over the
/// delimiter, up to the end of the C string. An empty slice is the C's
/// `!*portptr` at L372, because a slice ends where the terminator sits.
fn read_port(digits: &[u8]) -> PortText {
    // L372. Reported rather than decided here: whether an absent port is a
    // success is `has_scheme`'s business, and it belongs at the call site
    // where the C spells its conditional.
    if digits.is_empty() {
        return PortText::Absent;
    }

    // L375, both halves of one test. `str_number` advances the cursor over
    // the digits it consumed and not one byte further, so what remains is
    // exactly what the C's `*portptr` would look at, and an empty remainder
    // is its terminator. Splitting the test is the C's own division of
    // labor: `crate::strparse` documents why the scanner must not fold the
    // leftover check into itself, and `ipv4_normalize` is why.
    let mut cursor = digits;
    match str_number(&mut cursor, PORT_MAX) {
        Ok(port) if cursor.is_empty() => PortText::Number(port),
        // The three rejections of L375-L376: a leftover byte, a
        // non-digit first byte, and a number above the ceiling.
        Ok(_) | Err(_) => PortText::Rejected,
    }
}

/// Locates the delimiter and reads what follows it: `lib/urlapi.c`
/// L339-L376, everything except the truncation and the store.
///
/// Takes the host content by borrow and touches nothing, which is what
/// makes it callable before [`DynBuf::setlen`] shortens the buffer out from
/// under the digits. See the module documentation for why that ordering is
/// mandatory here and unobservable from outside.
fn plan(hostname: &[u8]) -> Plan {
    // L343. `first()` rather than `hostname[0]`: the C reads a
    // NUL-terminated string and so is safe on an empty one, where an index
    // would not be. An empty buffer therefore takes the `else` branch below
    // and finds no colon, which is what C does with an empty string too.
    if hostname.first() == Some(&b'[') {
        let Some(bracket) = hostname.iter().position(|&byte| byte == b']') else {
            // L345-L346. An address error, not a port error, and it returns
            // before the truncation at L370.
            return Plan::Failed(CURLUE_BAD_IPV6);
        };

        // L347: `portptr++` steps past the bracket. `saturating_add`
        // because the crate denies arithmetic that could wrap; it is exact
        // here, since `bracket` indexes a byte that exists.
        let after = bracket.saturating_add(1);
        match hostname.get(after) {
            // L349-L350: a `:` here is the delimiter, so `after` is the
            // index the host is cut at.
            Some(&b':') => at_delimiter(hostname, after),
            // L350-L351: any other byte after the bracket is a port error,
            // again before the truncation.
            Some(_) => Plan::Failed(CURLUE_BAD_PORT_NUMBER),
            // L353-L354: the string ended at the bracket, so `portptr`
            // becomes NULL and there is no port.
            None => Plan::NoPort,
        }
    } else {
        // L356-L357: the first colon anywhere in the string. `position`
        // stops at the first match exactly as `strchr` does, which is why
        // `host:1:2` fails on its leftover rather than parsing `2`.
        match hostname.iter().position(|&byte| byte == b':') {
            Some(colon) => at_delimiter(hostname, colon),
            // L386, by way of a NULL `portptr`.
            None => Plan::NoPort,
        }
    }
}

/// Builds the truncating plan for a delimiter at index `keep`:
/// `lib/urlapi.c` L361 and L371.
///
/// `keep` is the C's `portptr - hostname` at L361, and the bytes handed to
/// [`read_port`] are what `portptr` addresses after the increment at L371.
/// Both branches of [`plan`] end here, so the arithmetic that pairs them
/// exists once.
fn at_delimiter(hostname: &[u8], keep: usize) -> Plan {
    // `saturating_add` for the crate's arithmetic policy; exact, because
    // `keep` indexes the delimiter, a byte that exists. The fallback is an
    // empty slice, which is also what a delimiter in the last position
    // yields, so both spell the C's `!*portptr` the same way.
    let digits = hostname.get(keep.saturating_add(1)..).unwrap_or(&[]);
    Plan::Truncate {
        keep,
        port: read_port(digits),
    }
}

/// Stores a scanned port number in the handle: `lib/urlapi.c` L378-L383.
///
/// Split out so that the three-step order the C uses is in one place and
/// can be read against the C without the surrounding control flow in the
/// way. The order is the point; see the module documentation on the
/// contrast with `set_url_port`.
fn store_port(u: &mut CurlUrl, port: i64) -> CURLUcode {
    // L378: `u->portnum = (unsigned short)port`. The C's cast cannot lose
    // information, because L375 already refused anything above `0xffff`, so
    // `try_from` is that cast with the guarantee made explicit instead of
    // implied. The failing arm is unreachable for the same reason; it
    // returns the code the C gives an out-of-range port anyway, so an
    // unreachable branch cannot become a wrong answer, and no `unwrap` or
    // `panic!` appears.
    let Ok(portnum) = u16::try_from(port) else {
        return CURLUE_BAD_PORT_NUMBER;
    };
    u.set_portnum(portnum);

    // L380: `curlx_free(u->port)`, and it happens before the allocation
    // below rather than after it. Clearing the field releases the old
    // buffer through its `Drop`, which is what the C's free does, and it
    // leaves the field absent, which is what the C's assignment at L381
    // does with a NULL result. Both halves of that matter on the failure
    // path.
    u.clear(StringField::Port);

    // L379-L381: regenerate the text from the number, which is how leading
    // zeroes and any other spelling of the same number disappear. The
    // value printed is the `curl_off_t`, as the C's
    // `"%" CURL_FORMAT_CURL_OFF_T` prints, and not the narrowed
    // `unsigned short`; for a number this range they agree, and printing
    // the same one the C prints removes the question. `CBuf` puts the
    // result in the C allocator, so a caller's `curl_free` on it is
    // correct.
    let Some(text) = CBuf::format(format_args!("{port}")) else {
        // L382-L383. The handle is left with `portnum` set and no textual
        // port, exactly as the C leaves it.
        return CURLUE_OUT_OF_MEMORY;
    };
    u.store(StringField::Port, text);

    CURLUE_OK
}

/// Splits a trailing port number off the host name and stores it.
///
/// `Curl_parse_port` at `lib/urlapi.c` L335-L387. The module documentation
/// carries the full rule, the `FB4` reproduction and the reason the digits
/// are read before the buffer is shortened.
///
/// # Parameters
///
/// - `u`: the handle whose `portnum` and `port` are written on success.
///   Only those two members are touched, and only when a number was
///   actually scanned.
/// - `host`: the host buffer, holding the authority with credentials
///   already stripped. **Shortened in place** at the delimiter, including
///   on the two failing paths that reach the truncation; see `FB4`. Its
///   content may be left empty, which the caller turns into
///   `CURLUE_NO_HOST` at L631.
/// - `has_scheme`: whether the URL being parsed carried a scheme. Consulted
///   on exactly one path, the bare-delimiter case at L372-L373.
///
/// # Returns
///
/// `CURLUE_OK` when there was no port to extract or when one was extracted
/// and stored, and otherwise one of three codes: `CURLUE_BAD_IPV6` for a
/// bracketed address with no closing bracket, `CURLUE_BAD_PORT_NUMBER` for
/// anything that is not an acceptable port, and `CURLUE_OUT_OF_MEMORY` if
/// the textual port cannot be allocated. Those four, and no others, are
/// what the C can return.
#[must_use = "the result code carries the whole outcome and must be handled"]
pub(crate) fn parse_port(u: &mut CurlUrl, host: &mut DynBuf, has_scheme: bool) -> CURLUcode {
    // Stage one, L339-L376 minus the truncation: decide everything while
    // the buffer is only borrowed. The borrow ends with this statement,
    // which is what lets stage two take it mutably.
    let (keep, port) = match plan(cstring_window(host.as_bytes())) {
        // L386, reached with `portptr` NULL and nothing done.
        Plan::NoPort => return CURLUE_OK,
        // L346 and L351, both of which return before the truncation.
        Plan::Failed(code) => return code,
        Plan::Truncate { keep, port } => (keep, port),
    };

    // Stage two, L370. FB4, first half: this runs before both of the
    // failing returns below, so a rejected port still leaves the host
    // shortened. That is the C's behavior and reproducing it is the
    // requirement; do not move it under the `PortText::Number` arm.
    //
    // The `bool` is C's ignored return value. `keep` indexes a byte inside
    // the content, so it is below the length and the call cannot refuse;
    // `crate::dynbuf` documents why the C's own declaration is not
    // warn-unused and why both C call sites drop it too.
    host.setlen(keep);

    // Stage three, L372-L383.
    match port {
        // L372-L373. FB4, second half: the bare-delimiter leniency, and it
        // applies only with a scheme. The C's rationale is at L363-L369 and
        // is paraphrased in the module documentation; the short version is
        // that browsers ignore a digit-less colon, and that allowing it
        // without a scheme would accept something that looks far more like
        // a scheme than like a host.
        PortText::Absent => {
            if has_scheme {
                CURLUE_OK
            } else {
                CURLUE_BAD_PORT_NUMBER
            }
        }
        PortText::Rejected => CURLUE_BAD_PORT_NUMBER,
        PortText::Number(port) => store_port(u, port),
    }
}

#[cfg(test)]
mod tests {
    // The outcome record copies the buffers out so that an assertion can be
    // written after the handle and the host buffer are gone, and it reaches
    // the heap through the `alloc` crate rather than through `std` so that
    // this module compiles the same way whichever the crate root turns out
    // to declare. Every other module in this crate imports from `core`
    // alone, and this keeps that property intact.
    extern crate alloc;

    use super::{cstring_window, parse_port, read_port, PortText, PORT_MAX};
    use crate::abi::{
        CURLUcode, CURLUE_BAD_IPV6, CURLUE_BAD_PORT_NUMBER, CURLUE_OK, CURL_MAX_INPUT_LENGTH,
    };
    use crate::alloc::CBuf;
    use crate::dynbuf::DynBuf;
    use crate::handle::{CurlUrl, StringField};
    use alloc::vec::Vec;

    /// Everything one call leaves behind, copied out of the handle and the
    /// buffer.
    ///
    /// All four members are asserted on every case by [`check`], including
    /// on the failing ones. That is deliberate: `FB4` is a statement about
    /// what a *failing* call does to the host buffer, so a test suite that
    /// only checked result codes could not see it.
    #[derive(Debug, PartialEq, Eq)]
    struct Outcome {
        /// The `CURLUcode` returned.
        code: CURLUcode,
        /// The host buffer's content afterwards.
        host: Vec<u8>,
        /// `u->port`, the textual port, or `None` when the field is absent.
        port: Option<Vec<u8>>,
        /// `u->portnum`, which is zero on a fresh handle.
        portnum: u16,
    }

    /// Runs one case the way `tests/unit/unit1653.c` L30-L40 does: build a
    /// dynamic buffer over `input`, call the function, report what came out.
    ///
    /// The buffer's ceiling is `CURL_MAX_INPUT_LENGTH`, which is what
    /// `lib/urlapi.c` L664 and the parse path use. `unit1653.c` L34 passes
    /// 10000 instead and no input here comes anywhere near either number.
    fn run(input: &[u8], has_scheme: bool) -> Outcome {
        run_over(input, has_scheme, None)
    }

    /// [`run`] with `u->port` already populated, so that what this stage
    /// does to a value that was already there is observable.
    ///
    /// The live-handle path is real: `Curl_url_set_authority` at
    /// `lib/urlapi.c` L666-L667 parses an authority straight into a handle
    /// that may already hold a port.
    fn run_over(input: &[u8], has_scheme: bool, existing: Option<&[u8]>) -> Outcome {
        let mut u = CurlUrl::new();
        if let Some(text) = existing {
            let buf = CBuf::from_slice(text);
            assert!(buf.is_some(), "the fixture port allocation must succeed");
            if let Some(buf) = buf {
                u.store(StringField::Port, buf);
            }
        }

        let mut host = DynBuf::new(CURL_MAX_INPUT_LENGTH);
        assert!(host.addn(input).is_ok(), "the fixture append must succeed");

        let code = parse_port(&mut u, &mut host, has_scheme);
        Outcome {
            code,
            host: host.as_bytes().to_vec(),
            port: u.port().map(|bytes| bytes.to_vec()),
            portnum: u.portnum(),
        }
    }

    /// Asserts the whole outcome of a case rather than the part a test
    /// happens to be about.
    fn check(outcome: &Outcome, code: CURLUcode, host: &[u8], port: Option<&[u8]>, portnum: u16) {
        assert_eq!(outcome.code, code, "result code");
        assert_eq!(outcome.host.as_slice(), host, "host content");
        assert_eq!(outcome.port.as_deref(), port, "textual port");
        assert_eq!(outcome.portnum, portnum, "numeric port");
    }

    /// The ceiling is the C's, `0xffff` at `lib/urlapi.c` L375, and it is
    /// the same one `set_url_port` scans with at L1673. A URL parsed
    /// through one and edited through the other has to accept the same set
    /// of numbers.
    #[test]
    fn the_ceiling_is_the_c_ceiling() {
        assert_eq!(PORT_MAX, 0xffff);
        assert_eq!(PORT_MAX, 65_535);
    }

    /// The window stops where C's `strchr` at L344 and L357 stops, at the
    /// first zero byte, and covers the whole content when there is none.
    #[test]
    fn the_window_ends_at_the_first_zero_byte() {
        assert_eq!(cstring_window(b"example.com\0:80"), b"example.com");
        assert_eq!(cstring_window(b"example.com:80"), b"example.com:80");
        assert_eq!(cstring_window(b"\0:80"), b"");
        assert_eq!(cstring_window(b""), b"");
    }

    /// The three shapes of L372-L376, reported and not decided: whether an
    /// absent port is a success is `has_scheme`'s business at the call
    /// site, not this function's.
    ///
    /// The rejections are the C's whole rejection set. `"-1"` and `"+80"`
    /// fail because `valid_digit` at `lib/curlx/strparse.c` L142-L143
    /// refuses a sign, `" 80"` because the scanner passes no blanks,
    /// `"65536"` on the ceiling, and `"80x"` on the leftover byte the
    /// caller tests separately.
    #[test]
    fn read_port_classifies_the_bytes_after_the_delimiter() {
        assert_eq!(read_port(b""), PortText::Absent);
        assert_eq!(read_port(b"80"), PortText::Number(80));
        assert_eq!(read_port(b"0"), PortText::Number(0));
        assert_eq!(read_port(b"65535"), PortText::Number(65_535));
        assert_eq!(read_port(b"65536"), PortText::Rejected);
        assert_eq!(read_port(b"80x"), PortText::Rejected);
        assert_eq!(read_port(b"x80"), PortText::Rejected);
        assert_eq!(read_port(b"-1"), PortText::Rejected);
        assert_eq!(read_port(b"+80"), PortText::Rejected);
        assert_eq!(read_port(b" 80"), PortText::Rejected);
    }

    /// A name with no colon in it is left exactly as it was: `strchr`
    /// returns NULL at L357 and the function falls through to L386.
    #[test]
    fn a_name_without_a_delimiter_is_untouched() {
        let outcome = run(b"example.com", false);
        check(&outcome, CURLUE_OK, b"example.com", None, 0);
    }

    /// An empty buffer takes the same path. The C would be reading a
    /// zero-length string here, and this state is unreachable from
    /// `parse_authority` anyway: `curlx_dyn_addn` allocates even for a
    /// zero-length append, and L631 turns an empty host into
    /// `CURLUE_NO_HOST` immediately afterwards.
    #[test]
    fn an_empty_buffer_is_accepted_and_left_empty() {
        let outcome = run(b"", false);
        check(&outcome, CURLUE_OK, b"", None, 0);
    }

    /// The name and the port are split at the colon, and the number is
    /// stored twice over: as `u->portnum` at L378 and as regenerated text
    /// at L381.
    #[test]
    fn a_name_and_port_are_split() {
        let outcome = run(b"example.com:8080", false);
        check(&outcome, CURLUE_OK, b"example.com", Some(b"8080"), 8080);
    }

    /// Regenerating the text is what drops leading zeroes, which the C
    /// comment at L379 says outright. `tests/libtest/lib1560.c` L495-L498
    /// pins the same thing through the public API: `:01` reads back as a
    /// port of `1`.
    #[test]
    fn leading_zeroes_are_dropped_by_regeneration() {
        let outcome = run(b"example.com:080", false);
        check(&outcome, CURLUE_OK, b"example.com", Some(b"80"), 80);

        let outcome = run(b"example.com:0000000000000000000080", false);
        check(&outcome, CURLUE_OK, b"example.com", Some(b"80"), 80);
    }

    /// A digit-less colon is not the only way a valid port can be long: a
    /// run of leading zeroes is unbounded and still valid, which is exactly
    /// why the digits cannot be captured into a fixed-size buffer before
    /// the truncation. See the module documentation.
    #[test]
    fn a_very_long_run_of_leading_zeroes_is_still_a_valid_port() {
        let zeroes = [b'0'; 4096];
        let mut input = Vec::new();
        input.extend_from_slice(b"a:");
        input.extend_from_slice(&zeroes);
        input.extend_from_slice(b"443");

        let outcome = run(&input, false);
        check(&outcome, CURLUE_OK, b"a", Some(b"443"), 443);
    }

    /// Zero is a port. `tests/libtest/lib1560.c` L491-L494 asserts
    /// `https://example.com:0#moo` round-trips with a port of `0`, so this
    /// is not a case that may be folded into "no port".
    #[test]
    fn zero_is_a_valid_port() {
        let outcome = run(b"example.com:0", false);
        check(&outcome, CURLUE_OK, b"example.com", Some(b"0"), 0);
    }

    /// The ceiling is inclusive, and one past it fails **with the host
    /// already truncated**, because L370 runs before L376.
    /// `tests/libtest/lib1560.c` L485-L487 pins the rejection.
    #[test]
    fn the_ceiling_is_inclusive_and_overflow_still_truncates() {
        let outcome = run(b"example.com:65535", false);
        check(&outcome, CURLUE_OK, b"example.com", Some(b"65535"), 65_535);

        let outcome = run(b"example.com:65536", false);
        check(&outcome, CURLUE_BAD_PORT_NUMBER, b"example.com", None, 0);
    }

    /// A byte left over after the digits is rejected by the second half of
    /// the test at L375, and the host is truncated first.
    /// `tests/libtest/lib1560.c` L762 pins `http:/@example.com:123a/`.
    #[test]
    fn a_leftover_byte_after_the_digits_is_rejected() {
        let outcome = run(b"example.com:80x", false);
        check(&outcome, CURLUE_BAD_PORT_NUMBER, b"example.com", None, 0);

        let outcome = run(b"example.com:123a", false);
        check(&outcome, CURLUE_BAD_PORT_NUMBER, b"example.com", None, 0);
    }

    /// A port that does not start with a digit is rejected too, which is
    /// `STRE_NO_NUM` folded into the same code.
    /// `tests/libtest/lib1560.c` L488-L490 pins
    /// `https://example.com:-1#moo`.
    #[test]
    fn a_port_that_is_not_a_number_is_rejected() {
        let outcome = run(b"example.com:-1", false);
        check(&outcome, CURLUE_BAD_PORT_NUMBER, b"example.com", None, 0);
    }

    /// Only the **first** colon is the delimiter, so `host:1:2` cuts at the
    /// first one and then fails on the leftover `:2` rather than reading
    /// `2` as the port.
    #[test]
    fn only_the_first_colon_is_the_delimiter() {
        let outcome = run(b"example.com:1:2", false);
        check(&outcome, CURLUE_BAD_PORT_NUMBER, b"example.com", None, 0);
    }

    /// An authority that is nothing but a port leaves the host buffer
    /// empty, which is how `parse_authority` produces `CURLUE_NO_HOST` at
    /// `lib/urlapi.c` L631. This stage reports success; the caller is what
    /// turns it into an error.
    #[test]
    fn a_bare_port_empties_the_host_buffer() {
        let outcome = run(b":80", false);
        check(&outcome, CURLUE_OK, b"", Some(b"80"), 80);
    }

    /// `FB4`, case A: a colon with no digits after it succeeds when the URL
    /// had a scheme, and the host is cut short at the colon so that the
    /// default port applies. `lib/urlapi.c` L363-L373, and
    /// `tests/unit/unit1653.c` L161-L172 for the bracketed spelling.
    #[test]
    fn fb4_a_bare_delimiter_is_accepted_with_a_scheme() {
        let outcome = run(b"example.com:", true);
        check(&outcome, CURLUE_OK, b"example.com", None, 0);
    }

    /// `FB4`, case B, and the regression guard for the half of `FB4` that
    /// is easiest to lose.
    ///
    /// Without a scheme the same input is `CURLUE_BAD_PORT_NUMBER`, per the
    /// condition at L373 -- **and the host is still truncated**, because
    /// L370 already ran. The host assertion here is the guard: moving the
    /// truncation below the checks would leave the code passing and this
    /// assertion failing.
    #[test]
    fn fb4_a_bare_delimiter_is_rejected_without_a_scheme_and_still_truncates() {
        let outcome = run(b"example.com:", false);
        check(&outcome, CURLUE_BAD_PORT_NUMBER, b"example.com", None, 0);
    }

    /// The rationale for `FB4`'s scheme condition, as
    /// `tests/unit/unit1653.c` L202-L212 states it: sixty-four characters
    /// followed by a colon must not be accepted, because that shape looks
    /// far more like a scheme than like a host with no port.
    #[test]
    fn fb4_the_scheme_condition_is_why_a_long_name_and_a_colon_fail() {
        let name = [b'a'; 64];
        let mut input = Vec::new();
        input.extend_from_slice(&name);
        input.push(b':');

        let outcome = run(&input, false);
        check(&outcome, CURLUE_BAD_PORT_NUMBER, &name, None, 0);

        // With a scheme the very same input is accepted, which is the whole
        // point of the condition.
        let outcome = run(&input, true);
        check(&outcome, CURLUE_OK, &name, None, 0);
    }

    /// `has_scheme` is consulted on exactly one path. Everywhere else the
    /// two settings agree, byte for byte.
    #[test]
    fn has_scheme_changes_nothing_except_the_bare_delimiter_case() {
        for input in [
            b"example.com".as_slice(),
            b"example.com:80",
            b"example.com:80x",
            b"example.com:65536",
            b"[fe80::1]",
            b"[fe80::1]:443",
            b"[fe80::1]x",
            b"[fe80::1",
        ] {
            assert_eq!(
                run(input, false),
                run(input, true),
                "has_scheme must not matter for {input:?}"
            );
        }
    }

    /// A bracketed address with no port: the byte after the bracket is the
    /// terminator, so `portptr` becomes NULL at L354 and nothing happens.
    /// `tests/unit/unit1653.c` L52-L64 is this case, and it goes on to
    /// assert that a later `CURLUPART_PORT` retrieval with
    /// `CURLU_NO_DEFAULT_PORT` finds nothing -- which is what the absent
    /// `port` field below means.
    #[test]
    fn a_bracketed_address_without_a_port_is_accepted() {
        let outcome = run(b"[fe80::250:56ff:fea7:da15]", false);
        check(&outcome, CURLUE_OK, b"[fe80::250:56ff:fea7:da15]", None, 0);
    }

    /// No closing bracket is `CURLUE_BAD_IPV6`, an address error and not a
    /// port error, and it returns before the truncation.
    /// `tests/unit/unit1653.c` L66-L76 is the `|` spelling of it.
    #[test]
    fn an_unclosed_bracket_is_a_bad_address() {
        let outcome = run(b"[fe80::250:56ff:fea7:da15|", false);
        check(
            &outcome,
            CURLUE_BAD_IPV6,
            b"[fe80::250:56ff:fea7:da15|",
            None,
            0,
        );

        let outcome = run(b"[fe80::1", false);
        check(&outcome, CURLUE_BAD_IPV6, b"[fe80::1", None, 0);
    }

    /// A bracketed address with a port splits at the colon after the
    /// bracket. `tests/unit/unit1653.c` L122-L136 asserts `:81`, and this
    /// stage never looks inside the brackets: `ipv6_parse`, reached from
    /// `lib/urlapi.c` L638, is what validates the address afterwards.
    #[test]
    fn a_bracketed_address_with_a_port_is_split() {
        let outcome = run(b"[fe80::1]:443", false);
        check(&outcome, CURLUE_OK, b"[fe80::1]", Some(b"443"), 443);

        let outcome = run(b"[fe80::250:56ff:fea7:da15]:81", false);
        check(
            &outcome,
            CURLUE_OK,
            b"[fe80::250:56ff:fea7:da15]",
            Some(b"81"),
            81,
        );
    }

    /// The port extractor does not care what is between the brackets, only
    /// where they are. All three inputs are ported from
    /// `tests/unit/unit1653.c`: a semicolon inside the address at L78-L92,
    /// an encoded zone identifier at L94-L108, and two malformed zone
    /// identifiers at L174-L200.
    #[test]
    fn the_content_between_the_brackets_is_not_this_stages_business() {
        let outcome = run(b"[fe80::250:56ff;fea7:da15]:808", false);
        check(
            &outcome,
            CURLUE_OK,
            b"[fe80::250:56ff;fea7:da15]",
            Some(b"808"),
            808,
        );

        let outcome = run(b"[fe80::250:56ff:fea7:da15%25eth3]:80", false);
        check(
            &outcome,
            CURLUE_OK,
            b"[fe80::250:56ff:fea7:da15%25eth3]",
            Some(b"80"),
            80,
        );

        let outcome = run(b"[fe80::250:56ff:fea7:da15!25eth3]:180", false);
        check(
            &outcome,
            CURLUE_OK,
            b"[fe80::250:56ff:fea7:da15!25eth3]",
            Some(b"180"),
            180,
        );

        let outcome = run(b"[fe80::250:56ff:fea7:da15%eth3]:80", false);
        check(
            &outcome,
            CURLUE_OK,
            b"[fe80::250:56ff:fea7:da15%eth3]",
            Some(b"80"),
            80,
        );
    }

    /// An encoded zone identifier with no port is accepted and left alone,
    /// `tests/unit/unit1653.c` L110-L120.
    #[test]
    fn a_zone_identifier_without_a_port_is_untouched() {
        let outcome = run(b"[fe80::250:56ff:fea7:da15%25eth3]", false);
        check(
            &outcome,
            CURLUE_OK,
            b"[fe80::250:56ff:fea7:da15%25eth3]",
            None,
            0,
        );
    }

    /// Any byte other than a colon after the closing bracket is
    /// `CURLUE_BAD_PORT_NUMBER`, from L350-L351, and it returns before the
    /// truncation so the buffer is untouched.
    ///
    /// The four inputs are, in order: an ordinary letter; the semicolon of
    /// `tests/unit/unit1653.c` L138-L148; the digits of L150-L158, which is
    /// a port with the colon left out; and the `];80` and `]-80` rows of
    /// `tests/libtest/lib1560.c` L623-L628.
    #[test]
    fn a_byte_other_than_a_colon_after_the_bracket_is_rejected() {
        for input in [
            b"[fe80::1]x".as_slice(),
            b"[fe80::250:56ff:fea7:da15];81",
            b"[fe80::250:56ff:fea7:da15]80",
            b"[::%25fakeit];80",
            b"[fe80::20c:29ff:fe9c:409b]-80",
        ] {
            let outcome = run(input, false);
            check(&outcome, CURLUE_BAD_PORT_NUMBER, input, None, 0);
        }
    }

    /// A bracketed address with a digit-less colon is `FB4` as well, and
    /// `tests/unit/unit1653.c` L161-L172 asserts the success with a scheme.
    /// Without one it fails, and the host is truncated either way.
    #[test]
    fn fb4_applies_to_a_bracketed_address_too() {
        let outcome = run(b"[fe80::250:56ff:fea7:da15]:", true);
        check(&outcome, CURLUE_OK, b"[fe80::250:56ff:fea7:da15]", None, 0);

        let outcome = run(b"[fe80::250:56ff:fea7:da15]:", false);
        check(
            &outcome,
            CURLUE_BAD_PORT_NUMBER,
            b"[fe80::250:56ff:fea7:da15]",
            None,
            0,
        );
    }

    /// A successful parse replaces a port the handle already held, which is
    /// the release at L380 followed by the assignment at L381.
    #[test]
    fn a_successful_parse_replaces_an_existing_port() {
        let outcome = run_over(b"example.com:80", false, Some(b"9999"));
        check(&outcome, CURLUE_OK, b"example.com", Some(b"80"), 80);
    }

    /// The `FB4` bare-delimiter path returns at L373, before the release at
    /// L380, so a port the handle already held survives untouched. Faithful
    /// to the C, and worth pinning because it is the kind of detail a
    /// tidier rewrite would quietly change.
    #[test]
    fn the_bare_delimiter_path_leaves_an_existing_port_alone() {
        let outcome = run_over(b"example.com:", true, Some(b"9999"));
        check(&outcome, CURLUE_OK, b"example.com", Some(b"9999"), 0);
    }

    /// A rejected number returns at L376, also before the release at L380,
    /// so an existing port survives that too -- while the host is truncated
    /// regardless, which is `FB4` again.
    #[test]
    fn a_rejected_number_leaves_an_existing_port_alone() {
        let outcome = run_over(b"example.com:70000", false, Some(b"9999"));
        check(
            &outcome,
            CURLUE_BAD_PORT_NUMBER,
            b"example.com",
            Some(b"9999"),
            0,
        );
    }

    /// An early failure returns before L370, so neither the host buffer nor
    /// an existing port is touched.
    #[test]
    fn an_early_failure_changes_nothing_at_all() {
        let outcome = run_over(b"[fe80::1", false, Some(b"9999"));
        check(&outcome, CURLUE_BAD_IPV6, b"[fe80::1", Some(b"9999"), 0);

        let outcome = run_over(b"[fe80::1]x", false, Some(b"9999"));
        check(
            &outcome,
            CURLUE_BAD_PORT_NUMBER,
            b"[fe80::1]x",
            Some(b"9999"),
            0,
        );
    }

    /// Port numbers across the accepted range round-trip: the stored text is
    /// the decimal spelling of the input and `u->portnum` agrees with it.
    ///
    /// A sweep rather than a single case, because the two members are
    /// written by two different statements, L378 and L381, and a divergence
    /// between them would be invisible at any one value. The expected text
    /// is spelled out as data rather than computed, so that the assertion
    /// cannot reproduce a mistake the implementation makes.
    #[test]
    fn port_numbers_across_the_range_round_trip() {
        for (portnum, digits) in [
            (0_u16, b"0".as_slice()),
            (1, b"1"),
            (9, b"9"),
            (10, b"10"),
            (80, b"80"),
            (443, b"443"),
            (999, b"999"),
            (1000, b"1000"),
            (8080, b"8080"),
            (65_534, b"65534"),
            (65_535, b"65535"),
        ] {
            let mut input = Vec::new();
            input.extend_from_slice(b"example.com:");
            input.extend_from_slice(digits);

            let outcome = run(&input, false);
            check(&outcome, CURLUE_OK, b"example.com", Some(digits), portnum);
        }
    }

    /// An interior zero byte ends the string C would inspect, so a colon
    /// after one is not a delimiter and the buffer keeps its full length.
    /// Unreachable through the public API, since `Curl_junkscan` rejects the
    /// byte at `lib/urlapi.c` L233-L236, and pinned anyway because the
    /// window that produces it is a deliberate two lines rather than an
    /// accident.
    #[test]
    fn a_colon_after_an_interior_zero_byte_is_not_a_delimiter() {
        let outcome = run(b"example.com\0:80", false);
        check(&outcome, CURLUE_OK, b"example.com\0:80", None, 0);
    }
}
