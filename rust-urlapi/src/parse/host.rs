// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Host names: byte validation, IPv4 normalization and percent-decoding.
//!
//! Three `static` functions of `lib/urlapi.c`, ported into one module
//! because they are three stages of one pipeline over one buffer:
//!
//! | C function | Line | Ported as |
//! |---|---|---|
//! | `hostname_check` | L444-L462 | [`hostname_check`] |
//! | `ipv4_normalize` | L483-L575 | [`ipv4_normalize`] |
//! | `urldecode_host` | L578-L602 | [`urldecode_host`] |
//!
//! together with the `HOST_*` discriminants at L477-L481, which become
//! [`HostKind`].
//!
//! None of the three is exported. All three are `static` in C, none appears
//! in `lib/urlapi-int.h`, and none is part of the eight-symbol drop-in set,
//! so nothing here carries `#[no_mangle]` or `extern "C"`.
//!
//! # The stage order is the caller's, and it is load-bearing
//!
//! `parse_authority` at L634-L651 is the switch that drives all of this:
//!
//! ```c
//! switch(ipv4_normalize(host)) {
//! case HOST_IPV4:  break;
//! case HOST_IPV6:  uc = ipv6_parse(u, curlx_dyn_ptr(host),
//!                                  curlx_dyn_len(host));           break;
//! case HOST_NAME:  uc = urldecode_host(host);
//!                  if(!uc)
//!                    uc = hostname_check(u, curlx_dyn_ptr(host),
//!                                        curlx_dyn_len(host));      break;
//! case HOST_ERROR: uc = CURLUE_OUT_OF_MEMORY;                       break;
//! default:         uc = CURLUE_BAD_HOSTNAME; /* Bad IPv4 address even */
//! }
//! ```
//!
//! Read the `HOST_NAME` arm twice. Decoding runs **before** checking, and
//! the check is skipped entirely when decoding failed. That order cannot be
//! swapped, because `%` is the last of the thirty-one bytes
//! [`hostname_check`] refuses: run the check first and every
//! percent-encoded host on earth would be rejected. Measured against the
//! reference build, `https://ex%61mple.com/` yields the host `example.com`
//! precisely because of this ordering, and `https://exa%2fmple.com/` is
//! rejected with `CURLUE_BAD_HOSTNAME` because decoding turns `%2f` into
//! the `/` that the check then refuses.
//!
//! The order lives in the caller rather than here, and the two functions
//! stay independent, because not every caller wants both. `set_url_part`
//! decodes with `Curl_urldecode` itself and then checks, at L1979-L1981; at
//! L1985, where it encoded the value rather than receiving it encoded, it
//! checks without decoding at all. A convenience wrapper that fused the two
//! would quietly become a fourth code path.
//!
//! # Three rejection sets, and they are all different
//!
//! This module owns the third and widest of the crate's three sets of
//! refused bytes. They must not be folded together, and the concrete
//! consequences are visible in `tests/libtest/lib1560.c`:
//!
//! - **Set A**, `src/parse/junk.rs`: byte at or below `0x20` -- or `0x1f`,
//!   when `CURLU_ALLOW_SPACE` is set -- or `0x7f`. Applied to the whole URL
//!   before anything is parsed.
//! - **Set B**, `src/decode.rs` under `UrlReject::Ctrl`: byte below `0x20`
//!   only. Applied to the *decoded* byte. It accepts the space at `0x20`
//!   and delete at `0x7f`, which set A refuses.
//! - **Set C**, [`HOST_REJECT`] below: thirty-one specific bytes, four of
//!   them control or space and twenty-seven of them printable punctuation.
//!   Applied to the host after decoding.
//!
//! Sets B and C answer with the same `CURLUcode` from two different places,
//! which is worth knowing before debugging a mismatch. `https://%41%0D` is
//! `CURLUE_BAD_HOSTNAME` from set B, because `%0D` decodes to `0x0d`, below
//! `0x20`, so [`urldecode_host`] fails and the check never runs
//! (`lib1560.c` L652). `https://%20` is the same code from set C, because
//! set B lets the decoded space through and [`hostname_check`] then refuses
//! it (`lib1560.c` L651). Widen set B by one byte and the first case starts
//! reporting through the second path; narrow set C by one and the second
//! case starts succeeding.
//!
//! # A decoded host can turn into an IPv6 address
//!
//! [`hostname_check`] hands a host beginning with `[` to
//! [`crate::parse::ipv6::ipv6_parse`], and on the parse path that branch is
//! reachable only *because* decoding ran first. A host that already began
//! with a bracket was answered [`HostKind::Ipv6`] by [`ipv4_normalize`] and
//! took the switch's other arm, reaching the IPv6 parser without passing
//! through here at all. One that begins with `%` is a [`HostKind::Name`], is
//! decoded, and only then turns out to be bracketed -- at which point L452
//! sees the bracket and delegates. Measured:
//! `https://%5b%3a%3a%31%5d/` comes back as the host `[::1]`, brackets
//! included, and `https://%5bnonsense%5d/` is refused with
//! `CURLUE_BAD_IPV6` rather than with this module's own code.
//!
//! # What is not here
//!
//! No bracketed-address validation of any kind. [`ipv4_normalize`] returns
//! [`HostKind::Ipv6`] on a leading `[` without looking at another byte, so
//! `[` alone, `[nonsense` and `[::1]` are indistinguishable to this module.
//! Every check on such a host, the zone identifier included, belongs to
//! `src/parse/ipv6.rs`.
//!
//! No IDN conversion either. This module is entirely byte-oriented and
//! accepts every byte with the high bit set, which is what leaves a
//! non-ASCII host intact for `src/idn.rs` to convert later. That is the same
//! division of labor the C has, and the reason the encoder at L124-L129
//! documents host encoding as something that must be skipped.
//!
//! # Where the parity oracle lives
//!
//! End-to-end verification is the parity run over the unmodified
//! `tests/libtest/lib1560.c`, driven by
//! `rust-urlapi/scripts/run-parity.sh`. The sub-tests that exercise this
//! file hardest are `get_parts`, whose failure shows up as exit code 4, and
//! `set_parts`, exit code 2, per the exit-code mapping in the plan; the
//! host tables in `set_url` and `get_url` cover the rest. The unit tests at
//! the foot of this file are a second, independent oracle: every vector in
//! them was captured from a C program linked against an unmodified libcurl
//! archive rather than derived by reading this code.

// DEAD-CODE POLICY, TIME-BOXED. Identical in every module of this crate; grep
// for "DEAD-CODE POLICY" to find them all. They are removed together, by the
// checkpoint that creates src/getset.rs, and replaced there by one crate-level
// allowance in src/lib.rs carrying this same note. Until src/parse/mod.rs and
// src/parse/authority.rs exist, this module has no consumer -- its three C
// call sites land in src/parse/authority.rs and src/getset.rs -- and a crate
// held to zero warnings cannot build clean without this. Scoped to this module
// and to this lint alone.
//
// THE CHECKPOINT THAT CREATES src/parse/mod.rs MUST DECLARE `mod host;` THERE.
// Under edition 2021 no module declaration reaches this file without it, so
// otherwise nothing compiles it and none of the tests below ever run.
#![allow(dead_code)]
// The plan puts every `unsafe` block in `src/ffi.rs` (0.3.3) and the technical
// specification forbids `unsafe` outside FFI code (1.3.2.1). `forbid` rather
// than `deny` because an inner `allow` here would be a design change and
// should have to be argued for, not slipped in. This module walks a buffer
// with a cursor and hands a mutable view to a function that writes into it,
// which is exactly the shape of code that invites a raw pointer; the attribute
// turns "it did not need one" into a compiler guarantee.
#![forbid(unsafe_code)]

use crate::abi::{CURLUcode, CURLUE_BAD_HOSTNAME, CURLUE_NO_HOST, CURLUE_OK};
use crate::decode::{urldecode, UrlReject};
use crate::dynbuf::DynBuf;
use crate::error::cc2cu;
use crate::handle::CurlUrl;
use crate::parse::ipv6::ipv6_parse;
use crate::strparse::{str_hex, str_number, str_octal};

/// The bytes a host name may not contain: `lib/urlapi.c` L456, transcribed.
///
/// The C is one `strcspn` argument:
///
/// ```c
/// len = strcspn(hostname, " \r\n\t/:#?!@{}[]\\$\'\"^`*<>=;,+&()%");
/// ```
///
/// This is the same literal with the same bytes in the same order. It was
/// checked rather than typed out from the description: `od -c` over L456
/// and a C program that walks the compiled literal both report thirty-one
/// bytes, `0x20 0x0d 0x0a 0x09` followed by the twenty-seven printable
/// ones, and `tests::the_reject_set_is_the_c_string_literal` pins the same
/// conclusion from Rust.
///
/// The first four are written as escapes and must stay that way. A literal
/// tab or carriage return in this file would be rejected by
/// `scripts/spacecheck.pl`, which runs repository-wide and enforces
/// no-tabs, LF-only endings; the escapes are also the only spelling a
/// reader can see, since the raw bytes are invisible.
///
/// Read the last byte twice. `%` being in this set is what makes the stage
/// order in the module documentation load-bearing, and it is why
/// `https://%25` -- a host that decodes to a single `%` -- is
/// `CURLUE_BAD_HOSTNAME` rather than a host named `%`.
///
/// Not exhaustive over anything: this is a deny list, so every byte outside
/// it is accepted, high-bit bytes and non-ASCII UTF-8 sequences included.
const HOST_REJECT: &[u8] = b" \r\n\t/:#?!@{}[]\\$'\"^`*<>=;,+&()%";

/// `UINT_MAX`: the ceiling handed to every scanner in [`ipv4_normalize`].
///
/// `lib/urlapi.c` L500, L503 and L506 all pass `UINT_MAX` from `<limits.h>`,
/// which is 4294967295 on every platform curl supports, and the value
/// arrives here as an `i64` because that is what `curl_off_t` is and what
/// `crate::strparse` therefore takes.
///
/// This is deliberately looser than any address part can be. It bounds a
/// part to what an `unsigned int` can hold, which is what makes the cast at
/// L511 lossless, and the real per-arity limits -- `0xff`, `0xffff`,
/// `0xffffff` -- are applied afterwards by the four arms at L530-L571. The
/// consequence is observable: `https://4294967295` becomes
/// `255.255.255.255`, while `https://4294967296` overflows the scanner and
/// stays a name.
const UINT_MAX: i64 = 0xffff_ffff;

/// What a host buffer turned out to be: the `HOST_*` return values of
/// `ipv4_normalize`.
///
/// `lib/urlapi.c` L477-L481, in full:
///
/// ```c
/// #define HOST_ERROR   (-1) /* out of memory */
///
/// #define HOST_NAME    1
/// #define HOST_IPV4    2
/// #define HOST_IPV6    3
/// ```
///
/// The four values are carried explicitly, including the negative one and
/// the gap at zero, so that the correspondence is checkable; the numbers
/// themselves are never observed outside this crate, because the C function
/// is `static` and its `int` return crosses no boundary.
///
/// # The caller's `default` arm becomes impossible, and that is the point
///
/// `parse_authority` at L648-L650 ends its switch with
///
/// ```c
/// default:
///   uc = CURLUE_BAD_HOSTNAME; /* Bad IPv4 address even */
/// ```
///
/// which is unreachable in C -- the function returns nothing else -- yet
/// has to be written, because `int` admits every other value. A closed enum
/// says the same thing to the compiler instead: `src/parse/authority.rs`
/// matches these four variants and is exhaustive without a catch-all. No
/// fifth variant is invented to stand in for the C's `default`, and none
/// should be added; the arm is not lost, it is proven absent.
///
/// # Reading the variants
///
/// The names describe what the buffer is, not what to do about it, which
/// matters because two of the four are not verdicts on validity at all:
///
/// - [`HostKind::Name`] means "this is not an IPv4 address". It is what a
///   malformed number, an out-of-range part, a fifth part and an ordinary
///   host name all produce, and it is **not** an error. The caller decodes
///   and then checks the host.
/// - [`HostKind::Ipv6`] means "this begins with `[`" and nothing more. No
///   byte after the bracket has been looked at.
/// - [`HostKind::Ipv4`] means the buffer has been rewritten in place into
///   dotted-quad decimal form, and the caller is done: L635-L636 is a bare
///   `break` that leaves its `uc` at the `CURLUE_OK` it already held.
/// - [`HostKind::Error`] is the sole failure, and it means one specific
///   thing: the rewrite could not be appended. L645-L646 maps it to
///   `CURLUE_OUT_OF_MEMORY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub(crate) enum HostKind {
    /// `HOST_ERROR`, `-1`: out of memory, the C comment's own words.
    ///
    /// Produced only by a failed append at L572-L573. The buffer has
    /// already been released by then, which is contract 1 of
    /// `crate::dynbuf`, so no caller may free it again.
    Error = -1,
    /// `HOST_NAME`, `1`: not an IPv4 address, so treat it as a name.
    Name = 1,
    /// `HOST_IPV4`, `2`: an IPv4 address, now in dotted-quad decimal form.
    Ipv4 = 2,
    /// `HOST_IPV6`, `3`: begins with `[`, and nothing further is known.
    Ipv6 = 3,
}

/// The bytes a C function reading through this pointer would see: the prefix
/// up to the first NUL, or all of them if there is none.
///
/// Every C function this module ports takes a `char *` and stops at the
/// terminator -- `strcspn` at L456, `strchr` at L582, the `switch(*c)` at
/// L513 -- while this module is handed a slice whose length is the dynamic
/// buffer's own record. The two disagree exactly when the content holds an
/// interior zero byte, and the window is taken explicitly rather than
/// assumed away so that the disagreement is resolved the way C resolves it.
///
/// No call site can actually produce one. `Curl_junkscan` at L223-L246
/// refuses every byte at or below `0x20` in the input, `Curl_urldecode`
/// under `REJECT_CTRL` refuses a decoded zero at `lib/escape.c` L139, and
/// `Curl_url_set_authority` measures its argument with `strlen` at L666. So
/// this is a faithfulness measure and not a correction.
///
/// `src/parse/port.rs` has an identical private helper and `src/encode.rs`
/// an equivalent one. Neither is imported: this file's dependency whitelist
/// does not include those modules, and a helper this small is better
/// duplicated than reached for across a boundary the plan drew on purpose.
fn cstring_window(content: &[u8]) -> &[u8] {
    match content.iter().position(|&byte| byte == 0) {
        // The prefix is in bounds by construction, so the fallback is
        // unreachable; `get` is used anyway so that the bound is checked by
        // the compiler rather than argued for in a comment.
        Some(nul) => content.get(..nul).unwrap_or(content),
        None => content,
    }
}

/// `strcspn(hostname, HOST_REJECT)`: how many leading bytes are **not** in
/// the reject set.
///
/// The C's `strcspn` stops on two things, and both have to be reproduced or
/// the comparison at L457 means something else. It stops at the first byte
/// that is in the set, and it stops at the terminator, returning the string
/// length when the whole string is clean. [`cstring_window`] supplies the
/// second half and `position` the first.
///
/// # Returns
///
/// The index of the first refused byte, or the length of the C string when
/// there is none. Never larger than the window, so the caller's `hlen !=
/// span` test reads as "either a refused byte appears inside the first
/// `hlen` bytes, or the string is shorter than `hlen` claims".
fn reject_span(hostname: &[u8]) -> usize {
    let window = cstring_window(hostname);
    window
        .iter()
        .position(|byte| HOST_REJECT.contains(byte))
        .unwrap_or(window.len())
}

/// Validates a host name, or hands a bracketed one to the IPv6 parser.
///
/// `hostname_check` at `lib/urlapi.c` L444-L462, whole:
///
/// ```c
/// if(!hlen)
///   return CURLUE_NO_HOST;
/// else if(hostname[0] == '[')
///   return ipv6_parse(u, hostname, hlen);
/// else {
///   /* letters from the second string are not ok */
///   len = strcspn(hostname, " \r\n\t/:#?!@{}[]\\$\'\"^`*<>=;,+&()%");
///   if(hlen != len)
///     /* hostname with bad content */
///     return CURLUE_BAD_HOSTNAME;
/// }
/// return CURLUE_OK;
/// ```
///
/// The `DEBUGASSERT(hostname)` at L448 has no counterpart: an assertion is
/// a panic path, this crate has none, and a null slice cannot be expressed
/// in Rust at all.
///
/// # Three callers, two shapes of buffer
///
/// The signature keeps all three C arguments rather than taking a
/// [`DynBuf`], because only one of the three call sites has one:
///
/// - L643, the `HOST_NAME` arm of `parse_authority`, over the host dynamic
///   buffer, after [`urldecode_host`] has run.
/// - L1981, in the `CURLUPART_HOST` arm of `set_url_part`, over a
///   `Curl_urldecode` result and its `dlen`. That buffer is released at
///   L1983 immediately afterwards, so any rewriting done by the IPv6 branch
///   is discarded and only the verdict and the zone identifier survive.
/// - L1985, the same arm when the value was encoded there instead, over the
///   encoding buffer and its length.
///
/// # Parameters
///
/// - `u`: the handle. Untouched unless the host is bracketed, in which case
///   [`crate::parse::ipv6::ipv6_parse`] may store a zone identifier on it.
/// - `hostname`: the host bytes, writable because the IPv6 branch rewrites
///   them in place. Where the caller can supply it -- and
///   [`DynBuf::content_mut`] does -- the slice should be `hlen + 1` bytes so
///   that the terminator slot is reachable; `src/parse/ipv6.rs` documents
///   why, as `FB6`. A shorter extent still yields the same verdict.
/// - `hlen`: the length of the host, excluding any terminator. It is
///   compared against the span rather than used to bound it, which is what
///   makes a shorter `hlen` than the C string a rejection rather than a
///   truncation. That asymmetry is the C's, from L457.
///
/// # Returns
///
/// `crate::abi::CURLUE_OK` at L461, or whatever
/// [`crate::parse::ipv6::ipv6_parse`] answers for a bracketed host.
///
/// # Errors
///
/// - `crate::abi::CURLUE_NO_HOST` for an empty host, L450-L451. Note the
///   code: an empty host is "no host", not a bad one. The branch is
///   unreachable from both callers today -- `parse_authority` returns the
///   same code itself at L631-L632, before [`ipv4_normalize`] runs, and
///   `set_url_part` sets its own `bad` flag for an empty value at
///   L1972-L1973 -- and it is reproduced anyway, exactly as written.
/// - `crate::abi::CURLUE_BAD_HOSTNAME` when the span disagrees with `hlen`,
///   L457-L459.
/// - `crate::abi::CURLUE_BAD_IPV6` or `crate::abi::CURLUE_OUT_OF_MEMORY`
///   from the bracketed branch.
#[must_use = "the accept-or-reject verdict is the return value and must be handled"]
pub(crate) fn hostname_check(u: &mut CurlUrl, hostname: &mut [u8], hlen: usize) -> CURLUcode {
    // L450-L451.
    if hlen == 0 {
        return CURLUE_NO_HOST;
    }

    // L452-L453. `first` rather than an index, because the crate denies
    // direct indexing; the C reads `hostname[0]` after L450 has established
    // that there is at least one byte, and `first` needs no such argument.
    // Everything about a bracketed host belongs to the IPv6 parser: this
    // branch hands over `hostname` and `hlen` unchanged and does not look at
    // another byte, exactly as the C does.
    if hostname.first() == Some(&b'[') {
        return ipv6_parse(u, hostname, hlen);
    }

    // L455-L459. The comparison is the C's, in the C's direction: not "does
    // the host contain a refused byte" but "does the clean prefix measure
    // exactly `hlen`". Those differ when `hlen` is shorter than the C
    // string, which is a rejection here and would be an acceptance under the
    // other reading.
    if hlen != reject_span(hostname) {
        return CURLUE_BAD_HOSTNAME;
    }

    // L461.
    CURLUE_OK
}

/// A dotted address as the classification loop leaves it.
///
/// The C's two locals, `int n` at L486 and `unsigned int parts[4]` at L488,
/// carried together because neither means anything without the other: the
/// four arms at L530-L571 read a different number of parts depending on `n`,
/// and read a *different meaning* into the same parts.
struct Parts {
    /// The C's `n`: the number of `.` separators consumed, and so one less
    /// than the number of parts. Always 0, 1, 2 or 3, because L515-L516
    /// refuses a fifth part rather than incrementing past three.
    dots: usize,
    /// The C's `parts`: the scanned value of each part, in order. Slots
    /// above `dots` are the zeros L488 initializes and are never read.
    values: [u32; 4],
}

/// The classification loop: `lib/urlapi.c` L494-L528.
///
/// ```c
/// while(!done) {
///   int rc;
///   curl_off_t l;
///   if(*c == '0') {
///     if(c[1] == 'x') {
///       c += 2; /* skip the prefix */
///       rc = curlx_str_hex(&c, &l, UINT_MAX);
///     }
///     else
///       rc = curlx_str_octal(&c, &l, UINT_MAX);
///   }
///   else
///     rc = curlx_str_number(&c, &l, UINT_MAX);
///
///   if(rc)
///     return HOST_NAME;
///
///   parts[n] = (unsigned int)l;
///
///   switch(*c) {
///   case '.':
///     if(n == 3)
///       return HOST_NAME;
///     n++;
///     c++;
///     break;
///
///   case '\0':
///     done = TRUE;
///     break;
///
///   default:
///     return HOST_NAME;
///   }
/// }
/// ```
///
/// # The base is chosen per part, from that part's own first byte
///
/// Not once for the whole address, which is the mistake to avoid: every
/// iteration re-reads `*c` and re-decides. A leading `0` followed by a
/// lowercase `x` means hexadecimal with the two prefix bytes consumed
/// first; a leading `0` on its own means **octal**; anything else is
/// decimal. Mixed bases in one address are therefore perfectly legal, and
/// `https://0111.02.0x3` really does become `73.2.0.3`.
///
/// Two consequences of that spelling are easy to get wrong and both were
/// measured against the reference build. The prefix test is
/// case-sensitive, so `https://0X7f` is not hexadecimal: the octal scanner
/// reads the leading `0`, stops on the `X`, and the `default` arm below
/// makes it a name. And a leading zero is enough to make a part octal, so
/// `https://010` is `0.0.0.8` while `https://08` is a name, `8` not being
/// an octal digit.
///
/// # A refusal here is never an error
///
/// Every `return HOST_NAME` above says "this is not an IPv4 address", and
/// the caller's response is to decode and check the host as a name rather
/// than to report anything. That is why this function reports absence with
/// `None` instead of a code, and why the only failure [`ipv4_normalize`] can
/// produce is the append at the very end.
///
/// # Returns
///
/// `Some` with the parts and the separator count, which is the C reaching
/// L528 with `done` set. `None` for every `return HOST_NAME` above: a byte
/// the chosen scanner would not accept, a value above [`UINT_MAX`], a fifth
/// dotted part, or any byte other than `.` where a separator or the
/// terminator belongs.
fn classify(hostname: &[u8]) -> Option<Parts> {
    // `c = curlx_dyn_ptr(host)` at L487, as a cursor the scanners advance.
    let mut cursor = hostname;
    // `int n = 0` at L486.
    let mut dots: usize = 0;
    // `unsigned int parts[4] = { 0, 0, 0, 0 }` at L488.
    let mut values = [0_u32; 4];

    // `bool done = FALSE` at L485 with the `while(!done)` at L494. The exits
    // are all explicit returns below, so the flag itself is not needed.
    loop {
        // L497-L506. `first` and `get` rather than `*c` and `c[1]`: the C
        // may read `c[1]` because a C string always has a terminator to
        // read, and here the same lookahead is expressed as a question that
        // has an answer at the end of the slice too.
        let scanned = if cursor.first() == Some(&b'0') {
            if cursor.get(1) == Some(&b'x') {
                // L499: `c += 2`, the prefix consumed before the scan. An
                // empty remainder is exactly what `"0x"` alone produces, and
                // the hexadecimal scanner then reports no number, which is
                // the C's behavior: `https://0x` stays a name.
                cursor = cursor.get(2..).unwrap_or(&[]);
                str_hex(&mut cursor, UINT_MAX)
            } else {
                // L503. Octal, not decimal, and no prefix to skip: the
                // leading zero is a digit the scanner reads.
                str_octal(&mut cursor, UINT_MAX)
            }
        } else {
            // L506.
            str_number(&mut cursor, UINT_MAX)
        };

        // L508-L509. Both scanner failures collapse here, as they do in the
        // C, whose `rc` is any non-zero code: no number at all, and a number
        // above the ceiling. `crate::strparse` leaves the cursor untouched on
        // either, which does not matter to this loop because it never looks
        // at the cursor again.
        let value = match scanned {
            Ok(value) => value,
            Err(_) => return None,
        };

        // L511: `parts[n] = (unsigned int)l`.
        //
        // The conversion cannot lose information: every scanner above was
        // given UINT_MAX as its ceiling, so the value is between 0 and
        // 0xffffffff and fits a u32 exactly, which is what makes the C's
        // bare cast safe there. It is written as a checked conversion
        // regardless, because the crate has no panicking constructs and
        // because `as` would bury that reasoning instead of stating it.
        //
        // The `?` cannot fire: `dots` starts at zero and the separator arm
        // below refuses a fifth part rather than incrementing past three, so
        // the index is always inside the four slots. The C indexes
        // `parts[n]` unconditionally and would have undefined behavior on an
        // out-of-range `n`; answering "not an address" is the only defined
        // alternative available here, and it changes nothing observable
        // because the bound cannot be exceeded.
        let slot = values.get_mut(dots)?;
        *slot = u32::try_from(value).unwrap_or(u32::MAX);

        // L513-L527.
        match cursor.first() {
            // L514-L519. The order matters: the fifth part is refused
            // *before* the counter moves, so `dots` never leaves 0..=3.
            Some(&b'.') => {
                if dots == 3 {
                    return None;
                }
                // `saturating_add` because the crate denies arithmetic that
                // could wrap. Exact here: the test above caps `dots` at 3.
                dots = dots.saturating_add(1);
                // L518: `c++`, over the separator.
                cursor = cursor.get(1..).unwrap_or(&[]);
            }
            // L521-L523: `case '\0': done = TRUE;`. The end of the slice is
            // the same stopping condition as the terminator and is folded in
            // with it, so a caller that hands over the content without its
            // terminator gets the same answer as one that includes it.
            Some(&0) | None => return Some(Parts { dots, values }),
            // L525-L526: `default: return HOST_NAME`. Anything that is
            // neither a separator nor the end -- the `X` of `0X7f`, the `8`
            // the octal scanner stopped on in `08`, a letter, a `%` -- means
            // this was never an address.
            Some(_) => return None,
        }
    }
}

/// Classifies a host buffer and, when it is a partial or alternate-base
/// IPv4 address, rewrites it in place as dotted-quad decimal.
///
/// `ipv4_normalize` at `lib/urlapi.c` L483-L575. Its own comment at
/// L464-L475 states the purpose and supplies the four worked examples that
/// the unit tests below reuse verbatim:
///
/// ```text
/// Handle partial IPv4 numerical addresses and different bases, like
/// '16843009', '0x7f', '0x7f.1' '0177.1.1.1' etc.
///
/// If the given input string is syntactically wrong IPv4 or any part for
/// example is too big, this function returns HOST_NAME.
///
/// Output the "normalized" version of that input string in plain quad
/// decimal integers.
/// ```
///
/// # The four arities, and why the first needs no range check
///
/// A dotted address may have one, two, three or four parts, and the parts
/// mean different widths in each case. The table is the C's four `switch`
/// arms at L530-L571, unchanged:
///
/// | `dots` | Shape | Range requirement | Emitted quad |
/// |---|---|---|---|
/// | 0 | `a` -- 32 bits | **none** | `a>>24`, `(a>>16)&0xff`, `(a>>8)&0xff`, `a&0xff` |
/// | 1 | `a.b` -- 8 + 24 bits | `a <= 0xff`, `b <= 0xffffff` | `a`, `(b>>16)&0xff`, `(b>>8)&0xff`, `b&0xff` |
/// | 2 | `a.b.c` -- 8 + 8 + 16 bits | `a <= 0xff`, `b <= 0xff`, `c <= 0xffff` | `a`, `b`, `(c>>8)&0xff`, `c&0xff` |
/// | 3 | `a.b.c.d` -- 8 each | all four `<= 0xff` | `a`, `b`, `c`, `d` |
///
/// The first arm has no range test and needs none: a single part is a whole
/// 32-bit address by construction, already bounded by [`UINT_MAX`] in the
/// scanner, so every value splits into four bytes. That is why
/// `https://16843009` becomes `1.1.1.1` while `https://1.16777216` -- one
/// too many for a 24-bit second part -- stays a name.
///
/// # A rejected address is left exactly as it was
///
/// Each arm resets the buffer only *after* its range test has passed, so a
/// part that is out of range returns [`HostKind::Name`] with the host bytes
/// untouched. This is behavior, not tidiness: `https://1.2.3.256` really
/// does resolve as the host name `1.2.3.256`, which `lib1560.c` L672
/// asserts, and it could not if the buffer had already been cleared. The
/// reset therefore stays below the test in every arm.
///
/// # Parameters
///
/// - `host`: the host buffer. Read through
///   [`DynBuf::as_bytes_with_nul`] for the classification, then reset and
///   refilled on the [`HostKind::Ipv4`] path alone. An unallocated buffer
///   yields an empty slice and so answers [`HostKind::Name`]; the C would
///   dereference `curlx_dyn_ptr`'s null there, and cannot reach it, because
///   `parse_authority` returns `CURLUE_NO_HOST` at L631-L632 first.
///
/// # Returns
///
/// One of the four [`HostKind`] values; see that type for what each one
/// obliges the caller to do next. [`HostKind::Error`] is the only failure
/// and comes from one place, the append at L534, L544, L554 or L565. A
/// failed append has **already released the buffer**, which is contract 1 of
/// `crate::dynbuf` and the reason the C's L572-L573 returns without a free.
#[must_use = "the host classification decides the caller's next stage and must be handled"]
pub(crate) fn ipv4_normalize(host: &mut DynBuf) -> HostKind {
    // The borrow of `host` is confined to this block so that the rewrite
    // below can take it mutably. The C has the same two phases and does not
    // have to say so, because `c` and `parts` are a pointer and an array of
    // values rather than two borrows of one buffer.
    let parts = {
        // L487: `const char *c = curlx_dyn_ptr(host)`. The terminator is
        // included, because the loop's `case '\0'` is one of its two exits.
        let hostname = host.as_bytes_with_nul();

        // L491-L492: a leading bracket is answered without validating one
        // further byte. Every check on a bracketed host, the zone identifier
        // included, belongs to `src/parse/ipv6.rs`, which the caller reaches
        // through the `HOST_IPV6` arm at L637-L639.
        if hostname.first() == Some(&b'[') {
            return HostKind::Ipv6;
        }

        // L494-L528.
        match classify(hostname) {
            Some(parts) => parts,
            None => return HostKind::Name,
        }
    };

    // Destructured rather than indexed, which the crate's denial of direct
    // indexing requires and which also lets the arms below read like the C's
    // `a.b.c.d` comments.
    let Parts { dots, values } = parts;
    let [a, b, c, d] = values;

    // L530-L571. Each arm tests its ranges and then computes the quad; the
    // shifts are `wrapping_shr` because the crate denies arithmetic that
    // could panic, and every shift distance here is a constant below 32, so
    // the wrapping never happens. The masks are bitwise and cannot fail at
    // all.
    let quad: [u32; 4] = match dots {
        // L531-L539: a -- 32 bits, no range test. The top byte needs no mask
        // because a right shift of 24 leaves nothing above it, and the C
        // omits it there for the same reason.
        0 => [
            a.wrapping_shr(24),
            a.wrapping_shr(16) & 0xff,
            a.wrapping_shr(8) & 0xff,
            a & 0xff,
        ],
        // L540-L549: a.b -- 8.24 bits.
        1 => {
            if a > 0xff || b > 0x00ff_ffff {
                return HostKind::Name;
            }
            [
                a,
                b.wrapping_shr(16) & 0xff,
                b.wrapping_shr(8) & 0xff,
                b & 0xff,
            ]
        }
        // L550-L559: a.b.c -- 8.8.16 bits.
        2 => {
            if a > 0xff || b > 0xff || c > 0xffff {
                return HostKind::Name;
            }
            [a, b, c.wrapping_shr(8) & 0xff, c & 0xff]
        }
        // L560-L570: a.b.c.d -- 8.8.8.8 bits.
        3 => {
            if a > 0xff || b > 0xff || c > 0xff || d > 0xff {
                return HostKind::Name;
            }
            [a, b, c, d]
        }
        // Unreachable, and reproducing the C rather than inventing an answer.
        // `classify` caps `dots` at 3, so no fifth arm can be entered. The
        // C's `switch(n)` has no `default`, so a value above three would skip
        // every case, leave `result` at the `CURLE_OK` of L489 and fall
        // through to L574 returning HOST_IPV4 with the buffer unmodified --
        // which is exactly what this arm does.
        _ => return HostKind::Ipv4,
    };

    let [q0, q1, q2, q3] = quad;

    // L532, L543, L553 or L564: `curlx_dyn_reset(host)`, below the range test
    // and above the append in every arm. The allocation survives a reset, and
    // a quad is at most fifteen bytes -- "255.255.255.255" -- against a first
    // allocation of at least thirty-two at `lib/curlx/dynbuf.c` L29, so the
    // refill fits what the buffer already holds even where it is longer than
    // the text it replaces, as `0` becoming `0.0.0.0` is.
    host.reset();

    // L534, L544, L554 or L565: `curlx_dyn_addf(host, "%u.%u.%u.%u", ...)`.
    // Rust's `Display` for `u32` emits the same digits as C's `%u` for every
    // value, so the bytes are identical. The four examples from the C comment
    // and the whole oracle table in the tests below pin that against the
    // reference build rather than against this comment.
    let appended = host.addf(format_args!("{q0}.{q1}.{q2}.{q3}"));
    if appended.is_err() {
        // L572-L573. The append has already released the buffer, so there is
        // deliberately no free here, exactly as in the C. The caller maps
        // this to `CURLUE_OUT_OF_MEMORY` at L645-L646, which loses the
        // distinction between a ceiling breach and a failed allocation -- the
        // C loses it too, by folding both into one `HOST_ERROR`.
        return HostKind::Error;
    }

    // L574.
    HostKind::Ipv4
}

/// Replaces the host with its percent-decoded form, if it has one.
///
/// `urldecode_host` at `lib/urlapi.c` L577-L602, whose own comment is "if
/// necessary, replace the host content with a URL decoded version":
///
/// ```c
/// per = strchr(hostname, '%');
/// if(!per)
///   /* nothing to decode */
///   return CURLUE_OK;
/// else {
///   /* encoded */
///   size_t dlen;
///   char *decoded;
///   CURLcode result = Curl_urldecode(hostname, 0, &decoded, &dlen,
///                                    REJECT_CTRL);
///   if(result)
///     return CURLUE_BAD_HOSTNAME;
///   curlx_dyn_reset(host);
///   result = curlx_dyn_addn(host, decoded, dlen);
///   curlx_free(decoded);
///   if(result)
///     return cc2cu(result);
/// }
/// return CURLUE_OK;
/// ```
///
/// # The two failure codes come from different places, and swapping them
/// would be visible
///
/// A failed *decode* becomes `CURLUE_BAD_HOSTNAME` and the underlying
/// `CURLcode` is thrown away. That is the C at L592-L593, and it is not a
/// slip worth correcting: it means a genuine out-of-memory inside
/// `Curl_urldecode` is reported as a bad host name. Only the *append*
/// failure at L597-L598 goes through `cc2cu`, which is where
/// `CURLUE_TOO_LARGE` and `CURLUE_OUT_OF_MEMORY` can still be told apart.
/// Route the decode failure through `cc2cu` instead and `https://%41%0D`
/// starts answering 7 where the oracle says 21.
///
/// # What counts as a failed decode is narrower than it looks
///
/// `Curl_urldecode` refuses a *decoded* byte below `0x20` and nothing else,
/// `lib/escape.c` L139. A malformed escape is not a failure at all: L126
/// requires three bytes and two hexadecimal digits, and otherwise emits the
/// `%` literally, L134-L137. So `https://%4` and `https://test%test` both
/// decode successfully, to `%4` and `test%test`, and both are still rejected
/// -- by [`hostname_check`] afterwards, because `%` is in [`HOST_REJECT`].
/// The `CURLUE_BAD_HOSTNAME` the oracle reports for them therefore comes
/// from the *next* stage, and `tests::the_pipeline_reproduces_the_reference`
/// checks both halves rather than assuming either.
///
/// # Parameters
///
/// - `host`: the host buffer, replaced with the decoded bytes when it holds
///   a `%` and left byte-identical when it does not. The decode reads
///   through [`DynBuf::as_bytes_with_nul`] and passes the length `0` that
///   `lib/escape.c` L115 documents as "measure it with `strlen`", so an
///   interior zero byte bounds the window the same way it bounds the C's.
///
/// # Returns
///
/// `crate::abi::CURLUE_OK`, either because there was nothing to decode,
/// L583-L585, or because the replacement succeeded, L601.
///
/// # Errors
///
/// - `crate::abi::CURLUE_BAD_HOSTNAME` when the decode refuses a byte or
///   cannot allocate, L592-L593.
/// - `crate::abi::CURLUE_TOO_LARGE` or `crate::abi::CURLUE_OUT_OF_MEMORY`
///   from `crate::error::cc2cu` when the append fails, L597-L598. The buffer
///   has already been released in that case, contract 1 of `crate::dynbuf`,
///   which is why the C adds no free of its own.
///
/// That second error cannot actually be produced by a ceiling breach, and
/// the reasoning is worth recording so that nobody spends time trying to
/// test it: decoding never lengthens content, and the reset keeps the
/// allocation that already held the longer encoded form, so the append
/// neither exceeds the ceiling the first append satisfied nor needs to
/// reallocate at all. Only a failing allocator could reach it -- and in
/// `ipv4_normalize` the equivalent branch *is* reachable, because a quad may
/// be longer than the text it replaces. The branch is kept because the C
/// keeps it.
#[must_use = "the decode verdict is the return value and must be handled"]
pub(crate) fn urldecode_host(host: &mut DynBuf) -> CURLUcode {
    // As in `ipv4_normalize`, the read of the buffer is confined to a block
    // so that the write below can borrow it mutably. The decoded bytes live
    // in their own allocation, so nothing borrowed leaves this scope.
    let decoded = {
        // L581: `const char *hostname = curlx_dyn_ptr(host)`.
        let hostname = host.as_bytes_with_nul();

        // L582-L585: `strchr(hostname, '%')`, and the fast path that leaves
        // an unencoded host completely alone -- not reset, not reappended,
        // not reallocated. `cstring_window` is what makes this `strchr` and
        // not a search of the whole slice.
        if !cstring_window(hostname).contains(&b'%') {
            return CURLUE_OK;
        }

        // L590-L591. The literal `0` is the length overload: `lib/escape.c`
        // L115 computes `alloc = length ? length : strlen(string)`, so zero
        // means "measure the string". `REJECT_CTRL` is the mode all three URL
        // API call sites pass; it is rejection set B in the module
        // documentation and is narrower than this module's own set C.
        match urldecode(hostname, 0, UrlReject::Ctrl) {
            Ok(decoded) => decoded,
            // L592-L593: the `CURLcode` is deliberately discarded. See the
            // note above; this is not `cc2cu`.
            Err(_) => return CURLUE_BAD_HOSTNAME,
        }
    };

    // L594: reset first, so the append starts at offset zero in the
    // allocation the buffer already has.
    host.reset();

    // L595. `decoded.as_bytes()` is `decoded` with `dlen`: the C passes the
    // pointer and the decoded length separately, and `crate::alloc::CBuf`
    // keeps them together, so the two arguments become one.
    let appended = host.addn(decoded.as_bytes());

    // L596: `curlx_free(decoded)`, before the result is inspected and
    // unconditionally, whether the append succeeded or not. Dropping the
    // buffer here rather than at the end of the function is what puts the
    // release in the C's position; `crate::alloc::CBuf`'s `Drop` is the
    // free.
    drop(decoded);

    // L597-L598.
    if appended.is_err() {
        return cc2cu(appended);
    }

    // L601.
    CURLUE_OK
}

#[cfg(test)]
mod tests {
    // The crate root denies the panicking constructs so that no panic can
    // ever reach the C boundary. A test's entire job is to panic when an
    // assertion fails, and a test never crosses that boundary, so the
    // denials are relaxed here and only here. The allowance is scoped to
    // this module and enumerated rather than blanket, matching
    // `src/parse/ipv6.rs` and `src/dynbuf.rs`.
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::arithmetic_side_effects)]

    // The buffers these tests build need the heap, and they reach it through
    // the `alloc` crate rather than through `std`, so that this module
    // compiles the same way whichever the crate root turns out to declare.
    extern crate alloc;

    // Imported by name rather than through a glob, as everywhere else in the
    // crate, so each use site names its source.
    use super::{classify, cstring_window, hostname_check, ipv4_normalize, ipv6_parse};
    use super::{reject_span, urldecode_host, HostKind, HOST_REJECT, UINT_MAX};
    use crate::abi::{
        CURLUcode, CURLUE_BAD_HOSTNAME, CURLUE_BAD_IPV6, CURLUE_NO_HOST, CURLUE_OK,
        CURLUE_OUT_OF_MEMORY, CURL_MAX_INPUT_LENGTH,
    };
    use crate::dynbuf::DynBuf;
    use crate::handle::CurlUrl;
    use alloc::string::String;
    use alloc::vec::Vec;

    /// The thirty-one bytes of `lib/urlapi.c` L456, spelled a second way.
    ///
    /// [`HOST_REJECT`] is the C string literal transcribed; this is the same
    /// set written out one byte at a time, with the four invisible ones
    /// named. Two independent spellings compared against each other is the
    /// point: a single transcription can be wrong in a way no test would
    /// notice, and this file may not contain a literal tab or carriage
    /// return, so neither spelling can be checked by eye against the C.
    ///
    /// `clippy::byte_char_slices` would have this written as a byte string,
    /// which is precisely what [`HOST_REJECT`] already is. Collapsing the
    /// two spellings into one would delete the check rather than tidy it, so
    /// the lint is allowed here with that reason.
    #[allow(clippy::byte_char_slices)]
    const REJECT_ONE_BY_ONE: [u8; 31] = [
        b' ', b'\r', b'\n', b'\t', b'/', b':', b'#', b'?', b'!', b'@', b'{', b'}', b'[', b']',
        b'\\', b'$', b'\'', b'"', b'^', b'`', b'*', b'<', b'>', b'=', b';', b',', b'+', b'&', b'(',
        b')', b'%',
    ];

    /// A host buffer holding `content`, built the way `parse_authority` does
    /// at L621: one append into a buffer whose ceiling is the input limit.
    fn buffer(content: &[u8]) -> DynBuf {
        let mut host = DynBuf::new(CURL_MAX_INPUT_LENGTH);
        assert!(
            host.addn(content).is_ok(),
            "the test buffer could not be filled"
        );
        host
    }

    /// The host as a C caller reads it: the bytes up to the first
    /// terminator.
    ///
    /// Not [`DynBuf::as_bytes`], deliberately. `ipv6_parse` rewrites the
    /// buffer behind its back and never calls `curlx_dyn_setlen`, so the
    /// logical length can be stale by design; what the C then hands on is
    /// the pointer, and the string ends at the first zero byte.
    fn cstring_of(host: &DynBuf) -> Vec<u8> {
        let bytes = host.as_bytes_with_nul();
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        bytes[..end].to_vec()
    }

    /// Readable form of a host for an assertion message.
    fn shown(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    /// [`ipv4_normalize`] over a buffer holding `host`, with the verdict and
    /// the resulting bytes.
    fn normalize(host: &[u8]) -> (HostKind, Vec<u8>) {
        let mut buf = buffer(host);
        let kind = ipv4_normalize(&mut buf);
        (kind, cstring_of(&buf))
    }

    /// [`hostname_check`] over a buffer holding `host`, with `hlen` taken
    /// from the buffer as both callers take it.
    ///
    /// The mutable view is [`DynBuf::content_mut`], which is `hlen + 1`
    /// bytes: the extent `src/parse/ipv6.rs` documents as its entry
    /// contract, and the one the C's dynamic buffer always provides.
    fn check(host: &[u8]) -> CURLUcode {
        let mut u = CurlUrl::new();
        let mut buf = buffer(host);
        let hlen = buf.len();
        let mut view = buf.content_mut();
        hostname_check(&mut u, &mut view, hlen)
    }

    /// [`hostname_check`] with an `hlen` the caller invented, which is how
    /// the faithful `strcspn` comparison is exercised.
    fn check_with_hlen(host: &[u8], hlen: usize) -> CURLUcode {
        let mut u = CurlUrl::new();
        let mut buf = buffer(host);
        let mut view = buf.content_mut();
        hostname_check(&mut u, &mut view, hlen)
    }

    /// [`hostname_check`] with the rewritten host and any zone identifier,
    /// for the bracketed cases the IPv6 parser handles.
    fn check_full(host: &[u8]) -> (CURLUcode, Vec<u8>, Option<Vec<u8>>) {
        let mut u = CurlUrl::new();
        let mut buf = buffer(host);
        let hlen = buf.len();
        let code = {
            let mut view = buf.content_mut();
            hostname_check(&mut u, &mut view, hlen)
        };
        (code, cstring_of(&buf), u.zoneid().map(<[u8]>::to_vec))
    }

    /// [`urldecode_host`] over a buffer holding `host`, with the verdict and
    /// the resulting bytes.
    fn decode_host(host: &[u8]) -> (CURLUcode, Vec<u8>) {
        let mut buf = buffer(host);
        let code = urldecode_host(&mut buf);
        (code, cstring_of(&buf))
    }

    /// The whole host stage of `parse_authority`, L634-L651, as the C writes
    /// it.
    ///
    /// This is the switch the three ported functions exist to serve, and it
    /// lives here rather than in the implementation because
    /// `src/parse/authority.rs` owns it. Reproducing it in the tests is what
    /// lets a vector captured from the reference build -- where only the
    /// whole pipeline is observable -- be compared against this port at all.
    /// The `default` arm of the C has no counterpart, which is
    /// [`HostKind`]'s own documentation.
    fn pipeline(host: &[u8]) -> (CURLUcode, Vec<u8>) {
        let mut u = CurlUrl::new();
        let mut buf = buffer(host);
        let mut code = CURLUE_OK;
        match ipv4_normalize(&mut buf) {
            // L635-L636: a bare break, leaving `uc` at CURLUE_OK.
            HostKind::Ipv4 => {}
            // L637-L639.
            HostKind::Ipv6 => {
                let hlen = buf.len();
                let mut view = buf.content_mut();
                code = ipv6_parse(&mut u, &mut view, hlen);
            }
            // L640-L644.
            HostKind::Name => {
                code = urldecode_host(&mut buf);
                if code == CURLUE_OK {
                    let hlen = buf.len();
                    let mut view = buf.content_mut();
                    code = hostname_check(&mut u, &mut view, hlen);
                }
            }
            // L645-L646.
            HostKind::Error => code = CURLUE_OUT_OF_MEMORY,
        }
        (code, cstring_of(&buf))
    }

    /// Hosts the reference build accepts, with the host text it produces.
    ///
    /// Every row was captured from a C program linked against an unmodified
    /// libcurl archive under `LC_ALL=C.UTF-8`, by calling
    /// `curl_url_set(u, CURLUPART_URL, "https://<row>/", 0)` and then
    /// `curl_url_get(u, CURLUPART_HOST, .., 0)`. None of it was derived by
    /// reading this port, which is the whole value of the table.
    const PIPELINE_ACCEPTS: [(&[u8], &[u8]); 41] = [
        // The four examples from the C comment at L466.
        (b"16843009", b"1.1.1.1"),
        (b"0x7f", b"0.0.0.127"),
        (b"0x7f.1", b"127.0.0.1"),
        (b"0177.1.1.1", b"127.1.1.1"),
        // Already-canonical quads pass through untouched.
        (b"1.2.3.4", b"1.2.3.4"),
        (b"0.0.0.0", b"0.0.0.0"),
        (b"255.255.255.255", b"255.255.255.255"),
        // Arity one: a single 32-bit value, no range test.
        (b"0", b"0.0.0.0"),
        (b"0x0", b"0.0.0.0"),
        (b"010", b"0.0.0.8"),
        (b"0xffffffff", b"255.255.255.255"),
        (b"4294967295", b"255.255.255.255"),
        // Arity two, at and below the 24-bit bound.
        (b"1.16777215", b"1.255.255.255"),
        (b"1.0xffffff", b"1.255.255.255"),
        (b"0.0x0", b"0.0.0.0"),
        (b"192.0x0000A80001", b"192.168.0.1"),
        (b"0177.1", b"127.0.0.1"),
        // Arity three, at and below the 16-bit bound.
        (b"1.1.65535", b"1.1.255.255"),
        (b"0111.02.0x3", b"73.2.0.3"),
        (b"0111.02.030", b"73.2.0.24"),
        // Arity four, mixed bases.
        (b"0xff.0xff.0377.255", b"255.255.255.255"),
        (b"1.2.3.04", b"1.2.3.4"),
        // Not addresses, and so names, left exactly as they arrived.
        (b"example.com", b"example.com"),
        (b"1.2.3.4.5", b"1.2.3.4.5"),
        (b"256.1.1.1", b"256.1.1.1"),
        (b"1.16777216", b"1.16777216"),
        (b"1.1.65536", b"1.1.65536"),
        (b"1.0x1000000", b"1.0x1000000"),
        (b"0X7f", b"0X7f"),
        (b"08", b"08"),
        (b"0x", b"0x"),
        (b"4294967296", b"4294967296"),
        (b"999999999999999999999999", b"999999999999999999999999"),
        (b"0111.02.0x3.", b"0111.02.0x3."),
        (b"1.2.3.256", b"1.2.3.256"),
        (b"1.2.3.256.", b"1.2.3.256."),
        // Decoding, and the fact that it happens after normalization: the
        // decoded text is never re-classified, so none of these three
        // becomes a quad even though all three look like one afterwards.
        (b"ex%61mple.com", b"example.com"),
        (b"1%2e2%2e3%2e4", b"1.2.3.4"),
        (b"0%787f", b"0x7f"),
        (b"%30177.1.1.1", b"0177.1.1.1"),
        // A decoded bracketed host really does reach the IPv6 parser.
        (b"%5b%3a%3a%31%5d", b"[::1]"),
    ];

    /// Hosts the reference build rejects, with the code it reports.
    ///
    /// Captured the same way as [`PIPELINE_ACCEPTS`]. The host text is not
    /// recorded because it is not observable: `parse_authority` builds into
    /// a temporary the caller discards whole at L1188-L1191.
    const PIPELINE_REJECTS: [(&[u8], CURLUcode); 13] = [
        // Set B, inside the decoder: a decoded byte below 0x20.
        (b"%41%0D", CURLUE_BAD_HOSTNAME),
        (b"16843009%00", CURLUE_BAD_HOSTNAME),
        // Set C, after the decoder. The first two decode successfully and
        // are refused for the byte the decode produced; the last two decode
        // to a literal '%' because the escape is malformed.
        (b"%20", CURLUE_BAD_HOSTNAME),
        (b"exa%2fmple.com", CURLUE_BAD_HOSTNAME),
        (b"%25", CURLUE_BAD_HOSTNAME),
        (b"%2520", CURLUE_BAD_HOSTNAME),
        (b"%4", CURLUE_BAD_HOSTNAME),
        (b"test%test", CURLUE_BAD_HOSTNAME),
        (b"%", CURLUE_BAD_HOSTNAME),
        // Set C on undecoded input: lib1560.c L259-L278 walks the whole
        // punctuation half of the set this way.
        (b"exam{}[]ple.net", CURLUE_BAD_HOSTNAME),
        // Delegated, and refused by the IPv6 parser rather than by anything
        // here. The last row is the one byte of set C that is dispatched
        // before the span is measured: a host that begins with `[` reaches
        // L452 first, so it answers 22 where the other thirty answer 21.
        (b"%5b%3a%3a%31", CURLUE_BAD_IPV6),
        (b"%5bnonsense%5d", CURLUE_BAD_IPV6),
        (b"%5bexample.net", CURLUE_BAD_IPV6),
    ];

    /// [`HOST_REJECT`] and [`REJECT_ONE_BY_ONE`] are the same thirty-one
    /// bytes in the same order.
    ///
    /// Order is asserted as well as membership, because `HOST_REJECT` is a
    /// transcription of a C string literal and the cheapest way to keep it
    /// honest is to compare it against a spelling that cannot be confused
    /// with it.
    #[test]
    fn the_reject_set_is_the_c_string_literal() {
        assert_eq!(HOST_REJECT.len(), 31, "lib/urlapi.c L456 has 31 bytes");
        assert_eq!(HOST_REJECT, &REJECT_ONE_BY_ONE[..]);
        // The four invisible ones, named, in the C's order.
        assert_eq!(&HOST_REJECT[..4], &[0x20, 0x0d, 0x0a, 0x09]);
        // And the one the stage order depends on, at the far end.
        assert_eq!(HOST_REJECT.last(), Some(&b'%'));
    }

    /// No byte appears twice, and the set is exactly thirty-one of the two
    /// hundred and fifty-six.
    #[test]
    fn the_reject_set_has_no_duplicates() {
        let mut seen = [false; 256];
        let mut count = 0;
        for &byte in HOST_REJECT {
            let slot = &mut seen[usize::from(byte)];
            assert!(!*slot, "byte {byte:#04x} appears twice");
            *slot = true;
            count += 1;
        }
        assert_eq!(count, 31);
    }

    /// [`reject_span`] is `strcspn`: it stops at the first refused byte and
    /// at the terminator, and reports the length when neither occurs.
    #[test]
    fn the_span_helper_is_strcspn() {
        assert_eq!(reject_span(b"example.com\0"), 11);
        assert_eq!(reject_span(b"example.com"), 11);
        assert_eq!(reject_span(b"exa/mple\0"), 3);
        assert_eq!(reject_span(b"/exa\0"), 0);
        assert_eq!(reject_span(b"\0"), 0);
        assert_eq!(reject_span(b""), 0);
        // The terminator wins over a refused byte behind it, which is what
        // makes this strcspn rather than a search of the whole slice.
        assert_eq!(reject_span(b"exa\0/mple\0"), 3);
    }

    /// [`cstring_window`] is the prefix a C function would read.
    #[test]
    fn the_cstring_window_stops_at_the_terminator() {
        assert_eq!(cstring_window(b"host\0"), b"host");
        assert_eq!(cstring_window(b"host"), b"host");
        assert_eq!(cstring_window(b"ho\0st\0"), b"ho");
        assert_eq!(cstring_window(b"\0"), b"");
        assert_eq!(cstring_window(b""), b"");
    }

    /// An empty host is `CURLUE_NO_HOST`, not `CURLUE_BAD_HOSTNAME`.
    ///
    /// L450-L451. The branch is unreachable from both C callers, which is
    /// recorded on [`hostname_check`]; it is reproduced and tested anyway,
    /// because a future caller reaching it must get the code the C would
    /// have given.
    #[test]
    fn an_empty_host_is_no_host_not_a_bad_one() {
        assert_eq!(check_with_hlen(b"", 0), CURLUE_NO_HOST);
        // The length decides, not the content: a non-empty buffer with a
        // zero length takes the same branch, since the C only reads `hlen`.
        assert_eq!(check_with_hlen(b"example.com", 0), CURLUE_NO_HOST);
    }

    /// An ordinary host name is accepted.
    #[test]
    fn a_plain_name_is_accepted() {
        assert_eq!(check(b"example.com"), CURLUE_OK);
        assert_eq!(check(b"a"), CURLUE_OK);
        assert_eq!(check(b"127.0.0.1"), CURLUE_OK);
        assert_eq!(check(b"-._~"), CURLUE_OK);
        assert_eq!(check(b"a_b"), CURLUE_OK);
        assert_eq!(check(b"a|b"), CURLUE_OK);
    }

    /// Each of the thirty-one refused bytes is refused on its own.
    ///
    /// Driven from [`HOST_REJECT`] itself rather than from a second list, so
    /// that the test cannot drift away from the implementation, and shaped
    /// like the vectors at `tests/libtest/lib1560.c` L259-L278, which walk
    /// the printable half of the same set through the public API.
    #[test]
    fn every_rejected_byte_is_refused() {
        for &byte in HOST_REJECT {
            let mut host = Vec::from(&b"exam"[..]);
            host.push(byte);
            host.extend_from_slice(b"ple.net");
            assert_eq!(
                check(&host),
                CURLUE_BAD_HOSTNAME,
                "byte {byte:#04x} should be refused"
            );
            // And in first position, where the span is zero rather than
            // four, so that both sides of the `hlen != len` comparison are
            // exercised.
            //
            // One byte of the thirty-one is dispatched before the span is
            // ever measured, and that is not an exception to the set: L452
            // tests for `[` above the `strcspn` at L456, so a host that
            // *begins* with a bracket goes to the IPv6 parser and is refused
            // by it with `CURLUE_BAD_IPV6` instead. Measured through the
            // public API: `https://%5bexample.net/` reports 22, not 21. A
            // bracket anywhere else, as in the first assertion above, is
            // refused by the span like the other thirty.
            let expected = if byte == b'[' {
                CURLUE_BAD_IPV6
            } else {
                CURLUE_BAD_HOSTNAME
            };
            let mut leading = Vec::from(&[byte][..]);
            leading.extend_from_slice(b"example.net");
            assert_eq!(
                check(&leading),
                expected,
                "leading byte {byte:#04x} should be refused"
            );
        }
    }

    /// Every byte outside the set is accepted, the high-bit ones included.
    ///
    /// This is the other half of the deny list and the reason the set can be
    /// checked exhaustively: two hundred and twenty-four bytes must pass.
    /// The zero byte is excluded because it is a terminator rather than
    /// content -- `the_span_helper_is_strcspn` covers what it does instead.
    #[test]
    fn a_byte_outside_the_set_is_accepted() {
        for byte in 1..=u8::MAX {
            if HOST_REJECT.contains(&byte) {
                continue;
            }
            let mut host = Vec::from(&b"exam"[..]);
            host.push(byte);
            host.extend_from_slice(b"ple.net");
            assert_eq!(
                check(&host),
                CURLUE_OK,
                "byte {byte:#04x} should be accepted"
            );
        }
    }

    /// Delete and the high-bit bytes reach a host name intact.
    ///
    /// `0x7f` is refused by set A before parsing and accepted by both set B
    /// and set C, so the only way it can appear in a host is through an
    /// escape -- and then it is kept. Measured: `https://%7f` yields a
    /// one-byte host `0x7f`. The high-bit cases are what leave a non-ASCII
    /// host for `src/idn.rs`, and the text below is written with escapes
    /// because this file is held to ASCII source by
    /// `scripts/spacecheck.pl`.
    #[test]
    fn delete_and_high_bit_bytes_are_accepted() {
        assert_eq!(check(&[0x7f]), CURLUE_OK);
        assert_eq!(check(&[0xff]), CURLUE_OK);
        // "raksmorgas.se" with the three vowels replaced by their UTF-8
        // encodings, which is the host `tests/libtest/lib1560.c` L629-L631
        // asserts the IDN conversion of.
        let swedish = "r\u{e4}ksm\u{f6}rg\u{e5}s.se".as_bytes();
        assert_eq!(check(swedish), CURLUE_OK);
        assert_eq!(check("\u{4e2d}\u{6587}.tw".as_bytes()), CURLUE_OK);
    }

    /// An `hlen` shorter than the C string is a rejection, not a truncation.
    ///
    /// L457 compares the span against `hlen` for equality, so a caller that
    /// under-reports the length gets `CURLUE_BAD_HOSTNAME` even though every
    /// byte in its window is legal. Faithful to the C and worth pinning,
    /// because the intuitive reading -- "is there a refused byte in the
    /// first `hlen` bytes" -- would accept it.
    #[test]
    fn an_hlen_shorter_than_the_string_is_refused() {
        assert_eq!(check_with_hlen(b"example.com", 11), CURLUE_OK);
        assert_eq!(check_with_hlen(b"example.com", 5), CURLUE_BAD_HOSTNAME);
        assert_eq!(check_with_hlen(b"example.com", 10), CURLUE_BAD_HOSTNAME);
    }

    /// An interior zero byte ends the span, so the host is refused.
    ///
    /// The C's `strcspn` stops there and reports three for `exa\0mple`,
    /// which cannot equal a `hlen` of eight. Unreachable through the public
    /// API -- `Curl_junkscan` and `REJECT_CTRL` both refuse a zero byte --
    /// and reproduced so that the question does not arise.
    #[test]
    fn an_interior_zero_byte_shortens_the_span() {
        assert_eq!(check(b"exa\0mple"), CURLUE_BAD_HOSTNAME);
        assert_eq!(check_with_hlen(b"exa\0mple", 3), CURLUE_OK);
    }

    /// A bracketed host is handed to the IPv6 parser, with everything that
    /// implies: normalization, the zone identifier, and its error codes.
    ///
    /// The assertions are about delegation rather than about IPv6 parsing,
    /// which `src/parse/ipv6.rs` tests in depth. What matters here is that
    /// this module looks at the first byte and then stops deciding.
    #[test]
    fn a_bracketed_host_is_delegated_to_the_ipv6_parser() {
        let (code, host, zone) = check_full(b"[::1]");
        assert_eq!(code, CURLUE_OK);
        assert_eq!(host, b"[::1]");
        assert_eq!(zone, None);

        // Normalization, which only the IPv6 parser performs.
        let (code, host, _) = check_full(b"[0:0:0:0:0:0:0:1]");
        assert_eq!(code, CURLUE_OK);
        assert_eq!(host, b"[::1]");

        // A zone identifier, stored on the handle. This is the shape
        // `%5bfe80%3a%3a1%2525eth0%5d` decodes to, which the reference build
        // reports as the host `[fe80::1]` with the zone `eth0`.
        let (code, host, zone) = check_full(b"[fe80::1%25eth0]");
        assert_eq!(code, CURLUE_OK);
        assert_eq!(host, b"[fe80::1]");
        assert_eq!(zone.as_deref(), Some(&b"eth0"[..]));

        // And its refusals, which are not this module's codes.
        assert_eq!(check(b"[::1"), CURLUE_BAD_IPV6);
        assert_eq!(check(b"[nonsense]"), CURLUE_BAD_IPV6);
        assert_eq!(check(b"[]"), CURLUE_BAD_IPV6);
    }

    /// The four `HOST_*` numbers of `lib/urlapi.c` L477-L481.
    #[test]
    fn the_discriminants_match_the_c_defines() {
        assert_eq!(HostKind::Error as i32, -1);
        assert_eq!(HostKind::Name as i32, 1);
        assert_eq!(HostKind::Ipv4 as i32, 2);
        assert_eq!(HostKind::Ipv6 as i32, 3);
        // No variant occupies zero, which is the gap the C leaves between
        // HOST_ERROR and HOST_NAME.
        for kind in [
            HostKind::Error,
            HostKind::Name,
            HostKind::Ipv4,
            HostKind::Ipv6,
        ] {
            assert_ne!(kind as i32, 0);
        }
    }

    /// The four worked examples from the C comment at `lib/urlapi.c` L466.
    #[test]
    fn the_four_examples_from_the_c_comment() {
        assert_eq!(
            normalize(b"16843009"),
            (HostKind::Ipv4, Vec::from(&b"1.1.1.1"[..]))
        );
        assert_eq!(
            normalize(b"0x7f"),
            (HostKind::Ipv4, Vec::from(&b"0.0.0.127"[..]))
        );
        assert_eq!(
            normalize(b"0x7f.1"),
            (HostKind::Ipv4, Vec::from(&b"127.0.0.1"[..]))
        );
        assert_eq!(
            normalize(b"0177.1.1.1"),
            (HostKind::Ipv4, Vec::from(&b"127.1.1.1"[..]))
        );
    }

    /// A canonical dotted quad is accepted and rewritten to itself.
    #[test]
    fn a_canonical_quad_survives_unchanged() {
        for host in [
            &b"1.2.3.4"[..],
            b"0.0.0.0",
            b"255.255.255.255",
            b"127.0.0.1",
        ] {
            let (kind, text) = normalize(host);
            assert_eq!(kind, HostKind::Ipv4, "{}", shown(host));
            assert_eq!(text, host, "{}", shown(host));
        }
    }

    /// Arity one has no range test, because a 32-bit value cannot be out of
    /// range.
    ///
    /// The ceiling that does apply is the scanner's [`UINT_MAX`], one step
    /// above the largest address: `4294967295` normalizes and `4294967296`
    /// does not.
    #[test]
    fn arity_one_is_bounded_only_by_the_scanner() {
        assert_eq!(UINT_MAX, 0xffff_ffff);
        assert_eq!(
            normalize(b"4294967295"),
            (HostKind::Ipv4, Vec::from(&b"255.255.255.255"[..]))
        );
        assert_eq!(
            normalize(b"0xffffffff"),
            (HostKind::Ipv4, Vec::from(&b"255.255.255.255"[..]))
        );
        let (kind, text) = normalize(b"4294967296");
        assert_eq!(kind, HostKind::Name);
        assert_eq!(text, b"4294967296");
    }

    /// The upper bound of each remaining arity is exact, and a violation
    /// leaves the buffer alone.
    ///
    /// Each pair straddles one bound: 24 bits for a two-part address, 16 for
    /// a three-part one, 8 for each part of a four-part one. The
    /// "unchanged" half of every assertion is the reset-after-the-test
    /// ordering of L541-L543, L551-L553 and L561-L564.
    #[test]
    fn the_arity_bounds_are_exact_and_a_violation_changes_nothing() {
        for (host, expected) in [
            (&b"1.16777215"[..], &b"1.255.255.255"[..]),
            (b"1.1.65535", b"1.1.255.255"),
            (b"255.255.255.255", b"255.255.255.255"),
            (b"255.16777215", b"255.255.255.255"),
            (b"255.255.65535", b"255.255.255.255"),
        ] {
            assert_eq!(
                normalize(host),
                (HostKind::Ipv4, Vec::from(expected)),
                "{}",
                shown(host)
            );
        }
        for host in [
            &b"1.16777216"[..],
            b"1.1.65536",
            b"256.1.1.1",
            b"1.256.1.1",
            b"1.1.256.1",
            b"1.1.1.256",
            b"1.2.3.256",
            b"256.16777215",
            b"1.256.65535",
        ] {
            let (kind, text) = normalize(host);
            assert_eq!(kind, HostKind::Name, "{}", shown(host));
            assert_eq!(text, host, "{} was rewritten", shown(host));
        }
    }

    /// The base is decided per part, from that part's first byte, so one
    /// address may mix all three.
    #[test]
    fn the_base_is_chosen_per_part() {
        for (host, expected) in [
            (&b"0111.02.0x3"[..], &b"73.2.0.3"[..]),
            (b"0111.02.030", b"73.2.0.24"),
            (b"0xff.0xff.0377.255", b"255.255.255.255"),
            (b"0.0x0", b"0.0.0.0"),
            (b"192.0x0000A80001", b"192.168.0.1"),
            (b"0177.1", b"127.0.0.1"),
            (b"1.2.3.04", b"1.2.3.4"),
            (b"010", b"0.0.0.8"),
            (b"0", b"0.0.0.0"),
            (b"0x0", b"0.0.0.0"),
        ] {
            assert_eq!(
                normalize(host),
                (HostKind::Ipv4, Vec::from(expected)),
                "{}",
                shown(host)
            );
        }
    }

    /// The `0x` prefix test is case-sensitive, and a leading zero on its own
    /// means octal.
    ///
    /// Both halves are measurable and both are easy to get backwards.
    /// `0X7f` is not hexadecimal: the octal scanner reads the zero, stops on
    /// the `X`, and the `default` arm at L525 makes it a name. `08` is not
    /// decimal: the octal scanner stops on the `8` for the same reason.
    #[test]
    fn the_prefix_is_lowercase_and_a_bare_zero_means_octal() {
        for host in [&b"0X7f"[..], b"0X0", b"08", b"09", b"0x", b"0xg", b"00x7f"] {
            let (kind, text) = normalize(host);
            assert_eq!(kind, HostKind::Name, "{}", shown(host));
            assert_eq!(text, host, "{} was rewritten", shown(host));
        }
        // The same digits with a lowercase prefix are hexadecimal.
        assert_eq!(
            normalize(b"0x7f"),
            (HostKind::Ipv4, Vec::from(&b"0.0.0.127"[..]))
        );
    }

    /// A fifth part, a missing part and a stray byte all mean "name".
    #[test]
    fn a_malformed_address_is_a_name() {
        for host in [
            &b"1.2.3.4.5"[..],
            b"1.2.3.4.",
            b"1.",
            b".1",
            b"1..2",
            b"",
            b"example.com",
            b"1.0x1000000",
            b"0111.02.0x3.",
            b"1.2.3.256.",
            b"999999999999999999999999",
            b"1.2.3.4a",
            b"1%2e2",
            b"::1",
        ] {
            let (kind, text) = normalize(host);
            assert_eq!(kind, HostKind::Name, "{}", shown(host));
            assert_eq!(text, host, "{} was rewritten", shown(host));
        }
    }

    /// A buffer that was never appended to answers "name" rather than
    /// dereferencing a null pointer.
    ///
    /// The C reads `*curlx_dyn_ptr(host)` at L491 with no null test, and
    /// cannot reach it: `parse_authority` returns `CURLUE_NO_HOST` at
    /// L631-L632 for an empty buffer before this function is called. The
    /// port has a defined answer for the case regardless, because an empty
    /// slice simply has no first byte and no digits.
    #[test]
    fn an_unallocated_buffer_is_a_name() {
        let mut host = DynBuf::new(CURL_MAX_INPUT_LENGTH);
        assert_eq!(host.capacity(), 0, "nothing has been appended yet");
        assert_eq!(ipv4_normalize(&mut host), HostKind::Name);
        assert_eq!(host.len(), 0);
    }

    /// A refill the buffer cannot take is [`HostKind::Error`], and the buffer
    /// is gone afterwards.
    ///
    /// The only failure this function has, and it is reachable because a quad
    /// may be *longer* than the text it replaces: `0` is one byte and
    /// `0.0.0.0` is seven. A ceiling of two accepts the first append and
    /// refuses the second, which is `CURLE_TOO_LARGE` from
    /// `lib/curlx/dynbuf.c` L83 and `HOST_ERROR` at L572-L573. The caller
    /// turns it into `CURLUE_OUT_OF_MEMORY` at L645-L646, so the ceiling
    /// breach and a failed allocation are indistinguishable from outside --
    /// as they are in the C, which folds both into the one code.
    ///
    /// The assertion about capacity afterwards is contract 1 of
    /// `crate::dynbuf`: a failed append has already released the buffer, so
    /// neither this function nor its caller may free it again.
    #[test]
    fn a_refill_that_does_not_fit_is_an_error() {
        let mut host = DynBuf::new(2);
        assert!(host.addn(b"0").is_ok(), "one byte fits a ceiling of two");
        assert_eq!(ipv4_normalize(&mut host), HostKind::Error);
        assert_eq!(host.capacity(), 0, "a failed append releases the buffer");
        assert_eq!(host.len(), 0);

        // A ceiling that fits the quad exactly is accepted, so the boundary
        // is the ceiling and not the rewrite itself.
        let mut host = DynBuf::new(8);
        assert!(host.addn(b"0").is_ok());
        assert_eq!(ipv4_normalize(&mut host), HostKind::Ipv4);
        assert_eq!(cstring_of(&host), b"0.0.0.0");
    }

    /// A leading bracket short-circuits with nothing validated.
    ///
    /// L491-L492 returns before the loop, so a bracketed host is
    /// [`HostKind::Ipv6`] whatever follows the bracket -- including nothing
    /// at all -- and the buffer is untouched.
    #[test]
    fn a_bracket_short_circuits_without_validation() {
        for host in [&b"[::1]"[..], b"[", b"[nonsense", b"[]", b"[1.2.3.4]"] {
            let (kind, text) = normalize(host);
            assert_eq!(kind, HostKind::Ipv6, "{}", shown(host));
            assert_eq!(text, host, "{} was rewritten", shown(host));
        }
    }

    /// [`classify`] reports the separator count and the parts, and refuses
    /// everything [`ipv4_normalize`] reports as a name.
    ///
    /// A direct test of the loop, so that the arity dispatch above is not
    /// the only evidence that the parts are collected in order.
    #[test]
    fn the_classifier_reports_the_parts_and_the_separator_count() {
        let one = classify(b"16843009\0").unwrap();
        assert_eq!(one.dots, 0);
        assert_eq!(one.values, [16_843_009, 0, 0, 0]);

        let two = classify(b"0x7f.1\0").unwrap();
        assert_eq!(two.dots, 1);
        assert_eq!(two.values, [127, 1, 0, 0]);

        let three = classify(b"0111.02.0x3\0").unwrap();
        assert_eq!(three.dots, 2);
        assert_eq!(three.values, [73, 2, 3, 0]);

        let four = classify(b"1.2.3.4\0").unwrap();
        assert_eq!(four.dots, 3);
        assert_eq!(four.values, [1, 2, 3, 4]);

        // The ceiling, either side of it.
        assert_eq!(classify(b"4294967295\0").unwrap().values[0], 0xffff_ffff);
        assert!(classify(b"4294967296\0").is_none());

        // The terminator and the end of the slice are the same stopping
        // condition.
        assert_eq!(classify(b"1.2.3.4").unwrap().values, [1, 2, 3, 4]);

        // And every shape of refusal.
        for host in [
            &b"1.2.3.4.5\0"[..],
            b"1.2.3.4.\0",
            b"1.\0",
            b".1\0",
            b"1..2\0",
            b"\0",
            b"",
            b"example.com\0",
            b"0X7f\0",
            b"08\0",
            b"0x\0",
        ] {
            assert!(classify(host).is_none(), "{}", shown(host));
        }
    }

    /// A host with no `%` is left completely alone.
    #[test]
    fn a_host_without_a_percent_is_left_alone() {
        for host in [&b"example.com"[..], b"1.2.3.4", b"", b"[::1]", &[0xff]] {
            let (code, text) = decode_host(host);
            assert_eq!(code, CURLUE_OK, "{}", shown(host));
            assert_eq!(text, host, "{} was rewritten", shown(host));
        }
    }

    /// An escape is decoded and the buffer replaced.
    #[test]
    fn an_escape_is_decoded() {
        assert_eq!(
            decode_host(b"ex%61mple.com"),
            (CURLUE_OK, Vec::from(&b"example.com"[..]))
        );
        assert_eq!(
            decode_host(b"1%2e2%2e3%2e4"),
            (CURLUE_OK, Vec::from(&b"1.2.3.4"[..]))
        );
        assert_eq!(
            decode_host(b"%5b%3a%3a%31%5d"),
            (CURLUE_OK, Vec::from(&b"[::1]"[..]))
        );
        // Hexadecimal digit case does not matter, and an escape may sit at
        // either end.
        assert_eq!(
            decode_host(b"%41%42%43"),
            (CURLUE_OK, Vec::from(&b"ABC"[..]))
        );
    }

    /// A decoded byte below `0x20` fails the decode, and the buffer is left
    /// as it was.
    ///
    /// L592-L593 returns before the reset at L594, so the host still holds
    /// the encoded text afterwards. Not observable through the public API,
    /// because the caller discards the handle, and reproduced because it is
    /// what the C does.
    #[test]
    fn a_control_byte_fails_the_decode_and_changes_nothing() {
        for host in [&b"%41%0D"[..], b"%00", b"16843009%00", b"%1f", b"%09"] {
            let (code, text) = decode_host(host);
            assert_eq!(code, CURLUE_BAD_HOSTNAME, "{}", shown(host));
            assert_eq!(text, host, "{} was rewritten", shown(host));
        }
    }

    /// The decoder accepts the space and delete that the host check then
    /// judges separately.
    ///
    /// Set B stops below `0x20`, so `%20` decodes to a space and `%7f` to
    /// delete. The check refuses the first and accepts the second, which is
    /// how one `CURLUE_BAD_HOSTNAME` comes from two different stages.
    #[test]
    fn the_decoder_accepts_what_the_check_judges() {
        assert_eq!(decode_host(b"%20"), (CURLUE_OK, Vec::from(&b" "[..])));
        assert_eq!(check(b" "), CURLUE_BAD_HOSTNAME);

        assert_eq!(decode_host(b"%7f"), (CURLUE_OK, Vec::from(&[0x7f][..])));
        assert_eq!(check(&[0x7f]), CURLUE_OK);
    }

    /// A malformed escape is literal, not a decode failure -- and the `%` it
    /// leaves behind is what the check then refuses.
    ///
    /// This is the one place where the end-to-end answer and the
    /// stage-by-stage answer differ, and it is worth being explicit about.
    /// `Curl_urldecode` needs three bytes and two hexadecimal digits at
    /// `lib/escape.c` L126 and otherwise emits the `%` verbatim at
    /// L134-L137, so `%4` and `test%test` both decode *successfully*.
    /// `CURLUE_BAD_HOSTNAME` is nonetheless the code the reference build
    /// reports for both, and `tests/libtest/lib1560.c` L195 asserts it for
    /// `https://test%test` -- it comes from [`hostname_check`] on the next
    /// line of `parse_authority`, because `%` is the last byte of
    /// [`HOST_REJECT`]. Both halves are asserted here so that neither can be
    /// mistaken for the other.
    #[test]
    fn a_malformed_escape_is_literal_and_the_check_refuses_it() {
        for host in [&b"%4"[..], b"test%test", b"%", b"%zz", b"%2"] {
            let (code, text) = decode_host(host);
            assert_eq!(code, CURLUE_OK, "{} should decode", shown(host));
            assert_eq!(text, host, "{} should decode to itself", shown(host));
            assert_eq!(
                check(host),
                CURLUE_BAD_HOSTNAME,
                "{} should fail the check",
                shown(host)
            );
        }
        // And a well-formed escape of the percent sign itself, which is the
        // same conclusion by a different route: lib1560.c L653.
        assert_eq!(decode_host(b"%25"), (CURLUE_OK, Vec::from(&b"%"[..])));
        assert_eq!(check(b"%"), CURLUE_BAD_HOSTNAME);
    }

    /// The reference build's answers, reproduced by the three functions
    /// driven in the caller's order.
    ///
    /// This is the closest thing to the parity run that a unit test can be:
    /// [`pipeline`] is `parse_authority`'s switch at L634-L651, and the two
    /// tables were captured from an unmodified libcurl rather than written
    /// from this code. A single row failing here means the port and the C
    /// disagree about a host, which is exactly what the `get_parts` and
    /// `set_parts` sub-tests of `lib1560` would report as exit code 4 or 2.
    #[test]
    fn the_pipeline_reproduces_the_reference() {
        for (host, expected) in PIPELINE_ACCEPTS {
            let (code, text) = pipeline(host);
            assert_eq!(code, CURLUE_OK, "{} was refused", shown(host));
            assert_eq!(
                text,
                expected,
                "{} became {} rather than {}",
                shown(host),
                shown(&text),
                shown(expected)
            );
        }
        for (host, expected) in PIPELINE_REJECTS {
            let (code, _) = pipeline(host);
            assert_eq!(
                code,
                expected,
                "{} returned {} rather than {}",
                shown(host),
                code,
                expected
            );
        }
    }

    /// Normalization runs before decoding, so a decoded address is never
    /// re-classified.
    ///
    /// The order is the caller's and this is what it costs: `0%787f`
    /// decodes to `0x7f`, which would normalize to `0.0.0.127` had the
    /// stages run the other way about, and the reference build reports the
    /// host as `0x7f`. Three vectors, all measured.
    #[test]
    fn normalization_precedes_decoding() {
        for (host, expected) in [
            (&b"0%787f"[..], &b"0x7f"[..]),
            (b"%30x7f", b"0x7f"),
            (b"%30177.1.1.1", b"0177.1.1.1"),
        ] {
            let (code, text) = pipeline(host);
            assert_eq!(code, CURLUE_OK, "{}", shown(host));
            assert_eq!(text, expected, "{}", shown(host));
        }
    }
}
