// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The decimal, hexadecimal and octal number scanners.
//!
//! `lib/urlapi.c` has exactly two kinds of number to read out of a URL, a
//! port and the parts of a dotted IPv4 address, and it reads both through
//! functions it borrows from `lib/curlx/strparse.c`. An object file
//! standing in for `lib/urlapi.o` cannot borrow them back, so this module
//! re-implements them. The correspondence, C name first:
//!
//! - `curlx_str_number` at `lib/curlx/strparse.c` L195 becomes
//!   [`str_number`], base 10.
//! - `curlx_str_hex` at L202 becomes [`str_hex`], base 16.
//! - `curlx_str_octal` at L209 becomes [`str_octal`], base 8.
//!
//! Each of those three C functions is a single call into the shared engine
//! `str_num_base` at L157, and the port keeps that shape exactly:
//! `str_num_base` below carries the whole algorithm and the three entry
//! points differ only in the base they hand it.
//!
//! The other seventeen functions of `lib/curlx/strparse.c`, among them
//! `curlx_str_until`, `curlx_str_word`, `curlx_str_quotedword`,
//! `curlx_str_single` and `curlx_str_cspn`, are deliberately absent.
//! `lib/urlapi.c` calls none of them, a port of them would be dead code,
//! dead code is a warning, and this crate is built warning-free.
//!
//! Nothing here is `unsafe`: every operation is over a byte slice and two
//! integers, so there is no precondition for an `unsafe` block to assert.
//! Nothing here is conditional either. No `cfg` of any kind appears below,
//! so every feature combination of the crate gets the same scanners, which
//! is what keeps the two link modes from disagreeing about what a port
//! number is.
//!
//! # The division of labor, which is the subtle part
//!
//! A scanner reports one thing: the number it read, and where it stopped.
//! Whether the bytes after that stopping point are acceptable is the
//! *caller's* question, and the three callers in `lib/urlapi.c` answer it
//! in two different ways.
//!
//! `Curl_parse_port` at L375 rejects any leftover byte at all:
//!
//! ```c
//! if(curlx_str_number(&portptr, &port, 0xffff) || *portptr)
//!   return CURLUE_BAD_PORT_NUMBER;
//! ```
//!
//! `set_url_port` at L1673 spells the same test the same way, having
//! already rejected a non-digit first byte itself at L1670-L1672. But
//! `ipv4_normalize` at L494-L528 *expects* leftovers: it scans one part,
//! then looks at the byte the scanner stopped on, continues on `.`,
//! finishes on the terminating NUL and rejects anything else. An address of
//! four parts reaches the scanners four times.
//!
//! So a scanner that folded the leftover test into itself would break the
//! IPv4 walk, and one that consumed the delimiter as well would break it
//! the other way about. Neither failure shows on ordinary input, which is
//! why it is stated here rather than left to be discovered: this module
//! advances the cursor over the digits it consumed and not one byte
//! further, and it never inspects what follows them.
//!
//! # The failure posture
//!
//! The C zeroes its out-parameter before anything else, at L167, and
//! assigns the scanned value and the new cursor position together at
//! L188-L189, on the success path only. Both of its failure returns, L170
//! and L177 or L184, are therefore reached with the caller's cursor
//! untouched.
//!
//! This port reproduces that: on `Err` the cursor is left exactly as it was
//! found, so a caller may retry the same bytes with another base and get
//! the same answer the C would give. The one representational difference is
//! that `Err` carries no number at all, where the C leaves a zero behind
//! for a caller who ignores the return code to read. That removes a failure
//! mode rather than adding one, and it is the reason this module returns
//! `Result` instead of an integer code.
//!
//! # `curl_off_t` becomes `i64`
//!
//! The C signatures take and return `curl_off_t`, curl's signed 64-bit
//! offset type, so `i64` is that type on every platform this port targets.
//! The maxima therefore arrive unchanged: `0xffff` from L375 and L1673, and
//! `UINT_MAX` from L500, L503 and L506. The narrowing that follows keeps
//! its meaning too. `u->portnum = (unsigned short)port` at L378, and the
//! same cast at L1681, cannot lose information for any value a maximum of
//! `0xffff` lets through, which is why the C can afford to be that terse
//! and why a scanner that accepted more than its maximum would break the
//! port number silently rather than loudly.
//!
//! # Why not `i64::from_str_radix`
//!
//! The standard library's parser is unsuitable here for three independent
//! reasons, any one of which would be enough on its own.
//!
//! 1. It reports no stopping point, so neither the leftover test at L375
//!    nor the dot-separated walk at L494-L528 could be written over it.
//! 2. Its accepted set is different. It takes an optional leading `+` or
//!    `-`, and `valid_digit` at L142-L143 rejects both on the first byte,
//!    so `"+80"` and `"-1"` would become valid ports.
//! 3. Its bound is the target type's range rather than the caller's
//!    maximum. `"70000"` would parse, and the caller would have to compare
//!    afterwards, which is neither what the C does nor where the C reports
//!    the failure.
//!
//! Reproducing curl's acceptance set exactly is the whole job of this
//! module, so the scanning loop is written out rather than delegated.

// Reachability here is decided by the consumers. The three public scanners
// mirror `curlx_str_number`, `curlx_str_hex` and `curlx_str_octal`, and
// `src/parse/port.rs` and `src/parse/host.rs` reach them from the port parser
// and the IPv4 normaliser exactly where `lib/urlapi.c` does. The base table and
// its compile-time proof exist to keep the three radices checkable in one
// place, so they are deliberately not folded into the callers.
//
// No dead-code allowance appears in this module, and none is needed: every item
// below is reached from this crate's own paths in every configuration it
// builds. There is no crate-wide allowance either -- an item without a
// production caller carries its own, with its reason, as "DEAD-CODE POLICY" in
// `src/lib.rs` requires.

// The plan puts every `unsafe` block in `src/ffi.rs` (0.3.3) and the
// technical specification forbids `unsafe` outside FFI code (1.3.2.1).
// `forbid` rather than `deny` because an inner `allow` here would be a
// design change and should have to be argued for, not slipped in. This
// module needs nothing from C, so the attribute costs it nothing and turns
// the crate's single-unsafe-island property into a compiler guarantee
// instead of a convention.
#![forbid(unsafe_code)]

use crate::ctype::{hexval, is_digit, is_odigit, is_xdigit};

/// Why a scan produced no number.
///
/// The C engine returns `int`, zero for success, and the two non-zero codes
/// it can produce are `STRE_OVERFLOW`, 7, and `STRE_NO_NUM`, 8, from
/// `lib/curlx/strparse.h` L35-L36. The mapping this port uses is:
///
/// - `STRE_OK`, 0, which sets `*nump` and advances `*linep`, becomes
///   `Ok(value)` with the cursor advanced by the same number of bytes.
/// - `STRE_NO_NUM`, 8, which leaves `*nump` at the zero written on entry
///   and never touches `*linep`, becomes `Err(StrError::NoNumber)` with the
///   cursor untouched.
/// - `STRE_OVERFLOW`, 7, which does the same, becomes
///   `Err(StrError::Overflow)`, again with the cursor untouched.
///
/// A `Result` rather than an integer code because the crate root denies
/// `unwrap` and `expect`: a caller that must not ignore a failure gets a
/// type that says so, and the two `if(scan(..) || *rest)` tests at L375 and
/// L1673 become `is_err() || !cursor.is_empty()` with no sentinel value in
/// sight.
///
/// Both distinctions collapse at every call site in `lib/urlapi.c` today:
/// any non-zero code becomes `CURLUE_BAD_PORT_NUMBER` at L376 and L1675, or
/// `HOST_NAME` at L508-L509. The two variants are kept apart anyway,
/// because it costs one variant and it lets a reader of a failing
/// assertion tell "that was not a number" from "that number was too big".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StrError {
    /// `STRE_NO_NUM`, 8: the first byte was not a digit of the requested
    /// base, so there was no number there to scan.
    ///
    /// `lib/curlx/strparse.c` L169-L170. This is the outcome for empty
    /// input as well, because the C's guard reads the terminating NUL and
    /// finds it is not a digit either.
    NoNumber,
    /// `STRE_OVERFLOW`, 7: the digits scanned so far, extended by the next
    /// one, would exceed the caller's maximum.
    ///
    /// `lib/curlx/strparse.c` L176-L177 in the low-maximum branch and
    /// L183-L184 in the general one. Note what this is not: it is not an
    /// overflow of the accumulator's type. The general branch tests each
    /// digit before accumulating it, so the accumulator never leaves the
    /// range the caller asked for, however long the digit run.
    Overflow,
}

/// The three bases the engine accepts, as a type rather than as an integer
/// plus an assertion.
///
/// The C parameter is annotated "8, 10 or 16, nothing else" at
/// `lib/curlx/strparse.c` L158 and enforced by a `DEBUGASSERT` at L165,
/// which compiles out of a release build. An enum enforces the same thing
/// in every build, at compile time, and it carries both pieces of per-base
/// information the C derives separately: the radix each dispatcher passes,
/// and the largest digit the base accepts, which the C computes as `m` at
/// L162-L163 and feeds to `valid_digit`.
#[derive(Debug, Clone, Copy)]
enum Base {
    /// Base 8, `m` of `'7'`. Reached through [`str_octal`].
    Octal,
    /// Base 10, `m` of `'9'`. Reached through [`str_number`].
    Decimal,
    /// Base 16, `m` of `'f'`. Reached through [`str_hex`].
    Hex,
}

impl Base {
    /// The radix, that is the `base` argument the three C dispatchers pass:
    /// 8 at `lib/curlx/strparse.c` L211, 10 at L197 and 16 at L204.
    ///
    /// Typed `i64` rather than the C's `int` because every use of it is
    /// arithmetic against a `curl_off_t` accumulator and a `curl_off_t`
    /// maximum. A cast at each use would be one more place for a mistake to
    /// hide, and the values are small enough that the wider type costs
    /// nothing.
    const fn radix(self) -> i64 {
        match self {
            Self::Octal => 8,
            Self::Decimal => 10,
            Self::Hex => 16,
        }
    }

    /// `valid_digit(byte, m)` from `lib/curlx/strparse.c` L142-L143.
    ///
    /// The C macro is a conjunction of three tests: `byte >= '0'`,
    /// `byte <= m`, and a non-zero entry in `curlx_hexasciitable` at
    /// L148-L154. Worked through for each base, the accepted set that comes
    /// out is exactly one of the predicates `crate::ctype` already provides,
    /// so this method selects rather than re-derives:
    ///
    /// - base 8 with `m` of `'7'` accepts `'0'` through `'7'`, which is
    ///   `is_odigit`;
    /// - base 10 with `m` of `'9'` accepts `'0'` through `'9'`, which is
    ///   `is_digit`;
    /// - base 16 with `m` of `'f'` accepts `'0'` through `'f'` *minus* the
    ///   bytes whose table entry is zero, which removes `':'` through `'@'`
    ///   and `'G'` through the backquote and leaves the digits and both
    ///   letter cases, which is `is_xdigit`.
    ///
    /// One divergence a reader might expect is not there. The C reads
    /// `char`, whose signedness is platform-defined, while this reads `u8`.
    /// A high-bit byte is rejected either way: as a signed `char` it is
    /// negative and fails `byte >= '0'`, and as an unsigned one it is at
    /// least 0x80 and fails `byte <= m`, because the largest `m` is `'f'`,
    /// which is 0x66. `BASE_PROOF` pins that at compile time.
    const fn accepts(self, byte: u8) -> bool {
        match self {
            Self::Octal => is_odigit(byte),
            Self::Decimal => is_digit(byte),
            Self::Hex => is_xdigit(byte),
        }
    }

    /// The value of one digit of this base, or `None` for a byte this base
    /// does not accept.
    ///
    /// This fuses the C's two steps, the `valid_digit` gate and the
    /// `curlx_hexval` lookup at `lib/curlx/strparse.h` L111, into one. The C
    /// keeps them apart and pays for it with a documented precondition: the
    /// comment above the macro at L106-L109 says it only works on valid
    /// hexadecimal input and that the caller must check first, and reading
    /// the table with an unchecked byte is out-of-bounds. Fusing them here
    /// means the precondition cannot be forgotten, because the only way to
    /// get a value is to be handed one.
    ///
    /// `hexval` returns `Some` for every byte any of the three predicates
    /// accepts, each accepted set being a subset of `is_xdigit`, so the
    /// `None` arm of the inner lookup is unreachable in practice. It is
    /// mapped rather than asserted: the crate root denies the panicking
    /// constructs, and an unreachable arm that reports "not a digit" ends
    /// the scan cleanly instead of aborting the process.
    fn digit_value(self, byte: u8) -> Option<i64> {
        if self.accepts(byte) {
            hexval(byte).map(i64::from)
        } else {
            None
        }
    }
}

/// The scanning engine: `str_num_base` at `lib/curlx/strparse.c` L157-L191.
///
/// Reads the run of `base` digits at the front of `*cursor` and stops at the
/// first byte that is not one of them. On success the value is returned and
/// `cursor` is advanced past the digits, which is the C's
/// `*nump = num; *linep = p;` at L188-L189. On failure the cursor is left
/// where it was found, as described under the module's failure posture.
///
/// # The two overflow tests, and why both are needed
///
/// The C chooses between them on `max < base` at L171, and the port
/// reproduces both because they disagree on reachable input.
///
/// The general case, `max >= base` at L180-L187, tests the next digit
/// *before* accumulating it, as `if(num > ((max - n) / base))`. That test is
/// exact in both directions. Write `max - n` as `q * base + r` with
/// `0 <= r < base`. If `num <= q` then `num * base + n <= max - r <= max`,
/// so no valid number is rejected. If `num >= q + 1` then
/// `num * base + n >= q * base + base + n > max`, so no invalid one is
/// accepted. Because the test runs first, the accumulator never exceeds
/// `max`, and therefore never overflows its own type however long the digit
/// run: forty nines against a maximum of `0xffff` are rejected at the fifth
/// digit, the one that would cross the maximum, and not at the nineteenth,
/// the one that would cross `i64`.
///
/// The low-maximum case, `max < base` at L172-L179, cannot use that test,
/// and the C comment at L172 says as much without saying why. The reason is
/// truncation: `max - n` goes negative as soon as a digit exceeds `max`, C
/// divides toward zero, and the test degenerates. With `max` of 5, base 10
/// and an input of `"7"`, the general test computes `(5 - 7) / 10` as 0,
/// finds `0 > 0` false, and *accepts* 7 against a maximum of 5. So this
/// branch accumulates first and compares after, which is safe here because
/// `max < base` bounds the accumulator well below the type's range before
/// the comparison rejects it.
///
/// A negative `max` is not a supported input. The C asserts `max >= 0` at
/// L166, in debug builds only, so what a release build does is take the
/// low-maximum branch, where every digit exceeds `max` and the first one
/// reports [`StrError::Overflow`]. This port does the same for the same
/// reason, and a test pins it so that a later tidy-up cannot quietly change
/// it.
fn str_num_base(cursor: &mut &[u8], max: i64, base: Base) -> Result<i64, StrError> {
    // Forces the module's compile-time base check to be evaluated in every
    // build; see BASE_PROOF for why the constant is named and referenced
    // from a live function rather than written as an anonymous `const _`.
    // This binding emits no code.
    let () = BASE_PROOF;

    let radix = base.radix();
    // `curl_off_t num = 0` at L160.
    let mut num: i64 = 0;
    // `p = *linep` at L168. The C walks a pointer and stops on the string's
    // terminating NUL; this walks a slice and stops when the slice runs out.
    // Those are the same stopping condition, and they stay the same for a
    // slice that happens to contain a NUL, because a zero byte is below
    // `'0'` and so is not a digit of any base either.
    //
    // Written without a type annotation on purpose. Naming the type here
    // would make the initializer an auto-deref of the `&mut`, that is a
    // reborrow whose lifetime ends inside this function, and the assignment
    // to `*cursor` below could then not be written at all. Copying the inner
    // slice reference out instead, which `&[u8]` being `Copy` allows, keeps
    // the caller's lifetime.
    let mut rest = *cursor;
    // Whether a digit was consumed. `false` at the end is the C's
    // `if(!valid_digit(*p, m)) return STRE_NO_NUM` at L169-L170.
    let mut any = false;

    while let Some((&byte, tail)) = rest.split_first() {
        // `valid_digit(*p, m)` with the `curlx_hexval(*p)` that follows it,
        // fused into one step. Leaving the loop here plays two parts of the
        // C at once: on the first turn it is the guard at L169-L170, and on
        // every later turn it is the `while(valid_digit(*p, m))` that closes
        // the do-loop at L178 and L186.
        let Some(digit) = base.digit_value(byte) else {
            break;
        };

        if max < radix {
            // L173-L177: accumulate, then compare.
            //
            // The checked arithmetic is not guarding against a reachable
            // overflow. This branch runs only when `max < base`, and the
            // comparison below caps `num` at `max`, so the largest value the
            // multiply can ever see is `base * base + base`, that is 272 at
            // most. The operations are written checked because the crate
            // root denies unchecked arithmetic, and the impossible arm is
            // mapped to the C's own overflow code so that no branch here can
            // panic.
            let next = num
                .checked_mul(radix)
                .and_then(|scaled| scaled.checked_add(digit))
                .ok_or(StrError::Overflow)?;
            if next > max {
                return Err(StrError::Overflow);
            }
            num = next;
        } else {
            // L182-L185: compare, then accumulate.
            //
            // Both halves of the ceiling are infallible under this branch's
            // own precondition: `max >= base > digit >= 0` makes the
            // subtraction positive, and the radix is 8, 10 or 16, so the
            // division has neither a zero divisor nor the one overflowing
            // case. They are written checked for the reason given above.
            let ceiling = max
                .checked_sub(digit)
                .and_then(|room| room.checked_div(radix))
                .ok_or(StrError::Overflow)?;
            if num > ceiling {
                return Err(StrError::Overflow);
            }
            // Infallible once the test above has passed, since the result is
            // at most `max`.
            num = num
                .checked_mul(radix)
                .and_then(|scaled| scaled.checked_add(digit))
                .ok_or(StrError::Overflow)?;
        }

        // The `*p++` of L174 and L182, deferred to here. The C increments
        // before its overflow test and this moves after it, which is not
        // observable: the C's failure returns never reach `*linep = p`, so
        // in both versions the caller's cursor only ever passes a digit that
        // was accounted for.
        rest = tail;
        any = true;
    }

    if !any {
        // `return STRE_NO_NUM` at L170. Reached only when the *first* byte
        // was rejected: any later rejection leaves the loop with a digit
        // already consumed, which is the C's while condition failing rather
        // than its guard.
        return Err(StrError::NoNumber);
    }
    // `*nump = num; *linep = p;` at L188-L189, both on the success path
    // only. Assigning the cursor last is what makes every early return
    // above leave it untouched.
    *cursor = rest;
    Ok(num)
}

/// An unsigned decimal number: no leading space, no sign, no prefix.
///
/// `curlx_str_number` at `lib/curlx/strparse.c` L195-L198.
///
/// Leading zeros are accepted, which the comment at L193-L194 states and
/// `lib/urlapi.c` depends on: having parsed a port, `Curl_parse_port`
/// regenerates the port string from the number at L379-L381 expressly "to
/// get rid of leading zeroes etc", so `"080"` is a valid port that is stored
/// as `"80"`.
///
/// Call sites, all three of them: `Curl_parse_port` at L375 with a maximum
/// of `0xffff`, `set_url_port` at L1673 with the same maximum, and
/// `ipv4_normalize` at L506 with `UINT_MAX` for an address part that has
/// neither a `0x` nor a `0` prefix.
pub(crate) fn str_number(cursor: &mut &[u8], max: i64) -> Result<i64, StrError> {
    str_num_base(cursor, max, Base::Decimal)
}

/// An unsigned hexadecimal number: no leading space, no sign, and no `0x`
/// prefix support.
///
/// `curlx_str_hex` at `lib/curlx/strparse.c` L202-L205. Both letter cases
/// are accepted, and leading zeros are too, per the comment at L200-L201.
///
/// The absent prefix support is a contract with the caller, not an
/// oversight. `ipv4_normalize` recognizes the prefix itself and steps over
/// both of its bytes with `c += 2` at L499 before calling, so a scan that
/// also accepted `"0x"` would accept `"0x0x7f"`. Handing this function a
/// leading `'x'` therefore yields [`StrError::NoNumber`], and handing it
/// nothing at all, which is what `"0x"` on its own becomes after the skip,
/// yields the same.
///
/// Call site: `ipv4_normalize` at L500 with `UINT_MAX`, for a part written
/// as `0x7f`.
pub(crate) fn str_hex(cursor: &mut &[u8], max: i64) -> Result<i64, StrError> {
    str_num_base(cursor, max, Base::Hex)
}

/// An unsigned octal number: no leading space, no sign, and no `0` prefix
/// support.
///
/// `curlx_str_octal` at `lib/curlx/strparse.c` L209-L212, with leading zeros
/// accepted per the comment at L207-L208.
///
/// "No prefix support" means something different here from the way it reads.
/// `ipv4_normalize` selects this scanner *because* the part starts with
/// `'0'`, at L497 and L502-L503, and then hands over the `'0'` as well
/// rather than stepping over it. So the prefix is scanned as an ordinary
/// leading zero, and a part of `"08"` is a successful zero that leaves the
/// `'8'` behind for the caller, which rejects it at the default arm of the
/// switch at L525-L526 and returns `HOST_NAME`.
///
/// Call site: `ipv4_normalize` at L503 with `UINT_MAX`, for a part written
/// as `0177`.
pub(crate) fn str_octal(cursor: &mut &[u8], max: i64) -> Result<i64, StrError> {
    str_num_base(cursor, max, Base::Octal)
}

/// Every radix and digit set in this module, checked against the C.
///
/// A base whose radix and accepted digit set disagree is the worst kind of
/// defect this module could carry: it would parse most input correctly and
/// silently misread the rest, and the parity diff would surface it as an
/// unrelated assertion about a host name. Evaluating the check in a `const`
/// context turns it into a compile error instead.
const fn bases_hold() -> bool {
    // The radices the three C dispatchers pass: L211, L197, L204.
    let radices =
        Base::Octal.radix() == 8 && Base::Decimal.radix() == 10 && Base::Hex.radix() == 16;
    // `m` at L162-L163 is `'7'` for base 8, so `'8'` is out. 0x2f is the
    // byte below `'0'`.
    let octal = Base::Octal.accepts(b'0')
        && Base::Octal.accepts(b'7')
        && !Base::Octal.accepts(b'8')
        && !Base::Octal.accepts(0x2f);
    // `m` of `'9'` for base 10, so the hexadecimal letters are out. 0x3a is
    // the byte above `'9'`.
    let decimal = Base::Decimal.accepts(b'0')
        && Base::Decimal.accepts(b'9')
        && !Base::Decimal.accepts(b'a')
        && !Base::Decimal.accepts(b'A')
        && !Base::Decimal.accepts(0x3a)
        && !Base::Decimal.accepts(0x2f);
    // `m` of `'f'` for base 16, minus the zero entries of
    // `curlx_hexasciitable`: 0x3a through 0x40 sit between `'9'` and `'A'`,
    // and 0x47 through 0x60 between `'F'` and `'a'`.
    let hex = Base::Hex.accepts(b'0')
        && Base::Hex.accepts(b'9')
        && Base::Hex.accepts(b'a')
        && Base::Hex.accepts(b'f')
        && Base::Hex.accepts(b'A')
        && Base::Hex.accepts(b'F')
        && !Base::Hex.accepts(b'g')
        && !Base::Hex.accepts(b'G')
        && !Base::Hex.accepts(0x3a)
        && !Base::Hex.accepts(0x40)
        && !Base::Hex.accepts(0x60);
    // The high-bit rows, which the C rejects whichever way its `char` is
    // signed. See the note on `accepts`.
    let high = !Base::Octal.accepts(0x80)
        && !Base::Decimal.accepts(0x80)
        && !Base::Hex.accepts(0x80)
        && !Base::Hex.accepts(0xff);
    radices && octal && decimal && hex && high
}

/// Compile-time proof that the bases still agree with the C they port.
///
/// The constant is named, and referenced from `str_num_base`, rather than
/// written as the more usual anonymous `const _`. The reason is the same one
/// recorded above `BOUNDARY_PROOF` in `src/ctype.rs`: a `const` item's body
/// is evaluated only when the item is reachable, and on 1.75, this crate's
/// declared minimum, an anonymous `const _` is not a root, so every function
/// behind it draws a dead-code warning. Both toolchains agree once a live
/// function names the constant. Binding a unit constant emits no code, so
/// the check costs nothing at run time.
const BASE_PROOF: () = assert!(
    bases_hold(),
    "src/strparse.rs diverges from lib/curlx/strparse.c: radix or digit set"
);

#[cfg(test)]
mod tests {
    // The crate root denies the panicking constructs so that no panic can
    // ever reach the C boundary. A test's whole job is to panic when an
    // assertion fails, and no test crosses that boundary, so the denials are
    // relaxed here and only here, enumerated rather than blanket. This is
    // the same allowance, for the same reason, as the one in `src/alloc.rs`.
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]

    use super::{str_hex, str_number, str_octal, Base, StrError};

    /// The maximum both port call sites pass: `lib/urlapi.c` L375 and L1673.
    const PORT_MAX: i64 = 0xffff;

    /// The maximum `ipv4_normalize` passes at `lib/urlapi.c` L500, L503 and
    /// L506. `UINT_MAX` is 32 bits wide on every platform this port targets.
    const UINT_MAX: i64 = 0xffff_ffff;

    /// A digit run long enough that an unchecked accumulator would overflow
    /// `i64` before reaching the end of it. Nineteen digits are enough to
    /// cross `i64::MAX`; these are forty.
    const FORTY_NINES: &str = "9999999999999999999999999999999999999999";
    const FORTY_EFFS: &str = "ffffffffffffffffffffffffffffffffffffffff";
    const FORTY_SEVENS: &str = "7777777777777777777777777777777777777777";

    /// The shape all three scanners share, so that one table can drive any
    /// of them.
    type Scanner = fn(&mut &[u8], i64) -> Result<i64, StrError>;

    /// Runs `scanner` over `input` and reports both halves of the outcome:
    /// what it returned, and the bytes it left the cursor pointing at.
    fn scan(scanner: Scanner, input: &str, max: i64) -> (Result<i64, StrError>, &[u8]) {
        let mut cursor: &[u8] = input.as_bytes();
        let outcome = scanner(&mut cursor, max);
        (outcome, cursor)
    }

    /// Asserts the returned value and the resulting cursor position
    /// together.
    ///
    /// Every expectation in this module goes through here. Checking the
    /// value without checking the cursor would miss the one property the
    /// module's callers depend on most, and it is the property a plain
    /// integer parser cannot provide at all.
    fn check(scanner: Scanner, input: &str, max: i64, value: Result<i64, StrError>, rest: &str) {
        let (outcome, cursor) = scan(scanner, input, max);
        assert_eq!(outcome, value, "value scanning {input:?} with max {max}");
        assert_eq!(
            cursor,
            rest.as_bytes(),
            "cursor after scanning {input:?} with max {max}"
        );
    }

    /// The port vectors that reach the public API, reasoned from the C.
    ///
    /// `"65535"` is accepted because the general branch's test at
    /// `lib/curlx/strparse.c` L183 computes `(65535 - 5) / 10` as 6553 on the
    /// final digit and 6553 is not greater than 6553. `"65536"` is rejected
    /// on its final digit, where 6553 is greater than `(65535 - 6) / 10`,
    /// which is 6552. `"099"` is accepted as 99 because leading zeros are
    /// documented as accepted at L193-L194, and `Curl_parse_port` then
    /// regenerates the string at `lib/urlapi.c` L379-L381 to drop them.
    /// `""` and `"x80"` lose to the guard at L169-L170. `"80x"` succeeds and
    /// leaves the `'x'`, which is what makes the `|| *portptr` half of
    /// `lib/urlapi.c` L375 report `CURLUE_BAD_PORT_NUMBER`.
    #[test]
    fn port_vectors_match_the_c() {
        check(str_number, "0", PORT_MAX, Ok(0), "");
        check(str_number, "80", PORT_MAX, Ok(80), "");
        check(str_number, "65535", PORT_MAX, Ok(65535), "");
        check(
            str_number,
            "65536",
            PORT_MAX,
            Err(StrError::Overflow),
            "65536",
        );
        check(str_number, "099", PORT_MAX, Ok(99), "");
        check(str_number, "", PORT_MAX, Err(StrError::NoNumber), "");
        check(str_number, "80x", PORT_MAX, Ok(80), "x");
        check(str_number, "x80", PORT_MAX, Err(StrError::NoNumber), "x80");
        // Rejected at the fifth digit, the first one that would cross
        // 0xffff, so the cursor never moves at all.
        check(
            str_number,
            FORTY_NINES,
            PORT_MAX,
            Err(StrError::Overflow),
            FORTY_NINES,
        );
    }

    /// `u->portnum = (unsigned short)port` at `lib/urlapi.c` L378, and the
    /// same cast at L1681.
    ///
    /// The cast is lossless for every value a maximum of `0xffff` lets
    /// through, which is why the C can afford to be that terse. A scanner
    /// that accepted more than its maximum would make the two disagree
    /// silently, so the property is asserted rather than assumed.
    #[test]
    fn an_accepted_port_survives_the_unsigned_short_cast() {
        for input in ["0", "1", "80", "443", "8080", "65535", "0000065535"] {
            let (outcome, cursor) = scan(str_number, input, PORT_MAX);
            assert!(cursor.is_empty(), "cursor after {input:?}");
            assert!(
                matches!(outcome, Ok(port) if u16::try_from(port).is_ok()),
                "{input:?} gave {outcome:?}"
            );
        }
    }

    /// The decimal scanner over the nine shapes every base is checked for.
    #[test]
    fn decimal_covers_every_shape() {
        // A plain value, and the exact maximum.
        check(str_number, "12345", PORT_MAX, Ok(12345), "");
        check(str_number, "65535", PORT_MAX, Ok(65535), "");
        // One above the maximum, and far above it.
        check(
            str_number,
            "65536",
            PORT_MAX,
            Err(StrError::Overflow),
            "65536",
        );
        check(
            str_number,
            "999999999",
            PORT_MAX,
            Err(StrError::Overflow),
            "999999999",
        );
        // Leading zeros, including a value that is nothing but zeros.
        check(str_number, "00000012345", PORT_MAX, Ok(12345), "");
        check(str_number, "000", PORT_MAX, Ok(0), "");
        // Empty input, and a first byte that is not a decimal digit. The
        // signs matter: `i64::from_str_radix` would accept both, and
        // `valid_digit` at L142-L143 accepts neither, so a port that
        // delegated would turn `"-1"` into a valid port.
        check(str_number, "", PORT_MAX, Err(StrError::NoNumber), "");
        check(str_number, "a1", PORT_MAX, Err(StrError::NoNumber), "a1");
        check(str_number, "-1", PORT_MAX, Err(StrError::NoNumber), "-1");
        check(str_number, "+1", PORT_MAX, Err(StrError::NoNumber), "+1");
        check(str_number, " 1", PORT_MAX, Err(StrError::NoNumber), " 1");
        // Trailing junk, left for the caller in full.
        check(str_number, "8080/path", PORT_MAX, Ok(8080), "/path");
        check(str_number, "192.168", UINT_MAX, Ok(192), ".168");
        // A NUL inside the slice stops the scan where the C's
        // NUL-terminated walk would stop.
        check(str_number, "80\u{0}9", PORT_MAX, Ok(80), "\u{0}9");
    }

    /// The hexadecimal scanner over the same nine shapes.
    #[test]
    fn hexadecimal_covers_every_shape() {
        // A plain value in both letter cases, and the exact maximum in both.
        check(str_hex, "7f", PORT_MAX, Ok(127), "");
        check(str_hex, "7F", PORT_MAX, Ok(127), "");
        check(str_hex, "ffff", PORT_MAX, Ok(65535), "");
        check(str_hex, "FFFF", PORT_MAX, Ok(65535), "");
        check(str_hex, "fFfF", PORT_MAX, Ok(65535), "");
        // One above the maximum, and far above it.
        check(str_hex, "10000", PORT_MAX, Err(StrError::Overflow), "10000");
        check(
            str_hex,
            "fffffff",
            PORT_MAX,
            Err(StrError::Overflow),
            "fffffff",
        );
        // Leading zeros.
        check(str_hex, "0007f", PORT_MAX, Ok(127), "");
        // Empty input, and first bytes that are not hexadecimal digits. The
        // `'x'` case is the one that matters: `ipv4_normalize` steps over
        // the `0x` itself at L499, so this scanner must never accept it.
        check(str_hex, "", PORT_MAX, Err(StrError::NoNumber), "");
        check(str_hex, "g", PORT_MAX, Err(StrError::NoNumber), "g");
        check(str_hex, "x7f", PORT_MAX, Err(StrError::NoNumber), "x7f");
        // Trailing junk, which for a hexadecimal address part is the dot
        // `ipv4_normalize` continues on at L514-L519.
        check(str_hex, "7f.1", UINT_MAX, Ok(127), ".1");
        check(str_hex, "ff:", PORT_MAX, Ok(255), ":");
        check(str_hex, "abcdefg", UINT_MAX, Ok(11_259_375), "g");
        // The top of the type, exactly and one past it, and a run long
        // enough to overflow an unchecked accumulator.
        check(str_hex, "7fffffffffffffff", i64::MAX, Ok(i64::MAX), "");
        check(
            str_hex,
            "8000000000000000",
            i64::MAX,
            Err(StrError::Overflow),
            "8000000000000000",
        );
        check(
            str_hex,
            FORTY_EFFS,
            i64::MAX,
            Err(StrError::Overflow),
            FORTY_EFFS,
        );
    }

    /// The octal scanner over the same nine shapes.
    #[test]
    fn octal_covers_every_shape() {
        // A plain value, and the exact maximum: 0o177777 is 65535.
        check(str_octal, "177", PORT_MAX, Ok(127), "");
        check(str_octal, "177777", PORT_MAX, Ok(65535), "");
        // One above the maximum, 0o200000 being 65536, and far above it.
        check(
            str_octal,
            "200000",
            PORT_MAX,
            Err(StrError::Overflow),
            "200000",
        );
        check(
            str_octal,
            "7777777",
            PORT_MAX,
            Err(StrError::Overflow),
            "7777777",
        );
        // Leading zeros, which for this scanner include the `'0'` that made
        // `ipv4_normalize` choose it in the first place at L497-L503.
        check(str_octal, "0177", PORT_MAX, Ok(127), "");
        check(str_octal, "0000", PORT_MAX, Ok(0), "");
        // Empty input, and first bytes that are not octal digits.
        check(str_octal, "", PORT_MAX, Err(StrError::NoNumber), "");
        check(str_octal, "8", PORT_MAX, Err(StrError::NoNumber), "8");
        check(str_octal, "9", PORT_MAX, Err(StrError::NoNumber), "9");
        check(str_octal, "x", PORT_MAX, Err(StrError::NoNumber), "x");
        // Trailing junk. `"08"` is the one worth remembering: a successful
        // zero that leaves an `'8'`, which the caller rejects.
        check(str_octal, "0177.1.1.1", UINT_MAX, Ok(127), ".1.1.1");
        check(str_octal, "08", UINT_MAX, Ok(0), "8");
        check(str_octal, "0779", UINT_MAX, Ok(63), "9");
        // The top of the type: 21 sevens are 0o777777777777777777777, which
        // is exactly `i64::MAX`, so 22 are one digit too many.
        check(
            str_octal,
            "777777777777777777777",
            i64::MAX,
            Ok(i64::MAX),
            "",
        );
        check(
            str_octal,
            "7777777777777777777777",
            i64::MAX,
            Err(StrError::Overflow),
            "7777777777777777777777",
        );
        check(
            str_octal,
            FORTY_SEVENS,
            i64::MAX,
            Err(StrError::Overflow),
            FORTY_SEVENS,
        );
    }

    /// The decimal scanner at the top of `i64`, where unchecked arithmetic
    /// would be caught.
    ///
    /// The exact maximum is accepted because the general branch's test is
    /// exact, and the next value up is rejected on its final digit. Neither
    /// may panic: an unchecked `num * 10 + digit` would overflow on the
    /// second of these in a debug build, and this test is how that would be
    /// found.
    #[test]
    fn decimal_holds_at_the_top_of_the_type() {
        check(
            str_number,
            "9223372036854775807",
            i64::MAX,
            Ok(i64::MAX),
            "",
        );
        check(
            str_number,
            "9223372036854775808",
            i64::MAX,
            Err(StrError::Overflow),
            "9223372036854775808",
        );
        check(
            str_number,
            FORTY_NINES,
            i64::MAX,
            Err(StrError::Overflow),
            FORTY_NINES,
        );
        // The same run, but bounded by the maximum a real caller passes.
        check(
            str_number,
            FORTY_NINES,
            UINT_MAX,
            Err(StrError::Overflow),
            FORTY_NINES,
        );
    }

    /// The low-maximum branch, `max < base`, at `lib/curlx/strparse.c`
    /// L172-L179.
    ///
    /// No caller in `lib/urlapi.c` reaches it today, its maxima being
    /// `0xffff` and `UINT_MAX`. It is ported and tested anyway, because it
    /// is the branch whose absence would let a future caller with a small
    /// maximum silently accept an out-of-range digit, which is the mistake
    /// the C comment at L172 exists to prevent.
    #[test]
    fn the_low_maximum_branch_matches_the_c() {
        check(str_number, "5", 5, Ok(5), "");
        // Note what the general branch would do with this one: `(5 - 7) / 10`
        // truncates to 0, `0 > 0` is false, and 7 would be accepted against
        // a maximum of 5. That is the whole reason for the branch.
        check(str_number, "7", 5, Err(StrError::Overflow), "7");
        check(str_number, "05", 5, Ok(5), "");
        check(str_number, "12", 5, Err(StrError::Overflow), "12");
        check(str_number, "5x", 5, Ok(5), "x");
        // A maximum of zero accepts zero, written with any number of digits.
        check(str_number, "0", 0, Ok(0), "");
        check(str_number, "000", 0, Ok(0), "");
        check(str_number, "1", 0, Err(StrError::Overflow), "1");
        // `base - 1` is the largest maximum that still takes this branch and
        // `base` the smallest that takes the other, so the pairs below
        // straddle the `max < base` test itself.
        check(str_number, "9", 9, Ok(9), "");
        check(str_number, "10", 9, Err(StrError::Overflow), "10");
        check(str_number, "10", 10, Ok(10), "");
        check(str_number, "11", 10, Err(StrError::Overflow), "11");
        check(str_hex, "f", 15, Ok(15), "");
        check(str_hex, "10", 15, Err(StrError::Overflow), "10");
        check(str_hex, "10", 16, Ok(16), "");
        check(str_octal, "7", 7, Ok(7), "");
        check(str_octal, "10", 7, Err(StrError::Overflow), "10");
        check(str_octal, "10", 8, Ok(8), "");
        // A non-digit still loses to the guard at L169-L170, which runs
        // before the maximum is looked at.
        check(str_octal, "8", 0, Err(StrError::NoNumber), "8");
    }

    /// A negative maximum, which is not a supported input.
    ///
    /// The C asserts `max >= 0` at `lib/curlx/strparse.c` L166 and that
    /// assertion compiles out of a release build, so what a release build
    /// actually does is take the low-maximum branch, where the first digit
    /// exceeds the maximum and reports `STRE_OVERFLOW`. Reproduced rather
    /// than improved on, and pinned here so that a later tidy-up cannot
    /// change it by accident.
    #[test]
    fn a_negative_maximum_rejects_every_digit() {
        check(str_number, "0", -1, Err(StrError::Overflow), "0");
        check(str_hex, "0", i64::MIN, Err(StrError::Overflow), "0");
        check(str_octal, "z", -1, Err(StrError::NoNumber), "z");
    }

    /// A failed scan moves nothing, asserted on the slice itself.
    ///
    /// Both of the C's failure returns are reached before `*linep = p` at
    /// L189, so a caller may inspect the same bytes again. Identity is
    /// asserted rather than equality, so that a port which rebuilt an equal
    /// slice from a moved pointer would still fail here.
    #[test]
    fn a_failed_scan_moves_nothing() {
        let input: &[u8] = b"65536";
        let mut cursor: &[u8] = input;
        assert_eq!(str_number(&mut cursor, PORT_MAX), Err(StrError::Overflow));
        assert!(
            cursor.as_ptr() == input.as_ptr() && cursor.len() == input.len(),
            "the cursor moved on failure"
        );
        // The same bytes, scanned again with a maximum that admits them.
        assert_eq!(str_number(&mut cursor, UINT_MAX), Ok(65536));
        assert!(cursor.is_empty(), "the cursor stopped short on success");
    }

    /// The walk `ipv4_normalize` performs at `lib/urlapi.c` L494-L528,
    /// reproduced over the scanners alone.
    ///
    /// The C picks a base from the first byte or two, scans one part, then
    /// looks at where the cursor stopped: it continues on `'.'`, finishes on
    /// the terminating NUL, and returns `HOST_NAME` for anything else. The
    /// forms in the comment at L466, `16843009`, `0x7f`, `0x7f.1` and
    /// `0177.1.1.1`, are all covered below.
    #[test]
    fn the_ipv4_walk_sees_what_the_c_walk_sees() {
        // A single decimal part, which the arity-0 arm at L531 spreads over
        // all four bytes of the address.
        check(str_number, "16843009", UINT_MAX, Ok(16_843_009), "");
        // Four decimal parts, taken one at a time.
        check(str_number, "192.168.0.1", UINT_MAX, Ok(192), ".168.0.1");
        check(str_number, "168.0.1", UINT_MAX, Ok(168), ".0.1");
        check(str_number, "0.1", UINT_MAX, Ok(0), ".1");
        check(str_number, "1", UINT_MAX, Ok(1), "");
        // A hexadecimal part, reached after L499 steps over the `0x`.
        check(str_hex, "7f", UINT_MAX, Ok(127), "");
        check(str_hex, "7f.1", UINT_MAX, Ok(127), ".1");
        // `"0x"` with nothing after it becomes empty input, which fails the
        // guard and makes `rc` non-zero at L508.
        check(str_hex, "", UINT_MAX, Err(StrError::NoNumber), "");
        // An octal part, scanned from its leading zero.
        check(str_octal, "0177.1.1.1", UINT_MAX, Ok(127), ".1.1.1");
        // The maximum a part may reach, and one past it. Note where the
        // rejection comes from: the scanner itself, not the per-arity range
        // tests at L530-L571, which only ever see a value the scanner
        // already accepted.
        check(str_number, "4294967295", UINT_MAX, Ok(4_294_967_295), "");
        check(
            str_number,
            "4294967296",
            UINT_MAX,
            Err(StrError::Overflow),
            "4294967296",
        );
    }

    /// The value of one digit, derived from a literal list by position
    /// rather than from a range test.
    ///
    /// Deriving it independently is the point: an expectation computed the
    /// same way as the implementation would reproduce the same off-by-one on
    /// both sides and prove nothing.
    fn expected_value(digits: &str, byte: u8) -> Option<i64> {
        digits
            .as_bytes()
            .iter()
            .position(|digit| *digit == byte)
            .and_then(|index| i64::try_from(index).ok())
    }

    /// `valid_digit` at `lib/curlx/strparse.c` L142-L143 and `curlx_hexval`
    /// at `lib/curlx/strparse.h` L111, checked over all 256 byte values.
    #[test]
    fn the_accepted_digit_sets_match_the_c_tables() {
        const OCTAL: &str = "01234567";
        const DECIMAL: &str = "0123456789";
        const HEX: &str = "0123456789abcdef";
        for byte in 0u8..=u8::MAX {
            // The hexadecimal set is the only case-insensitive one, so its
            // expectation folds the byte before looking it up. That fold is
            // what `curlx_hexasciitable` encodes in its two letter rows at
            // L151 and L153.
            let hex = expected_value(HEX, byte.to_ascii_lowercase());
            let octal = expected_value(OCTAL, byte);
            let decimal = expected_value(DECIMAL, byte);
            assert_eq!(
                Base::Octal.accepts(byte),
                octal.is_some(),
                "octal accepts {byte:#04x}"
            );
            assert_eq!(
                Base::Decimal.accepts(byte),
                decimal.is_some(),
                "decimal accepts {byte:#04x}"
            );
            assert_eq!(
                Base::Hex.accepts(byte),
                hex.is_some(),
                "hexadecimal accepts {byte:#04x}"
            );
            assert_eq!(
                Base::Octal.digit_value(byte),
                octal,
                "octal value of {byte:#04x}"
            );
            assert_eq!(
                Base::Decimal.digit_value(byte),
                decimal,
                "decimal value of {byte:#04x}"
            );
            assert_eq!(
                Base::Hex.digit_value(byte),
                hex,
                "hexadecimal value of {byte:#04x}"
            );
        }
    }

    /// The radices, and the accepted-set sizes that follow from them.
    ///
    /// `BASE_PROOF` already checks the boundaries at compile time. This adds
    /// the counts, which a boundary check cannot catch: a set that gained or
    /// lost a byte in its middle would pass every boundary test.
    #[test]
    fn the_bases_have_the_radices_and_widths_the_c_uses() {
        assert_eq!(Base::Octal.radix(), 8);
        assert_eq!(Base::Decimal.radix(), 10);
        assert_eq!(Base::Hex.radix(), 16);
        let width = |base: Base| (0u8..=u8::MAX).filter(|byte| base.accepts(*byte)).count();
        assert_eq!(width(Base::Octal), 8, "octal digits");
        assert_eq!(width(Base::Decimal), 10, "decimal digits");
        // 22, not 16: ten digits plus six letters in each case.
        assert_eq!(width(Base::Hex), 22, "hexadecimal digits");
    }

    /// Every scanner consumes the whole input when the whole input is
    /// digits, and reports an empty cursor for it.
    ///
    /// The empty cursor is what the `|| *portptr` half of `lib/urlapi.c`
    /// L375 tests, so a scanner that stopped one byte short would turn every
    /// valid port into `CURLUE_BAD_PORT_NUMBER`.
    #[test]
    fn a_complete_scan_leaves_an_empty_cursor() {
        for (scanner, input) in [
            (str_number as Scanner, "1234567890"),
            // Sixteen hexadecimal digits in mixed case, which is 0x0123456789abcdef
            // and comfortably inside the type, where twenty-two would not be.
            (str_hex as Scanner, "0123456789abcDEF"),
            (str_octal as Scanner, "01234567"),
        ] {
            let (outcome, cursor) = scan(scanner, input, i64::MAX);
            assert!(outcome.is_ok(), "{input:?} gave {outcome:?}");
            assert!(cursor.is_empty(), "cursor after {input:?}");
        }
    }
}
