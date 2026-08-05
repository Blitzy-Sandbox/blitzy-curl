// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Numeric address conversion: presentation form to bytes and back.
//!
//! `lib/urlapi.c` uses exactly one pair of address functions, at L433 and
//! L435, to canonicalize a bracketed IPv6 host. It parses the text to
//! sixteen bytes and formats those bytes back over the same buffer, so that
//! `[fe80::0000:20c:29ff:fe9c:409b]` is stored as
//! `[fe80::20c:29ff:fe9c:409b]` and `[0:0:0:0:0:0:0:0]` is stored as `[::]`.
//! That single call pair is the whole reason this module exists.
//!
//! # The finding that shapes this module
//!
//! The Agent Action Plan maps this module onto `curlx_inet_pton` at
//! `lib/curlx/inet_pton.c` L207 and `curlx_inet_ntop` at
//! `lib/curlx/inet_ntop.c` L210, and a port that translated those two
//! functions and stopped would be **less** faithful than what is written
//! below. Neither name is reliably a function. Read the headers:
//!
//! - `lib/curlx/inet_pton.h` L28 opens `#ifdef HAVE_INET_PTON`, and inside
//!   it L42-L43 read `#define curlx_inet_pton(x, y, z) inet_pton(x, y, z)`,
//!   with an Amiga cast variant at L39-L40. Only the `#else` arm at L45-L46
//!   declares curl's own `int curlx_inet_pton(int, const char *, void *);`
//! - `lib/curlx/inet_ntop.h` L28-L48 has the same shape, with
//!   `#define curlx_inet_ntop(af, addr, buf, size)` forwarding to
//!   `inet_ntop` at L43-L44 and the own-code prototype at L47.
//!
//! So the Vixie-derived implementations in the two `.c` files are curl's
//! **fallback**, compiled only where the platform lacks the system
//! functions. Both `.c` files wrap their entire body in the same `#ifdef`,
//! inverted.
//!
//! The reference build resolves that switch towards the platform:
//! `HAVE_INET_NTOP` and `HAVE_INET_PTON` are both defined in the generated
//! `curl_config.h`. The behavioral oracle for the parity diff is therefore
//! the C library's `inet_pton`/`inet_ntop`, not curl's in-tree copy of
//! them.
//!
//! # Why that distinction is not academic
//!
//! The two implementations disagree, and the disagreement is reachable
//! through the public URL API. Curl's copy of `inet_pton6` accepts a
//! trailing colon after a complete group, because its colon handler at
//! `lib/curlx/inet_pton.c` L140-L154 stores the group and lets the loop
//! end. The C library rejects it: modern glibc adds a check that the colon
//! is not the last byte. Measured on glibc 2.42, over a table of
//! forty-three vectors, those are the only two disagreements found, and
//! both are of that one kind:
//!
//! | Input | System | Curl's own copy |
//! |---|---|---|
//! | `1::2:` | 0, rejected | 1, accepted as `1::2` |
//! | `1:2:3:4:5:6:7:8:` | 0, rejected | 1, accepted as `1:2:3:4:5:6:7:8` |
//!
//! Linked against the reference libcurl, `https://[1::2:]/` and
//! `https://[1:2:3:4:5:6:7:8:]/` both return `CURLUE_BAD_IPV6`. A port
//! built on curl's own copy would accept both and rewrite the host, which
//! is a visible behavior change in a module whose entire acceptance
//! criterion is that behavior does not change.
//!
//! Formatting, by contrast, agrees exactly: over the same table the two
//! `inet_ntop` implementations produce identical output, including the
//! zero-run tie-break and the embedded-IPv4 special case.
//!
//! # What this module therefore does
//!
//! - **Primary path**, `mod system`: delegate to the platform's
//!   `inet_pton`/`inet_ntop`. This is the Rust spelling of the macro the
//!   reference build expands, so agreement is structural rather than
//!   tested-for.
//! - **Secondary path**, `mod fallback`: curl's Vixie-derived code, ported
//!   to safe Rust, in exactly the role it plays in curl. It is selected
//!   where the platform pair is unavailable.
//! - The selection is a target-based `#[cfg]`, per transformation rule T5,
//!   compile-time capability switches replacing preprocessor switches. It
//!   is deliberately **not** a Cargo feature: `Cargo.toml` fixes the
//!   feature set, and inventing a seventh flag to express a platform
//!   property would be the wrong instrument anyway.
//! - The fallback is additionally compiled under `cfg(test)` on every
//!   target, so the two paths can be compared directly and the two known
//!   disagreements are pinned by name rather than left to be discovered.
//!
//! `libc` does not declare `inet_pton` or `inet_ntop`, so the prototypes
//! are declared in an `extern "C"` block in `mod system`. That block is the
//! direct equivalent of the `#include <arpa/inet.h>` at
//! `lib/curlx/inet_pton.h` L36, and it adds no dependency: `libc` still
//! supplies the types and the address-family numbers.
//!
//! # Address families
//!
//! The two constants below take the platform's values through `libc`,
//! which is what makes them usable as arguments to the platform's
//! functions. No other module needs a platform header as a result: callers
//! use `inet::AF_INET6`.
//!
//! `lib/urlapi.c` L62-L64, `lib/curlx/inet_pton.c` L46-L48 and
//! `lib/curlx/inet_ntop.c` L46-L48 each carry
//! `#if !defined(USE_IPV6) && !defined(AF_INET6)` followed by
//! `#define AF_INET6 (AF_INET + 1)`. That invented number exists so that
//! IPv6 addresses still parse where the platform offers no name for the
//! family, and it is safe there precisely because nothing hands it to the
//! platform. The same condition and the same invented number are
//! reproduced below for the fallback targets, where `libc` carries no
//! address-family constants and nothing crosses into C.
//!
//! # Unsafe posture
//!
//! Calling the platform pair is FFI, which is the one context in which
//! specification section 1.3.2.1 permits `unsafe` outside `src/ffi.rs`.
//! Every block is as narrow as the call it wraps and carries a `// SAFETY:`
//! comment, per section 3.2.1.2. `mod fallback` contains no `unsafe` at
//! all, and the surface this module presents is entirely safe: slices and
//! arrays in, slices and integers out, so `parse/ipv6.rs` and
//! `parse/host.rs` need no `unsafe` of their own. Concentrating it here is
//! the point of the module.

use libc::c_int;

/// Length of a binary IPv4 address. `INADDRSZ` at
/// `lib/curlx/inet_pton.c` L38.
pub(crate) const ADDRSZ_IPV4: usize = 4;

/// Length of a binary IPv6 address. `IN6ADDRSZ` at
/// `lib/curlx/inet_pton.c` L37 and `lib/curlx/inet_ntop.c` L37, and the
/// width of the `char dest[16]` the caller declares at `lib/urlapi.c`
/// L431.
pub(crate) const ADDRSZ_IPV6: usize = 16;

/// `AF_INET`, from the platform, so that it can be passed to the
/// platform's `inet_pton` and `inet_ntop`.
#[cfg(unix)]
pub(crate) const AF_INET: c_int = libc::AF_INET;

/// `AF_INET` where `libc` carries no address-family constants, which is
/// also where `mod fallback` is selected and nothing crosses into C. The
/// number is the one every platform that names the family uses, and here
/// it serves only to tag which of the two conversions to run.
#[cfg(not(unix))]
pub(crate) const AF_INET: c_int = 2;

/// `AF_INET6`, from the platform, for the same reason as `AF_INET`.
#[cfg(unix)]
pub(crate) const AF_INET6: c_int = libc::AF_INET6;

/// `AF_INET6` where the platform offers no value for it, reproducing
/// `#define AF_INET6 (AF_INET + 1)` from `lib/urlapi.c` L63 under the same
/// condition the C code guards it with: no platform name available. Safe
/// for the same reason it is safe there, that this number never reaches the
/// platform.
///
/// The C expression is `AF_INET + 1`; it is spelled here as a saturating
/// addition, which is exact at this value, because the crate root denies the
/// bare operators and this module holds to that everywhere rather than
/// making an exception for a constant.
#[cfg(not(unix))]
pub(crate) const AF_INET6: c_int = AF_INET.saturating_add(1);

/// `inet_pton` succeeded and the destination was written.
///
/// The three return values are the documented contract at
/// `lib/curlx/inet_pton.c` L195-L198: 1 for a valid address, 0 for an
/// invalid one, -1 for any other error, with the destination untouched in
/// both failure cases. The exact numbers are behavior rather than
/// convention, because the caller at `lib/urlapi.c` L433 tests `!= 1` and
/// so treats 0 and -1 alike; a port that collapsed the three to a boolean
/// here would be discarding the distinction at the layer that owns it.
pub(crate) const PTON_SUCCESS: c_int = 1;

/// `inet_pton` found the input invalid for the family. Destination
/// untouched.
pub(crate) const PTON_INVALID: c_int = 0;

/// `inet_pton` failed for a reason other than the input being invalid,
/// which for both implementations means an unsupported address family.
/// Destination untouched.
pub(crate) const PTON_ERROR: c_int = -1;

// The three values above are pinned at compile time because they are ABI in
// everything but name: they cross between this module and its callers as
// bare integers, exactly as they do in C. The two family numbers are pinned
// as distinct, because either implementation's dispatch is meaningless
// otherwise. `tests::the_address_family_constants_are_the_platforms` checks
// the same facts at run time; these are here so that a bad edit cannot even
// build.
//
// The assertions are gathered into one block so that a single allow covers
// them. Clippy releases up to and including 1.75 report every constant
// assertion as optimized-out, which for a `const` block is the opposite of
// what happens: it is evaluated at compile time and nothing survives to be
// optimized. Later clippy exempts const contexts, so this is a
// compatibility allow with the crate's declared minimum toolchain rather
// than a suppressed finding.
#[allow(clippy::assertions_on_constants)]
const _: () = {
    assert!(PTON_SUCCESS == 1);
    assert!(PTON_INVALID == 0);
    assert!(PTON_ERROR == -1);
    assert!(AF_INET != AF_INET6);
};

/// The longest presentation form either family accepts:
/// `ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255`, forty-five bytes.
///
/// This is not a guess. `lib/curlx/inet_ntop.c` L97 sizes its scratch
/// buffer with `sizeof()` of that exact string, which is forty-six with the
/// terminator, and the bound holds on the parsing side too: an accepted
/// address is at most eight four-digit groups with seven separators, which
/// is thirty-nine, or at most six such groups followed by a dotted quad of
/// at most fifteen bytes, which is forty-five. A seventh group before the
/// quad fails the `(tp + INADDRSZ) <= endp` test at
/// `lib/curlx/inet_pton.c` L156. The bound was also checked empirically:
/// seven million random strings of length forty-six through eighty, drawn
/// from the only byte set either parser accepts, were rejected by the
/// system implementation and by curl's alike.
///
/// What is *produced* is shorter still, at most thirty-nine bytes, because
/// the dotted-quad output at `lib/curlx/inet_ntop.c` L155-L162 is reserved
/// for addresses whose leading groups are zero and so is never the long
/// form. Using the accepted bound for both directions is therefore
/// conservative, which is exactly what the C code does with its one
/// `sizeof()`.
///
/// Both backends assert against this bound rather than merely mentioning
/// it, so that a future edit to either scratch size cannot quietly break
/// the reasoning that depends on it.
const TEXT_MAX: usize = 45;

/// The implementation the platform selects, standing in for the
/// preprocessor switch at `lib/curlx/inet_pton.h` L28 and
/// `lib/curlx/inet_ntop.h` L28.
#[cfg(unix)]
use self::system as backend;

/// The implementation used where the platform pair is unavailable, which
/// is the `#else` arm of those two switches.
#[cfg(not(unix))]
use self::fallback as backend;

/// Convert a presentation-form address to its binary form.
///
/// `curlx_inet_pton` at `lib/curlx/inet_pton.c` L207-L219, which is the
/// system `inet_pton` in the reference build, as the module documentation
/// explains.
///
/// `src` is the address text. A terminator inside it ends the address, as
/// it does for the C string the C code receives; bytes after it are
/// ignored. `dst` is sixteen bytes, the width `lib/urlapi.c` L431
/// declares, and is written only on success. For `AF_INET` only the first
/// four bytes are written, exactly as the C code writes `INADDRSZ` bytes
/// through a `void *`.
///
/// Returns `PTON_SUCCESS`, `PTON_INVALID` or `PTON_ERROR`. The caller at
/// `lib/urlapi.c` L433 accepts only the first.
pub(crate) fn inet_pton(af: c_int, src: &[u8], dst: &mut [u8; ADDRSZ_IPV6]) -> c_int {
    backend::pton(af, src, dst)
}

/// Convert a binary address to its presentation form, in place.
///
/// `curlx_inet_ntop` at `lib/curlx/inet_ntop.c` L210-L221, which is the
/// system `inet_ntop` in the reference build.
///
/// `src` is the binary address and must be at least four bytes for
/// `AF_INET` or sixteen for `AF_INET6`; anything beyond that is ignored.
/// `dst.len()` **is** the C `size` argument, so the caller passes a slice
/// of exactly the extent it is willing to have written, which at
/// `lib/urlapi.c` L435 is `hlen + 1`: the address bytes plus the one slot
/// the dynamic buffer guarantees for a terminator.
///
/// On success the text is written to the front of `dst`, a terminator is
/// written after it, and the text length is returned. That length is what
/// the C caller then recomputes with `strlen` at `lib/urlapi.c` L436, and
/// returning it saves the caller a second scan. **It can be shorter than
/// the input**, which is the entire point of the call.
///
/// On failure `None` is returned, mirroring the C null, and `dst` is left
/// untouched. Failure is not hypothetical: the canonical form can be
/// *longer* than the input, so a buffer sized from the input can be too
/// small. `1::2:3:4:5:6:7` is fourteen bytes and canonicalizes to
/// `1:0:2:3:4:5:6:7`, which is fifteen, so the call at `lib/urlapi.c` L435
/// fails with `size` at fifteen and the host is stored unnormalized. The
/// reference libcurl round-trips `https://[1::2:3:4:5:6:7]/` unchanged for
/// exactly that reason, and this function reproduces it.
pub(crate) fn inet_ntop(af: c_int, src: &[u8], dst: &mut [u8]) -> Option<usize> {
    backend::ntop(af, src, dst)
}

/// The platform's `inet_pton` and `inet_ntop`, which is what the reference
/// build's `curlx_inet_pton` and `curlx_inet_ntop` macros expand to.
///
/// This module is the crate's second FFI island after `src/ffi.rs`. It
/// exists so that the conversion pair can be reached without `unsafe`
/// anywhere else: the two functions below take slices and arrays, validate
/// every precondition the C prototypes impose, and confine each `unsafe`
/// block to the call itself.
#[cfg(unix)]
mod system {
    use libc::{c_char, c_int, c_void, socklen_t};

    use super::{ADDRSZ_IPV4, ADDRSZ_IPV6, AF_INET, AF_INET6, PTON_ERROR, PTON_INVALID, TEXT_MAX};

    // The prototypes from `<arpa/inet.h>`, which `lib/curlx/inet_pton.h`
    // L36 and `lib/curlx/inet_ntop.h` L36 include for exactly these two
    // declarations. `libc` does not carry them, so they are declared here;
    // that is the whole content of the dependency on the platform, and no
    // additional crate is involved.
    //
    // The signatures are POSIX verbatim. `inet_ntop` returns `const char *`
    // and yields the buffer it was given on success, so the returned
    // pointer carries no information beyond null versus non-null, and the
    // code below reads only that.
    extern "C" {
        fn inet_pton(af: c_int, src: *const c_char, dst: *mut c_void) -> c_int;
        fn inet_ntop(
            af: c_int,
            src: *const c_void,
            dst: *mut c_char,
            size: socklen_t,
        ) -> *const c_char;
    }

    /// The largest text either scratch buffer needs to hold, and so the
    /// largest `size` worth handing to `inet_ntop`: the longest address plus
    /// its terminator.
    ///
    /// Deriving it from `TEXT_MAX` rather than writing a number is what ties
    /// the two use sites to the bound they depend on. In `ntop` it is the
    /// cap on the size argument, which cannot change the call's outcome
    /// because every size at or above it succeeds. In `CText` it is the text
    /// capacity, and a text that overruns it cannot be a valid address for
    /// either family.
    const SIZE_CAP: usize = TEXT_MAX.saturating_add(1);

    /// Bytes of scratch used to bridge between Rust slices and the
    /// null-terminated, caller-sized buffers the C prototypes expect.
    ///
    /// One byte more than `SIZE_CAP`, so that an `inet_ntop` which writes
    /// one byte beyond the size it was handed, as some have, still lands
    /// inside the array.
    const SCRATCH: usize = SIZE_CAP.saturating_add(1);

    // Both derivations are asserted rather than left to the reader. The
    // saturating forms above cannot saturate at these values, and the strict
    // inequalities are what the two use sites actually rely on. The crate
    // root denies the bare operators, which is why the derivations are
    // spelled as method calls. The allow is the same 1.75 compatibility
    // allow explained at the crate-level assertions.
    #[allow(clippy::assertions_on_constants)]
    const _: () = {
        assert!(SIZE_CAP > TEXT_MAX);
        assert!(SCRATCH > SIZE_CAP);
    };

    /// A null-terminated copy of an address text, on the stack.
    ///
    /// The C code is handed a `const char *` and scans to the terminator.
    /// Rust hands this module a slice with no terminator, so one has to be
    /// added, and doing it in a named type keeps the guarantee the safety
    /// comment on the `inet_pton` call depends upon in one place: `bytes`
    /// always contains a zero byte at or before index `SIZE_CAP`, which
    /// `SCRATCH` exceeds.
    struct CText {
        bytes: [u8; SCRATCH],
    }

    impl CText {
        /// Copy `src` up to its first zero byte, terminating the result.
        ///
        /// Returns `None` when the text does not fit, which is the caller's
        /// signal to report the address invalid. That is not a shortcut:
        /// `SIZE_CAP` exceeds `TEXT_MAX`, so no input that fails to fit can
        /// be a valid address for either family, and the platform returns 0
        /// for every one of them.
        fn new(src: &[u8]) -> Option<Self> {
            let mut text = Self {
                bytes: [0; SCRATCH],
            };
            let mut len = 0usize;
            for byte in src {
                // A zero byte ends the address, exactly as it ends the C
                // string at `lib/curlx/inet_pton.c` L73 and L132.
                if *byte == 0 {
                    break;
                }
                if len >= SIZE_CAP {
                    return None;
                }
                *text.bytes.get_mut(len)? = *byte;
                len = len.wrapping_add(1);
            }
            // The array was zero-filled and `len <= SIZE_CAP`, which is
            // below `SCRATCH`, so the byte at `len` is still zero and the
            // text is terminated.
            Some(text)
        }

        /// The text as a `const char *` for the duration of the borrow.
        fn as_ptr(&self) -> *const c_char {
            self.bytes.as_ptr().cast()
        }
    }

    /// `curlx_inet_pton` at `lib/curlx/inet_pton.c` L207-L219, resolved to
    /// the platform's `inet_pton`.
    pub(super) fn pton(af: c_int, src: &[u8], dst: &mut [u8; ADDRSZ_IPV6]) -> c_int {
        // The switch at L209-L217, kept here rather than delegated. The
        // platform rejects an unknown family identically, with -1 and
        // `EAFNOSUPPORT`, so this costs no fidelity, and it buys the safety
        // argument below its second half: the destination is known to be
        // wide enough for whichever of the two families is in play, and no
        // third family can reach the call.
        if af != AF_INET && af != AF_INET6 {
            return PTON_ERROR;
        }
        let Some(text) = CText::new(src) else {
            return PTON_INVALID;
        };
        // SAFETY: `src` is a pointer to `text.bytes`, which `CText::new`
        // guarantees holds a zero byte at or before index `SIZE_CAP`, an
        // index inside the array, so the callee's scan terminates inside
        // memory it may read in full; `text` outlives the call. `dst` is
        // `ADDRSZ_IPV6` bytes,
        // which is the width `AF_INET6` writes and more than the
        // `ADDRSZ_IPV4` bytes `AF_INET` writes, and the guard above admits
        // no other family. The two pointers cannot alias, being a shared
        // borrow of a local and a unique borrow of the caller's array.
        unsafe { inet_pton(af, text.as_ptr(), dst.as_mut_ptr().cast()) }
    }

    /// `curlx_inet_ntop` at `lib/curlx/inet_ntop.c` L210-L221, resolved to
    /// the platform's `inet_ntop`.
    pub(super) fn ntop(af: c_int, src: &[u8], dst: &mut [u8]) -> Option<usize> {
        // The switch at L212-L220, and with it the length the family reads
        // from `src`. An unknown family yields null there and `None` here.
        let need = match af {
            AF_INET => ADDRSZ_IPV4,
            AF_INET6 => ADDRSZ_IPV6,
            _ => return None,
        };
        let binary = src.get(..need)?;

        // The formatting is directed into scratch rather than into `dst`.
        // That is not a detour, it is what both C implementations do: each
        // formats into its own `tmp` and copies to the destination only
        // after the overflow check, at `lib/curlx/inet_ntop.c` L186-L195,
        // which is why a failed call leaves the destination untouched. Two
        // further properties follow from it, and the safety comment below
        // rests on both. Nothing the callee writes can land outside a local
        // array, whatever it does with the size it is given. And no
        // partially formatted address can ever be observed by the caller.
        //
        // The size handed to the callee is `dst.len()` capped at
        // `SIZE_CAP`. The cap cannot change the outcome: the callee fails
        // exactly when the text plus its terminator does not fit in the
        // size, the text is at most `TEXT_MAX` bytes, and `SIZE_CAP` is
        // `TEXT_MAX` plus one, so every size at or above the cap succeeds
        // and the cap picks one of them. Below the cap the size passes
        // through unchanged.
        let capped = if dst.len() < SIZE_CAP {
            dst.len()
        } else {
            SIZE_CAP
        };
        // Infallible, since `capped` is at most `SIZE_CAP`. Written as a
        // conversion rather than a cast so that the bound is enforced by the
        // type system instead of asserted in a comment.
        let size = socklen_t::try_from(capped).ok()?;
        let mut scratch = [0u8; SCRATCH];
        // SAFETY: `src` points at `binary`, which is exactly the `need`
        // bytes the family reads, and the `get` above returned `None`
        // rather than a short slice. `dst` points at `scratch`, a live
        // local array of `SCRATCH` bytes, and `size` is at most `SIZE_CAP`,
        // which the assertion above puts strictly below `SCRATCH`; so even
        // an implementation that writes one byte beyond the size it was
        // handed, as some have, stays inside the array. The
        // two pointers cannot alias, being a shared borrow of the caller's
        // slice and a unique borrow of a local.
        let written = unsafe {
            inet_ntop(
                af,
                binary.as_ptr().cast(),
                scratch.as_mut_ptr().cast(),
                size,
            )
        };
        if written.is_null() {
            // The C null return at L192 and L219, which `lib/urlapi.c`
            // L435 turns into "leave the host as it was".
            return None;
        }
        // The callee terminated the text, so its length is the offset of
        // the first zero byte. `None` here would mean a null-returning
        // contract violation, and is handled rather than assumed away.
        let len = scratch.iter().position(|byte| *byte == 0)?;
        // `len` bytes of text plus the terminator, which is what
        // `curlx_strcopy` writes at `lib/curlx/strcopy.c` L45-L46. The
        // `get_mut` is what keeps this sound if a platform ever succeeds
        // with a text that does not fit the caller's slice: the copy is
        // declined and the call reports failure, rather than overrunning.
        let total = len.wrapping_add(1);
        let target = dst.get_mut(..total)?;
        target.copy_from_slice(scratch.get(..total)?);
        Some(len)
    }
}

/// Curl's own conversion pair, ported to safe Rust.
///
/// This is `inet_pton4`, `inet_pton6`, `inet_ntop4` and `inet_ntop6` from
/// `lib/curlx/inet_pton.c` and `lib/curlx/inet_ntop.c`, in the role they
/// hold in curl: the implementation compiled where the platform offers no
/// `inet_pton` or `inet_ntop`. Those files place their whole contents
/// inside `#ifdef`s that select exactly that case.
///
/// The upstream attribution is part of the provenance and is reproduced
/// here rather than dropped. `lib/curlx/inet_pton.c` names the author of
/// `inet_pton4` at L61-L62, of `inet_pton6` at L112-L113, and of
/// `curlx_inet_pton` at L204-L205:
///
/// > author: Paul Vixie, 1996.
///
/// with `inet_pton6` additionally crediting Mark Andrews for the approach
/// at L110-L111. The `inet_ntop` side descends from the same lineage.
///
/// Two properties are worth stating before the code. There is no `unsafe`
/// in this module, and there is nothing for it to do: every operation is
/// arithmetic over `u32` and `u8` or a checked slice access. And the
/// arithmetic is written with the checked and wrapping operators
/// throughout, because the crate root denies bare arithmetic; each
/// substitution is justified where it is not obviously exact, which for the
/// group shifting and the octet accumulation is at the site.
///
/// This module is compiled under `cfg(test)` on every target as well, so
/// that the test module can hold it against the platform's implementation
/// and pin the two places they disagree.
#[cfg(any(not(unix), test))]
mod fallback {
    use libc::c_int;

    use super::{
        ADDRSZ_IPV4, ADDRSZ_IPV6, AF_INET, AF_INET6, PTON_ERROR, PTON_INVALID, PTON_SUCCESS,
        TEXT_MAX,
    };
    use crate::ctype::{hexval, is_digit, is_xdigit};

    /// Width of one IPv6 group in bytes. `INT16SZ` at
    /// `lib/curlx/inet_pton.c` L39 and `lib/curlx/inet_ntop.c` L39.
    const GROUPSZ: usize = 2;

    /// Groups in an IPv6 address, which the C code spells
    /// `IN6ADDRSZ / INT16SZ` at every use, as at `lib/curlx/inet_ntop.c`
    /// L103, L119 and L140.
    const GROUPS: usize = 8;

    /// `sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")`, the
    /// scratch width at `lib/curlx/inet_ntop.c` L97.
    ///
    /// That `sizeof()` is the longest text plus its terminator, so it is
    /// derived from `TEXT_MAX` rather than written out, which keeps the two
    /// from drifting apart if the bound is ever revisited.
    const TEXT_BUF: usize = TEXT_MAX.saturating_add(1);

    /// `sizeof("255.255.255.255")`, the scratch width at
    /// `lib/curlx/inet_ntop.c` L60.
    const QUAD_BUF: usize = 16;

    // The scratch has to hold the longest text plus its terminator, which is
    // what the C `sizeof()` expressions compute, and the group decomposition
    // has to cover the address exactly, which is the identity every
    // `IN6ADDRSZ / INT16SZ` in the C code relies on. The saturating form is
    // used because the crate root denies the bare operator, and it cannot
    // saturate at these values. The allow is the same 1.75 compatibility
    // allow explained at the crate-level assertions.
    #[allow(clippy::assertions_on_constants)]
    const _: () = {
        assert!(TEXT_BUF > TEXT_MAX);
        assert!(GROUPS.saturating_mul(GROUPSZ) == ADDRSZ_IPV6);
    };

    /// Write one byte at `at` and return the next position, or `None` when
    /// `at` is past the end.
    ///
    /// This stands in for the `*tp++ =` idiom that both C files use
    /// throughout. The C pointer arithmetic is unchecked and relies on the
    /// scratch buffers being provably wide enough; the check here is what
    /// lets the port make the same claim without an assertion or an
    /// `unsafe` block.
    fn push_byte(out: &mut [u8], at: usize, byte: u8) -> Option<usize> {
        *out.get_mut(at)? = byte;
        Some(at.wrapping_add(1))
    }

    /// One nibble as a lowercase ASCII hexadecimal digit.
    ///
    /// The `ldigits` table at `lib/curlx/inet_ntop.c` L166. The comment
    /// above it at L164-L165 explains why the C code keeps a local table
    /// instead of borrowing one, and the port keeps it local for a sharper
    /// reason: `ctype::hexbyte` reproduces `Curl_hexbyte`, which formats
    /// **upper** case, so reusing it would upper-case every normalized IPv6
    /// host in the crate. The table is written out as a literal because a
    /// reviewer diffing this against L166 should read the same sixteen
    /// characters.
    fn lower_hex_digit(value: u32) -> u8 {
        const LDIGITS: &[u8; 16] = b"0123456789abcdef";
        let nibble = usize::try_from(value & 0x0f)
            .ok()
            .and_then(|index| LDIGITS.get(index));
        match nibble {
            Some(digit) => *digit,
            // Unreachable: the mask admits only 0 through 15 and the table
            // covers all sixteen. A digit is returned rather than a panic
            // because the crate root denies panicking constructs, and
            // because a panic here could not be anything but a port defect.
            None => b'0',
        }
    }

    /// One octet in decimal, shortest form, appended at `at`.
    ///
    /// The four `%d` conversions in the `SNPRINTF` at
    /// `lib/curlx/inet_ntop.c` L66-L70. Written out because the crate
    /// formats without an allocator, and because `%d` of a value below 256
    /// is exactly this: no leading zeros, and at least one digit so that
    /// zero prints as `0`.
    fn push_decimal_octet(out: &mut [u8], at: usize, value: u8) -> Option<usize> {
        // The divisors are nonzero literals, so neither operation can fail;
        // the checked forms are used because the crate root denies the bare
        // operators.
        let hundreds = value.checked_div(100)?;
        let tens = value.checked_div(10)?.checked_rem(10)?;
        let ones = value.checked_rem(10)?;
        let mut pos = at;
        if hundreds != 0 {
            pos = push_byte(out, pos, b'0'.wrapping_add(hundreds))?;
        }
        if hundreds != 0 || tens != 0 {
            pos = push_byte(out, pos, b'0'.wrapping_add(tens))?;
        }
        push_byte(out, pos, b'0'.wrapping_add(ones))
    }

    /// Store one IPv6 group in network order at `at`.
    ///
    /// `*tp++ = (val >> 8) & 0xff; *tp++ = val & 0xff;` at
    /// `lib/curlx/inet_pton.c` L150-L151 and again at L167-L168. Both
    /// conversions are exact: the caller has already rejected a fifth
    /// hexadecimal digit, so `value` is at most `0xffff` and each masked
    /// half fits in a byte.
    fn push_group(tmp: &mut [u8; ADDRSZ_IPV6], at: usize, value: u32) -> Option<usize> {
        let high = u8::try_from(value.wrapping_shr(8) & 0xff).ok()?;
        let low = u8::try_from(value & 0xff).ok()?;
        let next = push_byte(tmp, at, high)?;
        push_byte(tmp, next, low)
    }

    /// `curlx_inet_pton` at `lib/curlx/inet_pton.c` L207-L219.
    pub(super) fn pton(af: c_int, src: &[u8], dst: &mut [u8; ADDRSZ_IPV6]) -> c_int {
        match af {
            // L210-L211. The IPv4 conversion writes `ADDRSZ_IPV4` bytes
            // through what C types as `void *`, so a wider destination is
            // exactly as acceptable here as it is there.
            AF_INET => pton4(src, dst),
            // L212-L213.
            AF_INET6 => pton6(src, dst),
            // L214-L216, which sets `EAFNOSUPPORT` and returns -1. The
            // errno write is not reproduced: nothing in the URL API reads
            // it, `lib/urlapi.c` L433 branches on the return value alone,
            // and writing the platform's thread-local errno from Rust would
            // be a side effect the port does not need.
            _ => PTON_ERROR,
        }
    }

    /// `curlx_inet_ntop` at `lib/curlx/inet_ntop.c` L210-L221.
    pub(super) fn ntop(af: c_int, src: &[u8], dst: &mut [u8]) -> Option<usize> {
        match af {
            // L213-L214 and L215-L216.
            AF_INET => ntop4(src, dst),
            AF_INET6 => ntop6(src, dst),
            // L217-L219, the null return. As in `pton`, the errno write is
            // not reproduced.
            _ => None,
        }
    }

    /// `inet_pton4` at `lib/curlx/inet_pton.c` L64-L101: a dotted quad,
    /// with none of the hexadecimal and shorthand forms `inet_aton` allows.
    ///
    /// `dst` needs at least `ADDRSZ_IPV4` bytes and is written only on
    /// success, which is the "does not touch `dst` unless it is returning
    /// 1" note at L59-L60. The C code achieves that with a local `tmp` and
    /// a closing `memcpy` at L99; so does this.
    fn pton4(src: &[u8], dst: &mut [u8]) -> c_int {
        let mut tmp = [0u8; ADDRSZ_IPV4];
        // `tp` at L67, as an index rather than a pointer. `*tp = 0` at L72
        // is the zero-filled array.
        let mut tp = 0usize;
        let mut saw_digit = false;
        let mut octets = 0u32;
        for byte in src {
            let ch = *byte;
            // The `while((ch = *src++) != '\0')` at L73 stops at the
            // terminator of the C string.
            if ch == 0 {
                break;
            }
            if is_digit(ch) {
                let Some(slot) = tmp.get_mut(tp) else {
                    return PTON_INVALID;
                };
                let current = *slot;
                let digit = ch.wrapping_sub(b'0');
                // `(*tp * 10) + (ch - '0')` at L75. C computes it in
                // `unsigned int` and rejects `val > 255` at L79-L80. On
                // `u8` that rejection is exactly the overflow: `*tp` is at
                // most 255 and the digit at most 9, so the sum exceeds 255
                // precisely when it does not fit in a byte.
                let value = current
                    .checked_mul(10)
                    .and_then(|scaled| scaled.checked_add(digit));
                // L77-L78, in C's order: a second digit after a lone zero
                // is rejected, which is what forbids leading zeros.
                if saw_digit && current == 0 {
                    return PTON_INVALID;
                }
                // L79-L80.
                let Some(value) = value else {
                    return PTON_INVALID;
                };
                *slot = value;
                // L82-L86: `if(++octets > 4) return 0;`
                if !saw_digit {
                    octets = octets.wrapping_add(1);
                    if octets > 4 {
                        return PTON_INVALID;
                    }
                    saw_digit = true;
                }
            } else if ch == b'.' && saw_digit {
                // L88-L93. The guard at L89-L90 is what keeps `*++tp` at
                // L91 inside the four-byte scratch, and the checked access
                // below records that rather than trusting it.
                if octets == 4 {
                    return PTON_INVALID;
                }
                tp = tp.wrapping_add(1);
                let Some(slot) = tmp.get_mut(tp) else {
                    return PTON_INVALID;
                };
                *slot = 0;
                saw_digit = false;
            } else {
                // L94-L95.
                return PTON_INVALID;
            }
        }
        // L97-L98: a quad needs all four octets.
        if octets < 4 {
            return PTON_INVALID;
        }
        // L99, the `memcpy` that makes the write-on-success promise true.
        let Some(target) = dst.get_mut(..ADDRSZ_IPV4) else {
            return PTON_INVALID;
        };
        target.copy_from_slice(&tmp);
        PTON_SUCCESS
    }

    /// `inet_pton6` at `lib/curlx/inet_pton.c` L115-L190: an
    /// [RFC 1884 2.2] address, with `::` shorthand and an optional trailing
    /// dotted quad.
    ///
    /// Written on to `dst` only on success, per the note at L107-L109,
    /// which also records that a `::` in an otherwise full address is
    /// silently ignored.
    ///
    /// # The divergence this function embodies
    ///
    /// This is the code that accepts a trailing colon where the platform
    /// rejects one, as the module documentation sets out with measurements.
    /// The cause is here: the colon arm at L140-L154 stores the group it
    /// has accumulated and continues, and nothing afterwards notices that
    /// the colon was the final byte, so `1::2:` and `1:2:3:4:5:6:7:8:` both
    /// come out valid. That is reproduced faithfully, per transformation
    /// rule T6, and pinned by a test that names both inputs.
    ///
    /// [RFC 1884 2.2]: https://www.rfc-editor.org/rfc/rfc1884#section-2.2
    fn pton6(src: &[u8], dst: &mut [u8; ADDRSZ_IPV6]) -> c_int {
        // The address ends at the first zero byte, as the C string does at
        // L132.
        let text = match src.iter().position(|byte| *byte == 0) {
            Some(nul) => src.get(..nul),
            None => Some(src),
        };
        let Some(text) = text else {
            return PTON_INVALID;
        };

        // L122-L124: a zeroed scratch, its end, and no `::` seen yet.
        let mut tmp = [0u8; ADDRSZ_IPV6];
        let endp = ADDRSZ_IPV6;
        let mut tp = 0usize;
        let mut colonp: Option<usize> = None;

        // L125-L128. A leading colon is only legal as the first half of
        // `::`, and the C code advances past it before the loop so that the
        // loop sees the second colon and records the run there.
        let mut pos = 0usize;
        if text.first() == Some(&b':') {
            pos = 1;
            if text.get(1) != Some(&b':') {
                return PTON_INVALID;
            }
        }

        // L129-L131.
        let mut curtok = pos;
        let mut saw_xdigit = 0u32;
        let mut value = 0u32;

        while let Some(byte) = text.get(pos) {
            let ch = *byte;
            pos = pos.wrapping_add(1);
            if is_xdigit(ch) {
                // L133-L139. The shift happens before the count is checked,
                // so a fifth digit is rejected only after `value` has
                // already taken it; the order is kept because the result is
                // the same and the shape is easier to diff.
                let Some(digit) = hexval(ch) else {
                    // Unreachable: `is_xdigit` accepts exactly the bytes
                    // `hexval` converts, which a test in `ctype` pins over
                    // all 256 values.
                    return PTON_INVALID;
                };
                value = value.wrapping_shl(4) | u32::from(digit);
                saw_xdigit = saw_xdigit.wrapping_add(1);
                if saw_xdigit > 4 {
                    return PTON_INVALID;
                }
                continue;
            }
            if ch == b':' {
                // L140-L154.
                curtok = pos;
                if saw_xdigit == 0 {
                    // A second `::` is not allowed; the first one records
                    // where the zero run will be inserted.
                    if colonp.is_some() {
                        return PTON_INVALID;
                    }
                    colonp = Some(tp);
                    continue;
                }
                // L148-L149.
                if tp.wrapping_add(GROUPSZ) > endp {
                    return PTON_INVALID;
                }
                let Some(next) = push_group(&mut tmp, tp, value) else {
                    return PTON_INVALID;
                };
                tp = next;
                saw_xdigit = 0;
                value = 0;
                continue;
            }
            // L156-L161: a dot hands the rest of the token to the IPv4
            // parser, which consumes the remainder of the string, so the
            // loop ends here on success. All three conditions have to hold;
            // any of them failing falls through to the rejection below,
            // exactly as the single `if` at L156 does.
            if ch == b'.' && tp.wrapping_add(ADDRSZ_IPV4) <= endp {
                let rest = text.get(curtok..).unwrap_or_default();
                if let Some(room) = tmp.get_mut(tp..) {
                    if pton4(rest, room) > 0 {
                        // L158-L160. Clearing `saw_xdigit` is not
                        // housekeeping: the quad's own leading digits were
                        // counted by the hexadecimal arm above, and leaving
                        // the count set would make the flush after the loop
                        // append a phantom group and corrupt every
                        // IPv4-suffixed address.
                        tp = tp.wrapping_add(ADDRSZ_IPV4);
                        saw_xdigit = 0;
                        break;
                    }
                }
            }
            // L162.
            return PTON_INVALID;
        }

        // L164-L169: a trailing group that no colon flushed. The loop above
        // leaves `saw_xdigit` at zero when it broke out through the IPv4
        // branch, matching L159.
        if saw_xdigit != 0 {
            if tp.wrapping_add(GROUPSZ) > endp {
                return PTON_INVALID;
            }
            let Some(next) = push_group(&mut tmp, tp, value) else {
                return PTON_INVALID;
            };
            tp = next;
        }

        // L170-L185: expand `::` by moving what follows it to the end and
        // zeroing what it vacated. The C code does the move by hand, with
        // the comment at L171-L174 explaining that it does not trust
        // `memmove` with overlapping regions; the port keeps the same
        // element-by-element order so that the two read alike.
        if let Some(colon) = colonp {
            // L178-L179: `::` has to stand for at least one group, so a
            // full address leaves it nothing to expand into.
            if tp == endp {
                return PTON_INVALID;
            }
            // `n = tp - colonp` at L175. `tp` never moves below `colon`,
            // which is where it stood when the run was recorded.
            let n = tp.wrapping_sub(colon);
            let mut i = 1usize;
            while i <= n {
                // `*(endp - i) = *(colonp + n - i); *(colonp + n - i) = 0;`
                // at L181-L182, where `colonp + n` is `tp`. Source and
                // destination cannot coincide, because that would need
                // `tp == endp`, which the guard above already rejected.
                let from = tp.wrapping_sub(i);
                let to = endp.wrapping_sub(i);
                let Some(moved) = tmp.get(from).copied() else {
                    return PTON_INVALID;
                };
                let Some(slot) = tmp.get_mut(to) else {
                    return PTON_INVALID;
                };
                *slot = moved;
                let Some(slot) = tmp.get_mut(from) else {
                    return PTON_INVALID;
                };
                *slot = 0;
                i = i.wrapping_add(1);
            }
            tp = endp;
        }

        // L186-L187: anything short of a full sixteen bytes is invalid.
        if tp != endp {
            return PTON_INVALID;
        }
        // L188, the write-on-success `memcpy`.
        *dst = tmp;
        PTON_SUCCESS
    }

    /// `inet_ntop4` at `lib/curlx/inet_ntop.c` L58-L83.
    ///
    /// Returns the length of the text written, which is what the C caller
    /// recovers with `strlen` at L160, or `None` for the C null. `dst.len()`
    /// is the C `size`.
    ///
    /// The `DEBUGASSERT(size >= 16)` at L63 is not reproduced. It is a
    /// debug-build assertion about a caller, not behavior, and the crate
    /// root denies panicking constructs; the `size` check at L73 that does
    /// affect the result is reproduced exactly.
    fn ntop4(src: &[u8], dst: &mut [u8]) -> Option<usize> {
        let quad = src.get(..ADDRSZ_IPV4)?;
        // The `tmp` at L60 and the `SNPRINTF` at L66-L70, which cannot
        // overflow that buffer and so needs no size check of its own.
        let mut tmp = [0u8; QUAD_BUF];
        let mut len = 0usize;
        for (index, octet) in quad.iter().enumerate() {
            if index != 0 {
                len = push_byte(&mut tmp, len, b'.')?;
            }
            len = push_decimal_octet(&mut tmp, len, *octet)?;
        }
        // L72-L80. The zero-length arm cannot be reached, since four octets
        // always produce at least seven bytes, and it is kept because the C
        // code checks it. The `>=` is the load-bearing half: it demands room
        // for the terminator as well as the text.
        if len == 0 || len >= dst.len() {
            return None;
        }
        // L81, `curlx_strcopy`, which copies `len` bytes and terminates at
        // `dst[len]`, per `lib/curlx/strcopy.c` L45-L46.
        let target = dst.get_mut(..len)?;
        target.copy_from_slice(tmp.get(..len)?);
        *dst.get_mut(len)? = 0;
        Some(len)
    }

    /// The longest run of zero groups, as `inet_ntop6` tracks it in its two
    /// local `{ int base; int len; }` structures at
    /// `lib/curlx/inet_ntop.c` L99-L102.
    ///
    /// The C code spells "no run" as `base == -1`; this is `None` instead,
    /// which is why nothing here needs a signed index.
    #[derive(Clone, Copy)]
    struct Run {
        base: usize,
        len: usize,
    }

    /// `if(best.base == -1 || cur.len > best.len) best = cur;` at
    /// `lib/curlx/inet_ntop.c` L129-L130 and again at L134-L135.
    ///
    /// The comparison is strictly greater, so the **first** of two runs of
    /// equal length wins. That tie-break is observable and is asserted by
    /// curl's own test suite: `tests/libtest/lib1560.c` L616-L617 requires
    /// `https://[fe80:0:0:0:409b::]:80/moo` to come out as
    /// `https://[fe80::409b:0:0:0]:80/moo`, where the two three-group runs
    /// tie and the earlier one is compressed.
    fn longer(best: Option<Run>, run: Run) -> Option<Run> {
        match best {
            Some(current) if run.len <= current.len => Some(current),
            _ => Some(run),
        }
    }

    /// `inet_ntop6` at `lib/curlx/inet_ntop.c` L88-L197.
    ///
    /// Returns the length of the text written, or `None` for the C null.
    /// `dst.len()` is the C `size`.
    fn ntop6(src: &[u8], dst: &mut [u8]) -> Option<usize> {
        let binary = src.get(..ADDRSZ_IPV6)?;

        // L106-L112: the byte array as groups, big-endian. The shift at
        // L112 is `(1 - (i % 2)) << 3`, which is eight for an even index
        // and zero for an odd one.
        let mut words = [0u32; GROUPS];
        for (index, byte) in binary.iter().enumerate() {
            let slot = words.get_mut(index.wrapping_div(2))?;
            let shift = if index.wrapping_rem(2) == 0 {
                8u32
            } else {
                0u32
            };
            *slot |= u32::from(*byte).wrapping_shl(shift);
        }

        // L114-L135: find the run to compress.
        let mut best: Option<Run> = None;
        let mut cur: Option<Run> = None;
        for (index, word) in words.iter().enumerate() {
            if *word == 0 {
                cur = Some(match cur {
                    Some(run) => Run {
                        base: run.base,
                        len: run.len.wrapping_add(1),
                    },
                    None => Run {
                        base: index,
                        len: 1,
                    },
                });
            } else if let Some(run) = cur {
                best = longer(best, run);
                cur = None;
            }
        }
        if let Some(run) = cur {
            best = longer(best, run);
        }
        // L136-L137: a single zero group is written out rather than
        // compressed, because `::` standing for one group saves nothing and
        // RFC 5952 4.2.2 forbids it.
        if let Some(run) = best {
            if run.len < 2 {
                best = None;
            }
        }

        // L138-L178: format into the local scratch.
        let mut tmp = [0u8; TEXT_BUF];
        let mut len = 0usize;
        let mut index = 0usize;
        while index < GROUPS {
            // L141-L146: inside the compressed run, emit one colon at its
            // start and skip the rest. The colon that closes the run comes
            // from the `if(i)` below, or from the trailing-run arm at L182.
            if let Some(run) = best {
                if index >= run.base && index < run.base.wrapping_add(run.len) {
                    if index == run.base {
                        len = push_byte(&mut tmp, len, b':')?;
                    }
                    index = index.wrapping_add(1);
                    continue;
                }
            }
            // L148-L151.
            if index != 0 {
                len = push_byte(&mut tmp, len, b':')?;
            }
            // L153-L156: an address whose first six groups are zero, or
            // whose first five are zero and whose sixth is `ffff`, has its
            // last four bytes written as a dotted quad. That is what keeps
            // `::ffff:192.0.2.1` and `::192.0.2.1` in the form they were
            // given.
            let embedded = index == 6
                && match best {
                    Some(run) => {
                        run.base == 0
                            && (run.len == 6
                                || (run.len == 5 && words.get(5).copied() == Some(0xffff)))
                    }
                    None => false,
                };
            if embedded {
                // L157-L161. The size handed on is the room left in the
                // scratch, `sizeof(tmp) - (tp - tmp)`, and the C code then
                // advances by `strlen`, which is the returned length here.
                let quad = binary.get(12..)?;
                let room = tmp.get_mut(len..)?;
                len = len.wrapping_add(ntop4(quad, room)?);
                break;
            }
            // L163-L177: one group in lowercase hexadecimal with leading
            // zeros suppressed. The three conditions test cumulative masks,
            // which is what makes the suppression work: a digit is emitted
            // once any higher nibble is set.
            let word = *words.get(index)?;
            if word & 0xf000 != 0 {
                len = push_byte(&mut tmp, len, lower_hex_digit(word.wrapping_shr(12)))?;
            }
            if word & 0xff00 != 0 {
                len = push_byte(&mut tmp, len, lower_hex_digit(word.wrapping_shr(8)))?;
            }
            if word & 0xfff0 != 0 {
                len = push_byte(&mut tmp, len, lower_hex_digit(word.wrapping_shr(4)))?;
            }
            len = push_byte(&mut tmp, len, lower_hex_digit(word))?;
            index = index.wrapping_add(1);
        }

        // L180-L183: a run that reaches the end needs a second colon, since
        // the loop emitted only the one that opened it.
        if let Some(run) = best {
            if run.base.wrapping_add(run.len) == GROUPS {
                len = push_byte(&mut tmp, len, b':')?;
            }
        }

        // L185-L193. As in `ntop4`, the `>=` demands room for the
        // terminator too, and reaching this check having formatted into a
        // local is what leaves `dst` untouched on failure.
        if len >= dst.len() {
            return None;
        }
        // L195, `curlx_strcopy` again.
        let target = dst.get_mut(..len)?;
        target.copy_from_slice(tmp.get(..len)?);
        *dst.get_mut(len)? = 0;
        Some(len)
    }
}

#[cfg(test)]
mod tests {
    use libc::c_int;

    use super::{
        fallback, inet_ntop, inet_pton, ADDRSZ_IPV4, ADDRSZ_IPV6, AF_INET, AF_INET6, PTON_ERROR,
        PTON_INVALID, PTON_SUCCESS, TEXT_MAX,
    };

    /// A parse entry point, so that one test body can drive either backend.
    type PtonFn = fn(c_int, &[u8], &mut [u8; ADDRSZ_IPV6]) -> c_int;

    /// A format entry point, likewise.
    type NtopFn = fn(c_int, &[u8], &mut [u8]) -> Option<usize>;

    /// Curl's own conversion pair, which is compiled on every target under
    /// `cfg(test)` precisely so that it can appear here.
    const OWN: (PtonFn, NtopFn) = (fallback::pton, fallback::ntop);

    /// The platform's conversion pair, which is the reference build's
    /// behavioral oracle.
    #[cfg(unix)]
    const SYS: (PtonFn, NtopFn) = (super::system::pton, super::system::ntop);

    /// A formatted address, held without an allocator so that these tests
    /// impose no requirement the crate does not already meet.
    struct Text {
        bytes: [u8; 64],
        len: usize,
    }

    impl Text {
        const EMPTY: Self = Self {
            bytes: [0; 64],
            len: 0,
        };

        fn as_bytes(&self) -> &[u8] {
            self.bytes.get(..self.len).unwrap_or_default()
        }
    }

    /// Bytes as text for an assertion message, without risking a panic on
    /// input a test deliberately made invalid.
    fn show(bytes: &[u8]) -> &str {
        core::str::from_utf8(bytes).unwrap_or("<not text>")
    }

    /// What one backend made of one input, end to end: the tri-state parse
    /// result and, on success, the canonical form it formats back to. This
    /// is the `curlx_inet_pton` then `curlx_inet_ntop` sequence at
    /// `lib/urlapi.c` L433-L435, with a buffer generous enough that the
    /// formatting step cannot fail for want of room.
    fn round_trip(backend: (PtonFn, NtopFn), text: &[u8]) -> (c_int, Option<Text>) {
        let (pton, ntop) = backend;
        let mut binary = [0u8; ADDRSZ_IPV6];
        let rc = pton(AF_INET6, text, &mut binary);
        if rc != PTON_SUCCESS {
            return (rc, None);
        }
        let mut out = Text::EMPTY;
        let len = ntop(AF_INET6, &binary, &mut out.bytes);
        match len {
            Some(len) => {
                out.len = len;
                (rc, Some(out))
            }
            None => (rc, None),
        }
    }

    /// How curl's own parser treats a vector, relative to the platform's.
    enum Own {
        /// Same tri-state result and, where valid, same canonical form.
        /// This is the case for every vector but two.
        Agrees,
        /// Curl's parser accepts what the platform rejects, canonicalizing
        /// it to the given text. Both instances are trailing colons, and
        /// both are reproduced deliberately: see `fallback::pton6`.
        Accepts(&'static str),
    }

    /// One conversion vector.
    struct Vector {
        /// Presentation input.
        text: &'static str,
        /// The platform's canonical form, or `None` when it rejects the
        /// input.
        system: Option<&'static str>,
        /// What curl's own parser does with it.
        own: Own,
    }

    /// The shared table both backends are held to.
    ///
    /// Every expectation here was captured from glibc 2.42 and, for the two
    /// divergent rows, from curl's own code compiled from
    /// `lib/curlx/inet_pton.c` unchanged. The rows are grouped by the
    /// property they pin, and the grouping is the point: each one covers a
    /// branch of `inet_ntop6` or a rejection in `inet_pton6` that would
    /// otherwise be untested.
    const VECTORS: &[Vector] = &[
        // The two degenerate forms, and the shortest address there is.
        Vector {
            text: "::",
            system: Some("::"),
            own: Own::Agrees,
        },
        Vector {
            text: "::1",
            system: Some("::1"),
            own: Own::Agrees,
        },
        Vector {
            text: "1::",
            system: Some("1::"),
            own: Own::Agrees,
        },
        // Ordinary compressed and fully expanded forms.
        Vector {
            text: "2001:db8::1",
            system: Some("2001:db8::1"),
            own: Own::Agrees,
        },
        Vector {
            text: "1:2:3:4:5:6:7:8",
            system: Some("1:2:3:4:5:6:7:8"),
            own: Own::Agrees,
        },
        Vector {
            text: "abcd:ef01:2345:6789:abcd:ef01:2345:6789",
            system: Some("abcd:ef01:2345:6789:abcd:ef01:2345:6789"),
            own: Own::Agrees,
        },
        // Uppercase input, which must come out lowercase: the table at
        // `lib/curlx/inet_ntop.c` L166 is lowercase, and `ctype::hexbyte`
        // would have produced upper.
        Vector {
            text: "2001:DB8::1",
            system: Some("2001:db8::1"),
            own: Own::Agrees,
        },
        Vector {
            text: "FE80::1",
            system: Some("fe80::1"),
            own: Own::Agrees,
        },
        // Leading zeros within a group are dropped.
        Vector {
            text: "0000:0000:0000:0000:0000:0000:0000:0001",
            system: Some("::1"),
            own: Own::Agrees,
        },
        Vector {
            text: "fe80::0202:b3ff:fe1e:8329",
            system: Some("fe80::202:b3ff:fe1e:8329"),
            own: Own::Agrees,
        },
        // A zero run at the start, in the middle, and at the end. The last
        // is the one that needs the extra colon at
        // `lib/curlx/inet_ntop.c` L182-L183.
        Vector {
            text: "0:0:0:1:2:3:4:5",
            system: Some("::1:2:3:4:5"),
            own: Own::Agrees,
        },
        Vector {
            text: "1:2:0:0:0:6:7:8",
            system: Some("1:2::6:7:8"),
            own: Own::Agrees,
        },
        Vector {
            text: "1:2:3:4:5:0:0:0",
            system: Some("1:2:3:4:5::"),
            own: Own::Agrees,
        },
        // The longer of two runs wins, whichever side it is on.
        Vector {
            text: "1:0:0:0:2:0:0:3",
            system: Some("1::2:0:0:3"),
            own: Own::Agrees,
        },
        Vector {
            text: "1:0:0:2:0:0:0:3",
            system: Some("1:0:0:2::3"),
            own: Own::Agrees,
        },
        // Two runs of equal length: the first wins, because the comparison
        // at `lib/curlx/inet_ntop.c` L129 is strictly greater. This exact
        // address is asserted by `tests/libtest/lib1560.c` L616-L617.
        Vector {
            text: "fe80:0:0:0:409b::",
            system: Some("fe80::409b:0:0:0"),
            own: Own::Agrees,
        },
        Vector {
            text: "1:0:0:2:0:0:3:4",
            system: Some("1::2:0:0:3:4"),
            own: Own::Agrees,
        },
        // A run of one is written out rather than compressed, per L136-L137.
        Vector {
            text: "1:0:2:3:4:5:6:7",
            system: Some("1:0:2:3:4:5:6:7"),
            own: Own::Agrees,
        },
        Vector {
            text: "::1:2:3:4:5:6:7",
            system: Some("0:1:2:3:4:5:6:7"),
            own: Own::Agrees,
        },
        Vector {
            text: "fe80:0:a:0:409b::",
            system: Some("fe80:0:a:0:409b::"),
            own: Own::Agrees,
        },
        // The embedded-IPv4 branch at L153-L162, in all four shapes its
        // condition admits and one that it does not.
        Vector {
            text: "::ffff:192.0.2.1",
            system: Some("::ffff:192.0.2.1"),
            own: Own::Agrees,
        },
        Vector {
            text: "::192.0.2.1",
            system: Some("::192.0.2.1"),
            own: Own::Agrees,
        },
        Vector {
            text: "0:0:0:0:0:0:1.2.3.4",
            system: Some("::1.2.3.4"),
            own: Own::Agrees,
        },
        Vector {
            text: "::255.255.255.255",
            system: Some("::255.255.255.255"),
            own: Own::Agrees,
        },
        Vector {
            text: "::0.0.0.0",
            system: Some("::"),
            own: Own::Agrees,
        },
        // Five leading zero groups with a sixth that is not `ffff` fails
        // the L156 condition, so the quad is printed as two groups instead.
        Vector {
            text: "0:0:0:0:0:1:1.2.3.4",
            system: Some("::1:102:304"),
            own: Own::Agrees,
        },
        Vector {
            text: "::ffff:0:1.2.3.4",
            system: Some("::ffff:0:102:304"),
            own: Own::Agrees,
        },
        Vector {
            text: "1::1.2.3.4",
            system: Some("1::102:304"),
            own: Own::Agrees,
        },
        // The longest form either implementation accepts, at `TEXT_MAX`
        // bytes. Its canonical form is *shorter*, and instructively so: the
        // embedded-quad branch at `lib/curlx/inet_ntop.c` L155-L156 fires
        // only for an address whose leading groups are zero, so a quad in
        // the input does not survive into the output unless the address is
        // one of the two mapped forms.
        Vector {
            text: "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255",
            system: Some("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            own: Own::Agrees,
        },
        // Rejections. The empty string, a lone colon and a triple colon
        // exercise the leading-colon handling at L126-L128 and the
        // second-`::` guard at L143-L144.
        Vector {
            text: "",
            system: None,
            own: Own::Agrees,
        },
        Vector {
            text: ":",
            system: None,
            own: Own::Agrees,
        },
        Vector {
            text: ":::",
            system: None,
            own: Own::Agrees,
        },
        Vector {
            text: "::1::2",
            system: None,
            own: Own::Agrees,
        },
        // Too many groups, too few groups, a fifth hexadecimal digit, a
        // non-hexadecimal byte, and brackets left on by mistake.
        Vector {
            text: "1:2:3:4:5:6:7:8:9",
            system: None,
            own: Own::Agrees,
        },
        Vector {
            text: "1:2:3:4:5:6:7",
            system: None,
            own: Own::Agrees,
        },
        Vector {
            text: "12345::1",
            system: None,
            own: Own::Agrees,
        },
        Vector {
            text: "g::1",
            system: None,
            own: Own::Agrees,
        },
        Vector {
            text: "[::1]",
            system: None,
            own: Own::Agrees,
        },
        // A bare dotted quad is not an IPv6 address, and a quad with the
        // wrong number of octets is not one either.
        Vector {
            text: "1.2.3.4",
            system: None,
            own: Own::Agrees,
        },
        Vector {
            text: "::1.2.3",
            system: None,
            own: Own::Agrees,
        },
        Vector {
            text: "::1.2.3.4.5",
            system: None,
            own: Own::Agrees,
        },
        Vector {
            text: "::01.2.3.4",
            system: None,
            own: Own::Agrees,
        },
        // A zone identifier is stripped by the caller before it gets here,
        // so the percent sign must be rejected.
        Vector {
            text: "%25eth0",
            system: None,
            own: Own::Agrees,
        },
        Vector {
            text: "fe80::1%eth0",
            system: None,
            own: Own::Agrees,
        },
        // *** The two recorded divergences. ***
        //
        // Curl's own parser accepts a trailing colon after a complete
        // group; the platform rejects it. Both rows are asserted, in both
        // directions, so that neither behavior can change unnoticed. The
        // platform's answer is the one the port ships, and it is what the
        // reference libcurl produces: `https://[1::2:]/` and
        // `https://[1:2:3:4:5:6:7:8:]/` both give `CURLUE_BAD_IPV6`.
        Vector {
            text: "1::2:",
            system: None,
            own: Own::Accepts("1::2"),
        },
        Vector {
            text: "1:2:3:4:5:6:7:8:",
            system: None,
            own: Own::Accepts("1:2:3:4:5:6:7:8"),
        },
        // A trailing colon that no complete group precedes is rejected by
        // both, which is what makes the two rows above a narrow divergence
        // rather than a broad one.
        Vector {
            text: "1::2::",
            system: None,
            own: Own::Agrees,
        },
    ];

    /// Every vector, through curl's own conversion pair.
    ///
    /// This is the half of the comparison that runs on every target,
    /// including those where the platform pair is absent and this backend
    /// is the one the crate ships.
    #[test]
    fn curls_own_pair_matches_the_recorded_table() {
        for vector in VECTORS {
            let expected = match vector.own {
                Own::Agrees => vector.system,
                Own::Accepts(text) => Some(text),
            };
            let (rc, formatted) = round_trip(OWN, vector.text.as_bytes());
            let got = formatted.as_ref().map(|text| show(text.as_bytes()));
            assert_eq!(got, expected, "own canonical form for {:?}", vector.text);
            let want_rc = if expected.is_some() {
                PTON_SUCCESS
            } else {
                PTON_INVALID
            };
            assert_eq!(rc, want_rc, "own rc for {:?}", vector.text);
        }
    }

    /// Every vector, through the platform's conversion pair, held to the
    /// same table.
    ///
    /// Together with the test above, this is what turns the divergence
    /// table into an assertion: an `Own::Agrees` row that stopped agreeing,
    /// or an `Own::Accepts` row that started agreeing, fails here or there.
    #[cfg(unix)]
    #[test]
    fn the_platform_pair_matches_the_recorded_table() {
        for vector in VECTORS {
            let (rc, formatted) = round_trip(SYS, vector.text.as_bytes());
            let got = formatted.as_ref().map(|text| show(text.as_bytes()));
            assert_eq!(
                got, vector.system,
                "system canonical form for {:?}",
                vector.text
            );
            let want_rc = if vector.system.is_some() {
                PTON_SUCCESS
            } else {
                PTON_INVALID
            };
            assert_eq!(rc, want_rc, "system rc for {:?}", vector.text);
        }
    }

    /// The two backends produce byte-identical binary forms wherever both
    /// accept the input, which is the property the parity claim rests on.
    #[cfg(unix)]
    #[test]
    fn the_two_backends_produce_the_same_bytes() {
        let mut agreed = 0usize;
        for vector in VECTORS {
            let mut from_system = [0u8; ADDRSZ_IPV6];
            let mut from_own = [0u8; ADDRSZ_IPV6];
            let system_rc = SYS.0(AF_INET6, vector.text.as_bytes(), &mut from_system);
            let own_rc = OWN.0(AF_INET6, vector.text.as_bytes(), &mut from_own);
            match vector.own {
                Own::Agrees => {
                    assert_eq!(system_rc, own_rc, "rc for {:?}", vector.text);
                    if system_rc == PTON_SUCCESS {
                        assert_eq!(from_system, from_own, "bytes for {:?}", vector.text);
                        agreed = agreed.wrapping_add(1);
                    }
                }
                Own::Accepts(_) => {
                    assert_eq!(system_rc, PTON_INVALID, "rc for {:?}", vector.text);
                    assert_eq!(own_rc, PTON_SUCCESS, "rc for {:?}", vector.text);
                }
            }
        }
        // Guards against the table silently losing its accepted rows and
        // the two tests above passing vacuously.
        assert!(agreed >= 25, "only {agreed} accepted vectors agreed");
    }

    /// Formatting the same bytes with either backend gives the same text,
    /// which is the half of the pair that never disagreed.
    #[cfg(unix)]
    #[test]
    fn the_two_backends_format_identically() {
        for vector in VECTORS {
            let mut binary = [0u8; ADDRSZ_IPV6];
            if OWN.0(AF_INET6, vector.text.as_bytes(), &mut binary) != PTON_SUCCESS {
                continue;
            }
            let mut from_system = Text::EMPTY;
            let mut from_own = Text::EMPTY;
            let system_len = SYS.1(AF_INET6, &binary, &mut from_system.bytes);
            let own_len = OWN.1(AF_INET6, &binary, &mut from_own.bytes);
            assert_eq!(system_len, own_len, "length for {:?}", vector.text);
            assert_eq!(
                from_system.bytes, from_own.bytes,
                "text for {:?}",
                vector.text
            );
        }
    }

    /// The tri-state contract at `lib/curlx/inet_pton.c` L195-L198: 1 for a
    /// valid address, 0 for an invalid one, -1 for an unsupported family,
    /// with the destination untouched in both failure cases.
    #[test]
    fn the_parse_return_value_is_a_tri_state() {
        let backends: &[(&str, (PtonFn, NtopFn))] = &[
            ("own", OWN),
            #[cfg(unix)]
            ("system", SYS),
        ];
        for (name, backend) in backends {
            let (pton, ntop) = *backend;
            // 1, and the destination written.
            let mut binary = [0xAAu8; ADDRSZ_IPV6];
            assert_eq!(
                pton(AF_INET6, b"::1", &mut binary),
                PTON_SUCCESS,
                "{name} valid"
            );
            let mut expected = [0u8; ADDRSZ_IPV6];
            *expected.get_mut(15).unwrap_or(&mut 0) = 1;
            assert_eq!(binary, expected, "{name} bytes");
            // 0, and the destination untouched.
            let mut binary = [0xAAu8; ADDRSZ_IPV6];
            assert_eq!(
                pton(AF_INET6, b"nonsense", &mut binary),
                PTON_INVALID,
                "{name} invalid"
            );
            assert_eq!(binary, [0xAAu8; ADDRSZ_IPV6], "{name} untouched");
            // -1 for a family neither implementation knows, and the
            // destination untouched again. `AF_INET6 + 1` is used because it
            // cannot collide with either supported family.
            let mut binary = [0xAAu8; ADDRSZ_IPV6];
            let unknown = AF_INET6.wrapping_add(1);
            assert_eq!(
                pton(unknown, b"::1", &mut binary),
                PTON_ERROR,
                "{name} family"
            );
            assert_eq!(binary, [0xAAu8; ADDRSZ_IPV6], "{name} untouched");
            // And the formatting side rejects the same family with a null,
            // which is `None` here.
            let mut out = [0xAAu8; 64];
            assert!(
                ntop(unknown, &[0u8; ADDRSZ_IPV6], &mut out).is_none(),
                "{name} ntop family"
            );
            assert_eq!(out, [0xAAu8; 64], "{name} ntop untouched");
        }
    }

    /// Formatting never writes outside the slice it is given, and the
    /// `>=` in the overflow check at `lib/curlx/inet_ntop.c` L186 means the
    /// terminator has to fit too.
    ///
    /// Three sizes are exercised for each of several addresses: one byte
    /// more than needed, exactly enough, and one byte too few. The buffer is
    /// filled with a canary first, so a write past the slice would be
    /// visible, and the failing case must leave every byte of it alone.
    #[test]
    fn formatting_respects_the_size_it_is_given() {
        const CANARY: u8 = 0x5A;
        let backends: &[(&str, (PtonFn, NtopFn))] = &[
            ("own", OWN),
            #[cfg(unix)]
            ("system", SYS),
        ];
        let cases: &[&str] = &[
            "::",
            "::1",
            "2001:db8::1",
            "1:2:3:4:5:6:7:8",
            "::ffff:192.0.2.1",
            "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255",
        ];
        for (name, backend) in backends {
            let (pton, ntop) = *backend;
            for case in cases {
                let mut binary = [0u8; ADDRSZ_IPV6];
                assert_eq!(
                    pton(AF_INET6, case.as_bytes(), &mut binary),
                    PTON_SUCCESS,
                    "{name} {case}"
                );
                // Establish the canonical length with room to spare.
                let mut roomy = [CANARY; 80];
                let len = ntop(AF_INET6, &binary, &mut roomy).unwrap_or_default();
                assert!(len > 0 && len <= TEXT_MAX, "{name} {case} length {len}");

                // One byte more than the minimum: succeeds, and the byte
                // after the terminator is still the canary.
                let mut buffer = [CANARY; 80];
                let head = buffer.get_mut(..len.wrapping_add(2)).unwrap_or_default();
                assert_eq!(
                    ntop(AF_INET6, &binary, head),
                    Some(len),
                    "{name} {case} generous"
                );
                assert_eq!(
                    buffer.get(len.wrapping_add(1)),
                    Some(&CANARY),
                    "{name} {case} wrote past the text"
                );

                // Exactly enough: the text plus the terminator.
                let mut buffer = [CANARY; 80];
                let head = buffer.get_mut(..len.wrapping_add(1)).unwrap_or_default();
                assert_eq!(
                    ntop(AF_INET6, &binary, head),
                    Some(len),
                    "{name} {case} exact"
                );
                assert_eq!(
                    show(buffer.get(..len).unwrap_or_default()),
                    case_canonical(case),
                    "{name} {case} exact text"
                );
                assert_eq!(buffer.get(len), Some(&0), "{name} {case} terminator");
                assert_eq!(
                    buffer.get(len.wrapping_add(1)),
                    Some(&CANARY),
                    "{name} {case} wrote past the terminator"
                );

                // One byte too few: fails, and nothing is written at all.
                let mut buffer = [CANARY; 80];
                let head = buffer.get_mut(..len).unwrap_or_default();
                assert_eq!(ntop(AF_INET6, &binary, head), None, "{name} {case} tight");
                assert_eq!(buffer, [CANARY; 80], "{name} {case} touched on failure");

                // And an empty slice, which is the degenerate case of the
                // same check.
                let mut buffer = [CANARY; 80];
                let head = buffer.get_mut(..0).unwrap_or_default();
                assert_eq!(ntop(AF_INET6, &binary, head), None, "{name} {case} empty");
                assert_eq!(buffer, [CANARY; 80], "{name} {case} touched on empty");
            }
        }
    }

    /// The canonical form of one of the size-test cases, looked up rather
    /// than recomputed, so the size test is asserting text as well as
    /// lengths.
    fn case_canonical(case: &str) -> &'static str {
        for vector in VECTORS {
            if vector.text == case {
                if let Some(canonical) = vector.system {
                    return canonical;
                }
            }
        }
        "<not in the table>"
    }

    /// The canonical form can be **longer** than the input, so a buffer
    /// sized from the input can be too small and the call at
    /// `lib/urlapi.c` L435 can fail. When it does, curl keeps the
    /// unnormalized host, and the reference libcurl round-trips
    /// `https://[1::2:3:4:5:6:7]/` unchanged for exactly that reason.
    ///
    /// This is the behavior that makes the `>=` in the overflow check
    /// observable through the public API, which is why it gets a test of its
    /// own rather than being folded into the size test above.
    #[test]
    fn formatting_fails_when_the_canonical_form_grows() {
        let backends: &[(&str, (PtonFn, NtopFn))] = &[
            ("own", OWN),
            #[cfg(unix)]
            ("system", SYS),
        ];
        // Input, its length, and the longer canonical form it wants.
        let cases: &[(&str, &str)] = &[
            ("1::2:3:4:5:6:7", "1:0:2:3:4:5:6:7"),
            ("1:2::3:4:5:6:7", "1:2:0:3:4:5:6:7"),
        ];
        for (name, backend) in backends {
            let (pton, ntop) = *backend;
            for (input, canonical) in cases {
                let mut binary = [0u8; ADDRSZ_IPV6];
                assert_eq!(
                    pton(AF_INET6, input.as_bytes(), &mut binary),
                    PTON_SUCCESS,
                    "{name} {input}"
                );
                assert!(
                    canonical.len() > input.len(),
                    "{input} is not actually shorter than {canonical}"
                );
                // The caller's buffer is the address plus the one slot the
                // dynamic buffer guarantees, which is what `hlen + 1` is.
                let mut buffer = [0u8; 80];
                let head = buffer
                    .get_mut(..input.len().wrapping_add(1))
                    .unwrap_or_default();
                assert_eq!(ntop(AF_INET6, &binary, head), None, "{name} {input}");
                // With one more byte it fits, and the longer form appears.
                let mut buffer = [0u8; 80];
                let head = buffer
                    .get_mut(..canonical.len().wrapping_add(1))
                    .unwrap_or_default();
                assert_eq!(
                    ntop(AF_INET6, &binary, head),
                    Some(canonical.len()),
                    "{name} {input} with room"
                );
                assert_eq!(
                    show(buffer.get(..canonical.len()).unwrap_or_default()),
                    *canonical,
                    "{name} {input} text"
                );
            }
        }
    }

    /// Formatting is idempotent: the canonical form parses back to the same
    /// bytes and formats to the same text. Without this, "canonical" would
    /// be a claim rather than a property, and the normalization at
    /// `lib/urlapi.c` L433-L435 would not be safe to apply twice, which
    /// re-parsing a stored URL does.
    #[test]
    fn formatting_is_idempotent() {
        let backends: &[(&str, (PtonFn, NtopFn))] = &[
            ("own", OWN),
            #[cfg(unix)]
            ("system", SYS),
        ];
        for (name, backend) in backends {
            for vector in VECTORS {
                let (first_rc, first) = round_trip(*backend, vector.text.as_bytes());
                if first_rc != PTON_SUCCESS {
                    continue;
                }
                let Some(first) = first else {
                    continue;
                };
                let (second_rc, second) = round_trip(*backend, first.as_bytes());
                assert_eq!(second_rc, PTON_SUCCESS, "{name} reparse {:?}", vector.text);
                let again = second.as_ref().map(|text| show(text.as_bytes()));
                assert_eq!(
                    again,
                    Some(show(first.as_bytes())),
                    "{name} idempotence for {:?}",
                    vector.text
                );
            }
        }
    }

    /// Input longer than either implementation can accept is rejected, not
    /// truncated.
    ///
    /// This matters because the platform path copies the text into a fixed
    /// scratch buffer and reports anything that does not fit as invalid.
    /// That shortcut is only sound because no accepted address is that long,
    /// which the `TEXT_MAX` documentation argues from the C code and which
    /// these cases check at the boundary: at `TEXT_MAX` the longest real
    /// address is still accepted, and padding it further is rejected.
    #[test]
    fn over_long_input_is_rejected() {
        let backends: &[(&str, (PtonFn, NtopFn))] = &[
            ("own", OWN),
            #[cfg(unix)]
            ("system", SYS),
        ];
        // A run of the only bytes either parser accepts, at lengths that
        // straddle the scratch capacity of the platform path.
        let mut long = [b'0'; 200];
        for (index, byte) in long.iter_mut().enumerate() {
            if index.wrapping_rem(5) == 4 {
                *byte = b':';
            }
        }
        for (name, backend) in backends {
            let (pton, _) = *backend;
            let longest = "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255";
            assert_eq!(longest.len(), TEXT_MAX, "the longest form moved");
            let mut binary = [0u8; ADDRSZ_IPV6];
            assert_eq!(
                pton(AF_INET6, longest.as_bytes(), &mut binary),
                PTON_SUCCESS,
                "{name} longest"
            );
            for len in [46usize, 63, 64, 65, 100, 200] {
                let text = long.get(..len).unwrap_or_default();
                let mut binary = [0xAAu8; ADDRSZ_IPV6];
                assert_eq!(
                    pton(AF_INET6, text, &mut binary),
                    PTON_INVALID,
                    "{name} length {len}"
                );
                assert_eq!(binary, [0xAAu8; ADDRSZ_IPV6], "{name} length {len} wrote");
            }
        }
    }

    /// A zero byte inside the input ends the address, because that is what
    /// it does to the C string the C code is handed.
    #[test]
    fn an_interior_terminator_ends_the_address() {
        let backends: &[(&str, (PtonFn, NtopFn))] = &[
            ("own", OWN),
            #[cfg(unix)]
            ("system", SYS),
        ];
        for (name, backend) in backends {
            let (rc, formatted) = round_trip(*backend, b"::1\0:junk");
            assert_eq!(rc, PTON_SUCCESS, "{name} truncated at the terminator");
            let got = formatted.as_ref().map(|text| show(text.as_bytes()));
            assert_eq!(got, Some("::1"), "{name} text");
            // And a leading terminator is an empty address, which is
            // invalid.
            let (rc, _) = round_trip(*backend, b"\0::1");
            assert_eq!(rc, PTON_INVALID, "{name} empty");
        }
    }

    /// The IPv4 family, which the URL API never asks for but which both
    /// `curlx_inet_pton` and `curlx_inet_ntop` dispatch on, and which
    /// `inet_pton6` reaches internally for the embedded-quad form.
    ///
    /// The leading-zero rejection at `lib/curlx/inet_pton.c` L77-L78 is the
    /// interesting case: `010.1.1.1` is not octal here, it is invalid.
    #[test]
    fn the_ipv4_family_round_trips() {
        let backends: &[(&str, (PtonFn, NtopFn))] = &[
            ("own", OWN),
            #[cfg(unix)]
            ("system", SYS),
        ];
        let valid: &[&str] = &["0.0.0.0", "1.2.3.4", "255.255.255.255", "192.0.2.1"];
        let invalid: &[&str] = &[
            "",
            "1.2.3",
            "1.2.3.4.5",
            "256.1.1.1",
            "010.1.1.1",
            "1.2.3.",
            ".1.2.3",
            "1.2.3.4.",
            "1..2.3",
            "0x7f.1.1.1",
            "16843009",
        ];
        for (name, backend) in backends {
            let (pton, ntop) = *backend;
            for case in valid {
                let mut binary = [0u8; ADDRSZ_IPV6];
                assert_eq!(
                    pton(AF_INET, case.as_bytes(), &mut binary),
                    PTON_SUCCESS,
                    "{name} {case}"
                );
                let mut out = [0u8; 32];
                let quad = binary.get(..ADDRSZ_IPV4).unwrap_or_default();
                let len = ntop(AF_INET, quad, &mut out);
                assert_eq!(len, Some(case.len()), "{name} {case} length");
                assert_eq!(
                    show(out.get(..case.len()).unwrap_or_default()),
                    *case,
                    "{name} {case} text"
                );
                // The bytes past the quad are never touched by the IPv4
                // conversion, which is what makes a sixteen-byte
                // destination acceptable for it.
                assert_eq!(
                    binary.get(ADDRSZ_IPV4..),
                    Some(&[0u8; 12][..]),
                    "{name} {case} overwrote"
                );
            }
            for case in invalid {
                let mut binary = [0xAAu8; ADDRSZ_IPV6];
                assert_eq!(
                    pton(AF_INET, case.as_bytes(), &mut binary),
                    PTON_INVALID,
                    "{name} {case}"
                );
                assert_eq!(binary, [0xAAu8; ADDRSZ_IPV6], "{name} {case} wrote");
            }
        }
    }

    /// The address normalizations `tests/libtest/lib1560.c` asserts, driven
    /// here through the conversion pair so that a regression shows up in
    /// this module rather than only in the parity diff.
    ///
    /// The bracketed hosts in that file are stripped of their brackets by
    /// `ipv6_parse` before the conversion runs, so the inputs below are the
    /// address text alone.
    #[test]
    fn the_normalizations_curls_test_suite_asserts() {
        // Input, expected canonical form, and the line of
        // `tests/libtest/lib1560.c` that asserts the surrounding URL.
        let cases: &[(&str, &str, u32)] = &[
            ("::1", "::1", 344),
            ("::", "::", 347),
            ("fd00:a41::50", "fd00:a41::50", 406),
            (
                "fe80::0000:20c:29ff:fe9c:409b",
                "fe80::20c:29ff:fe9c:409b",
                607,
            ),
            ("fe80::020c:29ff:fe9c:409b", "fe80::20c:29ff:fe9c:409b", 610),
            ("fe80:0:0:0:409b::", "fe80::409b:0:0:0", 616),
            ("fe80:0:a:0:409b::", "fe80:0:a:0:409b::", 621),
            ("fe80::20c:29ff:fe9c:409b", "fe80::20c:29ff:fe9c:409b", 686),
            ("::1", "::1", 1026),
        ];
        let backends: &[(&str, (PtonFn, NtopFn))] = &[
            ("own", OWN),
            #[cfg(unix)]
            ("system", SYS),
        ];
        for (name, backend) in backends {
            for (input, expected, line) in cases {
                let (rc, formatted) = round_trip(*backend, input.as_bytes());
                assert_eq!(rc, PTON_SUCCESS, "{name} lib1560.c L{line}");
                let got = formatted.as_ref().map(|text| show(text.as_bytes()));
                assert_eq!(got, Some(*expected), "{name} lib1560.c L{line}");
            }
        }
    }

    /// The module's own entry points dispatch to the backend the target
    /// selects, and behave as the wrappers document.
    ///
    /// This is the surface `parse/ipv6.rs` and `parse/host.rs` see, and it
    /// is deliberately tested through the public names rather than through
    /// the backends, so that a mistake in the `cfg` selection or in a
    /// wrapper signature is caught here.
    #[test]
    fn the_public_entry_points_behave_as_documented() {
        // The exact sequence at `lib/urlapi.c` L429-L440, over a buffer
        // shaped the way the dynamic buffer shapes it: the address, one
        // slot for the closing bracket, and one for the terminator.
        let mut host = *b"0:0:0:0:0:0:0:1]\0";
        let hlen = 15usize;
        let mut binary = [0u8; ADDRSZ_IPV6];
        let address = host.get(..hlen).unwrap_or_default();
        assert_eq!(inet_pton(AF_INET6, address, &mut binary), PTON_SUCCESS);
        let room = host.get_mut(..hlen.wrapping_add(1)).unwrap_or_default();
        let shorter = inet_ntop(AF_INET6, &binary, room);
        assert_eq!(shorter, Some(3), "0:0:0:0:0:0:0:1 shortens to ::1");
        assert_eq!(show(host.get(..3).unwrap_or_default()), "::1");
        // The caller then restores the bracket at the new length, which is
        // the one-past write recorded in the divergences note. The byte is
        // there because the buffer carries the terminator slot.
        *host.get_mut(4).unwrap_or(&mut 0) = 0;
        *host.get_mut(3).unwrap_or(&mut 0) = b']';
        assert_eq!(show(host.get(..4).unwrap_or_default()), "::1]");

        // Rejection, and the tri-state passing through the wrapper.
        let mut binary = [0xAAu8; ADDRSZ_IPV6];
        assert_eq!(
            inet_pton(AF_INET6, b"not-an-address", &mut binary),
            PTON_INVALID
        );
        assert_eq!(
            inet_pton(AF_INET6.wrapping_add(1), b"::1", &mut binary),
            PTON_ERROR
        );
        assert_eq!(binary, [0xAAu8; ADDRSZ_IPV6]);

        // A short binary input is declined rather than read past.
        let mut out = [0u8; 64];
        assert_eq!(inet_ntop(AF_INET6, &[0u8; 15], &mut out), None);
        assert_eq!(inet_ntop(AF_INET, &[0u8; 3], &mut out), None);
        // And the exact widths are accepted.
        assert_eq!(inet_ntop(AF_INET6, &[0u8; ADDRSZ_IPV6], &mut out), Some(2));
        assert_eq!(show(out.get(..2).unwrap_or_default()), "::");
        assert_eq!(inet_ntop(AF_INET, &[0u8; ADDRSZ_IPV4], &mut out), Some(7));
        assert_eq!(show(out.get(..7).unwrap_or_default()), "0.0.0.0");
    }

    /// The family constants are distinct and, where the platform supplies
    /// them, are the platform's own numbers rather than a copy.
    #[test]
    fn the_address_family_constants_are_the_platforms() {
        assert_ne!(AF_INET, AF_INET6);
        #[cfg(unix)]
        {
            assert_eq!(AF_INET, libc::AF_INET);
            assert_eq!(AF_INET6, libc::AF_INET6);
        }
        // The tri-state numbers are ABI in everything but name.
        assert_eq!(PTON_SUCCESS, 1);
        assert_eq!(PTON_INVALID, 0);
        assert_eq!(PTON_ERROR, -1);
        // And the two widths are the ones the C code declares.
        assert_eq!(ADDRSZ_IPV4, 4);
        assert_eq!(ADDRSZ_IPV6, 16);
    }
}
