// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The growable byte buffer: `lib/curlx/dynbuf.c`, ported.
//!
//! `lib/urlapi.c` does not own this type. It borrows it, sixty call sites
//! deep, from a sibling translation unit that this port may not modify and
//! may not link against either, so the buffer has to come across with the
//! module. Everything the URL API assembles passes through here: the
//! percent encoder at `lib/urlapi.c:L130-L172`, the dot-segment remover at
//! L716-L821, the host pipeline at L604-L655, the relative-URL rebuild at
//! L1272-L1282 and the part setter at L1877-L1996.
//!
//! # The two contracts that are invisible from the call sites
//!
//! Read these two before reading anything else in this file. Neither is
//! stated at any call site in `lib/urlapi.c`, both are load-bearing for
//! code in other modules of this crate, and getting either wrong produces a
//! leak, a double free or a buffer overrun rather than a wrong answer.
//!
//! ## 1. A failed append releases the whole buffer
//!
//! `dyn_nappend()` at `lib/curlx/dynbuf.c:L67-L119` calls
//! `curlx_dyn_free()` on itself before reporting either failure: at L83
//! when the request would exceed the ceiling, and at L107 when the
//! reallocation fails. The buffer is *gone* by the time the caller sees the
//! error code.
//!
//! `lib/urlapi.c` depends on that. The `nomem:` label at L1959-L1961
//! releases `enc` and never touches `qbuf`, because a failed append on
//! `qbuf` at L1946, L1950 or L1953 already released it. The four returns at
//! L1885, L1895, L1905 and L1912 leave `enc` alone for the same reason.
//! Add a free at any of those sites and the result is a double free.
//!
//! [`DynBuf`] reproduces this by resetting itself to the empty initial
//! state on failure: the block is released, the pointer becomes null, both
//! lengths become zero and `toobig` is kept. A later [`DynBuf::free`],
//! [`DynBuf::reset`], accessor or `Drop` therefore sees a well-formed empty
//! buffer rather than a dangling pointer. A caller that treats the error as
//! recoverable and appends again gets a fresh allocation, exactly as the C
//! does, rather than appending into released memory.
//!
//! ## 2. The allocation always has one byte spare beyond the length
//!
//! `leng` counts content and excludes the terminator; `allc` is the whole
//! allocation and includes room for it. The invariant that follows from
//! `fit = len + idx + 1` at `lib/curlx/dynbuf.c:L72` is that a buffer
//! holding `leng` bytes is backed by **at least `leng + 1`** of them, and
//! that byte `[leng]` is a zero this module maintains.
//!
//! `src/parse/ipv6.rs` relies on the spare byte. `docs/KNOWN-DIVERGENCES.md`
//! records the detail as `FB6`: `ipv6_parse()` writes a terminator one byte
//! past the length it tracks, at `lib/urlapi.c:L422` and again at L437, and
//! in the case where normalization shortens nothing that second write lands
//! exactly on index `leng` of this buffer. Trimming the view to `leng`
//! bytes would make the write impossible to express, which would either
//! change behavior for input at the maximum length, forbidden by
//! transformation rule T6, or force `unsafe` into a parser module, which
//! the specification forbids outside the FFI facade. So the mutable view
//! this module hands out, [`DynBuf::as_mut_bytes_with_nul`], deliberately
//! covers `leng + 1` bytes.
//!
//! # What is ported and what is not
//!
//! Nine operations, the exact set `lib/urlapi.c` uses:
//!
//! | C entry point | Line | Ported as |
//! |---|---|---|
//! | `curlx_dyn_init` | L38 | [`DynBuf::new`] |
//! | `curlx_dyn_free` | L56 | [`DynBuf::free`] |
//! | `dyn_nappend` | L67 | [`DynBuf::grow`] plus its callers |
//! | `curlx_dyn_reset` | L125 | [`DynBuf::reset`] |
//! | `curlx_dyn_addn` | L162 | [`DynBuf::addn`] |
//! | `curlx_dyn_add` | L173 | [`DynBuf::add`] |
//! | `curlx_dyn_addf` | L220 | [`DynBuf::addf`] |
//! | `curlx_dyn_ptr` | L237 | four accessors, see below |
//! | `curlx_dyn_len` | L271 | [`DynBuf::len`] |
//! | `curlx_dyn_setlen` | L282 | [`DynBuf::setlen`] |
//!
//! Four are deliberately absent, because no consumer in this crate needs
//! them and unused code is a warning in a crate that treats warnings as
//! errors: `curlx_dyn_tail` at L139, `curlx_dyn_vaddf` at L187, whose two
//! branches are folded into [`DynBuf::addf`], `curlx_dyn_take` at L245,
//! which `lib/urlapi.c` never calls, and `curlx_dyn_uptr` at L260, which is
//! a cast this port does not need because its accessors are already
//! byte-typed.
//!
//! # One pointer, four accessors
//!
//! `curlx_dyn_ptr()` is a single function used for two incompatible
//! purposes, and the C signature cannot tell them apart: L237 declares it
//! over a `const struct dynbuf *` and L242 returns `s->bufr` without
//! clearing anything, so a handover happens only because the caller then
//! never frees the buffer again. `MEMORY-OWNERSHIP.md` catalogues both
//! groups of call sites. This module splits them, so that the compiler
//! knows which is which:
//!
//! - [`DynBuf::as_bytes`] and [`DynBuf::as_bytes_with_nul`] **borrow**. The
//!   buffer keeps ownership. These serve the read-only uses at
//!   `lib/urlapi.c:L339`, L487, L581, L783 and L986.
//! - [`DynBuf::as_mut_bytes_with_nul`] **borrows mutably**, for the
//!   in-place rewrites at `lib/urlapi.c:L1921-L1932` and inside
//!   `ipv6_parse()`. See contract 2 for why it is one byte wider than the
//!   content.
//! - [`DynBuf::into_cbuf`] and [`DynBuf::into_raw`] **hand over**. The
//!   value is consumed, `Drop` is suppressed and the obligation to release
//!   the block moves to the receiver. These serve the ten handover sites,
//!   `lib/urlapi.c:L672`, L813, L1025, L1049, L1077, L1185, L1399, L1489,
//!   L1934 and L1957.
//!
//! Confusing the two groups is a double free in one direction and a leak in
//! the other, which is why they are separated by name as well as by type.
//!
//! # Memory provenance
//!
//! Every byte comes from `src/alloc.rs` and therefore from the C allocator.
//! That is not a stylistic choice: the pointer this buffer yields is handed
//! to C at the ten sites above, and the C side releases it with
//! `curl_free()`, which `docs/libcurl/curl_url_get.md:L45` and
//! `include/curl/urlapi.h:L130-L131` document as the required call. A
//! Rust-allocated block would make that call wrong. `CString::into_raw` is
//! banned crate-wide for the same reason and appears nowhere here.
//!
//! # Thread safety
//!
//! [`DynBuf`] holds a raw pointer, so it is neither `Send` nor `Sync`, and
//! the C original is no different: `struct dynbuf` carries no lock and
//! `lib/urlapi.c` only ever uses one on the stack of the calling thread.

// This module is a complete port of the nine operations the URL API uses,
// and which of them are reachable depends on which sibling modules a given
// feature configuration compiles. `add` in particular exists for the
// literal appends and is not needed by every configuration. Warnings are
// errors for this crate, so the allowance is stated once, here, with its
// reason rather than left for the feature matrix to decide, exactly as
// `src/alloc.rs` and `src/error.rs` do. It is scoped to this module and to
// this one lint.
#![allow(dead_code)]

use core::fmt;
use core::mem;
use core::ptr;
use core::slice;
use libc::{c_char, c_void};

use crate::alloc::{c_free, c_realloc, CBuf};
use crate::error::CURLcode;

/// The size of a buffer's first allocation, unless the ceiling is smaller.
///
/// `lib/curlx/dynbuf.c:L29` defines it as 32, and the number is transcribed
/// from that line rather than chosen. It is the reason a buffer assembled
/// one byte at a time, as the dot-segment remover does at
/// `lib/urlapi.c:L806`, reallocates a handful of times rather than once per
/// byte.
const MIN_FIRST_ALLOC: usize = 32;

/// The largest ceiling a buffer may be given.
///
/// `lib/curlx/dynbuf.h:L63` defines `MAX_DYNBUF_SIZE` as `SIZE_MAX / 2`, and
/// `curlx_dyn_init()` asserts it at `lib/curlx/dynbuf.c:L42` with the
/// comment "catch crazy mistakes". The bound is what makes the doubling loop
/// at L97-L98 safe in C: every candidate size is at most `toobig`, so
/// doubling one cannot pass `SIZE_MAX`.
///
/// This port does not assert it, because an assertion is a panic path and
/// this crate has none. It uses saturating multiplication instead, which is
/// exact for every ceiling at or below this bound and merely terminates the
/// loop early above it. The constant is kept so that the reasoning has a
/// name, and [`DynBuf::ceiling_is_sane`] exposes the comparison as a query
/// for a caller that wants to check a ceiling it invented.
const MAX_DYNBUF_SIZE: usize = usize::MAX / 2;

/// A growable, NUL-terminated byte buffer backed by the C allocator.
///
/// The port of `struct dynbuf`, `lib/curlx/dynbuf.h:L27-L35`:
///
/// ```c
/// struct dynbuf {
///   char *bufr;    /* point to a null-terminated allocated buffer */
///   size_t leng;   /* number of bytes *EXCLUDING* the null-terminator */
///   size_t allc;   /* size of the current allocation */
///   size_t toobig; /* size limit for the buffer */
/// };
/// ```
///
/// The `init` sentinel that `lib/curlx/dynbuf.h:L32-L34` adds under
/// `DEBUGBUILD` has no counterpart here. It exists to catch a `struct
/// dynbuf` used before `curlx_dyn_init()` ran, which is a mistake Rust
/// cannot express: there is no way to obtain a `DynBuf` except from
/// [`DynBuf::new`], and no `Default` implementation is offered that would
/// invent a ceiling.
///
/// # Invariants
///
/// Every live value satisfies all four of the following, and every method
/// below both assumes and re-establishes them:
///
/// 1. `bufr` is either null, in which case `leng` and `allc` are both zero,
///    or a live block from `src/alloc.rs` that this value alone owns.
/// 2. `allc` is the exact size of that block, and `leng < allc`. The strict
///    inequality is contract 2 in the module documentation: there is always
///    room for the terminator at `[leng]`.
/// 3. When `bufr` is non-null, bytes `[0, leng)` are initialized and byte
///    `[leng]` is zero. Bytes above `[leng]` may be uninitialized, which is
///    why no method ever forms a reference wider than `leng + 1`.
/// 4. `toobig` never changes after construction, not even across
///    [`DynBuf::free`], which is what makes a freed buffer reusable.
///
/// # Ownership
///
/// Rust owns the block. `Drop` releases it, which is what removes the
/// failure-path leak class the C original carries: `lib/urlapi.c` has to
/// reach `curlx_dyn_free()` on every path out of every function that
/// declares a buffer, and `docs/KNOWN-DIVERGENCES.md` records where it does
/// not. [`DynBuf::into_cbuf`] and [`DynBuf::into_raw`] are the only ways
/// out of that ownership.
pub(crate) struct DynBuf {
    /// The allocation, or null before the first append and after a free.
    ///
    /// C's `bufr`. Null is a normal state rather than an error: the pointer
    /// taken at `lib/urlapi.c:L1934` may belong to a buffer that was never
    /// appended to, and L1936 and L1995 both handle that null.
    bufr: *mut c_char,
    /// Content length in bytes, excluding the terminator at `[leng]`.
    ///
    /// C's `leng`.
    leng: usize,
    /// Size of the whole allocation, including the terminator slot.
    ///
    /// C's `allc`. Zero exactly when `bufr` is null.
    allc: usize,
    /// The ceiling on `leng + 1`, fixed at construction.
    ///
    /// C's `toobig`. A request that would push `leng + 1` above it fails
    /// with `CURLE_TOO_LARGE` and releases the buffer, which is contract 1.
    toobig: usize,
}

impl DynBuf {
    /// Creates an empty buffer with `toobig` as its ceiling.
    ///
    /// The port of `curlx_dyn_init()`, `lib/curlx/dynbuf.c:L38-L50`: null
    /// pointer, zero length, zero allocation, the ceiling stored. Nothing
    /// is allocated here, exactly as in C, so a buffer that is never
    /// appended to costs nothing.
    ///
    /// # The ceiling is a real parameter, not a formality
    ///
    /// `lib/urlapi.c` passes three different values, and the differences are
    /// behavioral rather than defensive:
    ///
    /// - `CURL_MAX_INPUT_LENGTH`, 8000000 per `lib/urldata.h:L131`, at
    ///   L664, L1021, L1044, L1072, L1122, L1272, L1394, L1485 and L1944.
    /// - `clen + 1` at L726, where `clen` is the length of the path being
    ///   de-dotted. The output can never be longer than the input, so this
    ///   ceiling is exact and doubles as a correctness check.
    /// - `nalloc * 3 + 1 + leadingslash` at L1880, the worst case for
    ///   percent-encoding every byte of a part, plus a terminator and an
    ///   optional leading slash.
    ///
    /// C asserts a nonzero ceiling at `lib/curlx/dynbuf.c:L41`. This port
    /// accepts zero without asserting, because an assertion is a panic path
    /// and this crate has none, and the outcome is well defined anyway: the
    /// smallest possible request needs `fit == 1`, so every append on a
    /// zero-ceiling buffer fails with `CURLE_TOO_LARGE` and the buffer stays
    /// empty. See [`DynBuf::ceiling_is_sane`] for the upper bound.
    #[must_use]
    pub(crate) const fn new(toobig: usize) -> Self {
        Self {
            bufr: ptr::null_mut(),
            leng: 0,
            allc: 0,
            toobig,
        }
    }

    /// Whether the ceiling respects the bound C asserts for it.
    ///
    /// `lib/curlx/dynbuf.c:L42` carries
    /// `DEBUGASSERT(toobig <= MAX_DYNBUF_SIZE)` with the comment "catch
    /// crazy mistakes", where the bound is `SIZE_MAX / 2` per
    /// `lib/curlx/dynbuf.h:L63`. A ceiling at or below it keeps the doubling
    /// step exact, because no candidate size can then pass `usize::MAX`.
    ///
    /// This is a query rather than an assertion, and no method consults it.
    /// A larger ceiling is still handled safely: [`DynBuf::grow`] saturates
    /// instead of wrapping, so the loop terminates with the largest
    /// representable size rather than with a wrapped one. The predicate
    /// exists so that the bound has a name a test can check, and so that a
    /// future caller inventing a ceiling has a way to ask.
    #[must_use]
    pub(crate) const fn ceiling_is_sane(&self) -> bool {
        self.toobig <= MAX_DYNBUF_SIZE
    }

    /// Releases the allocation and returns to the empty initial state.
    ///
    /// The port of `curlx_dyn_free()`, `lib/curlx/dynbuf.c:L56-L62`:
    ///
    /// ```c
    /// void curlx_dyn_free(struct dynbuf *s)
    /// {
    ///   Curl_safefree(s->bufr);
    ///   s->leng = s->allc = 0;
    /// }
    /// ```
    ///
    /// `Curl_safefree`, the macro at `lib/curl_setup.h:L1319-L1323`, frees
    /// and then nulls the pointer, which is why a second call is harmless.
    /// The ceiling is untouched, and the C comment at L53-L54 is explicit
    /// that the buffer stays usable: appending again starts a fresh first
    /// allocation.
    ///
    /// # Ownership
    ///
    /// **The block is released here.** Any pointer previously taken from
    /// [`DynBuf::as_bytes_with_nul`] or from the mutable view is dangling
    /// afterwards, and no slice can outlive this call because every one of
    /// them borrows `self`. A pointer handed over by [`DynBuf::into_raw`]
    /// cannot be affected, because that call consumed the value.
    pub(crate) fn free(&mut self) {
        // SAFETY: invariant 1 says `bufr` is either null, which `c_free`
        // treats as a no-op, or a live block from `src/alloc.rs` that this
        // value alone owns, which is exactly `c_free`'s precondition. The
        // three field writes below run unconditionally, so the pointer
        // cannot be reached again and this cannot free twice; that is also
        // what makes a second `free()` and a later `Drop` safe.
        unsafe { c_free(self.bufr.cast::<c_void>()) };
        self.bufr = ptr::null_mut();
        self.leng = 0;
        self.allc = 0;
    }

    /// Clears the content and keeps the allocation.
    ///
    /// The port of `curlx_dyn_reset()`, `lib/curlx/dynbuf.c:L125-L133`,
    /// whose own comment at L121-L124 states both properties: "Clears the
    /// string, keeps the allocation. This can also be called on a buffer
    /// that already was freed."
    ///
    /// Both are reproduced. The allocation survives, which is the point:
    /// `lib/urlapi.c` resets and immediately refills the same buffer five
    /// times, at L532, L543, L553 and L564 while normalizing an IPv4
    /// address and again at L594 after decoding a host, and each of those
    /// refills is shorter than what it replaces, so no reallocation
    /// follows. A buffer that had already been freed has `leng == 0` by
    /// invariant 1, so the terminator write is skipped and the call is a
    /// no-op rather than a null dereference.
    ///
    /// The guard is written the way C writes it, `if(s->leng)`, rather than
    /// as an unconditional re-terminate. The two are observably identical,
    /// because invariant 3 already puts a zero at `[0]` when the length is
    /// zero, and following the C makes the correspondence checkable.
    pub(crate) fn reset(&mut self) {
        let had_content = self.leng != 0;
        self.leng = 0;
        if had_content {
            // Invariant 1 guarantees a non-null pointer whenever the length
            // was nonzero, so this writes the zero C writes at L131.
            self.terminate();
        }
    }

    /// Makes room for `len` more bytes, reallocating if the size changes.
    ///
    /// This is the sizing half of `dyn_nappend()`,
    /// `lib/curlx/dynbuf.c:L67-L112`, and the single place in this crate
    /// where the growth policy lives. It leaves `leng` alone: the caller
    /// writes into the space at `[leng, leng + len)` and then commits the
    /// new length. Splitting it that way lets [`DynBuf::addn`] and
    /// [`DynBuf::addf`] share one policy, where C shares it by routing the
    /// formatted path through a temporary allocation at L204-L209.
    ///
    /// # The policy, transcribed
    ///
    /// ```c
    /// size_t fit = len + idx + 1; /* new string + old string + zero byte */
    /// if(fit > s->toobig) {
    ///   curlx_dyn_free(s);
    ///   return CURLE_TOO_LARGE;
    /// }
    /// else if(!a) {
    ///   /* first invoke */
    ///   if(MIN_FIRST_ALLOC > s->toobig)      a = s->toobig;
    ///   else if(fit < MIN_FIRST_ALLOC)       a = MIN_FIRST_ALLOC;
    ///   else                                 a = fit;
    /// }
    /// else {
    ///   while(a < fit)
    ///     a *= 2;
    ///   if(a > s->toobig)
    ///     a = s->toobig;
    /// }
    /// ```
    ///
    /// Four consequences worth naming, because each one is observable:
    ///
    /// - The `+ 1` in `fit` is the terminator slot, so `toobig` bounds
    ///   `leng + 1` rather than `leng`. A ceiling of `clen + 1` at
    ///   `lib/urlapi.c:L726` therefore admits exactly `clen` bytes of
    ///   content.
    /// - A zero-length append still allocates. `fit` is at least 1, so the
    ///   first-invoke branch runs and produces a real block. That is not an
    ///   accident of the code: `lib/urlapi.c:L1156` appends the empty string
    ///   deliberately and L1185 hands the resulting pointer to `u->host`.
    /// - The reallocation is skipped when the computed size equals the
    ///   current one, L104, which is what keeps the byte-at-a-time loop at
    ///   `lib/urlapi.c:L806` down to a logarithmic number of calls.
    /// - The doubling never shrinks. Every candidate starts at `allc` and
    ///   only grows, and the clamp at L101 cannot go below `fit`, because
    ///   `fit <= toobig` was already established.
    ///
    /// # Failure releases the buffer
    ///
    /// Contract 1 from the module documentation, and the reason this
    /// function is worth reading twice. Both failure paths call
    /// [`DynBuf::free`] before returning, so on error the value is a
    /// well-formed empty buffer rather than a live one the caller must clean
    /// up or a dangling one a later `Drop` would free twice.
    ///
    /// # Arithmetic
    ///
    /// `fit` is a checked addition. C computes it with plain `+`, where an
    /// overflow would wrap to a small number, sail past the ceiling test and
    /// size the allocation far too small. That is unreachable in practice,
    /// because `Curl_junkscan()` caps input at 8000000 bytes at
    /// `lib/urlapi.c:L229-L230`, but the port reports it as
    /// `CURLE_TOO_LARGE` rather than reproducing a latent overflow: any
    /// request whose size cannot be represented is by definition above every
    /// legal ceiling, so the code is the truthful one.
    ///
    /// The doubling saturates rather than wrapping. For every ceiling at or
    /// below `MAX_DYNBUF_SIZE`, see [`DynBuf::ceiling_is_sane`], saturation
    /// is never reached and the arithmetic is identical to C's. Above it,
    /// saturation terminates the loop at `usize::MAX`, which the clamp then
    /// brings back down to the ceiling.
    ///
    /// # Returns
    ///
    /// `CURLcode::CURLE_OK` when at least `leng + len + 1` bytes are
    /// available, `CURLcode::CURLE_TOO_LARGE` when the request exceeds the
    /// ceiling, `lib/curlx/dynbuf.c:L84`, and
    /// `CURLcode::CURLE_OUT_OF_MEMORY` when the reallocation fails, L108.
    /// The buffer is released in both failure cases.
    fn grow(&mut self, len: usize) -> CURLcode {
        let idx = self.leng;
        let mut a = self.allc;

        // `fit = len + idx + 1`, L72. See the note on arithmetic above for
        // why an unrepresentable total is reported as too large.
        let Some(fit) = len.checked_add(idx).and_then(|sum| sum.checked_add(1)) else {
            self.free();
            return CURLcode::CURLE_TOO_LARGE;
        };

        if fit > self.toobig {
            // L82-L85. The free is contract 1, not tidiness.
            self.free();
            return CURLcode::CURLE_TOO_LARGE;
        } else if a == 0 {
            // L86-L95, the first invoke. `allc == 0` implies `leng == 0` by
            // invariant 1, which is the `DEBUGASSERT(!idx)` at L87.
            if MIN_FIRST_ALLOC > self.toobig {
                a = self.toobig;
            } else if fit < MIN_FIRST_ALLOC {
                a = MIN_FIRST_ALLOC;
            } else {
                a = fit;
            }
        } else {
            // L96-L102. Saturation keeps the loop bounded; see above.
            while a < fit {
                a = a.saturating_mul(2);
            }
            if a > self.toobig {
                // No point allocating more than the buffer may ever use.
                a = self.toobig;
            }
        }

        if a != self.allc {
            // SAFETY: `c_realloc` requires a pointer that is null or a live
            // block from `src/alloc.rs` owned by the caller, which is
            // invariant 1, and a nonzero size, which holds because `a` is at
            // least `fit` and `fit` is at least 1. On success ownership
            // moves to the new pointer and the old one is not touched
            // again; on failure `c_realloc` leaves the old block owned by
            // this value, which is why the `free()` below is correct and not
            // a double free.
            let fresh = unsafe { c_realloc(self.bufr.cast::<c_void>(), a) };
            if fresh.is_null() {
                // L106-L109. Contract 1 again: the buffer goes away before
                // the error is reported.
                self.free();
                return CURLcode::CURLE_OUT_OF_MEMORY;
            }
            self.bufr = fresh.cast::<c_char>();
            self.allc = a;
        }

        CURLcode::CURLE_OK
    }

    /// Copies `src` into the allocation at `offset`, without touching the
    /// length.
    ///
    /// The `memcpy` at `lib/curlx/dynbuf.c:L115`, expressed so that it
    /// cannot write outside the block. Returns `false` and writes nothing
    /// when the destination range would reach the terminator slot at
    /// `[allc - 1]` or run past the end, which keeps invariant 2 true no
    /// matter what a caller asks for.
    ///
    /// A raw copy rather than a slice assignment is deliberate. Bytes above
    /// `[leng]` are uninitialized, and forming a `&mut [u8]` over them to
    /// use `copy_from_slice` would be a reference to uninitialized memory.
    /// `src/alloc.rs` fills its own buffers the same way, for the same
    /// reason.
    fn write_at(&mut self, offset: usize, src: &[u8]) -> bool {
        if src.is_empty() {
            // C skips the copy entirely when the length is zero, L114, and
            // so does this. Nothing is written, so nothing needs checking.
            return true;
        }
        let Some(end) = offset.checked_add(src.len()) else {
            return false;
        };
        // `end < allc` rather than `end <= allc`: the last byte of the
        // allocation belongs to the terminator.
        if self.bufr.is_null() || end >= self.allc {
            return false;
        }
        let dst = self.bufr.cast::<u8>();
        // SAFETY: the guard above establishes `offset + src.len() < allc`
        // with `allc` the exact size of a live block, invariant 2, so the
        // whole destination range lies inside the allocation and the offset
        // computation stays in bounds. The destination came from the C
        // allocator and `src` is a live Rust slice, so they cannot overlap.
        // `u8` has an alignment of one, which any pointer satisfies.
        unsafe { ptr::copy_nonoverlapping(src.as_ptr(), dst.add(offset), src.len()) };
        true
    }

    /// Writes the terminator at `[leng]`.
    ///
    /// The `s->bufr[s->leng] = 0` that closes every successful append at
    /// `lib/curlx/dynbuf.c:L117`, and that `curlx_dyn_setlen()` repeats at
    /// L290. Invariant 2 guarantees `leng < allc`, so the byte is always
    /// inside the allocation.
    ///
    /// A null pointer is skipped. C would dereference it, and the only way
    /// to reach that in C is `curlx_dyn_setlen(s, 0)` on a buffer that was
    /// never allocated, which no call site in `lib/urlapi.c` does. Skipping
    /// is not a behavioral divergence, because the state C would leave
    /// behind is unreachable: with no allocation the length is already zero
    /// and invariant 3 has nothing to maintain.
    fn terminate(&mut self) {
        if self.bufr.is_null() {
            return;
        }
        // SAFETY: invariant 1 gives a live block of exactly `allc` bytes and
        // invariant 2 gives `leng < allc`, so byte `[leng]` is inside it.
        // `u8` needs no alignment beyond one byte. The write is what
        // establishes invariant 3 for the current length.
        unsafe { self.bufr.cast::<u8>().add(self.leng).write(0) };
    }

    /// Appends a counted run of bytes.
    ///
    /// The port of `curlx_dyn_addn()`, `lib/curlx/dynbuf.c:L162-L168`, which
    /// is a straight forward to `dyn_nappend()`. This is the workhorse:
    /// `lib/urlapi.c` calls it at L146, L153, L155, L160, L163, L595, L621,
    /// L766, L795, L806, L891, L1274, L1883, L1893, L1903, L1910, L1946 and
    /// L1950.
    ///
    /// It also covers `curlx_dyn_add()` for every caller that already holds
    /// bytes, because a Rust slice carries the length that C has to recover
    /// with `strlen()`. [`DynBuf::add`] exists for the string-literal case
    /// and forwards here.
    ///
    /// An empty slice is not a no-op: it forces the first allocation, which
    /// `lib/urlapi.c:L1156` relies on. See [`DynBuf::grow`].
    ///
    /// Interior zero bytes are stored as given, exactly as `memcpy` does at
    /// `lib/curlx/dynbuf.c:L115`. The buffer then holds more bytes than a C
    /// `strlen()` of its pointer would report, and [`DynBuf::len`] is the
    /// truthful number. No call site in this crate can produce one, because
    /// `Curl_junkscan()` rejects control bytes in the input at
    /// `lib/urlapi.c:L223-L246`.
    ///
    /// # Ownership
    ///
    /// Nothing changes hands. The bytes are copied, so `src` may be a
    /// borrow of anything, including of another buffer's content.
    ///
    /// # Returns
    ///
    /// `CURLcode::CURLE_OK`, or one of the two failures from
    /// [`DynBuf::grow`], each of which has **already released the buffer**.
    /// The caller must not free it again. `lib/urlapi.c` folds these into a
    /// `CURLUcode` with `cc2cu`, ported as `crate::error::cc2cu`.
    #[must_use = "a failed append has released the buffer; the code must be handled"]
    pub(crate) fn addn(&mut self, src: &[u8]) -> CURLcode {
        let idx = self.leng;
        let grown = self.grow(src.len());
        if grown.is_err() {
            // `grow` already released the buffer. Returning without a free
            // of our own is contract 1, and matches L83 and L107.
            return grown;
        }
        if !self.write_at(idx, src) {
            // Unreachable: `grow` just guaranteed `idx + src.len() + 1`
            // bytes, so the copy fits by construction. Reported rather than
            // asserted, because this crate has no panic paths, and the
            // buffer is released so that the caller's contract-1 assumption
            // still holds on this path.
            self.free();
            return CURLcode::CURLE_OUT_OF_MEMORY;
        }
        // L116-L117: commit the new length, then re-terminate. The addition
        // saturates only in theory: `grow` established that `idx + len + 1`
        // is representable.
        self.leng = idx.saturating_add(src.len());
        self.terminate();
        CURLcode::CURLE_OK
    }

    /// Appends a string slice.
    ///
    /// The port of `curlx_dyn_add()`, `lib/curlx/dynbuf.c:L173-L182`, whose
    /// only work beyond `dyn_nappend()` is the `strlen()` at L180 that a
    /// Rust slice already carries. Used for the literal appends and for text
    /// the port knows to be text; `lib/urlapi.c` calls the original at
    /// L1156, L1918 and L1953.
    ///
    /// For arbitrary bytes, a host name that came back from
    /// internationalized-domain decoding or a path holding any byte the junk
    /// scan allows, use [`DynBuf::addn`] instead. Nothing here validates
    /// UTF-8, so this is a convenience rather than a restriction, but a
    /// caller that has bytes should not have to invent a `&str` to reach it.
    ///
    /// # Returns
    ///
    /// Exactly as [`DynBuf::addn`], including that a failure has already
    /// released the buffer.
    #[must_use = "a failed append has released the buffer; the code must be handled"]
    pub(crate) fn add(&mut self, text: &str) -> CURLcode {
        self.addn(text.as_bytes())
    }

    /// Appends formatted output.
    ///
    /// The port of `curlx_dyn_addf()`, `lib/curlx/dynbuf.c:L220-L232`, by
    /// way of `curlx_dyn_vaddf()` at L187-L215. Call it with
    /// `format_args!`:
    ///
    /// ```ignore
    /// let code = host.addf(format_args!("{a}.{b}.{c}.{d}"));
    /// ```
    ///
    /// # This is not a printf, and that is on purpose
    ///
    /// C accepts a format string and a variadic list, and reproducing that
    /// would mean reimplementing format parsing for two call-site shapes.
    /// Rust's `fmt::Arguments` is already the parsed, type-checked form, so
    /// the port takes that and no format string of its own.
    ///
    /// The consequence a later consumer needs to know: **the arguments are
    /// rendered through Rust's formatting machinery, so everything written
    /// must be valid UTF-8.** That is exact for the four sites this exists
    /// to serve, `lib/urlapi.c:L534`, L544, L554 and L565, which print
    /// `"%u.%u.%u.%u"` while normalizing an IPv4 address and so emit ASCII
    /// digits and dots. It is *wrong* for the fifth site, L1486, whose
    /// `"%.*s%%25%s]"` interpolates a host name and a zone identifier, both
    /// arbitrary byte strings that need no encoding to be legal. That site
    /// belongs in [`DynBuf::addn`], as three appends or as one
    /// `crate::alloc::CBuf::concat`, and this restriction is stated here so
    /// that nobody discovers it by watching a non-ASCII host fail.
    ///
    /// # Implementation
    ///
    /// Two passes over the arguments: one to measure, then one to write
    /// straight into the space [`DynBuf::grow`] reserved. `fmt::Arguments`
    /// is `Copy`, so the second pass costs nothing extra.
    ///
    /// That is the shape of the `BUILDING_LIBCURL` branch at
    /// `lib/curlx/dynbuf.c:L189-L201`, which renders through
    /// `curlx_dyn_vprintf()` directly into the buffer, rather than the
    /// `#else` branch at L202-L214, which allocates a temporary with
    /// `curl_mvaprintf()`, appends it and frees it. Both branches are the
    /// same function in C and produce the same bytes; the direct one is
    /// chosen because it costs one allocation fewer, which matters for the
    /// allocation ceiling `tests/data/test1560` asserts.
    ///
    /// A second pass that emits fewer bytes than the first measured leaves
    /// the allocation wider than the content, which invariant 2 permits. One
    /// that tries to emit more is refused by [`DynBuf::write_at`] and
    /// surfaces as an error, never as a write outside the block.
    ///
    /// # Returns
    ///
    /// `CURLcode::CURLE_OK`, or `CURLcode::CURLE_TOO_LARGE` from
    /// [`DynBuf::grow`], or `CURLcode::CURLE_OUT_OF_MEMORY` for a failed
    /// reallocation or a `Display` implementation that reports an error. The
    /// buffer has been released in every failure case, which is what
    /// `lib/urlapi.c:L1486-L1488` relies on when it returns without a free.
    #[must_use = "a failed append has released the buffer; the code must be handled"]
    pub(crate) fn addf(&mut self, args: fmt::Arguments<'_>) -> CURLcode {
        let mut counter = FormatCounter { len: 0 };
        if fmt::write(&mut counter, args).is_err() {
            // The measuring pass cannot fail on its own; only a `Display`
            // implementation or a length overflow gets here. C's `#else`
            // branch answers a failed render the same way, releasing the
            // buffer at L212 before returning out of memory at L213.
            self.free();
            return CURLcode::CURLE_OUT_OF_MEMORY;
        }

        let idx = self.leng;
        let grown = self.grow(counter.len);
        if grown.is_err() {
            // Already released, contract 1.
            return grown;
        }

        // The sink borrows the buffer for the duration of the pass, so the
        // borrow is scoped and the two values it reports are copied out.
        let (outcome, end) = {
            let mut sink = FormatAppender {
                buf: self,
                offset: idx,
            };
            let outcome = fmt::write(&mut sink, args);
            (outcome, sink.offset)
        };
        if outcome.is_err() {
            self.free();
            return CURLcode::CURLE_OUT_OF_MEMORY;
        }

        self.leng = end;
        self.terminate();
        CURLcode::CURLE_OK
    }

    /// Shortens the content to `set` bytes and re-terminates there.
    ///
    /// The port of `curlx_dyn_setlen()`, `lib/curlx/dynbuf.c:L282-L292`. The
    /// allocation is kept, so a later append reuses it.
    ///
    /// Two call sites, both behaviorally live:
    ///
    /// - `lib/urlapi.c:L370` truncates the host at the colon in
    ///   `Curl_parse_port()`. That is the browser-compatibility leniency
    ///   `docs/KNOWN-DIVERGENCES.md` records as `FB4`: a trailing colon with
    ///   no digits cuts the name short and succeeds when a scheme is
    ///   present.
    /// - `lib/urlapi.c:L787` drops the last path segment while removing a
    ///   dot-dot segment, trimming the output at the final slash.
    ///
    /// # Why this returns a `bool` and not a `CURLcode`
    ///
    /// C returns `CURLE_BAD_FUNCTION_ARGUMENT` when `set > s->leng`, L288.
    /// That value, 43, is not part of `crate::error::CURLcode`, which
    /// carries only the five codes this port can produce, and adding it
    /// would mean adding a value no path can propagate. Nothing is lost:
    /// `lib/curlx/dynbuf.h:L49` declares the C function without
    /// `WARN_UNUSED_RESULT`, unlike its neighbors at L39-L44, and both call
    /// sites in `lib/urlapi.c` ignore the return value. So this reports
    /// whether the request was in bounds, and is deliberately not
    /// `#[must_use]`, which matches the C declaration rather than
    /// second-guessing it.
    ///
    /// # Returns
    ///
    /// `true` when the content was shortened, or was already that length.
    /// `false`, with nothing changed, when `set` exceeds the current length,
    /// which is the `CURLE_BAD_FUNCTION_ARGUMENT` case. Note that growing is
    /// not what this is for: bytes above the old length may be
    /// uninitialized, so the refusal is a safety property and not only a
    /// contract.
    pub(crate) fn setlen(&mut self, set: usize) -> bool {
        if set > self.leng {
            // L287-L288.
            return false;
        }
        self.leng = set;
        // L290. Shortening keeps `leng < allc`, so invariant 2 survives.
        self.terminate();
        true
    }

    /// The content length in bytes, excluding the terminator.
    ///
    /// The port of `curlx_dyn_len()`, `lib/curlx/dynbuf.c:L271-L277`. Used
    /// by `lib/urlapi.c` at L631, L638, L643, L781, L812, L1076 and L1966,
    /// where it decides whether a host is empty, how much of a buffer to
    /// pass on, and whether a part was produced at all.
    #[must_use]
    pub(crate) const fn len(&self) -> usize {
        self.leng
    }

    /// Whether the buffer holds no content.
    ///
    /// The `!curlx_dyn_len(host)` test at `lib/urlapi.c:L631` and the
    /// `if(curlx_dyn_len(&out))` at L812, spelled as a predicate. True both
    /// for a buffer that was never appended to, which has no allocation, and
    /// for one holding an empty string, which has one; the two are
    /// distinguishable through [`DynBuf::capacity`] when that matters, and it
    /// matters at L1934, where the pointer of the second is non-null.
    #[must_use]
    pub(crate) const fn is_empty(&self) -> bool {
        self.leng == 0
    }

    /// The size of the current allocation, including the terminator slot.
    ///
    /// C's `allc`, which has no accessor of its own because
    /// `lib/curlx/dynbuf.c` is a single translation unit that reads the
    /// field directly. Exposed here so that the growth policy in
    /// [`DynBuf::grow`] can be checked against
    /// `lib/curlx/dynbuf.c:L86-L102` numerically rather than by reading, and
    /// so that "has an allocation" is distinguishable from "has content".
    ///
    /// Zero exactly when there is no allocation. Otherwise strictly greater
    /// than [`DynBuf::len`], by invariant 2.
    #[must_use]
    pub(crate) const fn capacity(&self) -> usize {
        self.allc
    }

    /// The ceiling this buffer was built with.
    ///
    /// C's `toobig`, fixed by [`DynBuf::new`] and preserved by
    /// [`DynBuf::free`] so that a released buffer can be refilled under the
    /// same limit. Bounds `len() + 1`, not `len()`.
    #[must_use]
    pub(crate) const fn ceiling(&self) -> usize {
        self.toobig
    }

    /// The content, borrowed, without the terminator.
    ///
    /// One of the two read-only faces of `curlx_dyn_ptr()`,
    /// `lib/curlx/dynbuf.c:L237-L243`. This is what the port uses wherever
    /// C takes the pointer and reads through it without keeping it:
    /// `lib/urlapi.c:L339` looking for a bracket or a colon, L487 and L581
    /// inspecting a host, L783 searching backwards for a slash, and L986
    /// guessing a scheme from a host name.
    ///
    /// # Ownership
    ///
    /// **Nothing changes hands.** The buffer keeps the block, `Drop` will
    /// still release it, and the borrow checker ties the slice's lifetime to
    /// this value so it cannot outlive the allocation. Contrast
    /// [`DynBuf::into_raw`], which is the handover.
    ///
    /// An empty slice when there is no allocation, which is C's null return.
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        if self.bufr.is_null() {
            return &[];
        }
        // SAFETY: invariant 1 gives a non-null pointer to a live block,
        // invariant 2 gives it at least `leng + 1` bytes and invariant 3
        // says the first `leng` are initialized, so the slice lies inside the
        // allocation and reads only initialized memory. `u8` has an
        // alignment of one. The lifetime is tied to `&self`, so the slice
        // cannot outlive the block and no mutation can happen while it
        // lives.
        unsafe { slice::from_raw_parts(self.bufr.cast::<u8>(), self.leng) }
    }

    /// The content together with its terminator, borrowed.
    ///
    /// The other read-only face of `curlx_dyn_ptr()`, and the way to obtain
    /// a borrowed C-string pointer without giving up ownership:
    ///
    /// ```ignore
    /// let p: *const c_char = buf.as_bytes_with_nul().as_ptr().cast();
    /// ```
    ///
    /// The slice is `leng + 1` bytes and its last byte is zero, so a C
    /// function that only reads the pointer is safe to call with it. The
    /// callee must not free it.
    ///
    /// # Ownership
    ///
    /// **Nothing changes hands**, and this is the case to be careful about,
    /// because a pointer taken from the result looks exactly like the one
    /// [`DynBuf::into_raw`] produces. This value still owns the block and
    /// `Drop` will still release it, so a callee that frees the pointer
    /// causes a double free. Lend it; do not give it away.
    ///
    /// # Returns
    ///
    /// An empty slice, which is **not** NUL-terminated, when there is no
    /// allocation. That is the one case a caller has to check, and it
    /// corresponds exactly to C's null return: there is no terminator to
    /// point at because there is no memory. [`DynBuf::capacity`] distinguishes
    /// it from a buffer holding an empty string, whose slice here is the one
    /// byte `[0]`.
    #[must_use]
    pub(crate) fn as_bytes_with_nul(&self) -> &[u8] {
        if self.bufr.is_null() {
            return &[];
        }
        // `saturating_add` because the crate denies arithmetic that could
        // wrap. It is exact here: invariant 2 required `leng + 1` to be a
        // real allocation size, so `leng` cannot be `usize::MAX`.
        let with_nul = self.leng.saturating_add(1);
        // SAFETY: invariant 2 gives the block at least `with_nul` bytes and
        // invariant 3 says the last of them is the terminator, so every byte
        // of the slice is inside the allocation and initialized. Alignment
        // and lifetime reasoning is as in `as_bytes`.
        unsafe { slice::from_raw_parts(self.bufr.cast::<u8>(), with_nul) }
    }

    /// The content **plus its terminator byte**, borrowed mutably.
    ///
    /// This is the `FB6` surface, and the extra byte is the whole reason the
    /// method exists. Read contract 2 in the module documentation before
    /// changing the width of this slice.
    ///
    /// Two consumers need in-place mutation of a buffer, and both take a
    /// `char *` from `curlx_dyn_ptr()` in C:
    ///
    /// - `ipv6_parse()`, called at `lib/urlapi.c:L638`, rewrites a bracketed
    ///   address in place. It writes a terminator at `hostname[len + 1]` at
    ///   L422 and again at `hostname[hlen + 1]` at L437, and in the case
    ///   where normalization shortens nothing the second lands exactly on
    ///   index `leng` of this buffer, the terminator slot. A slice of `leng`
    ///   bytes has nowhere to put it.
    /// - the encoder's lowercase pass at `lib/urlapi.c:L1921-L1932` walks
    ///   the buffer looking for percent escapes and rewrites the two hex
    ///   digits of each. It stops at the terminator, so it needs to be able
    ///   to see it.
    ///
    /// # What a caller may and may not do
    ///
    /// Every byte of the slice may be written, the terminator included. What
    /// the caller must not do is leave the buffer without a zero at
    /// `[len()]`, because invariant 3 is what makes the C-string faces
    /// correct. Both consumers above satisfy that: `ipv6_parse()` restores
    /// the closing bracket at index `hlen` and leaves the byte above it
    /// zero, and the lowercase pass never changes a length.
    ///
    /// Writing a zero *inside* the content does not corrupt anything, but it
    /// does make [`DynBuf::len`] and a C `strlen()` of the pointer disagree,
    /// exactly as it would in C.
    ///
    /// # Ownership
    ///
    /// **Nothing changes hands.** The result is a unique borrow, so no other
    /// reference to these bytes can exist while it is held, and the
    /// obligation to release the block stays with this value.
    ///
    /// An empty slice when there is no allocation. Neither consumer can
    /// reach that: `lib/urlapi.c:L631` returns `CURLUE_NO_HOST` before
    /// L638 when the host buffer is empty, and L1918 always allocates
    /// before L1921 reads the pointer, because even an empty append
    /// allocates.
    #[must_use]
    pub(crate) fn as_mut_bytes_with_nul(&mut self) -> &mut [u8] {
        if self.bufr.is_null() {
            return &mut [];
        }
        // Exact for the same reason as in `as_bytes_with_nul`.
        let with_nul = self.leng.saturating_add(1);
        // SAFETY: the reasoning of `as_bytes_with_nul`, with a unique
        // borrow. `&mut self` guarantees no other reference to these bytes
        // exists, so handing out a `&mut [u8]` over them creates no
        // aliasing. Every byte in range is initialized, invariant 3, so the
        // caller may read as well as write.
        unsafe { slice::from_raw_parts_mut(self.bufr.cast::<u8>(), with_nul) }
    }

    /// Hands the block over as an owned [`CBuf`], relinquishing ownership.
    ///
    /// The handover face of `curlx_dyn_ptr()`, and the one
    /// `crate::alloc::CBuf::from_raw_parts` documents itself as existing
    /// for. `lib/urlapi.c` performs this transfer ten times, at L672, L813,
    /// L1025, L1049, L1077, L1185, L1399, L1489, L1934 and L1957, and in
    /// every case the buffer is simply never freed again. `MEMORY-OWNERSHIP.md`
    /// lists each site with the field that takes the pointer.
    ///
    /// Preferred over [`DynBuf::into_raw`] wherever the receiver is Rust,
    /// because the obligation stays typed: the `CBuf` releases the block on
    /// drop and `crate::alloc::CBuf::into_raw` is then the single point at
    /// which it reaches C.
    ///
    /// # Ownership
    ///
    /// **Ownership moves out of this value.** It is consumed, its `Drop` is
    /// suppressed, and the returned `CBuf` becomes the sole owner. The block
    /// keeps whatever spare capacity the growth policy gave it, which the
    /// `CBuf` invariant explicitly permits.
    ///
    /// # Returns
    ///
    /// `None` when there was no allocation, which is C's null pointer. That
    /// case is not an error: `lib/urlapi.c:L1934` takes a pointer that may
    /// be null and L1936 and L1995 both handle it.
    #[must_use = "ownership moves to the caller; discarding this leaks"]
    pub(crate) fn into_cbuf(self) -> Option<CBuf> {
        let len = self.leng;
        let raw = self.into_raw();
        // SAFETY: `from_raw_parts` needs a null pointer or a block this
        // crate may free, of at least `len + 1` bytes, whose first `len`
        // bytes are initialized and which no other owner will release.
        // Invariant 1 gives the provenance, invariant 2 the size, invariant
        // 3 the initialization, and `into_raw` above suppressed this value's
        // `Drop`, so this crate has exactly one owner again.
        unsafe { CBuf::from_raw_parts(raw, len) }
    }

    /// Hands the block over as a bare pointer, relinquishing ownership.
    ///
    /// The same transfer as [`DynBuf::into_cbuf`], in C's shape, for a
    /// caller that has to produce a `*mut c_char` and follow the C control
    /// flow line for line. Prefer [`DynBuf::into_cbuf`] in new code: an
    /// early return between this call and the point where the pointer
    /// reaches C leaks the block, which is precisely what the owned type
    /// prevents.
    ///
    /// # Ownership
    ///
    /// **Ownership moves to the caller**, and the whole obligation moves
    /// with it:
    ///
    /// * The C side must release it with `curl_free()`, per
    ///   `docs/libcurl/curl_url_get.md:L45` and
    ///   `include/curl/urlapi.h:L130-L131`. That call is correct because the
    ///   block came from the C allocator; `src/alloc.rs` documents the
    ///   resolution chain and the two configurations it does not support.
    /// * `curl_url_cleanup()` will not release it, per
    ///   `include/curl/urlapi.h:L116-L118`.
    /// * Rust code that wants the obligation back must call
    ///   `crate::alloc::CBuf::from_raw` or `from_raw_parts`. Keeping the
    ///   pointer around leaks it; building two owners over it frees it
    ///   twice.
    ///
    /// The value's `Drop` is suppressed with `ManuallyDrop` rather than
    /// merely skipped, so the suppression is visible at the type level.
    ///
    /// # Returns
    ///
    /// Null when there was no allocation, which is what C returns and what
    /// `lib/urlapi.c:L1936` tests for.
    #[must_use = "ownership moves to the caller; discarding this leaks"]
    pub(crate) fn into_raw(self) -> *mut c_char {
        let kept = mem::ManuallyDrop::new(self);
        kept.bufr
    }
}

impl Drop for DynBuf {
    /// Releases the block unless it was handed over.
    ///
    /// This is what removes the failure-path leak class the C original
    /// carries. `lib/urlapi.c` has to reach `curlx_dyn_free()` on every path
    /// out of every function that declares a buffer, which it manages at
    /// L669, L1189, L1282, L1955, L1960 and L1988 but which
    /// `docs/KNOWN-DIVERGENCES.md` records it missing elsewhere. Here there
    /// is no path to miss.
    fn drop(&mut self) {
        // SAFETY: invariant 1 says `bufr` is null, which `c_free` ignores, or
        // a live block from `src/alloc.rs` that this value alone owns.
        // `Drop` runs at most once per value, and the only other way out of
        // the type is `into_raw`, which wraps the value in `ManuallyDrop`
        // and so suppresses this call, therefore the block is released
        // exactly once and never after being given away.
        unsafe { c_free(self.bufr.cast::<c_void>()) };
    }
}

/// First pass of [`DynBuf::addf`]: measures the output without storing it.
///
/// Stands in for the length `curlx_dyn_vprintf()` computes internally while
/// it renders. Overflow is reported as a formatting error rather than
/// wrapped, so it becomes a failed append instead of an allocation sized far
/// too small.
struct FormatCounter {
    /// Bytes seen so far.
    len: usize,
}

impl fmt::Write for FormatCounter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.len = self.len.checked_add(s.len()).ok_or(fmt::Error)?;
        Ok(())
    }
}

/// Second pass of [`DynBuf::addf`]: writes into the reserved space.
///
/// Every write goes through [`DynBuf::write_at`], which bounds-checks
/// against the allocation and refuses to touch the terminator slot, so this
/// sink cannot write outside the block even if the second pass disagrees
/// with the first about how many bytes the output needs.
struct FormatAppender<'a> {
    /// The destination, borrowed for the duration of the pass.
    buf: &'a mut DynBuf,
    /// Bytes written so far, and the offset of the next write. Starts at the
    /// buffer's length, because this appends rather than overwrites.
    offset: usize,
}

impl fmt::Write for FormatAppender<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if !self.buf.write_at(self.offset, s.as_bytes()) {
            // The second pass wants more room than the first pass measured,
            // or than the allocation holds. Refused here so the failure is
            // an error code instead of an overrun.
            return Err(fmt::Error);
        }
        self.offset = self.offset.checked_add(s.len()).ok_or(fmt::Error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // The crate root denies the panicking constructs so that no panic can
    // ever reach the C boundary. A test's entire job is to panic when an
    // assertion fails, and a test never crosses that boundary, so the
    // denials are relaxed here and only here. The allowance is scoped to
    // this module and enumerated rather than blanket, matching
    // `src/alloc.rs`.
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::arithmetic_side_effects)]

    // Imported by name rather than through a glob, which is the rule the
    // plan sets for the whole crate at AAP 0.4.3.
    use super::{DynBuf, MAX_DYNBUF_SIZE, MIN_FIRST_ALLOC};
    use crate::alloc::CBuf;
    use crate::error::CURLcode;

    /// The ceiling `lib/urlapi.c` passes at nine of its twelve init sites.
    ///
    /// `CURL_MAX_INPUT_LENGTH`, `lib/urldata.h:L131`. Written out here
    /// rather than imported, so that this module's dependency set stays
    /// exactly `src/alloc.rs` and `src/error.rs`.
    const CEILING: usize = 8_000_000;

    /// Asserts the structural invariants after every state change.
    ///
    /// Invariant 2 is the interesting one, `leng < allc` whenever there is
    /// an allocation, because it is contract 2 from the module
    /// documentation: the terminator slot always exists.
    fn check_invariants(buf: &DynBuf) {
        if buf.capacity() == 0 {
            assert_eq!(buf.len(), 0, "no allocation implies no content");
            assert!(buf.as_bytes().is_empty());
            assert!(buf.as_bytes_with_nul().is_empty());
        } else {
            assert!(
                buf.len() < buf.capacity(),
                "len {} must leave room for a terminator in {} bytes",
                buf.len(),
                buf.capacity()
            );
            let with_nul = buf.as_bytes_with_nul();
            assert_eq!(with_nul.len(), buf.len() + 1);
            assert_eq!(with_nul[buf.len()], 0, "byte [len] must be the NUL");
        }
        // L99-L101: no allocation is ever larger than the ceiling.
        assert!(buf.capacity() <= buf.ceiling());
    }

    #[test]
    fn new_allocates_nothing() {
        // curlx_dyn_init, lib/curlx/dynbuf.c:L38-L50.
        let buf = DynBuf::new(CEILING);
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.capacity(), 0);
        assert_eq!(buf.ceiling(), CEILING);
        assert!(buf.is_empty());
        assert!(buf.ceiling_is_sane());
        check_invariants(&buf);
        // No allocation means C's NULL pointer, which the accessors report
        // as an empty slice rather than by panicking.
        assert!(buf.as_bytes().is_empty());
        assert!(buf.as_bytes_with_nul().is_empty());
        assert!(buf.into_raw().is_null());
    }

    #[test]
    fn first_append_reaches_min_first_alloc() {
        // lib/curlx/dynbuf.c:L91-L92: fit < MIN_FIRST_ALLOC, so the first
        // allocation is MIN_FIRST_ALLOC rather than the exact fit.
        let mut buf = DynBuf::new(CEILING);
        assert_eq!(buf.addn(b"https"), CURLcode::CURLE_OK);
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.capacity(), MIN_FIRST_ALLOC);
        assert_eq!(buf.as_bytes(), b"https");
        assert_eq!(buf.as_bytes_with_nul(), b"https\0");
        check_invariants(&buf);
    }

    #[test]
    fn min_first_alloc_boundary_is_exact() {
        // The comparison at L91 is `fit < MIN_FIRST_ALLOC`, strictly, so a
        // fit of exactly 32 takes the `a = fit` branch at L94. Both sides of
        // the boundary are pinned here because an off-by-one would change
        // every subsequent allocation size.
        let mut below = DynBuf::new(CEILING);
        assert_eq!(below.addn(&[b'x'; 30]), CURLcode::CURLE_OK);
        assert_eq!(below.capacity(), 32, "fit 31 < 32 takes MIN_FIRST_ALLOC");

        let mut at = DynBuf::new(CEILING);
        assert_eq!(at.addn(&[b'x'; 31]), CURLcode::CURLE_OK);
        assert_eq!(at.capacity(), 32, "fit 32 is not < 32, so a = fit = 32");

        let mut above = DynBuf::new(CEILING);
        assert_eq!(above.addn(&[b'x'; 32]), CURLcode::CURLE_OK);
        assert_eq!(above.capacity(), 33, "fit 33 takes a = fit");
        check_invariants(&above);
    }

    #[test]
    fn first_append_larger_than_min_first_alloc_uses_exact_fit() {
        // lib/curlx/dynbuf.c:L94: a = fit, the exact size and not a rounded
        // one, so a single large append costs exactly one allocation of
        // exactly the needed size.
        let mut buf = DynBuf::new(CEILING);
        assert_eq!(buf.addn(&[b'a'; 100]), CURLcode::CURLE_OK);
        assert_eq!(buf.len(), 100);
        assert_eq!(buf.capacity(), 101, "100 content bytes plus terminator");
        check_invariants(&buf);
    }

    #[test]
    fn first_append_is_clamped_by_a_small_ceiling() {
        // lib/curlx/dynbuf.c:L89-L90: MIN_FIRST_ALLOC > toobig, so the
        // ceiling wins and no allocation is larger than the buffer may use.
        let mut buf = DynBuf::new(8);
        assert_eq!(buf.addn(b"abc"), CURLcode::CURLE_OK);
        assert_eq!(buf.capacity(), 8, "the ceiling, not MIN_FIRST_ALLOC");
        assert_eq!(buf.len(), 3);
        check_invariants(&buf);

        // Right up against the ceiling: 7 content bytes plus a terminator is
        // exactly 8, so fit == toobig and L82 does not fire.
        let mut full = DynBuf::new(8);
        assert_eq!(full.addn(b"1234567"), CURLcode::CURLE_OK);
        assert_eq!(full.len(), 7);
        assert_eq!(full.capacity(), 8);
        check_invariants(&full);
    }

    #[test]
    fn empty_append_still_allocates() {
        // The property lib/urlapi.c:L1156 depends on, whose pointer becomes
        // u->host at L1185. fit is 1, so the first-invoke branch runs and a
        // real block appears even though nothing was added.
        let mut buf = DynBuf::new(CEILING);
        assert_eq!(buf.add(""), CURLcode::CURLE_OK);
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
        assert_eq!(buf.capacity(), MIN_FIRST_ALLOC, "an allocation exists");
        assert_eq!(buf.as_bytes_with_nul(), b"\0");
        check_invariants(&buf);
        // And the handover therefore yields a non-null empty C string, not a
        // null pointer, which is what distinguishes this from a fresh buffer.
        let handed = buf.into_cbuf();
        let handed = handed.unwrap();
        assert!(handed.is_empty());
        assert_eq!(handed.as_bytes_with_nul(), b"\0");
    }

    #[test]
    fn growth_doubles_from_the_current_allocation() {
        // The sequence below is worked through by hand against
        // lib/curlx/dynbuf.c:L96-L102 and pins every intermediate size,
        // because a divergence here changes the allocation count without
        // changing any output byte.
        let mut buf = DynBuf::new(CEILING);

        assert_eq!(buf.addn(&[b'a'; 5]), CURLcode::CURLE_OK);
        assert_eq!((buf.len(), buf.capacity()), (5, 32), "fit 6 -> 32");

        // fit 26 fits inside 32, so L104 skips the reallocation entirely.
        assert_eq!(buf.addn(&[b'b'; 20]), CURLcode::CURLE_OK);
        assert_eq!((buf.len(), buf.capacity()), (25, 32), "no realloc");

        // fit 36 needs one doubling.
        assert_eq!(buf.addn(&[b'c'; 10]), CURLcode::CURLE_OK);
        assert_eq!((buf.len(), buf.capacity()), (35, 64), "fit 36 -> 64");

        // fit 136 needs two more.
        assert_eq!(buf.addn(&[b'd'; 100]), CURLcode::CURLE_OK);
        assert_eq!((buf.len(), buf.capacity()), (135, 256), "fit 136 -> 256");

        // fit 1136 needs three more.
        assert_eq!(buf.addn(&[b'e'; 1000]), CURLcode::CURLE_OK);
        assert_eq!((buf.len(), buf.capacity()), (1135, 2048), "-> 2048");
        check_invariants(&buf);

        // The content is the concatenation, in order.
        let bytes = buf.as_bytes();
        assert_eq!(bytes.len(), 1135);
        assert!(bytes[..5].iter().all(|&b| b == b'a'));
        assert!(bytes[5..25].iter().all(|&b| b == b'b'));
        assert!(bytes[25..35].iter().all(|&b| b == b'c'));
        assert!(bytes[35..135].iter().all(|&b| b == b'd'));
        assert!(bytes[135..].iter().all(|&b| b == b'e'));
    }

    #[test]
    fn doubling_is_clamped_to_the_ceiling() {
        // lib/curlx/dynbuf.c:L99-L101, with the comment "no point in
        // allocating a larger buffer than this is allowed to use".
        let mut buf = DynBuf::new(100);
        assert_eq!(buf.addn(&[b'a'; 60]), CURLcode::CURLE_OK);
        assert_eq!(buf.capacity(), 61, "first invoke takes the exact fit");

        // fit 91; doubling 61 gives 122, which the clamp brings to 100.
        assert_eq!(buf.addn(&[b'b'; 30]), CURLcode::CURLE_OK);
        assert_eq!((buf.len(), buf.capacity()), (90, 100), "clamped");

        // fit 100 equals the ceiling exactly, and equals the allocation, so
        // no reallocation happens and the append succeeds.
        assert_eq!(buf.addn(&[b'c'; 9]), CURLcode::CURLE_OK);
        assert_eq!((buf.len(), buf.capacity()), (99, 100), "exactly full");
        check_invariants(&buf);

        // One more byte needs fit 101, above the ceiling.
        assert_eq!(buf.addn(b"x"), CURLcode::CURLE_TOO_LARGE);
        assert_eq!(buf.capacity(), 0, "and the buffer is gone");
    }

    #[test]
    fn too_large_releases_the_whole_buffer() {
        // Contract 1. lib/curlx/dynbuf.c:L82-L85 frees before returning, and
        // lib/urlapi.c:L1885, L1895, L1905, L1912 and L1959-L1961 all return
        // without a free of their own because of it. This is the single most
        // important assertion in the file.
        let mut buf = DynBuf::new(64);
        assert_eq!(buf.addn(b"kept until the failure"), CURLcode::CURLE_OK);
        assert_eq!(buf.len(), 22);
        assert!(buf.capacity() > 0);

        assert_eq!(buf.addn(&[b'x'; 64]), CURLcode::CURLE_TOO_LARGE);

        // Everything the C free at L60-L61 does: pointer nulled, both
        // lengths zeroed, ceiling untouched.
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.capacity(), 0);
        assert_eq!(buf.ceiling(), 64, "the ceiling survives a failure");
        assert!(buf.is_empty());
        assert!(buf.as_bytes().is_empty());
        assert!(buf.as_bytes_with_nul().is_empty());
        check_invariants(&buf);
        // A later free, reset and Drop must all be safe on the wreckage.
        buf.reset();
        buf.free();
        buf.free();
        check_invariants(&buf);
        assert!(buf.into_raw().is_null(), "nothing left to hand over");
    }

    #[test]
    fn a_failed_append_leaves_the_buffer_reusable() {
        // The C comment at lib/curlx/dynbuf.c:L52-L54 says free "does not
        // touch the 'init' field and thus this buffer can be reused to add
        // data to again". A poisoned buffer is a freed buffer, so the same
        // holds after a failure.
        let mut buf = DynBuf::new(16);
        assert_eq!(buf.addn(&[b'a'; 20]), CURLcode::CURLE_TOO_LARGE);
        assert_eq!(buf.capacity(), 0);

        assert_eq!(buf.addn(b"fresh"), CURLcode::CURLE_OK);
        assert_eq!(buf.as_bytes(), b"fresh");
        assert_eq!(buf.capacity(), 16, "MIN_FIRST_ALLOC > 16, so clamped");
        check_invariants(&buf);
    }

    #[test]
    fn a_zero_ceiling_rejects_every_append() {
        // C asserts a nonzero ceiling at lib/curlx/dynbuf.c:L41. This port
        // accepts one and behaves definitely instead: the smallest request
        // needs fit 1, which is already above zero.
        let mut buf = DynBuf::new(0);
        assert_eq!(buf.addn(b""), CURLcode::CURLE_TOO_LARGE);
        assert_eq!(buf.capacity(), 0);
        assert_eq!(buf.addn(b"x"), CURLcode::CURLE_TOO_LARGE);
        check_invariants(&buf);
    }

    #[test]
    fn reset_clears_the_content_and_keeps_the_allocation() {
        // curlx_dyn_reset, lib/curlx/dynbuf.c:L125-L133, and the reason
        // lib/urlapi.c:L532-L565 can reset and refill four times without
        // reallocating.
        let mut buf = DynBuf::new(CEILING);

        // On a fresh buffer: a no-op, and no null dereference.
        buf.reset();
        assert_eq!((buf.len(), buf.capacity()), (0, 0));
        check_invariants(&buf);

        assert_eq!(buf.addn(b"192.168.000.001"), CURLcode::CURLE_OK);
        let kept = buf.capacity();
        assert_eq!(kept, 32);

        // On a populated buffer: content gone, allocation kept, terminator
        // written at [0] as L131 does.
        buf.reset();
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.capacity(), kept, "the allocation survives");
        assert_eq!(buf.as_bytes_with_nul(), b"\0");
        check_invariants(&buf);

        // Refilling reuses it, so no reallocation follows.
        assert_eq!(buf.addn(b"192.168.0.1"), CURLcode::CURLE_OK);
        assert_eq!(buf.capacity(), kept);
        assert_eq!(buf.as_bytes(), b"192.168.0.1");

        // On an already-freed buffer: explicitly supported by the C comment
        // at L122-L123, and it must not touch the null pointer.
        buf.free();
        buf.reset();
        buf.reset();
        assert_eq!((buf.len(), buf.capacity()), (0, 0));
        check_invariants(&buf);
    }

    #[test]
    fn setlen_truncates_and_reterminates() {
        // curlx_dyn_setlen, lib/curlx/dynbuf.c:L282-L292. This is the host
        // truncation at lib/urlapi.c:L370, which is FB4, and the path trim
        // at L787.
        let mut buf = DynBuf::new(CEILING);
        assert_eq!(buf.addn(b"example.com:8080"), CURLcode::CURLE_OK);
        let kept = buf.capacity();

        assert!(buf.setlen(11), "11 is within the current length");
        assert_eq!(buf.len(), 11);
        assert_eq!(buf.as_bytes(), b"example.com");
        assert_eq!(buf.as_bytes_with_nul(), b"example.com\0");
        assert_eq!(buf.capacity(), kept, "truncation keeps the allocation");
        check_invariants(&buf);

        // Setting the same length again is the CURLE_OK case at L289-L291.
        assert!(buf.setlen(11));
        assert_eq!(buf.as_bytes(), b"example.com");

        // Truncating to nothing leaves a valid empty C string.
        assert!(buf.setlen(0));
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.as_bytes_with_nul(), b"\0");
        check_invariants(&buf);

        // Appending after a truncation continues from the new length.
        assert_eq!(buf.addn(b"host"), CURLcode::CURLE_OK);
        assert_eq!(buf.as_bytes(), b"host");
    }

    #[test]
    fn setlen_refuses_to_grow() {
        // L287-L288 answers set > leng with CURLE_BAD_FUNCTION_ARGUMENT,
        // reported here as false. Refusing matters beyond the contract:
        // bytes above the length may be uninitialized.
        let mut buf = DynBuf::new(CEILING);
        assert_eq!(buf.addn(b"abc"), CURLcode::CURLE_OK);
        assert!(!buf.setlen(4), "beyond the content");
        assert_eq!(buf.len(), 3, "and nothing changed");
        assert_eq!(buf.as_bytes(), b"abc");
        check_invariants(&buf);

        // Including on a buffer with no allocation at all, where C would
        // dereference a null pointer if it got past the bounds test.
        let mut fresh = DynBuf::new(CEILING);
        assert!(!fresh.setlen(1));
        assert!(fresh.setlen(0), "the in-bounds no-op is still accepted");
        assert_eq!(fresh.capacity(), 0);
        check_invariants(&fresh);
    }

    #[test]
    fn the_terminator_slot_is_always_writable() {
        // Contract 2, and FB6 in docs/KNOWN-DIVERGENCES.md. ipv6_parse()
        // writes hostname[hlen + 1] at lib/urlapi.c:L437; after the
        // hostname++ at L397 and the hlen -= 2 at L398, that index is
        // exactly `len()` of this buffer when normalization shortens
        // nothing. The write must be expressible without unsafe in
        // src/parse/ipv6.rs.
        let mut buf = DynBuf::new(CEILING);
        assert_eq!(buf.addn(b"[2001:db8::1]"), CURLcode::CURLE_OK);
        let leng = buf.len();
        assert_eq!(leng, 13);

        let view = buf.as_mut_bytes_with_nul();
        assert_eq!(view.len(), leng + 1, "the spare byte is reachable");
        // L437: terminate one past the closing bracket.
        view[leng] = 0;
        // L439: restore the ending bracket.
        view[leng - 1] = b']';
        assert_eq!(&view[..leng], b"[2001:db8::1]");

        check_invariants(&buf);
        assert_eq!(buf.as_bytes(), b"[2001:db8::1]");
        assert_eq!(buf.len(), leng, "an in-place rewrite changes no length");
    }

    #[test]
    fn the_mutable_view_covers_every_allocated_length() {
        // The guarantee has to hold for every length, not only for the one
        // above, because ipv6_parse() is reached with hosts of any size and
        // the interesting case is a length that sits exactly one below the
        // allocation.
        let source = [b'z'; 80];
        for len in 0..source.len() {
            let mut buf = DynBuf::new(CEILING);
            assert_eq!(buf.addn(&source[..len]), CURLcode::CURLE_OK);
            assert_eq!(buf.as_mut_bytes_with_nul().len(), len + 1);
            check_invariants(&buf);
        }

        // And at a length pressed right up against a small ceiling, where
        // the allocation is exactly len + 1 and there is no slack at all.
        let mut tight = DynBuf::new(8);
        assert_eq!(tight.addn(b"1234567"), CURLcode::CURLE_OK);
        assert_eq!(tight.capacity(), 8);
        let view = tight.as_mut_bytes_with_nul();
        assert_eq!(view.len(), 8);
        view[7] = 0;
        check_invariants(&tight);
    }

    #[test]
    fn the_mutable_view_serves_the_lowercase_pass() {
        // lib/urlapi.c:L1921-L1932 walks the buffer in place and lower-cases
        // the hex digits of any percent escape already present. It is a
        // borrow, not a handover, and it changes no length.
        let mut buf = DynBuf::new(CEILING);
        assert_eq!(buf.add("/a%2Fb%3Fc%FF"), CURLcode::CURLE_OK);
        {
            let view = buf.as_mut_bytes_with_nul();
            let mut i = 0;
            while i < view.len() && view[i] != 0 {
                let escape = view[i] == b'%' && i + 2 < view.len();
                if escape && view[i + 1] != 0 && view[i + 2] != 0 {
                    view[i + 1] = view[i + 1].to_ascii_lowercase();
                    view[i + 2] = view[i + 2].to_ascii_lowercase();
                    i += 3;
                } else {
                    i += 1;
                }
            }
        }
        assert_eq!(buf.as_bytes(), b"/a%2fb%3fc%ff");
        check_invariants(&buf);
    }

    #[test]
    fn addf_appends_formatted_output() {
        // The four IPv4 normalization sites, lib/urlapi.c:L534, L544, L554
        // and L565, which print "%u.%u.%u.%u" after a reset.
        let mut buf = DynBuf::new(CEILING);
        assert_eq!(buf.addn(b"010.0.0.1"), CURLcode::CURLE_OK);
        buf.reset();
        let parts: [u32; 4] = [10, 0, 0, 1];
        let code = buf.addf(format_args!(
            "{}.{}.{}.{}",
            parts[0], parts[1], parts[2], parts[3]
        ));
        assert_eq!(code, CURLcode::CURLE_OK);
        assert_eq!(buf.as_bytes(), b"10.0.0.1");
        assert_eq!(buf.as_bytes_with_nul(), b"10.0.0.1\0");
        check_invariants(&buf);

        // Appending, not replacing: the offset starts at the current length.
        assert_eq!(buf.addf(format_args!(":{}", 8080)), CURLcode::CURLE_OK);
        assert_eq!(buf.as_bytes(), b"10.0.0.1:8080");
        check_invariants(&buf);
    }

    #[test]
    fn addf_grows_and_respects_the_ceiling() {
        // A formatted append is subject to the same policy as any other, so
        // a failure releases the buffer exactly as in contract 1. That is
        // what lib/urlapi.c:L1486-L1488 relies on when it returns without a
        // free.
        let mut wide = DynBuf::new(CEILING);
        assert_eq!(wide.addf(format_args!("{:200}", 7)), CURLcode::CURLE_OK);
        assert_eq!(wide.len(), 200);
        assert_eq!(wide.capacity(), 201, "one allocation of the exact fit");
        check_invariants(&wide);

        let mut narrow = DynBuf::new(16);
        assert_eq!(
            narrow.addf(format_args!("{:32}", 1)),
            CURLcode::CURLE_TOO_LARGE
        );
        assert_eq!(narrow.capacity(), 0, "released, not merely refused");
        assert_eq!(narrow.len(), 0);
        check_invariants(&narrow);
    }

    #[test]
    fn interior_zero_bytes_are_stored_verbatim() {
        // memcpy at lib/curlx/dynbuf.c:L115 copies what it is given. The
        // buffer then holds more bytes than a C strlen() of its pointer
        // would report, and len() is the truthful number, exactly as in C.
        // Curl_junkscan rejects control bytes at lib/urlapi.c:L223-L246, so
        // no call site in this crate can produce one.
        let mut buf = DynBuf::new(CEILING);
        assert_eq!(buf.addn(b"a\0b"), CURLcode::CURLE_OK);
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.as_bytes(), b"a\0b");
        assert_eq!(buf.as_bytes_with_nul(), b"a\0b\0");
        check_invariants(&buf);
    }

    #[test]
    fn into_raw_suppresses_drop_and_hands_the_block_over() {
        // The handover at lib/urlapi.c:L672, L813, L1025, L1049, L1077,
        // L1185, L1399, L1489, L1934 and L1957. If Drop still ran, the
        // adoption below would be a use after free, and a run under
        // valgrind would say so.
        let mut buf = DynBuf::new(CEILING);
        assert_eq!(buf.addn(b"example.com/path"), CURLcode::CURLE_OK);
        let len = buf.len();
        let raw = buf.into_raw();
        assert!(!raw.is_null());

        // SAFETY: `raw` came from this module's C-allocator block, it is at
        // least `len + 1` bytes with its first `len` initialized, `into_raw`
        // suppressed the buffer's Drop, and no other owner exists. Adopting
        // it here is what keeps the test leak-free.
        let adopted = unsafe { CBuf::from_raw_parts(raw, len) };
        let adopted = adopted.unwrap();
        assert_eq!(adopted.as_bytes(), b"example.com/path");
        assert_eq!(adopted.len(), len);
    }

    #[test]
    fn into_cbuf_transfers_ownership_and_keeps_the_content() {
        let mut buf = DynBuf::new(CEILING);
        assert_eq!(buf.add("fragment"), CURLcode::CURLE_OK);
        let handed = buf.into_cbuf();
        let handed = handed.unwrap();
        assert_eq!(handed.as_bytes(), b"fragment");
        assert_eq!(handed.as_bytes_with_nul(), b"fragment\0");
        // The CBuf releases the block when it drops here, exactly once.
    }

    #[test]
    fn into_cbuf_reports_the_absent_allocation() {
        // C's null return at lib/curlx/dynbuf.c:L242, which
        // lib/urlapi.c:L1934 takes and L1936 and L1995 both handle.
        let fresh = DynBuf::new(CEILING);
        assert!(fresh.into_cbuf().is_none());

        let mut poisoned = DynBuf::new(4);
        assert_eq!(poisoned.addn(b"toolong"), CURLcode::CURLE_TOO_LARGE);
        assert!(poisoned.into_cbuf().is_none(), "a poisoned buffer too");
    }

    #[test]
    fn borrowing_accessors_keep_ownership() {
        // The counterpart to the handover test: after a borrow the buffer is
        // still the owner, still usable and still responsible for the free.
        // A double free here would abort the test binary.
        let mut buf = DynBuf::new(CEILING);
        assert_eq!(buf.addn(b"borrowed"), CURLcode::CURLE_OK);
        assert_eq!(buf.as_bytes().len(), 8);
        assert_eq!(buf.as_bytes_with_nul().len(), 9);
        assert_eq!(buf.as_mut_bytes_with_nul().len(), 9);
        assert_eq!(buf.addn(b" twice"), CURLcode::CURLE_OK);
        assert_eq!(buf.as_bytes(), b"borrowed twice");
        check_invariants(&buf);
        // Dropping here is the only release.
    }

    #[test]
    fn byte_at_a_time_assembly_matches_the_dedot_loop() {
        // lib/urlapi.c:L806 appends one byte per iteration, with the ceiling
        // set to clen + 1 at L726. The exact-fit ceiling means the output can
        // never overflow it, and the doubling means the loop costs a
        // logarithmic number of allocations rather than one per byte.
        let input = b"/hello/world/again";
        let mut buf = DynBuf::new(input.len() + 1);
        let mut allocations = 0usize;
        let mut previous = 0usize;
        for byte in input {
            assert_eq!(buf.addn(&[*byte]), CURLcode::CURLE_OK);
            if buf.capacity() != previous {
                previous = buf.capacity();
                allocations += 1;
            }
        }
        assert_eq!(buf.as_bytes(), input);
        assert_eq!(buf.len(), 18);
        // MIN_FIRST_ALLOC is 32, above the ceiling of 19, so the very first
        // append takes the L89-L90 branch and no further growth happens.
        assert_eq!(allocations, 1, "one allocation for eighteen appends");
        assert_eq!(previous, 19, "sized by the ceiling, which is clen + 1");
        check_invariants(&buf);
    }

    #[test]
    fn the_ceiling_bound_has_a_name() {
        // lib/curlx/dynbuf.h:L63 and the assertion at
        // lib/curlx/dynbuf.c:L42. The predicate is a query, not a gate: an
        // absurd ceiling is still handled, because the doubling saturates
        // rather than wrapping.
        assert_eq!(MAX_DYNBUF_SIZE, usize::MAX / 2);
        assert!(DynBuf::new(MAX_DYNBUF_SIZE).ceiling_is_sane());
        assert!(DynBuf::new(CEILING).ceiling_is_sane());
        let absurd = DynBuf::new(usize::MAX);
        assert!(!absurd.ceiling_is_sane());

        let mut usable = DynBuf::new(usize::MAX);
        assert_eq!(usable.addn(b"still works"), CURLcode::CURLE_OK);
        assert_eq!(usable.capacity(), MIN_FIRST_ALLOC);
        check_invariants(&usable);
    }

    #[test]
    fn an_unrepresentable_request_is_reported_as_too_large() {
        // C computes fit with a plain addition, so this would wrap. The port
        // reports it instead: a size that cannot be represented is above
        // every legal ceiling. Unreachable from any call site, because
        // Curl_junkscan caps input at 8000000 bytes, but pinned so that a
        // future edit cannot reintroduce the wrap.
        let mut buf = DynBuf::new(usize::MAX);
        assert_eq!(buf.addn(b"seed"), CURLcode::CURLE_OK);
        // A slice this long cannot exist, so the overflow is provoked
        // through the formatted path's measured length instead, which is the
        // one length the buffer accepts from outside itself.
        let mut counter = super::FormatCounter { len: usize::MAX };
        {
            use core::fmt::Write as _;
            assert!(counter.write_str("x").is_err(), "the counter overflows");
        }
        // And the buffer's own guard, exercised directly through grow.
        assert_eq!(buf.grow(usize::MAX), CURLcode::CURLE_TOO_LARGE);
        assert_eq!(buf.capacity(), 0, "released on the failure path");
        check_invariants(&buf);
    }

    #[test]
    fn write_at_refuses_to_touch_the_terminator_slot() {
        // The guard that makes the formatted path safe even if the second
        // pass disagrees with the first. Exercised directly, because no
        // public operation can reach it: grow always reserves enough first.
        let mut buf = DynBuf::new(CEILING);
        assert_eq!(buf.addn(b"abc"), CURLcode::CURLE_OK);
        let cap = buf.capacity();
        assert!(buf.write_at(0, b"xyz"), "inside the content");
        assert_eq!(buf.as_bytes(), b"xyz");
        assert!(!buf.write_at(cap - 1, b"!"), "the terminator slot");
        assert!(!buf.write_at(cap, b"!"), "past the allocation");
        assert!(!buf.write_at(usize::MAX, b"!"), "an overflowing offset");
        assert!(buf.write_at(0, b""), "an empty write is always fine");
        assert_eq!(buf.as_bytes(), b"xyz", "and nothing was corrupted");
        check_invariants(&buf);
    }
}
