// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The safe C-buffer adapter: every C-visible buffer this crate produces is
//! shaped here, over the owned blocks that `src/ffi.rs` allocates.
//!
//! The division of labour matters, because the two halves have different
//! risks. `src/ffi.rs` is the **raw allocator boundary**: it holds
//! `c_malloc`, `c_calloc`, `c_realloc`, `c_free`, the exported `curl_free`
//! and the owned-block type [`CBlock`], and it is the only module in the
//! crate that contains `unsafe`. This module is the **safe layer over
//! that**: it turns a [`CBlock`] into a [`CBuf`], a NUL-terminated buffer
//! with a length, and it is the one place the rest of the crate asks for a
//! C-visible buffer. It carries no `unsafe` of its own.
//!
//! What the two halves guarantee together is that every byte this crate
//! hands to C came from the C allocator. That single property is what makes
//! the documented free contract hold *by construction* rather than by
//! discipline repeated at each of the twenty-seven allocation sites in
//! `lib/urlapi.c`. If any module allocated a C-visible buffer some other
//! way, the contract would become a matter of hope.
//!
//! # The contract this module exists to satisfy
//!
//! `docs/libcurl/curl_url_get.md:L45` states it as documentation:
//!
//! > The returned content pointer must be freed with curl_free(3) after
//! > use.
//!
//! `include/curl/urlapi.h:L130-L131` restates it as the header's own
//! promise, that the returned pointer MUST be freed with `curl_free()`
//! afterwards. `include/curl/urlapi.h:L116-L118` completes the picture:
//! `curl_url_cleanup()` frees the handle and its own strings, and it
//! explicitly does *not* free strings previously returned with the URL
//! API. Ownership of a returned buffer therefore leaves this crate for
//! good, and its release happens in code this crate does not control and
//! cannot inspect.
//!
//! # How `curl_free()` actually resolves
//!
//! `curl_free()` is a one-line forward, `lib/escape.c:L189-L192`:
//!
//! ```c
//! void curl_free(void *p)
//! {
//!   curlx_free(p);
//! }
//! ```
//!
//! `curlx_free` is not a function. It is a macro that `lib/curl_setup.h`
//! resolves three different ways, decided entirely at compile time by the
//! configuration of whatever translation unit calls it:
//!
//! 1. `lib/curl_setup.h:L1461`, under `CURL_MEMDEBUG`: it becomes
//!    `curl_dbg_free(ptr, __LINE__, __FILE__)`, the tracking free. See the
//!    section on limitation R3 below, because this case is not merely
//!    unsupported, it is actively dangerous.
//! 2. `lib/curl_setup.h:L1478`, when `BUILDING_LIBCURL` is defined: it
//!    becomes `Curl_cfree`, an indirect call through a mutable global
//!    function pointer declared at `lib/curl_setup.h:L1309`, initialized
//!    to `free` at `lib/easy.c:L107` and reassignable at run time at
//!    `lib/easy.c:L237`. See limitation R4 below.
//! 3. `lib/curl_setup.h:L1484`, otherwise: plain `free`.
//!
//! Cases 2 and 3 are the two supported ones, and both end in the C
//! allocator's `free` as long as nobody has substituted the pointer in
//! case 2. That is precisely why this module allocates with the C
//! allocator: it is the one choice that is correct for both.
//!
//! # Why `CString::into_raw` is banned crate-wide
//!
//! The idiomatic Rust route to a `char *` is `CString::into_raw`, and it
//! is unusable here. A pointer produced that way is owned by the *Rust*
//! allocator, so it has to come back to Rust, through `CString::from_raw`,
//! to be released. Published guidance is explicit that the C free function
//! must not be called on such a pointer. The contract quoted above
//! requires exactly that call. The two cannot be reconciled, so the
//! conversion appears nowhere in this crate and this module deliberately
//! offers no helper that would hand out a Rust-allocated pointer. The
//! absence of such a helper here is the guard rail: a later module reaching
//! for `CString::into_raw` has to introduce the import itself, which is
//! visible in review.
//!
//! # Reported limitation R3: memory-debug builds are incompatible
//!
//! This is the sharp edge, and it is worse than "the accounting comes out
//! wrong". Under `CURL_MEMDEBUG`, `curl_dbg_malloc` allocates
//! `sizeof(struct memdebug) + wantedsize` and returns a pointer to the
//! *user* area, which sits immediately after a header it wrote.
//! `curl_dbg_free`, at `lib/memdebug.c:L362-L385`, computes
//!
//! ```c
//! mem = (void *)((char *)ptr - offsetof(struct memdebug, mem));
//! ```
//!
//! at L376 and releases *that* address at L383. The subtraction is
//! unconditional: nothing checks whether the incoming pointer really has a
//! header in front of it. A buffer from a plain C allocator has no such
//! header, so handing one to `curl_dbg_free` releases an address a few
//! bytes below the real allocation. That is a wild free, not a rejected
//! one, which means the failure mode is silent heap corruption rather than
//! a diagnostic.
//!
//! Routing this crate's frees through `Curl_cfree` instead would mean
//! importing a libcurl-private symbol, and it would still leave the
//! accounting wrong, because the matching allocation was never logged in
//! the tracking table. There is no fix available from inside this
//! directory, so the parity harness is built *without* the memory-debug
//! configuration. The visible cost is the `Allocations: 3000` ceiling
//! asserted by `tests/data/test1560`: curl's allocation counter belongs to
//! the memory-debug build, so it does not run and **that ceiling is not
//! measured in this configuration**. No substitute measurement is claimed.
//! This is reported, not worked around.
//!
//! # Reported limitation R4: alternative memory functions
//!
//! `Curl_cfree` is a mutable global, `lib/curl_setup.h:L1309`. It starts
//! out as `free`, `lib/easy.c:L107`, and `curl_global_init_mem()` assigns
//! to it at `lib/easy.c:L237`. An application that installs its own
//! allocators therefore causes `curl_free()` to reach a deallocator that
//! never allocated this crate's buffers. Nothing here detects the
//! substitution, because a C-allocator pointer carries no record of its
//! origin. The configuration is unsupported: it is reported rather than
//! accommodated, and no attempt is made to detect it.
//!
//! # Residual caveat: the library boundary itself
//!
//! Even with the C allocator on both sides, an allocator mismatch across a
//! library boundary stays possible depending on how the pieces are linked,
//! because "the C allocator" is a property of the linked image and not a
//! universal. The parity harness therefore links exactly *one* C library,
//! which removes the configuration in which such a mismatch could arise.
//!
//! # What this module provides
//!
//! The primitive set is modeled on the exact set `lib/urlapi.c` uses. At
//! the repository HEAD those helpers carry the `curlx_` prefix rather than
//! the older `Curl_*` names.
//!
//! Each row names the C helper it mirrors. The complete list of call
//! sites for a given primitive lives on that primitive's own doc comment,
//! which is the one place it cannot drift out of view.
//!
//! | Primitive | Mirrors | `curl_setup.h` | Lives in |
//! |---|---|---|---|
//! | `c_malloc` | `curlx_malloc` | L1481 | `src/ffi.rs` |
//! | `c_calloc` | `curlx_calloc` | L1482 | `src/ffi.rs` |
//! | `c_realloc` | `curlx_realloc` | L1483 | `src/ffi.rs` |
//! | `c_free` | `curlx_free` | L1484 | `src/ffi.rs` |
//! | [`c_strdup`] | `curlx_strdup`, from a byte slice | L1480 | here |
//! | `c_strdup_raw` | `curlx_strdup`, from a `char *` | L1480 | `src/ffi.rs` |
//! | `c_memdup0` | `curlx_memdup0` | n/a | `src/ffi.rs` |
//! | [`c_concat`] | `curl_maprintf`, `%s` conversions only | n/a | here |
//! | [`c_maprintf`] | `curl_maprintf`, any conversion | n/a | here |
//! | [`CBuf`] | the ownership C tracks by hand | n/a | here |
//! | [`CBlock`] | one owned C-allocator block | n/a | `src/ffi.rs` |
//! | `curl_free` | `curl_free`, `lib/escape.c:L189` | n/a | `src/ffi.rs` |
//!
//! The rows marked `src/ffi.rs` are the ones whose body is a foreign call or
//! a read through a pointer no compiler can vouch for. They are documented
//! there and reached from here through [`CBlock`], which this module
//! re-exports. Where the call sits differs; which allocator serves it does
//! not.
//!
//! Two of those rows deserve a note, because guessing wrong is a
//! correctness bug rather than a style choice.
//!
//! [`c_concat`] exists because the templates at `lib/urlapi.c:L1441`,
//! `"file://%s%s%s%s%s"`, and `L1517`, fifteen `%s` conversions in a single
//! call, concatenate *bytes*. A URL part is an arbitrary byte string, not
//! UTF-8, so routing those two sites through Rust's formatting machinery
//! would impose a UTF-8 validation that rejects input curl accepts.
//! [`c_concat`] is byte-oriented for exactly that reason, and it also
//! preserves the property that the whole-URL template assembles in one
//! pass rather than piece by piece.
//!
//! [`c_maprintf`] covers the other two sites, `L381` and `L1676`, which
//! format a `curl_off_t` port number in decimal. Those are pure ASCII by
//! construction, so Rust formatting is safe there and is used.
//!
//! `curl_msnprintf`, which `lib/urlapi.c` also calls at L1465, L1513 and
//! L1591, fills a caller-provided fixed buffer and allocates nothing. It
//! has no counterpart here on purpose.
//!
//! # Ownership rules for callers of this module
//!
//! There are exactly two shapes, and the difference is the whole point.
//!
//! * A function returning `*mut c_char` or `*mut c_void` **transfers
//!   ownership to the caller**. Nothing tracks it afterwards. Either hand
//!   it to C, which then owes a `curl_free()`, or take it back with
//!   `crate::ffi::adopt_c_string` so that Rust owes the free instead.
//! * A function returning [`CBuf`] **keeps ownership in Rust**, and the
//!   `Drop` implementation releases it. Call [`CBuf::into_raw`] at the one
//!   point where the buffer really does cross into C, and not before.
//!
//! Preferring the second shape is what removes the failure-path leak class
//! that the C original exhibits at `FB2` and `FB3` in
//! `docs/KNOWN-DIVERGENCES.md`: an early return cannot forget to free,
//! because there is nothing to forget.
//!
//! # `unsafe` posture
//!
//! **There is none.** `unsafe` is confined to `src/ffi.rs`, and
//! `#![forbid(unsafe_code)]` below makes that mechanical for this module
//! rather than conventional. Read [`CBlock`] first: its four invariants are
//! what make every method below expressible as an ordinary slice
//! operation.
//!
//! Nothing here can panic. `src/lib.rs` denies the panicking constructs,
//! and every size computation below uses checked arithmetic, so an
//! overflow yields a null return rather than a wrapped value and an
//! undersized allocation.
//!
//! # Thread safety
//!
//! The primitives are as thread-safe as the C allocator underneath them,
//! which is to say fully so on every platform this crate targets. [`CBuf`]
//! holds a raw pointer and is therefore neither `Send` nor `Sync`, which
//! matches the URL API's own posture: a `CURLU` handle is not safe to share
//! across threads either.
//!
//! # See also
//!
//! `docs/MEMORY-OWNERSHIP.md` records the same ownership chain end to end,
//! including how `curl_free()` resolves and every allocation site in
//! `lib/urlapi.c`.

// The adapter is deliberately complete, so that no other module has a reason
// to reach past it to the C allocator directly. Completeness and use are
// different things: which primitives a given build reaches depends on the
// selected feature set, so some of them are unreached in some configuration.
//
// Dead-code diagnostics are answered at the items. Where an item below has no
// production caller, it carries its own `#[allow(dead_code)]` with the reason
// it is kept immediately above it, and there is no crate-wide allowance to
// fall back on; see "DEAD-CODE POLICY" in `src/lib.rs` for the four outcomes
// that policy permits.

// `unsafe` belongs to `src/ffi.rs` alone; the lint keeps a future edit from
// reintroducing one here without deleting this line first.
#![forbid(unsafe_code)]

use core::fmt;
use core::ptr;
use libc::c_char;

// The owned C-allocator block every buffer in this module is built on.
// Re-exported rather than merely imported, so that `src/dynbuf.rs` reaches
// its blocks through this module and every C-visible buffer in the crate has
// one path to its allocator, while the raw `libc` calls stay in `src/ffi.rs`.
pub(crate) use crate::ffi::CBlock;

/// A NUL-terminated byte buffer that lives in the C allocator and is owned
/// by Rust until it is explicitly handed over.
///
/// This is the type that turns the C module's hand-tracked ownership into
/// something the compiler checks. `lib/urlapi.c` carries roughly thirty
/// `curlx_free()` calls whose correctness rests on a reader following every
/// path out of every function; `CBuf` carries the same obligation in the
/// [`CBlock`] it holds, whose own `Drop` no path can miss.
///
/// # Why this removes a whole class of bug
///
/// Two of the findings catalogued in `docs/KNOWN-DIVERGENCES.md` are leaks
/// on failure paths. `FB2` reaches a shared exit label that nulls the
/// handle's user, password and options fields without freeing whatever they
/// held. `FB3` stores a zone identifier over an existing one with no free
/// first. Both are the same shape: an assignment that drops the previous
/// owner on the floor. Replacing a `CBuf` releases the old value as part of
/// the assignment, so neither is expressible.
///
/// Note carefully what that does *not* mean. The port still reproduces the
/// observable behavior of both findings, because a leak is not observable
/// through the URL API; it simply does not leak while doing so. Reproducing
/// the behavior is the requirement, and reproducing the leak is not.
///
/// # Invariant
///
/// Every live `CBuf` satisfies all three of the following:
///
/// 1. `block` is a live [`CBlock`], so it carries that type's five
///    invariants: a non-null C-allocator pointer this value alone owns, an
///    exact capacity of at least one byte, an initialized prefix no longer
///    than that capacity, every byte of that prefix initialized, and `Drop`
///    as the only release.
/// 2. `block.capacity()` is **at least** `len + 1`, and
///    `block.initialized()` is **at least** `len + 1` as well: the content
///    and its terminator have all been written. The capacity may exceed that,
///    and routinely does -- `src/dynbuf.rs` grows geometrically and hands
///    over a buffer with spare capacity, and [`CBuf::format`] can end up with
///    a block wider than the string it holds. The spare is neither
///    initialized nor reachable, which is what keeps [`CBuf::as_bytes`] and
///    the two `_with_nul` faces sound.
/// 3. Byte `[len]` is zero, so the buffer is a valid C string of exactly
///    `len` bytes.
///
/// Invariant 2 is not a technicality. `FB6` in
/// `docs/KNOWN-DIVERGENCES.md` records that `ipv6_parse()` writes a
/// terminator one byte past the length it tracks, and that the port has to
/// keep that byte addressable rather than trim the host to its logical
/// length, because trimming would change behavior for input at the maximum
/// length. The reserved terminator slot at `[len]` is that byte.
///
/// # Ownership
///
/// Rust owns the buffer. Dropping the value releases it, because the
/// [`CBlock`] it holds releases itself; there is no `Drop` implementation
/// here to forget. [`CBuf::into_raw`] is the single point at which ownership
/// moves to C, and from then on the C side owes a `curl_free()`.
///
/// There is deliberately no method that yields a `*mut c_char` while
/// keeping ownership, because such a method is an invitation to a double
/// free: C frees the pointer, then the block frees it again. When a borrowed
/// C-string pointer is genuinely needed, for instance to pass a host name
/// to libidn2, take it from [`CBuf::as_bytes_with_nul`], whose slice is
/// NUL-terminated and whose lifetime the borrow checker ties to this value.
///
/// # Thread safety
///
/// `CBuf` holds a raw pointer through its block, so it is neither `Send` nor
/// `Sync`. That matches the C original: a `CURLU` handle and its strings are
/// not safe to share across threads either.
pub(crate) struct CBuf {
    /// The C-allocator block, which owns the memory and releases it on drop.
    block: CBlock,
    /// Logical length in bytes, excluding the terminator at `[len]`.
    len: usize,
}

/// The ceiling the C's own assembled strings are held to, 8,000,000 bytes.
///
/// `lib/urlapi.c` builds every one of its formatted and concatenated strings
/// through the dynamic buffer, and each of those buffers is initialised with
/// `curlx_dyn_init(&buf, CURL_MAX_INPUT_LENGTH)` -- `L1025`, `L1049`, `L1077`,
/// `L1185`, `L1399`, `L1489`, `L1957` and `L1995`. `curlx_dyn_nappend` then
/// refuses any append whose result would exceed it, at
/// `lib/curlx/dynbuf.c:L72-L79`, and answers `CURLE_TOO_LARGE`.
///
/// [`CBuf::concat`] and [`CBuf::format`] stand in for exactly those C sites,
/// so they answer the same question the same way. Without the test they would
/// be the one path in the crate where an assembled string could grow past a
/// limit the C enforces, and the divergence would only show on an input large
/// enough that nobody tries it.
///
/// The comparison is `content + 1 > DYN_MAX_LENGTH`, which is
/// `curlx_dyn_nappend`'s own `fit` expression at `lib/curlx/dynbuf.c:L72` --
/// the appended length, plus the length already held, plus the terminator --
/// so the two agree at the boundary and not only in spirit.
pub(crate) const DYN_MAX_LENGTH: usize = 8_000_000;

impl CBuf {
    /// Reserves room for `cap` content bytes plus the terminator, writing
    /// nothing.
    ///
    /// This is the only way to build a buffer whose content is assembled
    /// rather than copied in one go, and it is deliberately not a `CBuf`
    /// itself: a `CBuf` always satisfies invariant 3, a zero at `[len]`, and a
    /// half-filled allocation does not. [`CBufWriter`] is that intermediate
    /// state, and [`CBufWriter::finish`] is the single point where it becomes
    /// a `CBuf`.
    ///
    /// The `cap.checked_add(1)` below is this port's spelling of the guard in
    /// `curlx_memdup0`, `lib/curlx/strdup.c:L87`, which allocates only when
    /// `length < SIZE_MAX` so that `length + 1` cannot wrap to zero and yield
    /// a one-byte block for an enormous string.
    ///
    /// The block comes from `malloc` and is not zeroed, which is what
    /// `curlx_memdup0` does at `L89` and what `dyn_nappend()` does at
    /// `lib/curlx/dynbuf.c:L105`. The writer then writes exactly the content
    /// bytes and exactly one terminator, so no byte of the allocation is
    /// written that the C would not write. Nothing can read an unwritten byte:
    /// [`CBlock`] hands out slices bounded by its initialized prefix, and the
    /// prefix only ever advances through a write.
    ///
    /// # Ownership
    ///
    /// The returned writer owns the block. Dropping it releases the block, so
    /// an early return between here and `finish` cannot leak.
    ///
    /// # Returns
    ///
    /// `None` if the allocation fails or `cap + 1` overflows.
    #[must_use]
    pub(crate) fn writer(cap: usize) -> Option<CBufWriter> {
        let total = cap.checked_add(1)?;
        let block = CBlock::alloc(total)?;
        Some(CBufWriter { block, cap })
    }

    /// Builds a buffer over a block the caller already owns.
    ///
    /// The handover `src/dynbuf.rs` uses at the end of a parse stage: the
    /// dynamic buffer has assembled its content and gives the block up, and
    /// from here on the obligation to release it is this value's. The block
    /// keeps whatever spare capacity the growth policy gave it, which
    /// invariant 2 explicitly permits.
    ///
    /// # Ownership
    ///
    /// **Ownership moves into the returned value.** On a `None` return the
    /// block is dropped here, and so released, rather than handed back.
    ///
    /// # Returns
    ///
    /// `None` when the block has no room for the terminator at `[len]`, that
    /// is when its capacity is not at least `len + 1`, or when the block's
    /// initialized prefix does not already cover the `len` content bytes --
    /// which would mean the caller was claiming content that was never
    /// written. Reported rather than asserted, because this crate has no panic
    /// path.
    #[must_use]
    pub(crate) fn from_block(mut block: CBlock, len: usize) -> Option<Self> {
        let need = len.checked_add(1)?;
        if block.capacity() < need || block.initialized() < len {
            return None;
        }
        // Invariant 3, established rather than assumed. A block coming from
        // `src/dynbuf.rs` already carries a zero here, but a caller that
        // trimmed the length would not, and the write costs one byte.
        if !block.put_byte(len, 0) {
            return None;
        }
        Some(Self { block, len })
    }

    /// Shortens the logical length and re-terminates at the new end.
    ///
    /// The block itself is not shrunk, which invariant 2 permits. The caller
    /// that needs it is `crate::parse::path`, which trims a path buffer to the
    /// length the dot-segment pass produced, mirroring the way
    /// `lib/urlapi.c:L812-L816` hands on only the front of its output.
    pub(crate) fn truncate(&mut self, new_len: usize) {
        if new_len >= self.len {
            return;
        }
        // The write re-establishes invariant 3 for the new length before
        // `self.len` is updated to match. `new_len < self.len`, so the index
        // is inside both the capacity and the block's initialized prefix, and
        // `put_byte` therefore cannot refuse it; its answer is checked anyway
        // so that the bound is enforced rather than argued.
        if self.block.put_byte(new_len, 0) {
            self.len = new_len;
        }
    }

    /// Duplicates a byte slice as a NUL-terminated C string.
    ///
    /// This is the workhorse. It covers `curlx_strdup` where the port
    /// already holds the bytes, at `lib/urlapi.c:L418`, `L815`, `L838`,
    /// `L977`, `L1004`, `L1059` and `L1304`, and it covers `curlx_memdup0`
    /// wherever the port has narrowed a larger buffer to a subslice, at
    /// `L1028`, `L1052`, `L1086` and `L1367`. Exactly `bytes.len()` bytes
    /// are copied and a terminator is appended, which is `curlx_memdup0`'s
    /// contract from `lib/curlx/strdup.c:L85-L96`.
    ///
    /// An empty slice yields a one-byte block holding just the terminator,
    /// never a null pointer. That matters: `lib/urlapi.c:L815` and `L1059`
    /// both call `curlx_strdup("")` and treat a null result as
    /// out-of-memory, so an empty string has to be representable.
    ///
    /// A slice containing an interior zero byte produces a C string that
    /// ends at that byte. The behavior is the same in C and is not
    /// corrected here; no call site in this crate can produce one, because
    /// `Curl_junkscan` rejects control bytes in the input at
    /// `lib/urlapi.c:L223-L246`.
    ///
    /// # Ownership
    ///
    /// Rust owns the result until [`CBuf::into_raw`] is called on it.
    ///
    /// # Returns
    ///
    /// `None` if the allocation fails.
    #[must_use]
    pub(crate) fn from_slice(bytes: &[u8]) -> Option<Self> {
        let mut writer = Self::writer(bytes.len())?;
        if !writer.put(0, bytes) {
            // Unreachable: `writer` sized the block from this very slice, so
            // the copy fits by construction. Handled rather than asserted so
            // that no panic path exists even in principle.
            return None;
        }
        writer.finish(bytes.len())
    }

    /// Concatenates byte slices into one NUL-terminated C string.
    ///
    /// This is the byte-oriented stand-in for `curl_maprintf` with a format
    /// string made only of `%s` conversions, which is what the two
    /// assembly sites in the C module are: `"file://%s%s%s%s%s"` at
    /// `lib/urlapi.c:L1441`, and the whole-URL template at `L1517` with
    /// fifteen conversions in a single call.
    ///
    /// It is byte-oriented rather than built on Rust's formatting machinery
    /// for a correctness reason, not a stylistic one. A URL part is an
    /// arbitrary byte string; a host name that has come back from
    /// internationalized-domain decoding is not ASCII, and a path may carry
    /// any byte the junk scan allows. Formatting through `&str` would
    /// impose a UTF-8 validation that rejects input curl accepts.
    ///
    /// The whole result is sized first and then filled in one pass, so the
    /// fifteen-part template costs exactly one allocation and assembles in
    /// order, as the single `curl_maprintf` call does.
    ///
    /// # Ownership
    ///
    /// Rust owns the result until [`CBuf::into_raw`] is called on it.
    ///
    /// # Returns
    ///
    /// `None` if the allocation fails or if the total length would overflow
    /// `usize`.
    #[must_use]
    pub(crate) fn concat(parts: &[&[u8]]) -> Option<Self> {
        let mut total: usize = 0;
        for part in parts {
            total = total.checked_add(part.len())?;
        }
        // The C's own ceiling on an assembled string, checked with the
        // terminator counted exactly as `curlx_dyn_nappend` counts it.
        if total.checked_add(1)? > DYN_MAX_LENGTH {
            return None;
        }
        let mut writer = Self::writer(total)?;
        let mut offset: usize = 0;
        for part in parts {
            if !writer.put(offset, part) {
                // Unreachable, for the same reason as in `from_slice`: the
                // total was summed from these very slices. Reported rather
                // than asserted.
                return None;
            }
            offset = offset.checked_add(part.len())?;
        }
        writer.finish(total)
    }

    /// Renders formatted output into a NUL-terminated C string.
    ///
    /// The stand-in for `curl_maprintf` where the format string carries a
    /// real conversion: `lib/urlapi.c:L381` and `L1676`, both of which
    /// print a `curl_off_t` port number in decimal. Use it with
    /// `format_args!`, for example
    /// `CBuf::format(format_args!("{portnum}"))`. Decimal integer output is
    /// ASCII by construction, so routing it through Rust's formatting
    /// machinery is safe here in a way it would not be for the byte
    /// concatenations that [`CBuf::concat`] handles.
    ///
    /// # Implementation
    ///
    /// Two passes over the arguments: one to measure, then one to write
    /// straight into the C allocation. That costs exactly one allocation
    /// and, in particular, no Rust-heap allocation, which keeps this
    /// module from depending on the very allocator it exists to avoid.
    /// `fmt::Arguments` is `Copy`, so formatting it twice is free of
    /// ceremony.
    ///
    /// A second pass that emits *fewer* bytes than the first measured
    /// leaves the block wider than the string, which invariant 2 allows and
    /// [`CBuf::truncate`] tidies. A second pass that tries to emit *more*
    /// is refused by the bounds check in [`CBufWriter::put`] and surfaces as
    /// `None`. Neither case can write outside the allocation, so a
    /// misbehaving `Display` implementation is a failed call rather than a
    /// memory-safety problem.
    ///
    /// # Ownership
    ///
    /// Rust owns the result until [`CBuf::into_raw`] is called on it.
    ///
    /// # Returns
    ///
    /// `None` if the allocation fails, if the measured length would
    /// overflow `usize`, or if any `Display` implementation involved
    /// reports an error.
    #[must_use]
    pub(crate) fn format(args: fmt::Arguments<'_>) -> Option<Self> {
        let mut counter = CountSink { len: 0 };
        fmt::write(&mut counter, args).ok()?;
        // Same ceiling as [`CBuf::concat`], for the same reason: these two
        // stand in for the C's dynamic-buffer sites, which refuse a result
        // past `CURL_MAX_INPUT_LENGTH`.
        if counter.len.checked_add(1)? > DYN_MAX_LENGTH {
            return None;
        }
        let mut writer = Self::writer(counter.len)?;
        let written = {
            let mut sink = FillSink {
                writer: &mut writer,
                offset: 0,
            };
            // On an error here `sink` and then `writer` are dropped, and the
            // block is released. Nothing leaks on this path.
            fmt::write(&mut sink, args).ok()?;
            sink.offset
        };
        // A second pass that emitted fewer bytes than the first measured is
        // finished at what it actually wrote, so the terminator lands at the
        // end of the string rather than at the end of the measurement. The
        // block keeps the wider capacity, which invariant 2 allows.
        writer.finish(written)
    }

    // The inverse of `into_raw` below lives in `src/ffi.rs`, as
    // `adopt_c_string` and `adopt_c_bytes`: adopting a raw pointer means
    // reading provenance no compiler can check, so it belongs on the unsafe
    // side of the boundary. Both build their result through `from_block`
    // above, which keeps one construction path per buffer shape.

    /// The logical length in bytes, excluding the terminator.
    ///
    /// Equal to what `strlen` would report, unless the content holds an
    /// interior zero byte, in which case this is the larger and truer of the
    /// two numbers.
    ///
    /// # Ownership
    ///
    /// Nothing changes hands. This reads a field and creates no obligation
    /// on either side of the boundary.
    #[must_use]
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    /// Whether the buffer holds no bytes before its terminator.
    ///
    /// True for the result of `from_slice(b"")`, which is a real one-byte
    /// allocation and never a null pointer.
    ///
    /// # Ownership
    ///
    /// Nothing changes hands, exactly as for [`CBuf::len`].
    // The only production caller is the IDN host path, which asks whether a
    // conversion came back empty at `lib/idn.c` L317-L320; a build with no IDN
    // backend compiles that away. Retained unconditionally, both because it is
    // the companion predicate every `len` is expected to have and because
    // gating an accessor on an unrelated feature would be misleading.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The size of the block underneath, content plus terminator plus any
    /// spare the allocation left.
    ///
    /// Exposed so that the *shape* of an allocation is assertable rather than
    /// merely intended. `crate::decode` sizes its block from the input window
    /// the way `lib/escape.c:L116` does and then reports the shorter decoded
    /// length; a test that reads only the length cannot tell that apart from
    /// sizing the block to the answer, which is the divergence this crate is
    /// meant not to have.
    // No production caller: the crate reads a block's length, never its
    // capacity. Retained so that the tests below can assert the shape of an
    // allocation and not merely its length, for the reason just given.
    #[allow(dead_code)]
    pub(crate) const fn capacity(&self) -> usize {
        self.block.capacity()
    }

    /// The content, without the terminator.
    ///
    /// # Ownership
    ///
    /// Nothing changes hands. The result is a borrow whose lifetime the
    /// compiler ties to this value, so it cannot outlive the block, and the
    /// obligation to release the block stays exactly where it was.
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        // Invariant 2 makes the capacity at least `self.len + 1`, so the
        // range is always in bounds and the fallback below is unreachable.
        // The `get` is used anyway so the bound is checked by the compiler
        // rather than argued in a comment, which is the whole point of
        // building this type on `CBlock`.
        self.block.bytes().get(..self.len).unwrap_or(&[])
    }

    /// The content together with its terminator.
    ///
    /// This is how to obtain a borrowed C-string pointer without giving up
    /// ownership, which is why no `as_ptr` method exists:
    ///
    /// ```ignore
    /// let p: *const c_char = buf.as_bytes_with_nul().as_ptr().cast();
    /// ```
    ///
    /// The pointer is valid for as long as the borrow, it is
    /// NUL-terminated, and it is `*const`, so a C function that only reads
    /// it is safe to call with it. It must not be freed by the callee.
    ///
    /// # Ownership
    ///
    /// Nothing changes hands. This is the important case to be precise
    /// about, because a pointer taken from the result *looks* like the one
    /// [`CBuf::into_raw`] produces and is not: this value still owns the
    /// block, `Drop` will still release it, and a callee that frees the
    /// pointer causes a double free. Lend it; do not give it away.
    #[must_use]
    pub(crate) fn as_bytes_with_nul(&self) -> &[u8] {
        // `saturating_add` rather than `+`: the crate denies arithmetic that
        // could wrap, and saturation is exact here because invariant 2
        // already required `self.len + 1` to be a real allocation size, so
        // `self.len` cannot be `usize::MAX`.
        let with_nul = self.len.saturating_add(1);
        // Invariant 2 makes both the capacity and the initialized prefix at
        // least `with_nul`, and invariant 3 makes the last byte of the range
        // the terminator, so the range is in bounds and the fallback is
        // unreachable.
        self.block.bytes().get(..with_nul).unwrap_or(&[])
    }

    /// The content as a mutable slice, for in-place transformation.
    ///
    /// The view stops at the logical length, so the terminator at `[len]`
    /// is unreachable through it and invariant 3 cannot be broken by a
    /// caller. That is deliberate: the port needs in-place editing for the
    /// pass at `lib/urlapi.c:L1921-L1932`, which lower-cases percent
    /// escapes already present in the input, and that pass rewrites bytes
    /// without changing the length.
    ///
    /// # Ownership
    ///
    /// Nothing changes hands. The result is a unique borrow, so no other
    /// reference to these bytes can exist while it is held, and the
    /// obligation to release the block stays with this value.
    #[must_use]
    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8] {
        // The same reasoning as `as_bytes`, with a unique borrow. The length
        // excludes the terminator, so invariant 3 survives whatever the
        // caller writes, and the range is inside the initialized prefix by
        // invariant 2.
        let len = self.len;
        self.block.bytes_mut().get_mut(..len).unwrap_or(&mut [])
    }

    /// Relinquishes ownership and returns the bare pointer.
    ///
    /// # Ownership, in detail, because this is where it changes hands
    ///
    /// After this call **Rust no longer owns the buffer** and no release will
    /// run: the value is consumed and its block is handed on, so the
    /// obligation moves rather than being cancelled.
    ///
    /// Whoever receives the pointer inherits the whole obligation:
    ///
    /// * The C side must release it with `curl_free()`, per
    ///   `docs/libcurl/curl_url_get.md:L45` and
    ///   `include/curl/urlapi.h:L130-L131`. Because the block came from the
    ///   C allocator, that call is correct whether `curlx_free` resolves to
    ///   `Curl_cfree` at `lib/curl_setup.h:L1478` or to plain `free` at
    ///   `L1484`. The third resolution, the memory-debug one at `L1461`, is
    ///   the unsupported case the module documentation sets out under R3.
    /// * `curl_url_cleanup()` will *not* release it. The header says so at
    ///   `include/curl/urlapi.h:L116-L118`: cleanup frees the handle and the
    ///   strings the handle owns, and nothing that was handed out earlier.
    /// * Rust code that wants the obligation back must call
    ///   `crate::ffi::adopt_c_string` or `adopt_c_bytes`. Simply keeping the
    ///   pointer around leaks it, and building a second `CBuf` over the same
    ///   pointer frees it twice.
    ///
    /// The returned pointer is never null.
    ///
    /// # Where the release is suppressed
    ///
    /// There is no `Drop` implementation on this type, and there is nothing
    /// here to suppress: the block is a `CBlock` field, its own `Drop` is what
    /// releases it, and `CBlock::into_raw` consumes it and suppresses that.
    /// One owner, one release, and the compiler tracks the move rather than a
    /// reader tracking a flag.
    #[must_use = "ownership moves to the caller; discarding this leaks"]
    pub(crate) fn into_raw(self) -> *mut c_char {
        self.block.into_raw()
    }
}

/// A [`CBuf`] under construction: an owned block plus a reserved content
/// capacity, with nothing written yet.
///
/// # Why this type exists
///
/// Because the C writes each byte of a string exactly once. `curlx_memdup0`
/// at `lib/curlx/strdup.c:L89-L94` calls `malloc`, copies the content and
/// writes one terminator; `Curl_urldecode` at `lib/escape.c:L116-L147` calls
/// `malloc`, writes one byte per decoded character and one terminator at the
/// end. Neither zeroes the allocation first, and neither rewrites the
/// terminator as it goes.
///
/// A [`CBuf`] cannot represent that intermediate state, and should not: its
/// invariant 3 is a zero at `[len]`, which is what makes
/// [`CBuf::as_bytes_with_nul`] and [`CBuf::into_raw`] correct for a C
/// consumer. So the partially written state gets its own type, with no
/// C-string face at all, and [`CBufWriter::finish`] is the single place where
/// the terminator is written and a `CBuf` comes into existence.
///
/// # Invariants
///
/// 1. The block's capacity is exactly `cap + 1`, so `[cap]` is the terminator
///    slot and content may occupy `[0, cap)`.
/// 2. The block's initialized prefix is at most `cap`; the terminator slot is
///    written only by `finish`.
///
/// # Ownership
///
/// This value owns the block. Dropping it releases the block, which is what
/// makes every early return between [`CBuf::writer`] and
/// [`CBufWriter::finish`] leak-free -- including the mid-loop `Err` return in
/// `crate::decode`, which is the port of the `Curl_safefree(*ostring)` at
/// `lib/escape.c:L141`.
pub(crate) struct CBufWriter {
    /// The block, `cap + 1` bytes of it.
    block: CBlock,
    /// Reserved content capacity, excluding the terminator slot.
    cap: usize,
}

impl CBufWriter {
    /// Copies `src` into the content at `offset`.
    ///
    /// # Returns
    ///
    /// `false`, with nothing written, when the copy would reach the terminator
    /// slot or run past it, or when `offset` is above what has been written so
    /// far -- the contiguity condition [`CBlock::put`] documents. Reported
    /// rather than asserted, because this crate has no panic path.
    pub(crate) fn put(&mut self, offset: usize, src: &[u8]) -> bool {
        let Some(end) = offset.checked_add(src.len()) else {
            return false;
        };
        // `> self.cap`, not `>= self.cap`: content may fill `[0, cap)`
        // exactly, and `[cap]` stays for the terminator.
        if end > self.cap {
            return false;
        }
        self.block.put(offset, src)
    }

    /// Appends one byte to the content.
    ///
    /// The `*ns++ = (char)in` of `Curl_urldecode` at `lib/escape.c:L145`. No
    /// terminator is written here; `finish` writes it once, exactly as the C
    /// does at `L147`.
    ///
    /// # Returns
    ///
    /// `false`, with nothing written, when the content is already `cap` bytes
    /// long.
    pub(crate) fn push(&mut self, byte: u8) -> bool {
        if self.written() >= self.cap {
            return false;
        }
        self.block.push(byte)
    }

    /// How many content bytes have been written.
    #[must_use]
    pub(crate) const fn written(&self) -> usize {
        self.block.initialized()
    }

    /// How much content capacity is left.
    ///
    /// The loop bound `crate::decode` uses in place of the C's `while(alloc)`
    /// at `lib/escape.c:L124`: the destination drives the walk, so no write
    /// can land outside the block.
    #[must_use]
    pub(crate) fn remaining(&self) -> usize {
        // Saturating because the crate root denies the operators that could
        // panic. Exact: invariant 2 keeps `written()` at or below `cap`.
        self.cap.saturating_sub(self.written())
    }

    /// Writes the terminator at `[len]` and yields the finished buffer.
    ///
    /// The `dest[length] = 0` at `lib/curlx/strdup.c:L94` and the
    /// `*ns = 0` at `lib/escape.c:L147`: one byte, once, at the end.
    ///
    /// A `len` below what was written is how a caller reports a result shorter
    /// than the reservation, which is the C's `*olen` at
    /// `lib/escape.c:L149-L151` and the shorter second formatting pass in
    /// [`CBuf::format`]. The block keeps its full capacity either way, as the
    /// C keeps its `malloc`ed size.
    ///
    /// # Ownership
    ///
    /// **Ownership moves into the returned buffer.** On a `None` return the
    /// block is dropped here, and so released.
    ///
    /// # Returns
    ///
    /// `None` when `len` exceeds either the reserved capacity or the bytes
    /// actually written -- the latter because content that was never written
    /// cannot be claimed as content.
    #[must_use = "the finished buffer is owned; dropping it releases the memory"]
    pub(crate) fn finish(mut self, len: usize) -> Option<CBuf> {
        if len > self.cap || len > self.written() {
            return None;
        }
        if !self.block.put_byte(len, 0) {
            return None;
        }
        Some(CBuf {
            block: self.block,
            len,
        })
    }

    /// Finishes at exactly the number of bytes written.
    ///
    /// The shape `crate::decode` wants: the decoded length is whatever the
    /// single pass produced.
    #[must_use = "the finished buffer is owned; dropping it releases the memory"]
    pub(crate) fn finish_written(self) -> Option<CBuf> {
        let len = self.written();
        self.finish(len)
    }
}

impl fmt::Debug for CBufWriter {
    /// Prints the reservation and how much of it has been written.
    ///
    /// The contents are deliberately not shown, for the reason [`CBuf`]'s own
    /// implementation gives: a URL part can carry credentials.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CBufWriter")
            .field("cap", &self.cap)
            .field("written", &self.written())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for CBuf {
    /// Prints the buffer's length and **never its content**.
    ///
    /// A deliberate refusal rather than an omission. The strings a `CBuf`
    /// holds are URL parts, and four of the ten a handle carries -- `u->user`,
    /// `u->password`, `u->options` and `u->query` at `lib/urlapi.c:L69-L71`
    /// and `L78` -- routinely carry credentials, session tokens and API keys.
    /// A formatter that printed them would put those secrets wherever the
    /// caller's diagnostics go, which is CWE-532, insertion of sensitive
    /// information into a log file. A content-printing implementation is
    /// reachable from anything that formats a `crate::handle::CurlUrl`, so the
    /// only reliable defence is for the content to have no formatter at all.
    ///
    /// The length is safe to show and is what a debugging session actually
    /// needs from this type: whether a part is present, and how long it is. A
    /// caller that genuinely needs the bytes has [`CBuf::as_bytes`] and can
    /// decide at that one site whether printing them is appropriate; a test
    /// that wants to assert on content compares `as_bytes()` against a
    /// literal, which is the better assertion in any case.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CBuf")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

/// First pass of [`CBuf::format`]: measures the output without storing it.
struct CountSink {
    /// Bytes seen so far.
    len: usize,
}

impl fmt::Write for CountSink {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // A length that overflows `usize` is reported as a formatting error
        // and becomes a null return, never a wrapped total that would size
        // the allocation far too small.
        self.len = self.len.checked_add(s.len()).ok_or(fmt::Error)?;
        Ok(())
    }
}

/// Second pass of [`CBuf::format`]: writes into the C allocation.
///
/// Every write goes through [`CBufWriter::put`], which bounds-checks against
/// the reserved content capacity, so this sink cannot write outside the block
/// even if the second pass disagrees with the first about how many bytes the
/// output needs.
struct FillSink<'a> {
    /// The destination, borrowed for the duration of the pass.
    writer: &'a mut CBufWriter,
    /// Bytes written so far, and the offset of the next write.
    offset: usize,
}

impl fmt::Write for FillSink<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if !self.writer.put(self.offset, s.as_bytes()) {
            // The second pass wants more room than the first pass measured.
            // Refused here rather than accommodated, so the failure is a
            // null return instead of a buffer overrun.
            return Err(fmt::Error);
        }
        self.offset = self.offset.checked_add(s.len()).ok_or(fmt::Error)?;
        Ok(())
    }
}

// The four functions below are the raw-pointer face of the constructors
// above. They exist because a handful of call sites really do want C's
// return shape, a bare pointer with null meaning failure, so that the port
// can follow the C control flow line for line. Each is a thin wrapper that
// builds a `CBuf` and immediately relinquishes it, which keeps exactly one
// allocation code path per buffer shape and therefore exactly one place to
// audit.
//
// Prefer the `CBuf` constructors in new code. These hand ownership straight
// to the caller, so an early return between here and the point where the
// pointer reaches C leaks the block, which is precisely the failure mode
// `CBuf` exists to remove.

/// Duplicates a byte slice as a NUL-terminated C string.
///
/// Mirrors `curlx_strdup`, `lib/curlx/strdup.c` by way of the macro at
/// `lib/curl_setup.h:L1480`, for the case where the port already holds the
/// bytes. Also covers `curlx_memdup0` wherever the port has narrowed a
/// larger buffer to a subslice, because a Rust subslice already carries the
/// length that C has to pass separately.
///
/// See [`CBuf::from_slice`], which this wraps, for the empty-slice and
/// interior-zero-byte behavior.
///
/// # Ownership
///
/// **The caller owns the returned pointer.** Hand it to C, which then owes
/// a `curl_free()` on it, or take it back with
/// `crate::ffi::adopt_c_string`, or release it with `crate::ffi::c_free`.
/// Nothing else tracks it, so dropping it on the floor leaks.
///
/// # Returns
///
/// A null pointer if the allocation fails, matching `curlx_strdup`.
// No production caller: the port passes owned `CBuf` values around and
// only `src/ffi.rs` lowers one to a raw pointer at the boundary. Retained
// as the `curlx_strdup` mirror that this module's ownership contract and
// `docs/MEMORY-OWNERSHIP.md` both describe, and driven by the tests below.
#[allow(dead_code)]
#[must_use = "the caller owns this string; discarding it leaks memory"]
pub(crate) fn c_strdup(bytes: &[u8]) -> *mut c_char {
    CBuf::from_slice(bytes).map_or(ptr::null_mut(), CBuf::into_raw)
}

// The two raw-pointer duplicators the C module reaches for, `curlx_strdup`
// over a `char *` and `curlx_memdup0` over a pointer and a length, live in
// `src/ffi.rs` as `c_strdup_raw` and `c_memdup0`. Both read through a
// pointer whose provenance no compiler can check, so they belong to the
// crate's unsafe island; both build their result through `CBuf` here, so
// there is still exactly one allocation code path per buffer shape. The
// slice-taking `c_strdup` above is the form a Rust caller wants, because a
// slice already carries the length C has to recover with `strlen`.
//
// None of the three has a caller on the port's own paths, which hand owned
// `CBuf` values around and lower one to a raw pointer only at the boundary in
// `src/ffi.rs`. Each says so at itself, with the reason it is kept: the C
// module reaches for all three, so a port that describes its allocation
// contract has to offer all three.

/// Concatenates byte slices into one NUL-terminated C string.
///
/// The raw-pointer face of [`CBuf::concat`], which documents why the two
/// `%s`-only templates at `lib/urlapi.c:L1441` and `L1517` must be assembled
/// from bytes rather than through Rust's formatting machinery.
///
/// # Ownership
///
/// **The caller owns the returned pointer**, exactly as for [`c_strdup`].
///
/// # Returns
///
/// A null pointer if the allocation fails or the total length would overflow
/// `usize`, matching `curl_maprintf`.
// No production caller, for the same reason as `c_strdup`: the port
// concatenates into a `DynBuf`. Retained as the raw-pointer form of the
// `curl_maprintf` joining the C does at `lib/urlapi.c` L1517.
#[allow(dead_code)]
#[must_use = "the caller owns this string; discarding it leaks memory"]
pub(crate) fn c_concat(parts: &[&[u8]]) -> *mut c_char {
    CBuf::concat(parts).map_or(ptr::null_mut(), CBuf::into_raw)
}

/// Renders formatted output into a NUL-terminated C string.
///
/// The raw-pointer face of [`CBuf::format`], and the stand-in for
/// `curl_maprintf` at the two sites that format a port number,
/// `lib/urlapi.c:L381` and `L1676`. Use it with `format_args!`:
///
/// ```ignore
/// let p: *mut c_char = c_maprintf(format_args!("{portnum}"));
/// ```
///
/// # Ownership
///
/// **The caller owns the returned pointer**, exactly as for [`c_strdup`].
///
/// # Returns
///
/// A null pointer on any failure, matching `curl_maprintf`, which the C code
/// checks for at `lib/urlapi.c:L382` and `L1677`.
// No production caller: every formatting site in the port writes into a
// `DynBuf` instead. Retained as the `curl_maprintf` mirror the C calls at
// `lib/urlapi.c` L382 and L1677, whose null-on-failure contract the tests
// below pin.
#[allow(dead_code)]
#[must_use = "the caller owns this string; discarding it leaks memory"]
pub(crate) fn c_maprintf(args: fmt::Arguments<'_>) -> *mut c_char {
    CBuf::format(args).map_or(ptr::null_mut(), CBuf::into_raw)
}

#[cfg(test)]
mod tests {
    // The crate root denies the panicking constructs so that no panic can
    // ever reach the C boundary. A test's entire job is to panic when an
    // assertion fails, and a test never crosses that boundary, so the
    // denials are relaxed here and only here. The allowance is scoped to
    // this module and enumerated rather than blanket.
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::arithmetic_side_effects)]

    // Imported by name rather than through a glob, as everywhere else in
    // the crate, so each use site names its source.
    use super::{c_maprintf, CBlock, CBuf};
    use core::cell::Cell;
    use core::fmt;

    // What this module tests, and what it deliberately does not.
    //
    // Everything below exercises the owned face, `CBuf`, because that is
    // where the logic lives: `c_strdup`, `c_concat` and `c_maprintf` are
    // one-line wrappers that build a `CBuf` and immediately call `into_raw`
    // on it. Their raw round trips are tested in `src/ffi.rs`, next to the
    // primitives and the adopters they need, because reclaiming a
    // `*mut c_char` requires reading a pointer the compiler cannot vouch for
    // and this module is `#![forbid(unsafe_code)]`. Splitting the tests the
    // same way the code is split keeps every test leak-free without an
    // `unsafe` block, so a run under `valgrind --leak-check=full` stays clean
    // -- which matters more than usual here, because a leak in this module is
    // invisible to the parity diff and would surface only as slow growth.

    #[test]
    fn cbuf_from_slice_copies_and_terminates() {
        let buf = CBuf::from_slice(b"https").unwrap();
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.as_bytes(), b"https".as_slice());
        assert_eq!(buf.as_bytes_with_nul(), b"https\0".as_slice());
        // The terminator is what makes the pointer a C string at all.
        assert_eq!(buf.as_bytes_with_nul()[5], 0);
    }

    #[test]
    fn cbuf_from_slice_of_an_empty_slice_is_not_null() {
        // lib/urlapi.c:L815 and L1059 both call curlx_strdup("") and treat a
        // null result as out-of-memory, so an empty string has to exist.
        let buf = CBuf::from_slice(b"").unwrap();
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
        assert_eq!(buf.as_bytes_with_nul(), b"\0".as_slice());
    }

    #[test]
    fn cbuf_from_slice_preserves_bytes_that_are_not_utf8() {
        // The reason this module is byte-oriented throughout. A host name
        // returned from internationalized-domain decoding is not ASCII, and
        // a path may carry any byte the junk scan allows, so any UTF-8
        // validation on this path would reject input curl accepts.
        let raw: [u8; 5] = [0xff, 0xfe, b'/', 0x80, b'x'];
        let buf = CBuf::from_slice(&raw).unwrap();
        assert_eq!(buf.as_bytes(), raw.as_slice());
        assert_eq!(buf.as_bytes_with_nul()[5], 0);
    }

    #[test]
    fn cbuf_concat_assembles_fifteen_parts_in_order() {
        // The shape of the whole-URL template at lib/urlapi.c:L1517, which
        // takes fifteen %s conversions in a single curl_maprintf call. The
        // credential slots have to be exercised, because the template has
        // slots for them; the values below are literal placeholders and the
        // host is the reserved documentation domain from RFC 2606, so
        // nothing here is or resembles a real credential.
        let parts: [&[u8]; 15] = [
            b"https",
            b"://",
            b"user",
            b":",
            b"not-a-secret",
            b"@",
            b"example.com",
            b":",
            b"8080",
            b"/a/b",
            b"?",
            b"q=1",
            b"#",
            b"frag",
            b"",
        ];
        let buf = CBuf::concat(&parts).unwrap();
        let want = b"https://user:not-a-secret@example.com:8080/a/b?q=1#frag";
        assert_eq!(buf.as_bytes(), want.as_slice());
        assert_eq!(buf.len(), want.len());
    }

    #[test]
    fn cbuf_concat_handles_the_file_url_template_and_empty_inputs() {
        // The five-conversion template at lib/urlapi.c:L1441.
        let buf = CBuf::concat(&[b"file://", b"", b"", b"/tmp/x", b""]).unwrap();
        assert_eq!(buf.as_bytes(), b"file:///tmp/x".as_slice());
        // No parts at all yields the empty string, not a failure.
        let empty = CBuf::concat(&[]).unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.as_bytes_with_nul(), b"\0".as_slice());
    }

    #[test]
    fn cbuf_concat_preserves_bytes_that_are_not_utf8() {
        let host: [u8; 3] = [0xc3, 0xa4, b'.'];
        let buf = CBuf::concat(&[b"http://", &host, b"se/"]).unwrap();
        assert_eq!(buf.as_bytes(), b"http://\xc3\xa4.se/".as_slice());
    }

    #[test]
    fn cbuf_format_formats_a_port_number() {
        // lib/urlapi.c:L381 and L1676 print a curl_off_t in decimal.
        for (value, want) in [
            (8080_i64, b"8080".as_slice()),
            (0_i64, b"0".as_slice()),
            (65535_i64, b"65535".as_slice()),
            (i64::MAX, b"9223372036854775807".as_slice()),
            (i64::MIN, b"-9223372036854775808".as_slice()),
        ] {
            let buf = CBuf::format(format_args!("{value}")).unwrap();
            assert_eq!(buf.as_bytes(), want);
            assert_eq!(buf.len(), want.len());
        }
    }

    #[test]
    fn cbuf_from_block_takes_a_shorter_view_and_terminates() {
        // The dynbuf handover: a block wider than the logical length, which
        // invariant 2 permits and lib/urlapi.c relies on at L1185 and
        // friends. The terminator is written here rather than assumed.
        let mut block = CBlock::alloc(32).unwrap();
        assert!(block.put(0, b"example.com/path"));
        let buf = CBuf::from_block(block, 11).unwrap();
        assert_eq!(buf.len(), 11);
        assert_eq!(buf.as_bytes(), b"example.com".as_slice());
        assert_eq!(buf.as_bytes_with_nul(), b"example.com\0".as_slice());
    }

    #[test]
    fn cbuf_from_block_refuses_a_block_with_no_room_to_terminate() {
        // A one-byte block holds the empty string and nothing longer: byte
        // [0] is the terminator slot. Asking for a length of one would put
        // the terminator outside the block, which breaks invariant 3, so the
        // request is refused rather than accommodated.
        let block = CBlock::alloc(1).unwrap();
        assert!(CBuf::from_block(block, 1).is_none());
        let block = CBlock::alloc(1).unwrap();
        let buf = CBuf::from_block(block, 0).unwrap();
        assert!(buf.is_empty());
        // A length whose terminator index cannot be represented at all.
        let block = CBlock::alloc(4).unwrap();
        assert!(CBuf::from_block(block, usize::MAX).is_none());
    }

    #[test]
    fn cbuf_from_block_refuses_content_that_was_never_written() {
        // The other half of the contract: a block wide enough for the claim
        // but with an initialized prefix shorter than it. Accepting that would
        // hand `as_bytes` a slice over memory no write has reached, which is
        // undefined behavior; it is refused instead, and the block is released
        // here rather than handed back.
        let mut block = CBlock::alloc(32).unwrap();
        assert!(block.put(0, b"eight!!!"));
        assert!(CBuf::from_block(block, 9).is_none());
        // Exactly the written length is fine, terminator slot included.
        let mut block = CBlock::alloc(32).unwrap();
        assert!(block.put(0, b"eight!!!"));
        let buf = CBuf::from_block(block, 8).unwrap();
        assert_eq!(buf.as_bytes_with_nul(), b"eight!!!\0".as_slice());
    }

    #[test]
    fn cbuf_writer_writes_only_the_content_and_one_terminator() {
        // The C's write pattern, asserted rather than intended: the block is
        // uninitialized when it arrives, `put` accounts for exactly the bytes
        // it copies, and `finish` adds exactly one terminator.
        let mut writer = CBuf::writer(16).unwrap();
        assert_eq!((writer.written(), writer.remaining()), (0, 16));
        assert!(writer.put(0, b"https://"));
        assert_eq!((writer.written(), writer.remaining()), (8, 8));
        // Content may fill the reservation exactly; the terminator slot is
        // above it and is not part of the capacity a caller may write.
        assert!(writer.put(8, b"curl.se/"));
        assert_eq!(writer.remaining(), 0);
        assert!(!writer.put(16, b"x"), "the terminator slot is reserved");
        assert!(
            !writer.push(b'x'),
            "and so it is for the byte-at-a-time face"
        );
        let buf = writer.finish_written().unwrap();
        assert_eq!(buf.as_bytes(), b"https://curl.se/".as_slice());
        assert_eq!(buf.as_bytes_with_nul().last(), Some(&0));
        assert_eq!(buf.capacity(), 17);
    }

    #[test]
    fn cbuf_writer_finishes_short_and_refuses_to_overclaim() {
        // The shape lib/escape.c:L149-L151 reports through *olen: the block is
        // sized from the input and the answer is shorter.
        let mut writer = CBuf::writer(10).unwrap();
        assert!(writer.push(b'a'));
        assert!(writer.push(b'b'));
        assert!(writer.push(b'c'));
        // Above what was written is refused, so no unwritten byte can ever be
        // presented as content.
        let mut overclaim = CBuf::writer(10).unwrap();
        assert!(overclaim.push(b'a'));
        assert!(overclaim.finish(4).is_none());
        let buf = writer.finish(2).unwrap();
        assert_eq!(buf.as_bytes(), b"ab".as_slice());
        assert_eq!(buf.len(), 2);
        // The reservation survives the short finish, as the C's malloc does.
        assert_eq!(buf.capacity(), 11);
    }

    #[test]
    fn cbuf_writer_reserves_room_for_an_empty_string() {
        // curlx_strdup("") at lib/urlapi.c:L815 and L1059 must be
        // representable: a one-byte block holding just the terminator.
        let writer = CBuf::writer(0).unwrap();
        assert_eq!((writer.written(), writer.remaining()), (0, 0));
        let buf = writer.finish(0).unwrap();
        assert!(buf.is_empty());
        assert_eq!(buf.as_bytes_with_nul(), b"\0".as_slice());
        assert_eq!(buf.capacity(), 1);
    }

    #[test]
    fn cbuf_as_bytes_with_nul_is_a_valid_c_string() {
        // This is the borrow that replaces an `as_ptr` method: safe code,
        // lifetime-checked, and no *mut ever escapes. A C function that only
        // reads the pointer may be handed `as_bytes_with_nul().as_ptr()`.
        let buf = CBuf::from_slice(b"ftp.example.com").unwrap();
        let lent = buf.as_bytes_with_nul();
        assert_eq!(lent.len(), 16);
        // The first zero byte is at the logical length, which is what a C
        // `strlen` of the pointer would report.
        assert_eq!(lent.iter().position(|&b| b == 0), Some(buf.len()));
        assert_eq!(buf.len(), 15);
    }

    #[test]
    fn cbuf_as_mut_bytes_edits_in_place_and_cannot_reach_the_terminator() {
        // The pass at lib/urlapi.c:L1921-L1932 lower-cases percent escapes
        // already present in the input without changing the length.
        let mut buf = CBuf::from_slice(b"/a%2Fb%3Fc").unwrap();
        let before = buf.len();
        for byte in buf.as_mut_bytes() {
            byte.make_ascii_lowercase();
        }
        assert_eq!(buf.as_bytes(), b"/a%2fb%3fc".as_slice());
        // The mutable view stops short of the terminator, so invariant 3
        // survives whatever the caller wrote.
        assert_eq!(buf.as_mut_bytes().len(), before);
        assert_eq!(buf.len(), before);
        assert_eq!(buf.as_bytes_with_nul()[before], 0);
    }

    #[test]
    fn cbuf_format_truncates_when_the_second_pass_is_shorter() {
        // A Display implementation that shrinks between calls. The first
        // pass measures six bytes, the second writes four, and the result
        // must be a correct four-byte string in a block that is merely
        // wider than it needs to be, which invariant 2 allows.
        let shrinking = Shrinking(Cell::new(6));
        let buf = CBuf::format(format_args!("{shrinking}")).unwrap();
        assert_eq!(buf.len(), 4);
        assert_eq!(buf.as_bytes(), b"xxxx".as_slice());
        assert_eq!(buf.as_bytes_with_nul()[4], 0);
    }

    #[test]
    fn cbuf_format_refuses_when_the_second_pass_is_longer() {
        // The mirror case, and the important one: a second pass that wants
        // more room than was measured must be refused rather than allowed
        // to overrun the block. The failure surfaces as None, and as a null
        // pointer through c_maprintf, never as memory corruption.
        let growing = Growing(Cell::new(2));
        assert!(CBuf::format(format_args!("{growing}")).is_none());
        // The raw face maps that None onto the null pointer curl_maprintf
        // returns, which lib/urlapi.c checks at L382 and L1677. Asserting it
        // here leaks nothing, because there is no block to release.
        let growing = Growing(Cell::new(2));
        assert!(c_maprintf(format_args!("{growing}")).is_null());
    }

    #[test]
    fn cbuf_debug_reports_the_length_and_never_the_content() {
        // The content is a stand-in for a credential, which is what four of
        // the ten handle parts routinely hold. Formatting must not disclose
        // it (CWE-532), and must still say enough to debug with.
        let buf = CBuf::from_slice(b"s3cr3t-token").unwrap();
        let shown = format!("{buf:?}");
        assert!(
            !shown.contains("s3cr3t"),
            "content leaked into Debug: {shown}"
        );
        assert!(
            !shown.contains("token"),
            "content leaked into Debug: {shown}"
        );
        assert!(
            shown.contains("len"),
            "the length is the useful part: {shown}"
        );
        assert!(
            shown.contains("12"),
            "the length is the useful part: {shown}"
        );
        // A byte string that is not valid UTF-8 is equally silent, which is
        // where a content-printing formatter used to need escaping at all.
        let raw = CBuf::from_slice(b"a\xffb\"c").unwrap();
        let shown = format!("{raw:?}");
        assert!(!shown.contains('a'), "content leaked into Debug: {shown}");
    }

    #[test]
    fn repeated_allocation_and_release_stays_balanced() {
        // Exercises every allocating path many times over. The assertions
        // check correctness; the point of the repetition is that a leak or
        // a double free becomes loud under a leak checker.
        for n in 0_usize..2000 {
            let owned = CBuf::format(format_args!("{n}")).unwrap();
            let joined = CBuf::concat(&[b"n=", owned.as_bytes(), b";"]).unwrap();
            // Two bytes of prefix plus one of suffix around the digits.
            assert_eq!(joined.len(), owned.len() + 3);
            let copy = CBuf::from_slice(joined.as_bytes()).unwrap();
            assert_eq!(copy.as_bytes(), joined.as_bytes());
        }
    }

    /// A `Display` that emits two fewer bytes on each successive call.
    struct Shrinking(Cell<usize>);

    impl fmt::Display for Shrinking {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let count = self.0.get();
            self.0.set(count.saturating_sub(2));
            for _ in 0..count {
                f.write_str("x")?;
            }
            Ok(())
        }
    }

    /// A `Display` that emits four more bytes on each successive call.
    struct Growing(Cell<usize>);

    impl fmt::Display for Growing {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let count = self.0.get();
            self.0.set(count.saturating_add(4));
            for _ in 0..count {
                f.write_str("y")?;
            }
            Ok(())
        }
    }
}
