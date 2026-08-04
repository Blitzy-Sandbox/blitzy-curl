// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The C allocator adapter: this crate's sole producer of C-visible memory.
//!
//! Every byte this crate ever hands to C originates in this module, and
//! every byte is allocated with the C allocator. That single property is
//! what makes the documented free contract hold *by construction* rather
//! than by discipline repeated at each of the twenty-seven allocation
//! sites in `lib/urlapi.c`. If any other module of this crate allocates a
//! C-visible buffer without coming through here, the pattern is broken and
//! the contract becomes a matter of hope.
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
//! directory. The decision, per `AAP` 0.2.4.3, is that the parity harness
//! is built *without* the memory-debug configuration. The visible cost is
//! the `Allocations: 3000` ceiling asserted by `tests/data/test1560`: it is
//! honored in spirit, in that this port does not allocate materially more
//! than the C original, rather than counted by curl's own counter. This is
//! reported, not worked around.
//!
//! # Reported limitation R4: alternative memory functions
//!
//! `Curl_cfree` is a mutable global, `lib/curl_setup.h:L1309`. It starts
//! out as `free`, `lib/easy.c:L107`, and `curl_global_init_mem()` assigns
//! to it at `lib/easy.c:L237`. An application that installs its own
//! allocators therefore causes `curl_free()` to reach a deallocator that
//! never allocated this crate's buffers. Nothing here detects the
//! substitution, because a C-allocator pointer carries no record of its
//! origin. The configuration is unsupported, reported per `AAP` 0.2.4.4
//! rather than accommodated, and no attempt is made to detect it.
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
//! | This module | Mirrors | `curl_setup.h` |
//! |---|---|---|
//! | [`c_malloc`] | `curlx_malloc` | L1481 |
//! | [`c_calloc`] | `curlx_calloc` | L1482 |
//! | [`c_realloc`] | `curlx_realloc` | L1483 |
//! | [`c_free`] | `curlx_free` | L1484 |
//! | [`c_strdup`] | `curlx_strdup`, from a byte slice | L1480 |
//! | [`c_strdup_raw`] | `curlx_strdup`, from a `char *` | L1480 |
//! | [`c_memdup0`] | `curlx_memdup0` | n/a |
//! | [`c_concat`] | `curl_maprintf`, `%s` conversions only | n/a |
//! | [`c_maprintf`] | `curl_maprintf`, any conversion | n/a |
//! | [`CBuf`] | the ownership C tracks by hand | n/a |
//! | [`curl_free`] | `curl_free`, `lib/escape.c:L189` | n/a |
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
//!   [`CBuf::from_raw`] so that Rust owes the free instead.
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
//! Specification 1.3.2.1 confines `unsafe` to FFI code and 3.2.1.2
//! requires a `// SAFETY:` comment on every block. Calling
//! `libc::malloc`/`calloc`/`realloc`/`free` *is* FFI code, so the blocks
//! below are permitted; they are the only ones outside `src/ffi.rs`, and
//! every one of them carries its justification. Functions that accept a
//! raw pointer whose provenance they cannot verify are declared `unsafe
//! fn` with a `# Safety` section rather than quietly trusting the caller.
//! Functions that accept no pointer are safe.
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
//! `docs/MEMORY-OWNERSHIP.md` is the companion record. This module is the
//! code-side source for it: a reader stopped at one line needs the comment
//! here, and a reviewer auditing the whole chain needs the document.

// Every primitive below is part of a deliberately complete adapter, so that
// no other module ever has a reason to reach past this one to the C
// allocator directly. Completeness and use are different things: which
// primitives are reachable depends on the selected feature set, and
// `c_free` in particular is called from the `cfree`-gated export in
// `src/ffi.rs` and from nowhere else in the drop-in configuration.
// Warnings are errors for this crate, so rather than let the feature matrix
// decide whether the build is clean, the allowance is stated once here with
// its reason. It is scoped to this module and to this lint alone.
#![allow(dead_code)]

use core::fmt;
use core::mem;
use core::ptr;
use core::slice;
use libc::{c_char, c_void};

/// Allocates `size` bytes with the C allocator.
///
/// Mirrors `curlx_malloc`, which resolves to plain `malloc` outside a
/// libcurl build at `lib/curl_setup.h:L1481`. `lib/urlapi.c` never calls it
/// directly; it reaches it through `curlx_strdup`, `curlx_memdup0` and
/// `curl_maprintf`, which is the same relationship the helpers in this
/// module have with it.
///
/// # Ownership
///
/// The caller owns the returned block and must release it with [`c_free`],
/// or hand it to C, which then owes a `curl_free()` on it. Nothing else
/// tracks it. The block is uninitialized: read it only after writing it.
///
/// # Returns
///
/// A null pointer if the allocation fails, and never a panic, so this is
/// usable on any error path.
///
/// A request for zero bytes also returns null, deterministically. C leaves
/// `malloc(0)` unspecified, free to return either null or a unique pointer
/// that must still be freed, and a caller cannot tell which happened from
/// the return value alone. curl takes the same view: `curl_dbg_malloc`
/// carries `DEBUGASSERT(wantedsize != 0)`. No call site in this crate ever
/// asks for zero, because every string allocation is a length plus one for
/// the terminator, so the case only arises from a bug and is reported as a
/// failure.
#[must_use = "the caller owns this block; discarding it leaks memory"]
pub(crate) fn c_malloc(size: usize) -> *mut c_void {
    if size == 0 {
        return ptr::null_mut();
    }
    // SAFETY: `libc::malloc` has no preconditions beyond a nonzero size,
    // which the guard above establishes. `libc::size_t` is `usize` on every
    // supported target, so `size` passes through unconverted. The result is
    // returned to the caller unread, so no validity claim is made about the
    // contents; a null return is propagated rather than dereferenced.
    unsafe { libc::malloc(size) }
}

/// Allocates `nmemb * size` zeroed bytes with the C allocator.
///
/// Mirrors `curlx_calloc`, which resolves to plain `calloc` outside a
/// libcurl build at `lib/curl_setup.h:L1482`. Used twice in the C module,
/// both times for the handle itself: `curl_url()` at `lib/urlapi.c:L1290`
/// and `curl_url_dup()` at `L1312`.
///
/// The zeroing is load-bearing rather than tidy. `struct Curl_URL` has ten
/// string pointers plus `portnum`, `query_present`, `fragment_present` and
/// `guessed_scheme`, and every one of those fields is read before it is
/// ever written on some path. The C code never initializes them explicitly:
/// it relies on `calloc` for null, zero and false throughout, which is also
/// what makes the parse-into-a-temporary-and-swap idiom at
/// `lib/urlapi.c:L1197-L1209` safe.
///
/// # Ownership
///
/// The caller owns the returned block and must release it with [`c_free`].
///
/// # Returns
///
/// A null pointer if the allocation fails, if either argument is zero, or
/// if `nmemb * size` would overflow `usize`. The overflow case is checked
/// here rather than left to the platform: `calloc` is required to detect it
/// too, but checking makes the guarantee local and visible, and it keeps
/// the computation clear of the crate's arithmetic lint.
#[must_use = "the caller owns this block; discarding it leaks memory"]
pub(crate) fn c_calloc(nmemb: usize, size: usize) -> *mut c_void {
    if nmemb == 0 || size == 0 {
        return ptr::null_mut();
    }
    if nmemb.checked_mul(size).is_none() {
        return ptr::null_mut();
    }
    // SAFETY: `libc::calloc` requires nothing of its arguments; the guards
    // above additionally rule out a zero-size request and an overflowing
    // product, so the platform is never asked to resolve either case. The
    // result is returned unread and a null return is propagated.
    unsafe { libc::calloc(nmemb, size) }
}

/// Resizes a block previously produced by this module.
///
/// Mirrors `curlx_realloc`, which resolves to plain `realloc` outside a
/// libcurl build at `lib/curl_setup.h:L1483`. `lib/urlapi.c` never calls it
/// directly. It is here for `src/dynbuf.rs`, which reproduces the growth
/// step of `dyn_nappend()` in `lib/curlx/dynbuf.c`, and that is the only
/// caller it needs.
///
/// # Ownership
///
/// On success ownership moves from `ptr` to the returned pointer, and `ptr`
/// must not be used or freed again. On failure, that is a null return,
/// ownership stays with `ptr` exactly as C's `realloc` specifies, and the
/// caller still owes a [`c_free`] on it. Getting that backwards is the
/// classic `realloc` leak, so it is stated here rather than assumed.
///
/// # Returns
///
/// A null pointer if the reallocation fails, or if `size` is zero. The
/// zero case is rejected rather than forwarded because C's answer to
/// `realloc(p, 0)` is implementation-defined, and in the reading where it
/// frees `p` and returns null the caller cannot distinguish that from a
/// failure that left `p` alive. Rejecting it keeps the failure contract
/// above unambiguous: a null return always means `ptr` is untouched.
///
/// # Safety
///
/// `p` must either be null or point to a block currently owned by the
/// caller that came from [`c_malloc`], [`c_calloc`] or an earlier
/// successful `c_realloc`, and that has not already been freed. Passing a
/// pointer from any other allocator, or one that has been freed, or one
/// obtained from C when the two sides do not share an allocator, is
/// undefined behavior.
#[must_use = "discarding this leaks the new block and loses the old"]
pub(crate) unsafe fn c_realloc(p: *mut c_void, size: usize) -> *mut c_void {
    if size == 0 {
        return ptr::null_mut();
    }
    // SAFETY: the caller guarantees, per the contract above, that `p` is
    // null or a live block from this module's allocator, which is exactly
    // `libc::realloc`'s precondition. `size` is nonzero by the guard, so
    // the implementation-defined `realloc(p, 0)` case is never reached. A
    // null return leaves the original block owned by the caller, which the
    // documentation states, and this function performs no cleanup of its
    // own so no double free is possible here.
    unsafe { libc::realloc(p, size) }
}

/// Releases a block previously produced by this module.
///
/// Mirrors `curlx_free`, which resolves to plain `free` outside a libcurl
/// build at `lib/curl_setup.h:L1484`. This is the single deallocation point
/// for the whole crate; the module documentation traces where the *other*
/// two resolutions of that macro lead, and why neither is supported.
///
/// # Ownership
///
/// Ownership ends here. After this call `p` is dangling and must not be
/// read, written, freed or compared against a live pointer.
///
/// A null pointer is a no-op. C already guarantees that for `free`, and the
/// guard below states it locally so that an auditor does not have to take
/// the C library's word for it. The C module leans on the same property in
/// the other direction, guarding explicitly at `lib/urlapi.c:L1295` before
/// tearing a handle down.
///
/// This is also the function that `Curl_safefree`, the macro at
/// `lib/curl_setup.h:L1319-L1323`, wraps: it frees and then nulls the
/// variable, so a later path cannot reuse it. In this crate the equivalent
/// is holding a [`CBuf`] in an `Option` and setting it to `None`, which
/// frees and clears in one move and, unlike the macro, cannot be forgotten.
///
/// # Safety
///
/// `p` must either be null or point to a block currently owned by the
/// caller that came from [`c_malloc`], [`c_calloc`], [`c_realloc`] or one
/// of the string helpers built on them, and that has not already been
/// freed. Freeing a pointer from a different allocator, or freeing twice,
/// is undefined behavior. In particular, and this is the reason
/// `CString::into_raw` is banned crate-wide, a pointer whose memory belongs
/// to the Rust allocator must never reach this function.
pub(crate) unsafe fn c_free(p: *mut c_void) {
    if p.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `p` is a live block from this module's
    // allocator that has not been freed, which is `libc::free`'s
    // precondition; the guard above has already removed the null case, so
    // the only pointers reaching the call are ones the contract covers.
    unsafe { libc::free(p) }
}

/// The implementation behind an exported `curl_free()`.
///
/// Mirrors `lib/escape.c:L189-L192` exactly, which is a one-line forward:
///
/// ```c
/// void curl_free(void *p)
/// {
///   curlx_free(p);
/// }
/// ```
///
/// The split between this function and its export is deliberate. The
/// `#[no_mangle] extern "C"` symbol lives in `src/ffi.rs` behind the
/// `cfree` feature, and this module contains no `#[no_mangle]` at all, so
/// the decision about which symbols exist stays in one file.
///
/// The feature exists because the symbol cannot be defined unconditionally.
/// In the drop-in configuration a real libcurl already defines `curl_free`
/// in the object built from `lib/escape.c`, and a second definition in this
/// crate's archive turns a clean link into a duplicate-symbol link. In the
/// standalone configuration nothing else supplies it, yet the documented
/// contract that a buffer from `curl_url_get()` is released with
/// `curl_free()` still has to hold, so the crate provides it. Hence a
/// feature rather than a fixed choice.
///
/// # Ownership
///
/// Ownership ends here, exactly as for [`c_free`], to which this forwards
/// unchanged.
///
/// # Safety
///
/// Identical to [`c_free`]: `p` must be null, or a live block from this
/// module's allocator that has not already been freed.
pub(crate) unsafe fn curl_free(p: *mut c_void) {
    // SAFETY: this function's contract is `c_free`'s contract verbatim, so
    // the caller has already established the precondition; forwarding adds
    // no requirement of its own. The C original at lib/escape.c:L189-L192
    // is the same single forwarding call.
    unsafe { c_free(p) }
}

/// A NUL-terminated byte buffer that lives in the C allocator and is owned
/// by Rust until it is explicitly handed over.
///
/// This is the type that turns the C module's hand-tracked ownership into
/// something the compiler checks. `lib/urlapi.c` carries roughly thirty
/// `curlx_free()` calls whose correctness rests on a reader following every
/// path out of every function; `CBuf` carries the same obligation in its
/// `Drop` implementation, where no path can miss it.
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
/// 1. `ptr` is non-null and is the start of a live block held by the C
///    allocator, either allocated by this module or certified by the caller
///    of [`CBuf::from_raw`] or [`CBuf::from_raw_parts`].
/// 2. The block is **at least** `len + 1` bytes. It may be longer, and
///    routinely is: `src/dynbuf.rs` grows geometrically and hands over a
///    buffer with spare capacity, and [`CBuf::format`] can end up with a
///    block wider than the string it holds.
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
/// Rust owns the buffer. Dropping the value releases it through [`c_free`].
/// [`CBuf::into_raw`] is the single point at which ownership moves to C,
/// and from then on the C side owes a `curl_free()`.
///
/// There is deliberately no method that yields a `*mut c_char` while
/// keeping ownership, because such a method is an invitation to a double
/// free: C frees the pointer, then `Drop` frees it again. When a borrowed
/// C-string pointer is genuinely needed, for instance to pass a host name
/// to libidn2, take it from [`CBuf::as_bytes_with_nul`], whose slice is
/// NUL-terminated and whose lifetime the borrow checker ties to this value.
///
/// # Thread safety
///
/// `CBuf` holds a raw pointer, so it is neither `Send` nor `Sync`. That
/// matches the C original: a `CURLU` handle and its strings are not safe to
/// share across threads either.
pub(crate) struct CBuf {
    /// Start of the C-allocator block. Non-null for every live value.
    ptr: *mut c_char,
    /// Logical length in bytes, excluding the terminator at `[len]`.
    len: usize,
}

impl CBuf {
    /// Allocates a block of `len + 1` bytes and writes the terminator.
    ///
    /// The `len.checked_add(1)` below is this port's spelling of the guard
    /// in `curlx_memdup0`, `lib/curlx/strdup.c:L87`, which allocates only
    /// when `length < SIZE_MAX` so that `length + 1` cannot wrap to zero
    /// and yield a one-byte block for an enormous string.
    ///
    /// The first `len` bytes are left uninitialized. Every caller below
    /// fills them completely before the value escapes this module, and none
    /// of them reads the buffer in between, so no reference is ever formed
    /// over uninitialized memory. Should a caller return early, `Drop`
    /// releases the block; that is the whole reason this returns a `CBuf`
    /// rather than a bare pointer.
    fn alloc(len: usize) -> Option<Self> {
        let total = len.checked_add(1)?;
        let raw = c_malloc(total);
        if raw.is_null() {
            return None;
        }
        let base = raw.cast::<c_char>();
        // SAFETY: `c_malloc` returned a non-null block of exactly `total`
        // bytes, and `total == len + 1`, so byte index `len` is the last
        // byte of that block and the offset computation stays in bounds.
        // Writing there establishes invariant 3 before any `CBuf` exists,
        // and `u8` needs no alignment beyond one byte.
        unsafe { base.cast::<u8>().add(len).write(0) };
        Some(Self { ptr: base, len })
    }

    /// Copies `src` into the buffer starting at `offset`.
    ///
    /// Returns `false`, and writes nothing at all, when the copy would not
    /// fit inside the logical length. Reporting rather than asserting is
    /// deliberate: an assertion would be a panic path, and this crate has
    /// none.
    fn fill(&mut self, offset: usize, src: &[u8]) -> bool {
        let fits = match offset.checked_add(src.len()) {
            Some(end) => end <= self.len,
            None => false,
        };
        if !fits {
            return false;
        }
        let dst = self.ptr.cast::<u8>();
        // SAFETY: `offset + src.len() <= self.len` was just established, and
        // invariant 2 gives the block at least `self.len + 1` bytes, so the
        // destination range lies inside the allocation. The destination came
        // from the C allocator and `src` is a live Rust slice, so the two
        // cannot overlap. `u8` has an alignment of one, which any pointer
        // satisfies.
        unsafe {
            ptr::copy_nonoverlapping(src.as_ptr(), dst.add(offset), src.len());
        }
        true
    }

    /// Shortens the logical length and re-terminates at the new end.
    ///
    /// The block itself is not shrunk, which invariant 2 permits. Only
    /// [`CBuf::format`] needs this, for the case where the second formatting
    /// pass emits fewer bytes than the first pass measured.
    fn truncate(&mut self, new_len: usize) {
        if new_len >= self.len {
            return;
        }
        // SAFETY: `new_len < self.len` and invariant 2 gives the block at
        // least `self.len + 1` bytes, so byte index `new_len` is comfortably
        // inside it. The write re-establishes invariant 3 for the new
        // length before `self.len` is updated to match.
        unsafe { self.ptr.cast::<u8>().add(new_len).write(0) };
        self.len = new_len;
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
        let mut buf = Self::alloc(bytes.len())?;
        if buf.fill(0, bytes) {
            Some(buf)
        } else {
            // Unreachable: `alloc` sized the buffer from this very slice, so
            // the copy fits by construction. Handled rather than asserted so
            // that no panic path exists even in principle.
            None
        }
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
        let mut buf = Self::alloc(total)?;
        let mut offset: usize = 0;
        for part in parts {
            if !buf.fill(offset, part) {
                // Unreachable, for the same reason as in `from_slice`: the
                // total was summed from these very slices. Reported rather
                // than asserted.
                return None;
            }
            offset = offset.checked_add(part.len())?;
        }
        Some(buf)
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
    /// is refused by the bounds check in [`CBuf::fill`] and surfaces as
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
        let mut buf = Self::alloc(counter.len)?;
        let written = {
            let mut sink = FillSink {
                buf: &mut buf,
                offset: 0,
            };
            // On an error here `sink` and then `buf` are dropped, and the
            // block is released. Nothing leaks on this path.
            fmt::write(&mut sink, args).ok()?;
            sink.offset
        };
        buf.truncate(written);
        Some(buf)
    }

    /// Takes ownership of a NUL-terminated C string, measuring it.
    ///
    /// The exact inverse of [`CBuf::into_raw`], and the pair is meant to be
    /// read together: `into_raw` gives a pointer away, `from_raw` takes one
    /// back. Its use in the port is re-adopting a pointer that one of the
    /// raw-returning helpers in this module produced, so that Rust owes the
    /// free again instead of C.
    ///
    /// # Ownership
    ///
    /// Ownership moves *into* the returned value. The caller must not free
    /// `p` afterwards and must not keep using it: the `CBuf`'s `Drop` is now
    /// the one and only release.
    ///
    /// # Returns
    ///
    /// `None` if `p` is null, which lets an allocation failure from C be
    /// forwarded without a separate check at the call site.
    ///
    /// # Safety
    ///
    /// `p` must be a pointer this crate is entitled to free, that is one
    /// from [`c_malloc`], [`c_calloc`], [`c_realloc`] or one of the string
    /// helpers built on them, or null. It must be NUL-terminated, since the
    /// length is measured with `strlen`, and no other owner may release it.
    /// A pointer that came from a different allocator, notably from Rust's,
    /// must never be passed here.
    #[must_use = "discarding the value frees the block immediately"]
    pub(crate) unsafe fn from_raw(p: *mut c_char) -> Option<Self> {
        if p.is_null() {
            return None;
        }
        // SAFETY: the caller guarantees `p` points to a live,
        // NUL-terminated C string, which is exactly `strlen`'s
        // precondition. The value it returns is the index of that
        // terminator, so the block is at least `len + 1` bytes and
        // invariants 2 and 3 hold for the value built below; invariant 1
        // holds because the null case was already returned.
        let len = unsafe { libc::strlen(p) };
        Some(Self { ptr: p, len })
    }

    /// Takes ownership of a C-allocator block of a known length.
    ///
    /// This is the handover `src/dynbuf.rs` needs. The C code performs the
    /// same handover through `curlx_dyn_ptr()` at `lib/urlapi.c:L672`,
    /// `L813`, `L1025`, `L1049`, `L1077`, `L1185`, `L1399`, `L1489` and
    /// `L1934`, and it is worth being precise about what that call does
    /// *not* do. `lib/curlx/dynbuf.c:L237` declares it over a
    /// `const struct dynbuf *` and simply returns the buffer pointer; it
    /// clears nothing, and the `const` receiver makes clearing impossible.
    /// Ownership transfers only because the C code then never releases that
    /// buffer again. Nothing in the type system records the handover and
    /// nothing catches a later edit that releases it twice. This function is
    /// where that implicit contract becomes explicit: after it returns, the
    /// `CBuf` is the sole owner and the compiler enforces it.
    ///
    /// The terminator at `[len]` is written here rather than assumed, so
    /// invariant 3 holds by construction even if the incoming block was not
    /// already terminated.
    ///
    /// # Ownership
    ///
    /// Ownership moves *into* the returned value, exactly as for
    /// [`CBuf::from_raw`].
    ///
    /// # Returns
    ///
    /// `None` if `p` is null.
    ///
    /// # Safety
    ///
    /// All of the following must hold. `p` must be null, or a block this
    /// crate is entitled to free, from [`c_malloc`], [`c_calloc`],
    /// [`c_realloc`] or a helper built on them. That block must be at least
    /// `len + 1` bytes, so that the terminator write below stays inside it;
    /// passing a `len` larger than the block permits is undefined behavior,
    /// and note that `len` is the logical length rather than the capacity.
    /// The first `len` bytes must be initialized. No other owner may release
    /// the block.
    #[must_use = "discarding the value frees the block immediately"]
    pub(crate) unsafe fn from_raw_parts(p: *mut c_char, len: usize) -> Option<Self> {
        if p.is_null() {
            return None;
        }
        // SAFETY: the caller guarantees the block is at least `len + 1`
        // bytes, so the offset computation and the one-byte write both stay
        // inside the allocation, and `u8` needs no alignment beyond one
        // byte. The write establishes invariant 3; the caller's guarantee is
        // invariant 2; and the null case was already returned, which is
        // invariant 1.
        unsafe { p.cast::<u8>().add(len).write(0) };
        Some(Self { ptr: p, len })
    }

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
    #[must_use]
    pub(crate) const fn is_empty(&self) -> bool {
        self.len == 0
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
        // SAFETY: invariant 1 gives a non-null pointer into a live block and
        // invariant 2 gives it at least `self.len + 1` bytes, so `self.len`
        // bytes from the start are inside the allocation and initialized by
        // the constructors. `u8` has an alignment of one. The returned
        // lifetime is tied to `&self`, so the slice cannot outlive the block
        // and no mutation can occur while it is held.
        unsafe { slice::from_raw_parts(self.ptr.cast::<u8>(), self.len) }
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
        // SAFETY: invariant 2 gives the block at least `self.len + 1` bytes,
        // which is exactly `with_nul`, and invariant 3 says the last of them
        // is the terminator, so every byte of the slice is inside the
        // allocation and initialized. Alignment and lifetime reasoning is as
        // in `as_bytes`.
        unsafe { slice::from_raw_parts(self.ptr.cast::<u8>(), with_nul) }
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
        // SAFETY: the same reasoning as `as_bytes`, with a unique borrow.
        // `&mut self` guarantees no other reference to these bytes exists,
        // so handing out a `&mut [u8]` over them creates no aliasing. The
        // length excludes the terminator, so invariant 3 survives whatever
        // the caller writes.
        unsafe { slice::from_raw_parts_mut(self.ptr.cast::<u8>(), self.len) }
    }

    /// Relinquishes ownership and returns the bare pointer.
    ///
    /// # Ownership, in detail, because this is where it changes hands
    ///
    /// After this call **Rust no longer owns the buffer** and `Drop` will
    /// not run: the value is consumed and wrapped in `ManuallyDrop` so that
    /// the release is suppressed rather than merely skipped.
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
    ///   [`CBuf::from_raw`]. Simply keeping the pointer around leaks it, and
    ///   dropping a second `CBuf` built over the same pointer frees it
    ///   twice.
    ///
    /// The returned pointer is never null.
    #[must_use = "ownership moves to the caller; discarding this leaks"]
    pub(crate) fn into_raw(self) -> *mut c_char {
        // `ManuallyDrop` rather than `mem::forget`: both suppress the drop,
        // and this one says so at the type level.
        let kept = mem::ManuallyDrop::new(self);
        kept.ptr
    }
}

impl Drop for CBuf {
    /// Releases the block, replacing the C module's manual teardown.
    ///
    /// This one implementation stands in for `free_urlhandle()` at
    /// `lib/urlapi.c:L86-L98`, which frees ten fields by hand, and for the
    /// roughly thirty other `curlx_free()` calls scattered through the
    /// module's error paths.
    fn drop(&mut self) {
        // SAFETY: invariant 1 says `self.ptr` is a live block from the C
        // allocator that this crate owns, which is `c_free`'s precondition.
        // `Drop` runs at most once per value, and `into_raw` is the only
        // other way out of the type and suppresses this call, so the block
        // is released exactly once and never after being given away.
        unsafe { c_free(self.ptr.cast::<c_void>()) };
    }
}

impl fmt::Debug for CBuf {
    /// Prints the length and the content with non-printable bytes escaped.
    ///
    /// Escaping is not decoration. The content is arbitrary bytes rather
    /// than text, and this crate's sources are required to be pure ASCII by
    /// `scripts/spacecheck.pl`, so a raw dump would be both invalid UTF-8
    /// and unreadable in a test failure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CBuf(len {}, \"", self.len)?;
        for &b in self.as_bytes() {
            if (0x20..0x7f).contains(&b) && b != b'"' && b != b'\\' {
                write!(f, "{}", char::from(b))?;
            } else {
                write!(f, "\\x{b:02x}")?;
            }
        }
        f.write_str("\")")
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
/// Every write goes through [`CBuf::fill`], which bounds-checks against the
/// buffer's logical length, so this sink cannot write outside the block even
/// if the second pass disagrees with the first about how many bytes the
/// output needs.
struct FillSink<'a> {
    /// The destination, borrowed for the duration of the pass.
    buf: &'a mut CBuf,
    /// Bytes written so far, and the offset of the next write.
    offset: usize,
}

impl fmt::Write for FillSink<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if !self.buf.fill(self.offset, s.as_bytes()) {
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
/// a `curl_free()` on it, or take it back with [`CBuf::from_raw`], or
/// release it with [`c_free`]. Nothing else tracks it, so dropping it on
/// the floor leaks.
///
/// # Returns
///
/// A null pointer if the allocation fails, matching `curlx_strdup`.
#[must_use = "the caller owns this string; discarding it leaks memory"]
pub(crate) fn c_strdup(bytes: &[u8]) -> *mut c_char {
    CBuf::from_slice(bytes).map_or(ptr::null_mut(), CBuf::into_raw)
}

/// Duplicates a NUL-terminated C string.
///
/// The literal mirror of `curlx_strdup`, taking the same argument C does.
/// The port needs this shape where it duplicates a string it received from
/// C rather than one it built, which is what the `DUP` macro at
/// `lib/urlapi.c:L1301-L1308` does for each of the ten handle fields in
/// `curl_url_dup()`.
///
/// # Ownership
///
/// **The caller owns the returned pointer**, exactly as for [`c_strdup`].
/// `src` is only read, and ownership of it is unaffected.
///
/// # Returns
///
/// A null pointer if the allocation fails, or if `src` is null. C's
/// `strdup` has undefined behavior on a null argument; returning null
/// instead costs one branch and makes the function total. The C module never
/// relies on it, because the `DUP` macro guards with `if((src)->name)` at
/// `lib/urlapi.c:L1303` before calling.
///
/// # Safety
///
/// `src` must be null, or point to a NUL-terminated C string that stays
/// valid and unmodified for the duration of the call. The length is measured
/// with `strlen`, so an unterminated buffer reads out of bounds.
#[must_use = "the caller owns this string; discarding it leaks memory"]
pub(crate) unsafe fn c_strdup_raw(src: *const c_char) -> *mut c_char {
    if src.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the caller guarantees `src` is a live NUL-terminated C string,
    // which is `strlen`'s precondition, and the null case has already
    // returned. `strlen` therefore yields a length for which `src` is valid
    // for reads, which is exactly what `c_memdup0` requires next.
    let len = unsafe { libc::strlen(src) };
    // SAFETY: `src` is valid for reads of `len` bytes, since `strlen` just
    // walked precisely those bytes to find the terminator.
    unsafe { c_memdup0(src, len) }
}

/// Copies `len` bytes from `src` and appends a terminator.
///
/// The literal mirror of `curlx_memdup0`, `lib/curlx/strdup.c:L85-L96`, and
/// it reproduces that function's contract point for point: the overflow
/// guard, so `len + 1` can never wrap; the copy performed only when `len` is
/// nonzero, which is what makes a null `src` acceptable at zero length; and
/// the terminator written unconditionally at `[len]`.
///
/// This is how curl duplicates a *slice* of a larger string, at
/// `lib/urlapi.c:L1028`, `L1052`, `L1086` and `L1367`. Where the port
/// already holds a Rust subslice, [`c_strdup`] expresses the same operation
/// without a raw pointer and is preferred.
///
/// # Ownership
///
/// **The caller owns the returned pointer**, exactly as for [`c_strdup`].
/// `src` is only read, and ownership of it is unaffected.
///
/// # Returns
///
/// A null pointer if the allocation fails or if `len` is `usize::MAX`, which
/// is `curlx_memdup0`'s own `length < SIZE_MAX` guard at
/// `lib/curlx/strdup.c:L87`.
///
/// # Safety
///
/// `src` must be valid for reads of `len` bytes and must not overlap the
/// freshly allocated destination, which it cannot, since the destination did
/// not exist when the caller obtained `src`. When `len` is zero, `src` is
/// not read at all and may be null.
#[must_use = "the caller owns this string; discarding it leaks memory"]
pub(crate) unsafe fn c_memdup0(src: *const c_char, len: usize) -> *mut c_char {
    let Some(mut buf) = CBuf::alloc(len) else {
        return ptr::null_mut();
    };
    if len != 0 {
        // SAFETY: the caller guarantees `src` is valid for reads of `len`
        // bytes, and this branch has established that `len` is nonzero, so
        // no zero-length slice over a possibly null pointer is formed. `u8`
        // has an alignment of one, which any pointer satisfies. `len` is a
        // real allocation length, hence at most `isize::MAX`, so the slice
        // is representable. The borrow ends inside this statement, well
        // before anything could invalidate `src`.
        let source = unsafe { slice::from_raw_parts(src.cast::<u8>(), len) };
        if !buf.fill(0, source) {
            // Unreachable: `alloc(len)` reserved exactly this many bytes.
            // Reported rather than asserted, so no panic path exists.
            return ptr::null_mut();
        }
    }
    buf.into_raw()
}

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

    // Imported by name rather than through a glob, which is the rule the
    // plan sets for the whole crate at AAP 0.4.3, split across several
    // statements only so that no line grows unreadably long.
    use super::{c_calloc, c_concat, c_free, c_malloc, c_maprintf};
    use super::{c_memdup0, c_realloc, c_strdup, c_strdup_raw};
    use super::{curl_free, CBuf};
    use core::cell::Cell;
    use core::fmt;
    use core::ptr;
    use core::slice;
    use libc::{c_char, c_void};

    /// Adopts a pointer this module produced so that `Drop` releases it.
    ///
    /// Every test that receives a raw pointer routes it through here, which
    /// means no test leaks and a run under `valgrind --leak-check=full`
    /// stays clean. That matters more than usual: a leak in this module is
    /// invisible to the parity diff and would surface only as slow growth.
    ///
    /// # Safety
    ///
    /// `p` must be null, or a live NUL-terminated C string from this
    /// module's allocator that no one else will release.
    unsafe fn adopt(p: *mut c_char) -> CBuf {
        // SAFETY: forwarded from this function's own contract, which is
        // `CBuf::from_raw`'s contract verbatim.
        let buf = unsafe { CBuf::from_raw(p) };
        buf.unwrap()
    }

    #[test]
    fn c_malloc_round_trips_and_frees() {
        let p = c_malloc(32);
        assert!(!p.is_null(), "a 32-byte allocation should succeed");
        // SAFETY: `c_malloc` returned a non-null block of exactly 32 bytes,
        // so a 32-byte slice over it lies inside the allocation, and `u8`
        // needs no alignment beyond one byte.
        let bytes = unsafe { slice::from_raw_parts_mut(p.cast::<u8>(), 32) };
        bytes.fill(0xa5);
        assert!(bytes.iter().all(|&b| b == 0xa5));
        // SAFETY: `p` came from `c_malloc` above and has not been freed.
        unsafe { c_free(p) };
    }

    #[test]
    fn c_malloc_returns_null_for_zero_and_absurd_sizes() {
        // Deterministic rejection rather than the platform's unspecified
        // answer to `malloc(0)`.
        assert!(c_malloc(0).is_null());
        // An impossible request must fail rather than abort. This is the
        // property that lets every caller treat null as out-of-memory.
        assert!(c_malloc(usize::MAX).is_null());
        assert!(c_malloc(usize::MAX / 2).is_null());
    }

    #[test]
    fn c_calloc_zeroes_the_block() {
        let p = c_calloc(4, 8);
        assert!(!p.is_null());
        // SAFETY: `c_calloc` returned a non-null block of 4 * 8 == 32 zeroed
        // bytes, so the slice lies inside the allocation and is initialized.
        let bytes = unsafe { slice::from_raw_parts(p.cast::<u8>(), 32) };
        assert!(
            bytes.iter().all(|&b| b == 0),
            "the handle at lib/urlapi.c:L1290 relies on this zeroing"
        );
        // SAFETY: `p` came from `c_calloc` above and has not been freed.
        unsafe { c_free(p) };
    }

    #[test]
    fn c_calloc_rejects_zero_counts_and_overflow() {
        assert!(c_calloc(0, 8).is_null());
        assert!(c_calloc(8, 0).is_null());
        // The product overflows `usize`, which must be a null return rather
        // than a wrapped, undersized allocation.
        assert!(c_calloc(usize::MAX, 2).is_null());
        assert!(c_calloc(usize::MAX / 2, 4).is_null());
    }

    #[test]
    fn c_realloc_grows_and_preserves_the_prefix() {
        let small = c_malloc(4);
        assert!(!small.is_null());
        // SAFETY: `small` is a non-null 4-byte block from `c_malloc`.
        let dst = unsafe { slice::from_raw_parts_mut(small.cast(), 4) };
        dst.copy_from_slice(b"curl");
        // SAFETY: `small` is a live block from this module's allocator and
        // has not been freed, which is `c_realloc`'s precondition.
        let big = unsafe { c_realloc(small, 64) };
        assert!(!big.is_null());
        // SAFETY: on success `c_realloc` returned a 64-byte block whose
        // first four bytes carry the old contents.
        let head = unsafe { slice::from_raw_parts(big.cast::<u8>(), 4) };
        assert_eq!(head, b"curl".as_slice());
        // SAFETY: ownership moved from `small` to `big`, so `big` is the
        // only live pointer and freeing it once is correct.
        unsafe { c_free(big) };
    }

    #[test]
    fn c_realloc_rejects_zero_and_keeps_the_original() {
        let p = c_malloc(8);
        assert!(!p.is_null());
        // SAFETY: `p` is a live block from `c_malloc`.
        let out = unsafe { c_realloc(p, 0) };
        assert!(out.is_null(), "a zero size must be refused");
        // The documented failure contract says `p` is untouched, so it is
        // still ours to use and still ours to release. If `c_realloc` had
        // freed it, the write below and the free after would both be
        // use-after-free, which a run under valgrind would report.
        // SAFETY: `p` is still live, per the contract just asserted.
        unsafe { slice::from_raw_parts_mut(p.cast::<u8>(), 8) }.fill(b'z');
        // SAFETY: `p` is live and unfreed.
        unsafe { c_free(p) };
    }

    #[test]
    fn c_free_and_curl_free_are_no_ops_on_null() {
        // SAFETY: a null pointer is explicitly permitted by both contracts,
        // and both must return without touching anything.
        unsafe {
            c_free(ptr::null_mut());
            curl_free(ptr::null_mut());
        }
    }

    #[test]
    fn curl_free_releases_a_block_from_this_module() {
        let p = c_strdup(b"https://example.com/");
        assert!(!p.is_null());
        // This is the round trip the whole module exists for: a buffer
        // allocated here and released through the exported free function,
        // exactly as a caller of curl_url_get() would do.
        // SAFETY: `p` is a live block from `c_strdup` that nothing else
        // owns, which is `curl_free`'s precondition.
        unsafe { curl_free(p.cast::<c_void>()) };
    }

    #[test]
    fn c_strdup_copies_and_terminates() {
        let p = c_strdup(b"https");
        assert!(!p.is_null());
        // SAFETY: `p` is a live NUL-terminated string from `c_strdup`.
        let buf = unsafe { adopt(p) };
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.as_bytes(), b"https".as_slice());
        assert_eq!(buf.as_bytes_with_nul(), b"https\0".as_slice());
        // The terminator is what makes the pointer a C string at all.
        assert_eq!(buf.as_bytes_with_nul()[5], 0);
    }

    #[test]
    fn c_strdup_of_an_empty_slice_is_not_null() {
        // lib/urlapi.c:L815 and L1059 both call curlx_strdup("") and treat a
        // null result as out-of-memory, so an empty string has to exist.
        let p = c_strdup(b"");
        assert!(!p.is_null());
        // SAFETY: `p` is a live NUL-terminated string from `c_strdup`.
        let buf = unsafe { adopt(p) };
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
        assert_eq!(buf.as_bytes_with_nul(), b"\0".as_slice());
    }

    #[test]
    fn c_strdup_preserves_bytes_that_are_not_utf8() {
        // The reason this module is byte-oriented throughout. A host name
        // returned from internationalized-domain decoding is not ASCII, and
        // a path may carry any byte the junk scan allows, so any UTF-8
        // validation on this path would reject input curl accepts.
        let raw: [u8; 5] = [0xff, 0xfe, b'/', 0x80, b'x'];
        let p = c_strdup(&raw);
        assert!(!p.is_null());
        // SAFETY: `p` is a live NUL-terminated string from `c_strdup`.
        let buf = unsafe { adopt(p) };
        assert_eq!(buf.as_bytes(), raw.as_slice());
    }

    #[test]
    fn c_strdup_raw_duplicates_a_c_string() {
        let first = c_strdup(b"example.com");
        assert!(!first.is_null());
        // SAFETY: `first` is a live NUL-terminated C string.
        let second = unsafe { c_strdup_raw(first) };
        assert!(!second.is_null());
        assert!(!ptr::eq(first, second), "it must copy, not alias");
        // SAFETY: both pointers are live NUL-terminated strings from this
        // module, and each is adopted exactly once.
        let (a, b) = unsafe { (adopt(first), adopt(second)) };
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_eq!(b.as_bytes(), b"example.com".as_slice());
    }

    #[test]
    fn c_strdup_raw_returns_null_for_null() {
        // C's strdup has undefined behavior here. One branch makes the
        // function total instead, which is why the DUP macro's guard at
        // lib/urlapi.c:L1303 is a belt rather than the only brace.
        // SAFETY: a null argument is explicitly permitted by the contract.
        assert!(unsafe { c_strdup_raw(ptr::null()) }.is_null());
    }

    #[test]
    fn c_memdup0_copies_exactly_len_bytes_and_terminates() {
        let whole = c_strdup(b"host:8080/path");
        assert!(!whole.is_null());
        // SAFETY: `whole` is a live 14-byte NUL-terminated string, so it is
        // valid for reads of the first 4 bytes.
        let part = unsafe { c_memdup0(whole, 4) };
        assert!(!part.is_null());
        // SAFETY: both are live NUL-terminated strings from this module,
        // each adopted exactly once.
        let (all, four) = unsafe { (adopt(whole), adopt(part)) };
        assert_eq!(all.as_bytes(), b"host:8080/path".as_slice());
        // Exactly len bytes, and a terminator that was not in the source.
        assert_eq!(four.len(), 4);
        assert_eq!(four.as_bytes(), b"host".as_slice());
        assert_eq!(four.as_bytes_with_nul(), b"host\0".as_slice());
    }

    #[test]
    fn c_memdup0_accepts_a_null_source_at_zero_length() {
        // curlx_memdup0 copies only when length is nonzero, at
        // lib/curlx/strdup.c:L90-L93, so this case never reads the source.
        // SAFETY: `len` is zero, so `src` is not read and may be null.
        let p = unsafe { c_memdup0(ptr::null(), 0) };
        assert!(!p.is_null());
        // SAFETY: `p` is a live NUL-terminated string from this module.
        let buf = unsafe { adopt(p) };
        assert!(buf.is_empty());
    }

    #[test]
    fn c_memdup0_rejects_a_length_that_cannot_be_terminated() {
        let src = c_strdup(b"x");
        assert!(!src.is_null());
        // usize::MAX + 1 for the terminator would wrap to zero and yield a
        // one-byte block for an enormous string. This is curlx_memdup0's own
        // `length < SIZE_MAX` guard at lib/curlx/strdup.c:L87.
        // SAFETY: the length check rejects the request before `src` is read,
        // so no out-of-bounds read can occur despite the absurd length.
        assert!(unsafe { c_memdup0(src, usize::MAX) }.is_null());
        // A merely impossible length must also fail rather than abort.
        // SAFETY: as above, the allocation fails before any read.
        assert!(unsafe { c_memdup0(src, usize::MAX / 2) }.is_null());
        // SAFETY: `src` is still live; none of the failed calls freed it.
        drop(unsafe { adopt(src) });
    }

    #[test]
    fn c_concat_assembles_fifteen_parts_in_order() {
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
        let p = c_concat(&parts);
        assert!(!p.is_null());
        // SAFETY: `p` is a live NUL-terminated string from `c_concat`.
        let buf = unsafe { adopt(p) };
        let want = b"https://user:not-a-secret@example.com:8080/a/b?q=1#frag";
        assert_eq!(buf.as_bytes(), want.as_slice());
        assert_eq!(buf.len(), want.len());
    }

    #[test]
    fn c_concat_handles_the_file_url_template_and_empty_inputs() {
        // The five-conversion template at lib/urlapi.c:L1441.
        let p = c_concat(&[b"file://", b"", b"", b"/tmp/x", b""]);
        assert!(!p.is_null());
        // SAFETY: `p` is a live NUL-terminated string from `c_concat`.
        let buf = unsafe { adopt(p) };
        assert_eq!(buf.as_bytes(), b"file:///tmp/x".as_slice());
        // No parts at all yields the empty string, not a null pointer.
        let empty = c_concat(&[]);
        assert!(!empty.is_null());
        // SAFETY: `empty` is a live NUL-terminated string from `c_concat`.
        let buf = unsafe { adopt(empty) };
        assert!(buf.is_empty());
    }

    #[test]
    fn c_concat_preserves_bytes_that_are_not_utf8() {
        let host: [u8; 3] = [0xc3, 0xa4, b'.'];
        let p = c_concat(&[b"http://", &host, b"se/"]);
        assert!(!p.is_null());
        // SAFETY: `p` is a live NUL-terminated string from `c_concat`.
        let buf = unsafe { adopt(p) };
        assert_eq!(buf.as_bytes(), b"http://\xc3\xa4.se/".as_slice());
    }

    #[test]
    fn c_maprintf_formats_a_port_number() {
        // lib/urlapi.c:L381 and L1676 print a curl_off_t in decimal.
        for (value, want) in [
            (8080_i64, b"8080".as_slice()),
            (0_i64, b"0".as_slice()),
            (65535_i64, b"65535".as_slice()),
            (i64::MAX, b"9223372036854775807".as_slice()),
            (i64::MIN, b"-9223372036854775808".as_slice()),
        ] {
            let p = c_maprintf(format_args!("{value}"));
            assert!(!p.is_null());
            // SAFETY: `p` is a live NUL-terminated string from
            // `c_maprintf`, adopted exactly once per iteration.
            let buf = unsafe { adopt(p) };
            assert_eq!(buf.as_bytes(), want);
            assert_eq!(buf.len(), want.len());
        }
    }

    #[test]
    fn cbuf_drop_releases_and_into_raw_suppresses_it() {
        // Path one: the value is dropped, so Drop frees the block. A
        // failure here is a leak, which only a leak checker sees, so this
        // test earns its keep under `valgrind --leak-check=full`.
        {
            let buf = CBuf::from_slice(b"dropped").unwrap();
            assert_eq!(buf.len(), 7);
        }
        // Path two: ownership is relinquished, so Drop must not run. Were
        // it to run, the read below would be a use-after-free and the free
        // after it a double free; both are reported under valgrind.
        let raw = CBuf::from_slice(b"handed over").unwrap().into_raw();
        assert!(!raw.is_null(), "into_raw never yields null");
        // SAFETY: `raw` is the live block just relinquished, and nothing
        // else owns it, so adopting it makes this scope the sole owner.
        let back = unsafe { adopt(raw) };
        assert_eq!(back.as_bytes(), b"handed over".as_slice());
    }

    #[test]
    fn cbuf_from_raw_parts_takes_a_shorter_view_and_terminates() {
        // The dynbuf handover: a block wider than the logical length, which
        // invariant 2 permits and lib/urlapi.c relies on at L1185 and
        // friends. The terminator is written here rather than assumed.
        let raw = CBuf::from_slice(b"example.com/path").unwrap().into_raw();
        // SAFETY: `raw` is a live 16-byte block plus terminator from this
        // module, so it is at least 11 + 1 bytes, its first 11 bytes are
        // initialized, and nothing else owns it.
        let buf = unsafe { CBuf::from_raw_parts(raw, 11) }.unwrap();
        assert_eq!(buf.len(), 11);
        assert_eq!(buf.as_bytes(), b"example.com".as_slice());
        assert_eq!(buf.as_bytes_with_nul(), b"example.com\0".as_slice());
        // Null in, None out, so a C allocation failure forwards cleanly.
        // SAFETY: a null pointer is explicitly permitted by the contract.
        assert!(unsafe { CBuf::from_raw_parts(ptr::null_mut(), 0) }.is_none());
        // SAFETY: as above.
        assert!(unsafe { CBuf::from_raw(ptr::null_mut()) }.is_none());
    }

    #[test]
    fn cbuf_as_bytes_with_nul_yields_a_valid_c_string_pointer() {
        // This is the borrow that replaces an `as_ptr` method: safe code,
        // lifetime-checked, and no *mut ever escapes.
        let buf = CBuf::from_slice(b"ftp.example.com").unwrap();
        let p: *const c_char = buf.as_bytes_with_nul().as_ptr().cast();
        // SAFETY: the slice is NUL-terminated by invariant 3 and its
        // lifetime is tied to `buf`, which outlives this call, so `strlen`
        // reads only initialized bytes inside the allocation.
        let measured = unsafe { libc::strlen(p) };
        assert_eq!(measured, buf.len());
        assert_eq!(measured, 15);
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
        let growing = Growing(Cell::new(2));
        assert!(c_maprintf(format_args!("{growing}")).is_null());
    }

    #[test]
    fn cbuf_debug_escapes_bytes_that_are_not_printable() {
        let buf = CBuf::from_slice(b"a\xffb\"c").unwrap();
        let shown = format!("{buf:?}");
        assert_eq!(shown, "CBuf(len 5, \"a\\xffb\\x22c\")");
    }

    #[test]
    fn repeated_allocation_and_release_stays_balanced() {
        // Exercises every allocating path many times over. The assertions
        // check correctness; the point of the repetition is that a leak or
        // a double free becomes loud under a leak checker.
        for n in 0_usize..2000 {
            let text = c_maprintf(format_args!("{n}"));
            assert!(!text.is_null());
            // SAFETY: `text` is a live NUL-terminated string from
            // `c_maprintf`, adopted exactly once in this iteration.
            let owned = unsafe { adopt(text) };
            let joined = c_concat(&[b"n=", owned.as_bytes(), b";"]);
            assert!(!joined.is_null());
            // SAFETY: `joined` is a live NUL-terminated string from
            // `c_concat`, adopted exactly once in this iteration.
            let joined = unsafe { adopt(joined) };
            // Two bytes of prefix plus one of suffix around the digits.
            assert_eq!(joined.len(), owned.len() + 3);
            let copy = c_strdup(joined.as_bytes());
            assert!(!copy.is_null());
            // SAFETY: `copy` is a live NUL-terminated string from
            // `c_strdup`, adopted exactly once in this iteration.
            drop(unsafe { adopt(copy) });
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
