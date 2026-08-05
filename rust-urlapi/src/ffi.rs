// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The FFI facade: the crate's one and only `unsafe` island.
//!
//! Every foreign call this crate makes, and every raw pointer it ever
//! dereferences, lives in this file. No other module contains an `unsafe`
//! block, an `unsafe fn`, an `unsafe impl` or an `extern` block, and the
//! ones that could plausibly need one say so mechanically with a
//! module-level `#![forbid(unsafe_code)]` rather than by convention. That is
//! the plan's design at 0.3.3, restated in the file-by-file mapping at
//! 0.4.1.3 as "the only `unsafe` in the crate", and again in the substitute
//! baseline at 0.7.2; the technical specification reaches the same place
//! from the other direction by confining `unsafe` to FFI code at 1.3.2.1 and
//! requiring a `// SAFETY:` comment on every block at 3.2.1.2.
//!
//! # Why one island rather than five
//!
//! An earlier arrangement spread the foreign calls across the modules that
//! needed them: the C allocator in `src/alloc.rs`, the platform address
//! conversion in `src/inet.rs`, the libidn2 binding in `src/idn.rs`, and
//! libcurl's scheme lookup in `src/scheme.rs`. Each site was individually
//! defensible -- calling `libc::malloc` really is FFI -- but the sum was
//! five files an auditor had to read to answer "what can this crate do that
//! the compiler cannot check", and five files a future edit could add a
//! sixth `unsafe` block to without anyone noticing.
//!
//! Concentrating them here answers that question with one file, and lets
//! every other module state the guarantee in a form the compiler enforces.
//! Nothing about the *interfaces* moved: `src/alloc.rs` is still the crate's
//! memory adapter and still the only module the rest of the crate asks for a
//! C-visible buffer, `src/idn.rs` and `src/scheme.rs` still own their
//! compile-time backend selection, and `src/inet.rs` still presents the
//! conversion pair. What moved is the raw call at the bottom of each.
//!
//! # Section map
//!
//! | Section | Contents | Consumer |
//! |---------|----------|----------|
//! | 1 | The C allocator and `CBlock`, the owned block every C-visible buffer is built on | `src/alloc.rs`, `src/dynbuf.rs` |
//! | 2 | `inet_sys`, the platform `inet_pton` and `inet_ntop` | `src/inet.rs` |
//! | 3 | `idn2`, the libidn2 binding | `src/idn.rs` |
//! | 4 | `scheme_import`, libcurl's own `Curl_get_scheme` | `src/scheme.rs` |
//! | 5 | `test_locale`, the locale and codeset probes | `src/idn.rs` tests |
//! | 6 | `exports`, the C-linkage symbols: eight unconditional plus two feature-gated | the C side |
//!
//! Sections 2 through 5 are each selected by a configuration switch, so which
//! of them a given build contains depends on the target and the feature set;
//! they are named in plain text above rather than linked for that reason.
//! Section 1 is unconditional.
//!
//! # What the archive exports
//!
//! Section 6 holds the eight symbols an archive must export to stand in for
//! the object file `lib/urlapi.c` produces -- `curl_url`,
//! `curl_url_cleanup`, `curl_url_dup`, `curl_url_get`, `curl_url_set`,
//! `Curl_is_absolute_url`, `Curl_junkscan` and `Curl_url_set_authority` --
//! together with the two feature-gated ones, `curl_url_strerror` and
//! `curl_free`, which exist for the standalone link and **must be off in
//! drop-in mode** because `strerror.c.o` and `escape.c.o` already define
//! them. That is the whole set, and nothing else in the crate carries
//! `#[no_mangle]` outside `#[cfg(test)]`, which is what keeps the archive
//! collision-free. `scripts/check-abi.sh` is to compare the archive's set
//! against the C object's; it is a later deliverable and does not exist yet,
//! so for now `nm -g --defined-only` over both artifacts is the check, and it
//! has to disregard the compiler-builtins and Rust-runtime symbols the
//! staticlib carries alongside this crate's own.
//!
//! Every one of the ten is a thin skin: it validates the pointers, converts
//! the representations, and delegates. `src/getset.rs` owns the get and set
//! logic, `src/parse/` the parser stages and the authority setter, and
//! `src/handle.rs` the handle itself. No parsing decision is made in this
//! file.
//!
//! Because the skin is all this file contributes, the skin is what its own
//! tests exercise: the `c_surface` module at the bottom calls every symbol
//! this file defines through its C signature, raw pointers and integer codes
//! only, including every null precondition and the two error paths that
//! deliberately leave the caller's out-parameter untouched. Over that,
//! `tests/libtest/lib1560.c`, compiled unmodified and linked in both modes, is
//! the authority: it drives the same symbols as an ordinary C caller does,
//! which is the only oracle that exercises the real ABI rather than a Rust
//! call to the same function.
//!
//! # Memory ownership, in one place
//!
//! `docs/libcurl/curl_url_get.md:L45` and `include/curl/urlapi.h:L130-L131`
//! both require that a buffer returned by the URL API be released with
//! `curl_free()`, and `include/curl/urlapi.h:L116-L118` adds that
//! `curl_url_cleanup()` does *not* release strings handed out earlier. So
//! ownership of such a buffer leaves this crate for good, and its release
//! happens in code this crate neither controls nor can inspect.
//!
//! That is why section 1 exists and why it uses the C allocator. `curl_free`
//! is a one-line forward at `lib/escape.c:L189-L192` to `curlx_free`, a
//! macro `lib/curl_setup.h` resolves three ways at compile time: to the
//! tracking free `curl_dbg_free` under the memory-debug configuration
//! (`L1461`), to an indirect call through the mutable global hook
//! `Curl_cfree` when building libcurl (`L1478`), or to plain `free`
//! otherwise (`L1484`). The last two both end in the C allocator's `free`,
//! and allocating with the C allocator is the one choice that is correct for
//! both. `docs/MEMORY-OWNERSHIP.md` records the whole chain, including the
//! two configurations that are reported as unsupported rather than worked
//! around: memory-debug builds (R3) and applications that install
//! alternative allocators (R4).
//!
//! `CString::into_raw` is banned crate-wide for the same reason. Its pointer
//! must come back to Rust to be deallocated, which no `curl_free()` caller
//! will ever do, and calling the C deallocator on it is undefined behavior.
//! It appears nowhere in this crate, and nothing here hands out a pointer
//! into Rust-allocated memory.
//!
//! # Panic posture
//!
//! Nothing here can panic. `src/lib.rs` denies the panicking constructs --
//! `unwrap`, `expect`, `panic!`, direct indexing and unchecked arithmetic --
//! so panics are designed out rather than caught. That matters more in this
//! file than anywhere else: a panic crossing an `extern "C"` boundary aborts
//! the calling process by RFC 2945, which is a defined outcome but not a
//! recoverable one, and substituting an error code for a panic would mask
//! exactly the class of bug the parity diff exists to expose.
//!
//! # Thread safety
//!
//! The allocator primitives are as thread-safe as the C allocator beneath
//! them, which is to say fully so on every target this crate builds for.
//! `CBlock` holds a raw pointer and is therefore neither `Send` nor
//! `Sync`, matching the URL API's own posture: a `CURLU` handle and the
//! strings it owns are not safe to share across threads either.

// Section 1 is a deliberately complete allocator adapter, so that no other
// module ever has a reason to reach past `src/alloc.rs` to the C allocator
// directly. Completeness and use are different things: which primitives are
// reachable depends on the selected feature set, and `curl_free` in particular
// is called only from the `cfree`-gated export.
//
// No dead-code allowance is stated here. The crate-level one in `src/lib.rs`
// covers the whole feature matrix in one place, which is where the reason for
// it belongs; see "DEAD-CODE POLICY" there.

use core::fmt;
use core::mem;
use core::ptr;
use core::slice;
use libc::{c_char, c_void};

use crate::alloc::CBuf;

// ==========================================================================
// Section 1 -- the C allocator
// ==========================================================================

/// The largest allocation this module will make, `isize::MAX` bytes.
///
/// Not a policy choice and not a curl limit: it is the bound Rust's own
/// pointer and slice model imposes. `slice::from_raw_parts` requires that the
/// total size of the slice be no larger than `isize::MAX`, and every block
/// here is eventually viewed as a slice by [`CBlock::bytes`] and
/// [`CBlock::bytes_mut`], so a larger block could not be handed out safely
/// even if the platform allocator produced one. Refusing the request is the
/// only honest answer, and it reads to the caller as an ordinary allocation
/// failure, which is what curl's own out-of-memory paths already handle:
/// `lib/urlapi.c` answers a null allocation with `CURLUE_OUT_OF_MEMORY` at
/// every site.
///
/// No reachable input approaches it. `Curl_junkscan` caps a URL at
/// `CURL_MAX_INPUT_LENGTH`, 8,000,000 bytes, at `lib/urlapi.c:L229-L230`, so
/// the bound exists for the arithmetic rather than for the data.
pub(crate) const MAX_ALLOC: usize = isize::MAX as usize;

/// Allocates `size` bytes with the C allocator.
///
/// Mirrors `curlx_malloc`, which resolves to plain `malloc` outside a libcurl
/// build at `lib/curl_setup.h:L1481`. `lib/urlapi.c` never calls it directly;
/// it reaches it through `curlx_strdup`, `curlx_memdup0` and
/// `curl_maprintf`, which is the same relationship the helpers below have
/// with it.
///
/// # Ownership
///
/// The caller owns the returned block and must release it with [`c_free`], or
/// hand it to C, which then owes a `curl_free()` on it. Nothing else tracks
/// it. The block is uninitialized: read it only after writing it. Prefer
/// [`CBlock::alloc`], which tracks how much of the block has been written and
/// whose release cannot be forgotten.
///
/// # Returns
///
/// A null pointer if the allocation fails, and never a panic, so this is
/// usable on any error path.
///
/// A request for zero bytes also returns null, deterministically. C leaves
/// `malloc(0)` unspecified, free to return either null or a unique pointer
/// that must still be freed, and a caller cannot tell which happened from the
/// return value alone. curl takes the same view: `curl_dbg_malloc` carries
/// `DEBUGASSERT(wantedsize != 0)`. No call site in this crate ever asks for
/// zero, because every string allocation is a length plus one for the
/// terminator, so the case only arises from a bug and is reported as a
/// failure.
///
/// A request above [`MAX_ALLOC`] returns null too, for the reason recorded on
/// that constant: such a block could never be viewed as a slice, so it is
/// refused here rather than handed out and mishandled later.
#[must_use = "the caller owns this block; discarding it leaks memory"]
pub(crate) fn c_malloc(size: usize) -> *mut c_void {
    if size == 0 || size > MAX_ALLOC {
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
/// Mirrors `curlx_calloc`, which resolves to plain `calloc` outside a libcurl
/// build at `lib/curl_setup.h:L1482`. Used twice in the C module, both times
/// for the handle itself: `curl_url()` at `lib/urlapi.c:L1290` and
/// `curl_url_dup()` at `L1312`.
///
/// The zeroing is load-bearing rather than tidy. `struct Curl_URL` has ten
/// string pointers plus `portnum`, `query_present`, `fragment_present` and
/// `guessed_scheme`, and every one of those fields is read before it is ever
/// written on some path. The C code never initializes them explicitly: it
/// relies on `calloc` for null, zero and false throughout, which is also what
/// makes the parse-into-a-temporary-and-swap idiom at
/// `lib/urlapi.c:L1197-L1209` safe.
///
/// # Ownership
///
/// The caller owns the returned block and must release it with [`c_free`].
///
/// # Returns
///
/// A null pointer if the allocation fails, if either argument is zero, or if
/// `nmemb * size` would overflow `usize`. The overflow case is checked here
/// rather than left to the platform: `calloc` is required to detect it too,
/// but checking makes the guarantee local and visible, and it keeps the
/// computation clear of the crate's arithmetic lint.
#[must_use = "the caller owns this block; discarding it leaks memory"]
pub(crate) fn c_calloc(nmemb: usize, size: usize) -> *mut c_void {
    if nmemb == 0 || size == 0 {
        return ptr::null_mut();
    }
    // The product is both the overflow check the platform also performs and
    // the [`MAX_ALLOC`] bound: a block larger than `isize::MAX` could not be
    // viewed as a slice, so it is refused rather than allocated.
    match nmemb.checked_mul(size) {
        Some(total) if total <= MAX_ALLOC => {}
        _ => return ptr::null_mut(),
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
/// directly. It is here for [`CBlock::resize`], which reproduces the growth
/// step of `dyn_nappend()` in `lib/curlx/dynbuf.c`, and that is the only
/// caller it needs.
///
/// # Ownership
///
/// On success ownership moves from `p` to the returned pointer, and `p` must
/// not be used or freed again. On failure, that is a null return, ownership
/// stays with `p` exactly as C's `realloc` specifies, and the caller still
/// owes a [`c_free`] on it. Getting that backwards is the classic `realloc`
/// leak, so it is stated here rather than assumed.
///
/// # Returns
///
/// A null pointer if the reallocation fails, if `size` is zero, or if `size`
/// exceeds [`MAX_ALLOC`]. The zero case is rejected rather than forwarded
/// because C's answer to `realloc(p, 0)` is implementation-defined, and in the
/// reading where it frees `p` and returns null the caller cannot distinguish
/// that from a failure that left `p` alive. Rejecting it keeps the failure
/// contract above unambiguous: a null return always means `p` is untouched.
///
/// The [`MAX_ALLOC`] ceiling is the same one [`c_malloc`] and [`c_calloc`]
/// apply, and it is applied here for the same reason and so that every raw
/// entry point in this module agrees on what a representable block is: a block
/// larger than `isize::MAX` can never be viewed as a Rust slice, so accepting
/// one would only defer the failure to the first use of the result. Refusing it
/// here also leaves the old block intact, which is the outcome the caller can
/// actually recover from.
///
/// # Safety
///
/// `p` must either be null or point to a block currently owned by the caller
/// that came from [`c_malloc`], [`c_calloc`] or an earlier successful
/// `c_realloc`, and that has not already been freed. Passing a pointer from
/// any other allocator, or one that has been freed, or one obtained from C
/// when the two sides do not share an allocator, is undefined behavior.
#[must_use = "discarding this leaks the new block and loses the old"]
pub(crate) unsafe fn c_realloc(p: *mut c_void, size: usize) -> *mut c_void {
    if size == 0 || size > MAX_ALLOC {
        return ptr::null_mut();
    }
    // SAFETY: the caller guarantees, per the contract above, that `p` is null
    // or a live block from this module's allocator, which is exactly
    // `libc::realloc`'s precondition. `size` is nonzero by the guard, so the
    // implementation-defined `realloc(p, 0)` case is never reached. A null
    // return leaves the original block owned by the caller, which the
    // documentation states, and this function performs no cleanup of its own
    // so no double free is possible here.
    unsafe { libc::realloc(p, size) }
}

/// Releases a block previously produced by this module.
///
/// Mirrors `curlx_free`, which resolves to plain `free` outside a libcurl
/// build at `lib/curl_setup.h:L1484`. This is the single deallocation point
/// for the whole crate; the module documentation traces where the *other* two
/// resolutions of that macro lead, and why neither is supported.
///
/// # Ownership
///
/// Ownership ends here. After this call `p` is dangling and must not be read,
/// written, freed or compared against a live pointer.
///
/// A null pointer is a no-op. C already guarantees that for `free`, and the
/// guard below states it locally so that an auditor does not have to take the
/// C library's word for it. The C module leans on the same property in the
/// other direction, guarding explicitly at `lib/urlapi.c:L1295` before
/// tearing a handle down.
///
/// This is also the function that `Curl_safefree`, the macro at
/// `lib/curl_setup.h:L1319-L1323`, wraps: it frees and then nulls the
/// variable, so a later path cannot reuse it. In this crate the equivalent is
/// holding a `crate::alloc::CBuf` in an `Option` and setting it to `None`,
/// which frees and clears in one move and, unlike the macro, cannot be
/// forgotten.
///
/// # Safety
///
/// `p` must either be null or point to a block currently owned by the caller
/// that came from [`c_malloc`], [`c_calloc`], [`c_realloc`] or one of the
/// string helpers built on them, and that has not already been freed. Freeing
/// a pointer from a different allocator, or freeing twice, is undefined
/// behavior. In particular, and this is the reason `CString::into_raw` is
/// banned crate-wide, a pointer whose memory belongs to the Rust allocator
/// must never reach this function.
pub(crate) unsafe fn c_free(p: *mut c_void) {
    if p.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `p` is a live block from this module's
    // allocator that has not been freed, which is `libc::free`'s
    // precondition; the guard above has already removed the null case, so the
    // only pointers reaching the call are ones the contract covers.
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
/// The feature exists because the symbol cannot be defined unconditionally.
/// In the drop-in configuration a real libcurl already defines `curl_free` in
/// the object built from `lib/escape.c`, and a second definition in this
/// crate's archive turns a clean link into a duplicate-symbol link. In the
/// standalone configuration nothing else supplies it, yet the documented
/// contract that a buffer from `curl_url_get()` is released with
/// `curl_free()` still has to hold, so the crate provides it. Hence a feature
/// rather than a fixed choice.
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
    // SAFETY: this function's contract is `c_free`'s contract verbatim, so the
    // caller has already established the precondition; forwarding adds no
    // requirement of its own. The C original at lib/escape.c:L189-L192 is the
    // same single forwarding call.
    unsafe { c_free(p) }
}

/// An owned block of C-allocator memory with a wholly safe surface.
///
/// This is the type that lets the rest of the crate be `unsafe`-free. It owns
/// a block from the C allocator and presents it as an ordinary byte slice, so
/// `crate::alloc::CBuf` and `crate::dynbuf::DynBuf` are built out of slice
/// operations the compiler checks rather than out of pointer arithmetic a
/// reader has to check.
///
/// # Invariants
///
/// Every live value satisfies all five of the following, and every method
/// below both assumes and re-establishes them:
///
/// 1. `ptr` is non-null and points at a block from this module's allocator
///    that this value alone owns.
/// 2. `cap` is at least 1 and is exactly the size of that block.
/// 3. `init` is at most `cap`.
/// 4. **The `init` bytes `[0, init)` are initialized.** Nothing is promised
///    about `[init, cap)`. This is the invariant that makes
///    [`CBlock::bytes`] and [`CBlock::bytes_mut`] sound, and it is why those
///    two return a slice of `init` bytes rather than of `cap` bytes.
/// 5. `Drop` is the only release, unless [`CBlock::into_raw`] moved the
///    obligation to C first.
///
/// # Why an initialized prefix rather than a zeroed block
///
/// Forming a `&[u8]` or `&mut [u8]` over uninitialized memory is undefined
/// behavior, whether or not the reference is read. There are two ways to
/// avoid it: zero the whole capacity up front, or track how much of it has
/// been written and hand out only that much. This type does the second,
/// because the first is not what the C does.
///
/// `curlx_memdup0` at `lib/curlx/strdup.c:L85-L96` calls `malloc`, copies the
/// live bytes and writes one terminator. `dyn_nappend()` at
/// `lib/curlx/dynbuf.c:L104-L117` calls `realloc`, copies the appended bytes
/// and writes one terminator; everything above the content stays
/// uninitialized. Zeroing the capacity instead would add a write of every
/// byte of every allocation and of every newly exposed byte of every growth
/// -- writes the original never performs, on memory no reader can observe.
/// The plan puts correctness before performance at 0.8.5, and this
/// arrangement gives up neither: the prefix is tracked in one field, the two
/// slice faces are bounded by it, and the only way to extend it is
/// [`CBlock::put`], [`CBlock::put_byte`] or [`CBlock::push`], each of which
/// writes the bytes it accounts for.
///
/// The one place C does zero is the handle allocation, `calloc` at
/// `lib/urlapi.c:L1290` and `L1312`, and that path does not go through this
/// type at all: it is [`c_calloc`] in `new_handle`, which is where the port
/// keeps it so the allocator calls `tests/data/test1560` counts stay the
/// same.
///
/// # Ownership
///
/// Rust owns the block. `Drop` releases it, so a value that never reaches
/// [`CBlock::into_raw`] cannot leak, which is what removes the failure-path
/// leak class the C original carries at `FB2` and `FB3` in
/// `docs/KNOWN-DIVERGENCES.md`. There is deliberately no method that yields a
/// `*mut c_char` while keeping ownership, because such a method is an
/// invitation to a double free.
pub(crate) struct CBlock {
    /// Start of the C-allocator block. Non-null for every live value.
    ptr: *mut c_char,
    /// Size of the whole block in bytes. At least 1.
    cap: usize,
    /// Length of the initialized prefix. Bytes `[0, init)` are initialized;
    /// bytes `[init, cap)` may not be. At most `cap`.
    init: usize,
}

impl CBlock {
    /// Allocates `cap` bytes, none of them initialized.
    ///
    /// `malloc`, which is what `curlx_memdup0` and `dyn_nappend()` use. The
    /// block starts with an empty initialized prefix, so
    /// [`CBlock::bytes`] returns an empty slice until something is written
    /// through [`CBlock::put`], [`CBlock::put_byte`] or [`CBlock::push`].
    ///
    /// # Returns
    ///
    /// `None` if `cap` is zero or the allocation fails. A zero capacity is
    /// refused rather than turned into a one-byte block, because invariant 2
    /// would then be a lie about what the caller asked for; callers that want
    /// room for a terminator ask for it explicitly.
    #[must_use]
    pub(crate) fn alloc(cap: usize) -> Option<Self> {
        // `c_malloc` already refuses zero and anything above `MAX_ALLOC`; the
        // test is repeated here so the guarantee is local to this function
        // rather than inherited from a helper a reader has to go and check.
        if cap == 0 || cap > MAX_ALLOC {
            return None;
        }
        let raw = c_malloc(cap);
        if raw.is_null() {
            return None;
        }
        Some(Self {
            ptr: raw.cast::<c_char>(),
            cap,
            init: 0,
        })
    }

    /// The size of the block in bytes, terminator slot and spare included.
    #[must_use]
    pub(crate) const fn capacity(&self) -> usize {
        self.cap
    }

    /// The length of the initialized prefix, which is also the length of the
    /// slices [`CBlock::bytes`] and [`CBlock::bytes_mut`] return.
    #[must_use]
    pub(crate) const fn initialized(&self) -> usize {
        self.init
    }

    /// The initialized prefix, borrowed immutably.
    ///
    /// # Ownership
    ///
    /// **Nothing changes hands.** The lifetime is tied to `&self`, so the
    /// slice cannot outlive the block and no mutation can happen while it
    /// lives.
    #[must_use]
    pub(crate) fn bytes(&self) -> &[u8] {
        // SAFETY: invariant 1 gives a non-null pointer to a live block,
        // invariants 2 and 3 put `self.init` bytes inside that block, and
        // invariant 4 says every one of them is initialized, so the slice
        // lies inside the allocation and reads only initialized memory. `u8`
        // has an alignment of one, which any pointer satisfies. The lifetime
        // is tied to `&self`, so the slice cannot outlive the block and the
        // borrow checker rules out a concurrent mutable view.
        unsafe { slice::from_raw_parts(self.ptr.cast::<u8>(), self.init) }
    }

    /// The initialized prefix, borrowed mutably.
    ///
    /// Editing in place is all this permits; it cannot grow the prefix, which
    /// is what keeps invariant 4 true no matter what a caller does with the
    /// slice. Use [`CBlock::put`], [`CBlock::put_byte`] or [`CBlock::push`]
    /// to write bytes above it.
    ///
    /// # Ownership
    ///
    /// **Nothing changes hands.** The result is a unique borrow, so no other
    /// reference to these bytes can exist while it is held, and the obligation
    /// to release the block stays with this value.
    #[must_use]
    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: the reasoning of `bytes`, with a unique borrow. `&mut self`
        // guarantees no other reference to these bytes exists, so handing out
        // a `&mut [u8]` over them creates no aliasing, and invariant 4 lets
        // the caller read as well as write every byte in range.
        unsafe { slice::from_raw_parts_mut(self.ptr.cast::<u8>(), self.init) }
    }

    /// Copies `src` into the block at `offset`, extending the initialized
    /// prefix to cover it.
    ///
    /// The `memcpy` of `curlx_memdup0` at `lib/curlx/strdup.c:L93` and of
    /// `dyn_nappend()` at `lib/curlx/dynbuf.c:L115`, with the two conditions
    /// that keep this type's invariants explicit rather than assumed.
    ///
    /// # Returns
    ///
    /// `true` when the bytes were written. `false`, with **nothing written at
    /// all**, when either condition fails:
    ///
    /// * `offset` is above the initialized prefix. Writing there would leave
    ///   a gap of uninitialized bytes below the new content, and no single
    ///   length could then describe what is initialized. Every caller in this
    ///   crate appends at the prefix or overwrites inside it, so this is a
    ///   bug check rather than a case to handle.
    /// * the copy would run past the capacity, or its end is not
    ///   representable.
    ///
    /// Reported rather than asserted, because this crate has no panic path.
    pub(crate) fn put(&mut self, offset: usize, src: &[u8]) -> bool {
        if offset > self.init {
            return false;
        }
        let Some(end) = offset.checked_add(src.len()) else {
            return false;
        };
        if end > self.cap {
            return false;
        }
        if src.is_empty() {
            // C skips a zero-length copy too, `lib/curlx/dynbuf.c:L114`.
            // Nothing is written, so the prefix does not move.
            return true;
        }
        // SAFETY: `src` is a live slice of `src.len()` bytes, so it is valid
        // for that many reads. The destination is `self.ptr` advanced by
        // `offset`, and `end <= self.cap` puts the whole written range inside
        // the block invariants 1 and 2 describe, so it is valid for that many
        // writes. The two cannot overlap: `src` is a Rust slice the caller
        // holds and this block is owned exclusively through `&mut self`, and
        // any borrow of it would have to come from `bytes`/`bytes_mut`, whose
        // lifetimes the borrow checker ties to that same `&mut self`. `u8`
        // has an alignment of one, so both pointers are aligned. The offset
        // arithmetic stays in bounds by the same `end <= self.cap` test.
        unsafe {
            ptr::copy_nonoverlapping(src.as_ptr(), self.ptr.cast::<u8>().add(offset), src.len());
        }
        if end > self.init {
            // The copy initialized `[offset, end)` and `offset <= self.init`,
            // so `[0, end)` is now contiguous and invariant 4 holds for the
            // wider prefix.
            self.init = end;
        }
        true
    }

    /// Writes one byte at `offset`, extending the initialized prefix to cover
    /// it.
    ///
    /// The terminator write: `s->bufr[s->leng] = 0` at
    /// `lib/curlx/dynbuf.c:L117` and `L290`, and `dest[length] = 0` at
    /// `lib/curlx/strdup.c:L94`.
    ///
    /// # Returns
    ///
    /// As [`CBlock::put`]: `false`, with nothing written, when `offset` is
    /// above the initialized prefix or at or past the capacity.
    pub(crate) fn put_byte(&mut self, offset: usize, byte: u8) -> bool {
        self.put(offset, &[byte])
    }

    /// Appends one byte at the end of the initialized prefix.
    ///
    /// The `*ns++ = (char)in` of `Curl_urldecode` at `lib/escape.c:L145`,
    /// where the destination is written straight through with no separate
    /// index to keep in step. Exactly one byte is written per call and
    /// nothing else is touched.
    ///
    /// # Returns
    ///
    /// `false`, with nothing written, when the block is full.
    pub(crate) fn push(&mut self, byte: u8) -> bool {
        self.put(self.init, &[byte])
    }

    /// Resizes the block, without initializing anything new.
    ///
    /// The growth step of `dyn_nappend()` at `lib/curlx/dynbuf.c:L104-L112`,
    /// which is a bare `realloc`: the bytes above the old capacity are
    /// uninitialized afterwards, and this type says so by leaving `init`
    /// where it was. A shrink below the prefix truncates the prefix, because
    /// bytes outside the block cannot be initialized.
    ///
    /// # Why the new tail is neither zeroed nor reachable
    ///
    /// `realloc` grows a block by handing back memory whose new tail holds
    /// *uninitialized* bytes, and a `&[u8]` or `&mut [u8]` may never be formed
    /// over uninitialized memory: the slice contract requires every element to
    /// be initialized, and `MaybeUninit`'s own documentation spells out that
    /// constructing an ordinary reference to an uninitialized value is
    /// undefined behavior on its own, before anything reads or writes through
    /// it. That hazard is answered by the `init` prefix rather than by a fill.
    /// [`CBlock::bytes`] and [`CBlock::bytes_mut`] expose `[0, init)` and
    /// nothing beyond it, and only [`CBlock::put`] -- which writes through a
    /// raw pointer and then extends `init` by exactly the bytes it copied --
    /// can move that boundary. So no slice over this block can reach the tail
    /// `realloc` just produced, and clearing it would be both unnecessary and
    /// a departure from `dyn_nappend()`, which writes each byte exactly once.
    ///
    /// # Ownership
    ///
    /// On success the old block is gone and this value owns the new one; on
    /// failure the old block is untouched and still owned here, which is
    /// exactly C's `realloc` contract and is why a failed growth in
    /// `crate::dynbuf` can still free the buffer safely afterwards.
    ///
    /// # Returns
    ///
    /// `false`, with nothing changed, if `new_cap` is zero or the
    /// reallocation fails.
    pub(crate) fn resize(&mut self, new_cap: usize) -> bool {
        // [`MAX_ALLOC`] again: growth past the representable bound is refused
        // here rather than discovered when the block is next viewed as a
        // slice, and the caller reads it as an allocation failure.
        if new_cap == 0 || new_cap > MAX_ALLOC {
            return false;
        }
        if new_cap == self.cap {
            return true;
        }
        // SAFETY: `c_realloc` requires a pointer that is null or a live block
        // from this module's allocator owned by the caller, which is invariant
        // 1, and a nonzero size, which the guard above establishes. On success
        // ownership moves to the new pointer and the old one is not touched
        // again; on failure the old block stays owned by this value, so the
        // early return below leaves every invariant as it found them.
        // `realloc` preserves the bytes up to the smaller of the two sizes,
        // which is what lets the prefix survive a growth untouched.
        let fresh = unsafe { c_realloc(self.ptr.cast::<c_void>(), new_cap) };
        if fresh.is_null() {
            return false;
        }
        // The new extent is deliberately left as `realloc` returned it. `init`
        // stays where it was, so `bytes()` and `bytes_mut()` continue to end at
        // the old prefix and no reference can be formed over the uninitialized
        // tail; the bytes above it become reachable only as `put` writes them.
        self.ptr = fresh.cast::<c_char>();
        self.cap = new_cap;
        if self.init > new_cap {
            // Invariant 3 after a shrink: the bytes that are gone cannot be
            // described as initialized. No call site in this crate shrinks
            // below its own content -- `crate::alloc` shrinks a block to
            // exactly `len + 1` -- so this is a bound rather than a case.
            self.init = new_cap;
        }
        true
    }

    /// Hands the block over as a bare pointer, relinquishing ownership.
    ///
    /// # Ownership
    ///
    /// **Ownership moves to the caller**, and the whole obligation moves with
    /// it:
    ///
    /// * The C side must release it with `curl_free()`, per
    ///   `docs/libcurl/curl_url_get.md:L45` and
    ///   `include/curl/urlapi.h:L130-L131`. That call is correct because the
    ///   block came from the C allocator; the module documentation traces the
    ///   resolution chain and the two configurations it does not support.
    /// * `curl_url_cleanup()` will *not* release it, per
    ///   `include/curl/urlapi.h:L116-L118`.
    /// * Rust code that wants the obligation back must call
    ///   [`CBlock::from_raw`] or [`CBlock::from_raw_parts`]. Keeping the
    ///   pointer around leaks it; building two owners over it frees it twice.
    ///
    /// `Drop` is suppressed with `ManuallyDrop` rather than merely skipped, so
    /// the suppression is visible at the type level. The returned pointer is
    /// never null.
    #[must_use = "ownership moves to the caller; discarding this leaks"]
    pub(crate) fn into_raw(self) -> *mut c_char {
        let kept = mem::ManuallyDrop::new(self);
        kept.ptr
    }

    /// Takes ownership of a NUL-terminated C string, measuring it.
    ///
    /// The capacity of the result is the measured length plus one, and the
    /// initialized prefix is the whole of it: the string's bytes plus its
    /// terminator are exactly what the measurement proves initialized, so
    /// invariant 4 holds over the entire block.
    ///
    /// # Ownership
    ///
    /// Ownership moves *into* the returned value. The caller must not free `p`
    /// afterwards and must not keep using it: `Drop` is now the one and only
    /// release.
    ///
    /// # Returns
    ///
    /// `None` if `p` is null, which lets an allocation failure from C be
    /// forwarded without a separate check at the call site. `None` also if the
    /// measured length plus its terminator would exceed [`MAX_ALLOC`], the same
    /// bound [`CBlock::alloc`] and [`CBlock::from_raw_parts`] enforce; as
    /// there, the block then stays the caller's, which is what the `Option`
    /// says. That outcome is unreachable for a string that really lives in one
    /// allocation, and the check is present so that every entry point into this
    /// type agrees on what a representable capacity is rather than one of them
    /// recording a capacity its own accessors could never view as a slice.
    ///
    /// # Safety
    ///
    /// `p` must be a pointer this crate is entitled to free, that is one from
    /// [`c_malloc`], [`c_calloc`], [`c_realloc`] or one of the string helpers
    /// built on them, or null. It must be NUL-terminated, since the length is
    /// measured with `strlen`, and no other owner may release it. A pointer
    /// that came from a different allocator, notably from Rust's, must never
    /// be passed here.
    #[must_use = "discarding the value frees the block immediately"]
    pub(crate) unsafe fn from_raw(p: *mut c_char) -> Option<(Self, usize)> {
        if p.is_null() {
            return None;
        }
        // SAFETY: the caller guarantees `p` points to a live, NUL-terminated C
        // string, which is exactly `strlen`'s precondition. The value it
        // returns is the index of that terminator, so the block is at least
        // `len + 1` bytes.
        let len = unsafe { libc::strlen(p) };
        // Exact: `strlen` returned an index inside a live allocation, so it
        // cannot be `usize::MAX`. Written as a checked addition because the
        // crate denies the bare operators.
        let cap = len.checked_add(1)?;
        // `MAX_ALLOC` bounds every other raw entry point of this type, so it
        // bounds adoption too: a block this crate would refuse to allocate is a
        // block it refuses to take ownership of, which keeps the ceiling a
        // property of the type rather than of one constructor.
        if cap > MAX_ALLOC {
            return None;
        }
        Some((
            Self {
                ptr: p,
                cap,
                init: cap,
            },
            len,
        ))
    }

    /// Takes ownership of a C-allocator block of a known size.
    ///
    /// The counterpart to [`CBlock::from_raw`] for a block whose size the
    /// caller already knows, so no `strlen` is needed and an interior zero
    /// byte does not shorten the result.
    ///
    /// # Ownership
    ///
    /// As for [`CBlock::from_raw`]: ownership moves in, and `Drop` becomes the
    /// only release.
    ///
    /// # Returns
    ///
    /// `None` if `p` is null or `cap` is zero.
    ///
    /// # Safety
    ///
    /// `p` must be null, or a block this crate may free of at least `cap`
    /// bytes, all of them initialized, with no other owner. The provenance
    /// requirement is [`CBlock::from_raw`]'s verbatim.
    #[must_use = "discarding the value frees the block immediately"]
    pub(crate) unsafe fn from_raw_parts(p: *mut c_char, cap: usize) -> Option<Self> {
        // A capacity past [`MAX_ALLOC`] cannot describe a block Rust is able
        // to view as a slice, so the claim is rejected rather than recorded.
        // The block stays the caller's, which is what the `Option` says.
        if p.is_null() || cap == 0 || cap > MAX_ALLOC {
            return None;
        }
        // The caller's guarantee is the whole of the safety argument here;
        // there is no operation to perform, only a claim to record. Invariant
        // 1 is the provenance, invariant 2 the size, invariant 4 the
        // initialization -- which is why the prefix is recorded as the whole
        // capacity, the caller having promised exactly that -- and invariant 5
        // the sole ownership.
        Some(Self {
            ptr: p,
            cap,
            init: cap,
        })
    }
}

impl Drop for CBlock {
    /// Releases the block, replacing the C module's manual teardown.
    ///
    /// This one implementation stands in for `free_urlhandle()` at
    /// `lib/urlapi.c:L86-L98`, which frees ten fields by hand, and for the
    /// roughly thirty other `curlx_free()` calls scattered through the
    /// module's error paths.
    fn drop(&mut self) {
        // SAFETY: invariant 1 says `self.ptr` is a live block from the C
        // allocator that this value alone owns, which is `c_free`'s
        // precondition. `Drop` runs at most once per value, and `into_raw` is
        // the only other way out of the type and suppresses this call, so the
        // block is released exactly once and never after being given away.
        unsafe { c_free(self.ptr.cast::<c_void>()) };
    }
}

impl fmt::Debug for CBlock {
    /// Prints the capacity and the initialized prefix length only.
    ///
    /// The contents are deliberately not shown. A `CBlock` is a raw extent
    /// whose meaningful prefix only its owner knows, and
    /// `crate::alloc::CBuf`'s own `Debug` prints that prefix with
    /// non-printable bytes escaped.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CBlock(cap {}, init {})", self.cap, self.init)
    }
}

/// Duplicates a NUL-terminated C string into a fresh C-allocator block.
///
/// Mirrors `curlx_strdup`, `lib/curlx/strdup.c`, in the shape the C uses at
/// `lib/urlapi.c:L418`, `L815`, `L977`, `L1004` and `L1304`: a `char *` in, a
/// `char *` out, null meaning failure.
///
/// # Ownership
///
/// **The caller owns the returned pointer** and must release it with
/// [`c_free`], or hand it to C, which then owes a `curl_free()` on it. `src`
/// is only read and is not consumed.
///
/// # Returns
///
/// A null pointer if `src` is null or the allocation fails.
///
/// # Safety
///
/// `src` must be null or point at a NUL-terminated string that stays readable
/// for the duration of the call.
#[must_use = "the caller owns this string; discarding it leaks memory"]
pub(crate) unsafe fn c_strdup_raw(src: *const c_char) -> *mut c_char {
    if src.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the caller guarantees `src` is a live, NUL-terminated string,
    // which is `strlen`'s precondition; the null case has already returned.
    let len = unsafe { libc::strlen(src) };
    // SAFETY: `len` is the index of `src`'s terminator, so `len` bytes from
    // `src` are readable, which is exactly what `c_memdup0` requires.
    unsafe { c_memdup0(src, len) }
}

/// Duplicates `len` bytes as a NUL-terminated C string.
///
/// Mirrors `curlx_memdup0`, `lib/curlx/strdup.c:L85-L96`, in the shape the C
/// uses at `lib/urlapi.c:L1028`, `L1052`, `L1086` and `L1367`: exactly `len`
/// bytes are copied and a terminator is appended, which is how curl duplicates
/// a *slice* of a larger string.
///
/// # Ownership
///
/// **The caller owns the returned pointer**, exactly as for [`c_strdup_raw`].
///
/// # Returns
///
/// A null pointer if the allocation fails, or if `len + 1` would overflow
/// `usize`, which is this port's spelling of the `length < SIZE_MAX` guard at
/// `lib/curlx/strdup.c:L87`. A null `src` with a nonzero `len` also yields
/// null; a null `src` with `len` zero yields a one-byte block holding just the
/// terminator, because an empty string has to be representable.
///
/// # Safety
///
/// `src` must point at `len` readable, initialized bytes, or be null when
/// `len` is zero. No terminator is required or assumed.
#[must_use = "the caller owns this string; discarding it leaks memory"]
pub(crate) unsafe fn c_memdup0(src: *const c_char, len: usize) -> *mut c_char {
    if src.is_null() && len != 0 {
        return ptr::null_mut();
    }
    let Some(total) = len.checked_add(1) else {
        return ptr::null_mut();
    };
    // `malloc`, as `curlx_memdup0` uses at `lib/curlx/strdup.c:L89`. The
    // block is uninitialized here and the two writes below initialize exactly
    // the bytes the C writes: `len` copied bytes and one terminator.
    let Some(mut block) = CBlock::alloc(total) else {
        return ptr::null_mut();
    };
    if len != 0 {
        // SAFETY: the caller guarantees `src` points at `len` readable,
        // initialized bytes; the null-with-nonzero-length case has already
        // returned. The destination is a fresh block of `len + 1` bytes that
        // nothing else references, so the two regions cannot overlap, and
        // `u8` has an alignment of one.
        let source = unsafe { slice::from_raw_parts(src.cast::<u8>(), len) };
        // The `memcpy` at `lib/curlx/strdup.c:L93`. Infallible: the block is
        // `len + 1` bytes and the prefix starts empty, so the offset of zero
        // is at the prefix and the end is inside the capacity. Reported rather
        // than asserted, because this crate has no panic path.
        if !block.put(0, source) {
            return ptr::null_mut();
        }
    }
    // The terminator at `[len]`, which is `dest[length] = 0` at
    // `lib/curlx/strdup.c:L94`. It is written rather than inherited from a
    // zeroed allocation, so the block above the terminator stays untouched,
    // exactly as the C leaves it. Infallible for the same reason as the copy:
    // `len` is now the prefix length and `len < total`.
    if !block.put_byte(len, 0) {
        return ptr::null_mut();
    }
    block.into_raw()
}

/// Adopts a NUL-terminated C string as an owned [`CBuf`].
///
/// The inverse of `crate::alloc::CBuf::into_raw`, and the pair is meant to be
/// read together: `into_raw` gives a pointer away, this takes one back so that
/// Rust owes the free again instead of C.
///
/// # Ownership
///
/// Ownership moves *into* the returned value. The caller must not free `p`
/// afterwards and must not keep using it.
///
/// # Returns
///
/// `None` if `p` is null, which lets an allocation failure from C be forwarded
/// without a separate check at the call site.
///
/// # Safety
///
/// [`CBlock::from_raw`]'s contract verbatim.
#[must_use = "discarding the value frees the block immediately"]
pub(crate) unsafe fn adopt_c_string(p: *mut c_char) -> Option<CBuf> {
    // SAFETY: the caller's guarantee is `CBlock::from_raw`'s precondition and
    // is forwarded unchanged.
    let (block, len) = unsafe { CBlock::from_raw(p) }?;
    CBuf::from_block(block, len)
}

/// Adopts a C-allocator block of a known content length as an owned [`CBuf`].
///
/// The counterpart to [`adopt_c_string`] for a block whose content length the
/// caller already knows, so no `strlen` is needed and an interior zero byte
/// does not shorten the result. The block must have room for the terminator at
/// `[len]`, that is at least `len + 1` bytes.
///
/// # Ownership
///
/// As for [`adopt_c_string`].
///
/// # Returns
///
/// `None` if `p` is null or `len + 1` would overflow `usize`.
///
/// # Safety
///
/// `p` must be null, or a block this crate may free of at least `len + 1`
/// initialized bytes, with no other owner.
#[must_use = "discarding the value frees the block immediately"]
pub(crate) unsafe fn adopt_c_bytes(p: *mut c_char, len: usize) -> Option<CBuf> {
    let cap = len.checked_add(1)?;
    // SAFETY: the caller guarantees at least `len + 1` initialized bytes with
    // this crate's provenance and no other owner, which is
    // `CBlock::from_raw_parts`' precondition for a capacity of `cap`.
    let block = unsafe { CBlock::from_raw_parts(p, cap) }?;
    CBuf::from_block(block, len)
}

// ==========================================================================
// Section 2 -- the platform address conversion
// ==========================================================================

/// The platform's `inet_pton` and `inet_ntop`, which is what the reference
/// build's `curlx_inet_pton` and `curlx_inet_ntop` macros expand to.
///
/// `src/inet.rs` owns the interface -- the two entry points, the address-family
/// and result constants, and the choice between this backend and curl's own
/// ported one -- and this module owns the call. The surface presented back to
/// it is entirely safe: the two functions below take slices and arrays,
/// validate every precondition the C prototypes impose, and confine each
/// `unsafe` block to the call itself, so `src/inet.rs`, `src/parse/ipv6.rs`
/// and `src/parse/host.rs` need none of their own.
#[cfg(any(have_inet_pton, have_inet_ntop))]
pub(crate) mod inet_sys {
    use libc::{c_char, c_int, c_void, socklen_t};

    use crate::inet::{ADDRSZ_IPV4, ADDRSZ_IPV6, AF_INET, AF_INET6};
    use crate::inet::{PTON_ERROR, PTON_INVALID, TEXT_MAX};

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
    // spelled as method calls. The allow is the same deliberate, scoped
    // exception `src/inet.rs` explains and measures at its own constant block.
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
    pub(crate) fn pton(af: c_int, src: &[u8], dst: &mut [u8; ADDRSZ_IPV6]) -> c_int {
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
    pub(crate) fn ntop(af: c_int, src: &[u8], dst: &mut [u8]) -> Option<usize> {
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

// ==========================================================================
// Section 3 -- the libidn2 binding
// ==========================================================================

/// The default internationalised-domain backend: libidn2, bound directly.
///
/// This module stands in for the `USE_LIBIDN2` arms of `lib/idn.c`, which are
/// the `#include <idn2.h>` at L33, the `IDN2_LOOKUP` macro at L35-L41, the
/// `USE_LIBIDN2` body of `idn_decode` at L251-L271, the whole of `idn_encode`
/// at L285-L288, and the re-duplication blocks at L306-L315 and L331-L340.
///
/// `src/idn.rs` owns the interface -- the two public conversions, the two
/// `CURLUcode` folds, the ASCII gate, the pure-Rust alternative and the choice
/// between backends -- and this module owns the calls. Every `unsafe` block
/// below is a call into libidn2 or a read of memory libidn2 returned, and each
/// carries the invariant it relies on. What leaves the module is a
/// `crate::alloc::CBuf` and a `crate::error::CURLcode`, so `src/idn.rs` and
/// `src/getset.rs` never see a raw pointer.
///
/// `rust-urlapi/build.rs` emits `cargo:rustc-link-lib=idn2` for this
/// configuration, so nothing here has to arrange the link.
#[cfg(idn_backend_libidn2)]
pub(crate) mod idn2 {
    use core::ptr;
    use core::slice;
    use libc::{c_char, c_int, c_void};

    use crate::alloc::CBuf;
    use crate::error::CURLcode;

    /// `IDN2_OK`, `idn2.h`. The success value of every entry point here.
    const IDN2_OK: c_int = 0;

    /// `IDN2_MALLOC`, `idn2.h`. libidn2 could not allocate.
    const IDN2_MALLOC: c_int = -100;

    /// `IDN2_NFC_INPUT`, `idn2.h`: normalise the input to normalisation form
    /// C. Requested at `lib/idn.c` L253.
    const IDN2_NFC_INPUT: c_int = 1;

    /// `IDN2_TRANSITIONAL`, `idn2.h`: Unicode TR46 transitional processing.
    /// The retry at `lib/idn.c` L265 passes this **alone**, dropping
    /// `IDN2_NFC_INPUT` along with everything else.
    const IDN2_TRANSITIONAL: c_int = 4;

    /// `IDN2_NONTRANSITIONAL`, `idn2.h`: Unicode TR46 non-transitional
    /// processing. Added at `lib/idn.c` L258.
    const IDN2_NONTRANSITIONAL: c_int = 8;

    /// `IDNA_SUCCESS`, `idn2.h`, which that header defines as `IDN2_OK`.
    ///
    /// `idn_encode` at `lib/idn.c` L287 tests the `IDNA_*` compatibility names
    /// where `idn_decode` tests the `IDN2_*` ones, for the same two values.
    /// Both spellings are kept here, aliased exactly as `idn2.h` aliases them,
    /// so that each call site can be read against the C line it came from.
    const IDNA_SUCCESS: c_int = IDN2_OK;

    /// `IDNA_MALLOC_ERROR`, `idn2.h`, which that header defines as
    /// `IDN2_MALLOC`. Tested at `lib/idn.c` L288.
    const IDNA_MALLOC_ERROR: c_int = IDN2_MALLOC;

    /// The version handed to `idn2_check_version`, NUL terminated.
    ///
    /// `lib/idn.c` L252 passes `IDN2_VERSION`, the version string of the
    /// **header** the C was compiled against, so the guard asks "is the
    /// library at least as new as the header I was built from". That is the
    /// question reproduced here, and it is reproduced literally rather than
    /// approximated: `rust-urlapi/build.rs` locates the `<idn2.h>` this
    /// artifact will link against, reads `IDN2_VERSION` out of it and hands it
    /// over as `CURL_URLAPI_IDN2_VERSION`, so the string below is the same
    /// bytes a C compile of `lib/idn.c` on this host would have baked in.
    ///
    /// The fallback is the floor `build.rs` enforces, and it is unreachable in
    /// a normal build: `build.rs` panics when the header cannot be found, so
    /// the environment variable is always present when the libidn2 backend is
    /// selected. It is written out rather than unwrapped because this crate
    /// denies `unwrap` and because a constant with a stated fallback is easier
    /// to audit than one that cannot fail for reasons stated elsewhere.
    const IDN2_VERSION: &[u8] = match option_env!("CURL_URLAPI_IDN2_VERSION") {
        Some(_) => concat!(env!("CURL_URLAPI_IDN2_VERSION"), "\0").as_bytes(),
        None => b"2.2.0\0",
    };

    /// The same version in the packed form `IDN2_VERSION_NUMBER` uses, which is
    /// what the preprocessor test at `lib/idn.c` L254 compares.
    ///
    /// Read from the same header by `build.rs`, which emits it as
    /// `CURL_URLAPI_IDN2_VERSION_NUMBER` in libidn2's own hexadecimal
    /// spelling: 2.3.8 reports `0x02030008`, and 2.2.0 -- the floor -- is
    /// `0x02020000`.
    const IDN2_VERSION_NUMBER: u32 = match option_env!("CURL_URLAPI_IDN2_VERSION_NUMBER") {
        Some(_) => parse_packed_version(env!("CURL_URLAPI_IDN2_VERSION_NUMBER")),
        None => 0x0202_0000,
    };

    /// The release that introduced `IDN2_NONTRANSITIONAL`, 0.20.0, encoded the
    /// same way. This is the literal the C compares against at `lib/idn.c`
    /// L254.
    const NONTRANSITIONAL_SINCE: u32 = 0x0014_0000;

    /// Read `0x0000_0000`-style hexadecimal at compile time.
    ///
    /// `u32::from_str_radix` is not a `const fn`, so the packed version has to
    /// be decoded by hand to reach a `const`. Anything that is not `0x` plus
    /// one to eight hexadecimal digits collapses to 0, which selects the
    /// single-flag arm below -- the conservative answer, and the same one a C
    /// build against a pre-0.20.0 header takes.
    const fn parse_packed_version(text: &str) -> u32 {
        // Written over a slice pattern rather than by indexing, because the
        // crate denies `clippy::indexing_slicing`: a `const fn` is compiled
        // like any other and is held to the same rule.
        let bytes = text.as_bytes();
        let mut rest = match bytes {
            [b'0', b'x' | b'X', rest @ ..] => rest,
            _ => return 0,
        };
        if rest.is_empty() {
            return 0;
        }
        let mut value: u32 = 0;
        while let [digit, tail @ ..] = rest {
            // `wrapping_sub` and `wrapping_add` rather than the bare
            // operators, because the crate denies arithmetic that could panic.
            // Each is exact: the match arm has already established the byte's
            // range, so the subtraction cannot go below zero and the sum
            // cannot exceed 15.
            let nibble = match *digit {
                b'0'..=b'9' => digit.wrapping_sub(b'0'),
                b'a'..=b'f' => digit.wrapping_sub(b'a').wrapping_add(10),
                b'A'..=b'F' => digit.wrapping_sub(b'A').wrapping_add(10),
                _ => return 0,
            };
            value = match value.checked_mul(16) {
                Some(shifted) => shifted,
                None => return 0,
            };
            value = match value.checked_add(nibble as u32) {
                Some(sum) => sum,
                None => return 0,
            };
            rest = tail;
        }
        value
    }

    /// The flag word of the first lookup, built exactly as `lib/idn.c`
    /// L253-L260 builds it:
    ///
    /// ```c
    /// int flags = IDN2_NFC_INPUT
    /// #if IDN2_VERSION_NUMBER >= 0x00140000
    ///   | IDN2_NONTRANSITIONAL
    /// #endif
    ///   ;
    /// ```
    ///
    /// The conditional is reproduced rather than collapsed into its answer.
    /// With the floor above it selects the two-flag arm, which is what a build
    /// against any libidn2 2.x header also selects, but writing the structure
    /// out keeps the reason visible and keeps a lowered floor honest.
    const LOOKUP_FLAGS: c_int = if IDN2_VERSION_NUMBER >= NONTRANSITIONAL_SINCE {
        IDN2_NFC_INPUT | IDN2_NONTRANSITIONAL
    } else {
        IDN2_NFC_INPUT
    };

    // The declarations from `<idn2.h>`, which `lib/idn.c` L33 includes for
    // exactly these entry points. `libc` does not carry them, so they are
    // written out here; that is the whole of the binding, and no additional
    // crate is involved.
    //
    // The signatures are `idn2.h` verbatim. `idn2_check_version` returns the
    // library's own version string, or null when the requested version is
    // newer than the library, and the C reads only which of the two it got.
    // Both lookup entry points are declared because the C header declares
    // both and the macro at L35-L41 chooses between them per platform.
    extern "C" {
        /// `const char *idn2_check_version(const char *req_version)`.
        fn idn2_check_version(req_version: *const c_char) -> *const c_char;

        /// `int idn2_lookup_ul(const char *src, char **lookupname, int flags)`.
        ///
        /// The **locale-aware** entry point, and so the origin of the locale
        /// trap the module documentation describes. Selected by `lib/idn.c`
        /// L39-L40 on every platform except Windows with wide characters.
        fn idn2_lookup_ul(src: *const c_char, lookupname: *mut *mut c_char, flags: c_int) -> c_int;

        /// `int idn2_lookup_u8(const uint8_t *src, uint8_t **lookupname,
        /// int flags)`.
        ///
        /// The byte-oriented entry point, which reads its input as UTF-8 and
        /// is therefore indifferent to the locale. Selected by `lib/idn.c`
        /// L36-L37 for Windows with wide characters.
        fn idn2_lookup_u8(src: *const u8, lookupname: *mut *mut u8, flags: c_int) -> c_int;

        /// `int idn2_to_unicode_8z8z(const char *input, char **output,
        /// int flags)`.
        ///
        /// UTF-8 in, UTF-8 out, with no locale involvement. Called at
        /// `lib/idn.c` L286.
        fn idn2_to_unicode_8z8z(
            input: *const c_char,
            output: *mut *mut c_char,
            flags: c_int,
        ) -> c_int;

        /// `void idn2_free(void *ptr)`.
        ///
        /// The only correct release for a buffer libidn2 allocated, because
        /// libidn2 may have been built against a different allocator than the
        /// caller. `Idn2Buf` exists so that nothing else can be called on one.
        fn idn2_free(ptr: *mut c_void);
    }

    /// A NUL-terminated string **libidn2 owns**, released with `idn2_free`.
    ///
    /// This is one half of the two-allocator handoff the module documentation
    /// describes, and the type exists to make the halves impossible to
    /// confuse. [`CBuf`] owns C-allocator memory and is released with `free`;
    /// this owns libidn2 memory and is released with `idn2_free`. The C keeps
    /// both in a variable of the same type, `char *d`, and relies on the
    /// programmer to remember which release each one needs.
    ///
    /// It is private to this module and never escapes it: the only way out is
    /// [`reduplicate`], which copies the bytes into a `CBuf` and releases this
    /// one. That is what `lib/idn.c` L306-L315 does, and confining it to one
    /// function means the ordering cannot be got wrong at a second site.
    ///
    /// # Invariants
    ///
    /// 1. `ptr` is non-null and was returned by libidn2.
    /// 2. `len` is the index of its terminator, so `len + 1` bytes are
    ///    readable from `ptr`.
    /// 3. No other owner exists, so `Drop` is the one and only release.
    struct Idn2Buf {
        /// Start of the libidn2-allocated string.
        ptr: *mut c_char,
        /// Length in bytes, excluding the terminator.
        len: usize,
    }

    impl Idn2Buf {
        /// Adopts a pointer libidn2 produced, measuring it.
        ///
        /// Returning `None` for null is what lets a caller adopt the
        /// out-parameter unconditionally and then decide what the return code
        /// meant, which is the order the C works in: it inspects `rc` and
        /// leaves `decoded` alone.
        ///
        /// # Ownership
        ///
        /// Ownership moves *into* the returned value. The caller must not free
        /// `p` afterwards, and must not keep the pointer: `Drop` is now the
        /// only release.
        ///
        /// # Safety
        ///
        /// `p` must be null, or a NUL-terminated string returned by libidn2
        /// and not yet freed, with no other owner. A pointer from any other
        /// allocator must never be passed here, because `idn2_free` is the
        /// only release this type will ever perform.
        #[must_use = "discarding the value frees the string immediately"]
        unsafe fn from_raw(p: *mut c_char) -> Option<Self> {
            if p.is_null() {
                return None;
            }
            // SAFETY: the caller guarantees `p` points at a live,
            // NUL-terminated string, which is `strlen`'s precondition. Its
            // result is the index of that terminator, establishing invariant
            // 2; invariant 1 holds because the null case already returned, and
            // invariant 3 is the caller's guarantee.
            let len = unsafe { libc::strlen(p) };
            Some(Self { ptr: p, len })
        }

        /// The string's bytes, without the terminator.
        ///
        /// # Ownership
        ///
        /// Nothing changes hands. The lifetime of the result is tied to the
        /// borrow, so it cannot outlive the string, and the obligation to
        /// release stays with this value.
        fn as_bytes(&self) -> &[u8] {
            // SAFETY: invariant 1 gives a non-null pointer into a live
            // allocation and invariant 2 makes `self.len` bytes from its start
            // readable and initialised, since libidn2 wrote the string there.
            // `u8` has an alignment of one, which any pointer satisfies. The
            // returned lifetime is tied to `&self`, so the slice cannot
            // outlive the allocation, and `&self` rules out concurrent
            // mutation.
            unsafe { slice::from_raw_parts(self.ptr.cast::<u8>(), self.len) }
        }
    }

    impl Drop for Idn2Buf {
        /// `idn2_free(d)` at `lib/idn.c` L309 and L334.
        fn drop(&mut self) {
            // SAFETY: invariant 1 says `self.ptr` came from libidn2 and
            // invariant 3 says this value is its only owner, which together
            // are `idn2_free`'s precondition. `Drop` runs at most once per
            // value and there is no other way out of this type, so the string
            // is released exactly once.
            unsafe { idn2_free(self.ptr.cast::<c_void>()) };
        }
    }

    /// `IDN2_LOOKUP` at `lib/idn.c` L39-L40, the arm every platform except
    /// Windows with wide characters takes.
    ///
    /// # Safety
    ///
    /// `name` must be a valid pointer to a NUL-terminated string, readable for
    /// the duration of the call. `host` must be a valid, writable location for
    /// one pointer. On success libidn2 writes a string it owns there, which
    /// the caller must release with `idn2_free` exactly once.
    #[cfg(not(all(windows, win32_unicode)))]
    unsafe fn lookup(name: *const c_char, host: *mut *mut c_char, flags: c_int) -> c_int {
        // SAFETY: the preconditions are exactly this call's own and are
        // forwarded from the caller unchanged.
        unsafe { idn2_lookup_ul(name, host, flags) }
    }

    /// `IDN2_LOOKUP` at `lib/idn.c` L36-L37, the Windows arm.
    ///
    /// The two casts are the macro's own. They are a reinterpretation of
    /// `char` as `uint8_t`, which have the same size and alignment on every
    /// platform this crate targets, and no conversion of the bytes.
    ///
    /// The plan states that Windows-only paths are ported as conditional code
    /// and validated on that platform rather than here, and this is one of
    /// them. Selecting the byte-oriented entry point means the Windows build
    /// has no locale trap at all.
    ///
    /// # Safety
    ///
    /// As for the other arm.
    #[cfg(all(windows, win32_unicode))]
    unsafe fn lookup(name: *const c_char, host: *mut *mut c_char, flags: c_int) -> c_int {
        // SAFETY: the preconditions are forwarded from the caller, and the
        // casts change only how the same bytes are named, exactly as the C
        // macro's casts do.
        unsafe { idn2_lookup_u8(name.cast::<u8>(), host.cast::<*mut u8>(), flags) }
    }

    /// The version guard at `lib/idn.c` L252.
    ///
    /// `if(idn2_check_version(IDN2_VERSION))` reads the returned pointer as a
    /// truth value and nothing more, so this returns a `bool` and the string
    /// libidn2 reports is deliberately not examined. That string points into
    /// libidn2's own static data and must not be freed.
    fn version_ok() -> bool {
        // SAFETY: `IDN2_VERSION` is a NUL-terminated ASCII literal with static
        // lifetime, so the pointer is valid for reads for the whole call, and
        // `idn2_check_version` only reads it. Its result is either null or a
        // pointer to libidn2's own static version string; only its nullness is
        // read here, so nothing is dereferenced and nothing is freed.
        let reported = unsafe { idn2_check_version(IDN2_VERSION.as_ptr().cast::<c_char>()) };
        !reported.is_null()
    }

    /// Copy a libidn2 string into C-allocator memory and release the original.
    ///
    /// `lib/idn.c` L306-L315 and L331-L340, which are the same five lines
    /// written twice:
    ///
    /// ```c
    /// char *c = curlx_strdup(d);
    /// idn2_free(d);
    /// if(c)
    ///   d = c;
    /// else
    ///   result = CURLE_OUT_OF_MEMORY;
    /// ```
    ///
    /// # Why this exists at all
    ///
    /// Because two allocators are live at once. libidn2 allocated the string
    /// with its own allocator, so it must go back to `idn2_free`; and the
    /// value curl keeps has to come from curl's allocator, because whoever
    /// called `curl_url_get` releases it with `curl_free`
    /// (`docs/libcurl/curl_url_get.md` L45, repeated at
    /// `include/curl/urlapi.h` L130-L131). Handing libidn2's pointer straight
    /// to C would mean a buffer freed by an allocator that never allocated it.
    ///
    /// # Ownership
    ///
    /// `original` is consumed, and it is released here rather than at the end
    /// of the caller: the C frees it *before* testing whether the duplication
    /// worked, and the explicit `drop` below preserves that order. On failure
    /// the original is therefore already gone, which is why the C's own
    /// out-of-memory report at L313 does not free anything. The returned
    /// [`CBuf`] owns C-allocator memory and is what may cross into C.
    ///
    /// # Errors
    ///
    /// `CURLcode::CURLE_OUT_OF_MEMORY` if the copy could not be allocated.
    fn reduplicate(original: Idn2Buf) -> Result<CBuf, CURLcode> {
        // L308. `CBuf::from_slice` is `curlx_strdup` for bytes already in
        // hand: it allocates from the C allocator and appends a terminator.
        let duplicate = CBuf::from_slice(original.as_bytes());
        // L309. Releasing the libidn2 string here, and not one line later,
        // is deliberate: it is the order the C uses, and it keeps the two
        // allocators from both owning a copy of the same name for any longer
        // than the C does.
        drop(original);
        match duplicate {
            Some(buf) => Ok(buf),
            None => Err(CURLcode::CURLE_OUT_OF_MEMORY),
        }
    }

    /// The `USE_LIBIDN2` body of `static idn_decode` at `lib/idn.c`
    /// L247-L280, followed by the re-duplication at L306-L315.
    ///
    /// The re-duplication belongs here rather than one layer up because the C
    /// guards it with `#ifdef USE_LIBIDN2`, which makes it a property of this
    /// backend and not of `Curl_idn_decode`. The other backends in `lib/idn.c`
    /// allocate with curl's allocator to begin with and skip the block
    /// entirely, and `super::pure` does the same.
    ///
    /// # Errors
    ///
    /// `CURLcode::CURLE_NOT_BUILT_IN` when the library is too old (L271),
    /// `CURLcode::CURLE_URL_MALFORMAT` when both lookups failed (L267), and
    /// `CURLcode::CURLE_OUT_OF_MEMORY` when the duplication failed (L313).
    pub(crate) fn idn_decode(input: &CBuf) -> Result<CBuf, CURLcode> {
        // L252 and L269-L271. The guard is the first thing the C does and the
        // first thing done here; a library too old to trust is not asked.
        if !version_ok() {
            return Err(CURLcode::CURLE_NOT_BUILT_IN);
        }

        // The borrow is bound rather than used inline so that it is plainly
        // live for every call below. `as_bytes_with_nul` is documented as the
        // way to lend a C-string pointer without giving up ownership: the
        // slice is NUL terminated, `input` keeps owning the block, and libidn2
        // only reads it.
        let source = input.as_bytes_with_nul();
        let name: *const c_char = source.as_ptr().cast::<c_char>();

        let mut decoded: *mut c_char = ptr::null_mut();
        // SAFETY: `name` points at the NUL-terminated `source` slice, which is
        // borrowed from `input` for the whole function, so it is readable for
        // the call. `decoded` is a live local, so `&mut decoded` is a valid
        // writable location for one pointer.
        let mut rc = unsafe { lookup(name, &mut decoded, LOOKUP_FLAGS) };
        // SAFETY: `decoded` is null unless libidn2 wrote a string it owns
        // there, which is exactly this function's precondition, and nothing
        // else has taken ownership of it.
        let mut owned = unsafe { Idn2Buf::from_raw(decoded) };

        if rc != IDN2_OK {
            // L262-L265, the retry. The comment there calls it a fallback to
            // TR46 transitional mode for better IDNA2003 compatibility, and it
            // is not decoration: against libidn2 2.3.8 the first call rejects
            // `\u{2603}.de` with IDN2_DISALLOWED and the retry converts it to
            // `xn--n3h.de`. Note that the flag word is replaced rather than
            // extended, so IDN2_NFC_INPUT is not passed the second time.
            //
            // Dropping `owned` first releases anything a failed call left
            // behind. The C reuses `&decoded` and would abandon such a buffer,
            // but no libidn2 allocates on failure -- measured across the
            // failing codes this port can provoke, the out-parameter is always
            // null -- so `owned` is `None` here in practice and this is
            // insurance rather than a behavioural difference.
            drop(owned);
            decoded = ptr::null_mut();
            // SAFETY: as for the first call. `name` still points at the same
            // live borrow and `decoded` has been reset to null.
            rc = unsafe { lookup(name, &mut decoded, IDN2_TRANSITIONAL) };
            // SAFETY: as for the first adoption.
            owned = unsafe { Idn2Buf::from_raw(decoded) };
        }

        if rc != IDN2_OK {
            // L266-L267. Dropping `owned` on the way out releases anything
            // libidn2 left behind, which in practice is nothing.
            return Err(CURLcode::CURLE_URL_MALFORMAT);
        }

        match owned {
            // L277-L278 hands the string up, and L306-L315 immediately
            // re-owns it through curl's allocator.
            Some(buf) => reduplicate(buf),
            // Unreachable against any libidn2 that honours its own contract:
            // IDN2_OK with a null out-parameter. The C would pass that null to
            // `curlx_strdup` at L308 and then read `d[0]` at L317, both of
            // which are undefined, so there is no behaviour to be faithful to.
            // Reporting a malformed name is the one defined answer.
            None => Err(CURLcode::CURLE_URL_MALFORMAT),
        }
    }

    /// The `USE_LIBIDN2` body of `static idn_encode` at `lib/idn.c`
    /// L282-L300, followed by the re-duplication at L331-L340.
    ///
    /// Three differences from [`idn_decode`] are all deliberate. There is no
    /// version guard, because L282-L300 has none. The flag argument is `0`,
    /// spelled out at L286, rather than a computed word. And there is no
    /// retry: one call, and its verdict stands.
    ///
    /// # Errors
    ///
    /// `CURLcode::CURLE_OUT_OF_MEMORY` when libidn2 reported
    /// `IDNA_MALLOC_ERROR` or the duplication failed, and
    /// `CURLcode::CURLE_URL_MALFORMAT` for every other libidn2 failure
    /// (L287-L288).
    pub(crate) fn idn_encode(puny: &CBuf) -> Result<CBuf, CURLcode> {
        // Bound for the same reason as in `idn_decode`.
        let source = puny.as_bytes_with_nul();
        let input: *const c_char = source.as_ptr().cast::<c_char>();

        let mut enc: *mut c_char = ptr::null_mut();
        // SAFETY: `input` points at the NUL-terminated `source` slice, which
        // is borrowed from `puny` for the whole function, so it is readable
        // for the call. `enc` is a live local, so `&mut enc` is a valid
        // writable location for one pointer. The third argument is the literal
        // flag word the C passes.
        let rc = unsafe { idn2_to_unicode_8z8z(input, &mut enc, 0) };
        // SAFETY: `enc` is null unless libidn2 wrote a string it owns there,
        // and nothing else has taken ownership of it.
        let owned = unsafe { Idn2Buf::from_raw(enc) };

        if rc != IDNA_SUCCESS {
            // L287-L288. The C returns here without freeing, because a failed
            // conversion allocates nothing; dropping `owned` on the way out
            // covers the case where one somehow did.
            return Err(if rc == IDNA_MALLOC_ERROR {
                CURLcode::CURLE_OUT_OF_MEMORY
            } else {
                CURLcode::CURLE_URL_MALFORMAT
            });
        }

        match owned {
            // L298 hands the string up, and L331-L340 re-owns it through
            // curl's allocator.
            Some(buf) => reduplicate(buf),
            // Unreachable, for the reason given in `idn_decode`. An empty
            // input converts to an empty *allocated* string, not to null.
            None => Err(CURLcode::CURLE_URL_MALFORMAT),
        }
    }
}

// ==========================================================================
// Section 4 -- libcurl's own scheme table, imported for drop-in mode
// ==========================================================================

/// libcurl's own scheme lookup, imported for the drop-in configuration.
///
/// Selected when the `scheme-table` feature is off, which is the drop-in and
/// authoritative configuration: the real and complete table is used and this
/// crate contributes none of its own. `src/scheme.rs` owns the interface and
/// the choice between this backend and the built-in table; this module owns
/// the call and the read through the descriptor pointer libcurl returns.
///
/// What leaves the module is a `SchemeInfo`, an owned copy of the three fields
/// the URL API reads, so no raw pointer reaches `src/scheme.rs` at all.
///
/// Note what is *not* here: no definition of `Curl_get_scheme`. The crate
/// imports it, so the archive must show the symbol as undefined rather than
/// defined, or the drop-in link acquires a duplicate of a symbol `lib/url.c`
/// already provides and the archive exports something the C object file does
/// not. `scripts/check-abi.sh` is to be the automated check for that property
/// and is a later deliverable; until it lands, `nm -u` over the archive is the
/// way to confirm the symbol is still undefined.
#[cfg(not(feature = "scheme-table"))]
pub(crate) mod scheme_import {
    use core::ffi::CStr;
    use core::mem;
    use libc::{c_char, c_void, size_t};

    use crate::scheme::SchemeInfo;

    /// Mirror of `struct Curl_scheme` at `lib/urldata.h` L515-L524.
    ///
    /// The field order is the C's, and it is not negotiable: this structure is
    /// never constructed here, only read through a pointer libcurl handed
    /// back, so the offsets are the whole contract. `name`, `protocol` and
    /// `family` are described even though nothing reads them, because the
    /// three fields that *are* read sit after them and cannot be located
    /// otherwise.
    ///
    /// # THE LAYOUT HAZARD
    ///
    /// `protocol` and `family` are `curl_prot_t`, and `curl_prot_t` is
    /// **conditional**:
    ///
    /// ```text
    /// lib/urldata.h:81   /* This should be undefined once we need bit 32 or higher */
    /// lib/urldata.h:82   #define PROTO_TYPE_SMALL
    /// lib/urldata.h:84   #ifndef PROTO_TYPE_SMALL
    /// lib/urldata.h:85   typedef curl_off_t curl_prot_t;
    /// lib/urldata.h:87   typedef uint32_t curl_prot_t;
    /// ```
    ///
    /// So `u32` above is correct only while `PROTO_TYPE_SMALL` is defined in
    /// the libcurl being linked against. If it is ever undefined the two
    /// fields become 64-bit and **every field after them shifts**, which is
    /// exactly the pair of fields this module reads. A reviewer who notices
    /// that `protocol` and `family` are never read may conclude their width
    /// does not matter. It matters more than any other line in this file:
    /// `flags` and `defport` are located by it, and getting it wrong does not
    /// fail to compile, it silently returns another field's bytes as a default
    /// port.
    ///
    /// This is not a hypothetical. `lib/urldata.h` L71 already defines
    /// `CURLPROTO_WSS` as `((curl_prot_t)1 << 31)`, so bit 31 is taken and the
    /// header is one protocol away from the condition its own comment
    /// describes.
    ///
    /// Two things guard the assumption, and it is worth being precise about
    /// what each one can do.
    ///
    /// [`LAYOUT_PROOF`] pins *this* structure to the shape the port assumes,
    /// at compile time. It catches an edit here -- a reordered field, a
    /// widened integer, a `#[repr(C)]` accidentally dropped. It cannot observe
    /// the C side at all: no assertion written in Rust can read
    /// `lib/urldata.h`. The 32-bit `curl_prot_t` is therefore a documented
    /// *precondition* of drop-in mode rather than a checked one, and belongs
    /// with the other documented limitations of that mode in
    /// `docs/KNOWN-DIVERGENCES.md`.
    ///
    /// The live cross-check is the parity run. `tests/libtest/lib1560.c`
    /// asserts default ports directly -- `https://127.0.0.1` with
    /// `CURLU_DEFAULT_PORT` must yield `443` at L592-L594, and
    /// `http://example.com:80` with `CURLU_NO_DEFAULT_PORT` must serialise
    /// without the port at L786-L788 -- and both readings come through
    /// `defport`. A shifted mirror fails them on the first sub-test rather
    /// than subtly, which is the outcome to want.
    #[repr(C)]
    struct CurlScheme {
        /// L516, "URL scheme name in lowercase" -- which four descriptors
        /// disregard, as the module documentation records. Never read: the
        /// lookup is by name and libcurl has already done the comparing.
        name: *const c_char,
        /// L517, `const struct Curl_protocol *`, the implementation.
        ///
        /// Modelled as an opaque pointer because it is only ever tested for
        /// null. `struct Curl_protocol` is a 30-odd member function table at
        /// `lib/urldata.h` L400-L513 and describing it would add a large
        /// second ABI contract for no gain.
        run: *const c_void,
        /// L518-L519, `curl_prot_t`. Never read. See the layout hazard above:
        /// its width is load-bearing regardless.
        protocol: u32,
        /// L520-L521, `curl_prot_t`. Never read, same caveat.
        family: u32,
        /// L522, `uint32_t` of `PROTOPT_*` bits. Read, for
        /// `PROTOPT_URLOPTIONS`.
        flags: u32,
        /// L523, `uint16_t`. Read, as the scheme's default port.
        defport: u16,
    }

    // The names below are C identifiers and must stay exactly as libcurl
    // spells them, so the Rust naming convention cannot apply. Scoped to the
    // extern block, so nothing else in the module inherits the allowance.
    #[allow(non_snake_case)]
    extern "C" {
        /// `lib/url.c` L1469-L1472, declared at `lib/url.h` L76.
        ///
        /// Returns null for a name the table does not hold.
        fn Curl_get_scheme(scheme: *const c_char) -> *const CurlScheme;

        /// `lib/url.c` L1477-L1541, declared at `lib/url.h` L77.
        ///
        /// The length-delimited form `Curl_get_scheme` forwards to. `size_t`
        /// is `usize` on every platform this crate targets, which is what
        /// `libc::size_t` states.
        fn Curl_getn_scheme(scheme: *const c_char, len: size_t) -> *const CurlScheme;
    }

    /// The size [`CurlScheme`] must have, given a 32-bit `curl_prot_t`.
    ///
    /// Written as a table rather than as arithmetic, so that the padding
    /// reasoning is visible instead of encoded, and so that no arithmetic
    /// operator appears in a file the crate's lint policy holds to checked
    /// arithmetic.
    ///
    /// - 64-bit pointers: `name` 8 at 0, `run` 8 at 8, `protocol` 4 at 16,
    ///   `family` 4 at 20, `flags` 4 at 24, `defport` 2 at 28, then 2 bytes of
    ///   tail padding to the 8-byte alignment. 32 in total. A 64-bit
    ///   `curl_prot_t` would make it 40, so the check discriminates.
    /// - 32-bit pointers: `name` 4 at 0, `run` 4 at 4, `protocol` 4 at 8,
    ///   `family` 4 at 12, `flags` 4 at 16, `defport` 2 at 20, then 2 bytes of
    ///   tail padding to the 4-byte alignment. 24 in total, against 32 for the
    ///   wide variant.
    ///
    /// Any other pointer width is a platform this port has not reasoned about.
    /// Returning zero for it fails [`LAYOUT_PROOF`] outright, because no
    /// structure containing a pointer can be zero bytes, which is the intended
    /// outcome: refuse rather than guess.
    const fn expected_mirror_size() -> usize {
        match mem::size_of::<*const c_void>() {
            8 => 32,
            4 => 24,
            _ => 0,
        }
    }

    /// Compile-time proof that the mirror still has the layout the port
    /// assumes. See the hazard note on [`CurlScheme`] for what this does and
    /// does not establish.
    const LAYOUT_PROOF: () = {
        assert!(
            mem::size_of::<CurlScheme>() == expected_mirror_size(),
            "src/ffi.rs: the struct Curl_scheme mirror is not the size \
             lib/urldata.h:515-524 implies with a 32-bit curl_prot_t. Either \
             a field here was reordered, widened or narrowed, or the target \
             has an unexpected pointer width."
        );
        assert!(
            mem::align_of::<CurlScheme>() == mem::align_of::<*const c_void>(),
            "src/ffi.rs: the struct Curl_scheme mirror is not \
             pointer-aligned, so its first member is no longer a pointer and \
             every offset after it has moved."
        );
        assert!(
            mem::size_of::<u32>() == 4 && mem::size_of::<u16>() == 2,
            "src/ffi.rs: uint32_t and uint16_t are not 4 and 2 bytes, so \
             the flags and defport fields cannot be where lib/urldata.h puts \
             them."
        );
    };

    /// `Curl_get_scheme`, drop-in.
    pub(crate) fn get_scheme(scheme: &CStr) -> Option<SchemeInfo> {
        // SAFETY: `Curl_get_scheme` reads its argument as a NUL-terminated C
        // string and does not retain it. `CStr::as_ptr` yields a non-null,
        // readable pointer to bytes that are NUL terminated by the type's own
        // invariant, and the borrow keeps them alive for the whole call, which
        // is longer than libcurl needs them: `lib/url.c` L1471 passes the
        // pointer to `strlen` and to `Curl_getn_scheme`, which compares it and
        // returns. Nothing is written through the pointer, matching the C's
        // `const char *`.
        let descriptor = unsafe { Curl_get_scheme(scheme.as_ptr()) };
        describe(descriptor)
    }

    /// `Curl_getn_scheme`, drop-in.
    pub(crate) fn getn_scheme(name: &[u8]) -> Option<SchemeInfo> {
        // Reproduces the `len &&` half of the guard at `lib/url.c` L1524
        // before the call rather than after it, for a reason that is about
        // Rust and not about C: `<[u8]>::as_ptr` on an empty slice yields a
        // dangling pointer, which the C would never dereference -- it tests
        // `len` first -- but which has no business crossing the boundary at
        // all. The outcome is identical either way.
        if name.is_empty() {
            return None;
        }
        // SAFETY: the slice is non-empty, so `as_ptr` yields a pointer to
        // `name.len()` readable, initialised bytes, and the borrow keeps them
        // alive for the whole call. `len` is that same count, so libcurl reads
        // exactly the slice and never past it: `lib/url.c` L1529-L1534 walks
        // `len` bytes and L1537 compares `len` bytes. No terminator is needed
        // or assumed on this path, which is why the length-delimited entry
        // point exists. `u8` and `c_char` have the same size and alignment, so
        // the cast changes only the sign the compiler ascribes to the bytes,
        // and libcurl folds them through a 256-entry table that is total over
        // all byte values.
        let descriptor = unsafe { Curl_getn_scheme(name.as_ptr().cast::<c_char>(), name.len()) };
        describe(descriptor)
    }

    /// Turns the descriptor pointer libcurl returned into the safe, owned
    /// answer, so no raw pointer leaves this module.
    fn describe(descriptor: *const CurlScheme) -> Option<SchemeInfo> {
        // Forces the layout proof to be evaluated in every build. It emits no
        // code, and `describe` is on every path out of this backend, so the
        // proof cannot be compiled out of a configuration that uses the
        // mirror.
        let () = LAYOUT_PROOF;
        // The C's own test, at `lib/urlapi.c` L284 followed by L290, L951,
        // L1460 followed by L1465, L1589, L1598 and L1645: every one of the
        // six call sites checks the pointer before reading through it.
        if descriptor.is_null() {
            return None;
        }
        // SAFETY: the pointer is non-null, checked immediately above. libcurl
        // only ever returns `&Curl_scheme_<name>`, one of the 33 `const struct
        // Curl_scheme` objects with static storage duration listed in
        // `lib/url.c` L1488-L1522, so the referent outlives this call by the
        // whole program and is never written to by libcurl or by this crate --
        // which makes a shared reference sound and rules out any aliasing
        // conflict. The referent's layout matches `CurlScheme` under the
        // precondition documented on that type and pinned as far as Rust can
        // pin it by `LAYOUT_PROOF`. The reference is dropped before this
        // function returns; only copies of three scalar fields escape.
        let scheme = unsafe { &*descriptor };
        Some(SchemeInfo::new(
            scheme.flags,
            scheme.defport,
            // `!h->run` at `lib/urlapi.c` L1646, inverted: the C tests for
            // absence, this records presence.
            !scheme.run.is_null(),
        ))
    }

    #[cfg(test)]
    mod tests {
        // The crate root denies the panicking constructs so that no panic can
        // ever reach the C boundary. A test's entire job is to panic when an
        // assertion fails, and a test never crosses that boundary, so the
        // denial is relaxed here and only here, for the one construct this
        // module needs.
        #![allow(clippy::unwrap_used)]

        use super::{expected_mirror_size, CurlScheme, LAYOUT_PROOF};
        use super::{get_scheme, getn_scheme};
        use crate::abi::PROTOPT_URLOPTIONS;
        use crate::scheme::SchemeInfo;
        use core::ffi::CStr;
        use core::mem;
        use core::ptr;
        use libc::{c_char, c_void, size_t};

        /// Builds a `&CStr` from a byte literal that ends in NUL.
        ///
        /// The checked constructor rather than the unchecked one, even here in
        /// the crate's unsafe island: an `unsafe` block should carry weight,
        /// and a literal that does not end in exactly one NUL is a defect in
        /// the test rather than a case to handle.
        fn cstr(terminated: &[u8]) -> &CStr {
            assert!(
                CStr::from_bytes_with_nul(terminated).is_ok(),
                "test literal must end in exactly one NUL and hold no other"
            );
            CStr::from_bytes_with_nul(terminated).unwrap()
        }

        /// A `static const struct Curl_scheme` stand-in for libcurl's table.
        ///
        /// Drop-in mode imports `Curl_get_scheme` rather than defining it, so a
        /// test binary in this configuration has no libcurl to link against and
        /// the symbol would be undefined. The double below supplies it, which
        /// buys more than a working link: it exercises the real code path --
        /// the call, the null check and the dereference through the mirror --
        /// including the disabled-protocol case, which a real libcurl only
        /// produces for a protocol its build switched off.
        ///
        /// It is defined under `cfg(test)` and can therefore never reach the
        /// shipped archive, so `Curl_get_scheme` remains an undefined symbol
        /// there -- which is what a symbol-set check over the archive, whether
        /// `nm -u` by hand or `scripts/check-abi.sh` once that script lands,
        /// has to see.
        struct Descriptors([CurlScheme; 4]);

        // SAFETY: the array is immutable for the whole program and the only
        // pointers it holds are into `static` byte literals, so no thread can
        // observe it changing and none of its contents can be freed. That is
        // the same posture as libcurl's own table, whose entries are
        // `const struct Curl_scheme` objects with static storage duration.
        unsafe impl Sync for Descriptors {}

        /// One byte with static storage, used as a non-null `run` that is never
        /// dereferenced. `lib/urlapi.c` L1646 only tests the pointer, so any
        /// non-null value models an implemented protocol faithfully.
        static RUN_MARKER: u8 = 0;

        /// Four rows: two ordinary schemes, one with `PROTOPT_URLOPTIONS`, and
        /// one whose `run` is null the way `ZERO_NULL` leaves it at
        /// `lib/file.c` L629.
        static DESCRIPTORS: Descriptors = Descriptors([
            CurlScheme {
                name: b"https\0".as_ptr().cast::<c_char>(),
                run: (&RUN_MARKER as *const u8).cast::<c_void>(),
                protocol: 1 << 1,
                family: 1 << 0,
                // PROTOPT_SSL | PROTOPT_CREDSPERREQUEST | PROTOPT_ALPN |
                // PROTOPT_USERPWDCTRL | PROTOPT_CONN_REUSE, lib/http.c:5037.
                flags: 0x0001_2181,
                defport: 443,
            },
            CurlScheme {
                name: b"imap\0".as_ptr().cast::<c_char>(),
                run: (&RUN_MARKER as *const u8).cast::<c_void>(),
                protocol: 1 << 10,
                family: 1 << 10,
                // PROTOPT_CLOSEACTION | PROTOPT_URLOPTIONS |
                // PROTOPT_SSL_REUSE | PROTOPT_CONN_REUSE, lib/imap.c:2339.
                flags: 0x0001_8404,
                defport: 143,
            },
            CurlScheme {
                name: b"file\0".as_ptr().cast::<c_char>(),
                run: (&RUN_MARKER as *const u8).cast::<c_void>(),
                protocol: 1 << 9,
                family: 1 << 9,
                // PROTOPT_NONETWORK | PROTOPT_NOURLQUERY, lib/file.c:635.
                flags: 0x0050,
                defport: 0,
            },
            CurlScheme {
                // A protocol whose module compiled its implementation out.
                name: b"rtmp\0".as_ptr().cast::<c_char>(),
                run: ptr::null(),
                protocol: 1 << 19,
                family: 1 << 19,
                flags: 0,
                defport: 1935,
            },
        ]);

        /// Case-insensitive lookup over the double, matching `Curl_getn_scheme`
        /// at `lib/url.c` L1524-L1540 in rule if not in mechanism.
        fn find(name: &[u8]) -> *const CurlScheme {
            if name.is_empty() || name.len() > 7 {
                return ptr::null();
            }
            for descriptor in &DESCRIPTORS.0 {
                // SAFETY: every `name` above is a byte literal ending in
                // exactly one NUL, so the pointer stored in the row is a valid
                // NUL-terminated C string with static lifetime.
                let stored = unsafe { CStr::from_ptr(descriptor.name) };
                if crate::ctype::eq_ignore_case(name, stored.to_bytes()) {
                    return descriptor;
                }
            }
            ptr::null()
        }

        /// Stands in for `lib/url.c` L1469-L1472 while the crate's own tests
        /// run.
        #[no_mangle]
        extern "C" fn Curl_get_scheme(scheme: *const c_char) -> *const CurlScheme {
            if scheme.is_null() {
                return ptr::null();
            }
            // SAFETY: the only caller is `super::get_scheme`, which passes
            // `CStr::as_ptr`, so the pointer is non-null -- rechecked above in
            // any case -- and NUL terminated for the duration of the call.
            let name = unsafe { CStr::from_ptr(scheme) };
            find(name.to_bytes())
        }

        /// Stands in for `lib/url.c` L1477-L1541.
        #[no_mangle]
        extern "C" fn Curl_getn_scheme(scheme: *const c_char, len: size_t) -> *const CurlScheme {
            if scheme.is_null() || len == 0 {
                return ptr::null();
            }
            // SAFETY: the only caller is `super::getn_scheme`, which rejects an
            // empty slice and then passes that slice's pointer together with
            // its own length, so exactly `len` initialised bytes are readable
            // and they stay borrowed for the whole call. `c_char` and `u8`
            // share size and alignment.
            let name = unsafe { core::slice::from_raw_parts(scheme.cast::<u8>(), len) };
            find(name)
        }

        /// The compile-time proof has to actually be evaluated, and a test that
        /// references it says so out loud rather than relying on a reader
        /// spotting the binding inside `describe`.
        #[test]
        fn the_layout_proof_is_evaluated() {
            let () = LAYOUT_PROOF;
            assert_eq!(mem::size_of::<CurlScheme>(), expected_mirror_size());
            assert_eq!(
                mem::align_of::<CurlScheme>(),
                mem::align_of::<*const c_void>()
            );
        }

        /// The offsets the compile-time proof cannot express at this crate's
        /// minimum supported Rust version, `mem::offset_of!` having arrived in
        /// 1.77. Measured on a live value instead, which is exactly as
        /// authoritative and costs one stack slot in a test.
        ///
        /// These four numbers are the ABI contract. If `curl_prot_t` ever
        /// widens, `flags` and `defport` move and this test still passes --
        /// because it measures the Rust mirror, not the C original -- which is
        /// why the hazard is documented on [`CurlScheme`] as a precondition and
        /// cross-checked by the parity run rather than pretended to be checked
        /// here.
        #[test]
        fn mirror_field_offsets_are_where_the_c_layout_puts_them() {
            let probe = CurlScheme {
                name: ptr::null(),
                run: ptr::null(),
                protocol: 0,
                family: 0,
                flags: 0,
                defport: 0,
            };
            let base = (&probe as *const CurlScheme).cast::<u8>() as usize;
            let offset_of = |field: usize| field.wrapping_sub(base);
            let pointer = mem::size_of::<*const c_void>();

            assert_eq!(offset_of((&probe.name as *const *const c_char) as usize), 0);
            assert_eq!(
                offset_of((&probe.run as *const *const c_void) as usize),
                pointer,
                "run must follow name immediately"
            );
            assert_eq!(
                offset_of((&probe.protocol as *const u32) as usize),
                pointer.saturating_mul(2),
                "protocol must follow the two pointers"
            );
            assert_eq!(
                offset_of((&probe.family as *const u32) as usize),
                pointer.saturating_mul(2).saturating_add(4)
            );
            assert_eq!(
                offset_of((&probe.flags as *const u32) as usize),
                pointer.saturating_mul(2).saturating_add(8),
                "flags is read, so its offset is part of the ABI contract"
            );
            assert_eq!(
                offset_of((&probe.defport as *const u16) as usize),
                pointer.saturating_mul(2).saturating_add(12),
                "defport is read, so its offset is part of the ABI contract"
            );
        }

        /// The whole drop-in path: call, null check, dereference, and the three
        /// fields arriving in the right places rather than merely arriving.
        #[test]
        fn the_three_fields_are_read_through_the_mirror() {
            let https = getn_scheme(b"https");
            assert_eq!(https.map(SchemeInfo::defport), Some(443));
            assert_eq!(https.map(SchemeInfo::flags), Some(0x0001_2181));
            assert_eq!(https.map(SchemeInfo::implemented), Some(true));
            assert_eq!(https.map(SchemeInfo::has_url_options), Some(false));

            let imap = getn_scheme(b"imap");
            assert_eq!(imap.map(SchemeInfo::defport), Some(143));
            assert_eq!(imap.map(SchemeInfo::has_url_options), Some(true));
            assert_eq!(
                imap.map(|info| info.flags() & PROTOPT_URLOPTIONS),
                Some(PROTOPT_URLOPTIONS)
            );

            // The zero default port has to survive the trip as a zero and not
            // be confused with "not found".
            let file = getn_scheme(b"file");
            assert_eq!(file.map(SchemeInfo::defport), Some(0));
            assert!(file.is_some());
        }

        /// `!h->run` at `lib/urlapi.c` L1646. A protocol whose module compiled
        /// its implementation out is still found, and still reports that it
        /// cannot be driven.
        #[test]
        fn a_null_run_pointer_reports_a_disabled_protocol() {
            let rtmp = getn_scheme(b"rtmp");
            assert!(rtmp.is_some(), "a disabled protocol is still in the table");
            assert_eq!(rtmp.map(SchemeInfo::implemented), Some(false));
            assert_eq!(rtmp.map(SchemeInfo::defport), Some(1935));
        }

        /// A null descriptor is the C's "not a known scheme", and must never be
        /// dereferenced.
        #[test]
        fn a_null_descriptor_is_reported_as_not_found() {
            assert_eq!(getn_scheme(b"nope"), None);
            assert_eq!(super::describe(ptr::null()), None);
        }

        /// The empty slice is turned away before its pointer can cross the
        /// boundary, and the terminated entry point agrees.
        #[test]
        fn an_empty_name_never_reaches_the_c_lookup() {
            assert_eq!(getn_scheme(b""), None);
            assert_eq!(get_scheme(cstr(b"\0")), None);
        }

        /// Both entry points reach the same descriptor, as `Curl_get_scheme`
        /// forwarding to `Curl_getn_scheme` guarantees on the C side.
        #[test]
        fn the_two_entry_points_agree() {
            for (terminated, name) in [
                (b"https\0".as_slice(), b"https".as_slice()),
                (b"file\0".as_slice(), b"file".as_slice()),
                (b"rtmp\0".as_slice(), b"rtmp".as_slice()),
                (b"nope\0".as_slice(), b"nope".as_slice()),
            ] {
                assert_eq!(get_scheme(cstr(terminated)), getn_scheme(name));
            }
        }
    }
}

// ==========================================================================
// Section 5 -- the locale and codeset probes
// ==========================================================================

/// The locale and codeset probes the crate's own tests need.
///
/// `setlocale` and `nl_langinfo` are foreign calls like any other, so they
/// belong here rather than in the module that consumes them. Everything below
/// is `#[cfg(test)]`: these two functions exist to let `src/idn.rs`'s tests
/// reproduce the environment the parity harness establishes, and neither has
/// any business in the shipped archive.
///
/// The distinction matters more than it looks. `tests/libtest/first.c` L231
/// calls `setlocale(LC_ALL, "")` because the whole internationalised-domain
/// path depends on it, and the *library* must not make that call: choosing a
/// locale is the application's decision, and libcurl does not take it either.
/// So the crate never calls it, and the tests do.
#[cfg(test)]
pub(crate) mod test_locale {
    /// Put the process in the locale its environment names, exactly once.
    ///
    /// A Rust program never calls `setlocale`, so it starts in the `C` locale
    /// whatever the environment says, and `idn2_lookup_ul` then fails on every
    /// non-ASCII name with `IDN2_ICONV_FAIL`. `tests/libtest/first.c` L231
    /// makes the same call for the same reason, and a harness that omits it
    /// passes while exercising none of the conversion path.
    ///
    /// Once, and before any lookup. `Once::call_once` blocks its other callers
    /// until the initialiser has returned, and every test here that reaches
    /// libidn2 calls this first, so no lookup can observe the locale while it
    /// is being changed.
    pub(crate) fn ensure_locale() {
        // Reached through `std` rather than assumed to be in the prelude, so
        // that this module compiles the same way whichever the crate root
        // turns out to declare. Every non-test module of this crate imports
        // from `core` and `libc` alone.
        extern crate std;
        use libc::c_char;
        use std::sync::Once;

        static SELECTED: Once = Once::new();

        SELECTED.call_once(|| {
            // The empty string is what asks for the environment's own locale,
            // and it is exactly what `tests/libtest/first.c` L231 passes.
            const FROM_ENVIRONMENT: &[u8] = b"\0";
            // SAFETY: the pointer is to a NUL-terminated static literal, which
            // `setlocale` only reads. The returned pointer is to libc's own
            // storage and is deliberately not read or freed. `Once` guarantees
            // this runs on one thread with every other caller blocked, which
            // is what makes a call that mutates process-wide state safe here.
            unsafe { libc::setlocale(libc::LC_ALL, FROM_ENVIRONMENT.as_ptr().cast::<c_char>()) };
        });
    }

    /// Whether the process locale's codeset is UTF-8.
    ///
    /// This is the same question `tests/runtests.pl` answers with
    /// `is_utf8_supported()` at L836 and exports as
    /// `CURL_TEST_HAVE_CODESET_UTF8` at L837-L839 for
    /// `tests/libtest/lib1560.c` to read at L2036 and gate three sub-tests on.
    /// Asking the C library directly is better than reading the variable,
    /// because the variable can be right about the environment and wrong about
    /// the machine: on this container `LC_ALL=en_US.UTF-8` names a locale that
    /// is not generated and yields the codeset `ANSI_X3.4-1968`, where a check
    /// of the variable's spelling would have concluded UTF-8.
    pub(crate) fn utf8_codeset() -> bool {
        use core::ffi::CStr;

        ensure_locale();
        // SAFETY: `nl_langinfo` returns a pointer to libc's own static,
        // NUL-terminated storage for the current locale, never null for a
        // valid item, and `CODESET` is a valid item. The locale is fixed by
        // `ensure_locale` before this runs and is never changed again, so the
        // string cannot be rewritten while it is borrowed here.
        let codeset = unsafe { CStr::from_ptr(libc::nl_langinfo(libc::CODESET)) };
        codeset.to_bytes() == b"UTF-8"
    }
}

// ==========================================================================
// Section 6 -- the exported C-linkage symbols
// ==========================================================================

/// The exported symbols: the crate's whole public face.
///
/// Up to ten definitions live here -- **eight unconditional plus two
/// feature-gated** -- so the set an archive actually exports depends on the
/// feature selection. Authoritative drop-in mode exports the eight; the
/// default standalone configuration exports all ten.
///
/// The eight unconditional ones are exactly the eight globals
/// `nm -g --defined-only` reports for the object file `lib/urlapi.c` produces:
/// the five public functions of `include/curl/urlapi.h` L113-L142 and the
/// three internal entry points of `lib/urlapi-int.h` L28-L33. Replacing that
/// object file in a libcurl archive needs all eight, because the three
/// internal ones have real consumers -- `lib/http1.c` L220, `lib/url.c` L1661
/// and `lib/http.c` L1177 for `Curl_is_absolute_url`, `lib/doh.c` L1127 for
/// `Curl_junkscan`, and `lib/http2.c` L739 for `Curl_url_set_authority`.
///
/// The other two are feature-gated and **must be off in drop-in mode**:
/// `curl_url_strerror` is defined in `lib/strerror.c` L420-L531 and
/// `curl_free` in `lib/escape.c` L189-L192, both of which stay in the archive,
/// so exporting either unconditionally would be a duplicate definition. They
/// exist for the standalone link, where no libcurl participates and a consumer
/// still has to be able to call them: `rust-urlapi/demo/urlapi_demo.c` calls
/// `curl_url_strerror` for every result code it reports and `curl_free` for
/// every buffer a getter hands it, and links against this crate alone when
/// compiled with `-DURLAPI_DEMO_STANDALONE`.
///
/// # The two symbols deliberately not here
///
/// `lib/urlapi-int.h` declares four functions, and only three are exported
/// above. The fourth, `Curl_parse_port` at its L35-L38, sits inside
/// `#ifdef UNITTESTS`, so it is a global only in a unit-test build and is
/// absent from the object file this archive replaces -- which is why exporting
/// it would *add* a symbol rather than match one. `dedotdotify`, declared with
/// the same marker at `lib/urlapi.c` L715, is in the same position.
///
/// The consequence is real and is reported rather than worked around: it puts
/// `tests/unit/unit1653.c` out of reach. That test calls
/// `Curl_parse_port(url, &host, has_scheme)` at its L37 with a
/// `struct dynbuf` it built itself at L32-L34, so satisfying it would need a
/// ninth exported symbol *and* a layout-compatible mirror of C's dynamic
/// buffer -- a materially stronger contract than anything the public API asks
/// for, and one the plan records as constraint R2. The user's success criteria
/// name `lib1560`/`test1560` only. Adding the symbol anyway would break the
/// property `scripts/check-abi.sh` is to check once it lands, that this
/// archive's exported set
/// equals the C object's exactly.
///
/// # Why this is a submodule rather than items at file scope
///
/// One name: section 1 already has a `curl_free`, the crate-internal release
/// path every owned buffer ends at, and the export of the same name is a
/// different function with a different job. A submodule keeps both, which is
/// better than renaming a helper that a dozen call sites and several documents
/// already refer to. `#[no_mangle]` ignores module nesting entirely, so the
/// symbol table is the same either way.
///
/// # The attribute set, and why the spelling is the plain one
///
/// Every item below carries three things and needs all three: `#[no_mangle]`,
/// so the symbol keeps the name C asks the linker for instead of a mangled
/// one; `extern "C"`, so the calling convention and the unwind posture are
/// C's; and `pub`, so the item is nameable at all.
///
/// It is worth being explicit that `pub` is the one of the three that does
/// **not** put anything in the symbol table. Rust visibility governs which
/// paths may refer to an item within the language, and nothing else -- an
/// ordinary `pub fn` is compiled with an internal, mangled name and is
/// invisible to a C linker, while `#[no_mangle] pub extern "C" fn` is the
/// combination that produces a C symbol.
///
/// `src/lib.rs` in fact declares both `pub mod abi;` and `pub mod ffi;`, and
/// that costs the ABI nothing, which is the point: what the archive exports is
/// decided entirely by the attributes, not by the module tree. The two are
/// public for reasons internal to Rust, given at their declarations --
/// `#[deny(missing_docs)]` reaches the items of a public module, and a Cargo
/// integration test links this crate as an external crate and can therefore
/// name only `pub` paths. Making them private again would not remove a single
/// symbol from the archive, and making the other thirteen public would not add
/// one.
///
/// The spelling is the plain `#[no_mangle]`, not the `#[unsafe(no_mangle)]`
/// form. The latter belongs to later editions, where the attribute is treated
/// as unsafe to apply, and `rust-urlapi/Cargo.toml` pins `edition = "2021"`
/// precisely so that this file's attribute set stays the one written here.
/// Raising the edition would require rewriting all ten, which is a change to
/// the ABI surface and therefore not a change to make casually.
///
/// # The preconditions, and the three places the C would fault
///
/// `curl_url_get` and `curl_url_set` have documented answers for a null
/// handle and a null part pointer, `CURLUE_BAD_HANDLE` and
/// `CURLUE_BAD_PARTPOINTER`, and those are reproduced exactly at L1548-L1552
/// and L1817-L1818.
///
/// Three entry points have no such answer because the C never asks the
/// question, each in its own way. `curl_url_dup` dereferences its argument at
/// L1314 without testing it. `Curl_url_set_authority` calls
/// `strlen(authority)` at L666, having only `DEBUGASSERT(authority)` at L662,
/// which compiles to nothing in a release build. `Curl_is_absolute_url` calls
/// no `strlen` at all -- it reads `url[0]` at L195 and then indexes `url[i]`
/// directly in the bounded loop at L196-L205, so a null argument is
/// dereferenced by the very first test rather than by a library call.
/// A null in any of the three is undefined behaviour in the C and
/// cannot be "reproduced"; each one below returns instead the answer its
/// caller already has to handle -- a null handle from the duplicator, which is
/// what an allocation failure gives, zero from the absolute-URL test, and
/// `CURLUE_MALFORMED_INPUT` from the authority setter. Every real caller in
/// the tree passes a non-null pointer, so no behaviour visible to libcurl
/// changes.
///
/// # `bool` across the boundary, and the configurations this holds for
///
/// Two of the internal entry points take a `bool`, and C's `bool` is not one
/// type. `lib/curl_setup.h` makes it one of three, and which one is a property
/// of the libcurl this archive is linked beside rather than of this crate:
///
/// * `_Bool`, when `HAVE_STDBOOL_H` and `HAVE_BOOL_T` are both defined and
///   L848-L850 includes `<stdbool.h>`. One byte holding 0 or 1.
/// * `int`, from `typedef int bool` at L1007-L1012, on HP-UX without
///   `HAVE_BOOL_T`.
/// * an int-width enumeration, from `typedef enum { bool_false, bool_true }
///   bool` at L1020-L1024, on any other pre-C99 platform.
///
/// Rust's `bool` is ABI-compatible with the first and with neither of the
/// others, and the disagreement is not a link error: it is a silent argument
/// width mismatch, so the callee reads whatever bits lie beyond the byte it
/// expected. Writing `bool` in the two signatures would therefore be correct
/// on the common platform and wrong on the two curl still supports.
///
/// So the two signatures name [`exports::CurlBool`] instead, which is the C
/// scalar rather than a Rust type: `u8` by default, `c_int` under the
/// `curl_bool_int` cfg, `c_uint` under `curl_bool_enum`. `build.rs` emits
/// those from `CURL_URLAPI_CURL_BOOL`, and nothing else in the crate sees
/// them -- [`exports::curl_bool_is_true`] converts once, immediately, and
/// every function below the facade keeps a plain Rust `bool`. The conversion
/// is `value != 0`, which is what C's own coercion to a truth value is, so no
/// bit pattern a caller can produce is invalid on any of the three.
pub(crate) mod exports {
    use core::ffi::{c_char, c_uint, c_void, CStr};
    use core::{mem, ptr};
    use libc::size_t;

    use crate::abi::{
        CURLUPart, CURLUcode, CURLUE_BAD_HANDLE, CURLUE_BAD_PARTPOINTER, CURLUE_MALFORMED_INPUT,
        CURLUE_OK, MAX_SCHEME_LEN,
    };
    use crate::alloc::CBuf;
    use crate::getset::{url_get, url_set};
    use crate::handle::CurlUrl;
    use crate::parse::junk::junkscan;
    use crate::parse::scheme::is_absolute_url;

    /// The C scalar that carries curl's `bool` across this boundary.
    ///
    /// See the module documentation's "`bool` across the boundary" section for
    /// the three representations `lib/curl_setup.h` can give `bool` and why the
    /// choice cannot be made once and for all in the source. This alias is the
    /// `_Bool` arm of that choice, `lib/curl_setup.h` L848-L850: one byte
    /// holding 0 or 1, which is what Rust's own `bool` is ABI-compatible with
    /// and what every platform with a C99 library selects.
    ///
    /// Deliberately not `bool`. `bool` would make the *value* validity a
    /// language-level obligation -- a `bool` holding 2 is instant undefined
    /// behaviour -- and this side of the boundary cannot enforce what a C
    /// caller passes. `u8` accepts every bit pattern and
    /// [`curl_bool_is_true`] gives it C's own meaning.
    #[cfg(not(any(curl_bool_int, curl_bool_enum)))]
    pub type CurlBool = u8;

    /// The C scalar that carries curl's `bool` across this boundary.
    ///
    /// The `typedef int bool` arm, `lib/curl_setup.h` L1007-L1012, selected by
    /// building with `CURL_URLAPI_CURL_BOOL=int`.
    #[cfg(curl_bool_int)]
    pub type CurlBool = core::ffi::c_int;

    /// The C scalar that carries curl's `bool` across this boundary.
    ///
    /// The `typedef enum { bool_false, bool_true } bool` arm,
    /// `lib/curl_setup.h` L1020-L1024, selected by building with
    /// `CURL_URLAPI_CURL_BOOL=enum`. An enumeration whose enumerators are all
    /// non-negative is `unsigned int` on the System V ABI and `int` under
    /// MSVC; the calling convention acts on the width, which both share, and
    /// the only two values that ever travel here are 0 and 1.
    #[cfg(curl_bool_enum)]
    pub type CurlBool = c_uint;

    /// The most bytes `Curl_is_absolute_url` can write into its buffer.
    ///
    /// Forty-one: `lib/urlapi.c` L195 stops the scan index below
    /// `MAX_SCHEME_LEN`, or leaves it exactly at `MAX_SCHEME_LEN` when every
    /// byte of a forty-byte run could continue a scheme, and L215 then writes
    /// the terminator *at* that index. One byte more than the bound, therefore,
    /// which is also what the C's `DEBUGASSERT(!buf || (buflen >
    /// MAX_SCHEME_LEN))` at L186 demands of its caller and what its own caller
    /// at L1114 declares. `tests/libtest/lib1560.c` L677-L681 requires the
    /// forty-byte scheme to parse, so the extra byte is reachable rather than
    /// theoretical.
    const SCHEME_SCRATCH_LEN: usize = MAX_SCHEME_LEN.saturating_add(1);

    /// C's truth test, applied to a [`CurlBool`] the moment it arrives.
    ///
    /// `value != 0` is what C means by the value being true, for all three
    /// representations: `_Bool` normalises on assignment so it only ever holds
    /// 0 or 1, and the other two are int-width scalars a caller sets from
    /// `TRUE`/`FALSE` at `lib/curl_setup.h` L1046-L1052. Every function below
    /// the facade takes a Rust `bool`, so this is the single point of
    /// conversion and there is nowhere else for the width to leak to.
    pub(crate) fn curl_bool_is_true(value: CurlBool) -> bool {
        value != 0
    }

    // The handle include/curl/urlapi.h L107 declares as an incomplete type.
    //
    // `typedef struct Curl_URL CURLU;` never gains a definition in any public
    // header, so C can only ever hold a pointer to it and this crate is free
    // to choose the layout -- which is what makes the port tractable at all
    // (plan 0.3.3, "layout freedom follows from opacity"). The Rust type is
    // CurlUrl, and the signatures below name it directly: from C's side a
    // pointer is a pointer, and naming the real type keeps the ownership
    // documentation on each function honest.
    //
    // The one property the layout must have is that malloc alignment is
    // enough for it, since curl_url() allocates the block with the C
    // allocator exactly as L1290 does. The items below are that check: the
    // types whose alignment C actually promises, and the two compile-time
    // assertions against them.

    /// A union of the fundamental C types, which is how C defines
    /// `max_align_t` itself.
    ///
    /// Compiled on every target even where nothing selects it, so that the one
    /// arm of [`MallocAlignment`] that uses it is never the only thing holding
    /// it to a compiler. Its alignment is the strictest of its members', which
    /// is what "suitable for any fundamental type" means.
    ///
    /// The one fundamental type absent from it is `long double`, because Rust
    /// has no name for an 80-bit extended float. That makes the union's
    /// alignment a possible *under*-estimate of the platform's, never an
    /// over-estimate, and under-estimating is the safe direction: it makes the
    /// assertion below stricter than the truth, so a build it accepts is
    /// certainly sound. `libc`'s own model has the same gap -- on
    /// `x86_64-unknown-linux-gnu` it describes `max_align_t` as `[f64; 4]`,
    /// alignment eight, where glibc's real one is sixteen.
    #[repr(C)]
    union FundamentalAlign {
        /// The widest integer C guarantees.
        integral: libc::c_longlong,
        /// The widest floating type Rust can name.
        floating: f64,
        /// Every object pointer has the same alignment on every supported
        /// target, so one stands for all of them.
        pointer: *mut c_void,
    }

    /// The type whose alignment `malloc` promises to satisfy on this target.
    ///
    /// C requires an allocation to be "suitably aligned so that it may be
    /// assigned to a pointer to any type of object with a fundamental
    /// alignment requirement", which is `_Alignof(max_align_t)` -- not any
    /// particular number. `libc::max_align_t` is that type, described per
    /// target by the `libc` crate.
    #[cfg(not(all(windows, target_env = "msvc")))]
    type MallocAlignment = libc::max_align_t;

    /// The type whose alignment `malloc` promises to satisfy on this target.
    ///
    /// `libc` 0.2 describes `max_align_t` for Unix, WASI and Windows/GNU but
    /// not for Windows/MSVC, so that one target uses
    /// [`FundamentalAlign`] instead. MSVC's own guarantee is stricter than the
    /// union's -- `MEMORY_ALLOCATION_ALIGNMENT` is sixteen on 64-bit and eight
    /// on 32-bit -- so the substitution keeps the assertion below on the
    /// conservative side there too.
    #[cfg(all(windows, target_env = "msvc"))]
    type MallocAlignment = FundamentalAlign;

    /// The handle's alignment is no stricter than the C allocator guarantees.
    ///
    /// Checked at compile time against [`MallocAlignment`], which names the
    /// platform's actual promise rather than a literal. An earlier version
    /// compared against a hard-coded sixteen, which was true of the targets
    /// then in view but proved nothing: C promises `_Alignof(max_align_t)`, and
    /// a field added to [`CurlUrl`] on a target whose promise is weaker would
    /// have slipped past.
    ///
    /// The handle is a group of pointers, one `u16` and three flags, so this
    /// holds with room to spare and is expected to keep holding. If it ever
    /// fails, the fix is not to relax it: it is for [`new_handle`] to obtain
    /// the block from an allocator that takes an alignment and whose result
    /// `free` still accepts -- `posix_memalign` or C11 `aligned_alloc` -- and
    /// for `docs/MEMORY-OWNERSHIP.md` to record the new call, because
    /// `tests/data/test1560` counts allocator calls.
    const HANDLE_FITS_MALLOC_ALIGNMENT: () = {
        assert!(
            mem::align_of::<CurlUrl>() <= mem::align_of::<MallocAlignment>(),
            "the handle needs stricter alignment than the C allocator \
             guarantees on this target; curl_url() would have to allocate \
             differently"
        );
    };

    /// The handle also fits the fundamental-alignment bound, on every target.
    ///
    /// [`HANDLE_FITS_MALLOC_ALIGNMENT`] checks whichever [`MallocAlignment`]
    /// this target selected, so on all but one target the
    /// [`FundamentalAlign`] bound is never checked at all. This second
    /// assertion checks it everywhere, so that a field added to [`CurlUrl`]
    /// cannot pass on the target it was added on and fail only on Windows with
    /// MSVC, where nobody would see it until a cross build ran.
    const HANDLE_FITS_FUNDAMENTAL_ALIGNMENT: () = {
        assert!(
            mem::align_of::<CurlUrl>() <= mem::align_of::<FundamentalAlign>(),
            "the handle needs stricter alignment than the fundamental C types; \
             the Windows/MSVC arm of MallocAlignment would reject it"
        );
    };

    /// The alignment the C allocator promises on this target.
    ///
    /// The same number [`HANDLE_FITS_MALLOC_ALIGNMENT`] asserts against, made
    /// readable so that the run-time half of the check can report it instead of
    /// only comparing it.
    pub(crate) fn malloc_alignment() -> usize {
        let () = HANDLE_FITS_FUNDAMENTAL_ALIGNMENT;
        mem::align_of::<MallocAlignment>()
    }

    /// Allocates a zeroed handle block and constructs a handle in it.
    ///
    /// `curlx_calloc(1, sizeof(struct Curl_URL))` at `lib/urlapi.c` L1290 and
    /// L1312, plus the one thing C does not need: an initialised value. A
    /// zeroed block is a valid `struct Curl_URL` in C and is *not* necessarily
    /// a valid `CurlUrl` in Rust, because nothing promises that all-zero bits
    /// spell `None` for an owned buffer. So the constructor is written into
    /// the block before any reference to it exists, and the calloc's zeroing
    /// is immediately overwritten -- kept anyway, because using `malloc` here
    /// would change which allocator call the port makes and
    /// `tests/data/test1560` counts those.
    ///
    /// # Ownership
    ///
    /// **The caller owns the returned block** and must release it with
    /// [`curl_url_cleanup`], which is the obligation
    /// `include/curl/urlapi.h` L109-L110 places on the C caller.
    ///
    /// # Returns
    ///
    /// Null when the allocation fails, which is what C returns and what every
    /// caller of `curl_url()` already tests for.
    fn new_handle() -> *mut CurlUrl {
        // The compile-time alignment proof has to be reachable to be
        // evaluated; referencing it here costs nothing at run time.
        let () = HANDLE_FITS_MALLOC_ALIGNMENT;

        let block = super::c_calloc(1, mem::size_of::<CurlUrl>());
        if block.is_null() {
            return ptr::null_mut();
        }
        let handle = block.cast::<CurlUrl>();
        // SAFETY: `c_calloc` returned a non-null block of exactly
        // `size_of::<CurlUrl>()` bytes, aligned by `malloc` to at least
        // sixteen and so to at least `align_of::<CurlUrl>()` by the assertion
        // above. The block is uninitialised as far as Rust is concerned, which
        // is precisely what `write` requires: it initialises without dropping
        // whatever bits were there. No reference to the block exists yet, so
        // there is nothing this write could alias.
        unsafe { ptr::write(handle, CurlUrl::new()) };
        handle
    }

    /// `curl_url()`, `lib/urlapi.c` L1288-L1291.
    ///
    /// # Ownership
    ///
    /// As [`new_handle`]: the caller owns the result and owes it a
    /// `curl_url_cleanup()`.
    #[no_mangle]
    pub extern "C" fn curl_url() -> *mut CurlUrl {
        new_handle()
    }

    /// `curl_url_cleanup()`, `lib/urlapi.c` L1293-L1299.
    ///
    /// # Ownership
    ///
    /// **Takes ownership of the handle** and of the ten buffers it holds, and
    /// releases all eleven blocks. It does *not* release strings handed out
    /// earlier by `curl_url_get()`, which `include/curl/urlapi.h` L116-L118
    /// states explicitly and which falls out of the design here: those buffers
    /// stopped being the handle's the moment `CBuf::into_raw` was called on
    /// them.
    ///
    /// # Safety
    ///
    /// The caller must guarantee all of the following.
    ///
    /// * `handle` is null, or a pointer this crate's `curl_url()` or
    ///   `curl_url_dup()` returned, properly aligned and not already cleaned
    ///   up. Calling this twice on the same pointer frees it twice.
    /// * No other pointer to the handle is used again afterwards, and no other
    ///   reference to it -- shared or unique -- exists during the call. The
    ///   handle is *consumed*, not merely written.
    #[no_mangle]
    pub unsafe extern "C" fn curl_url_cleanup(handle: *mut CurlUrl) {
        // L1295, `if(u)`.
        if handle.is_null() {
            return;
        }
        // SAFETY: the caller's precondition says this is a live handle from
        // `curl_url()` or `curl_url_dup()`, so it is properly aligned,
        // initialised, and uniquely ours to consume. `drop_in_place` runs the
        // handle's `Drop`, which releases the ten strings -- that is
        // `free_urlhandle(u)` at L1296 -- and leaves the block itself
        // uninitialised but still allocated, which is exactly the state
        // `curlx_free(u)` at L1297 expects. Nothing reads the block
        // afterwards.
        unsafe {
            ptr::drop_in_place(handle);
            super::c_free(handle.cast::<c_void>());
        }
    }

    /// `curl_url_dup()`, `lib/urlapi.c` L1310-L1332.
    ///
    /// Reproduces the duplication `src/handle.rs` implements, **including the
    /// member it does not copy**: `guessed_scheme` is absent from L1314-L1326,
    /// so a duplicate answers differently from its original under
    /// `CURLU_NO_GUESS_SCHEME`. That is `FB1`, recorded in
    /// `docs/KNOWN-DIVERGENCES.md` and pinned by tests in both `src/handle.rs`
    /// and `src/getset.rs`.
    ///
    /// # Ownership
    ///
    /// As [`curl_url`]: the caller owns the copy and owes it its own
    /// `curl_url_cleanup()`, per `include/curl/urlapi.h` L121-L123. The
    /// original is untouched.
    ///
    /// # Safety
    ///
    /// * `input` must be null, or point to a live, initialised handle from
    ///   [`curl_url`] or [`curl_url_dup`], properly aligned, that stays valid
    ///   for the duration of the call. It is read, never written, which is what
    ///   `const CURLU *` at `include/curl/urlapi.h` L126 promises.
    /// * No other thread may write the handle while the call runs. There is no
    ///   second pointer to be disjoint from: this function takes only one.
    ///
    /// # Returns
    ///
    /// Null if any of the ten copies cannot be allocated, which is L1306's
    /// `goto fail` reaching L1330-L1331 -- and also null for a null input,
    /// which the C would instead fault on; see the module documentation.
    #[no_mangle]
    pub unsafe extern "C" fn curl_url_dup(input: *const CurlUrl) -> *mut CurlUrl {
        // SAFETY: by the caller's precondition `input` is null or an aligned,
        // live, readable handle that nothing else is writing for the duration
        // of the call, so a shared reference to it is sound; `as_ref`
        // distinguishes the two cases without dereferencing a null. The
        // reference never becomes a mutable one, which is what `const CURLU *`
        // asks of this function.
        let Some(source) = (unsafe { input.as_ref() }) else {
            return ptr::null_mut();
        };

        // L1311-L1329 in one step: `dup` performs the calloc-free part of the
        // work and reports a failed copy as `None`, which is the `goto fail`.
        let Some(copy) = source.dup() else {
            return ptr::null_mut();
        };

        // L1312's allocation, moved after the copying so that a failure needs
        // no cleanup at all. The C has to reach `curl_url_cleanup(u)` at L1330
        // on the failure path; here the copy is simply dropped.
        let handle = new_handle();
        if handle.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `new_handle` returned a block holding a valid, empty handle
        // that nothing else references. Writing the copy over it initialises
        // it a second time, which would leak the empty handle's contents if it
        // had any -- it has none by construction, ten absent strings. `write`
        // rather than an assignment through a reference because there is no
        // reference to make.
        unsafe { ptr::write(handle, copy) };
        handle
    }

    /// `curl_url_get()`, `lib/urlapi.c` L1541-L1634.
    ///
    /// This function is the three preconditions and the pointer transfer; all
    /// of the logic is `crate::getset::url_get`.
    ///
    /// # Ownership
    ///
    /// On success `*part` becomes **the caller's**, and the caller must
    /// release it with `curl_free()` -- `docs/libcurl/curl_url_get.md` L45 and
    /// `include/curl/urlapi.h` L130-L131. That call is correct because the
    /// block came from the C allocator; `src/alloc.rs` documents the whole
    /// resolution chain and the two configurations it does not support.
    /// `curl_url_cleanup()` will not release it.
    ///
    /// `*part` is set to null before anything can fail, L1552, so a caller who
    /// ignores the code cannot read a stale pointer.
    ///
    /// # Why the borrow is scoped
    ///
    /// Both writes through `part` happen while no reference to the handle
    /// exists: the L1552 null before the borrow is taken, and the result
    /// pointer after it has ended. That ordering is what makes the two pointers
    /// independent of each other, and it costs nothing -- `url_get` returns an
    /// owned buffer, so there is no borrow left to keep alive across the
    /// second write.
    ///
    /// It is not, however, licence to point `part` into the handle. The
    /// requirement below stands: writing a null over the middle of a live
    /// handle would leave it holding values its own type forbids, and the read
    /// that follows would then be reading a handle the caller has broken. The
    /// C has the same hazard in a different currency -- it would read a
    /// half-nulled `struct Curl_URL` -- and no caller in the tree does it.
    ///
    /// # Safety
    ///
    /// * `handle` must be null, or point to a live, initialised handle from
    ///   [`curl_url`] or [`curl_url_dup`], properly aligned, that stays valid
    ///   for the duration of the call. It is read, never written, which is what
    ///   `const CURLU *` at `include/curl/urlapi.h` L126 promises.
    /// * `part` must be null, or point to one properly aligned, writable
    ///   `char *` that stays valid for the duration of the call.
    /// * `part` must not point into the handle's own storage, and must not
    ///   alias anything else the call reaches.
    /// * No other thread may access the handle or `*part` while the call runs.
    ///
    /// # Returns
    ///
    /// `CURLUE_OK` with `*part` set, or `CURLUE_OK` with `*part` still null --
    /// the case `crate::getset::url_get` documents, where the C stores the null
    /// `curlx_dyn_ptr` gave it at L1399 and reports success -- or the failing
    /// part's code.
    #[no_mangle]
    pub unsafe extern "C" fn curl_url_get(
        handle: *const CurlUrl,
        what: CURLUPart,
        part: *mut *mut c_char,
        flags: c_uint,
    ) -> CURLUcode {
        // L1548-L1549, answered from the raw pointer so that no reference to
        // the handle exists yet when `*part` is written below.
        if handle.is_null() {
            return CURLUE_BAD_HANDLE;
        }
        // L1550-L1551.
        if part.is_null() {
            return CURLUE_BAD_PARTPOINTER;
        }
        // SAFETY: `part` is non-null by the test above and points to a
        // writable, aligned `char *` by the caller's precondition. Nothing
        // borrows the handle at this point, so this write cannot conflict with
        // a reference however the two pointers are related. L1552.
        unsafe { ptr::write(part, ptr::null_mut()) };

        // The borrow lives for this statement only. `url_get` hands back an
        // owned `CBuf` or a code, neither of which holds any part of it, so the
        // reference is gone before `*part` is written again.
        let result = {
            // SAFETY: `handle` is non-null by the test above and, by the
            // caller's precondition, points to a live, aligned, initialised
            // handle that stays valid for the call. The shared reference never
            // becomes a mutable one, which `const CURLU *` requires, and the
            // caller's requirement that `part` stay outside the handle means
            // the write above cannot have disturbed what it refers to.
            let u = unsafe { &*handle };
            url_get(u, what, flags)
        };

        match result {
            Ok(Some(buffer)) => {
                // L1537 and L1421. OWNERSHIP CHANGES HANDS HERE: `into_raw`
                // consumes the buffer, so this crate stops tracking the block
                // and no `Drop` will run for it. The obligation to call
                // `curl_free()` is now the caller's, and it is discharged
                // correctly because the block came from the C allocator.
                //
                // SAFETY: `part` is writable and aligned, as above, and the
                // borrow of the handle has ended, so this write conflicts with
                // no reference.
                unsafe { ptr::write(part, buffer.into_raw()) };
                CURLUE_OK
            }
            // Success with nothing to hand over. `*part` keeps the null
            // written above, which is the pointer the C would have stored.
            Ok(None) => CURLUE_OK,
            Err(code) => code,
        }
    }

    /// `curl_url_set()`, `lib/urlapi.c` L1805-L1998.
    ///
    /// As with the getter, this function is the preconditions and the string
    /// conversion; the logic is `crate::getset::url_set`.
    ///
    /// # Ownership
    ///
    /// Nothing changes hands. `part` is **copied**, which
    /// `include/curl/urlapi.h` L137-L139 promises, so the caller may free or
    /// reuse it immediately. A null `part` clears the part instead, L1819-L1821.
    ///
    /// # `part` may point into the handle
    ///
    /// The C requires no separation here either, and its setters are written
    /// so that overlap works: each one duplicates the incoming bytes before it
    /// frees what it is replacing, so `curl_url_set(u, CURLUPART_HOST, p, 0)`
    /// with `p` addressing something the handle owns is a supported C call.
    ///
    /// Rust cannot hold `&mut CurlUrl` and a `&[u8]` over the same bytes, so
    /// [`disjoint_from_handle`] decides the question before the unique
    /// reference is formed. Disjoint -- which is every real call -- borrows the
    /// input directly and costs nothing. Overlapping copies the input into an
    /// owned buffer first, which is behaviour-preserving for exactly the reason
    /// the C is safe: the bytes are read before anything is replaced either
    /// way. An allocation failure on that copy is reported as
    /// `CURLUE_OUT_OF_MEMORY`, which is the code every other failed allocation
    /// on this path already returns.
    ///
    /// # Safety
    ///
    /// * `handle` must be null, or point to a live, initialised handle from
    ///   [`curl_url`] or [`curl_url_dup`], properly aligned, that stays valid
    ///   for the duration of the call. `curl_url_set` takes a non-const
    ///   `CURLU *` at `include/curl/urlapi.h` L141-L142 and does write it.
    /// * The caller must have exclusive access to the handle for the duration
    ///   of the call: no other pointer may read or write it, and no other
    ///   thread may touch it. That is the same requirement the C has -- a
    ///   `CURLU` carries no lock -- stated rather than assumed.
    /// * `part` must be null, or point to a NUL-terminated byte string that
    ///   stays valid, readable and unmodified for the duration of the call.
    ///   Alignment is unconstrained. It **may** overlap the handle's storage.
    #[no_mangle]
    pub unsafe extern "C" fn curl_url_set(
        handle: *mut CurlUrl,
        what: CURLUPart,
        part: *const c_char,
        flags: c_uint,
    ) -> CURLUcode {
        // L1817-L1818, answered from the raw pointer so that the input can be
        // measured before any reference to the handle exists.
        if handle.is_null() {
            return CURLUE_BAD_HANDLE;
        }

        if part.is_null() {
            // SAFETY: `handle` is non-null by the test above and, by the
            // caller's precondition, points to a live, aligned, initialised
            // handle the caller has exclusive access to for this call, so the
            // unique reference is the only one there is. There is no second
            // pointer on this path at all.
            let u = unsafe { &mut *handle };
            // L1819-L1821: "setting a part to NULL clears it".
            return url_set(u, what, None, flags);
        }

        // L1823's `strlen(part)`. Taken here, through the raw pointer, so that
        // the extent is known before the decision below.
        //
        // SAFETY: `part` is non-null and, by the caller's precondition, points
        // to a NUL-terminated string that stays valid and unmodified for the
        // call. The borrow is used only to measure and, on the disjoint path,
        // to copy from; nothing in `url_set` retains it, because every byte
        // that reaches the handle is copied into a freshly allocated buffer.
        let bytes = unsafe { CStr::from_ptr(part) }.to_bytes();

        if disjoint_from_handle(part, bytes.len(), handle) {
            // SAFETY: as the null-`part` arm above for the handle. The unique
            // reference and `bytes` address provably disjoint ranges, which is
            // what `disjoint_from_handle` just established.
            let u = unsafe { &mut *handle };
            return url_set(u, what, Some(bytes), flags);
        }

        // Overlapping. Copy first, then borrow the handle uniquely, so the two
        // never describe the same bytes. `CBuf` is the crate's C-allocator
        // buffer, so this temporary is accounted for exactly like every other
        // allocation the port makes and is released by its own `Drop`.
        let Some(copy) = CBuf::from_slice(bytes) else {
            return crate::abi::CURLUE_OUT_OF_MEMORY;
        };
        // SAFETY: as above. `copy` owns its bytes and cannot overlap the
        // handle, and the borrow of `part` is not used past this point.
        let u = unsafe { &mut *handle };
        url_set(u, what, Some(copy.as_bytes()), flags)
    }

    /// Whether `[start, start + len]` and the handle's own storage are
    /// disjoint.
    ///
    /// The half-open input range is widened by one byte to take in the NUL that
    /// [`CStr::from_ptr`] read, so a terminator sitting inside the handle counts
    /// as overlap.
    ///
    /// Two ranges in different allocations can never overlap, and comparing
    /// their addresses answers that case correctly too, so no provenance
    /// question arises: the comparison is arithmetic on `usize`, not a pointer
    /// dereference, and a false "overlapping" verdict would only take the
    /// copying path, which is correct for every input.
    pub(crate) fn disjoint_from_handle(
        start: *const c_char,
        len: usize,
        handle: *const CurlUrl,
    ) -> bool {
        let input_start = start as usize;
        let input_end = input_start.saturating_add(len).saturating_add(1);
        let handle_start = handle as usize;
        let handle_end = handle_start.saturating_add(mem::size_of::<CurlUrl>());

        input_end <= handle_start || handle_end <= input_start
    }

    /// `Curl_is_absolute_url()`, `lib/urlapi.c` L182-L220, declared at
    /// `lib/urlapi-int.h` L28-L29.
    ///
    /// # Why `buf` is never borrowed as a slice
    ///
    /// `buf` is a plain C output buffer, and the C signature asks nothing of
    /// its contents. A caller is entitled to hand over a bare
    /// `char scheme[MAX_SCHEME_LEN + 1];` local it has never written to, and
    /// nothing in the declaration forbids that storage from overlapping `url`
    /// either. Both of those are ordinary C, and both are outside what a
    /// `&mut [u8]` may describe: the slice contract requires every element to
    /// be initialized and requires the borrow to be exclusive for its whole
    /// lifetime. Forming one over the caller's buffer would therefore have
    /// added two preconditions that the ABI being replaced does not have --
    /// silently, since a C caller has no way to learn of them.
    ///
    /// So the scheme is measured into storage this function owns, and the
    /// caller's buffer is then written through raw pointers alone, exactly the
    /// bytes the C writes and no others:
    ///
    /// * `buf[0] = 0`, L189's "always leave a defined value in buf", which the
    ///   C performs before it knows the answer and this does too;
    /// * on a non-zero result, the lower-cased scheme from L214 followed by the
    ///   terminator at L215.
    ///
    /// Bytes past that terminator are left untouched, as in the C. Because the
    /// source of the copy is a local array it can never overlap the caller's
    /// buffer, so a `buf` that aliases `url` is written correctly rather than
    /// being undefined behaviour, and `url` has in any case been fully read by
    /// then.
    ///
    /// # Ownership
    ///
    /// Nothing changes hands. `url` is read and `buf`, if given, is written in
    /// place in the caller's own allocation.
    ///
    /// # `buf` may be `url`
    ///
    /// The C requires no separation between its two pointers, and a caller
    /// that scans a buffer into itself -- `Curl_is_absolute_url(b, b, sizeof(b),
    /// FALSE)` -- is a perfectly ordinary C call. This function therefore
    /// never holds a shared borrow of `url` and a mutable borrow of `buf` at
    /// the same time: the scan writes into [`SCHEME_SCRATCH_LEN`] bytes of local
    /// scratch, and only once that borrow has ended are the bytes the C would
    /// have written copied out through the raw pointer. Overlap is supported,
    /// not merely tolerated, and needs no test.
    ///
    /// Two properties of the C are reproduced deliberately, and getting either
    /// wrong changes the answer rather than merely the tidiness.
    ///
    /// The first is ORDER. L188-L189 writes `buf[0] = 0` before L194 reads the
    /// input, so an aliased call has already truncated its own input by the
    /// time the scan starts. Measured against the reference build, scanning a
    /// buffer holding `HTTPS://example.com/` into itself answers zero and
    /// leaves the buffer empty. This function writes that byte first for
    /// exactly that reason.
    ///
    /// The second is EXTENT. The copy reproduces what the C writes and no more,
    /// because the C leaves everything past the scheme untouched: L188-L189
    /// writes one byte on every path, L214-L215 then writes the lowercased
    /// scheme and its terminator, and nothing else in L182-L220 writes at all.
    /// So the extent is one byte when the answer is zero and `n + 1` when it is
    /// `n`, clamped to `buflen`.
    ///
    /// # Safety
    ///
    /// * `url` must be null, or point to a NUL-terminated byte string that
    ///   stays valid, readable and unmodified for the duration of the call.
    /// * `buf` must be null, or point to `buflen` bytes that stay valid and
    ///   writable for the duration of the call. Alignment is unconstrained:
    ///   `c_char` has an alignment of one. `buf` may overlap `url`, wholly or
    ///   partly.
    /// * The C's own precondition, asserted at L186, is that `buflen` exceeds
    ///   `MAX_SCHEME_LEN` whenever `buf` is given. This function does not rely
    ///   on it: a shorter buffer is filled as far as it goes and left
    ///   unterminated, and a `buflen` of zero gets nothing written at all,
    ///   where the C would write one byte past the end. That is the bounded
    ///   direction and the only one Rust can take.
    /// * No other thread may write `url` or `buf` while the call runs.
    ///
    /// # Returns
    ///
    /// The length of the scheme, or zero for a relative URL -- and zero for a
    /// null `url`, which the C would instead fault on. The result reports what
    /// was *measured*, never how much of `buf` a short `buflen` allowed to be
    /// written, which is again what the C returns.
    #[no_mangle]
    #[allow(non_snake_case)]
    pub unsafe extern "C" fn Curl_is_absolute_url(
        url: *const c_char,
        buf: *mut c_char,
        buflen: size_t,
        guess_scheme: CurlBool,
    ) -> size_t {
        if url.is_null() {
            return 0;
        }
        let guess_scheme = curl_bool_is_true(guess_scheme);

        if buf.is_null() {
            // L188: the C tolerates a null buffer and every in-tree caller but
            // one passes exactly that. With no buffer there is no second
            // pointer, so the input can be borrowed directly.
            //
            // SAFETY: `url` is non-null and NUL-terminated by the
            // precondition, and stays valid and unmodified for the call. The
            // borrow does not outlive this statement. Taking the length here
            // is what bounds the scan at L195, which in C runs off the end
            // only because the terminator stops it.
            let bytes = unsafe { CStr::from_ptr(url) }.to_bytes();
            return is_absolute_url(bytes, None, guess_scheme);
        }

        // L188-L189, "always leave a defined value in buf", AND IT HAPPENS
        // FIRST. Ordering is behaviour here, not tidiness: when `buf` overlaps
        // `url` this write lands in the input, so the scan below sees the
        // truncated string the C's scan would have seen. Measured against the
        // reference build, `Curl_is_absolute_url(b, b, sizeof(b), FALSE)` on a
        // buffer holding "HTTPS://example.com/" answers 0 with an emptied
        // buffer, because L189 turned the first byte into the terminator before
        // L194 looked at it. Reading the input into scratch before this write
        // would answer 5 instead, which is a different function.
        //
        // The C writes unconditionally on `if(buf)` and relies on its L186
        // precondition for the room; a zero length gets nothing written here
        // rather than a byte out of bounds.
        if buflen != 0 {
            // SAFETY: `buf` is non-null by the test above and, by the caller's
            // precondition, writable for `buflen` bytes, which is at least one.
            // `c_char`'s alignment is one, so any address satisfies it. No Rust
            // reference to these bytes exists.
            unsafe { ptr::write(buf.cast::<u8>(), 0) };
        }

        // The scan's whole output, on the C's own bound: L195 stops the index
        // below `MAX_SCHEME_LEN`, or leaves it exactly at `MAX_SCHEME_LEN` when
        // every byte could continue a scheme, and L215 then writes the
        // terminator at that index. One byte more than the bound, therefore,
        // and never more than that -- which is also why the C asserts
        // `buflen > MAX_SCHEME_LEN` at L186.
        let mut scratch = [0u8; SCHEME_SCRATCH_LEN];

        // Clamped so that a caller who ignores the C's precondition gets the
        // same truncation from the scratch buffer that it would have got from
        // its own: `is_absolute_url` decides what it can write from the length
        // of the slice it is handed.
        let window = buflen.min(SCHEME_SCRATCH_LEN);

        let found = match scratch.get_mut(..window) {
            // SAFETY: `url` is non-null and, by the caller's precondition,
            // NUL-terminated and valid and unmodified for this call, which is
            // the whole of the callee's contract. `slot` is this function's own
            // stack, so it cannot alias `url`.
            Some(slot) => unsafe { is_absolute_url_into(url, slot, guess_scheme) },
            // Unreachable: `window` is at most `scratch.len()`. Written as a
            // fallible lookup because the crate root denies direct indexing,
            // and answered with the value a zero-length buffer produces.
            None => 0,
        };

        // The C's write extent, from L188-L189 and L214-L215. `saturating_add`
        // because the crate root denies unchecked arithmetic; `found` is at
        // most `MAX_SCHEME_LEN`, so it cannot saturate.
        let extent = if found == 0 {
            1
        } else {
            found.saturating_add(1)
        }
        .min(window);

        if let Some(written) = scratch.get(..extent) {
            // SAFETY: `buf` is non-null and writable for `buflen` bytes by the
            // caller's precondition, and `extent` is at most `window`, which is
            // at most `buflen`. `c_char` and `u8` have the same size and
            // alignment on every target, so the cast changes only signedness,
            // and `c_char`'s alignment of one is satisfied by any address. The
            // source is this function's own stack, so it cannot overlap the
            // caller's buffer however `buf` and `url` are related. No Rust
            // reference to `buf`'s bytes exists here or anywhere in this
            // function, and the borrow of `url` ended with the call above.
            unsafe { ptr::copy_nonoverlapping(written.as_ptr(), buf.cast::<u8>(), extent) };
        }
        found
    }

    /// Runs the scheme scan over a C string, writing into a Rust buffer.
    ///
    /// Split out so that the borrow of `url` provably ends before
    /// [`Curl_is_absolute_url`] writes through `buf`: a function body is the
    /// clearest scope there is, and the borrow cannot escape it because
    /// [`is_absolute_url`] returns a `usize`.
    ///
    /// # Safety
    ///
    /// `url` must be non-null and point to a NUL-terminated byte string that
    /// stays valid, readable and unmodified for the duration of the call. `out`
    /// is an ordinary Rust slice and carries its own guarantees; it must not
    /// alias `url`, which holds by construction because every caller passes
    /// local scratch.
    unsafe fn is_absolute_url_into(
        url: *const c_char,
        out: &mut [u8],
        guess_scheme: bool,
    ) -> usize {
        // SAFETY: forwarded verbatim from this function's own contract. The
        // borrow does not outlive the statement below, and `is_absolute_url`
        // keeps no part of it.
        let bytes = unsafe { CStr::from_ptr(url) }.to_bytes();
        is_absolute_url(bytes, Some(out), guess_scheme)
    }

    /// `Curl_junkscan()`, `lib/urlapi.c` L223-L239, declared at
    /// `lib/urlapi-int.h` L33.
    ///
    /// # Ownership
    ///
    /// Nothing changes hands.
    ///
    /// # `urllen` may point into `url`
    ///
    /// As with [`Curl_is_absolute_url`], the C requires no separation between
    /// the two. The scan therefore runs in its own scope and yields a `usize`,
    /// so the borrow of `url` has ended before `*urllen` is written. Overlap is
    /// supported and needs no test.
    ///
    /// # Safety
    ///
    /// * `url` must be null, or point to a NUL-terminated byte string that
    ///   stays valid, readable and unmodified for the duration of the call.
    ///   Alignment is unconstrained.
    /// * `urllen` must be null, or point to one properly aligned, writable
    ///   `size_t` that stays valid for the duration of the call. It may overlap
    ///   `url`.
    /// * No other thread may write `url` or `*urllen` while the call runs.
    ///
    /// # Returns
    ///
    /// `CURLUE_OK` with `*urllen` set to the length, L237, or
    /// `CURLUE_MALFORMED_INPUT` -- including for a null `url`, which the C
    /// would instead fault on. `*urllen` is written only on success, as at
    /// L237.
    #[no_mangle]
    #[allow(non_snake_case)]
    pub unsafe extern "C" fn Curl_junkscan(
        url: *const c_char,
        urllen: *mut size_t,
        allowspace: CurlBool,
    ) -> CURLUcode {
        if url.is_null() {
            return CURLUE_MALFORMED_INPUT;
        }

        // The borrow lives for this block only, so the write below cannot
        // conflict with it however the two pointers are related.
        let scanned = {
            // SAFETY: `url` is non-null and, by the caller's precondition,
            // NUL-terminated and valid and unmodified for this call. The
            // `strlen` at L225 is the borrow's own length, and `junkscan`
            // returns a `usize` that keeps no part of it.
            let bytes = unsafe { CStr::from_ptr(url) }.to_bytes();
            junkscan(bytes, curl_bool_is_true(allowspace))
        };

        match scanned {
            Ok(length) => {
                if !urllen.is_null() {
                    // SAFETY: `urllen` is non-null by the test and points to a
                    // writable, aligned `size_t` by the caller's precondition.
                    // No borrow of `url` is live here. L237.
                    unsafe { ptr::write(urllen, length) };
                }
                CURLUE_OK
            }
            Err(code) => code,
        }
    }

    /// `Curl_url_set_authority()`, `lib/urlapi.c` L658-L675, declared at
    /// `lib/urlapi-int.h` L31.
    ///
    /// Its only consumer is `lib/http2.c` L739, and it is the one entry point
    /// that operates on a **live** handle rather than a parse temporary --
    /// which is what makes the `FB2` finding observable at all.
    /// `src/parse/authority.rs` owns that reproduction.
    ///
    /// # Ownership
    ///
    /// Nothing changes hands. `authority` is copied.
    ///
    /// # `authority` may point into the handle
    ///
    /// Handled exactly as in [`curl_url_set`], and it matters more here than
    /// there: this is the one entry point that operates on a live handle, so a
    /// caller passing a pointer the handle itself owns is the plausible case
    /// rather than the contrived one. [`disjoint_from_handle`] decides before
    /// the unique reference is formed; overlap takes an owned copy.
    ///
    /// # Safety
    ///
    /// * `u` must be null, or point to a live, initialised handle from
    ///   [`curl_url`] or [`curl_url_dup`], properly aligned, that stays valid
    ///   for the duration of the call. It is written.
    /// * The caller must have exclusive access to the handle for the duration
    ///   of the call: no other pointer may read or write it, and no other
    ///   thread may touch it.
    /// * `authority` must be null, or point to a NUL-terminated byte string
    ///   that stays valid, readable and unmodified for the duration of the
    ///   call. Alignment is unconstrained. It **may** overlap the handle's
    ///   storage.
    ///
    /// # Returns
    ///
    /// Whatever the authority parse reported, or `CURLUE_BAD_HANDLE` for a
    /// null handle, or `CURLUE_MALFORMED_INPUT` for a null authority -- the
    /// second and third being answers the C does not have, since it tests
    /// neither pointer.
    #[no_mangle]
    #[allow(non_snake_case)]
    pub unsafe extern "C" fn Curl_url_set_authority(
        u: *mut CurlUrl,
        authority: *const c_char,
    ) -> CURLUcode {
        if u.is_null() {
            return CURLUE_BAD_HANDLE;
        }
        if authority.is_null() {
            return CURLUE_MALFORMED_INPUT;
        }

        // L672's `strlen(authority)`, taken through the raw pointer so that the
        // extent is known before the handle is borrowed.
        //
        // SAFETY: `authority` is non-null and, by the caller's precondition,
        // NUL-terminated and valid and unmodified for this call.
        let bytes = unsafe { CStr::from_ptr(authority) }.to_bytes();

        if disjoint_from_handle(authority, bytes.len(), u) {
            // SAFETY: `u` is non-null by the test above and, by the caller's
            // precondition, a live, aligned, initialised handle the caller has
            // exclusive access to for this call. The unique reference and
            // `bytes` address provably disjoint ranges.
            let handle = unsafe { &mut *u };
            return crate::parse::authority::url_set_authority(handle, bytes);
        }

        // Overlapping: copy before borrowing, as `curl_url_set` does and for
        // the same reason.
        let Some(copy) = CBuf::from_slice(bytes) else {
            return crate::abi::CURLUE_OUT_OF_MEMORY;
        };
        // SAFETY: as above. `copy` owns its bytes and cannot overlap the
        // handle.
        let handle = unsafe { &mut *u };
        crate::parse::authority::url_set_authority(handle, copy.as_bytes())
    }

    /// `curl_url_strerror()`, `lib/strerror.c` L420-L531.
    ///
    /// **Feature-gated, and the gate is not optional.** The function is not in
    /// `lib/urlapi.c` at all: it lives in `lib/strerror.c`, which stays in the
    /// archive in drop-in mode, so exporting this unconditionally would define
    /// the symbol twice. The `strerror` feature is on by default for the
    /// standalone link, where the demo calls it and no libcurl supplies it,
    /// and must be off for the drop-in link.
    ///
    /// # Ownership
    ///
    /// **Nothing changes hands.** The returned pointer addresses a `'static`
    /// string literal in this object's read-only data, exactly as the C's
    /// strings live in `strerror.c.o`. The caller must not free it, and
    /// `docs/libcurl/curl_url_strerror.md` imposes no obligation -- unlike
    /// `curl_url_get`, this is the one string-returning entry point of the API
    /// whose result did not come from an allocator.
    #[cfg(feature = "strerror")]
    #[no_mangle]
    pub extern "C" fn curl_url_strerror(code: CURLUcode) -> *const c_char {
        crate::error::strerror(code)
    }

    /// `curl_free()`, `lib/escape.c` L189-L192.
    ///
    /// **Feature-gated for the same reason as [`curl_url_strerror`]**: the
    /// symbol is defined in `escape.c.o`, which stays in the archive in
    /// drop-in mode. The `cfree` feature exists so that the standalone link
    /// can release the buffers `curl_url_get` hands out, which
    /// `include/curl/urlapi.h` L130-L131 requires be released with exactly
    /// this function.
    ///
    /// # Ownership
    ///
    /// **Takes ownership of the pointer and releases it.** Correct for every
    /// pointer this crate hands out, because every one of them is a block from
    /// the C allocator; `src/alloc.rs` documents the chain and the two
    /// configurations reported as unsupported rather than worked around,
    /// memory-debug builds and applications that install their own allocators.
    ///
    /// # Safety
    ///
    /// The caller must guarantee all of the following.
    ///
    /// * `p` is null, or a pointer this crate handed out -- one that came from
    ///   the C allocator through `src/alloc.rs` -- and that has not already
    ///   been released.
    /// * No other pointer to that block is used afterwards, and no reference
    ///   into it exists during the call. The block is *consumed*.
    /// * The C allocator that produced the block is the one `free` releases.
    ///   This holds for the standalone link, which is the only one that
    ///   compiles this export at all; the two configurations it does not hold
    ///   for are recorded in `src/alloc.rs` and in `docs/MEMORY-OWNERSHIP.md`.
    #[cfg(feature = "cfree")]
    #[no_mangle]
    pub unsafe extern "C" fn curl_free(p: *mut c_void) {
        // SAFETY: the caller's precondition is exactly `free`'s. The forward
        // is `lib/escape.c` L191, one line.
        unsafe { super::curl_free(p) };
    }
}

#[cfg(test)]
mod tests {
    // The crate root denies the panicking constructs so that no panic can
    // ever reach the C boundary. A test's entire job is to panic when an
    // assertion fails, and a test never crosses that boundary, so the
    // denials are relaxed here and only here. The allowance is scoped to
    // this module and enumerated rather than blanket, matching
    // `src/alloc.rs` and `src/dynbuf.rs`.
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::arithmetic_side_effects)]

    // Imported by name rather than through a glob, which is the rule the plan
    // sets for the whole crate at AAP 0.4.3, split across several statements
    // only so that no line grows unreadably long.
    use super::{adopt_c_bytes, adopt_c_string, c_calloc, c_free, c_malloc};
    use super::{c_memdup0, c_realloc, c_strdup_raw, curl_free, CBlock, MAX_ALLOC};
    use crate::alloc::{c_concat, c_maprintf, c_strdup, CBuf};
    use crate::dynbuf::DynBuf;
    use crate::error::CURLcode;
    use core::ptr;
    use core::slice;
    use libc::{c_char, c_void};

    /// Adopts a pointer one of the helpers here produced, so `Drop` releases
    /// it.
    ///
    /// Every test that receives a raw pointer routes it through here, which
    /// means no test leaks and a run under `valgrind --leak-check=full` stays
    /// clean. That matters more than usual: a leak in the allocator adapter is
    /// invisible to the parity diff and would surface only as slow growth.
    ///
    /// # Safety
    ///
    /// `p` must be a live NUL-terminated C string from this module's allocator
    /// that no one else will release.
    unsafe fn adopt(p: *mut c_char) -> CBuf {
        // SAFETY: forwarded from this function's own contract, which is
        // `adopt_c_string`'s contract for a non-null pointer.
        let buf = unsafe { adopt_c_string(p) };
        buf.unwrap()
    }

    #[test]
    fn c_malloc_round_trips_and_frees() {
        let p = c_malloc(32);
        assert!(!p.is_null(), "a 32-byte allocation should succeed");
        // `c_malloc` is `malloc`, so these 32 bytes are uninitialized and no
        // reference may be formed over them yet. They are initialized with a
        // raw write first -- the same rule `CBlock::resize` follows for the
        // extent `realloc` adds -- and only then read back through a slice.
        // SAFETY: `p` is a live block of exactly 32 bytes, `write_bytes` writes
        // 32 of them and reads none, and it forms no reference. `u8` needs no
        // alignment beyond one byte.
        unsafe { ptr::write_bytes(p.cast::<u8>(), 0xa5, 32) };
        // SAFETY: all 32 bytes are now initialized by the write above, so a
        // shared slice over the block reads only initialized memory and lies
        // wholly inside the allocation.
        let bytes = unsafe { slice::from_raw_parts(p.cast::<u8>(), 32) };
        assert!(bytes.iter().all(|&b| b == 0xa5));
        // SAFETY: `p` came from `c_malloc` above and has not been freed.
        unsafe { c_free(p) };
    }

    #[test]
    fn c_malloc_returns_null_for_zero_and_absurd_sizes() {
        // Deterministic rejection rather than the platform's unspecified
        // answer to `malloc(0)`. This one is this module's own guard, so it is
        // asserted directly.
        assert!(c_malloc(0).is_null());
        // An impossible request must return rather than abort. That is the
        // property every caller relies on when it treats the result as
        // out-of-memory, and it is what is asserted here: that the call comes
        // back at all.
        //
        // Whether the allocator actually refuses is deliberately not asserted.
        // Under optimization LLVM is entitled to assume an allocation call
        // succeeds and to fold the null test away, and it does: with the
        // release profile's link-time optimization these requests come back
        // non-null. An assertion on the null would therefore be a statement
        // about the optimizer rather than about this function, and it failed in
        // `cargo test --release` while passing in `cargo test`. Any block that
        // does materialize is released, so the test leaks nothing either way.
        for absurd in [usize::MAX, usize::MAX / 2] {
            let p = c_malloc(absurd);
            if !p.is_null() {
                // SAFETY: `p` came from `c_malloc` immediately above and has
                // not been freed.
                unsafe { c_free(p) };
            }
        }
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
        // Uninitialized on arrival, so the four bytes are stored with a raw
        // copy rather than through a `&mut [u8]` that would claim they were
        // already initialized.
        // SAFETY: `small` is a non-null 4-byte block from `c_malloc`, the source
        // is a four-byte literal, and a fresh allocation cannot overlap a static.
        unsafe { ptr::copy_nonoverlapping(b"curl".as_ptr(), small.cast::<u8>(), 4) };
        // SAFETY: `small` is a live block from this module's allocator and has
        // not been freed, which is `c_realloc`'s precondition.
        let big = unsafe { c_realloc(small, 64) };
        assert!(!big.is_null());
        // SAFETY: on success `c_realloc` returned a 64-byte block whose first
        // four bytes carry the old contents.
        let head = unsafe { slice::from_raw_parts(big.cast::<u8>(), 4) };
        assert_eq!(head, b"curl".as_slice());
        // SAFETY: ownership moved from `small` to `big`, so `big` is the only
        // live pointer and freeing it once is correct.
        unsafe { c_free(big) };
    }

    #[test]
    fn c_realloc_rejects_zero_and_keeps_the_original() {
        let p = c_malloc(8);
        assert!(!p.is_null());
        // SAFETY: `p` is a live block from `c_malloc`.
        let out = unsafe { c_realloc(p, 0) };
        assert!(
            out.is_null(),
            "realloc(p, 0) is implementation-defined in C and is refused here"
        );
        // The contract says a null return leaves the original alive, so `p` is
        // still this test's to write and to free. The write is raw because the
        // block came from `malloc` and is therefore still uninitialized.
        // SAFETY: `p` was untouched by the refused call above, so it is still
        // a live 8-byte block from this module's allocator; `write_bytes`
        // writes eight bytes, reads none and forms no reference.
        unsafe { ptr::write_bytes(p.cast::<u8>(), b'z', 8) };
        // SAFETY: as above, and this is its single release.
        unsafe { c_free(p) };
    }

    #[test]
    fn c_realloc_refuses_a_size_past_max_alloc_and_keeps_the_original() {
        // The same ceiling `c_malloc` and `c_calloc` apply, applied here so that
        // every raw entry point in this module agrees on what a representable
        // block is. A refusal is a null return, which by this function's
        // contract means the original block is untouched.
        let p = c_malloc(8);
        assert!(!p.is_null());
        // SAFETY: `p` is a live eight-byte block from `c_malloc`.
        let out = unsafe { c_realloc(p, MAX_ALLOC.saturating_add(1)) };
        assert!(out.is_null(), "a size past MAX_ALLOC is refused");
        // SAFETY: the refused call above allocated and freed nothing, so `p` is
        // still a live eight-byte block owned here; the write is raw because a
        // `malloc` block is uninitialized until something stores into it.
        unsafe { ptr::write_bytes(p.cast::<u8>(), b'k', 8) };
        // SAFETY: as above, and this is its single release.
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
        // This is the round trip the whole allocator exists for: a buffer
        // allocated by the adapter and released through the exported free
        // function, exactly as a caller of curl_url_get() would do.
        // SAFETY: `p` is a live block from `c_strdup` that nothing else owns,
        // which is `curl_free`'s precondition.
        unsafe { curl_free(p.cast::<c_void>()) };
    }

    #[test]
    fn c_strdup_raw_duplicates_a_c_string() {
        // The DUP macro at lib/urlapi.c:L1301-L1308 duplicates a string that
        // came from C rather than one this crate built, which is the shape
        // this function exists for.
        let first = c_strdup(b"example.com");
        assert!(!first.is_null());
        // SAFETY: `first` is a live NUL-terminated string from the adapter.
        let second = unsafe { c_strdup_raw(first) };
        assert!(!second.is_null());
        assert_ne!(first, second, "a copy, not the same pointer");
        // SAFETY: both are live NUL-terminated strings from this module's
        // allocator, each adopted exactly once.
        let (a, b) = unsafe { (adopt(first), adopt(second)) };
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_eq!(b.as_bytes(), b"example.com".as_slice());
    }

    #[test]
    fn c_strdup_raw_returns_null_for_null() {
        // SAFETY: a null source is explicitly permitted by the contract and
        // must be reported rather than dereferenced.
        assert!(unsafe { c_strdup_raw(ptr::null()) }.is_null());
    }

    #[test]
    fn c_memdup0_copies_exactly_len_bytes_and_terminates() {
        // curlx_memdup0 as lib/urlapi.c:L1028, L1052, L1086 and L1367 use it:
        // a prefix of a longer string, terminated at the requested length.
        let whole = c_strdup(b"example.com/path");
        assert!(!whole.is_null());
        // SAFETY: `whole` is a live 16-byte string, so its first 4 bytes are
        // readable, which is what a length of 4 requires.
        let part = unsafe { c_memdup0(whole, 4) };
        assert!(!part.is_null());
        // SAFETY: both are live NUL-terminated strings from this module's
        // allocator, each adopted exactly once.
        let (all, four) = unsafe { (adopt(whole), adopt(part)) };
        assert_eq!(four.len(), 4);
        assert_eq!(four.as_bytes(), b"exam".as_slice());
        assert_eq!(four.as_bytes_with_nul(), b"exam\0".as_slice());
        assert_eq!(all.len(), 16, "the source is untouched");
    }

    #[test]
    fn c_memdup0_accepts_a_null_source_at_zero_length() {
        // Zero bytes to copy means the source is never read, so a null
        // pointer is answerable with the empty string rather than a failure.
        // SAFETY: a null source at zero length is explicitly permitted.
        let p = unsafe { c_memdup0(ptr::null(), 0) };
        assert!(!p.is_null());
        // SAFETY: `p` is a live one-byte NUL-terminated block from this
        // module's allocator, adopted exactly once.
        let buf = unsafe { adopt(p) };
        assert!(buf.is_empty());
        assert_eq!(buf.as_bytes_with_nul(), b"\0".as_slice());
        // A null source with something to copy is a caller error and is
        // reported rather than dereferenced.
        // SAFETY: the guard rejects the request before `src` is read.
        assert!(unsafe { c_memdup0(ptr::null(), 4) }.is_null());
    }

    #[test]
    fn c_memdup0_rejects_a_length_that_cannot_be_terminated() {
        let src = c_strdup(b"x");
        assert!(!src.is_null());
        // usize::MAX + 1 for the terminator would wrap to zero and yield a
        // one-byte block for an enormous string. This is curlx_memdup0's own
        // `length < SIZE_MAX` guard at lib/curlx/strdup.c:L87, and the
        // checked_add here rejects it before the allocator or `src` is reached
        // at all, so the null is deterministic and is asserted directly.
        // SAFETY: the length check rejects the request before `src` is read,
        // so no out-of-bounds read can occur despite the absurd length.
        assert!(unsafe { c_memdup0(src, usize::MAX) }.is_null());
        // A merely impossible length is *not* exercised here, and the reason
        // is a soundness one rather than a coverage one. `c_memdup0`'s
        // contract requires `src` to be valid for reads of `len` bytes, so
        // calling it with `usize::MAX / 2` over a two-byte block breaks that
        // contract; nothing but the allocation failing first keeps the copy
        // from running, and an allocation failure is not something a caller
        // may rely on to hold a safety precondition up. The "an impossible
        // request returns rather than aborts" property belongs to `c_malloc`,
        // which is where `c_malloc_returns_null_for_zero_and_absurd_sizes`
        // asserts it, with no safety contract to break.
        // SAFETY: `src` is still live; the failed call above freed nothing.
        drop(unsafe { adopt(src) });
    }

    #[test]
    fn cblock_alloc_starts_with_an_empty_initialized_prefix() {
        // Invariant 4, and the property that lets `src/alloc.rs` and
        // `src/dynbuf.rs` hold to `#![forbid(unsafe_code)]` over a block that
        // came from `malloc`: the slice faces are bounded by the prefix, so
        // they can only ever read memory a write has reached. The block is
        // `malloc`ed rather than `calloc`ed, which is what `curlx_memdup0` at
        // lib/curlx/strdup.c:L89 and `dyn_nappend()` at
        // lib/curlx/dynbuf.c:L105 do.
        let block = CBlock::alloc(64).unwrap();
        assert_eq!(block.capacity(), 64);
        assert_eq!(block.initialized(), 0);
        assert!(block.bytes().is_empty(), "nothing is readable yet");
    }

    #[test]
    fn cblock_alloc_refuses_a_zero_capacity() {
        assert!(CBlock::alloc(0).is_none());
    }

    #[test]
    fn cblock_put_extends_the_prefix_by_exactly_what_it_writes() {
        let mut block = CBlock::alloc(16).unwrap();
        assert!(block.put(0, b"curl"));
        assert_eq!(block.initialized(), 4);
        assert_eq!(block.bytes(), b"curl".as_slice());
        // Appending at the prefix extends it; the bytes above stay unreadable.
        assert!(block.put(4, b"!"));
        assert_eq!(block.bytes(), b"curl!".as_slice());
        // Overwriting inside the prefix does not move it.
        assert!(block.put(0, b"CURL"));
        assert_eq!((block.initialized(), block.bytes()), (5, b"CURL!".as_ref()));
        // A gap is refused: no single length could then describe what is
        // initialized, so the write is rejected rather than performed.
        assert!(!block.put(6, b"x"), "offset above the prefix is refused");
        assert_eq!(block.initialized(), 5, "and nothing moved");
        // Past the capacity is refused too.
        assert!(!block.put(5, &[0; 12]));
        assert_eq!(block.initialized(), 5);
        // An empty copy is a no-op, as it is at lib/curlx/dynbuf.c:L114.
        assert!(block.put(5, b""));
        assert_eq!(block.initialized(), 5);
    }

    #[test]
    fn cblock_put_byte_and_push_write_one_byte_each() {
        let mut block = CBlock::alloc(4).unwrap();
        assert!(block.push(b'a'));
        assert!(block.push(b'b'));
        assert_eq!(block.bytes(), b"ab".as_slice());
        // The terminator write of curlx_memdup0, lib/curlx/strdup.c:L94.
        assert!(block.put_byte(2, 0));
        assert_eq!(block.bytes(), b"ab\0".as_slice());
        assert!(block.push(b'c'));
        assert_eq!(block.bytes(), b"ab\0c".as_slice());
        // Full: the next append has nowhere to go.
        assert!(!block.push(b'd'));
        assert_eq!(block.initialized(), 4);
    }

    #[test]
    fn cblock_resize_grows_and_leaves_the_new_space_uninitialized() {
        let mut block = CBlock::alloc(8).unwrap();
        assert!(block.put(0, &[0xa5; 8]));
        assert!(block.resize(32));
        assert_eq!(block.capacity(), 32);
        // The old contents survive, which is C's realloc contract.
        assert_eq!(block.bytes(), [0xa5; 8].as_slice());
        // The newly exposed tail is not initialized and is not readable, which
        // is exactly what `realloc` leaves behind: nothing zeroes it, because
        // dyn_nappend() at lib/curlx/dynbuf.c:L104-L117 does not either.
        assert_eq!(block.initialized(), 8);
        assert!(block.put(8, b"more"));
        assert_eq!(block.initialized(), 12);
    }

    #[test]
    fn cblock_resize_never_exposes_the_new_tail_on_successive_growths() {
        // The doubling `crate::dynbuf::DynBuf::ensure` performs at
        // lib/curlx/dynbuf.c:L96-L102, which is how a plain URL encode reaches
        // `resize` several times in a row. Each step must leave invariant 3
        // true, not merely the first growth: the tail `realloc` hands back is
        // uninitialized every time. It is neither cleared nor reachable -- the
        // prefix does not move, so the slice faces still end where the written
        // bytes end, and `dyn_nappend()` writes each byte exactly once.
        let mut block = CBlock::alloc(4).unwrap();
        assert!(block.put(0, &[0xa5; 4]));
        let mut filled = 0_usize;
        for cap in [8_usize, 16, 32, 64, 128, 4096] {
            filled = block.initialized();
            assert!(block.resize(cap), "growth to {cap} must succeed");
            assert_eq!(block.capacity(), cap);
            assert_eq!(
                block.initialized(),
                filled,
                "growth to {cap} must not widen the initialized prefix"
            );
            let seen = block.bytes();
            assert_eq!(
                seen.len(),
                filled,
                "the slice face must stop at the prefix at {cap}"
            );
            assert!(
                seen.iter().all(|&b| b == 0xa5),
                "realloc preserves the old contents"
            );
            // One more written byte extends the prefix by exactly one, so the
            // tail becomes reachable only as it is written.
            assert!(block.put(filled, &[0xa5]));
            assert_eq!(block.initialized(), filled.saturating_add(1));
        }
        assert_eq!(filled, 9, "the loop really grew six times");
    }

    #[test]
    fn cblock_resize_refuses_a_capacity_past_max_alloc() {
        // A block larger than `isize::MAX` could never be viewed as a slice, so
        // the request is refused here rather than recorded and discovered
        // later. The old block stays owned by the value, unchanged.
        let mut block = CBlock::alloc(8).unwrap();
        assert!(block.put(0, b"qqqqqqqq"));
        assert!(!block.resize(MAX_ALLOC.saturating_add(1)));
        assert_eq!(block.capacity(), 8);
        assert_eq!(block.initialized(), 8);
        assert!(block.bytes().iter().all(|&b| b == b'q'));
    }

    #[test]
    fn cblock_resize_is_a_no_op_at_the_same_capacity() {
        // The skip at lib/curlx/dynbuf.c:L104, which is what keeps the
        // byte-at-a-time loop at lib/urlapi.c:L806 to a logarithmic number of
        // reallocations.
        let mut block = CBlock::alloc(16).unwrap();
        assert!(block.put(0, b"x"));
        assert!(block.resize(16));
        assert_eq!(block.capacity(), 16);
        assert_eq!(block.bytes(), b"x".as_slice());
        // A zero capacity is refused, leaving the block as it was.
        assert!(!block.resize(0));
        assert_eq!(block.capacity(), 16);
        assert_eq!(block.bytes(), b"x".as_slice());
    }

    #[test]
    fn cblock_resize_shrinks_and_keeps_the_prefix() {
        let mut block = CBlock::alloc(64).unwrap();
        assert!(block.put(0, b"curl!"));
        assert!(block.resize(5));
        assert_eq!(block.capacity(), 5);
        assert_eq!(block.bytes(), b"curl!".as_slice());
        // A shrink below the content truncates the prefix with it: bytes
        // outside the block cannot be described as initialized.
        assert!(block.resize(2));
        assert_eq!((block.capacity(), block.initialized()), (2, 2));
        assert_eq!(block.bytes(), b"cu".as_slice());
    }

    #[test]
    fn cblock_into_raw_hands_over_and_from_raw_takes_back() {
        let mut block = CBlock::alloc(12).unwrap();
        assert!(block.put(0, b"example.com"));
        assert!(block.put_byte(11, 0));
        let raw = block.into_raw();
        assert!(!raw.is_null(), "into_raw never yields null");
        // SAFETY: `raw` is the live 12-byte NUL-terminated block just
        // relinquished, and nothing else owns it, so adopting it makes this
        // scope the sole owner again.
        let (back, len) = unsafe { CBlock::from_raw(raw) }.unwrap();
        assert_eq!(len, 11, "measured with strlen, so the terminator decides");
        assert_eq!(back.capacity(), 12);
        assert_eq!(back.bytes(), b"example.com\0".as_slice());
    }

    #[test]
    fn cblock_adopters_report_a_null_pointer() {
        // Null in, None out, so a C allocation failure forwards cleanly
        // without a separate check at the call site.
        // SAFETY: a null pointer is explicitly permitted by every contract
        // below, and each must report rather than dereference.
        unsafe {
            assert!(CBlock::from_raw(ptr::null_mut()).is_none());
            assert!(CBlock::from_raw_parts(ptr::null_mut(), 8).is_none());
            assert!(adopt_c_string(ptr::null_mut()).is_none());
            assert!(adopt_c_bytes(ptr::null_mut(), 0).is_none());
        }
        let block = CBlock::alloc(4).unwrap();
        let raw = block.into_raw();
        // A zero capacity is refused, so the block has to be reclaimed
        // through the other door to keep the test leak-free.
        // SAFETY: `raw` is a live four-byte block nothing else owns.
        unsafe {
            assert!(CBlock::from_raw_parts(raw, 0).is_none());
            c_free(raw.cast::<c_void>());
        }
    }

    #[test]
    fn adopt_c_string_reclaims_a_buffer_the_adapter_handed_out() {
        // The exact inverse of CBuf::into_raw, which is the transfer
        // lib/urlapi.c performs at L1025, L1049, L1077, L1185, L1399, L1489
        // and L1957. Were the release not suppressed on the way out, the read
        // below would be a use after free and a run under valgrind would say
        // so.
        let raw = CBuf::from_slice(b"handed over").unwrap().into_raw();
        assert!(!raw.is_null());
        // SAFETY: `raw` is the live block just relinquished, and nothing else
        // owns it, so adopting it makes this scope the sole owner.
        let back = unsafe { adopt(raw) };
        assert_eq!(back.as_bytes(), b"handed over".as_slice());
        assert_eq!(back.len(), 11);
    }

    #[test]
    fn adopt_c_bytes_takes_a_shorter_view_and_terminates() {
        // A block wider than the logical length, which the CBuf invariant
        // permits and lib/urlapi.c relies on at L1185 and friends. The
        // terminator is written by the adopter rather than assumed.
        let raw = CBuf::from_slice(b"example.com/path").unwrap().into_raw();
        // SAFETY: `raw` is a live 16-byte block plus terminator from the
        // adapter, so it is at least 11 + 1 bytes, all of them initialized,
        // and nothing else owns it.
        let buf = unsafe { adopt_c_bytes(raw, 11) }.unwrap();
        assert_eq!(buf.len(), 11);
        assert_eq!(buf.as_bytes(), b"example.com".as_slice());
        assert_eq!(buf.as_bytes_with_nul(), b"example.com\0".as_slice());
    }

    #[test]
    fn dynbuf_into_raw_hands_over_a_block_this_module_can_adopt() {
        // The raw handover at lib/urlapi.c:L672, L813, L1025, L1049, L1077,
        // L1185, L1399, L1489, L1934 and L1957. `src/dynbuf.rs` cannot test
        // this itself, because reclaiming the pointer needs an adopter and
        // that module forbids `unsafe`; the transfer is exercised here, next
        // to the adopter it needs.
        let mut buf = DynBuf::new(8_000_000);
        assert_eq!(buf.addn(b"example.com/path"), CURLcode::CURLE_OK);
        let len = buf.len();
        let raw = buf.into_raw();
        assert!(!raw.is_null());
        // SAFETY: `raw` came from a C-allocator block owned by the buffer, it
        // is at least `len + 1` initialized bytes, `into_raw` moved the block
        // out so the buffer released nothing, and no other owner exists.
        let adopted = unsafe { adopt_c_bytes(raw, len) }.unwrap();
        assert_eq!(adopted.as_bytes(), b"example.com/path".as_slice());
        assert_eq!(adopted.len(), len);
    }

    #[test]
    fn dynbuf_into_raw_reports_the_absent_allocation() {
        // C's null return at lib/curlx/dynbuf.c:L242, which lib/urlapi.c:L1934
        // takes and L1936 and L1995 both handle.
        assert!(DynBuf::new(8_000_000).into_raw().is_null());
    }

    #[test]
    fn the_raw_faces_of_the_adapter_round_trip() {
        // `c_strdup`, `c_concat` and `c_maprintf` are one-line wrappers that
        // build a `CBuf` and relinquish it, so their bodies are exactly this
        // transfer. `src/alloc.rs` tests the constructors; this tests that the
        // pointer they hand out is one this crate can take back and free.
        let text = c_strdup(b"https");
        assert!(!text.is_null());
        // SAFETY: each pointer below is a live NUL-terminated string from the
        // adapter, adopted exactly once.
        let text = unsafe { adopt(text) };
        assert_eq!(text.as_bytes(), b"https".as_slice());

        let joined = c_concat(&[b"file://", b"", b"/tmp/x"]);
        assert!(!joined.is_null());
        // SAFETY: as above.
        let joined = unsafe { adopt(joined) };
        assert_eq!(joined.as_bytes(), b"file:///tmp/x".as_slice());

        let port = c_maprintf(format_args!("{}", 8080_u16));
        assert!(!port.is_null());
        // SAFETY: as above.
        let port = unsafe { adopt(port) };
        assert_eq!(port.as_bytes(), b"8080".as_slice());
    }

    #[test]
    fn repeated_allocation_and_release_stays_balanced() {
        // Exercises every raw path many times over. The assertions check
        // correctness; the point of the repetition is that a leak or a double
        // free becomes loud under a leak checker.
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
            // SAFETY: `joined` is live and NUL-terminated, so duplicating it
            // through the raw face reads only initialized bytes.
            let copy = unsafe { c_strdup_raw(joined.as_bytes_with_nul().as_ptr().cast()) };
            assert!(!copy.is_null());
            // SAFETY: `copy` is a live NUL-terminated string from
            // `c_strdup_raw`, adopted exactly once in this iteration.
            drop(unsafe { adopt(copy) });
        }
    }

    /// The exported symbols, driven through their C signatures.
    ///
    /// The tests above cover section 1, the allocator every other section is
    /// built on. These cover section 6, and they call every symbol it defines
    /// exactly as C does: raw pointers in, raw
    /// pointers and integer codes out, no Rust-side convenience path. That is
    /// the point. `crate::getset` and `crate::parse` already test the logic
    /// against `lib/urlapi.c` line by line, so what is left to check is the
    /// skin -- the pointer validation, the representation conversion and the
    /// ownership transfer -- and the only honest way to check a C signature is
    /// to use it as a C caller would.
    ///
    /// A separate module rather than more functions above, because the import
    /// set is disjoint: nothing here touches the allocator primitives and
    /// nothing above touches [`crate::abi`].
    ///
    /// Every buffer a getter hands over is reclaimed before the test ends,
    /// either by adopting it back through [`adopt_c_string`] or by handing it
    /// to the exported `curl_free`. That is a property of the test bodies
    /// below, checkable by reading them: each `get` is paired with exactly one
    /// release, so the module leaks nothing it was given and frees nothing
    /// twice. Whether a particular run is clean under a leak checker is a
    /// measurement, not a property of this file, and no such measurement is
    /// asserted here.
    mod c_surface {
        use crate::abi::{
            CURLUPart, CURLUE_BAD_HANDLE, CURLUE_BAD_PARTPOINTER, CURLUE_MALFORMED_INPUT,
            CURLUE_NO_FRAGMENT, CURLUE_NO_QUERY, CURLUE_NO_SCHEME, CURLUE_OK, CURLUE_UNKNOWN_PART,
        };
        use crate::abi::{
            CURLUPART_FRAGMENT, CURLUPART_HOST, CURLUPART_PASSWORD, CURLUPART_PATH, CURLUPART_PORT,
            CURLUPART_QUERY, CURLUPART_SCHEME, CURLUPART_URL, CURLUPART_USER, CURLUPART_ZONEID,
        };
        use crate::abi::{CURLU_GUESS_SCHEME, CURLU_NO_GUESS_SCHEME, MAX_SCHEME_LEN};
        use crate::alloc::CBuf;
        use crate::ffi::{adopt_c_string, exports};
        use crate::handle::CurlUrl;
        use core::ptr;
        use libc::{c_char, c_void, size_t};

        /// C's `TRUE`, in whichever representation [`exports::CurlBool`] has.
        ///
        /// `lib/curl_setup.h` L1046-L1052 defines `TRUE` as 1 for every one of
        /// the three, so the literal is right in all three configurations and
        /// these two constants are what keeps the tests below from having to
        /// know which one is selected.
        const C_TRUE: exports::CurlBool = 1;

        /// C's `FALSE`, in whichever representation [`exports::CurlBool`] has.
        const C_FALSE: exports::CurlBool = 0;

        /// A live handle, or a failed test.
        ///
        /// Every test starts here, and an allocation failure is a failure of
        /// the test rather than a case to handle: the assertion says so
        /// instead of silently returning.
        fn handle() -> *mut CurlUrl {
            let u = exports::curl_url();
            assert!(!u.is_null(), "curl_url() must return a handle");
            u
        }

        /// `curl_url_set(u, what, part, flags)` with a Rust byte literal.
        ///
        /// The literal must end in NUL, which is checked rather than assumed,
        /// so that a malformed literal is a loud test bug and not a read past
        /// the end of a static.
        fn set(u: *mut CurlUrl, what: CURLUPart, terminated: &[u8], flags: u32) -> i32 {
            assert_eq!(
                terminated.iter().position(|&b| b == 0),
                Some(terminated.len().wrapping_sub(1)),
                "test literal must end in exactly one NUL and hold no other"
            );
            // SAFETY: `u` is a live handle from `handle()` and the pointer is
            // to a static byte literal just verified to end in exactly one
            // NUL, which is `curl_url_set`'s precondition. The literal
            // outlives the call.
            unsafe { exports::curl_url_set(u, what, terminated.as_ptr().cast::<c_char>(), flags) }
        }

        /// A recognisable non-null address to seed an out-parameter with.
        ///
        /// Deliberately not a readable address: it exists to be compared, and
        /// a test that mistakenly dereferenced it would fault at once rather
        /// than quietly succeed. Seeding with null instead would make "the
        /// callee wrote null" and "the callee wrote nothing" indistinguishable,
        /// and telling those two apart is exactly what
        /// `lib/urlapi.c` L1548-L1552 is about.
        fn sentinel() -> *mut c_char {
            ptr::NonNull::<c_char>::dangling().as_ptr()
        }

        /// `curl_url_get(u, what, &out, flags)`, with the buffer reclaimed.
        ///
        /// The returned pair is the code and the part, and the part is an
        /// owned [`CBuf`] rather than a raw pointer so that the test cannot
        /// leak it. Adopting it back is sound for exactly the reason the C
        /// caller's `curl_free()` is: the block came from the C allocator.
        ///
        /// Only for calls that get past the two pointer tests. `*part = NULL`
        /// at L1552 sits after them, so this asserts the write happened and
        /// the two paths that return before it use [`get_untouched`] instead.
        fn get(u: *const CurlUrl, what: CURLUPart, flags: u32) -> (i32, Option<CBuf>) {
            let mut out: *mut c_char = sentinel();
            // SAFETY: `u` is a live handle, and `out` is a local
            // `*mut c_char` this stack frame owns, so it is aligned and
            // writable for the duration of the call.
            let code = unsafe { exports::curl_url_get(u, what, &mut out, flags) };
            assert_ne!(
                out,
                sentinel(),
                "L1552 writes the out-parameter before any work can fail"
            );
            // SAFETY: `out` is either null or the pointer `curl_url_get` just
            // handed over, which is a live C-allocator block this test now
            // owns and nothing else will release. The assertion above has
            // already ruled out the seeded sentinel, so no unreadable address
            // reaches this call. Adopting it once discharges the `curl_free()`
            // obligation of `include/curl/urlapi.h` L130-L131.
            let part = unsafe { adopt_c_string(out) };
            (code, part)
        }

        /// `curl_url_get` for the paths that return before L1552.
        ///
        /// A null handle is answered at L1548-L1549 and a null part pointer at
        /// L1550-L1551, both *above* the `*part = NULL` at L1552, so the
        /// caller's variable keeps whatever it held. That is faithful to the
        /// C and it is asserted here rather than glossed over -- and it is the
        /// reason [`get`] cannot be used for these two: adopting the seeded
        /// sentinel would read an address that was never a string.
        fn get_untouched(u: *const CurlUrl, what: CURLUPart, flags: u32) -> i32 {
            let mut out: *mut c_char = sentinel();
            // SAFETY: `u` is null or a live handle, and `out` is a local this
            // frame owns. Nothing is adopted afterwards, so no invalid address
            // is ever read.
            let code = unsafe { exports::curl_url_get(u, what, &mut out, flags) };
            assert_eq!(
                out,
                sentinel(),
                "a return above L1552 must leave the caller's pointer alone"
            );
            code
        }

        /// The bytes of a part the getter was expected to produce.
        fn bytes(part: &Option<CBuf>) -> &[u8] {
            part.as_ref().map_or(b"".as_slice(), CBuf::as_bytes)
        }

        /// Releases a handle. Named so the tests read as their C equivalents.
        fn cleanup(u: *mut CurlUrl) {
            // SAFETY: `u` is null or a handle from `curl_url()` or
            // `curl_url_dup()` that has not been cleaned up, and this is its
            // single release.
            unsafe { exports::curl_url_cleanup(u) };
        }

        #[test]
        fn a_null_handle_is_a_bad_handle_everywhere_it_can_be_reported() {
            // lib/urlapi.c L1548-L1549 and L1817-L1818. Two of the three
            // pointer-taking entry points have a documented answer for a null
            // handle; `Curl_url_set_authority` has none in the C, which never
            // tests it, and answers `CURLUE_BAD_HANDLE` here rather than
            // faulting.
            assert_eq!(
                get_untouched(ptr::null(), CURLUPART_URL, 0),
                CURLUE_BAD_HANDLE
            );

            assert_eq!(
                set(ptr::null_mut(), CURLUPART_URL, b"https://example.com/\0", 0),
                CURLUE_BAD_HANDLE
            );

            // SAFETY: a null handle is explicitly permitted by this
            // function's contract and must be reported, not dereferenced.
            let code = unsafe {
                exports::Curl_url_set_authority(
                    ptr::null_mut(),
                    b"example.com\0".as_ptr().cast::<c_char>(),
                )
            };
            assert_eq!(code, CURLUE_BAD_HANDLE);
        }

        #[test]
        fn a_null_part_pointer_is_a_bad_part_pointer_and_the_handle_is_checked_first() {
            let u = handle();
            // lib/urlapi.c L1550-L1551.
            // SAFETY: `u` is a live handle, and a null out-parameter is
            // explicitly permitted and must be reported rather than written.
            let code = unsafe { exports::curl_url_get(u, CURLUPART_URL, ptr::null_mut(), 0) };
            assert_eq!(code, CURLUE_BAD_PARTPOINTER);

            // The order of the two tests is observable: with both pointers
            // null the C reaches L1548 first, so the answer is the handle's
            // code and not the part pointer's.
            // SAFETY: both arguments are null, which both preconditions
            // permit; neither is dereferenced.
            let code =
                unsafe { exports::curl_url_get(ptr::null(), CURLUPART_URL, ptr::null_mut(), 0) };
            assert_eq!(code, CURLUE_BAD_HANDLE);
            cleanup(u);
        }

        #[test]
        fn the_out_parameter_is_nulled_before_any_work() {
            // lib/urlapi.c L1552, and the reason it is there: a caller who
            // ignores the code must not read a stale pointer. `get` seeds the
            // out-parameter with a dangling non-null value, so a code path
            // that failed to write it would be caught here rather than
            // reported as an absent part.
            let u = handle();
            let (code, part) = get(u, CURLUPART_QUERY, 0);
            assert_eq!(code, CURLUE_NO_QUERY);
            assert!(
                part.is_none(),
                "the seeded sentinel must have been overwritten"
            );

            let (code, part) = get(u, CURLUPART_FRAGMENT, 0);
            assert_eq!(code, CURLUE_NO_FRAGMENT);
            assert!(part.is_none());
            cleanup(u);
        }

        #[test]
        fn curl_url_cleanup_ignores_a_null_handle() {
            // lib/urlapi.c L1295, `if(u)`. Twice, because the property being
            // asserted is that the call is a no-op rather than that it
            // survives once.
            cleanup(ptr::null_mut());
            cleanup(ptr::null_mut());
        }

        #[test]
        fn an_out_of_range_part_is_an_unknown_part() {
            // lib/urlapi.c L1626-L1628 reaching L1633 for the getter,
            // L1873-L1874 for the setter, and L1773-L1774 for the clear path.
            // All three answer `CURLUE_UNKNOWN_PART`, value 9.
            let u = handle();
            assert_eq!(
                set(u, CURLUPART_URL, b"https://example.com/\0", 0),
                CURLUE_OK
            );

            // One past the last part, a value far outside the range, and a
            // negative one: `CURLUPart` is an `int`, so C can pass all three.
            for what in [CURLUPART_ZONEID.wrapping_add(1), 99, -1] {
                let (code, part) = get(u, what, 0);
                assert_eq!(code, CURLUE_UNKNOWN_PART, "get({what})");
                assert!(part.is_none());
                assert_eq!(set(u, what, b"x\0", 0), CURLUE_UNKNOWN_PART, "set({what})");
                // The clear path has its own switch and its own default.
                // SAFETY: `u` is a live handle and a null part string is
                // explicitly permitted, meaning "clear this part".
                let code = unsafe { exports::curl_url_set(u, what, ptr::null(), 0) };
                assert_eq!(code, CURLUE_UNKNOWN_PART, "clear({what})");
            }
            cleanup(u);
        }

        #[test]
        fn a_null_part_string_clears_the_part_rather_than_failing() {
            // lib/urlapi.c L1819-L1821, "setting a part to NULL clears it".
            // This is the exact opposite of `curl_url_get`, where a null
            // pointer is `CURLUE_BAD_PARTPOINTER`, and both are reproduced.
            let u = handle();
            assert_eq!(
                set(u, CURLUPART_URL, b"https://example.com/x?a=b#frag\0", 0),
                CURLUE_OK
            );
            let (code, part) = get(u, CURLUPART_QUERY, 0);
            assert_eq!(code, CURLUE_OK);
            assert_eq!(bytes(&part), b"a=b".as_slice());

            // SAFETY: `u` is a live handle; a null part string is permitted
            // and means "clear".
            let code = unsafe { exports::curl_url_set(u, CURLUPART_QUERY, ptr::null(), 0) };
            assert_eq!(code, CURLUE_OK, "a null part string is not an error");

            let (code, part) = get(u, CURLUPART_QUERY, 0);
            assert_eq!(code, CURLUE_NO_QUERY, "the part must be gone, not empty");
            assert!(part.is_none());

            // The fragment is untouched by clearing the query.
            let (code, part) = get(u, CURLUPART_FRAGMENT, 0);
            assert_eq!(code, CURLUE_OK);
            assert_eq!(bytes(&part), b"frag".as_slice());
            cleanup(u);
        }

        #[test]
        fn the_whole_round_trip_creates_sets_gets_dups_and_cleans_up() {
            // Create, set the whole URL, read every part back, duplicate,
            // confirm the copy agrees, release both. That is the sequence
            // `rust-urlapi/demo/urlapi_demo.c` performs across its first and
            // sixth sections, and the one every
            // caller in `lib/` performs in pieces.
            //
            // The credential fields carry a self-describing placeholder rather
            // than anything that reads like a password, so that no secret
            // scanner has to make a judgement call about a test fixture. What
            // the assertions need of them is only that they round-trip.
            let u = handle();
            assert_eq!(
                set(
                    u,
                    CURLUPART_URL,
                    b"https://user:notarealpassword@example.com:8080/a/b?c=d#e\0",
                    0
                ),
                CURLUE_OK
            );

            for (what, expected) in [
                (CURLUPART_SCHEME, b"https".as_slice()),
                (CURLUPART_USER, b"user".as_slice()),
                (CURLUPART_PASSWORD, b"notarealpassword".as_slice()),
                (CURLUPART_HOST, b"example.com".as_slice()),
                (CURLUPART_PORT, b"8080".as_slice()),
                (CURLUPART_PATH, b"/a/b".as_slice()),
                (CURLUPART_QUERY, b"c=d".as_slice()),
                (CURLUPART_FRAGMENT, b"e".as_slice()),
            ] {
                let (code, part) = get(u, what, 0);
                assert_eq!(code, CURLUE_OK, "get({what})");
                assert_eq!(bytes(&part), expected, "get({what})");
            }

            let (code, whole) = get(u, CURLUPART_URL, 0);
            assert_eq!(code, CURLUE_OK);
            assert_eq!(
                bytes(&whole),
                b"https://user:notarealpassword@example.com:8080/a/b?c=d#e".as_slice()
            );

            // SAFETY: `u` is a live handle, read and never written, which is
            // what `const CURLU *` at `include/curl/urlapi.h` L126 promises.
            let copy = unsafe { exports::curl_url_dup(u) };
            assert!(!copy.is_null(), "the duplicate must exist");
            assert_ne!(
                copy.cast::<c_void>(),
                u.cast::<c_void>(),
                "a copy, not an alias"
            );

            let (code, copied) = get(copy, CURLUPART_URL, 0);
            assert_eq!(code, CURLUE_OK);
            assert_eq!(bytes(&copied), bytes(&whole));

            // The copy is independent: changing it must not reach the
            // original, which is what `curlx_strdup` per member at L1314-L1323
            // buys.
            assert_eq!(set(copy, CURLUPART_HOST, b"other.example\0", 0), CURLUE_OK);
            let (code, changed) = get(copy, CURLUPART_HOST, 0);
            assert_eq!(code, CURLUE_OK);
            assert_eq!(bytes(&changed), b"other.example".as_slice());
            let (code, original) = get(u, CURLUPART_HOST, 0);
            assert_eq!(code, CURLUE_OK);
            assert_eq!(bytes(&original), b"example.com".as_slice());

            cleanup(copy);
            // The original outlives its copy, and so do the parts read out of
            // both: `whole`, `copied`, `changed` and `original` are still
            // live and still readable here, because
            // `include/curl/urlapi.h` L116-L118 says cleanup does not release
            // strings handed out earlier and it does not. Each is released by
            // its own `Drop` at the end of this function, which is what a C
            // caller does with `curl_free()`.
            assert_eq!(bytes(&changed), b"other.example".as_slice());
            let (code, still_there) = get(u, CURLUPART_HOST, 0);
            assert_eq!(code, CURLUE_OK);
            assert_eq!(bytes(&still_there), b"example.com".as_slice());
            cleanup(u);
        }

        #[test]
        fn an_empty_whole_url_is_a_no_op_success() {
            // The user's own worked example, confirmed at
            // lib/urlapi.c L1697-L1710: setting `CURLUPART_URL` to `""` on a
            // handle that already holds a URL succeeds and changes nothing.
            let u = handle();
            assert_eq!(
                set(u, CURLUPART_URL, b"https://example.com/a\0", 0),
                CURLUE_OK
            );
            assert_eq!(set(u, CURLUPART_URL, b"\0", 0), CURLUE_OK);
            let (code, whole) = get(u, CURLUPART_URL, 0);
            assert_eq!(code, CURLUE_OK);
            assert_eq!(bytes(&whole), b"https://example.com/a".as_slice());

            // And on a handle that cannot produce one it is malformed input,
            // L1707, because the retrieval it performs at L1697 fails.
            let empty = handle();
            assert_eq!(set(empty, CURLUPART_URL, b"\0", 0), CURLUE_MALFORMED_INPUT);
            cleanup(empty);
            cleanup(u);
        }

        #[test]
        fn curl_url_dup_reports_a_null_input_rather_than_faulting() {
            // The C dereferences `in` at L1314 without testing it, so a null
            // there is undefined behaviour and cannot be reproduced. Null is
            // returned instead, which is the answer every caller of
            // `curl_url_dup()` already handles because it is also what an
            // allocation failure gives.
            // SAFETY: a null input is permitted by this crate's contract for
            // the function and must be reported, not dereferenced.
            assert!(unsafe { exports::curl_url_dup(ptr::null()) }.is_null());
        }

        #[test]
        fn curl_url_dup_drops_the_guessed_scheme_flag() {
            // FB1, observed through the exported surface rather than through
            // the handle. L1314-L1326 copies ten strings, `portnum`,
            // `fragment_present` and `query_present` -- and not
            // `guessed_scheme`, which is a real member at L81. So a duplicate
            // answers `CURLUPART_SCHEME` under `CURLU_NO_GUESS_SCHEME`
            // differently from its original: the original reports having no
            // scheme, L1559-L1560, and the copy reports the guessed one.
            //
            // Reproduced deliberately. `docs/KNOWN-DIVERGENCES.md` records it,
            // and `tests/libtest/lib1560.c` L1970-L2031 cannot catch it
            // because it compares original against copy with flags of zero.
            let u = handle();
            assert_eq!(
                set(u, CURLUPART_URL, b"example.com/path\0", CURLU_GUESS_SCHEME),
                CURLUE_OK
            );

            // `guess_scheme` at L984-L1010 falls through its six-entry
            // hostname-prefix table to `"http"`. `DEFAULT_SCHEME` at L84 is
            // `"https"` and belongs to `CURLU_DEFAULT_SCHEME`, a different
            // flag, which is a distinction worth pinning here because getting
            // it backwards would look like a parser bug.
            let (code, guessed) = get(u, CURLUPART_SCHEME, 0);
            assert_eq!(code, CURLUE_OK);
            assert_eq!(bytes(&guessed), b"http".as_slice());

            let (code, part) = get(u, CURLUPART_SCHEME, CURLU_NO_GUESS_SCHEME);
            assert_eq!(code, CURLUE_NO_SCHEME, "the original knows it guessed");
            assert!(part.is_none());

            // SAFETY: `u` is a live handle, read and never written.
            let copy = unsafe { exports::curl_url_dup(u) };
            assert!(!copy.is_null());
            let (code, part) = get(copy, CURLUPART_SCHEME, CURLU_NO_GUESS_SCHEME);
            assert_eq!(
                code, CURLUE_OK,
                "FB1: the copy has forgotten that the scheme was guessed"
            );
            assert_eq!(bytes(&part), b"http".as_slice());

            // The other half of FB1, L1512-L1515: the whole URL emits the
            // scheme prefix from the copy and suppresses it from the original.
            // The suppression takes the `://` with it, because L1513 formats
            // the scheme and the separator together and L1515 replaces the
            // pair with an empty string rather than just the name.
            let (code, whole) = get(u, CURLUPART_URL, CURLU_NO_GUESS_SCHEME);
            assert_eq!(code, CURLUE_OK);
            assert_eq!(bytes(&whole), b"example.com/path".as_slice());
            let (code, copied) = get(copy, CURLUPART_URL, CURLU_NO_GUESS_SCHEME);
            assert_eq!(code, CURLUE_OK);
            assert_eq!(bytes(&copied), b"http://example.com/path".as_slice());
            cleanup(copy);
            cleanup(u);
        }

        #[test]
        fn curl_is_absolute_url_measures_the_scheme_and_always_defines_the_buffer() {
            // lib/urlapi.c L182-L220. The buffer must hold more than
            // `MAX_SCHEME_LEN`, which is the C's own precondition at L186, so
            // the test allocates exactly that shape.
            let mut buf = [0xa5_u8; MAX_SCHEME_LEN + 1];

            for (url, expected, scheme) in [
                (
                    b"HTTPS://example.com/\0".as_slice(),
                    5_usize,
                    b"https".as_slice(),
                ),
                (b"ftp://example.com/\0".as_slice(), 3, b"ftp".as_slice()),
                // L206-L209: without guessing the colon alone ends a scheme,
                // so `data:` is absolute even with no slash after it.
                (b"data:text/plain\0".as_slice(), 4, b"data".as_slice()),
                // Relative: nothing is written past the terminator L189 put
                // at the front.
                (b"/just/a/path\0".as_slice(), 0, b"".as_slice()),
                (b"\0".as_slice(), 0, b"".as_slice()),
            ] {
                buf.fill(0xa5);
                // SAFETY: `url` is a static literal ending in NUL, and `buf`
                // is a live local array of `MAX_SCHEME_LEN + 1` bytes, which
                // satisfies the L186 contract that `buflen > MAX_SCHEME_LEN`.
                let len = unsafe {
                    exports::Curl_is_absolute_url(
                        url.as_ptr().cast::<c_char>(),
                        buf.as_mut_ptr().cast::<c_char>(),
                        buf.len() as size_t,
                        C_FALSE,
                    )
                };
                assert_eq!(len, expected, "length for {url:?}");
                let written = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                assert_eq!(&buf[..written], scheme, "buffer for {url:?}");
                assert_eq!(written, expected, "L215 puts the terminator at `i`");
                // The write extent is exactly what the C writes and no more.
                // L188-L189 writes one byte on every path and L214-L215 adds
                // the scheme and its terminator; nothing else in L182-L220
                // touches the buffer, so every byte past the terminator must
                // still hold the fill. This is the assertion that would catch
                // a copy-out length computed one byte too generously.
                assert!(
                    buf[written + 1..].iter().all(|&b| b == 0xa5),
                    "nothing past the terminator is written for {url:?}"
                );
            }

            // L206's third condition: in guessing mode a scheme needs a slash
            // after the colon, so `data:` is a host called `data` on a port.
            // SAFETY: as above, with a null buffer -- L188 tolerates one and
            // every in-tree caller but one passes exactly that.
            let len = unsafe {
                exports::Curl_is_absolute_url(
                    b"data:text/plain\0".as_ptr().cast::<c_char>(),
                    ptr::null_mut(),
                    0,
                    C_TRUE,
                )
            };
            assert_eq!(len, 0, "guessing mode needs a slash after the colon");

            // SAFETY: `url` is null, which this crate's contract permits and
            // reports as zero; the C would fault instead.
            let len =
                unsafe { exports::Curl_is_absolute_url(ptr::null(), ptr::null_mut(), 0, C_TRUE) };
            assert_eq!(len, 0);
        }

        /// The one call the C permits that a borrowed input and a borrowed
        /// output could not both survive: scanning a buffer into itself.
        ///
        /// `Curl_is_absolute_url(b, b, sizeof(b), FALSE)` passes one address as
        /// both arguments, which the C permits and this function's contract
        /// permits too. The answer is always zero, and that is the C's answer
        /// rather than a simplification: L188-L189 writes the terminator into
        /// `buf[0]` before L194 reads `url[0]`, so an aliased call destroys the
        /// first byte of its own input and then finds nothing there.
        /// `ISALPHA(0)` is false, the scan is skipped, and the `i &&` guard at
        /// L206 fails.
        ///
        /// Both expectations were measured against this same driver linked to
        /// an unmodified `libcurl.a` rather than derived from reading. This is
        /// the one place where an implementation that read the input before
        /// writing the buffer would answer five for the first case, look more
        /// reasonable, and be a different function.
        #[test]
        fn curl_is_absolute_url_accepts_a_buffer_that_is_its_own_input() {
            for input in [
                b"HTTPS://example.com/\0".as_slice(),
                b"data:text/plain\0".as_slice(),
                b"/just/a/path\0".as_slice(),
                b"\0".as_slice(),
            ] {
                // Wide enough for the C's L186 precondition and for the
                // longest input above, so the aliasing is the only thing under
                // test.
                let mut buf = [0u8; MAX_SCHEME_LEN + 24];
                buf[..input.len()].copy_from_slice(input);

                let p = buf.as_mut_ptr().cast::<c_char>();
                // SAFETY: `p` is the same live local array for both arguments,
                // which this function's contract explicitly permits, and the
                // array holds a NUL-terminated copy of `input`. Its length
                // exceeds `MAX_SCHEME_LEN`, satisfying L186.
                let len =
                    unsafe { exports::Curl_is_absolute_url(p, p, buf.len() as size_t, C_FALSE) };

                assert_eq!(len, 0, "the aliased {input:?} loses its own first byte");
                assert_eq!(buf[0], 0, "L189 left the terminator at the front");
            }

            // Aliasing at an offset truncates the input at that offset instead
            // of at its front, which is the same mechanism seen from further
            // along. Both offsets below were measured against the reference.
            //
            // At five the terminator lands exactly on the colon, so the scan
            // finds `https` followed by a terminator rather than by a colon and
            // L206's second condition fails: the answer is zero even though the
            // scheme name is intact in the buffer.
            let mut buf = [0u8; MAX_SCHEME_LEN + 24];
            buf[..21].copy_from_slice(b"https://example.com/\0");
            let start = buf.as_mut_ptr().cast::<c_char>();
            // SAFETY: as above, and the offset stays inside the same live
            // array, so both pointers are valid for the lengths given.
            let len = unsafe {
                let out = start.add(5);
                exports::Curl_is_absolute_url(start, out, (buf.len() - 5) as size_t, C_FALSE)
            };
            assert_eq!(len, 0, "the terminator replaced the colon L206 needs");
            assert_eq!(&buf[..5], b"https", "the scheme name itself is untouched");
            assert_eq!(buf[5], 0, "L189 wrote the terminator at the offset");

            // At six the colon survives, so the scan succeeds and the copy-out
            // lands the lowercased scheme and its terminator at the offset --
            // which is what proves the write extent is `n + 1` bytes placed
            // where the caller asked, and not a buffer fill.
            let mut buf = [0xa5_u8; MAX_SCHEME_LEN + 24];
            buf[..21].copy_from_slice(b"https://example.com/\0");
            let start = buf.as_mut_ptr().cast::<c_char>();
            // SAFETY: as above.
            let len = unsafe {
                let out = start.add(6);
                exports::Curl_is_absolute_url(start, out, (buf.len() - 6) as size_t, C_FALSE)
            };
            assert_eq!(len, 5, "the colon at index five ended the scheme");
            assert_eq!(&buf[..6], b"https:", "the input up to the offset is intact");
            assert_eq!(&buf[6..12], b"https\0", "exactly six bytes were written");
            // Index twelve still holds the input byte the copy did not reach --
            // `p` of `example` -- which is what "and no more" means here.
            assert_eq!(buf[12], b'p', "and not one byte more");
            assert!(
                buf[21..].iter().all(|&b| b == 0xa5),
                "nothing past the input was touched either"
            );
        }

        /// `Curl_junkscan` with its length pointer inside its input.
        ///
        /// The C writes `*urllen` at L237 after it has finished reading, so
        /// overlap is harmless there; the port has to be arranged the same way,
        /// and the storage below makes the two pointers genuinely the same
        /// address. `[size_t; 4]` rather than `[u8; 32]` because `urllen` must
        /// be aligned for a `size_t` and this is the portable way to say so.
        #[test]
        fn curl_junkscan_accepts_a_length_pointer_inside_its_input() {
            const TEXT: &[u8] = b"https://example.com/\0";
            let mut store = [0_usize; 4];

            // SAFETY: `store` is a live local of 4 * size_of::<usize>() bytes,
            // which is at least `TEXT.len()` on every target this crate builds
            // for, and the destination is a byte pointer into it, so alignment
            // is satisfied trivially. The two ranges do not overlap: `TEXT` is
            // a static literal.
            unsafe {
                ptr::copy_nonoverlapping(
                    TEXT.as_ptr(),
                    store.as_mut_ptr().cast::<u8>(),
                    TEXT.len(),
                );
            }

            let url = store.as_mut_ptr().cast::<c_char>();
            let urllen = store.as_mut_ptr().cast::<size_t>();
            // SAFETY: `url` and `urllen` address the same live local, which
            // this function's contract explicitly permits. `url` is
            // NUL-terminated by the copy above and `urllen` is aligned for a
            // `size_t` because it is the array's own element pointer.
            let code = unsafe { exports::Curl_junkscan(url, urllen, C_FALSE) };

            assert_eq!(code, CURLUE_OK);
            assert_eq!(
                store[0],
                TEXT.len() - 1,
                "L237 wrote the length over the input"
            );
        }

        /// A `CurlBool` holding something other than 0 or 1 means true, as it
        /// does in C.
        ///
        /// The point of not spelling these two parameters `bool` is that a C
        /// caller whose `bool` is an `int` or an enumeration can hand over any
        /// int-width value, and 2 in a Rust `bool` would be instant undefined
        /// behaviour. Here it is simply true, which is C's own coercion.
        #[test]
        fn a_noncanonical_curl_bool_reads_as_true() {
            let odd: exports::CurlBool = 2;

            // Guessing mode needs a slash after the colon, L206, so a true
            // `guess_scheme` answers zero for `data:` where a false one
            // answers four.
            // SAFETY: both literals end in NUL and the buffer pointer is null,
            // which L188 tolerates.
            let guessing = unsafe {
                exports::Curl_is_absolute_url(
                    b"data:text/plain\0".as_ptr().cast::<c_char>(),
                    ptr::null_mut(),
                    0,
                    odd,
                )
            };
            assert_eq!(guessing, 0, "2 means true, as it does in C");

            // And `allowspace`, L232: a space is junk when it is false and
            // acceptable when it is true.
            let mut len: size_t = 0;
            // SAFETY: the literal ends in NUL and `len` is a local this frame
            // owns, so it is aligned and writable, and disjoint from the
            // static.
            let code = unsafe {
                exports::Curl_junkscan(
                    b"https://exa mple.com/\0".as_ptr().cast::<c_char>(),
                    &mut len,
                    odd,
                )
            };
            assert_eq!(code, CURLUE_OK);
            assert_eq!(len, 21);
        }

        /// The overlap test that decides whether the setters copy.
        ///
        /// A pure function of two addresses and two lengths, so it is checked
        /// directly and exhaustively at its boundaries rather than through a
        /// handle whose layout is deliberately unspecified. No pointer here is
        /// dereferenced; forming one from an integer is safe, and the function
        /// only compares.
        #[test]
        fn the_handle_overlap_test_is_exact_at_its_boundaries() {
            let size = core::mem::size_of::<CurlUrl>();
            let base = 0x1_0000_usize;
            let handle = base as *const CurlUrl;
            let at = |address: usize| address as *const c_char;

            // Wholly before, with the NUL landing on the byte just before the
            // handle: disjoint.
            assert!(exports::disjoint_from_handle(at(base - 4), 3, handle));
            // Wholly after the last byte: disjoint.
            assert!(exports::disjoint_from_handle(at(base + size), 3, handle));

            // The NUL lands on the handle's first byte: overlapping, which is
            // why the range is widened by one.
            assert!(!exports::disjoint_from_handle(at(base - 3), 3, handle));
            // The first byte of the string is the handle's last byte.
            assert!(!exports::disjoint_from_handle(
                at(base + size - 1),
                3,
                handle
            ));
            // Starts at the handle, and an empty string still reads its NUL.
            assert!(!exports::disjoint_from_handle(at(base), 0, handle));
            // Strictly inside.
            assert!(!exports::disjoint_from_handle(at(base + 1), 1, handle));
            // Contains the handle.
            assert!(!exports::disjoint_from_handle(
                at(base - 8),
                size + 16,
                handle
            ));
        }

        /// The handle fits the alignment the C allocator actually promises.
        ///
        /// `HANDLE_FITS_MALLOC_ALIGNMENT` proves this at compile time; the
        /// run-time half exists so that the bound is reported rather than
        /// merely satisfied, and so that a target whose `max_align_t` model is
        /// weaker than its `CurlUrl` is caught by a named test rather than by a
        /// bare `assert!` inside a `const` block.
        #[test]
        fn the_handle_needs_no_more_alignment_than_malloc_gives() {
            let needed = core::mem::align_of::<CurlUrl>();
            let promised = exports::malloc_alignment();

            assert!(
                needed <= promised,
                "the handle wants {needed}-byte alignment and the C allocator \
                 promises {promised}"
            );
            assert!(
                promised >= core::mem::align_of::<*mut c_void>(),
                "any model of max_align_t must be at least pointer-aligned"
            );
        }

        #[test]
        fn curl_is_absolute_url_writes_only_the_bytes_the_c_writes() {
            // lib/urlapi.c writes at most `buf[0]` at L189 and, on success, the
            // name at L214 plus one terminator at L215. Everything past that is
            // the caller's business and must survive untouched, which is what a
            // sentinel fill measures. This also pins the reason the caller's
            // buffer is never borrowed as a slice: the function only ever
            // stores, so a buffer a C caller has not initialized is fine.
            const GUARD: u8 = 0x5a;

            let mut buf = [GUARD; MAX_SCHEME_LEN + 8];
            // SAFETY: the URL is a static literal ending in NUL, and `buf` is a
            // live local array longer than `MAX_SCHEME_LEN`, which satisfies the
            // L186 contract.
            let len = unsafe {
                exports::Curl_is_absolute_url(
                    b"HTTPS://example.com/\0".as_ptr().cast::<c_char>(),
                    buf.as_mut_ptr().cast::<c_char>(),
                    buf.len() as size_t,
                    C_FALSE,
                )
            };
            assert_eq!(len, 5);
            assert_eq!(&buf[..5], b"https".as_slice(), "L214 lower-cases");
            assert_eq!(buf[5], 0, "L215 terminates at `i`");
            assert!(
                buf[6..].iter().all(|&b| b == GUARD),
                "nothing past the terminator may be written"
            );

            buf.fill(GUARD);
            // SAFETY: as above, with a relative URL.
            let len = unsafe {
                exports::Curl_is_absolute_url(
                    b"/just/a/path\0".as_ptr().cast::<c_char>(),
                    buf.as_mut_ptr().cast::<c_char>(),
                    buf.len() as size_t,
                    C_FALSE,
                )
            };
            assert_eq!(len, 0);
            assert_eq!(buf[0], 0, "L189 always leaves a defined value");
            assert!(
                buf[1..].iter().all(|&b| b == GUARD),
                "a relative URL writes exactly one byte"
            );
        }

        #[test]
        fn curl_is_absolute_url_accepts_an_output_buffer_overlapping_the_url() {
            // Nothing in the C declaration forbids `buf` from overlapping `url`,
            // so this port has to tolerate it without undefined behaviour: the
            // caller's buffer is never borrowed as a slice, the scheme is
            // measured into a local array, and the result is copied out through
            // raw pointers. The extreme case is `buf == url`.
            //
            // The ANSWER for that case is not the answer for two separate
            // buffers, and reproducing the difference is the point. L188-L189
            // writes `buf[0] = 0` *before* L194 reads `url[0]`, so an aliased
            // call has already truncated its own input and reports no scheme.
            // Measured against the unmodified reference archive:
            //
            //     aliased  "HTTPS://example.com/"  rc=0  buf=[]
            //     separate "HTTPS://example.com/"  rc=5  out=[https]
            //
            // A port that read the input into scratch before writing would
            // answer 5 here, which is a different function.
            let mut inout =
                *b"HTTPS://example.com/\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
            let raw = inout.as_mut_ptr().cast::<c_char>();
            assert!(
                inout.len() > MAX_SCHEME_LEN,
                "the L186 buffer precondition has to hold for the aliased call"
            );
            // SAFETY: `inout` is a live NUL-terminated local array longer than
            // `MAX_SCHEME_LEN`, so it is a valid `url` and a valid `buf` at once.
            // Passing it as both is exactly what this test exists to exercise,
            // and this function's contract permits it.
            let len = unsafe {
                exports::Curl_is_absolute_url(raw.cast_const(), raw, inout.len() as size_t, C_FALSE)
            };
            assert_eq!(len, 0, "L189 emptied the input before L194 read it");
            assert_eq!(inout[0], 0, "the defined value L189 leaves");
        }

        #[test]
        fn curl_is_absolute_url_bounds_a_buffer_shorter_than_the_c_requires() {
            // The C's L186 precondition is `buflen > MAX_SCHEME_LEN`, and the C
            // has no bounded behaviour when it is broken -- L215 simply writes
            // out of range. This port truncates instead, which is the only
            // direction available and the safe one, and it still reports the
            // measurement rather than the number of bytes it managed to store.
            const GUARD: u8 = 0x5a;
            let mut framed = [GUARD; 16];

            // Three writable bytes, then untouchable guard bytes after them.
            // SAFETY: the URL is a NUL-terminated literal and the pointer is
            // writable for the three bytes named, which is what `buflen` claims.
            let len = unsafe {
                exports::Curl_is_absolute_url(
                    b"https://example.com/\0".as_ptr().cast::<c_char>(),
                    framed.as_mut_ptr().cast::<c_char>(),
                    3,
                    C_FALSE,
                )
            };
            assert_eq!(len, 5, "the measurement is unaffected by the short buffer");
            assert_eq!(&framed[..3], b"htt".as_slice());
            assert!(
                framed[3..].iter().all(|&b| b == GUARD),
                "not one byte past `buflen` may be written"
            );

            // A zero-length buffer is writable for nothing at all, so not even
            // L189's terminator can be placed.
            framed.fill(GUARD);
            // SAFETY: `buflen` is zero, so no byte of `framed` is claimed to be
            // writable and none may be written; the pointer is live regardless.
            let len = unsafe {
                exports::Curl_is_absolute_url(
                    b"https://example.com/\0".as_ptr().cast::<c_char>(),
                    framed.as_mut_ptr().cast::<c_char>(),
                    0,
                    C_FALSE,
                )
            };
            assert_eq!(len, 5);
            assert!(framed.iter().all(|&b| b == GUARD));
        }

        #[test]
        fn curl_junkscan_writes_the_length_only_on_success() {
            // lib/urlapi.c L223-L239. `*urllen = n` is at L237, after both
            // rejections, so a failing scan must leave the caller's variable
            // exactly as it was.
            const SENTINEL: size_t = 0xdead_beef;
            let mut len: size_t = SENTINEL;

            // SAFETY: the literal ends in NUL and `len` is a local this frame
            // owns, so it is aligned and writable.
            let code = unsafe {
                exports::Curl_junkscan(
                    b"https://example.com/\0".as_ptr().cast::<c_char>(),
                    &mut len,
                    C_FALSE,
                )
            };
            assert_eq!(code, CURLUE_OK);
            assert_eq!(len, 20);

            // A space is junk unless `allowspace` says otherwise, L232.
            len = SENTINEL;
            // SAFETY: as above.
            let code = unsafe {
                exports::Curl_junkscan(
                    b"https://exa mple.com/\0".as_ptr().cast::<c_char>(),
                    &mut len,
                    C_FALSE,
                )
            };
            assert_eq!(code, CURLUE_MALFORMED_INPUT);
            assert_eq!(len, SENTINEL, "L237 is past the rejection");

            // SAFETY: as above.
            let code = unsafe {
                exports::Curl_junkscan(
                    b"https://exa mple.com/\0".as_ptr().cast::<c_char>(),
                    &mut len,
                    C_TRUE,
                )
            };
            assert_eq!(code, CURLUE_OK);
            assert_eq!(len, 21);

            // A control byte is junk either way, L234.
            len = SENTINEL;
            // SAFETY: as above.
            let code = unsafe {
                exports::Curl_junkscan(
                    b"http://a\x7fb/\0".as_ptr().cast::<c_char>(),
                    &mut len,
                    C_TRUE,
                )
            };
            assert_eq!(code, CURLUE_MALFORMED_INPUT);
            assert_eq!(len, SENTINEL);

            // A null length pointer is tolerated rather than written through,
            // and a null URL is reported rather than measured. The C does
            // neither; both would fault there.
            // SAFETY: both null arguments are permitted by this crate's
            // contract for the function.
            let code = unsafe {
                exports::Curl_junkscan(
                    b"http://a/\0".as_ptr().cast::<c_char>(),
                    ptr::null_mut(),
                    C_FALSE,
                )
            };
            assert_eq!(code, CURLUE_OK);
            // SAFETY: as above.
            let code = unsafe { exports::Curl_junkscan(ptr::null(), ptr::null_mut(), C_FALSE) };
            assert_eq!(code, CURLUE_MALFORMED_INPUT);
        }

        #[test]
        fn curl_url_set_authority_replaces_the_host_on_a_live_handle() {
            // lib/urlapi.c L658-L675, whose one consumer is
            // `lib/http2.c` L739. It is the only entry point that parses an
            // authority into a handle that is already populated, and it passes
            // `CURLU_DISALLOW_USER` at L667, so credentials in the authority
            // are refused rather than stored.
            let u = handle();
            assert_eq!(
                set(u, CURLUPART_URL, b"https://example.com/a\0", 0),
                CURLUE_OK
            );

            // SAFETY: `u` is a live handle and the literal ends in NUL.
            let code = unsafe {
                exports::Curl_url_set_authority(
                    u,
                    b"other.example:8080\0".as_ptr().cast::<c_char>(),
                )
            };
            assert_eq!(code, CURLUE_OK);

            let (code, host) = get(u, CURLUPART_HOST, 0);
            assert_eq!(code, CURLUE_OK);
            assert_eq!(bytes(&host), b"other.example".as_slice());
            let (code, port) = get(u, CURLUPART_PORT, 0);
            assert_eq!(code, CURLUE_OK);
            assert_eq!(bytes(&port), b"8080".as_slice());
            // The path is untouched: only the authority is replaced.
            let (code, path) = get(u, CURLUPART_PATH, 0);
            assert_eq!(code, CURLUE_OK);
            assert_eq!(bytes(&path), b"/a".as_slice());

            // A null authority is reported rather than measured; the C's
            // `strlen` at L666 would fault.
            // SAFETY: a null authority is permitted by this crate's contract.
            let code = unsafe { exports::Curl_url_set_authority(u, ptr::null()) };
            assert_eq!(code, CURLUE_MALFORMED_INPUT);
            cleanup(u);
        }

        /// `curl_url_strerror` is only exported when the `strerror` feature is
        /// on, which is the standalone configuration; in drop-in mode
        /// `lib/strerror.c` supplies it and this symbol must not exist.
        #[cfg(feature = "strerror")]
        #[test]
        fn curl_url_strerror_returns_a_static_message_the_caller_must_not_free() {
            use core::ffi::CStr;

            for (code, expected) in [
                (CURLUE_OK, b"No error".as_slice()),
                (
                    CURLUE_BAD_HANDLE,
                    b"An invalid CURLU pointer was passed as argument".as_slice(),
                ),
                (
                    CURLUE_UNKNOWN_PART,
                    b"An unknown part ID was passed to a URL API function".as_slice(),
                ),
            ] {
                let p = exports::curl_url_strerror(code);
                assert!(!p.is_null(), "the message pointer is never null");
                // SAFETY: `crate::error::strerror` returns the address of a
                // NUL-terminated `'static` literal in this object's read-only
                // data, so the borrow is valid for any lifetime and the bytes
                // never change.
                assert_eq!(unsafe { CStr::from_ptr(p) }.to_bytes(), expected);
                // OWNERSHIP: nothing changed hands. The pointer addresses a
                // literal, so it is NOT freed here -- this is the one
                // string-returning entry point of the API that breaks the
                // otherwise-universal "caller frees with curl_free()" rule of
                // `include/curl/urlapi.h` L130-L131. Calling `curl_free` on
                // it would be a free of a non-allocated address.
                //
                // Calling twice must give the same address, which is what
                // makes "static" observable.
                assert_eq!(p, exports::curl_url_strerror(code));
            }

            // Every code, including out-of-range ones, has an answer and none
            // of them is null: `lib/strerror.c` L528-L530 falls through to a
            // catch-all.
            for code in -3..40 {
                assert!(!exports::curl_url_strerror(code).is_null(), "code {code}");
            }
        }

        /// `curl_free` is only exported when the `cfree` feature is on. In
        /// drop-in mode `lib/escape.c` supplies it and this symbol must not
        /// exist, or the link fails on a duplicate definition.
        #[cfg(feature = "cfree")]
        #[test]
        fn curl_free_releases_a_buffer_curl_url_get_handed_out() {
            // The documented ownership round trip, end to end and through the
            // exported symbols only: `curl_url_get` hands a block over, and
            // `curl_free` is what releases it per
            // `docs/libcurl/curl_url_get.md` L45. This is the one test that
            // deliberately does not adopt the pointer back, because the point
            // is to exercise the C caller's path rather than Rust's.
            let u = handle();
            assert_eq!(
                set(u, CURLUPART_URL, b"https://example.com/a?b=c\0", 0),
                CURLUE_OK
            );

            let mut out: *mut c_char = ptr::null_mut();
            // SAFETY: `u` is a live handle and `out` is a local this frame
            // owns.
            let code = unsafe { exports::curl_url_get(u, CURLUPART_URL, &mut out, 0) };
            assert_eq!(code, CURLUE_OK);
            assert!(!out.is_null());
            // SAFETY: `out` is the block `curl_url_get` just handed over, so
            // it is a live NUL-terminated C-allocator string owned by this
            // frame and released exactly once, below.
            unsafe { exports::curl_free(out.cast::<c_void>()) };

            // And a null pointer is a no-op, as `free` guarantees and
            // `lib/escape.c` L191 inherits.
            // SAFETY: a null pointer is explicitly permitted.
            unsafe { exports::curl_free(ptr::null_mut()) };
            cleanup(u);
        }
    }
}
